#!/usr/bin/env node
// Offline decryption of LG NCG v2 content-protected app files, and IPK
// repackaging (zero-dependency Node.js; no npm packages).
//
// NCG-protected IPKs from the LG Content Store do not run in Developer Mode:
// the payload files (index.html, *.js, ...) are encrypted with a per-content
// key (CEK) that the TV normally fetches from LG's Right Object service and
// keeps in a device-bound license store. This tool decrypts the payload
// offline. It needs the CEK once per content id (cid); the CEK is obtained with
// the RO exchange (see docs/ro-protocol.md) and cached in the user's home.
//
// Key material derivation (verified on webOS 25 firmware,
// libncg_agent.so.2.0.0; see docs/ncg-format.md):
//
//     cek     = base64decode(<cek> from the RO response)   // 32 bytes
//     aes_key = cek[0:16]                                   // raw
//     ctr_iv  = cek[16:32]                                  // raw
//
// Both decrypt commands verify their output before reporting success: the
// result must no longer be NCG, and for IPKs the repack is re-checked end to
// end (valid ar/tar structure, zero NCG members left, every member that was not
// replaced byte-identical to the input).
//
// Commands:
//
//     cache list
//     cache add --app-id ID --sid SID --cid CID --cek-b64 B64 [--source TXT]
//     cache remove --app-id ID --cid CID
//     decrypt-file FILE [--cid CID] [--key HEX] [--iv HEX] [--out PATH]
//     decrypt-ipk IPK --out IPK [--app-id ID]
//
// Requirements: Node.js 18+ (built-in crypto/zlib; no npm packages).

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const NCG_MAGIC = Buffer.from('NCGFILE_HEADER', 'latin1');

// 512-byte scatter table. Extracted from firmware libncg_agent.so.2.0.0 at
// file offset 0x17660.
const TABLE = Buffer.from(
    '080d0e0f040001090e0b0f010d050a0505030f0209060d020b0d05030d09060b' +
    '0a0f080c02050801000a0102060c050106060e060b0501050201010509030b0d' +
    '0f03020b0e050807040e0c0d09010c0c0a060f0309000f07090802020e090508' +
    '0e0b060200020f050d0e0108050f030f050f0c080501020101080e0e0000000e' +
    '090b04070a050507030d0503010602070c0b030004050a0e010806010a07010d' +
    '090f000a060b0b060707030f0500060f080c05070909010b08020a000a040c08' +
    '020306070a07000c0b0100050c0804030d0a020e0d0603010e030a080f0b0900' +
    '08040d050601080c0d090709060f000c03080c0f040f0409090902010a0f0b0b' +
    '0a070901030c07020f0200070d000a0207050f0501030b040b00060b06090a00' +
    '02030a0c0d09010c09070f05050f0e080f060e050c020404080d0d0e0c040f02' +
    '0903020c0a03030606090e09060e0d0d0c02020c0e0f0103010d040207090406' +
    '0b0c0c0b050c030f0c0e0b0407070105000d010509050d0e0907060c03040800' +
    '0f0a0b09080f010b00010f05000200060103040b090404090f090a0900050503' +
    '040f090308050a09040c0b08060e0b0a090c0f07090e0a0d010407020f0b0b0e' +
    '0008030c03010a0a000a080f0205000f0d0e0504050804090007010002070a04' +
    '070f0102050b03070e020f0f0f03070300020d050e090f0909080e07080a0101', 'hex');
if (TABLE.length !== 512) throw new Error('scatter table is not 512 bytes');

// -----------------------------------------------------------------------------
// NCG v2 payload algorithm
// -----------------------------------------------------------------------------

function ctrXor(data, key, iv) {
  const c = crypto.createCipheriv('aes-128-ctr', key, iv);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}

function parseHeader(buf) {
  if (buf.length < 14 || !buf.subarray(0, 14).equals(NCG_MAGIC)) {
    throw new Error('not an NCG v2 file (bad magic)');
  }
  const version = buf.readUInt16LE(0xE);
  const bodySize = buf.readUInt32LE(0x10);
  const nul = buf.indexOf(0, 512, 1024);
  const xml = buf.subarray(512, nul === -1 ? 1024 : nul).toString('utf8');
  let cid = null;
  const i = xml.indexOf('<cid>');
  if (i >= 0) {
    const j = xml.indexOf('</cid>', i);
    if (j > i) cid = xml.slice(i + 5, j).trim();
  }
  return { version, bodySize, cid, xml };
}

// Scatter-pattern seed (empirically verified; see docs/ncg-format.md).
function seedFor(cid) {
  let sum = 0;
  for (const ch of Buffer.from(cid, 'utf8')) sum += ch;
  return sum % 16;
}

function decryptPayload(payload, key, iv, seed) {
  if (key.length !== 16 || iv.length !== 16) {
    throw new Error('key and iv must be 16 bytes each');
  }
  // The CTR counter is re-seeded from the IV for every block and for the tail,
  // so the keystream is one fixed 512-byte prefix: compute it once.
  const ks = ctrXor(Buffer.alloc(512), key, iv);
  const tbl = TABLE.subarray(32 * seed, 32 * seed + 32);
  const out = [];
  const n = payload.length;
  let i = 0;
  while (i + 512 <= n) {
    const block = Buffer.from(payload.subarray(i, i + 512));
    const keys = Buffer.alloc(32);
    for (let k = 0; k < 32; k++) keys[k] = block[16 * k + tbl[k]];
    for (let j = 0; j < 480; j++) block[j] ^= keys[j % 32];
    for (let k = 0; k < 32; k++) block[16 * k + tbl[k]] = keys[k] ^ ks[k];
    // block[480:512] is stored in the clear
    out.push(block);
    i += 512;
  }
  if (i < n) {
    // final partial block: pure AES-128-CTR from the IV
    const tail = payload.subarray(i);
    const dec = Buffer.alloc(tail.length);
    for (let j = 0; j < tail.length; j++) dec[j] = tail[j] ^ ks[j];
    out.push(dec);
  }
  return Buffer.concat(out);
}

// -----------------------------------------------------------------------------
// IPK container: standard ar archive (member names carry a trailing '/', an LG
// packaging quirk) containing debian-binary, control.tar.gz, data.tar.gz.
// -----------------------------------------------------------------------------

const AR_MAGIC = Buffer.from('!<arch>\n', 'latin1');
const AR_HDR = 60;
const AR_SIZE_OFF = 16 + 12 + 6 + 6 + 8; // 48
const AR_END = Buffer.from('`\n', 'latin1');

function arRead(data) {
  if (data.subarray(0, 8).compare(AR_MAGIC) !== 0) {
    throw new Error('not an ar archive');
  }
  const members = [];
  let off = 8;
  while (off + AR_HDR <= data.length) {
    const hdr = data.subarray(off, off + AR_HDR);
    if (!hdr.subarray(58, 60).equals(AR_END)) {
      throw new Error(`bad ar magic at offset 0x${off.toString(16)}`);
    }
    const size = parseInt(hdr.subarray(AR_SIZE_OFF, AR_SIZE_OFF + 10)
      .toString('ascii').trim(), 10);
    const bodyOff = off + AR_HDR;
    if (bodyOff + size > data.length) {
      throw new Error(`ar member body overruns file at 0x${off.toString(16)}`);
    }
    members.push({ hdr, body: data.subarray(bodyOff, bodyOff + size) });
    off = bodyOff + size + (size & 1);
  }
  if (off !== data.length) {
    throw new Error('trailing bytes after last ar member');
  }
  return members;
}

function arWrite(members) {
  const out = [AR_MAGIC];
  for (const { hdr, body } of members) {
    out.push(hdr, body);
    if (body.length & 1) out.push(Buffer.from('\n', 'latin1'));
  }
  return Buffer.concat(out);
}

function arMemberName(hdr) {
  let name = hdr.subarray(0, 16).toString('ascii').replace(/\s+/g, '');
  if (name.endsWith('/')) name = name.slice(0, -1);
  return name;
}

function isNcg(body) {
  return body.length >= 14 && body.subarray(0, 14).equals(NCG_MAGIC);
}

// -----------------------------------------------------------------------------
// tar (data.tar.gz inner container). Hand-rolled ustar reader/writer: regular
// files, dirs, links are preserved byte-for-byte (raw headers pass through
// untouched); GNU long names are supported on read and write; pax/sparse are
// rejected loudly rather than mangled.
// -----------------------------------------------------------------------------

function tarOctal(buf, off, len) {
  let s = '';
  for (let i = 0; i < len; i++) {
    const b = buf[off + i];
    if (b === 0 || b === 0x20) break;
    s += String.fromCharCode(b);
  }
  if (s === '') return 0;
  if ((s.charCodeAt(0) & 0x80) !== 0) {
    throw new Error(`unsupported GNU base-256 tar field "${s.slice(0, 8)}"`);
  }
  const v = parseInt(s, 8);
  if (Number.isNaN(v)) throw new Error(`bad tar octal field "${s}"`);
  return v;
}

function tarCstr(buf, off, len) {
  const end = buf.indexOf(0, off, off + len);
  return buf.subarray(off, end === -1 ? off + len : end).toString('latin1');
}

function tarRead(tar) {
  // Return [{name, type, mode, uid, gid, size, mtime, linkname, uname, gname,
  // data (regular files only), rawHeader}]
  const members = [];
  let off = 0;
  let pendingName = null;
  let pendingLink = null;
  while (off + 512 <= tar.length) {
    if (tar.subarray(off, off + 512).every(b => b === 0)) {
      // EOF: two zero blocks (or the end of the data)
      const rest = tar.subarray(off + 512);
      if (rest.length > 0 && rest.some(b => b !== 0)) {
        throw new Error('trailing non-zero bytes after tar EOF blocks');
      }
      return members;
    }
    const hdr = tar.subarray(off, off + 512);
    // checksum: sum of the header with the checksum field treated as spaces
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 0x20 : hdr[i];
    const chk = tarOctal(hdr, 148, 8);
    if (chk !== sum) {
      throw new Error(`bad tar checksum at offset ${off} (want ${chk}, got ${sum})`);
    }
    let name = tarCstr(hdr, 0, 100);
    const magic = hdr.subarray(257, 263).toString('latin1');
    if (magic.slice(0, 5) !== 'ustar') {
      throw new Error(`unsupported tar magic at offset ${off}`);
    }
    const prefix = tarCstr(hdr, 345, 155);
    if (prefix) name = prefix + '/' + name;
    const type = (hdr[156] || 0) === 0 ? '0' : String.fromCharCode(hdr[156]);
    const entry = {
      name,
      type,
      mode: tarOctal(hdr, 100, 8),
      uid: tarOctal(hdr, 108, 8),
      gid: tarOctal(hdr, 116, 8),
      size: tarOctal(hdr, 124, 12),
      mtime: tarOctal(hdr, 136, 12),
      linkname: tarCstr(hdr, 157, 100),
      uname: tarCstr(hdr, 265, 32),
      gname: tarCstr(hdr, 297, 32),
      rawHeader: Buffer.from(hdr),
    };
    off += 512;
    if (type === 'L') {
      if (off + entry.size > tar.length) throw new Error('tar longname overruns data');
      pendingName = tar.subarray(off, off + entry.size).toString('latin1');
      off += entry.size + ((512 - (entry.size % 512)) % 512);
      continue;
    }
    if (type === 'K') {
      if (off + entry.size > tar.length) throw new Error('tar longlink overruns data');
      pendingLink = tar.subarray(off, off + entry.size).toString('latin1');
      off += entry.size + ((512 - (entry.size % 512)) % 512);
      continue;
    }
    if (type === 'x' || type === 'g') {
      throw new Error('pax tar extension is not supported');
    }
    if (type === 'S') {
      throw new Error('sparse tar members are not supported');
    }
    if (pendingName !== null) { entry.name = pendingName; pendingName = null; }
    if (pendingLink !== null) { entry.linkname = pendingLink; pendingLink = null; }
    if (entry.type === '0') {
      if (off + entry.size > tar.length) {
        throw new Error(`tar member ${entry.name} overruns data`);
      }
      entry.data = Buffer.from(tar.subarray(off, off + entry.size));
      off += entry.size + ((512 - (entry.size % 512)) % 512);
    }
    members.push(entry);
  }
  if (off !== tar.length) {
    throw new Error(`tar data does not end on a block boundary (${tar.length - off} stray bytes)`);
  }
  return members;
}

function tarFieldOctal(v, len) {
  // 7/11 digit octal, NUL-padded to the field width
  return Buffer.from(v.toString(8).padStart(len - 1, '0') + '\0', 'latin1');
}

function tarFieldStr(s, len) {
  const b = Buffer.from(s, 'latin1');
  if (b.length > len) throw new Error(`tar field too long: "${s}"`);
  const out = Buffer.alloc(len);
  b.copy(out, 0);
  return out;
}

function tarHeaderFor(entry) {
  const hdr = Buffer.alloc(512);
  let name = entry.name;
  let prefix = '';
  if (name.length > 100) {
    const cut = name.lastIndexOf('/', 155);
    if (cut <= 0 || name.length - cut - 1 > 100) {
      throw new Error(`tar name too long and unsplittable: ${name}`);
    }
    prefix = name.slice(0, cut);
    name = name.slice(cut + 1);
  }
  hdr.set(tarFieldStr(name, 100), 0);
  hdr.set(tarFieldOctal(entry.mode, 8), 100);
  hdr.set(tarFieldOctal(entry.uid, 8), 108);
  hdr.set(tarFieldOctal(entry.gid, 8), 116);
  hdr.set(tarFieldOctal(entry.size, 12), 124);
  hdr.set(tarFieldOctal(entry.mtime, 12), 136);
  // The checksum field counts as spaces while the checksum is computed.
  hdr.fill(0x20, 148, 156);
  hdr[156] = entry.type === '0' ? 0x30 : Buffer.from(entry.type, 'latin1')[0];
  hdr.set(tarFieldStr(entry.linkname || '', 100), 157);
  Buffer.from('ustar\0', 'latin1').copy(hdr, 257);
  Buffer.from('00', 'ascii').copy(hdr, 263);
  hdr.set(tarFieldStr(entry.uname || '', 32), 265);
  hdr.set(tarFieldStr(entry.gname || '', 32), 297);
  hdr.set(tarFieldStr(prefix, 155), 345);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += hdr[i];
  Buffer.from(sum.toString(8).padStart(6, '0') + ' \0', 'latin1').copy(hdr, 148);
  return hdr;
}

function tarWrite(members) {
  const out = [];
  for (const m of members) {
    if (m.rawHeader && !m.modified) {
      out.push(m.rawHeader);
      if (m.data) {
        out.push(m.data);
        const pad = (512 - (m.data.length % 512)) % 512;
        if (pad) out.push(Buffer.alloc(pad));
      }
      continue;
    }
    out.push(tarHeaderFor(m));
    if (m.data) {
      out.push(m.data);
      const pad = (512 - (m.data.length % 512)) % 512;
      if (pad) out.push(Buffer.alloc(pad));
    }
  }
  out.push(Buffer.alloc(1024)); // two EOF blocks
  return Buffer.concat(out);
}

// -----------------------------------------------------------------------------
// CEK cache: ~/.cache/lg-ipk-download/ncg/<app_id>.json
// -----------------------------------------------------------------------------

function defaultCacheDir() {
  const env = process.env.NCG_CACHE_DIR;
  if (env) return path.resolve(env);
  return path.join(os.homedir(), '.cache', 'lg-ipk-download', 'ncg');
}

function cachePath(appId, cacheDir) {
  return path.join(cacheDir, `${appId}.json`);
}

function loadCache(appId, cacheDir) {
  const p = cachePath(appId, cacheDir);
  if (!fs.existsSync(p)) return { app_id: appId, entries: [] };
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function saveCache(doc, cacheDir) {
  const p = cachePath(doc.app_id, cacheDir);
  fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
  fs.writeFileSync(p, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
}

function findEntry(cid, appId, cacheDir) {
  const candidates = [];
  if (appId) candidates.push(appId);
  if (fs.existsSync(cacheDir)) {
    for (const f of fs.readdirSync(cacheDir).sort()) {
      if (!f.endsWith('.json')) continue;
      const stem = f.slice(0, -5);
      if (!candidates.includes(stem)) candidates.push(stem);
    }
  }
  for (const app of candidates) {
    const doc = loadCache(app, cacheDir);
    for (const e of doc.entries || []) {
      if (e.cid === cid) return e;
    }
  }
  return null;
}

function entryToKeyIv(entry) {
  const cek = Buffer.from(entry.cek_b64, 'base64');
  if (cek.length !== 32) throw new Error(`expected 32-byte CEK, got ${cek.length}`);
  return { key: cek.subarray(0, 16), iv: cek.subarray(16, 32) };
}

// -----------------------------------------------------------------------------
// Commands
// -----------------------------------------------------------------------------

function printableRatio(data, sample = 4096) {
  const head = data.subarray(0, sample);
  if (head.length === 0) return 0;
  let ok = 0;
  for (const b of head) if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) ok++;
  return ok / head.length;
}

const pct = f => `${Math.round(f * 100)}%`;

function cmdCacheList(args) {
  const cacheDir = args.cacheDir;
  if (!fs.existsSync(cacheDir)) {
    console.log(`(no cache at ${cacheDir})`);
    return 0;
  }
  let any = false;
  for (const f of fs.readdirSync(cacheDir).sort()) {
    if (!f.endsWith('.json')) continue;
    const doc = JSON.parse(fs.readFileSync(path.join(cacheDir, f), 'utf8'));
    for (const e of doc.entries || []) {
      any = true;
      console.log(`${doc.app_id}\t sid=${e.sid || ''}\t cid=${e.cid || ''}\t ` +
        `obtained=${e.obtained_at || '?'}`);
    }
  }
  if (!any) console.log(`(cache dir ${cacheDir} is empty)`);
  return 0;
}

function cmdCacheAdd(args) {
  const cek = Buffer.from(args['cek-b64'], 'base64');
  if (cek.length !== 32) {
    console.error(`error: --cek-b64 decodes to ${cek.length} bytes, expected 32`);
    return 2;
  }
  const doc = loadCache(args['app-id'], args.cacheDir);
  const entry = {
    sid: args.sid,
    cid: args.cid,
    cek_b64: args['cek-b64'],
    key_hex: cek.subarray(0, 16).toString('hex'),
    iv_hex: cek.subarray(16, 32).toString('hex'),
    source: args.source || 'manual',
    obtained_at: args.date || 'unknown',
  };
  doc.entries = (doc.entries || []).filter(
    e => !(e.cid === args.cid && e.sid === args.sid));
  doc.entries.push(entry);
  saveCache(doc, args.cacheDir);
  console.log(`cached ${args['app-id']} sid=${args.sid} cid=${args.cid}`);
  return 0;
}

function cmdCacheRemove(args) {
  const doc = loadCache(args['app-id'], args.cacheDir);
  const before = (doc.entries || []).length;
  doc.entries = (doc.entries || []).filter(e => e.cid !== args.cid);
  if (doc.entries.length === before) {
    console.log(`no entry with cid=${args.cid} for ${args['app-id']}`);
    return 1;
  }
  saveCache(doc, args.cacheDir);
  console.log(`removed cid=${args.cid} from ${args['app-id']}`);
  return 0;
}

function resolveKeyIv(args, cid) {
  if (args.key && args.iv) {
    return { key: Buffer.from(args.key, 'hex'), iv: Buffer.from(args.iv, 'hex') };
  }
  const entry = findEntry(cid, args['app-id'] || null, args.cacheDir);
  if (!entry) {
    console.error(`error: no cached CEK for cid=${cid}; run \`cache add\` first ` +
      `(or pass --key/--iv)`);
    return null;
  }
  return entryToKeyIv(entry);
}

function cmdDecryptFile(args) {
  const buf = fs.readFileSync(args.file);
  const { bodySize, cid } = parseHeader(buf);
  if (!cid) {
    console.error('error: NCG header has no <cid>');
    return 2;
  }
  if (args.cid && args.cid !== cid) {
    console.error(`error: file cid ${cid} != --cid ${args.cid}`);
    return 2;
  }
  const resolved = resolveKeyIv(args, cid);
  if (!resolved) return 2;
  const payload = buf.subarray(512 + bodySize);
  const dec = decryptPayload(payload, resolved.key, resolved.iv, seedFor(cid));
  if (isNcg(dec)) {
    console.error('verify: error: output still starts with the NCG magic ' +
      '(wrong key/iv?)');
    return 1;
  }
  const ratio = printableRatio(dec);
  const verdict = ratio >= 0.9 ? 'text-like' : 'binary-looking';
  if (args.out) {
    fs.writeFileSync(args.out, dec);
    console.log(`${args.file} -> ${args.out} (${dec.length} bytes, cid=${cid} ` +
      `seed=${seedFor(cid)})`);
    console.log(`verify: ok (${dec.length} bytes, ${pct(ratio)} printable, ` +
      `${verdict})`);
  } else {
    // keep the data stream clean: verification goes to stderr
    console.error(`verify: ok (${args.file}: ${dec.length} bytes, ${pct(ratio)} ` +
      `printable, ${verdict})`);
    process.stdout.write(dec);
  }
  return 0;
}

function repackDataTar(body, args) {
  const tar = zlib.gunzipSync(body);
  const members = tarRead(tar);
  const replaced = [];
  for (const m of members) {
    if (m.type !== '0') continue;
    if (!isNcg(m.data)) continue;
    const { bodySize, cid } = parseHeader(m.data);
    if (!cid) throw new Error(`${m.name}: NCG header has no <cid>`);
    const resolved = resolveKeyIv(args, cid);
    if (!resolved) throw new Error(`no CEK for ${m.name} (cid=${cid})`);
    const dec = decryptPayload(m.data.subarray(512 + bodySize),
      resolved.key, resolved.iv, seedFor(cid));
    m.data = dec;
    m.size = dec.length;
    m.modified = true;
    replaced.push({ name: m.name, old: m.data.length, newSize: dec.length });
  }
  return { gz: zlib.gzipSync(tarWrite(members), { mtime: Math.floor(Date.now() / 1000) }),
    replaced };
}

function cmdDecryptIpk(args) {
  const data = fs.readFileSync(args.ipk);
  const members = arRead(data);
  const outMembers = [];
  const replaced = [];
  for (const { hdr, body } of members) {
    const name = arMemberName(hdr);
    if (name === 'data.tar.gz') {
      let rep;
      try {
        rep = repackDataTar(body, args);
      } catch (e) {
        console.error(`error: ${e.message}`);
        return 1;
      }
      if (rep.replaced.length === 0) {
        console.error('error: no NCG files found in data.tar.gz');
        return 1;
      }
      const sizeHdr = Buffer.from(hdr);
      sizeHdr.fill(0x20, AR_SIZE_OFF, AR_SIZE_OFF + 10);
      Buffer.from(String(rep.gz.length).padEnd(10, ' '), 'ascii')
        .copy(sizeHdr, AR_SIZE_OFF);
      outMembers.push({ hdr: sizeHdr, body: rep.gz });
      for (const r of rep.replaced) {
        console.log(`  replaced ${r.name} (${r.old}B NCG -> ${r.newSize}B plaintext)`);
      }
      replaced.push(...rep.replaced);
    } else {
      outMembers.push({ hdr, body });
    }
  }
  if (replaced.length === 0) {
    console.error('error: no NCG files found in data.tar.gz');
    return 1;
  }
  fs.writeFileSync(args.out, arWrite(outMembers));
  console.log(`${args.ipk} -> ${args.out} (${data.length}B -> ` +
    `${fs.statSync(args.out).size}B)`);
  return verifyRepacked(args.out, members, replaced.map(r => r.name));
}

// Verify a repacked IPK against its input. Returns 0 on success.
// Checks, in order:
//   1. the output is a valid ar archive with the standard three members
//   2. the member set/order matches the input and every member that was not
//      replaced is byte-identical to it
//   3. data.tar.gz is a readable gzip+tar
//   4. no regular member is still NCG-encrypted
//   5. advisory: replaced members that do not look like text are warned about
//      (NCG files in store apps are html/js/css; a binary result usually means
//      the wrong CEK)
function verifyRepacked(outPath, inMembers, replacedNames) {
  const errors = [];
  const warnings = [];
  let outMembers;
  try {
    outMembers = arRead(fs.readFileSync(outPath));
  } catch (e) {
    console.error(`verify: error: output is not a valid IPK: ${e.message}`);
    return 1;
  }
  const outNames = outMembers.map(m => arMemberName(m.hdr));
  for (const req of ['debian-binary', 'control.tar.gz', 'data.tar.gz']) {
    if (!outNames.includes(req)) errors.push(`missing ar member ${req}`);
  }
  const inNames = inMembers.map(m => arMemberName(m.hdr));
  if (inNames.length !== outNames.length ||
      inNames.some((n, i) => n !== outNames[i])) {
    errors.push('ar member set or order differs from the input');
  }
  const modified = new Set([...replacedNames, 'data.tar.gz']);
  const inByName = new Map(inMembers.map(m => [arMemberName(m.hdr), m.body]));
  for (const { hdr, body } of outMembers) {
    const n = arMemberName(hdr);
    if (!modified.has(n) &&
        (!inByName.has(n) || !inByName.get(n).equals(body))) {
      errors.push(`${n} differs from the input but was not replaced`);
    }
  }
  let nFiles = 0;
  if (outNames.includes('data.tar.gz')) {
    try {
      const byName = new Map(outMembers.map(m => [arMemberName(m.hdr), m.body]));
      const tar = zlib.gunzipSync(byName.get('data.tar.gz'));
      const repSet = new Set(replacedNames);
      const left = [];
      for (const m of tarRead(tar)) {
        if (m.type !== '0') continue;
        nFiles++;
        if (isNcg(m.data)) {
          left.push(m.name);
        } else if (repSet.has(m.name) && printableRatio(m.data) < 0.9) {
          warnings.push(`${m.name} decrypted but does not look like text ` +
            `(${pct(printableRatio(m.data))} printable)`);
        }
      }
      if (left.length) {
        errors.push(`${left.length} members still NCG-encrypted: ` +
          left.slice(0, 5).join(', '));
      }
    } catch (e) {
      errors.push(`data.tar.gz unreadable: ${e.message}`);
    }
  }
  for (const w of warnings) console.error(`verify: warning: ${w}`);
  if (errors.length) {
    for (const e of errors) console.error(`verify: error: ${e}`);
    console.error(`verify: FAILED for ${outPath}`);
    return 1;
  }
  console.log(`verify: ok (${outPath}: ${outNames.length} ar members, ` +
    `${nFiles} files in data.tar.gz, 0 NCG remaining, ` +
    `${replacedNames.length} replaced, untouched members identical)`);
  return 0;
}

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------

const COMMANDS = {
  'cache list': {},
  'cache add': { required: ['app-id', 'sid', 'cid', 'cek-b64'],
    optional: ['source', 'date'] },
  'cache remove': { required: ['app-id', 'cid'] },
  'decrypt-file': { positional: 'file',
    optional: ['cid', 'key', 'iv', 'out'] },
  'decrypt-ipk': { positional: 'ipk', required: ['out'],
    optional: ['app-id'] },
};

function usage() {
  console.error(`usage: ncg-decrypt [--cache-dir DIR]
    cache list
    cache add --app-id ID --sid SID --cid CID --cek-b64 B64 [--source TXT] [--date D]
    cache remove --app-id ID --cid CID
    decrypt-file FILE [--cid CID] [--key HEX] [--iv HEX] [--out PATH]
    decrypt-ipk IPK --out IPK [--app-id ID]`);
}

function parseArgs(argv) {
  const args = { cacheDir: defaultCacheDir() };
  let cmd = '';
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a === '--cache-dir') {
      args.cacheDir = argv[++i] ?? '';
    } else if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const name = eq === -1 ? a.slice(2) : a.slice(2, eq);
      let val;
      if (eq !== -1) {
        val = a.slice(eq + 1);
      } else {
        val = argv[++i];
        if (val === undefined || (val.startsWith('--') && val !== '--')) {
          usage();
          process.exit(2);
        }
      }
      if (cmd === '' && !COMMANDS['cache add'].optional.includes(name) &&
          name !== 'app-id' && name !== 'sid' && name !== 'cid' &&
          name !== 'cek-b64') {
        usage();
        process.exit(2);
      }
      args[name] = val;
    } else {
      if (cmd === '' && (a === 'cache' || a === 'decrypt-file' || a === 'decrypt-ipk')) {
        cmd = a;
        if (a === 'cache') cmd = 'cache ' + (argv[++i] ?? '');
      } else if (cmd === 'cache list' || cmd === 'cache add' ||
                 cmd === 'cache remove') {
        usage();
        process.exit(2);
      } else {
        const spec = COMMANDS[cmd];
        if (spec && spec.positional && !args[spec.positional]) {
          args[spec.positional] = a;
        } else {
          usage();
          process.exit(2);
        }
      }
    }
    i++;
  }
  if (!COMMANDS[cmd]) {
    usage();
    process.exit(2);
  }
  const spec = COMMANDS[cmd];
  if (spec.positional && !args[spec.positional]) {
    usage();
    process.exit(2);
  }
  for (const req of spec.required || []) {
    if (!args[req]) {
      console.error(`error: ${cmd} requires --${req.replace(/-/g, '-')}`);
      usage();
      process.exit(2);
    }
  }
  return { cmd, args };
}

function main(argv) {
  const { cmd, args } = parseArgs(argv);
  try {
    switch (cmd) {
      case 'cache list': return cmdCacheList(args);
      case 'cache add': return cmdCacheAdd(args);
      case 'cache remove': return cmdCacheRemove(args);
      case 'decrypt-file': return cmdDecryptFile(args);
      case 'decrypt-ipk': return cmdDecryptIpk(args);
    }
  } catch (e) {
    console.error(`error: ${e.message}`);
    return 1;
  }
  return 1;
}

module.exports = {
  NCG_MAGIC, TABLE,
  ctrXor, parseHeader, seedFor, decryptPayload,
  arRead, arWrite, arMemberName, isNcg,
  tarRead, tarWrite,
  defaultCacheDir, loadCache, saveCache, findEntry, entryToKeyIv,
  printableRatio, verifyRepacked,
};

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}
