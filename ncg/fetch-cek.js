#!/usr/bin/env node
// TV-native CEK fetch (all-node): one Right Object exchange per app, run with
// the TV's own libncg_agent.so on the TV itself.
//
// Why: the RO request body (deviceid/p/A/hmac) is computed inside the TV's ARM
// libncg_agent.so, so that library has to run somewhere. Running it natively on
// the TV means the request leaves from the TV's own IP, the signed SDX headers
// never leave the TV, and the HTTP POST uses node's own
// networking (native DNS -- no static-glibc caveat).
//
// What it does (one live RO exchange, then nothing more touches LG):
//   1. pick one NCG file out of the given encrypted IPK (host side)
//   2. push the driver (tv/ro-exchange.js), the N-API addon
//      (ncg/dist/ncg_native.node) and the NCG file to /tmp/ncgrow
//   3. the driver: SDX headers (luna) -> applicense (sid + RO URL) ->
//      addon init / makeRequest / save -> CEK; --verify-file proves the CEK
//      against the pushed NCG file through the library itself
//   4. capture the CEK from the driver's JSON line (host side; fallback:
//      the TV library log /var/log/ncgdrm-*.log)
//   5. cache the CEK locally (lg-ipk cache add)
//   6. clean up /tmp/ncgrow on the TV (it is also wiped on reboot)
//
// Prerequisites: ares-setup-device + expect (same as lib/tv.sh), and a
// prebuilt addon:
//   ncg/build.sh
//
// Usage:
//   lg-ipk fetch-cek --app-id <id> --ipk <file> [options]
//
// Options:
//       --version <version>   App version (default: from IPK control)
//       --sid <sid>           Skip the applicense lookup and use this SID
//       --ro-url <url>        Skip the applicense lookup and use this RO URL
//       --country <code>      Store region for the applicense lookup
//                             (default: the TV's current region)
//       --device <profile>    ares-setup-device profile (default device)
//       --device-id <mac>     Override the TV's eth0 MAC read by the driver
//       --skip-cache          Print the CEK without caching it
//       --keep-remote         Leave /tmp/ncgrow on the TV
//   -h, --help                Show this help
//
// Keep this rare: repeated RO requests from one device risk the device being
// blocked by LG. Once the CEK is cached, everything is offline
// (lg-ipk decrypt).
'use strict';

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const m = require('./ncg-decrypt');
const cache = require('./cache');
const parseOptions = require('../lib/parse-options');

const ROOT = path.resolve(__dirname, '..');
const TV = path.join(ROOT, 'lib', 'tv.sh');
const WORK = '/tmp/ncgrow';
// Relative on purpose: every tv.sh spawn runs from the repo root, so the
// remote-side commands and the scp source paths stay identical to what the
// TV (and the docs) expect.
const DRIVER = 'tv/ro-exchange.js';
const ADDON = 'ncg/dist/ncg_native.node';

const USAGE = `Usage: lg-ipk fetch-cek --app-id <id> --ipk <file> [options]

Options:
      --version <version>   App version (default: from IPK control)
      --sid <sid>           Skip the applicense lookup and use this SID
      --ro-url <url>        Skip the applicense lookup and use this RO URL
      --country <code>      Store region (default: the TV's current region)
      --device <profile>    ares-setup-device profile (default device)
      --device-id <mac>     Override the TV's eth0 MAC
      --skip-cache          Print the CEK without caching it
      --keep-remote         Leave temporary files on the TV
  -h, --help                Show this help`;

function today() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}` +
         `-${String(d.getDate()).padStart(2, '0')}`;
}

function parseCli(argv) {
  const { options: args, positional } = parseOptions(argv, {
    values: ['app-id', 'ipk', 'version', 'sid', 'ro-url', 'country', 'device', 'device-id'],
    flags: ['skip-cache', 'keep-remote']
  });
  if (positional.length) {
    throw { usage: true, message: `unexpected argument: ${positional[0]}` };
  }
  const app = args['app-id'] || '';
  const ipk = args.ipk || '';
  if (!app || !ipk)
    throw { usage: true,
            message: USAGE };
  let country = args.country || '';
  if (country) {
    if (!/^(?:[A-Za-z]{2}|C01)$/i.test(country))
      throw { usage: true,
              message: '--country must be a two-letter code such as US, DE, or CN' };
    country = country.toUpperCase();
    if (country === 'C01') country = 'CN';
  }
  return {
    app, ipk,
    version: args.version || '',
    sid: args.sid || '',
    roUrl: args['ro-url'] || '',
    deviceId: args['device-id'] || '',
    deviceProfile: args.device || '',
    country,
    doCache: !args['skip-cache'],
    keepRemote: Boolean(args['keep-remote'])
  };
}

function run(argv) {
  const cli = parseCli(argv);
  const { app, ipk, deviceId, deviceProfile, roUrl, keepRemote, country } = cli;
  let { version, sid, doCache } = cli;
  if (!fs.existsSync(ipk)) {
    process.stderr.write(`error: IPK not found: ${ipk}\n`);
    process.exit(1);
  }
  if (!fs.existsSync(path.join(ROOT, ADDON))) {
    process.stderr.write(`error: ${ADDON} not found; run ncg/build.sh first\n`);
    process.exit(1);
  }

  const env = Object.assign({}, process.env);
  if (env.NCG_CACHE_DIR) env.NCG_CACHE_DIR = cache.defaultCacheDir();
  if (deviceProfile) env.TV_DEVICE = deviceProfile;

  function tv(...args) {
    return childProcess.spawnSync(TV, args, {
      cwd: ROOT, env, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024
    });
  }
  // Mirrors the old script's `set -e`: an unexpected transport failure aborts
  // with that exit code.
  function tvOrDie(...args) {
    const r = tv(...args);
    if (r.stderr) process.stderr.write(r.stderr);
    if (r.error) throw { message: `error: ${TV} ${args[0]} failed: ${r.error.message}` };
    if (r.status !== 0) process.exit(r.status || 1);
  }
  function cleanupRemote() {
    if (keepRemote) {
      process.stdout.write(`keeping ${WORK} on the TV (--keep-remote)\n`);
    } else {
      const r = tv('run', `rm -rf ${WORK}`);
      if (r.stderr) process.stderr.write(r.stderr);
    }
  }

  try {
    // 1. pick one NCG file -------------------------------------------------
    process.stdout.write(`\n== pick one NCG file from ${ipk}\n`);
    const pickDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncg-pick.'));
    const ipkMembers = {};
    for (const { hdr, body } of m.arRead(fs.readFileSync(ipk)))
      ipkMembers[m.arMemberName(hdr)] = body;
    const dataTar = m.tarRead(zlib.gunzipSync(ipkMembers['data.tar.gz']));
    const prefix = `./usr/palm/applications/${app}/`;
    const cands = [], other = [];
    for (const e of dataTar) {
      if (!e.data || !m.isNcg(e.data)) continue;
      if (e.name.startsWith(prefix) && e.name.endsWith('/index.html')) cands.push(e);
      else other.push(e);
    }
    const chosen = (cands.length ? cands : other)[0];
    if (!chosen) {
      fs.rmSync(pickDir, { recursive: true, force: true });
      throw { message: 'error: no NCG files found in the IPK' };
    }
    const ngcBase = chosen.name.split('/').pop();
    const ngcLocal = path.join(pickDir, ngcBase);
    fs.writeFileSync(ngcLocal, chosen.data);
    const cid = m.parseHeader(chosen.data).cid;
    process.stdout.write(`picked: ${ngcLocal} (cid=${cid})\n`);

    // 2. version --------------------------------------------------------------
    if (!version) {
      const controlTar = m.tarRead(zlib.gunzipSync(ipkMembers['control.tar.gz']));
      for (const e of controlTar) {
        if (e.name.endsWith('control') && e.data) {
          for (const line of e.data.toString('utf8').split('\n'))
            if (line.startsWith('Version:')) version = line.split(': ', 2)[1].trim();
          break;
        }
      }
    }
    if (!version) {
      fs.rmSync(pickDir, { recursive: true, force: true });
      throw { message: 'error: could not determine app version (pass --version)' };
    }
    process.stdout.write(`version=${version}\n`);

    // 3. push ---------------------------------------------------------------
    process.stdout.write(`\n== push driver + addon + NCG file to ${WORK} on the TV\n`);
    tvOrDie('run', `rm -rf ${WORK} && mkdir -p ${WORK}/files ${WORK}/secret`);
    tvOrDie('push', DRIVER, `${WORK}/ro-exchange.js`);
    tvOrDie('push', ADDON, `${WORK}/ncg_native.node`);
    tvOrDie('push', ngcLocal, `${WORK}/files/${ngcBase}`);

    // 4. THE exchange ------------------------------------------------------
    process.stdout.write('\n== running the RO exchange on the TV (one live request to LG)\n');
    let tvArgs = `--addon ${WORK}/ncg_native.node --app-id '${app}' ` +
      `--version '${version}' --verify-file ${WORK}/files/${ngcBase}`;
    if (sid) tvArgs += ` --sid '${sid}'`;
    if (roUrl) tvArgs += ` --ro-url '${roUrl}'`;
    if (deviceId) tvArgs += ` --device-id '${deviceId}'`;
    if (country) tvArgs += ` --country '${country}'`;

    // NODE_PATH so the driver's require('palmbus') resolves: the TV's node does not
    // search those global module directories by default.
    const drv = tv('run', `rm -f /var/log/ncgdrm-*.log 2>/dev/null; ` +
      `NODE_PATH=/usr/lib/node_modules:/usr/lib/nodejs ` +
      `node ${WORK}/ro-exchange.js ${tvArgs}`);
    if (drv.stderr) process.stderr.write(drv.stderr);
    const driverOut = drv.stdout || '';
    if (drv.status !== 0) {
      process.stderr.write('warning: driver exited non-zero (the RO exchange itself may have\n');
      process.stderr.write('warning: succeeded -- checking for a recoverable CEK)\n');
    }
    if (driverOut) process.stdout.write(driverOut);

    // 5. capture CEK ----------------------------------------------------------
    process.stdout.write('\n== capture CEK\n');
    let cekB64 = '';
    let licCid = '';
    let verified = '';
    {
      // The driver prints exactly one JSON line, but the TV transport captures
      // the [NCG_Agent] library log (from libncg_agent) into the same output.
      // Scan for the first line that parses as a JSON object rather than parsing
      // the whole (log-polluted) blob.
      let doc;
      for (const line of driverOut.split('\n')) {
        const t = line.trim();
        if (!t.startsWith('{')) continue;
        try {
          const o = JSON.parse(t);
          if (o && typeof o === 'object') { doc = o; break; }
        } catch (e) { /* not the JSON line */ }
      }
      if (!doc) {
        process.stderr.write('no JSON line from the driver: ' + driverOut.slice(-300) + '\n');
      } else if (!doc.ok) {
        process.stderr.write(`driver failed at stage ${doc.stage}: ${doc.error}\n`);
      } else {
        // The driver's own sid (if any) is authoritative, even when --sid was
        // given (same as the old script's `read` overwriting all fields).
        sid = doc.sid || '';
        cekB64 = doc.cek ? doc.cek.b64 : '';
        licCid = doc.cek ? doc.cek.cid : '';
        verified = doc.verified === true ? 'yes' : 'no';
      }
    }
    if (licCid && licCid !== cid)
      process.stderr.write(`note: license cid ${licCid} differs from the picked file's cid ${cid}\n`);
    // Fallback: the library log on the TV, which the library writes as it parses
    // the RO response (used when the driver died before printing JSON).
    if (!cekB64) {
      const g = tv('run',
        `grep -hoE '<cek>[A-Za-z0-9+/]{43}=<\\/cek>' /var/log/ncgdrm-*.log 2>/dev/null | head -1`);
      if (g.stderr) process.stderr.write(g.stderr);
      const hit = (g.stdout || '').match(/[A-Za-z0-9+/]{43}=/);
      if (hit) {
        cekB64 = hit[0];
        process.stdout.write('CEK recovered from the TV library log\n');
      }
    }
    if (!cekB64) {
      fs.rmSync(pickDir, { recursive: true, force: true });
      cleanupRemote();
      throw { message: 'error: no CEK in the driver output or the library log' };
    }
    process.stdout.write(`CEK b64: ${cekB64}\n`);
    if (verified) process.stdout.write(`verify-file: ${verified}\n`);
    if (!sid) {
      process.stdout.write('warning: no sid available (driver produced no JSON and no --sid); cannot cache\n');
      doCache = false;
    }

    // 6. cache -----------------------------------------------------------------
    if (doCache) {
      process.stdout.write('\n== cache the CEK locally (offline from now on)\n');
      const date = today();
      const r = childProcess.spawnSync(process.execPath,
        [path.join(ROOT, 'bin', 'lg-ipk.js'), 'cache', 'add',
         '--app-id', app, '--sid', sid, '--cid', cid, '--cek-b64', cekB64,
         '--source', `TV-native exchange ${date}`, '--date', date],
        { cwd: ROOT, env, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
      if (r.stdout) process.stdout.write(r.stdout);
      if (r.stderr) process.stderr.write(r.stderr);
      if (r.status !== 0) {
        // set -e parity: a failed cache add aborts before the cleanup step
        // (the TV dir is wiped on reboot anyway).
        process.exit(r.status || 1);
      }
    }

    // 7. cleanup ------------------------------------------------------------------
    process.stdout.write('\n== cleanup\n');
    fs.rmSync(pickDir, { recursive: true, force: true });
    cleanupRemote();
    process.stdout.write(`done. sid=${sid} cid=${cid} app=${app}\n`);
    process.stdout.write(`next: lg-ipk decrypt ${ipk} --output <path> --app-id ${app}\n`);
  } catch (err) {
    if (err && err.usage) {
      process.stderr.write(`${err.message}\n`);
      process.exit(2);
    }
    process.stderr.write(`${(err && err.message) || err}\n`);
    process.exit(1);
  }
}

module.exports = { help: `${USAGE}\n`, run };

if (require.main === module) {
  require('../bin/lg-ipk').run(['fetch-cek', ...process.argv.slice(2)]);
}
