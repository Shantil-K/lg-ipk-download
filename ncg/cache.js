#!/usr/bin/env node
// Usage:
//   lg-ipk cache <list|add|remove> [options]
//
// Commands:
//   lg-ipk cache list [--cache-dir <dir>]
//   lg-ipk cache add --app-id <id> --sid <sid> --cid <cid> --cek-b64 <base64> \
//     [--source <text>] [--date <date>] [--cache-dir <dir>]
//   lg-ipk cache remove --app-id <id> --cid <cid> [--cache-dir <dir>]

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const parseOptions = require('../lib/parse-options');

const help = `Usage: lg-ipk cache <list|add|remove> [options]

Commands:
  list                      List cached CEKs
  add                       Add or update a CEK
  remove                    Remove a CEK by app ID and content ID

Options:
      --app-id <id>         App ID (required for add/remove)
      --sid <sid>           Right Session ID (required for add)
      --cid <cid>           Content ID (required for add/remove)
      --cek-b64 <base64>    Base64 CEK (required for add)
      --source <text>       Source description (optional for add)
      --date <date>         Acquisition date (optional for add)
      --cache-dir <dir>     Override the CEK cache directory
  -h, --help                Show this help
`;

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

// Key material derivation (verified on webOS 25 firmware,
// libncg_agent.so.2.0.0; see docs/ncg-format.md):
//
//     cek     = base64decode(<cek> from the RO response)    // 32 bytes
//     aes_key = cek[0:16]                                   // raw
//     ctr_iv  = cek[16:32]                                  // raw
function entryToKeyIv(entry) {
  const cek = Buffer.from(entry.cek_b64, 'base64');
  if (cek.length !== 32) throw new Error(`expected 32-byte CEK, got ${cek.length}`);
  return { key: cek.subarray(0, 16), iv: cek.subarray(16, 32) };
}

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

const actions = {
  list: { run: cmdCacheList, required: [], optional: [] },
  add: { run: cmdCacheAdd, required: ['app-id', 'sid', 'cid', 'cek-b64'],
    optional: ['source', 'date'] },
  remove: { run: cmdCacheRemove, required: ['app-id', 'cid'], optional: [] }
};

function run(argv) {
  const { options, positional } = parseOptions(argv, {
    values: ['cache-dir', 'app-id', 'sid', 'cid', 'cek-b64', 'source', 'date']
  });
  const [name] = positional;
  if (!Object.hasOwn(actions, name)) {
    throw { usage: true, message: 'a valid command is required' };
  }
  if (positional.length > 1) {
    throw { usage: true, message: `unexpected argument: ${positional[1]}` };
  }
  const action = actions[name];
  const allowed = new Set(['cache-dir', ...action.required, ...action.optional]);
  for (const option of Object.keys(options)) {
    if (!allowed.has(option)) {
      throw { usage: true, message: `--${option} is not valid for cache ${name}` };
    }
  }
  for (const option of action.required) {
    if (!options[option]) {
      throw { usage: true, message: `cache ${name} requires --${option}` };
    }
  }
  return action.run({ ...options, cacheDir: options['cache-dir'] || defaultCacheDir() });
}

module.exports = {
  help, run,
  defaultCacheDir, loadCache, saveCache, findEntry, entryToKeyIv,
  cacheList: cmdCacheList, cacheAdd: cmdCacheAdd, cacheRemove: cmdCacheRemove
};

if (require.main === module) {
  require('../bin/lg-ipk').run(['cache', ...process.argv.slice(2)]);
}
