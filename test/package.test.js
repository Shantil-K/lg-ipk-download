'use strict';

const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const zlib = require('node:zlib');

const ROOT = path.resolve(__dirname, '..');

test('text detection counts Unicode characters and rejects control characters', () => {
  const { printableRatio } = require('../ncg/ncg-decrypt');
  assert.equal(printableRatio(Buffer.from('/* \u4e2d\u6587\u6ce8\u91ca */\nbody { color: red; }\t\r\n')), 1);
  assert.equal(printableRatio(Buffer.from('A\u{1f600}\0')), 2 / 3);
  assert.equal(printableRatio(Buffer.from('\u007f\u0085')), 0);
});

test('text detection rejects malformed and incomplete UTF-8', () => {
  const { printableRatio } = require('../ncg/ncg-decrypt');
  assert.equal(printableRatio(Buffer.from([0xff])), 0);
  assert.equal(printableRatio(Buffer.from([0x61, 0xe4, 0xb8])), 0);
});

test('text detection tolerates UTF-8 characters split by the sampling boundary', () => {
  const { printableRatio } = require('../ncg/ncg-decrypt');
  for (const character of ['\u00e9', '\u4e2d', '\u{1f600}']) {
    for (let cut = 1; cut < Buffer.byteLength(character); cut++) {
      const data = Buffer.from('a'.repeat(4096 - cut) + character);
      assert.equal(printableRatio(data), 1);
    }
  }
});

test('the npm tarball installs working commands and passes an offline smoke test', () => {
  const temporary = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lg-ipk-package-')));
  try {
    const result = JSON.parse(execFileSync('npm', [
      'pack', '--json', '--pack-destination', temporary
    ], { cwd: ROOT, encoding: 'utf8' }));
    const [packed] = Array.isArray(result) ? result : Object.values(result);
    const files = new Set(packed.files.map(file => file.path));
    for (const required of [
      'package.json',
      'LICENSE',
      'README.md',
      'ncg/README.md',
      'bin/lg-ipk.js',
      'lib/download.js',
      'lib/search.js',
      'lib/parse-options.js',
      'lib/store.js',
      'lib/tv.sh',
      'tv/download-ipk.js',
      'tv/ro-exchange.js',
      'ncg/ncg-decrypt.js',
      'ncg/fetch-cek.js',
      'ncg/cache.js',
      'ncg/build.sh',
      'ncg/Dockerfile',
      'ncg/ncg_native.c',
      'ncg/ncg_napi.h',
      'ncg/dist/ncg_native.node'
    ]) {
      assert.ok(files.has(required), `missing runtime/build file: ${required}`);
    }
    for (const file of files) {
      assert.ok(!/^(?:cache|test|\.github|\.qwen)\//.test(file),
        `unexpected package file: ${file}`);
      assert.ok(!file.endsWith('.ipk'), `downloaded IPK included: ${file}`);
    }

    const prefix = path.join(temporary, 'installed');
    execFileSync('npm', [
      'install', '--global', '--prefix', prefix,
      '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
      path.join(temporary, packed.filename)
    ], { cwd: temporary, encoding: 'utf8' });
    const command = path.join(prefix, 'bin', 'lg-ipk');
    const help = execFileSync(command, ['--help'], {
      cwd: temporary, encoding: 'utf8'
    });
    assert.match(help, /Usage: lg-ipk <command>/);
    assert.doesNotMatch(help, /Options:|--cache-dir|--skip-cache/);
    for (const [subcommand, option, args] of [
      ['download', '--fetch-cek', ['--country', 'US']],
      ['search', '--country', ['--country', 'US']],
      ['decrypt', '--key <hex>', ['--output', 'unused']],
      ['fetch-cek', '--skip-cache', ['--app-id', 'com.example.smoke']],
      ['cache', '--cek-b64', ['list']]
    ]) {
      assert.ok(help.includes(`  ${subcommand} `), `missing command: ${subcommand}`);
      const subcommandHelp = execFileSync(command, [subcommand, '--help'], {
        cwd: temporary, encoding: 'utf8'
      });
      assert.match(subcommandHelp, new RegExp(`Usage: lg-ipk ${subcommand}`));
      assert.ok(subcommandHelp.includes(option), `missing ${subcommand} option: ${option}`);
      assert.doesNotMatch(subcommandHelp, /--out <path>/);
      const optionLines = subcommandHelp.split('Options:\n')[1].split('\n\n')[0].split('\n');
      for (const line of optionLines.filter(line => line.trim())) {
        if (/^\s+-/.test(line)) {
          assert.equal(line.indexOf('--'), 6, `${subcommand}: ${line}`);
          const columns = /^(\s+.*?\S)(\s{2,})(\S.*)$/.exec(line);
          assert.ok(columns, `${subcommand}: ${line}`);
          assert.equal(columns[1].length + columns[2].length, 28, `${subcommand}: ${line}`);
        } else {
          assert.equal(line.length - line.trimStart().length, 28, `${subcommand}: ${line}`);
        }
      }
      if (subcommand === 'search') {
        assert.doesNotMatch(subcommandHelp, /--output|--fetch-cek|--no-decrypt/);
      }
      if (subcommand === 'decrypt') {
        assert.doesNotMatch(subcommandHelp, /--cek-b64|cache add/);
      }
      const helpAfterArgs = execFileSync(command, [subcommand, ...args, '--help'], {
        cwd: temporary, encoding: 'utf8'
      });
      assert.equal(helpAfterArgs, subcommandHelp);
    }
    for (const name of ['ncg-decrypt', 'ncg-fetch-cek']) {
      assert.ok(!fs.existsSync(path.join(prefix, 'bin', name)),
        `unexpected standalone command: ${name}`);
    }
    const invalid = spawnSync(command, ['--unknown-option'], {
      cwd: temporary, encoding: 'utf8'
    });
    assert.ifError(invalid.error);
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /unknown option: --unknown-option/);
    for (const [args, message] of [
      [[], 'command is required'],
      [['com.example.smoke'], 'unknown command: com.example.smoke'],
      [['download'], 'app identifier is required'],
      [['search'], 'search keyword is required']
    ]) {
      const result = spawnSync(command, args, {
        cwd: temporary,
        env: { ...process.env, NCG_CACHE_DIR: path.join(temporary, 'cache') },
        encoding: 'utf8'
      });
      assert.ifError(result.error);
      assert.equal(result.status, 1, JSON.stringify(args));
      assert.ok(result.stderr.includes(`lg-ipk: ${message}`), result.stderr);
    }

    const cache = execFileSync(command, ['cache', 'list', '--cache-dir', './cache'], {
      cwd: temporary,
      env: { ...process.env, NCG_CACHE_DIR: path.join(temporary, 'cache') },
      encoding: 'utf8'
    });
    assert.match(cache, /no cache at/);

    for (const args of [['decrypt'], ['decrypt', '--out'], ['fetch-cek'],
      ['cache'], ['cache', 'add']]) {
      const result = spawnSync(command, args, { cwd: temporary, encoding: 'utf8' });
      assert.ifError(result.error);
      assert.equal(result.status, 2, JSON.stringify(args));
      assert.ok(result.stderr.includes(`Usage: lg-ipk ${args[0]}`), result.stderr);
    }
    for (const [args, status, message] of [
      [['cache', 'list', '--unknown-option', 'value'], 2, 'unknown option'],
      [['cache', 'list', '--unknown-option=value'], 2, 'unknown option'],
      [['cache', 'list', '--cid', 'example'], 2, 'not valid for cache list'],
      [['cache', 'list', '--cache-dir'], 2, '--cache-dir requires a value'],
      [['decrypt', '--unknown-option', 'value'], 2, 'unknown option'],
      [['fetch-cek', '--unknown-option', 'value'], 2, 'unknown option'],
      [['fetch-cek', '--app-id', '--ipk', 'example.ipk'], 2, '--app-id requires a value'],
      [['fetch-cek', '--skip-cache=false'], 2, 'does not accept a value'],
      [['download', 'com.example.smoke', '--output', '--json'], 1, '--output requires a value']
    ]) {
      const result = spawnSync(command, args, {
        cwd: temporary,
        env: { ...process.env, NCG_CACHE_DIR: path.join(temporary, 'cache') },
        encoding: 'utf8'
      });
      assert.ifError(result.error);
      assert.equal(result.status, status, `${JSON.stringify(args)}: ${result.stderr}`);
      assert.ok(result.stderr.includes(message), result.stderr);
    }

    const installed = path.join(prefix, 'lib/node_modules/lg-ipk');
    const imported = execFileSync(process.execPath, ['-e', `
require('./ncg/cache');
if (require.cache[require.resolve('./ncg/ncg-decrypt')]) {
  throw new Error('cache must not depend on the decryption module');
}
for (const name of ['lib/download', 'lib/search',
  'ncg/ncg-decrypt', 'ncg/fetch-cek', 'ncg/cache']) {
  require('./' + name);
}
`], { cwd: installed, encoding: 'utf8' });
    assert.equal(imported, '', 'importing commands must not execute them');
    assert.equal(typeof require(path.join(installed, 'ncg/ncg-decrypt.js')).arRead,
      'function');
    assert.ok(fs.statSync(path.join(installed, 'lib/tv.sh')).mode & 0o111,
      'TV transport must be executable');
    const rejectedCache = spawnSync(process.execPath, [
      path.join(installed, 'ncg/ncg-decrypt.js'),
      '--cache-dir', 'standalone-cache', 'cache', 'list'
    ], { cwd: temporary, encoding: 'utf8' });
    assert.ifError(rejectedCache.error);
    assert.equal(rejectedCache.status, 2);
    assert.match(rejectedCache.stderr, /unexpected argument: list/);
    assert.equal(rejectedCache.stdout, '');
    const standaloneCache = execFileSync(process.execPath, [
      path.join(installed, 'ncg/cache.js'), 'list', '--cache-dir', 'standalone-cache'
    ], { cwd: temporary, encoding: 'utf8' });
    assert.match(standaloneCache, /no cache at standalone-cache/);
    const legacyFetch = execFileSync(process.execPath, [
      path.join(installed, 'ncg/fetch-cek.js'), '--help'
    ], { cwd: temporary, encoding: 'utf8' });
    assert.match(legacyFetch, /^Usage: lg-ipk fetch-cek/);

    const m = require(path.join(installed, 'ncg/ncg-decrypt.js'));
    const app = 'com.example.smoke';
    const cid = '00112233445566778899AABBCCDDEEFF';
    const cek = Buffer.alloc(32, 0x42);
    const key = cek.subarray(0, 16).toString('hex');
    const iv = cek.subarray(16).toString('hex');
    const plaintext = Buffer.from('<html>offline smoke test</html>');
    const cipher = crypto.createCipheriv('aes-128-ctr', cek.subarray(0, 16), cek.subarray(16));
    const header = Buffer.alloc(1024);
    m.NCG_MAGIC.copy(header);
    header.writeUInt16LE(2, 14);
    header.writeUInt32LE(512, 16);
    header.write(`<cid>${cid}</cid>`, 512);
    const encrypted = Buffer.concat([header, cipher.update(plaintext), cipher.final()]);
    // Mismatched extensions ensure format detection uses contents.
    fs.writeFileSync(path.join(temporary, 'index.ipk'), encrypted);
    const tar = (name, data) => m.tarWrite([{
      name, data, size: data.length, type: '0', mode: 0o644, uid: 0, gid: 0, mtime: 0
    }]);
    const member = (name, body) => ({
      hdr: Buffer.from(`${`${name}/`.padEnd(16)}${'0'.padEnd(12)}` +
        `${'0'.padEnd(6)}${'0'.padEnd(6)}${'100644'.padEnd(8)}` +
        `${String(body.length).padEnd(10)}\x60\n`, 'ascii'),
      body
    });
    const ipk = m.arWrite([
      member('debian-binary', Buffer.from('2.0\n')),
      member('control.tar.gz', zlib.gzipSync(tar('./control', Buffer.from('Version: 1.0.0\n')))),
      member('data.tar.gz', zlib.gzipSync(tar(`./usr/palm/applications/${app}/index.html`, encrypted)))
    ]);
    const fixture = path.join(temporary, 'fixture.ncg');
    fs.writeFileSync(fixture, ipk);
    const mockBin = path.join(temporary, 'mock-bin');
    fs.mkdirSync(mockBin);
    const executable = (name, code) => fs.writeFileSync(path.join(mockBin, name),
      `#!${process.execPath}\n${code}`, { mode: 0o755 });
    executable('ares-setup-device', `
console.log(JSON.stringify([{
  name: 'smoke', default: true,
  deviceinfo: { ip: '127.0.0.1', port: 22, user: 'smoke' },
  details: { privatekey: 'unused-smoke-key' }
}]));
`);
    // Replace only the TV boundary; all installed host-side commands run normally.
    executable('expect', `
const fs = require('node:fs');
const e = process.env;
if (e.TV_MODE === 'push') {
  fs.accessSync(e.TV_SRC);
} else if (e.TV_MODE === 'pull') {
  fs.copyFileSync(e.SMOKE_IPK, e.TV_DST);
} else if (e.TV_CMD.includes('--search')) {
  console.log(JSON.stringify({ ok: true, apps: [{ id: e.SMOKE_APP, name: 'Smoke' }] }));
} else if (e.TV_CMD.includes('ro-exchange.js')) {
  console.log(JSON.stringify({
    ok: true, sid: '1', verified: true, cek: { cid: e.SMOKE_CID, b64: e.SMOKE_CEK }
  }));
} else if (e.TV_CMD.includes('--app-id')) {
  console.log(JSON.stringify({
    ok: true, appId: e.SMOKE_APP, packageVersion: '1.0.0',
    remotePath: '/tmp/lg-ipk-download/smoke.ipk', expectedSize: Number(e.SMOKE_SIZE)
  }));
}
`);
    const env = {
      ...process.env,
      PATH: [mockBin, path.join(prefix, 'bin'), path.dirname(process.execPath),
        process.env.PATH].join(path.delimiter),
      NCG_CACHE_DIR: 'smoke-cache',
      SMOKE_IPK: fixture, SMOKE_SIZE: String(ipk.length),
      SMOKE_APP: app, SMOKE_CID: cid, SMOKE_CEK: cek.toString('base64')
    };
    const run = args => {
      const result = spawnSync(command, args, {
        cwd: temporary, env, encoding: 'utf8'
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, `${args.join(' ')}: ${result.stderr}\n${result.stdout}`);
      return result.stdout;
    };
    const unsupported = path.join(temporary, 'unsupported.ipk');
    fs.writeFileSync(unsupported, 'not an IPK or NCG file');
    const rejectedOutput = path.join(temporary, 'rejected.ipk');
    for (const [args, status, message] of [
      [['decrypt', 'decrypt-file', 'index.ipk', '--output', rejectedOutput],
        2, 'unexpected argument: index.ipk'],
      [['decrypt', 'decrypt-ipk', fixture, '--output', rejectedOutput],
        2, `unexpected argument: ${fixture}`],
      [['decrypt', fixture], 2, 'requires --output'],
      [['decrypt', fixture, '--output', rejectedOutput, '--cid', cid],
        2, '--cid is only valid for a single NCG file'],
      [['decrypt', 'index.ipk', '-o', rejectedOutput, '--key', key],
        2, '--key and --iv must be provided together'],
      [['decrypt', 'index.ipk', '-o', rejectedOutput, '--iv', iv],
        2, '--key and --iv must be provided together'],
      [['decrypt', 'index.ipk', '-o', rejectedOutput, '--key', 'zz'.repeat(16), '--iv', iv],
        2, '--key must contain exactly 32 hexadecimal digits'],
      [['decrypt', 'missing.ipk', '--out', rejectedOutput], 1, 'ENOENT'],
      [['decrypt', unsupported, '--out', rejectedOutput], 1, 'unsupported file format']
    ]) {
      const result = spawnSync(command, args, { cwd: temporary, env, encoding: 'utf8' });
      assert.ifError(result.error);
      assert.equal(result.status, status, result.stderr);
      assert.ok(result.stderr.includes(message), result.stderr);
      assert.ok(!fs.existsSync(rejectedOutput));
    }
    const search = JSON.parse(run(['search', '--json', 'smoke']));
    assert.equal(search.apps[0].id, app);
    const commandKeyword = JSON.parse(run(['search', '--json', 'download']));
    assert.equal(commandKeyword.query, 'download');
    const download = JSON.parse(run(
      ['download', '--json', '--no-decrypt', '--out', 'download.ipk', app]));
    assert.deepEqual(fs.readFileSync(download.output), ipk);
    assert.equal(download.sha256, crypto.createHash('sha256').update(ipk).digest('hex'));
    run(['cache', 'add', '--app-id', app, '--sid', '1',
      '--cid', cid, '--cek-b64', cek.toString('base64')]);
    assert.match(run(['cache', 'list']), /com\.example\.smoke/);
    run(['decrypt', '-o', 'index.html', 'index.ipk']);
    assert.deepEqual(fs.readFileSync(path.join(temporary, 'index.html')), plaintext);
    assert.equal(run(['decrypt', 'index.ipk']), plaintext.toString());
    execFileSync(process.execPath, [
      path.join(installed, 'ncg/ncg-decrypt.js'),
      'index.ipk', '--output', 'standalone.html'
    ], { cwd: temporary, env, encoding: 'utf8' });
    assert.deepEqual(fs.readFileSync(path.join(temporary, 'standalone.html')), plaintext);
    run(['decrypt', fixture, '--out', 'manual.ipk', '--app-id', app]);
    const assertDecrypted = filename => {
      const data = m.arRead(fs.readFileSync(filename))
        .find(entry => m.arMemberName(entry.hdr) === 'data.tar.gz');
      assert.deepEqual(m.tarRead(zlib.gunzipSync(data.body))[0].data, plaintext);
    };
    assertDecrypted(path.join(temporary, 'manual.ipk'));
    run(['decrypt', fixture, '--output', 'explicit.ipk', '--key', key, '--iv', iv,
      '--cache-dir', 'empty-cache']);
    assertDecrypted(path.join(temporary, 'explicit.ipk'));
    assert.equal(run(['decrypt', 'index.ipk', '--key', key, '--iv', iv,
      '--cache-dir', 'empty-cache']), plaintext.toString());
    run(['cache', 'remove', '--app-id', app, '--cid', cid]);
    assert.match(run(['cache', 'list']), /is empty/);
    run(['fetch-cek', '--app-id', app, '--ipk', fixture]);
    assert.match(run(['cache', 'list']), /com\.example\.smoke/);
    run(['cache', 'remove', '--app-id', app, '--cid', cid]);
    const automatic = JSON.parse(run(
      ['download', '--json', '--fetch-cek', '--output', 'automatic.ipk', app]));
    assert.equal(automatic.decryption.status, 'ok');
    assertDecrypted(automatic.decryption.output);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
