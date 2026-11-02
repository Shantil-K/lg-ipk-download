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

test('the npm tarball installs working commands and passes an offline smoke test', () => {
  const temporary = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lg-ipk-package-')));
  try {
    const result = JSON.parse(execFileSync('npm', [
      'pack', '--json', '--pack-destination', temporary
    ], { cwd: ROOT, encoding: 'utf8' }));
    const [packed] = Array.isArray(result) ? result : Object.values(result);
    const files = new Set(packed.files.map(file => file.path));
    for (const required of [
      'bin/lg-ipk-download.js',
      'lib/tv.sh',
      'tv/download-ipk.js',
      'tv/ro-exchange.js',
      'ncg/ncg-decrypt.js',
      'ncg/fetch-cek.js',
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
    const command = path.join(prefix, 'bin', 'lg-ipk-download');
    const help = execFileSync(command, ['--help'], {
      cwd: temporary, encoding: 'utf8'
    });
    assert.match(help, /Usage:\s+lg-ipk-download/);
    assert.match(help, /lg-ipk-download search/);
    const invalid = spawnSync(command, ['--unknown-option'], {
      cwd: temporary, encoding: 'utf8'
    });
    assert.ifError(invalid.error);
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /unknown option: --unknown-option/);

    const decrypt = path.join(prefix, 'bin', 'ncg-decrypt');
    const cache = execFileSync(decrypt, ['cache', 'list'], {
      cwd: temporary,
      env: { ...process.env, NCG_CACHE_DIR: path.join(temporary, 'cache') },
      encoding: 'utf8'
    });
    assert.match(cache, /no cache at/);

    const fetch = spawnSync(path.join(prefix, 'bin', 'ncg-fetch-cek'), [], {
      cwd: temporary, encoding: 'utf8'
    });
    assert.ifError(fetch.error);
    assert.equal(fetch.status, 2);
    assert.match(fetch.stderr, /usage: ncg-fetch-cek/);

    const installed = path.join(prefix, 'lib/node_modules/lg-ipk-download');
    assert.equal(typeof require(path.join(installed, 'ncg/ncg-decrypt.js')).arRead,
      'function');
    assert.ok(fs.statSync(path.join(installed, 'lib/tv.sh')).mode & 0o111,
      'TV transport must be executable');

    const m = require(path.join(installed, 'ncg/ncg-decrypt.js'));
    const app = 'com.example.smoke';
    const cid = '00112233445566778899AABBCCDDEEFF';
    const cek = Buffer.alloc(32, 0x42);
    const plaintext = Buffer.from('<html>offline smoke test</html>');
    const cipher = crypto.createCipheriv('aes-128-ctr', cek.subarray(0, 16), cek.subarray(16));
    const header = Buffer.alloc(1024);
    m.NCG_MAGIC.copy(header);
    header.writeUInt16LE(2, 14);
    header.writeUInt32LE(512, 16);
    header.write(`<cid>${cid}</cid>`, 512);
    const encrypted = Buffer.concat([header, cipher.update(plaintext), cipher.final()]);
    fs.writeFileSync(path.join(temporary, 'index.ncg'), encrypted);
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
    const fixture = path.join(temporary, 'fixture.ipk');
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
    const run = (name, args) => {
      const result = spawnSync(path.join(prefix, 'bin', name), args, {
        cwd: temporary, env, encoding: 'utf8'
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, `${name}: ${result.stderr}\n${result.stdout}`);
      return result.stdout;
    };
    const search = JSON.parse(run('lg-ipk-download', ['search', '--json', 'smoke']));
    assert.equal(search.apps[0].id, app);
    const download = JSON.parse(run('lg-ipk-download',
      ['--json', '--no-decrypt', '--output', 'download.ipk', app]));
    assert.deepEqual(fs.readFileSync(download.output), ipk);
    assert.equal(download.sha256, crypto.createHash('sha256').update(ipk).digest('hex'));
    run('ncg-decrypt', ['cache', 'add', '--app-id', app, '--sid', '1',
      '--cid', cid, '--cek-b64', cek.toString('base64')]);
    assert.match(run('ncg-decrypt', ['cache', 'list']), /com\.example\.smoke/);
    run('ncg-decrypt', ['decrypt-file', 'index.ncg', '--out', 'index.html']);
    assert.deepEqual(fs.readFileSync(path.join(temporary, 'index.html')), plaintext);
    run('ncg-decrypt', ['decrypt-ipk', fixture, '--out', 'manual.ipk', '--app-id', app]);
    const assertDecrypted = filename => {
      const data = m.arRead(fs.readFileSync(filename))
        .find(entry => m.arMemberName(entry.hdr) === 'data.tar.gz');
      assert.deepEqual(m.tarRead(zlib.gunzipSync(data.body))[0].data, plaintext);
    };
    assertDecrypted(path.join(temporary, 'manual.ipk'));
    run('ncg-decrypt', ['cache', 'remove', '--app-id', app, '--cid', cid]);
    assert.match(run('ncg-decrypt', ['cache', 'list']), /is empty/);
    run('ncg-fetch-cek', ['--app-id', app, '--ipk', fixture]);
    assert.match(run('ncg-decrypt', ['cache', 'list']), /com\.example\.smoke/);
    run('ncg-decrypt', ['cache', 'remove', '--app-id', app, '--cid', cid]);
    const automatic = JSON.parse(run('lg-ipk-download',
      ['--json', '--fetch-cek', '--output', 'automatic.ipk', app]));
    assert.equal(automatic.decryption.status, 'ok');
    assertDecrypted(automatic.decryption.output);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
