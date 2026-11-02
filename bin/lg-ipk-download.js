#!/usr/bin/env node
'use strict';

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TV_TRANSPORT = path.join(ROOT, 'lib', 'tv.sh');
const TV_HELPER = path.join(ROOT, 'tv', 'download-ipk.js');
const DECRYPT_TOOL = path.join(ROOT, 'ncg', 'ncg-decrypt.js');
const FETCH_CEK = path.join(ROOT, 'ncg', 'fetch-cek.js');

function fail(message) {
  process.stderr.write(`lg-ipk-download: ${message}\n`);
  process.exitCode = 1;
}

function usage() {
  process.stdout.write(`Usage:
  lg-ipk-download [options] <internal-app-id|numeric-store-id>
  lg-ipk-download search [options] <keyword>

Commands:
  search <keyword>          Search for apps without downloading

Options:
  -o, --output <path>       Local output path
  -d, --device <name>       ares-setup-device profile name
      --country <code>      Store country/region (e.g. US, DE, CN)
      --api-version <ver>   SDP API version (default: 10.0.0)
      --timeout <seconds>   Download timeout (default: 180)
      --keep-remote         Keep the downloaded file on the TV
      --force               Replace an existing output file
      --no-decrypt          Skip the automatic NCG decryption after download
      --fetch-cek           If no CEK is cached, run one live RO exchange to
                            obtain it and retry the decryption
      --json                Print the final result as JSON
  -h, --help                Show this help

Numeric store IDs use the selected country's LG Apps site (default: US).
Without --country, TV requests use the TV's current store region.
After a download, NCG-protected payloads are decrypted automatically when a
CEK for the app is cached (see docs/ro-protocol.md). --no-decrypt skips it.
--fetch-cek performs a live Right Object exchange from your TV (keep it
rare: each exchange is a real request to LG's service).
`);
}

function parseArgs(argv) {
  const options = {
    apiVersion: '10.0.0',
    timeout: 180,
    keepRemote: false,
    force: false,
    noDecrypt: false,
    fetchCek: false,
    json: false,
    output: null,
    device: null,
    country: null,
    search: null,
    input: null
  };
  let searching = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      usage();
      process.exit(0);
    } else if (arg === '-o' || arg === '--output') {
      options.output = argv[++i];
    } else if (arg === '-d' || arg === '--device') {
      options.device = argv[++i];
    } else if (arg === '--country') {
      options.country = argv[++i];
    } else if (arg === '--api-version') {
      options.apiVersion = argv[++i];
    } else if (arg === '--timeout') {
      options.timeout = Number(argv[++i]);
    } else if (arg === '--keep-remote') {
      options.keepRemote = true;
    } else if (arg === '--force') {
      options.force = true;
    } else if (arg === '--no-decrypt') {
      options.noDecrypt = true;
    } else if (arg === '--fetch-cek') {
      options.fetchCek = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg.startsWith('-')) {
      throw new Error(`unknown option: ${arg}`);
    } else if (arg === 'search' && !searching && options.input === null) {
      searching = true;
    } else if (searching) {
      if (options.search !== null) throw new Error('only one search keyword may be specified');
      options.search = arg;
    } else if (options.input) {
      throw new Error('only one app identifier may be specified');
    } else {
      options.input = arg;
    }
  }
  if (searching) {
    if (options.search === null || !options.search.trim()) throw new Error('search keyword is required');
    if (options.output !== null || options.keepRemote || options.force ||
        options.noDecrypt || options.fetchCek) {
      throw new Error('--output, --keep-remote, --force, --no-decrypt, and ' +
        '--fetch-cek are only valid when downloading');
    }
  } else if (!options.input) {
    throw new Error('app identifier is required');
  }
  if (options.noDecrypt && options.fetchCek) {
    throw new Error('--no-decrypt and --fetch-cek cannot be combined');
  }
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(options.apiVersion || '')) {
    throw new Error('API version must look like 10.0.0');
  }
  if (!Number.isFinite(options.timeout) || options.timeout < 15 || options.timeout > 3600) {
    throw new Error('timeout must be between 15 and 3600 seconds');
  }
  if ((options.output === undefined) || (options.device === undefined) ||
      (options.apiVersion === undefined) || (options.country === undefined)) {
    throw new Error('an option value is missing');
  }
  if (options.country !== null) {
    if (!/^(?:[A-Za-z]{2}|C01)$/i.test(options.country)) {
      throw new Error('country must be a two-letter code such as US, DE, or CN');
    }
    options.country = options.country.toUpperCase();
    if (options.country === 'C01') options.country = 'CN';
  }
  return options;
}

function requestWebsiteApp(appId, country) {
  return new Promise((resolve, reject) => {
    const storeCountry = country === 'CN' ? 'C01' : country || 'US';
    const website = country === 'CN' ? 'wasu' : storeCountry.toLowerCase();
    const body = `appId=${encodeURIComponent(appId)}&searchCntryCode=${storeCountry}`;
    const request = https.request({
      hostname: `${website}.lgappstv.com`,
      port: 443,
      method: 'POST',
      path: '/api/tvapp/retrieveAppInfo.ajax',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      }
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        if (response.statusCode !== 200) {
          reject(new Error(`LG Apps metadata HTTP ${response.statusCode}`));
          return;
        }
        let parsed;
        try {
          parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch (error) {
          reject(new Error('LG Apps metadata returned invalid JSON'));
          return;
        }
        const product = (parsed.prodInfo || [])[0];
        if (!product || !product.appName || !product.catCode) {
          reject(new Error(`LG Apps store ID ${appId} was not found in ${country || 'US'}`));
          return;
        }
        resolve({
          webAppId: String(appId),
          catalogName: String(product.appName),
          categoryId: String(product.catCode),
          websiteVersion: product.appVer ? String(product.appVer) : null
        });
      });
    });
    request.on('error', reject);
    request.setTimeout(30000, () => request.destroy(new Error('LG Apps metadata timeout')));
    request.end(body);
  });
}

async function resolveInput(input, country) {
  if (/^[0-9]+$/.test(input)) {
    return requestWebsiteApp(input, country);
  }
  if (/^https?:\/\//i.test(input)) {
    throw new Error('store page URLs are not supported; pass the numeric appId instead');
  }
  if (!/^[A-Za-z0-9._-]+$/.test(input)) {
    throw new Error('internal app ID contains unsupported characters');
  }
  return { appId: input };
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function runTransport(action, args, options) {
  const env = Object.assign({}, process.env, {
    TV_TIMEOUT: String(Math.max(options.timeout + 60, 120))
  });
  if (options.device) env.TV_DEVICE = options.device;
  const result = childProcess.spawnSync(TV_TRANSPORT, [action].concat(args), {
    cwd: ROOT,
    env,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new Error(`${action} failed${detail ? `: ${detail}` : ''}`);
  }
  return {
    stdout: result.stdout || '',
    stderr: result.stderr || ''
  };
}

function parseLastJson(output) {
  const lines = output.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    if (lines[i][0] !== '{') continue;
    try {
      return JSON.parse(lines[i]);
    } catch (error) {
      // Continue looking for the final machine-readable line.
    }
  }
  throw new Error('TV helper did not return a JSON result');
}

function sha256File(filename) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const input = fs.createReadStream(filename);
    input.on('error', reject);
    input.on('data', chunk => hash.update(chunk));
    input.on('end', () => resolve(hash.digest('hex')));
  });
}

// Decrypt NCG-protected payloads of a downloaded IPK, offline. The CEK must
// already be cached locally (docs/ro-protocol.md); without it the
// download still succeeds and the caller prints how to obtain one. The
// decrypted IPK is written next to the original as <name>_dec.ipk.
// Returns { status: 'ok' | 'not-protected' | 'no-cek' | 'error',
//           output, replaced, error }.
function autoDecrypt(ipk, appId) {
  const out = /\.ipk$/i.test(ipk) ? ipk.replace(/\.ipk$/i, '_dec.ipk')
                                  : `${ipk}_dec.ipk`;
  const result = childProcess.spawnSync(
    process.execPath,
    [DECRYPT_TOOL, 'decrypt-ipk', ipk, '--out', out, '--app-id', appId],
    { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  if (result.error) {
    return { status: 'error', output: null, replaced: 0,
             error: `could not run ${DECRYPT_TOOL}: ${result.error.message}` };
  }
  const stderr = (result.stderr || '').trim();
  if (result.status === 0) {
    if (stderr) process.stderr.write(`${stderr}\n`);
    const replaced = (result.stdout.match(/^  replaced /gm) || []).length;
    return { status: 'ok', output: out, replaced, error: null };
  }
  if (stderr.includes('no NCG files found')) {
    return { status: 'not-protected', output: null, replaced: 0, error: null };
  }
  process.stderr.write(`${stderr}\n`);
  const first = stderr.split('\n')[0] || `decryption exited ${result.status}`;
  if (stderr.includes('no CEK for')) {
    return { status: 'no-cek', output: null, replaced: 0, error: first };
  }
  return { status: 'error', output: null, replaced: 0, error: first };
}

// One live Right Object exchange via ncg/fetch-cek.js (needs the TV and
// the prebuilt addon). Prints the tool's output; in --json mode it goes to
// stderr to keep the JSON stream clean. Returns { ok, detail }.
function runFetchCek(appId, ipk, options) {
  const args = ['--app-id', appId, '--ipk', ipk];
  if (options.device) args.push('--device', options.device);
  if (options.country) args.push('--country', options.country);
  const result = childProcess.spawnSync(process.execPath, [FETCH_CEK].concat(args), {
    cwd: ROOT,
    env: Object.assign({}, process.env, {
      NCG_CACHE_DIR: process.env.NCG_CACHE_DIR ? path.resolve(process.env.NCG_CACHE_DIR) : '',
      TV_TIMEOUT: String(Math.max(options.timeout + 60, 120))
    }),
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
    timeout: (options.timeout + 300) * 1000
  });
  const out = result.stdout || '';
  const err = result.stderr || '';
  if (options.json) {
    if (out) process.stderr.write(out);
    if (err) process.stderr.write(err);
  } else {
    if (out) process.stdout.write(out);
    if (err) process.stderr.write(err);
  }
  if (result.error) {
    const why = (result.error.code === 'ETIMEDOUT')
      ? `timed out after ${options.timeout + 300}s`
      : result.error.message;
    return { ok: false, detail: why };
  }
  if (result.status === 0) return { ok: true, detail: null };
  const lines = `${out}\n${err}`.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  return { ok: false, detail: lines[lines.length - 1] || `exited ${result.status}` };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const resolvedInput = options.search === null
    ? await resolveInput(options.input, options.country)
    : null;
  const remoteHelper = `/tmp/lg-ipk-download-${process.pid}.js`;
  let download = null;
  let pulled = false;
  let decryption = null;
  let fetchError = null;

  runTransport('push', [TV_HELPER, remoteHelper], options);
  try {
    const commandParts = [
      'NODE_PATH=/usr/lib/node_modules:/usr/lib/nodejs',
      'node',
      shellQuote(remoteHelper),
      '--api-version', shellQuote(options.apiVersion),
      '--timeout', shellQuote(String(options.timeout))
    ];
    if (options.country) {
      commandParts.push('--country', shellQuote(options.country));
    }
    if (options.search !== null) {
      commandParts.push('--search', shellQuote(options.search));
    } else if (resolvedInput.appId) {
      commandParts.push('--app-id', shellQuote(resolvedInput.appId));
    } else {
      commandParts.push(
        '--catalog-name', shellQuote(resolvedInput.catalogName),
        '--category-id', shellQuote(resolvedInput.categoryId),
        '--web-app-id', shellQuote(resolvedInput.webAppId)
      );
    }
    const command = commandParts.join(' ');
    const result = runTransport('run', [command], options);
    if (result.stderr) process.stderr.write(result.stderr);
    const response = parseLastJson(result.stdout);
    if (!response.ok) throw new Error(response.error || 'TV request failed');
    if (options.search !== null) {
      if (!Array.isArray(response.apps)) throw new Error('TV helper returned invalid search results');
      if (options.json) {
        process.stdout.write(`${JSON.stringify({ query: options.search, apps: response.apps })}\n`);
      } else if (!response.apps.length) {
        process.stdout.write('No matching apps found.\n');
      } else {
        process.stdout.write('App ID\tName\n');
        response.apps.forEach(app => {
          process.stdout.write(`${app.id}\t${app.name}\n`);
        });
      }
      return;
    }
    download = response;

    const defaultName = `${download.appId}_${download.packageVersion}.ipk`;
    const output = path.resolve(options.output || defaultName);
    if (fs.existsSync(output) && !options.force) {
      throw new Error(`output already exists: ${output} (use --force to replace it)`);
    }
    fs.mkdirSync(path.dirname(output), { recursive: true });
    const partial = `${output}.partial-${process.pid}`;
    try {
      if (fs.existsSync(partial)) fs.unlinkSync(partial);
      runTransport('pull', [download.remotePath, partial], options);
      const size = fs.statSync(partial).size;
      if (size !== download.expectedSize) {
        throw new Error(`size mismatch: expected ${download.expectedSize}, received ${size}`);
      }
      const sha256 = await sha256File(partial);
      if (fs.existsSync(output)) fs.unlinkSync(output);
      fs.renameSync(partial, output);
      pulled = true;

      decryption = options.noDecrypt
        ? { status: 'skipped', output: null, replaced: 0, error: null }
        : autoDecrypt(output, download.appId);

      if (options.fetchCek && decryption.status === 'no-cek') {
        process.stderr.write('info: no cached CEK; running a live RO exchange ' +
          '(one request to LG from the TV)...\n');
        const exchange = runFetchCek(download.appId, output, options);
        if (exchange.ok) {
          decryption = autoDecrypt(output, download.appId);
          if (decryption.status === 'no-cek') {
            fetchError = `--fetch-cek: exchange reported success but no CEK ` +
              `was cached for ${download.appId}`;
          }
        } else {
          fetchError = `--fetch-cek: RO exchange failed: ${exchange.detail}`;
        }
      }

      const finalResult = {
        appId: download.appId,
        webAppId: download.webAppId || null,
        installedVersion: download.installedVersion,
        storeVersion: download.storeVersion,
        packageVersion: download.packageVersion,
        size,
        sha256,
        output,
        decryption
      };
      if (options.json) {
        process.stdout.write(`${JSON.stringify(finalResult)}\n`);
      } else {
        if (download.webAppId) {
          process.stdout.write(`Resolved LG Apps ${download.webAppId} -> ${download.appId}\n`);
        }
        process.stdout.write(`Downloaded ${download.appId} ${download.packageVersion}\n`);
        process.stdout.write(`Output:  ${output}\n`);
        process.stdout.write(`Size:    ${size} bytes\n`);
        process.stdout.write(`SHA-256: ${sha256}\n`);
        if (decryption.status === 'ok') {
          process.stdout.write(`Decrypted:  ${decryption.output} ` +
            `(${decryption.replaced === 1 ? '1 NCG file' :
               `${decryption.replaced} NCG files`} replaced)\n`);
        }
      }
    } finally {
      if (fs.existsSync(partial)) fs.unlinkSync(partial);
    }

    if (!options.keepRemote && pulled) {
      const cleanupCommand = [
        'rm -f --', shellQuote(download.remotePath),
        '; rmdir', shellQuote(path.posix.dirname(download.remotePath)),
        '2>/dev/null || true'
      ].join(' ');
      try {
        runTransport('run', [cleanupCommand], options);
      } catch (error) {
        process.stderr.write(`warning: TV file cleanup failed: ${error.message}\n`);
      }
    }

    if (decryption.status === 'no-cek' && !fetchError) {
      process.stderr.write(
        `warning: NCG-protected IPK but no cached CEK for ${download.appId}; ` +
        `the IPK is kept at ${output}.\n` +
        `warning: obtain the CEK with: ncg-fetch-cek --app-id ` +
        `${download.appId} --ipk ${shellQuote(output)}\n` +
        `warning: then re-run the download (it will decrypt automatically).\n`
      );
    }
    if (fetchError) {
      throw new Error(`${fetchError}; the downloaded IPK is kept at ${output}`);
    }
    if (decryption.status === 'error') {
      throw new Error(`decryption failed; the downloaded IPK is kept at ${output}`);
    }
  } finally {
    const removeCommand = `rm -f -- ${shellQuote(remoteHelper)}`;
    try {
      runTransport('run', [removeCommand], options);
    } catch (error) {
      process.stderr.write(`warning: temporary helper cleanup failed: ${error.message}\n`);
    }
    if (download && !pulled) {
      process.stderr.write(`TV file retained for recovery: ${download.remotePath}\n`);
    }
  }
}

main().catch(error => fail(error.message));
