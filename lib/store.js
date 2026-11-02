'use strict';

const childProcess = require('child_process');
const path = require('path');
const parseOptions = require('./parse-options');

const ROOT = path.resolve(__dirname, '..');
const TV_TRANSPORT = path.join(ROOT, 'lib', 'tv.sh');
const TV_HELPER = path.join(ROOT, 'tv', 'download-ipk.js');

function parseArgs(argv, command) {
  const { options: args, positional } = parseOptions(argv, {
    values: ['output', 'device', 'country', 'api-version', 'timeout'],
    flags: ['keep-remote', 'force', 'no-decrypt', 'fetch-cek', 'json'],
    aliases: { '-o': 'output', '--out': 'output', '-d': 'device' }
  });
  const options = {
    apiVersion: args['api-version'] || '10.0.0',
    timeout: args.timeout === undefined ? 180 : Number(args.timeout),
    keepRemote: Boolean(args['keep-remote']),
    force: Boolean(args.force),
    noDecrypt: Boolean(args['no-decrypt']),
    fetchCek: Boolean(args['fetch-cek']),
    json: Boolean(args.json),
    output: args.output || null,
    device: args.device || null,
    country: args.country || null,
    search: command === 'search' ? positional[0] ?? null : null,
    input: command === 'download' ? positional[0] ?? null : null
  };
  if (positional.length > 1) {
    throw new Error(command === 'search' ? 'only one search keyword may be specified'
      : 'only one app identifier may be specified');
  }
  if (command === 'search') {
    if (options.search === null || !options.search.trim()) {
      throw new Error('search keyword is required');
    }
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
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(options.apiVersion)) {
    throw new Error('API version must look like 10.0.0');
  }
  if (!Number.isFinite(options.timeout) || options.timeout < 15 || options.timeout > 3600) {
    throw new Error('timeout must be between 15 and 3600 seconds');
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
  return { stdout: result.stdout || '', stderr: result.stderr || '' };
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

function requestStore(remoteHelper, options, resolvedInput) {
  const parts = [
    'NODE_PATH=/usr/lib/node_modules:/usr/lib/nodejs',
    'node', shellQuote(remoteHelper),
    '--api-version', shellQuote(options.apiVersion),
    '--timeout', shellQuote(String(options.timeout))
  ];
  if (options.country) parts.push('--country', shellQuote(options.country));
  if (options.search !== null) {
    parts.push('--search', shellQuote(options.search));
  } else if (resolvedInput.appId) {
    parts.push('--app-id', shellQuote(resolvedInput.appId));
  } else {
    parts.push(
      '--catalog-name', shellQuote(resolvedInput.catalogName),
      '--category-id', shellQuote(resolvedInput.categoryId),
      '--web-app-id', shellQuote(resolvedInput.webAppId)
    );
  }
  const result = runTransport('run', [parts.join(' ')], options);
  if (result.stderr) process.stderr.write(result.stderr);
  const response = parseLastJson(result.stdout);
  if (!response.ok) throw new Error(response.error || 'TV request failed');
  return response;
}

function removeHelper(remoteHelper, options) {
  try {
    runTransport('run', [`rm -f -- ${shellQuote(remoteHelper)}`], options);
  } catch (error) {
    process.stderr.write(`warning: temporary helper cleanup failed: ${error.message}\n`);
  }
}

module.exports = {
  ROOT, TV_HELPER, parseArgs, shellQuote, runTransport, requestStore, removeHelper
};
