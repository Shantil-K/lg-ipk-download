'use strict';

const { TV_HELPER, parseArgs, runTransport, requestStore, removeHelper } = require('./store');

const help = `Usage: lg-ipk search [options] <keyword>

Search the TV's app store without downloading or installing anything.

Options:
  -d, --device <profile>    ares-setup-device profile
      --country <code>      Store country/region (e.g. US, DE, CN)
      --api-version <ver>   SDP API version (default: 10.0.0)
      --timeout <seconds>   Request timeout (default: 180)
      --json                Print the result as JSON
  -h, --help                Show this help

Without --country, searches use the TV's current store region.
`;

function run(argv) {
  const options = parseArgs(argv, 'search');
  const remoteHelper = `/tmp/lg-ipk-download-${process.pid}.js`;
  runTransport('push', [TV_HELPER, remoteHelper], options);
  try {
    const response = requestStore(remoteHelper, options);
    if (!Array.isArray(response.apps)) throw new Error('TV helper returned invalid search results');
    if (options.json) {
      process.stdout.write(`${JSON.stringify({ query: options.search, apps: response.apps })}\n`);
    } else if (!response.apps.length) {
      process.stdout.write('No matching apps found.\n');
    } else {
      process.stdout.write('App ID\tName\n');
      response.apps.forEach(app => process.stdout.write(`${app.id}\t${app.name}\n`));
    }
    return 0;
  } finally {
    removeHelper(remoteHelper, options);
  }
}

module.exports = { help, run };
