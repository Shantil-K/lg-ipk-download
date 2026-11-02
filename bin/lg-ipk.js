#!/usr/bin/env node
'use strict';

const commands = {
  download: '../lib/download',
  search: '../lib/search',
  decrypt: '../ncg/ncg-decrypt',
  'fetch-cek': '../ncg/fetch-cek',
  cache: '../ncg/cache'
};

const help = `Usage: lg-ipk <command> [options]

Commands:
  download    Download an app's IPK
  search      Search the LG Content Store
  decrypt     Auto-detect and decrypt an IPK or NCG file
  fetch-cek   Fetch and cache a CEK using the TV
  cache       List, add, or remove cached CEKs

Examples:
  lg-ipk download com.palmdts.devmode
  lg-ipk search "Developer Mode"
  lg-ipk decrypt app.ipk --output app_dec.ipk

Run lg-ipk <command> --help for detailed options.
`;

async function run(argv) {
  const [name, ...args] = argv;
  let command;
  try {
    if (name === '-h' || name === '--help') {
      process.stdout.write(help);
      return;
    }
    if (!name) throw new Error('command is required (use --help)');
    if (!Object.hasOwn(commands, name)) {
      throw new Error(name.startsWith('-') ? `unknown option: ${name}`
        : `unknown command: ${name} (use --help)`);
    }
    command = require(commands[name]);
    if (args.includes('-h') || args.includes('--help')) {
      process.stdout.write(command.help);
      return;
    }
    const status = await command.run(args);
    if (status !== undefined) process.exitCode = status;
  } catch (error) {
    const storeCommand = !command || name === 'download' || name === 'search';
    const message = error.message;
    const prefix = storeCommand ? 'lg-ipk: ' : 'error: ';
    process.stderr.write(`${message.startsWith('Usage:') ? '' : prefix}${message}\n`);
    if (error.usage && !storeCommand && name !== 'fetch-cek') {
      process.stderr.write(command.help);
    }
    process.exitCode = error.usage && !storeCommand ? 2 : 1;
  }
}

module.exports = { run };

if (require.main === module) {
  run(process.argv.slice(2));
}
