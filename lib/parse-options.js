'use strict';

function parseOptions(argv, { values = [], flags = [], aliases = {} }) {
  const options = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('-')) {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf('=');
    const option = eq === -1 ? arg : arg.slice(0, eq);
    const name = Object.hasOwn(aliases, option) ? aliases[option]
      : option.startsWith('--') ? option.slice(2) : null;
    if (flags.includes(name)) {
      if (eq !== -1) {
        throw { usage: true, message: `${option} does not accept a value` };
      }
      options[name] = true;
    } else if (values.includes(name)) {
      const value = eq === -1 ? argv[++i] : arg.slice(eq + 1);
      if (!value || (eq === -1 && value.startsWith('-'))) {
        throw { usage: true, message: `${option} requires a value` };
      }
      options[name] = value;
    } else {
      throw { usage: true, message: `unknown option: ${option}` };
    }
  }
  return { options, positional };
}

module.exports = parseOptions;
