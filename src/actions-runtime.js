'use strict';

const fs = require('node:fs');

/** @param {NodeJS.ProcessEnv} env */
function createCore(env) {
  let summary = '';
  return {
    /** @param {string} name @param {{required?: boolean}} [options] */
    getInput(name, options = {}) {
      const key = `INPUT_${name.replace(/ /g, '_').toUpperCase()}`;
      const value = (env[key] || '').trim();
      if (options.required && !value) throw new Error(`Input required and not supplied: ${name}.`);
      return value;
    },
    /** @param {string} name @param {string | number | boolean} value */
    setOutput(name, value) {
      const line = `${name}=${String(value).replace(/[\r\n]/g, '')}\n`;
      if (env.GITHUB_OUTPUT)
        fs.appendFileSync(env.GITHUB_OUTPUT, line, { encoding: 'utf8', mode: 0o600 });
    },
    /** @param {string} message */
    setFailed(message) {
      process.exitCode = 1;
      process.stderr.write(`::error::${String(message).replace(/[\r\n]/g, ' ')}\n`);
    },
    summary: {
      /** @param {string} markdown */
      addRaw(markdown) {
        summary += String(markdown);
        return this;
      },
      async write() {
        if (env.GITHUB_STEP_SUMMARY) {
          fs.appendFileSync(env.GITHUB_STEP_SUMMARY, summary, { encoding: 'utf8', mode: 0o600 });
        }
      }
    }
  };
}

module.exports = { createCore };
