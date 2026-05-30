const SUSPICIOUS_HOOKS = ['preinstall'];
const LOADER_SCRIPTS = ['setup.mjs', 'loader.js', 'stager.js', 'init.mjs'];
const BUN_RUN_RE = /\bbun\s+run\b/;
const NODE_SETUP_RE = /\bnode\s+(setup\.mjs|init\.mjs|loader\.js|stager\.js)\b/;
const PREINSTALL_STAGER_RE = /preinstall\s*[:=]/;

export function scanPreinstallLoader(pkgJson) {
  const scripts = pkgJson?.scripts || {};
  const triggered = [];

  for (const hook of SUSPICIOUS_HOOKS) {
    const cmd = scripts[hook];
    if (!cmd) continue;

    const details = { hookType: hook, hookCommand: cmd };

    if (BUN_RUN_RE.test(cmd)) {
      details.runtimeAbuse = 'Bun as stealthy loader';
      triggered.push(details);
    } else if (NODE_SETUP_RE.test(cmd)) {
      const match = cmd.match(/node\s+(setup\.mjs|init\.mjs|loader\.js|stager\.js)\b/);
      details.generation = match && match[1] === 'stager.js' ? 2 : 1;
      triggered.push(details);
    } else {
      triggered.push(details);
    }
  }

  if (triggered.length > 0) {
    return {
      triggered: true,
      details: triggered,
    };
  }

  return { triggered: false, details: [] };
}
