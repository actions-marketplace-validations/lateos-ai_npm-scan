const ACTIVATION_RISK_MATRIX = {
  '*': { base: 'critical', label: 'Wildcard (all files)' },
  onStartupFinished: { base: 'high', label: 'Startup finished' },
  'workspaceContains:**/*': { base: 'high', label: 'Workspace contains wildcard' },
  workspaceContains: { base: 'high', label: 'Workspace contains' },
  'onCommand:*': { base: 'low', label: 'Any command' },
};

const DEFAULT_BASE_RISK = 'medium';

const ESCALATION_KEYWORDS = [
  'npx',
  'bun',
  'curl',
  'wget',
  'fetch(',
  'exec(',
  'spawn(',
  'execSync',
  'spawnSync',
  'child_process',
  'shell: true',
  'detached: true',
];

const BUNDLED_BUN_PATTERN = /bun|runtime/;

const SIZE_DELTA_THRESHOLD = 400 * 1024;

const SHELL_CMDS = ['npx', 'bun', 'curl', 'wget', 'exec', 'spawn', 'execSync'];

export async function checkActivationEventRisk(
  extensionManifest,
  versionHistory = [],
  priorVersions = []
) {
  const signals = [];

  const activationEvents = extensionManifest?.activationEvents || [];
  if (activationEvents.length === 0 && extensionManifest?.main) {
    return { triggered: false, signals: [], riskLevel: null, why: [] };
  }

  let maxBaseRisk = 0;
  const riskLabels = ['none', 'low', 'medium', 'high', 'critical'];
  const riskValues = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

  let _worstEvent = null;
  const why = [];

  for (const event of activationEvents) {
    const risk = ACTIVATION_RISK_MATRIX[event];
    if (risk) {
      const baseIdx = riskValues[risk.base] || riskValues[DEFAULT_BASE_RISK];
      if (baseIdx > maxBaseRisk) {
        maxBaseRisk = baseIdx;
        _worstEvent = event;
      }
    } else if (event.includes('*') && event !== 'onCommand:*') {
      const baseIdx = riskValues['high'];
      if (baseIdx > maxBaseRisk) {
        maxBaseRisk = baseIdx;
        _worstEvent = event;
      }
    }
  }

  const contributes = extensionManifest?.contributes || {};
  const commands = contributes?.commands || [];
  const cmdTitles = commands.map((c) => (c.title || '').toLowerCase()).join(' ');

  const bundledDeps = extensionManifest?.bundledDependencies || [];
  const bundledStr = Array.isArray(bundledDeps) ? bundledDeps.join(' ') : '';

  const hasShellKeyword = SHELL_CMDS.some((cmd) => cmdTitles.includes(cmd));
  const hasBunBundled = BUNDLED_BUN_PATTERN.test(bundledStr);

  const activationEventsStr = activationEvents.join(' ');
  const hasShellInActivationContext = ESCALATION_KEYWORDS.some((kw) =>
    activationEventsStr.toLowerCase().includes(kw.toLowerCase())
  );

  let escalateToCritical = false;

  if (hasShellKeyword || hasBunBundled || hasShellInActivationContext) {
    escalateToCritical = true;
    why.push('HIGH activation event + shell/execution keywords');
  }

  if (versionHistory.length >= 2) {
    const sizes = versionHistory
      .filter((v) => v.assetSize)
      .map((v) => v.assetSize)
      .sort((a, b) => b - a);

    if (sizes.length >= 2 && sizes[0] - sizes[sizes.length - 1] > SIZE_DELTA_THRESHOLD) {
      escalateToCritical = true;
      why.push(`HIGH activation event + version size delta > ${SIZE_DELTA_THRESHOLD} bytes`);
    }
  }

  const priorActivationEvents = priorVersions
    .filter((v) => v.activationEvents)
    .flatMap((v) => v.activationEvents);

  if (priorActivationEvents.length > 0) {
    const newEvents = activationEvents.filter((e) => !priorActivationEvents.includes(e));
    if (newEvents.length > 0) {
      why.push(`First-time activation event(s) added: ${newEvents.join(', ')}`);
      if (!escalateToCritical && maxBaseRisk >= riskValues['high']) {
        escalateToCritical = true;
      }
    }
  }

  let riskLevel = maxBaseRisk > 0 ? riskLabels[maxBaseRisk] : null;
  if (escalateToCritical && riskValues[riskLevel] <= riskValues['high']) {
    riskLevel = 'critical';
  }

  if (!riskLevel) {
    return { triggered: false, signals: [], riskLevel: null, why: [] };
  }

  signals.push({
    type: 'ACTIVATION_EVENT_RISK',
    activationEvents,
    riskLevel,
    why,
  });

  return { triggered: true, signals, riskLevel, why };
}
