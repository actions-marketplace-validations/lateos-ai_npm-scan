import { MegalodonSignal } from './types.js';
import { scan as scanD1 } from './d1-workflow-scan.js';
import { scan as scanD2 } from './d2-credential-harvest.js';
import { scan as scanD3 } from './d3-publish-velocity.js';
import { scan as scanD4 } from './d4-publisher-drift.js';
import { scan as scanD5 } from './d5-bot-commit-identity.js';
import { scan as scanD6 } from './d6-date-anachronism.js';

const SIGNAL_SEVERITY = {
  [MegalodonSignal.WORKFLOW_C2_EXFIL]: 5,
  [MegalodonSignal.WORKFLOW_DECODE_CHAIN]: 4,
  [MegalodonSignal.PUBLISH_VELOCITY]: 4,
  [MegalodonSignal.PUBLISHER_DRIFT]: 4,
  [MegalodonSignal.CREDENTIAL_HARVEST]: 3,
  [MegalodonSignal.BOT_COMMIT_IDENTITY]: 2,
  [MegalodonSignal.DATE_ANACHRONISM]: 2,
};

const SEVERITY_LABELS = ['none', 'low', 'medium', 'high', 'critical', 'critical'];

function resolveSeverity(signals, d4Evidence) {
  let maxScore = 0;
  for (const s of signals) {
    maxScore = Math.max(maxScore, SIGNAL_SEVERITY[s] || 0);
  }

  const d4Hint = d4Evidence.find(e => e._severityHint);
  if (d4Hint) {
    const hintScore = d4Hint._severityHint === 'HIGH' ? 4 : d4Hint._severityHint === 'MEDIUM' ? 3 : 0;
    maxScore = Math.max(maxScore, hintScore);
  }

  return SEVERITY_LABELS[maxScore] || 'none';
}

export async function scanAll(pkgJson, allFiles = [], registryMeta = {}) {
  const allEvidence = [];

  const d1Ev = await scanD1(allFiles);
  allEvidence.push(...d1Ev);

  const d2Ev = await scanD2(allFiles);
  allEvidence.push(...d2Ev);

  const d3Ev = await scanD3(registryMeta);
  allEvidence.push(...d3Ev);

  const velocityResult = d3Ev.length > 0 ? {
    triggered: true,
    windowStartISO: d3Ev[0]._windowStartISO || null,
    versionsInWindow: d3Ev[0].excerpt || '',
    _allVersions: d3Ev[0]._allVersions || [],
  } : { triggered: false, versionsInWindow: [], windowStartISO: null };

  const d4Ev = await scanD4(registryMeta, velocityResult);
  allEvidence.push(...d4Ev);

  allEvidence.push(...await scanD5(registryMeta));
  allEvidence.push(...await scanD6(pkgJson, registryMeta));

  const signals = [...new Set(allEvidence.map(e => e.signal).filter(Boolean))];

  if (signals.length === 0) return [];

  const severity = resolveSeverity(signals, d4Ev);

  const cleaned = allEvidence.map(({ _windowStartISO, _allVersions, _severityHint, ...rest }) => rest);

  return [{
    id: 'MEGALODON',
    severity,
    title: 'Megalodon CI/CD attack campaign',
    description: `${signals.length} signal(s): ${signals.join(', ')}`,
    evidence: JSON.stringify({
      campaign: 'MEGALODON',
      signals,
      evidence: cleaned,
    }),
  }];
}
