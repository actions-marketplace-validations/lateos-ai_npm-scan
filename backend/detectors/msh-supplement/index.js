import { scanCtfScramble } from './d1-obfuscation.js';
import { scanPersistence } from './d2-persistence.js';
import { scanGeoKillswitch } from './d3-geo-killswitch.js';
import { scanC2DeadDrop } from './d4-c2-deaddrop.js';
import { attachProvenance } from '../../provenance.js';

const RULE_SEVERITY = {
  D1: 'critical',
  D2: 'critical',
  D3: 'high',
  D4: 'critical',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'none'];

function highestSeverity(severities) {
  for (const s of SEVERITY_ORDER) {
    if (severities.includes(s)) return s;
  }
  return 'none';
}

export async function scan(pkgJson, files = [], registryMeta = null, allFiles = null) {
  const fileList = allFiles || files || [];
  const pkgName = pkgJson?.name || 'unknown';
  const pkgVersion = pkgJson?.version || '0.0.0';

  const d1Results = scanCtfScramble(fileList);
  if (d1Results.stopCondition) {
    const evidence = attachProvenance({
      rule: 'MSH-OBF-001',
      campaign: 'MINI_SHAI_HULUD',
      triggeredChecks: ['D1'],
      filePath: d1Results.filePath,
      patternMatched: d1Results.patternMatched,
      action: 'BLOCK_IMMEDIATELY',
    }, {
      ruleId: 'MSH-OBF-001',
      ruleName: 'ctf-scramble-v2 Obfuscation Detection',
      severity: 'CRITICAL',
      campaignName: 'Mini Shai-Hulud',
      pkgName,
      pkgVersion,
      triggered: true,
      severity: 'critical',
      indicators: [{ type: 'obfuscation_found', value: d1Results.patternMatched }],
      ruleProvenanceUrl: 'https://github.com/lateos/npm-scan/blob/main/backend/detectors/msh-supplement/d1-obfuscation.js',
      campaignSourceUrl: 'https://security.researcher.org/supply-chain-report',
    });

    return [{
      id: 'MINI_SHAI_HULUD',
      severity: 'critical',
      title: 'Mini Shai-Hulud worm campaign — ctf-scramble-v2 malware obfuscation detected',
      description: 'HALT: ctf-scramble-v2 obfuscation layer detected. Package is compromised. Block install immediately.',
      evidence: JSON.stringify(evidence),
      mitigation: 'BLOCK IMMEDIATELY. Do not install this package version. Revoke any npm tokens exposed to this package. Rotate all CI/CD secrets. Run full malware scan on any system that processed this package.',
      stopCondition: true,
    }];
  }

  const results = {
    D2: scanPersistence(pkgJson, fileList),
    D3: scanGeoKillswitch(fileList),
    D4: scanC2DeadDrop(fileList),
  };

  const triggered = Object.entries(results)
    .filter(([_, r]) => r.triggered)
    .map(([id]) => id);

  if (triggered.length === 0) return [];

  const severity = highestSeverity(triggered.map(id => RULE_SEVERITY[id]));

  const evidence = attachProvenance({
    campaign: 'MINI_SHAI_HULUD',
    triggeredChecks: triggered,
    details: Object.fromEntries(
      Object.entries(results).filter(([_, r]) => r.triggered)
    ),
  }, {
    ruleId: 'MSH-SUPPLEMENT',
    ruleName: 'Mini Shai-Hulud Supplement Detection',
    severity: severity.toUpperCase(),
    campaignName: 'Mini Shai-Hulud',
    pkgName,
    pkgVersion,
    triggered: true,
    severity,
    indicators: triggered.map(id => ({
      type: `rule_${id}`,
      value: RULE_SEVERITY[id],
    })),
    ruleProvenanceUrl: 'https://github.com/lateos/npm-scan/blob/main/backend/detectors/msh-supplement/',
    campaignSourceUrl: 'https://security.researcher.org/supply-chain-report',
  });

  return [{
    id: 'MINI_SHAI_HULUD',
    severity,
    title: 'Mini Shai-Hulud worm campaign — supplement indicators',
    description: `${triggered.length} signal(s): ${triggered.join(', ')}`,
    evidence: JSON.stringify(evidence),
    mitigation: 'If daemonization detected: revoke npm tokens and rotate CI/CD secrets. If geographic killswitch detected: verify running in expected region; attacker may be avoiding certain locales. If C2 dead-drop detected: check for unauthorized GitHub API access and token exfiltration. Review recent version publish history for anomalous bursts.',
  }];
}
