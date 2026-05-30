import { scanMaintainerAnomaly } from './d1-maintainer.js';
import { scanPreinstallLoader } from './d2-preinstall-loader.js';
import { scanCredExfil } from './d3-cred-exfil.js';
import { attachProvenance } from '../../provenance.js';

const RULE_SEVERITY = { D1: 'critical', D2: 'critical', D3: 'critical' };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'none'];

function highestSeverity(severities) {
  for (const s of SEVERITY_ORDER) if (severities.includes(s)) return s;
  return 'none';
}

export async function scan(pkgJson, files = [], registryMeta = null, allFiles = null) {
  const pkgName = pkgJson?.name || 'unknown';
  const pkgVersion = pkgJson?.version || '0.0.0';
  const fileList = allFiles || files || [];

  const d1Result = scanMaintainerAnomaly(pkgJson, registryMeta);
  if (d1Result.stopCondition) {
    const evidence = attachProvenance({
      rule: 'TSQ-MAINT-001',
      campaign: 'TYPOSQUAT_VPMDHAJ',
      triggeredChecks: ['D1'],
      maintainer: d1Result.maintainer,
      suspiciousAliases: d1Result.suspiciousAliases,
      action: 'BLOCK',
    }, {
      ruleId: 'TSQ-MAINT-001',
      ruleName: 'Maintainer & Package Alias Anomalies',
      severity: 'CRITICAL',
      campaignName: 'Mass Typosquatting (vpmdhaj)',
      pkgName,
      pkgVersion,
      triggered: true,
      severity: 'critical',
      indicators: [{ type: 'blocked_maintainer', value: d1Result.maintainer }, ...d1Result.suspiciousAliases.map(a => ({ type: 'suspicious_alias', value: a }))],
      ruleProvenanceUrl: 'https://github.com/lateos/npm-scan/blob/main/backend/detectors/typosquat-vpmdhaj/d1-maintainer.js',
      campaignSourceUrl: 'https://security.researcher.org/supply-chain-report',
    });

    return [{
      id: 'TYPOSQUAT_VPMDHAJ',
      severity: 'critical',
      title: 'Mass Typosquatting campaign (vpmdhaj) — blocked maintainer',
      description: d1Result.reason,
      evidence: JSON.stringify(evidence),
      mitigation: 'BLOCK IMMEDIATELY. Do not install packages from maintainer vpmdhaj. Audit all packages from your lockfile for this maintainer. Check for typosquatting of popular packages.',
      stopCondition: true,
    }];
  }

  const d2Result = scanPreinstallLoader(pkgJson);
  const d3Result = scanCredExfil(fileList, pkgJson);

  const results = {
    D1: d1Result,
    D2: d2Result,
    D3: d3Result,
  };

  const triggered = Object.entries(results)
    .filter(([_, r]) => r.triggered)
    .map(([id]) => id);

  if (triggered.length === 0) return [];

  const severity = highestSeverity(triggered.map(id => RULE_SEVERITY[id]));

  const evidence = attachProvenance({
    campaign: 'TYPOSQUAT_VPMDHAJ',
    triggeredChecks: triggered,
    details: Object.fromEntries(
      Object.entries(results).filter(([_, r]) => r.triggered)
    ),
  }, {
    ruleId: 'TYPOSQUAT_VPMDHAJ',
    ruleName: 'Mass Typosquatting Campaign Detection',
    severity: severity.toUpperCase(),
    campaignName: 'Mass Typosquatting (vpmdhaj)',
    pkgName,
    pkgVersion,
    triggered: true,
    severity,
    indicators: triggered.map(id => ({ type: `rule_${id}`, value: RULE_SEVERITY[id] })),
    ruleProvenanceUrl: 'https://github.com/lateos/npm-scan/blob/main/backend/detectors/typosquat-vpmdhaj/',
    campaignSourceUrl: 'https://security.researcher.org/supply-chain-report',
  });

  return [{
    id: 'TYPOSQUAT_VPMDHAJ',
    severity,
    title: 'Mass Typosquatting campaign (vpmdhaj)',
    description: `${triggered.length} signal(s): ${triggered.join(', ')}`,
    evidence: JSON.stringify(evidence),
    mitigation: 'Block install immediately. Revoke any npm tokens. Rotate CI/CD secrets. Audit all packages from maintainer vpmdhaj. If credential exfiltration detected: rotate AWS IAM keys, Vault tokens, and GitHub tokens immediately. Verify CloudTrail/audit logs for unauthorized access.',
  }];
}
