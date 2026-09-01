import { scanVersionBlocklist } from './d1-version-fingerprint.js';
import { scanDecoyDependency } from './d2-decoy-dep.js';
import { scanPostinstallRAT } from './d3-postinstall-rat.js';
import { attachProvenance } from '../../provenance.js';

const RULE_SEVERITY = { D1: 'critical', D2: 'critical', D3: 'critical' };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'none'];

function highestSeverity(severities) {
  for (const s of SEVERITY_ORDER) {
    if (severities.includes(s)) {
      return s;
    }
  }
  return 'none';
}

export async function scan(pkgJson, files = [], _registryMeta = null, allFiles = null) {
  const pkgName = pkgJson?.name || 'unknown';
  const pkgVersion = pkgJson?.version || '0.0.0';
  const fileList = allFiles || files || [];

  const d1Result = scanVersionBlocklist(pkgJson);
  if (d1Result.stopCondition) {
    const evidence = attachProvenance(
      {
        rule: 'AXS-VER-001',
        campaign: 'AXIOS_POISONING',
        triggeredChecks: ['D1'],
        matchedVersion: d1Result.matchedVersion,
        action: 'BLOCK_IMMEDIATELY',
        remediation: `Upgrade to axios@1.14.2 or later, or use pinned safe version`,
      },
      {
        ruleId: 'AXS-VER-001',
        ruleName: 'Compromised Axios Version Fingerprinting',
        campaignName: 'Axios Registry Poisoning',
        pkgName,
        pkgVersion,
        triggered: true,
        severity: 'critical',
        indicators: [{ type: 'known_malicious_version', value: `${pkgName}@${pkgVersion}` }],
        ruleProvenanceUrl:
          'https://github.com/lateos/npm-scan/blob/main/backend/detectors/axios-poisoning/d1-version-fingerprint.js',
        campaignSourceUrl: 'https://security.researcher.org/supply-chain-report',
      }
    );

    return [
      {
        id: 'AXIOS_POISONING',
        severity: 'critical',
        title: 'Axios Registry Poisoning campaign',
        description: `HALT: ${pkgName}@${pkgVersion} is a known compromised version in the Axios registry poisoning campaign. Block install immediately.`,
        evidence: JSON.stringify(evidence),
        mitigation: d1Result.reason
          ? `BLOCK IMMEDIATELY. ${d1Result.reason}. Upgrade to axios@1.14.2 or later, or use pinned safe version.`
          : 'BLOCK IMMEDIATELY. Upgrade to a safe version.',
        stopCondition: true,
      },
    ];
  }

  const d2Result = scanDecoyDependency(pkgJson);
  const d3Result = scanPostinstallRAT(pkgJson, fileList);

  const results = { D1: d1Result, D2: d2Result, D3: d3Result };

  const triggered = Object.entries(results)
    .filter(([_, r]) => r.triggered)
    .map(([id]) => id);

  if (triggered.length === 0) {
    return [];
  }

  const severity = highestSeverity(triggered.map((id) => RULE_SEVERITY[id]));

  const evidence = attachProvenance(
    {
      campaign: 'AXIOS_POISONING',
      triggeredChecks: triggered,
      details: Object.fromEntries(Object.entries(results).filter(([_, r]) => r.triggered)),
    },
    {
      ruleId: 'AXIOS_POISONING',
      ruleName: 'Axios Registry Poisoning Detection',
      campaignName: 'Axios Registry Poisoning',
      pkgName,
      pkgVersion,
      triggered: true,
      severity,
      indicators: triggered.map((id) => ({ type: `rule_${id}`, value: RULE_SEVERITY[id] })),
      ruleProvenanceUrl:
        'https://github.com/lateos/npm-scan/blob/main/backend/detectors/axios-poisoning/',
      campaignSourceUrl: 'https://security.researcher.org/supply-chain-report',
    }
  );

  return [
    {
      id: 'AXIOS_POISONING',
      severity,
      title: 'Axios Registry Poisoning campaign',
      description: `${triggered.length} signal(s): ${triggered.join(', ')}`,
      evidence: JSON.stringify(evidence),
      mitigation:
        'If decoy dependency detected: verify all axios dependencies are legitimate. If RAT payload detected: run full malware scan on the system, rotate all credentials, check for unauthorized network connections. Upgrade to axios@1.14.2+ or pin to a known safe version.',
    },
  ];
}
