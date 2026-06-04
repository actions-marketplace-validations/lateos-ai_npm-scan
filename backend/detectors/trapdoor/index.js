import { scanCampaignMarker } from './d1-campaign-marker.js';
import { scanPayloadFingerprint } from './d2-payload-fingerprint.js';
import { scanPublisherBlocklist } from './d3-publisher-blocklist.js';
import { scanGistsExfil } from './d4-gists-exfil.js';
import { scanAIPoisoning } from './d5-ai-poisoning.js';
import { scanLureName } from './d6-lure-name.js';
import { scanCryptoPrimitives } from './d7-crypto-primitives.js';
import { scanXorKey } from './d8-xor-key.js';
import { scanCredValidation } from './d9-cred-validation.js';

const RULE_SEVERITY = {
  D1: 'critical',
  D2: 'critical',
  D3: 'critical',
  D4: 'critical',
  D5: 'high',
  D6: 'medium',
  D7: 'high',
  D8: 'high',
  D9: 'critical',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'none'];

function highestSeverity(severities) {
  for (const s of SEVERITY_ORDER) {
    if (severities.includes(s)) {
      return s;
    }
  }
  return 'none';
}

export async function scan(pkgJson, files = [], registryMeta = null, allFiles = null) {
  const fileList = allFiles || files || [];

  const results = {
    D1: scanCampaignMarker(fileList),
    D2: scanPayloadFingerprint(fileList),
    D3: scanPublisherBlocklist(pkgJson, registryMeta),
    D4: scanGistsExfil(fileList, pkgJson),
    D5: scanAIPoisoning(fileList),
    D6: scanLureName(pkgJson, registryMeta),
    D7: scanCryptoPrimitives(fileList, pkgJson),
    D8: scanXorKey(fileList),
    D9: scanCredValidation(fileList, pkgJson),
  };

  const triggered = Object.entries(results)
    .filter(([_, r]) => r.triggered)
    .map(([id]) => id);

  if (triggered.length === 0) {
    return [];
  }

  const severity = highestSeverity(triggered.map((id) => RULE_SEVERITY[id]));

  const evidence = {
    campaign: 'TRAPDOOR',
    triggeredRules: triggered,
    details: Object.fromEntries(Object.entries(results).filter(([_, r]) => r.triggered)),
    iocSummary: {
      publisher: 'asdxzxc',
      c2Domain: 'ddjidd564.github.io',
      campaignMarker: 'P-2024-001',
      payloadFile: 'trap-core.js',
    },
  };

  return [
    {
      id: 'TRAPDOOR',
      severity,
      title: 'TrapDoor cross-ecosystem supply chain attack campaign',
      description: `${triggered.length} signal(s): ${triggered.join(', ')}`,
      evidence: JSON.stringify(evidence),
      mitigation:
        'Block install immediately. Revoke any npm tokens associated with this package. Rotate CI/CD secrets. Audit for postinstall scripts accessing credentials. Check for AI config poisoning (.cursorrules/CLAUDE.md). Verify all package versions from publisher asdxzxc. If confirmed compromise, follow incident response procedures per SECURITY.md.',
    },
  ];
}
