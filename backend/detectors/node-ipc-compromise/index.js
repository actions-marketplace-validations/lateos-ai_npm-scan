import { scanVersionBlocklist } from './d1-version-blocklist.js';
import { scanTarballHash } from './d2-tarball-hash.js';
import { scanCjsPayloadInjection } from './d3-cjs-payload-injection.js';
import { scanInjectedPayloadHash } from './d4-injected-payload-hash.js';
import { scanDnsC2Pattern } from './d5-dns-c2-pattern.js';
import { scanBootstrapResolver } from './d6-bootstrap-resolver.js';
import { scanDnsTxtExfil } from './d7-dns-txt-exfil.js';
import { scanRuntimeTrigger } from './d8-runtime-trigger.js';
import { scanTempArtifact } from './d9-temp-artifact.js';
import { scanUnauthorizedPublisher } from './d10-unauthorized-publisher.js';
import { scanBlastRadius } from './d11-blast-radius.js';

const RULE_SEVERITY = {
  D1: 'critical',
  D2: 'critical',
  D3: 'critical',
  D4: 'critical',
  D5: 'critical',
  D6: 'critical',
  D7: 'critical',
  D8: 'info',
  D9: 'critical',
  D10: 'critical',
  D11: 'critical',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'none'];

function highestSeverity(severities) {
  for (const s of SEVERITY_ORDER) {
    if (severities.includes(s)) return s;
  }
  return 'none';
}

function buildRemediation(triggered) {
  const lines = [];
  if (triggered.includes('D1') || triggered.includes('D11')) {
    lines.push('Pin node-ipc to safe version: 9.1.5 or 12.0.0');
  }
  if (triggered.includes('D9')) {
    lines.push('PRESERVE ~/nt-*/ artifacts for incident response');
  }
  if (triggered.includes('D5') || triggered.includes('D6') || triggered.includes('D7')) {
    lines.push('Review DNS egress logs for sh.azurestaticprovider.net and 37.16.75.69 post May 14, 2026');
  }
  lines.push('Rotate all CI/CD secrets and OIDC tokens');
  lines.push('Audit maintainer email domain expiry for all critical dependencies');
  return lines.join('. ');
}

export async function scan(pkgJson, files = [], registryMeta = null, allFiles = null) {
  const fileList = allFiles || files || [];

  const results = {
    D1: scanVersionBlocklist(pkgJson, registryMeta),
    D2: scanTarballHash(fileList),
    D3: scanCjsPayloadInjection(fileList),
    D4: scanInjectedPayloadHash(fileList),
    D5: scanDnsC2Pattern(fileList, pkgJson),
    D6: scanBootstrapResolver(fileList, pkgJson),
    D7: scanDnsTxtExfil(fileList, pkgJson),
    D8: scanRuntimeTrigger(fileList, pkgJson),
    D9: scanTempArtifact(fileList),
    D10: scanUnauthorizedPublisher(pkgJson, registryMeta),
    D11: scanBlastRadius(fileList),
  };

  const triggered = Object.entries(results)
    .filter(([_, r]) => r.triggered)
    .map(([id]) => id);

  if (triggered.length === 0) return [];

  const severity = highestSeverity(triggered.map(id => RULE_SEVERITY[id]));

  const evidence = {
    campaign: 'NODE_IPC_COMPROMISE',
    triggeredRules: triggered,
    details: Object.fromEntries(
      Object.entries(results).filter(([_, r]) => r.triggered)
    ),
  };

  return [{
    id: 'NODE_IPC_COMPROMISE',
    severity,
    title: 'node-ipc supply chain compromise (May 14, 2026)',
    description: `${triggered.length} signal(s): ${triggered.join(', ')}`,
    evidence: JSON.stringify(evidence),
    mitigation: buildRemediation(triggered),
  }];
}
