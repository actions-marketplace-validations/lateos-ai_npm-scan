import { test, describe } from 'node:test';
import assert from 'assert/strict';
import * as detectors from './detectors/index.js';

// ─── D6a — tier1-version-confusion ──────────────────────────────────

describe('D6a — tier1-version-confusion', () => {
  test('D6a: exact sentinel 99.99.99 → HIGH, confidenceScore >= 80', async () => {
    const pkg = { name: 'internal-utils', version: '99.99.99' };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-VERSION-CONFUSION');
    assert(match, 'Expected TIER1-VERSION-CONFUSION finding');
    assert.equal(match.confidence, 'HIGH');
    assert(match.confidenceScore >= 80, `confidenceScore ${match.confidenceScore} < 80`);
  });

  test('D6a: exact sentinel 9.9.9 → MEDIUM, confidenceScore >= 60', async () => {
    const pkg = { name: 'corp-auth', version: '9.9.9' };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-VERSION-CONFUSION');
    assert(match, 'Expected TIER1-VERSION-CONFUSION finding');
    assert.equal(match.confidence, 'MEDIUM');
    assert(match.confidenceScore >= 60, `confidenceScore ${match.confidenceScore} < 60`);
  });

  test('D6a: high-version heuristic 99.5.8 → MEDIUM, confidenceScore >= 60', async () => {
    const pkg = { name: 'internal-payments', version: '99.5.8' };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-VERSION-CONFUSION');
    assert(match, 'Expected TIER1-VERSION-CONFUSION finding');
    assert.equal(match.confidence, 'MEDIUM');
    assert(match.confidenceScore >= 60, `confidenceScore ${match.confidenceScore} < 60`);
  });

  test('D6a: heuristic does not fire on legitimate high patch, e.g. 1.99.0', async () => {
    const pkg = { name: 'some-lib', version: '1.99.0' };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-VERSION-CONFUSION');
    assert(!match);
  });

  test('D6a: no finding on legitimate semver 4.17.21', async () => {
    const pkg = { name: 'lodash', version: '4.17.21' };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-VERSION-CONFUSION');
    assert(!match);
  });

  test('D6a: no finding on KNOWN_REPUTABLE_PACKAGES regardless of version', async () => {
    const pkg = { name: 'react', version: '99.99.99' };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-VERSION-CONFUSION');
    assert(!match);
  });
});

// ─── D6c — tier1-cloud-imds ─────────────────────────────────────────

describe('D6c — tier1-cloud-imds', () => {
  test('D6c: detects GCP metadata endpoint in JS file', async () => {
    const jsFiles = [{ path: 'index.js', content: 'fetch("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")' }];
    const findings = await detectors.runAll({ name: 'test-pkg' }, jsFiles);
    const match = findings.find(f => f.id === 'TIER1-CLOUD-IMDS');
    assert(match, 'Expected TIER1-CLOUD-IMDS finding');
    assert.equal(match.confidence, 'HIGH');
    assert(match.confidenceScore >= 80, `confidenceScore ${match.confidenceScore} < 80`);
  });

  test('D6c: detects Azure IMDS endpoint in JS file', async () => {
    const jsFiles = [{ path: 'app.js', content: 'axios.get("http://169.254.169.254/metadata/instance", { headers: { Metadata: "true" } })' }];
    const findings = await detectors.runAll({ name: 'test-pkg' }, jsFiles);
    const match = findings.find(f => f.id === 'TIER1-CLOUD-IMDS');
    assert(match, 'Expected TIER1-CLOUD-IMDS finding');
    assert.equal(match.confidence, 'HIGH');
    assert(match.confidenceScore >= 80, `confidenceScore ${match.confidenceScore} < 80`);
  });

  test('D6c: detects GCP/Azure pattern in postinstall script', async () => {
    const pkg = {
      name: 'malicious-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'node -e "require(\\"http\\").get(\\"http://metadata.google.internal/computeMetadata/v1/\\")"',
      },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-CLOUD-IMDS');
    assert(match, 'Expected TIER1-CLOUD-IMDS finding');
    assert.equal(match.confidence, 'HIGH');
    assert(match.confidenceScore >= 80, `confidenceScore ${match.confidenceScore} < 80`);
  });

  test('D6c: no finding on clean JS with no IMDS patterns', async () => {
    const jsFiles = [{ path: 'clean.js', content: 'const x = 1 + 1;' }];
    const findings = await detectors.runAll({ name: 'test-pkg' }, jsFiles);
    const match = findings.find(f => f.id === 'TIER1-CLOUD-IMDS');
    assert(!match);
  });

  test('D6c: no finding when 169.254.169.254 appears without /metadata path', async () => {
    const jsFiles = [{ path: 'docs.js', content: '// link-local range starts at 169.254.0.0' }];
    const findings = await detectors.runAll({ name: 'test-pkg' }, jsFiles);
    const match = findings.find(f => f.id === 'TIER1-CLOUD-IMDS');
    assert(!match);
  });
});
