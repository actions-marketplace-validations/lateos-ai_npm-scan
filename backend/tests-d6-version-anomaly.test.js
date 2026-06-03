import { test, describe } from 'node:test';
import assert from 'assert/strict';
import * as detectors from './detectors/index.js';

describe('D6: Version Anomaly', () => {
  test('D6: flags 99.99.99 when legitimate max is 5.3.2', async () => {
    const pkg = { name: '@widget/core', version: '99.99.99' };
    const registryMeta = ['1.0.0', '1.5.0', '2.0.0', '2.1.0', '3.0.0', '4.0.0', '5.0.0', '5.3.2'];
    const findings = await detectors.runAll(pkg, [], registryMeta);
    const match = findings.find(f => f.id === 'TIER1-VERSION-ANOMALY');
    assert(match, 'Expected TIER1-VERSION-ANOMALY finding');
    assert(match.confidenceScore > 90, `confidenceScore ${match.confidenceScore} <= 90`);
  });

  test('D6: flags 11.11.11 with high confidence', async () => {
    const pkg = { name: 'internal-utils', version: '11.11.11' };
    const registryMeta = ['1.0.0', '1.0.1', '1.1.0', '1.2.0', '2.0.0'];
    const findings = await detectors.runAll(pkg, [], registryMeta);
    const match = findings.find(f => f.id === 'TIER1-VERSION-ANOMALY');
    assert(match, 'Expected TIER1-VERSION-ANOMALY finding');
    assert(match.confidenceScore > 85, `confidenceScore ${match.confidenceScore} <= 85`);
  });

  test('D6: does NOT flag legitimate 2.0.0 jump from 1.9.9', async () => {
    const pkg = { name: 'stable-lib', version: '2.0.0' };
    const registryMeta = [
      '1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0',
      '1.6.0', '1.7.0', '1.8.0', '1.9.0', '1.9.9',
    ];
    const findings = await detectors.runAll(pkg, [], registryMeta);
    const match = findings.find(f => f.id === 'TIER1-VERSION-ANOMALY');
    assert(!match, 'Should not flag legitimate 2.0.0 major bump');
  });

  test('D6: handles null registry gracefully — degrades confidence', async () => {
    const pkg = { name: 'offline-pkg', version: '99.99.99' };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-VERSION-ANOMALY');
    assert(match, 'Expected TIER1-VERSION-ANOMALY finding');
    assert(match.confidenceScore < 70, `confidenceScore ${match.confidenceScore} >= 70`);
  });

  test('D6: no finding on KNOWN_REPUTABLE_PACKAGES regardless of version', async () => {
    const pkg = { name: 'react', version: '99.99.99' };
    const registryMeta = ['1.0.0', '2.0.0'];
    const findings = await detectors.runAll(pkg, [], registryMeta);
    const match = findings.find(f => f.id === 'TIER1-VERSION-ANOMALY');
    assert(!match);
  });

  test('D6: no finding on normal semver within range', async () => {
    const pkg = { name: 'widget-core', version: '5.4.1' };
    const registryMeta = ['1.0.0', '2.0.0', '3.0.0', '4.0.0', '5.0.0', '5.4.0'];
    const findings = await detectors.runAll(pkg, [], registryMeta);
    const match = findings.find(f => f.id === 'TIER1-VERSION-ANOMALY');
    assert(!match);
  });
});
