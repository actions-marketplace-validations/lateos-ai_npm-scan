import { test, describe } from 'node:test';
import assert from 'assert/strict';
import * as detectors from './detectors/index.js';

describe('D5: Binary Embed Enhancement', () => {
  test('D5: flags cross-platform campaign-1 binary set with high confidence', async () => {
    const allFiles = [
      { path: 'bin/agent-linux-x64', content: String.fromCharCode(0x7f) + 'ELF' },
      { path: 'bin/agent-macos-arm64', content: String.fromCharCode(0xcf, 0xfa, 0xed, 0xfe) },
      { path: 'bin/agent-windows-x86.exe', content: String.fromCharCode(0x4d, 0x5a) },
    ];
    const pkg = { name: 'suspicious-pkg', version: '1.0.0' };
    const findings = await detectors.runAll(pkg, [], null, allFiles);
    const matches = findings.filter((f) => f.id === 'TIER1-BINARY-EMBED');
    assert(matches.length > 0, 'Expected TIER1-BINARY-EMBED finding');
    const hasCrossPlatform = matches.some((m) =>
      m.evidence.some((e) => e.includes('cross-platform'))
    );
    assert(hasCrossPlatform, 'Expected cross-platform binary set evidence');
  });

  test('D5: cross-platform binary set scores > 85', async () => {
    const allFiles = [
      { path: 'bin/agent-linux-x64', content: String.fromCharCode(0x7f) + 'ELF' },
      { path: 'bin/agent-macos-arm64', content: String.fromCharCode(0xcf, 0xfa, 0xed, 0xfe) },
    ];
    const pkg = { name: 'suspicious-pkg', version: '1.0.0' };
    const findings = await detectors.runAll(pkg, [], null, allFiles);
    const matches = findings.filter((f) => f.id === 'TIER1-BINARY-EMBED');
    const hasHighScore = matches.some((m) => m.confidenceScore > 85);
    assert(
      hasHighScore,
      `No finding with confidenceScore > 85; scores: ${matches.map((m) => m.confidenceScore).join(', ')}`
    );
  });

  test('D5: single binary not flagged as cross-platform', async () => {
    const allFiles = [{ path: 'bin/agent-linux-x64', content: String.fromCharCode(0x7f) + 'ELF' }];
    const pkg = { name: 'normal-pkg', version: '1.0.0' };
    const findings = await detectors.runAll(pkg, [], null, allFiles);
    const matches = findings.filter((f) => f.id === 'TIER1-BINARY-EMBED');
    const hasPlatformLabel = matches.some((m) =>
      m.evidence.some((e) => e.includes('cross-platform'))
    );
    assert(!hasPlatformLabel, 'Single binary should not be flagged as cross-platform');
  });
});
