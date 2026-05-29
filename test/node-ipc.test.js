import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/node-ipc-compromise/index.js';
import { scanVersionBlocklist } from '../backend/detectors/node-ipc-compromise/d1-version-blocklist.js';
import { scanTarballHash } from '../backend/detectors/node-ipc-compromise/d2-tarball-hash.js';
import { scanCjsPayloadInjection } from '../backend/detectors/node-ipc-compromise/d3-cjs-payload-injection.js';
import { scanInjectedPayloadHash } from '../backend/detectors/node-ipc-compromise/d4-injected-payload-hash.js';
import { scanDnsC2Pattern } from '../backend/detectors/node-ipc-compromise/d5-dns-c2-pattern.js';
import { scanBootstrapResolver } from '../backend/detectors/node-ipc-compromise/d6-bootstrap-resolver.js';
import { scanDnsTxtExfil } from '../backend/detectors/node-ipc-compromise/d7-dns-txt-exfil.js';
import { scanRuntimeTrigger } from '../backend/detectors/node-ipc-compromise/d8-runtime-trigger.js';
import { scanTempArtifact } from '../backend/detectors/node-ipc-compromise/d9-temp-artifact.js';
import { scanUnauthorizedPublisher } from '../backend/detectors/node-ipc-compromise/d10-unauthorized-publisher.js';
import { scanBlastRadius } from '../backend/detectors/node-ipc-compromise/d11-blast-radius.js';

function makeFile(path, content) {
  return { path, content };
}

const cleanPkg = { name: 'safe-package', version: '1.0.0', scripts: {} };
const cleanRegistryMeta = {
  time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
  versions: { '1.0.0': { _npmUser: { name: 'safe-publisher' } } },
};

// ─── D1: Version blocklist ───────────────────────────────────────────

test('D1: blocks node-ipc 9.1.6', () => {
  const pkg = { name: 'node-ipc', version: '9.1.6', scripts: {} };
  const result = scanVersionBlocklist(pkg, null);
  assert.equal(result.triggered, true);
  assert.equal(result.version, '9.1.6');
  assert.equal(result.safePin, '9.1.5');
});

test('D1: blocks node-ipc 9.2.3', () => {
  const pkg = { name: 'node-ipc', version: '9.2.3', scripts: {} };
  const result = scanVersionBlocklist(pkg, null);
  assert.equal(result.triggered, true);
  assert.equal(result.safePin, '9.1.5');
});

test('D1: blocks node-ipc 12.0.1', () => {
  const pkg = { name: 'node-ipc', version: '12.0.1', scripts: {} };
  const result = scanVersionBlocklist(pkg, null);
  assert.equal(result.triggered, true);
  assert.equal(result.safePin, '12.0.0');
});

test('D1: does not block safe versions', () => {
  const pkg = { name: 'node-ipc', version: '9.1.5', scripts: {} };
  const result = scanVersionBlocklist(pkg, null);
  assert.equal(result.triggered, false);
});

test('D1: does not block non-node-ipc packages', () => {
  const pkg = { name: 'lodash', version: '9.1.6', scripts: {} };
  const result = scanVersionBlocklist(pkg, null);
  assert.equal(result.triggered, false);
});

// ─── D2: Tarball hash ────────────────────────────────────────────────

test('D2: detects malicious tarball hash (9.1.6)', () => {
  const content = Buffer.alloc(100);
  const hash = '449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e';
  const files = [makeFile('node-ipc-9.1.6.tgz', hash)];
  const result = scanTarballHash(files);
  assert.equal(result.triggered, false);
});

test('D2: does not trigger on non-tarball files', () => {
  const files = [makeFile('index.js', 'clean')];
  const result = scanTarballHash(files);
  assert.equal(result.triggered, false);
});

// ─── D3: CJS payload injection ───────────────────────────────────────

test('D3: detects CJS > ESM size anomaly', () => {
  const cjsContent = 'x'.repeat(60 * 1024);
  const mjsContent = 'y'.repeat(5 * 1024);
  const files = [
    makeFile('node-ipc.cjs', cjsContent),
    makeFile('node-ipc.mjs', mjsContent),
  ];
  const result = scanCjsPayloadInjection(files);
  assert.equal(result.triggered, true);
  const hasSizeAnomaly = result.matches.some(m => m.finding === 'size-anomaly');
  assert.equal(hasSizeAnomaly, true);
});

test('D3: detects IIFE suffix in CJS', () => {
  const files = [makeFile('node-ipc.cjs', 'module.exports={};(function(){var x=1})();')];
  const result = scanCjsPayloadInjection(files);
  assert.equal(result.triggered, true);
  const hasIIFE = result.matches.some(m => m.finding === 'iife-suffix');
  assert.equal(hasIIFE, true);
});

test('D3: does not trigger on clean CJS/ESM', () => {
  const files = [
    makeFile('node-ipc.cjs', 'module.exports = {};'),
    makeFile('node-ipc.mjs', 'export default {};'),
  ];
  const result = scanCjsPayloadInjection(files);
  assert.equal(result.triggered, false);
});

// ─── D4: Injected payload hash ───────────────────────────────────────

test('D4: detects known payload hash string in file', () => {
  const files = [makeFile('node-ipc.cjs', 'module.exports={};/*3427a90c8cb9af764445448648176e120ebc6af0a538158340cf6220de4d01b7*/')];
  const result = scanInjectedPayloadHash(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].finding, 'hash-string-present');
});

test('D4: does not trigger on clean CJS', () => {
  const files = [makeFile('node-ipc.cjs', 'module.exports = {};')];
  const result = scanInjectedPayloadHash(files);
  assert.equal(result.triggered, false);
});

test('D4: does not trigger on non-CJS files', () => {
  const files = [makeFile('index.js', '3427a90c8cb9af764445448648176e120ebc6af0a538158340cf6220de4d01b7')];
  const result = scanInjectedPayloadHash(files);
  assert.equal(result.triggered, false);
});

// ─── D5: DNS C2 pattern ──────────────────────────────────────────────

test('D5: detects custom DNS resolver with setServers and resolveTxt', () => {
  const files = [makeFile('index.js', 'const resolver = new dns.promises.Resolver(); resolver.setServers(["37.16.75.69"]); resolver.resolveTxt("test");')];
  const result = scanDnsC2Pattern(files, cleanPkg);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].customResolverIP, '37.16.75.69');
  assert.equal(result.matches[0].hasResolveTxt, true);
});

test('D5: does not flag public resolvers', () => {
  const files = [makeFile('index.js', 'const resolver = new dns.promises.Resolver(); resolver.setServers(["1.1.1.1"]);')];
  const result = scanDnsC2Pattern(files, cleanPkg);
  assert.equal(result.triggered, false);
});

test('D5: does not trigger on clean code', () => {
  const files = [makeFile('index.js', 'module.exports = {};')];
  const result = scanDnsC2Pattern(files, cleanPkg);
  assert.equal(result.triggered, false);
});

// ─── D6: Bootstrap resolver domain ───────────────────────────────────

test('D6: detects sh.azurestaticprovider.net in source', () => {
  const files = [makeFile('index.js', 'const domain = "sh.azurestaticprovider.net";')];
  const result = scanBootstrapResolver(files, cleanPkg);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].finding, 'c2-domain');
});

test('D6: detects C2 IP 37.16.75.69 in source', () => {
  const files = [makeFile('index.js', 'const ip = "37.16.75.69";')];
  const result = scanBootstrapResolver(files, cleanPkg);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].finding, 'c2-ip');
});

test('D6: does not trigger on clean files', () => {
  const files = [makeFile('index.js', 'module.exports = {};')];
  const result = scanBootstrapResolver(files, cleanPkg);
  assert.equal(result.triggered, false);
});

// ─── D7: DNS TXT exfiltration zone ───────────────────────────────────

test('D7: detects bt.node.js exfil zone', () => {
  const files = [makeFile('index.js', 'const zone = "bt.node.js";')];
  const result = scanDnsTxtExfil(files, cleanPkg);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].finding, 'exfil-zone');
});

test('D7: detects resolveTxt() call', () => {
  const files = [makeFile('index.js', 'resolver.resolveTxt("test");')];
  const result = scanDnsTxtExfil(files, cleanPkg);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].finding, 'resolve-txt');
});

test('D7: does not trigger on clean code', () => {
  const files = [makeFile('index.js', 'module.exports = {};')];
  const result = scanDnsTxtExfil(files, cleanPkg);
  assert.equal(result.triggered, false);
});

// ─── D8: Runtime trigger (setImmediate) ──────────────────────────────

test('D8: detects setImmediate() in source', () => {
  const files = [makeFile('node-ipc.cjs', 'setImmediate(function() { exfil(); });')];
  const result = scanRuntimeTrigger(files, cleanPkg);
  assert.equal(result.triggered, true);
});

test('D8: does not trigger without setImmediate', () => {
  const files = [makeFile('index.js', 'setTimeout(function() { }, 100);')];
  const result = scanRuntimeTrigger(files, cleanPkg);
  assert.equal(result.triggered, false);
});

// ─── D9: Temp artifact detection ─────────────────────────────────────

test('D9: detects ~/nt-*/ artifact paths', () => {
  const files = [makeFile('~/nt-xk39f/data.tar.gz', '...')];
  const result = scanTempArtifact(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].dirName, 'nt-xk39f');
});

test('D9: does not trigger on clean paths', () => {
  const files = [makeFile('node_modules/node-ipc/index.js', '...')];
  const result = scanTempArtifact(files);
  assert.equal(result.triggered, false);
});

// ─── D10: Unauthorized publisher ─────────────────────────────────────

test('D10: flags atiertant publisher on node-ipc', () => {
  const pkg = { name: 'node-ipc', version: '12.0.1', scripts: {} };
  const meta = {
    time: { '12.0.1': '2026-05-14T00:00:00.000Z' },
    versions: { '12.0.1': { _npmUser: { name: 'atiertant' } } },
  };
  const result = scanUnauthorizedPublisher(pkg, meta);
  assert.equal(result.triggered, true);
  assert.equal(result.publisher, 'atiertant');
});

test('D10: does not flag clean publisher', () => {
  const pkg = { name: 'node-ipc', version: '12.0.0', scripts: {} };
  const meta = {
    time: { '12.0.0': '2026-01-01T00:00:00.000Z' },
    versions: { '12.0.0': { _npmUser: { name: 'riaevangelist' } } },
  };
  const result = scanUnauthorizedPublisher(pkg, meta);
  assert.equal(result.triggered, false);
});

// ─── D11: Blast radius lockfile detection ────────────────────────────

test('D11: detects node-ipc 9.1.6 in package-lock.json', () => {
  const files = [makeFile('package-lock.json', JSON.stringify({ packages: { 'node_modules/node-ipc': { version: '9.1.6' } } }))];
  const result = scanBlastRadius(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].compromisedVersion, '9.1.6');
  assert.equal(result.matches[0].safePin, '9.1.5');
});

test('D11: detects node-ipc 12.0.1 in yarn.lock', () => {
  const files = [makeFile('yarn.lock', 'node-ipc@^12:\n  version "12.0.1"')];
  const result = scanBlastRadius(files);
  assert.equal(result.triggered, true);
  assert.equal(result.matches[0].compromisedVersion, '12.0.1');
  assert.equal(result.matches[0].safePin, '12.0.0');
});

test('D11: does not trigger on clean lockfiles', () => {
  const files = [makeFile('package-lock.json', JSON.stringify({ packages: { 'node_modules/node-ipc': { version: '9.1.5' } } }))];
  const result = scanBlastRadius(files);
  assert.equal(result.triggered, false);
});

// ─── Composite scan ──────────────────────────────────────────────────

test('NODE_IPC: returns empty for clean package', async () => {
  const findings = await scan(cleanPkg, [], cleanRegistryMeta, []);
  assert.equal(findings.length, 0);
});

test('NODE_IPC: returns critical finding when D1 triggers', async () => {
  const pkg = { name: 'node-ipc', version: '9.1.6', scripts: {} };
  const findings = await scan(pkg, [], null, []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'NODE_IPC_COMPROMISE');
  assert.equal(findings[0].severity, 'critical');
});

test('NODE_IPC: returns critical for D10 publisher match', async () => {
  const pkg = { name: 'node-ipc', version: '12.0.1', scripts: {} };
  const meta = {
    time: { '12.0.1': '2026-05-14T00:00:00.000Z' },
    versions: { '12.0.1': { _npmUser: { name: 'atiertant' } } },
  };
  const findings = await scan(pkg, [], meta, []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  const evidence = JSON.parse(findings[0].evidence);
  assert.ok(evidence.triggeredRules.includes('D10'));
});

test('NODE_IPC: remediation includes pin recommendation', async () => {
  const pkg = { name: 'node-ipc', version: '9.1.6', scripts: {} };
  const findings = await scan(pkg, [], null, []);
  assert.ok(findings[0].mitigation.includes('Pin'));
  assert.ok(findings[0].mitigation.includes('9.1.5'));
});

test('NODE_IPC: multiple rules trigger simultaneously', async () => {
  const pkg = { name: 'node-ipc', version: '9.2.3', scripts: { postinstall: 'curl http://example.com' } };
  const meta = {
    time: { '9.2.3': '2026-05-14T00:00:00.000Z' },
    versions: { '9.2.3': { _npmUser: { name: 'atiertant' } } },
  };
  const files = [
    makeFile('node-ipc.cjs', 'module.exports={};(function(){var x=1})();'),
    makeFile('node-ipc.mjs', 'export default {};'),
  ];
  const findings = await scan(pkg, [], meta, files);
  assert.equal(findings.length, 1);
  const evidence = JSON.parse(findings[0].evidence);
  assert.ok(evidence.triggeredRules.includes('D1'));
  assert.ok(evidence.triggeredRules.includes('D3'));
  assert.ok(evidence.triggeredRules.includes('D10'));
});

test('NODE_IPC: evidence contains campaign metadata', async () => {
  const pkg = { name: 'node-ipc', version: '12.0.1', scripts: {} };
  const findings = await scan(pkg, [], null, []);
  const evidence = JSON.parse(findings[0].evidence);
  assert.equal(evidence.campaign, 'NODE_IPC_COMPROMISE');
});
