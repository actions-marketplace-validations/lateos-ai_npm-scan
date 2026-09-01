import { test, mock as _mock } from 'node:test';
import assert from 'assert/strict';
import { checkActivationEventRisk } from '../../backend/vsix-scan/detectors/activation-event-risk.js';

test('VSIX activation: onStartupFinished alone = HIGH', async () => {
  const manifest = { activationEvents: ['onStartupFinished'], main: './dist/main.js' };
  const result = await checkActivationEventRisk(manifest, [], []);
  assert.ok(result.triggered);
  assert.equal(result.riskLevel, 'high');
});

test('VSIX activation: * wildcard = CRITICAL', async () => {
  const manifest = { activationEvents: ['*'], main: './dist/main.js' };
  const result = await checkActivationEventRisk(manifest, [], []);
  assert.ok(result.triggered);
  assert.equal(result.riskLevel, 'critical');
});

test('VSIX activation: HIGH + external npx = CRITICAL', async () => {
  const manifest = {
    activationEvents: ['onStartupFinished'],
    main: './dist/main.js',
    contributes: {
      commands: [{ title: 'npx external command' }],
    },
  };
  const result = await checkActivationEventRisk(manifest, [], []);
  assert.ok(result.triggered);
  assert.equal(result.riskLevel, 'critical');
});

test('VSIX activation: first-time activation event addition fires', async () => {
  const manifest = { activationEvents: ['onStartupFinished'], main: './dist/main.js' };
  const priorVersions = [{ activationEvents: ['onCommand:foo'] }];
  const result = await checkActivationEventRisk(manifest, [], priorVersions);
  assert.ok(result.triggered);
  assert.ok(result.why.some((w) => w.includes('First-time')));
});

test('VSIX activation: low-risk onCommand = silent', async () => {
  const manifest = { activationEvents: ['onCommand:foo.bar'], main: './dist/main.js' };
  const result = await checkActivationEventRisk(manifest, [], []);
  assert.equal(result.triggered, false);
});
