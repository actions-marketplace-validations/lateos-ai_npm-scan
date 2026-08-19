import { test } from 'node:test';
import assert from 'assert/strict';
import { generateSARIF } from '../backend/report.js';
import { scan as d29 } from '../backend/detectors/tier1-runtime-evasion.js';
import { scan as d30 } from '../backend/detectors/tier1-workspace-persistence.js';
import { scan as d31 } from '../backend/detectors/tier1-tarball-git-desync.js';

/**
 * Tier-1 detectors emit { message, evidence: string[], locations: [{file,line}] }
 * while ATK-* detectors emit { title, description, evidence: string }. Both
 * must serialize to valid SARIF 2.1.0 — the tier-1 shape previously produced
 * `message: {}` and an array in `artifactLocation.uri`, neither of which is
 * schema-valid.
 */

const f = (path, content) => ({ path, content });

async function collectFindings() {
  const findings = [];
  findings.push(
    ...d29({ name: 'ui-theme-toolkit', version: '1.0.0', main: 'index.js' }, [], null, [
      f('index.js', 'import { dlopen } from "bun:ffi"; dlopen("libc.so", {});'),
    ])
  );
  findings.push(
    ...d30({ name: 'ui-theme-toolkit', version: '1.0.0' }, [], null, [
      f('index.js', "require('fs').writeFileSync(process.env.HOME + '/.claude/mcp.json', p);"),
    ])
  );
  findings.push(
    ...(await d31(
      {
        name: 'payment-sdk',
        version: '3.2.0',
        repository: { url: 'https://github.com/acme/payment-sdk' },
        bin: { cli: './bin/cli.js' },
      },
      [],
      { gitHead: 'a'.repeat(40) },
      [f('package/bin/cli.js', 'require("child_process").execSync("id");')],
      { enabled: true, sourceProvider: async () => new Map([['index.js', 'export const a = 1;']]) }
    ))
  );
  // ATK-* shape, for the mixed-shape case
  findings.push({
    id: 'ATK-001',
    severity: 'high',
    title: 'Lifecycle hook',
    description: 'preinstall executes code',
    evidence: 'package.json',
  });
  return findings;
}

function validateSarifResult(result, ruleIds) {
  // Required by the SARIF 2.1.0 schema.
  assert.ok(ruleIds.has(result.ruleId), `ruleId ${result.ruleId} missing from tool.driver.rules`);
  assert.ok(['error', 'warning', 'note', 'none'].includes(result.level), 'invalid level');
  assert.equal(typeof result.message, 'object');
  assert.equal(typeof result.message.text, 'string', 'message.text must be a string');
  assert.ok(result.message.text.length > 0, 'message.text must not be empty');
  assert.ok(Array.isArray(result.locations) && result.locations.length > 0);
  for (const loc of result.locations) {
    const phys = loc.physicalLocation;
    assert.ok(phys, 'missing physicalLocation');
    assert.equal(typeof phys.artifactLocation.uri, 'string', 'artifactLocation.uri must be string');
    assert.ok(phys.artifactLocation.uri.length > 0);
    assert.equal(typeof phys.region.startLine, 'number');
    assert.ok(phys.region.startLine >= 1, 'startLine must be 1-based');
  }
}

test('SARIF: new detectors emit schema-valid results', async () => {
  const findings = await collectFindings();
  assert.ok(findings.length >= 4, 'expected findings from all three new detectors');

  const sarif = JSON.parse(generateSARIF({ findings }));
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.schema.includes('sarif-schema-2.1.0'));

  const run = sarif.runs[0];
  const ruleIds = new Set(run.tool.driver.rules.map((r) => r.id));
  assert.equal(run.results.length, findings.length);
  for (const result of run.results) {
    validateSarifResult(result, ruleIds);
  }
});

test('SARIF: every declared rule carries non-empty descriptions', async () => {
  const sarif = JSON.parse(generateSARIF({ findings: await collectFindings() }));
  for (const rule of sarif.runs[0].tool.driver.rules) {
    assert.equal(typeof rule.id, 'string');
    assert.ok(rule.id.length > 0);
    assert.equal(typeof rule.name, 'string');
    assert.ok(rule.shortDescription.text.length > 0, `${rule.id} has an empty shortDescription`);
    assert.ok(rule.fullDescription.text.length > 0, `${rule.id} has an empty fullDescription`);
  }
});

test('SARIF: the three new rule ids appear as declared rules', async () => {
  const sarif = JSON.parse(generateSARIF({ findings: await collectFindings() }));
  const ids = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  for (const id of ['D29-RUNTIME-EVASION', 'D30-WORKSPACE-PERSISTENCE', 'ERR_TARBALL_GIT_DESYNC']) {
    assert.ok(ids.includes(id), `missing rule ${id}`);
  }
});

test('SARIF: locations point at real files and lines, not evidence strings', async () => {
  const findings = d30({ name: 'ui-theme-toolkit', version: '1.0.0' }, [], null, [
    f(
      'lib/persist.js',
      "\n\nrequire('fs').writeFileSync(process.env.HOME + '/.claude/mcp.json', p);"
    ),
  ]);
  const sarif = JSON.parse(generateSARIF({ findings }));
  const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(loc.artifactLocation.uri, 'lib/persist.js');
  assert.equal(loc.region.startLine, 3);
});

test('SARIF: evidence lines are carried as properties, not locations', async () => {
  const findings = d30({ name: 'ui-theme-toolkit', version: '1.0.0' }, [], null, [
    f('index.js', "require('fs').writeFileSync(process.env.HOME + '/.claude/mcp.json', p);"),
  ]);
  const result = JSON.parse(generateSARIF({ findings })).runs[0].results[0];
  assert.ok(Array.isArray(result.properties.evidence));
  assert.ok(result.properties.evidence.every((e) => typeof e === 'string'));
  assert.equal(typeof result.properties.confidenceScore, 'number');
  assert.equal(typeof result.properties.recommendation, 'string');
});

test('SARIF: legacy ATK-shaped findings still serialize correctly', () => {
  const findings = [
    {
      id: 'ATK-004',
      severity: 'medium',
      title: 'Persistence',
      description: 'Creates editor config dirs',
      evidence: 'mkdir pattern match',
    },
  ];
  const sarif = JSON.parse(generateSARIF({ findings }));
  const result = sarif.runs[0].results[0];
  assert.equal(result.message.text, 'Creates editor config dirs');
  assert.equal(result.level, 'warning');
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'mkdir pattern match');
});

test('SARIF: severity maps to SARIF levels consistently', () => {
  const findings = [
    { id: 'A', severity: 'critical', message: 'c', locations: [{ file: 'a.js', line: 1 }] },
    { id: 'B', severity: 'high', message: 'h', locations: [{ file: 'a.js', line: 1 }] },
    { id: 'C', severity: 'medium', message: 'm', locations: [{ file: 'a.js', line: 1 }] },
    { id: 'D', severity: 'low', message: 'l', locations: [{ file: 'a.js', line: 1 }] },
  ];
  const results = JSON.parse(generateSARIF({ findings })).runs[0].results;
  assert.deepEqual(
    results.map((r) => r.level),
    ['error', 'error', 'warning', 'note']
  );
});
