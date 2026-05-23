import { test, mock } from 'node:test';
import assert from 'assert/strict';
import { scan, clearCache } from '../backend/detectors/hf-impersonation/index.js';
import { KNOWN_HF_ORGS } from '../backend/detectors/hf-impersonation/known-orgs.js';
import { jaroWinkler } from '../backend/detectors/hf-impersonation/jaro-winkler.js';
import { simhash, similarity as simhashSimilarity } from '../backend/detectors/hf-impersonation/simhash.js';

function mockResponse(body, status = 200, headers = {}) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: new Headers({ 'Content-Type': 'application/json', ...headers }),
  });
}

function buildModelResponse(overrides = {}) {
  return {
    id: overrides.id || 'test/org',
    cardData: overrides.cardData || { library_name: null },
    siblings: overrides.siblings || [{ rfilename: 'model.bin' }],
    downloads: overrides.downloads ?? 1000,
  };
}

function buildUserResponse(overrides = {}) {
  return {
    user: overrides.user || 'testuser',
    dateCreated: overrides.dateCreated || '2023-01-01T00:00:00.000Z',
    type: 'org',
    orgs: [],
  };
}

function makeMockFetch(routes) {
  return async (url) => {
    const urlStr = typeof url === 'string' ? url : url.toString();
    for (const [pattern, handler] of routes) {
      if (urlStr.includes(pattern)) {
        return handler(urlStr);
      }
    }
    throw new Error(`Unexpected fetch: ${urlStr}`);
  };
}

/* ───────── Test 1: No HF references ───────── */

test('HF: no HF references returns empty findings, Stage 2 never runs', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('fetch should not be called');
  });

  const pkgJson = {
    name: 'clean-pkg',
    version: '1.0.0',
    scripts: { test: 'node test.js' },
  };

  const findings = await scan(pkgJson, []);
  assert.equal(findings.length, 0);
});

/* ───────── Test 2: Exact match, no spoof ───────── */

test('HF: exact match openai/gpt2 produces no findings', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('fetch should not be called');
  });

  const pkgJson = {
    name: 'test-pkg',
    scripts: { preinstall: 'echo huggingface.co/openai/gpt2' },
  };

  const findings = await scan(pkgJson, []);
  assert.equal(findings.length, 0);
});

/* ───────── Test 3: 0penai/gpt2 → HF_ORG_SPOOF ───────── */

test('HF: 0penai/gpt2 triggers HF_ORG_SPOOF HIGH with similarity', async (t) => {
  clearCache();
  const spoofedId = '0penai/gpt2';
  const [spoofedOrg] = spoofedId.split('/');

  t.mock.method(globalThis, 'fetch', makeMockFetch([
    [`/api/models/${spoofedId}`, () => mockResponse(buildModelResponse({ id: spoofedId, downloads: 50 }))],
    ['/api/models/openai/gpt2', () => mockResponse(buildModelResponse({ id: 'openai/gpt2', downloads: 500000 }))],
    [`/api/users/${spoofedOrg}`, () => mockResponse(buildUserResponse({ user: spoofedOrg, dateCreated: '2023-06-01T00:00:00.000Z' }))],
    [`${spoofedId}/resolve/main/README.md`, () => mockResponse('spoofed readme content', 200)],
    ['openai/gpt2/resolve/main/README.md', () => mockResponse('canonical readme content', 200)],
  ]));

  const pkgJson = {
    name: 'test-pkg',
    scripts: { test: `echo huggingface.co/${spoofedId}` },
  };

  const findings = await scan(pkgJson, []);
  assert.ok(findings.length >= 1);

  const spoof = findings.find(f => f.id === 'HF_ORG_SPOOF');
  assert.ok(spoof, 'Expected HF_ORG_SPOOF finding');
  assert.equal(spoof.severity, 'high');
  assert.equal(spoof.referencedRepo, spoofedId);
  assert.equal(spoof.canonicalOrg, 'openai');
  assert.ok(spoof.similarityScore >= 0.82);
});

/* ───────── Test 4: rnicrosoft/privacy-filter → HF_ORG_SPOOF + HF_README_CLONE ───────── */

test('HF: rnicrosoft/privacy-filter triggers spoof + README clone', async (t) => {
  clearCache();
  const spoofedId = 'rnicrosoft/privacy-filter';
  const canonicalId = 'microsoft/privacy-filter';
  const [spoofedOrg] = spoofedId.split('/');
  const [canonicalOrg] = canonicalId.split('/');

  const readmeText = Array(50).fill(
    'This model provides privacy-preserving filtering for AI applications. '
    + 'It is designed to remove sensitive information from text while maintaining '
    + 'semantic meaning. Built on transformer architecture with 350M parameters.'
  ).join(' ');

  t.mock.method(globalThis, 'fetch', makeMockFetch([
    [`/api/models/${spoofedId}`, () => mockResponse(buildModelResponse({ id: spoofedId, downloads: 10 }))],
    [`/api/models/${canonicalId}`, () => mockResponse(buildModelResponse({ id: canonicalId, downloads: 25000 }))],
    [`/api/users/${spoofedOrg}`, () => mockResponse(buildUserResponse({ user: spoofedOrg, dateCreated: '2023-06-01T00:00:00.000Z' }))],
    [`${spoofedId}/resolve/main/README.md`, () => mockResponse(readmeText, 200)],
    [`${canonicalId}/resolve/main/README.md`, () => mockResponse(readmeText, 200)],
  ]));

  const pkgJson = {
    name: 'test-pkg',
    scripts: { test: `echo huggingface.co/${spoofedId}` },
  };

  const findings = await scan(pkgJson, []);
  assert.ok(findings.length >= 2);

  const spoof = findings.find(f => f.id === 'HF_ORG_SPOOF');
  assert.ok(spoof, 'Expected HF_ORG_SPOOF');
  assert.equal(spoof.canonicalOrg, canonicalOrg);

  const clone = findings.find(f => f.id === 'HF_README_CLONE');
  assert.ok(clone, 'Expected HF_README_CLONE');
  assert.equal(clone.severity, 'high');
  assert.ok(clone.similarityScore >= 0.9);
  assert.equal(clone.canonicalOrg, canonicalOrg);
});

/* ───────── Test 5: .exe sibling + transformers card → HF_ARTIFACT_MISMATCH ───────── */

test('HF: m1crosoft/suspicious-repo with .exe sibling triggers artifact mismatch', async (t) => {
  clearCache();
  const spoofedId = 'm1crosoft/suspicious-repo';
  const canonicalId = 'microsoft/suspicious-repo';
  const [spoofedOrg] = spoofedId.split('/');
  const [canonicalOrg] = canonicalId.split('/');

  t.mock.method(globalThis, 'fetch', makeMockFetch([
    [`/api/models/${spoofedId}`, () => mockResponse(buildModelResponse({
      id: spoofedId,
      downloads: 5,
      cardData: { library_name: 'transformers' },
      siblings: [
        { rfilename: 'pytorch_model.bin' },
        { rfilename: 'config.json' },
        { rfilename: 'install.exe' },
      ],
    }))],
    [`/api/models/${canonicalId}`, () => mockResponse(buildModelResponse({ id: canonicalId, downloads: 100000 }))],
    [`/api/users/${spoofedOrg}`, () => mockResponse(buildUserResponse({ user: spoofedOrg, dateCreated: '2023-06-01T00:00:00.000Z' }))],
    [`${spoofedId}/resolve/main/README.md`, () => mockResponse('spoofed readme', 200)],
    [`${canonicalId}/resolve/main/README.md`, () => mockResponse('canonical readme', 200)],
  ]));

  const pkgJson = {
    name: 'test-pkg',
    scripts: { test: `echo huggingface.co/${spoofedId}` },
  };

  const findings = await scan(pkgJson, []);
  assert.ok(findings.length >= 2);

  const spoof = findings.find(f => f.id === 'HF_ORG_SPOOF');
  assert.ok(spoof);

  const artifact = findings.find(f => f.id === 'HF_ARTIFACT_MISMATCH');
  assert.ok(artifact, 'Expected HF_ARTIFACT_MISMATCH');
  assert.equal(artifact.severity, 'critical');
  assert.equal(artifact.artifactConflict.declaredType, 'transformers');
  assert.equal(artifact.artifactConflict.suspiciousFilename, 'install.exe');
});

/* ───────── Test 6: Postinstall escalation ───────── */

test('HF: m1crosoft/suspicious-repo with postinstall escalates all findings', async (t) => {
  clearCache();
  const spoofedId = 'm1crosoft/suspicious-repo';
  const canonicalId = 'microsoft/suspicious-repo';
  const [spoofedOrg] = spoofedId.split('/');
  const [canonicalOrg] = canonicalId.split('/');

  t.mock.method(globalThis, 'fetch', makeMockFetch([
    [`/api/models/${spoofedId}`, () => mockResponse(buildModelResponse({
      id: spoofedId,
      downloads: 5,
      cardData: { library_name: 'transformers' },
      siblings: [
        { rfilename: 'pytorch_model.bin' },
        { rfilename: 'config.json' },
        { rfilename: 'install.exe' },
      ],
    }))],
    [`/api/models/${canonicalId}`, () => mockResponse(buildModelResponse({ id: canonicalId, downloads: 100000 }))],
    [`/api/users/${spoofedOrg}`, () => mockResponse(buildUserResponse({ user: spoofedOrg, dateCreated: '2023-06-01T00:00:00.000Z' }))],
    [`${spoofedId}/resolve/main/README.md`, () => mockResponse('spoofed readme', 200)],
    [`${canonicalId}/resolve/main/README.md`, () => mockResponse('canonical readme', 200)],
  ]));

  const pkgJson = {
    name: 'test-pkg',
    scripts: {
      postinstall: `echo huggingface.co/${spoofedId}`,
    },
  };

  const findings = await scan(pkgJson, []);
  assert.ok(findings.length >= 2);

  for (const f of findings) {
    assert.equal(f.severity, 'critical', `Expected critical severity for ${f.id}`);
    assert.ok(f.tags.includes('POSTINSTALL_ESCALATED'), `Expected POSTINSTALL_ESCALATED tag on ${f.id}`);
  }
});

/* ───────── Test 7: NEW_ORG tag when org < 30 days old ───────── */

test('HF: new org with dateCreated < 30 days gets NEW_ORG tag', async (t) => {
  clearCache();
  const spoofedId = 'm1crosoft/new-repo';
  const canonicalId = 'microsoft/new-repo';
  const [spoofedOrg] = spoofedId.split('/');
  const [canonicalOrg] = canonicalId.split('/');

  const recentDate = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();

  t.mock.method(globalThis, 'fetch', makeMockFetch([
    [`/api/models/${spoofedId}`, () => mockResponse(buildModelResponse({ id: spoofedId, downloads: 2 }))],
    [`/api/models/${canonicalId}`, () => mockResponse(buildModelResponse({ id: canonicalId, downloads: 50000 }))],
    [`/api/users/${spoofedOrg}`, () => mockResponse(buildUserResponse({ user: spoofedOrg, dateCreated: recentDate }))],
    [`${spoofedId}/resolve/main/README.md`, () => mockResponse('readme', 200)],
    [`${canonicalId}/resolve/main/README.md`, () => mockResponse('readme', 200)],
  ]));

  const pkgJson = {
    name: 'test-pkg',
    scripts: { test: `echo huggingface.co/${spoofedId}` },
  };

  const findings = await scan(pkgJson, []);
  assert.ok(findings.length >= 1);

  for (const f of findings) {
    assert.ok(f.tags.includes('NEW_ORG'), `Expected NEW_ORG tag on ${f.id}`);
    assert.ok(f.hfMeta, `Expected hfMeta on ${f.id}`);
    assert.ok(f.hfMeta.orgAgeDays < 30, `Expected orgAgeDays < 30`);
  }
});

/* ───────── Utility tests for jaro-winkler and simhash ───────── */

test('HF: jaro-winkler exact match returns 1', () => {
  assert.equal(jaroWinkler('openai', 'openai'), 1);
});

test('HF: jaro-winkler completely different returns 0', () => {
  assert.equal(jaroWinkler('', 'abc'), 0);
});

test('HF: simhash identical texts have similarity 1', () => {
  const text = 'Hello world this is a test of SimHash';
  const fp1 = simhash(text);
  const fp2 = simhash(text);
  assert.equal(simhashSimilarity(fp1, fp2), 1);
});

test('HF: simhash very similar texts have high similarity', () => {
  const base = 'This is a model for text generation with transformer architecture.';
  const fp1 = simhash(base);
  const fp2 = simhash(base.replace('transformer', 'transformer'));
  assert.ok(simhashSimilarity(fp1, fp2) >= 0.9);
});

/* ───────── Edge case: from_pretrained pattern ───────── */

test('HF: from_pretrained with spoofed org is detected', async (t) => {
  const spoofedId = 'm1crosoft/fancy-model';

  t.mock.method(globalThis, 'fetch', makeMockFetch([
    [`/api/models/${spoofedId}`, () => mockResponse(buildModelResponse({ id: spoofedId, downloads: 3 }))],
    ['/api/models/microsoft/fancy-model', () => mockResponse(buildModelResponse({ id: 'microsoft/fancy-model', downloads: 80000 }))],
    ['/api/users/m1crosoft', () => mockResponse(buildUserResponse({ user: 'm1crosoft', dateCreated: '2023-06-01T00:00:00.000Z' }))],
    [`${spoofedId}/resolve/main/README.md`, () => mockResponse('readme', 200)],
    ['microsoft/fancy-model/resolve/main/README.md', () => mockResponse('readme', 200)],
  ]));

  const pkgJson = {
    name: 'test-pkg',
    scripts: { test: 'node -e "from_pretrained(\'m1crosoft/fancy-model\')"' },
  };

  const findings = await scan(pkgJson, []);
  const spoof = findings.find(f => f.id === 'HF_ORG_SPOOF');
  assert.ok(spoof);
  assert.equal(spoof.referencedRepo, 'm1crosoft/fancy-model');
});

/* ───────── Known orgs constant is seeded correctly ───────── */

test('HF: KNOWN_HF_ORGS contains 15 entries', () => {
  assert.equal(KNOWN_HF_ORGS.length, 15);
  assert.ok(KNOWN_HF_ORGS.includes('openai'));
  assert.ok(KNOWN_HF_ORGS.includes('meta-llama'));
  assert.ok(KNOWN_HF_ORGS.includes('microsoft'));
});
