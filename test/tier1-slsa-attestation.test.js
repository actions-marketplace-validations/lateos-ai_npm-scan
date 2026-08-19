import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-slsa-attestation.js';
import {
  verifyProvenance,
  buildPurl,
  integrityToDigest,
  normalizeRepoUrl,
  applyProvenanceDiscount,
  _clearBundleCache,
} from '../backend/detectors/lib/slsa-verifier.js';

/*
 * Fixtures mirror the real npm packument / attestation shapes:
 *  - dist.attestations is an OBJECT holding a pointer, not an array
 *  - in-toto subject names are purls (pkg:npm/name@version)
 *  - in-toto digests are hex; dist.integrity is "sha512-<base64>"
 */

const TARBALL_HEX = 'a'.repeat(128);
const TARBALL_INTEGRITY = `sha512-${Buffer.from(TARBALL_HEX, 'hex').toString('base64')}`;

function makeStatement({ subjectName, digestHex, repo }) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: subjectName, digest: { sha512: digestHex } }],
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: { workflow: { repository: repo } },
      },
      runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } },
    },
  };
}

function makeMeta({
  name = 'demo',
  version = '1.0.0',
  digestHex = TARBALL_HEX,
  integrity = TARBALL_INTEGRITY,
  repo = 'https://github.com/acme/demo',
  declaredRepo = 'git+https://github.com/acme/demo.git',
  subjectName,
  attestations = 'inline',
} = {}) {
  const statement = makeStatement({
    subjectName: subjectName ?? buildPurl(name, version),
    digestHex,
    repo,
  });
  const bundle = {
    dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString('base64') },
  };
  const meta = {
    name,
    version,
    repository: declaredRepo ? { type: 'git', url: declaredRepo } : undefined,
    dist: { integrity },
  };
  if (attestations === 'inline') {
    meta.dist.attestations = [{ predicateType: 'https://slsa.dev/provenance/v1', bundle }];
  } else if (attestations === 'none') {
    // no dist.attestations at all
  }
  return meta;
}

/** Swap globalThis.fetch for the duration of a test; no network in the suite. */
async function withFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  _clearBundleCache();
  try {
    await fn();
  } finally {
    globalThis.fetch = original;
    _clearBundleCache();
  }
}

test('SLSA: dist.attestations OBJECT pointer is followed instead of read as an array', async () => {
  // Regression guard for the shape bug: `.length` on an object is undefined,
  // which made every provenance-bearing package report "no_attestations".
  const inline = makeMeta();
  const attestationDoc = { attestations: inline.dist.attestations };

  const meta = makeMeta({ attestations: 'none' });
  meta.dist.attestations = {
    url: 'https://registry.npmjs.org/-/npm/v1/attestations/demo@1.0.0',
    provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
  };

  let requested = null;
  await withFetch(
    async (url) => {
      requested = url;
      return { ok: true, json: async () => attestationDoc };
    },
    async () => {
      const prov = await verifyProvenance('demo', '1.0.0', meta);
      assert.equal(requested, meta.dist.attestations.url, 'should follow the pointer URL');
      assert.notEqual(prov.error, 'no_attestations');
      assert.equal(prov.provenancePresent, true);
      assert.equal(prov.digestBound, true);
      assert.equal(prov.slsaLevel, 3);
    }
  );
});

test('SLSA: unreachable attestation document degrades to a low-severity finding', async () => {
  const meta = makeMeta({ attestations: 'none' });
  meta.dist.attestations = { url: 'https://registry.npmjs.org/-/npm/v1/attestations/demo@1.0.0' };

  await withFetch(
    async () => ({ ok: false, json: async () => ({}) }),
    async () => {
      const findings = await scan({ name: 'demo', version: '1.0.0' }, [], meta, []);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].severity, 'low');
      assert.match(findings[0].message, /Could not retrieve provenance/);
    }
  );
});

test('SLSA: attestation document is fetched once and cached across calls', async () => {
  const inline = makeMeta();
  const attestationDoc = { attestations: inline.dist.attestations };
  const meta = makeMeta({ attestations: 'none' });
  meta.dist.attestations = { url: 'https://registry.npmjs.org/-/npm/v1/attestations/demo@1.0.0' };

  let calls = 0;
  await withFetch(
    async () => {
      calls += 1;
      return { ok: true, json: async () => attestationDoc };
    },
    async () => {
      await verifyProvenance('demo', '1.0.0', meta);
      await verifyProvenance('demo', '1.0.0', meta);
      assert.equal(calls, 1, 'second call should hit the cache');
    }
  );
});

test('SLSA: purl subject name matches the package (scoped and unscoped)', async () => {
  const unscoped = await verifyProvenance('demo', '1.0.0', makeMeta());
  assert.notEqual(unscoped.error, 'subject_mismatch');
  assert.equal(unscoped.provenancePresent, true);

  const scopedMeta = makeMeta({ name: '@acme/demo', version: '2.1.0' });
  const scoped = await verifyProvenance('@acme/demo', '2.1.0', scopedMeta);
  assert.notEqual(scoped.error, 'subject_mismatch');
  assert.equal(scoped.digestBound, true);
});

test('SLSA: buildPurl percent-encodes only the scope marker', () => {
  assert.equal(buildPurl('demo', '1.0.0'), 'pkg:npm/demo@1.0.0');
  assert.equal(buildPurl('@acme/demo', '2.1.0'), 'pkg:npm/%40acme/demo@2.1.0');
});

test('SLSA: integrityToDigest converts sha512-<base64> to hex', () => {
  assert.deepEqual(integrityToDigest(TARBALL_INTEGRITY), { alg: 'sha512', hex: TARBALL_HEX });
  assert.equal(integrityToDigest('garbage'), null);
  assert.equal(integrityToDigest(undefined), null);
});

test('SLSA: normalizeRepoUrl reconciles git+https, ssh, and .git forms', () => {
  const want = 'https://github.com/acme/demo';
  assert.equal(normalizeRepoUrl('git+https://github.com/acme/demo.git'), want);
  assert.equal(normalizeRepoUrl('git@github.com:acme/demo.git'), want);
  assert.equal(normalizeRepoUrl('https://github.com/acme/demo/'), want);
  assert.equal(normalizeRepoUrl({ url: 'git+https://github.com/acme/demo.git' }), want);
  assert.equal(normalizeRepoUrl(null), null);
});

test('SLSA: verified is always false and grants no trust, even on a well-formed attestation', async () => {
  const prov = await verifyProvenance('demo', '1.0.0', makeMeta());
  assert.equal(prov.digestBound, true);
  assert.equal(prov.claimsMatchRepo, true);
  assert.equal(prov.slsaLevel, 3);
  // The trust-model invariant:
  assert.equal(prov.verified, false);
  assert.equal(prov.trustGrant, 0);
  assert.equal(prov.signatureVerified, false);
});

test('SLSA: applyProvenanceDiscount never alters findings under the current trust model', async () => {
  const prov = await verifyProvenance('demo', '1.0.0', makeMeta());
  const findings = [{ id: 'X', confidenceScore: 90, evidence: [] }];
  const out = applyProvenanceDiscount(findings, prov);
  assert.equal(out[0].confidenceScore, 90);
  assert.equal(out, findings);
});

test('SLSA: digest mismatch between attestation and tarball is flagged high', async () => {
  const meta = makeMeta({ digestHex: 'b'.repeat(128) });
  const findings = await scan({ name: 'demo', version: '1.0.0' }, [], meta, []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'high');
  assert.match(findings[0].message, /does not match the published tarball digest/);
});

test('SLSA: attestation minted for a different subject is flagged high', async () => {
  const meta = makeMeta({ subjectName: 'pkg:npm/other-package@9.9.9' });
  const findings = await scan({ name: 'demo', version: '1.0.0' }, [], meta, []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'high');
  assert.match(findings[0].message, /different subject/);
});

test('SLSA: build-source repo differing from declared repository is flagged medium', async () => {
  const meta = makeMeta({ repo: 'https://github.com/attacker/demo' });
  const findings = await scan({ name: 'demo', version: '1.0.0' }, [], meta, []);
  const mismatch = findings.find((f) => f.severity === 'medium');
  assert.ok(mismatch, 'expected a repo-mismatch finding');
  assert.match(mismatch.message, /built from a different repository/);
});

test('SLSA: valid provenance is informational and does NOT set provenance_verified', async () => {
  const findings = await scan({ name: 'demo', version: '1.0.0' }, [], makeMeta(), []);
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.severity, 'low');
  assert.match(f.message, /signature NOT verified/);
  assert.equal(f.context.signature_verified, false);
  // Must not exist, or report.js/policy.js would grant a discount.
  assert.equal(f.context.provenance_verified, undefined);
});

test('SLSA: missing provenance is low severity, not medium', async () => {
  // Guards the "permanent +3 risk floor on every scan" regression.
  const meta = makeMeta({ attestations: 'none' });
  const findings = await scan({ name: 'demo', version: '1.0.0' }, [], meta, []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'low');
  assert.match(findings[0].message, /no SLSA provenance attestation/);
});

test('SLSA: no registry metadata and no registry reachability yields no findings', async () => {
  await withFetch(
    async () => ({ ok: false, json: async () => ({}) }),
    async () => {
      const findings = await scan({ name: 'demo', version: '1.0.0' }, [], null, []);
      assert.deepEqual(findings, []);
    }
  );
});

test('SLSA: missing name or version yields no findings', async () => {
  assert.deepEqual(await scan({ version: '1.0.0' }, [], makeMeta(), []), []);
  assert.deepEqual(await scan({ name: 'demo' }, [], makeMeta(), []), []);
});
