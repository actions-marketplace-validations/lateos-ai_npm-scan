/**
 * SLSA provenance inspection.
 *
 * TRUST MODEL — read before changing `verified`:
 *
 * This module performs *structural* verification only. It confirms that an
 * attestation exists, that it binds to the exact tarball the registry is
 * serving (subject digest === dist.integrity), and that its build claims are
 * self-consistent with the package's declared repository.
 *
 * It does NOT verify the Sigstore bundle signature, the Fulcio certificate
 * chain, or the Rekor transparency-log inclusion proof. Therefore
 * `verified` is ALWAYS false and `trustGrant` is ALWAYS 0 — a structurally
 * valid attestation is not evidence of trustworthiness, because an attacker
 * who can serve the attestation document can also author its contents.
 *
 * Do not flip `verified` to true, and do not grant a confidence discount,
 * until real signature + chain + inclusion-proof verification lands.
 * See docs/security/gap-analysis-2026-08.md §1-§2.
 */

const SLSA_PREDICATE_LEVELS = {
  'https://slsa.dev/provenance/v0.2': 2,
  'https://slsa.dev/provenance/v1': 3,
};

const ATTESTATION_FETCH_TIMEOUT_MS = 3000;

const bundleCache = new Map();

function emptyResult() {
  return {
    provenancePresent: false,
    digestBound: false,
    claimsMatchRepo: null,
    slsaLevel: 0,
    buildType: null,
    builderId: null,
    sourceRepo: null,
    signatureVerified: false,
    verified: false,
    trustGrant: 0,
    error: null,
  };
}

/**
 * npm packuments expose `dist.attestations` as an OBJECT holding a pointer to
 * the attestation document, not as an inline array:
 *   { url: "...", provenance: { predicateType: "https://slsa.dev/provenance/v1" } }
 * Older/other shapes are tolerated defensively.
 */
function getAttestationRef(registryMeta) {
  const raw = registryMeta?.dist?.attestations ?? registryMeta?.attestations;
  if (!raw) return null;

  if (Array.isArray(raw)) {
    return raw.length ? { inline: raw } : null;
  }
  if (typeof raw === 'object' && raw.url) {
    return { url: raw.url, predicateType: raw.provenance?.predicateType || null };
  }
  return null;
}

/**
 * Package URL form used in in-toto subjects: pkg:npm/name@version.
 * Scoped packages percent-encode the leading '@' only: pkg:npm/%40scope/name@version.
 */
export function buildPurl(pkgName, version) {
  const encoded = pkgName.startsWith('@') ? `%40${pkgName.slice(1)}` : pkgName;
  return `pkg:npm/${encoded}@${version}`;
}

function subjectMatchesPackage(subject, pkgName, version) {
  if (!Array.isArray(subject)) return false;
  const purl = buildPurl(pkgName, version).toLowerCase();
  const accepted = new Set([purl, `${pkgName}@${version}`.toLowerCase(), pkgName.toLowerCase()]);
  return subject.some((s) => accepted.has(String(s?.name || '').toLowerCase()));
}

/**
 * `dist.integrity` is "<alg>-<base64>"; in-toto digests are hex-encoded.
 */
export function integrityToDigest(integrity) {
  const match = /^([a-z0-9]+)-(.+)$/i.exec(String(integrity || ''));
  if (!match) return null;
  try {
    return { alg: match[1].toLowerCase(), hex: Buffer.from(match[2], 'base64').toString('hex') };
  } catch {
    return null;
  }
}

function subjectBindsToTarball(subject, distIntegrity) {
  const expected = integrityToDigest(distIntegrity);
  if (!expected || !Array.isArray(subject)) return false;

  return subject.some((s) => {
    const actual = s?.digest?.[expected.alg];
    return typeof actual === 'string' && actual.toLowerCase() === expected.hex;
  });
}

export function normalizeRepoUrl(url) {
  if (!url) return null;
  const raw = typeof url === 'string' ? url : url.url;
  if (!raw) return null;

  return String(raw)
    .trim()
    .replace(/^git\+/, '')
    .replace(/^git@([^:/]+):/, 'https://$1/')
    .replace(/^(?:git|ssh):\/\/(?:git@)?/, 'https://')
    .replace(/\.git$/, '')
    .replace(/\/+$/, '')
    .toLowerCase();
}

function decodeStatement(bundle) {
  const payload = bundle?.dsseEnvelope?.payload;
  if (!payload) return null;
  try {
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf-8'));
  } catch {
    return null;
  }
}

async function fetchAttestationDocument(url) {
  if (bundleCache.has(url)) return bundleCache.get(url);

  let doc = null;
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(ATTESTATION_FETCH_TIMEOUT_MS),
    });
    if (response.ok) {
      doc = await response.json();
    }
  } catch {
    doc = null;
  }

  bundleCache.set(url, doc);
  return doc;
}

/**
 * Inspect a package's SLSA provenance.
 *
 * Returns a structural report. `verified` is always false by design — see the
 * trust-model note at the top of this file.
 */
export async function verifyProvenance(pkgName, version, registryMeta) {
  const result = emptyResult();
  if (!registryMeta || !pkgName || !version) {
    result.error = 'missing_input';
    return result;
  }

  const ref = getAttestationRef(registryMeta);
  if (!ref) {
    result.error = 'no_attestations';
    return result;
  }

  let attestations = ref.inline;
  if (!attestations) {
    const doc = await fetchAttestationDocument(ref.url);
    attestations = doc?.attestations;
    if (!Array.isArray(attestations) || attestations.length === 0) {
      result.error = 'attestation_fetch_failed';
      return result;
    }
  }

  result.provenancePresent = true;

  const slsaAttestation = attestations.find((a) =>
    String(a?.predicateType || '').startsWith('https://slsa.dev/provenance')
  );
  if (!slsaAttestation) {
    result.error = 'no_slsa_predicate';
    return result;
  }

  result.slsaLevel = SLSA_PREDICATE_LEVELS[slsaAttestation.predicateType] || 0;

  const statement = decodeStatement(slsaAttestation.bundle);
  if (!statement) {
    result.error = 'malformed_statement';
    return result;
  }

  if (!subjectMatchesPackage(statement.subject, pkgName, version)) {
    result.error = 'subject_mismatch';
    return result;
  }

  result.digestBound = subjectBindsToTarball(statement.subject, registryMeta?.dist?.integrity);

  const predicate = statement.predicate || {};
  result.buildType = predicate.buildDefinition?.buildType || predicate.buildType || null;
  result.builderId = predicate.runDetails?.builder?.id || predicate.builder?.id || null;
  result.sourceRepo = normalizeRepoUrl(
    predicate.buildDefinition?.externalParameters?.workflow?.repository
  );

  const declaredRepo = normalizeRepoUrl(registryMeta.repository);
  if (result.sourceRepo && declaredRepo) {
    result.claimsMatchRepo = result.sourceRepo === declaredRepo;
  }

  if (!result.digestBound) {
    result.error = 'digest_unbound';
  }

  return result;
}

export async function fetchProvenanceFromRegistry(pkgName, version) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}/${encodeURIComponent(version)}`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(ATTESTATION_FETCH_TIMEOUT_MS),
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * No-op by design. Structural provenance earns no confidence discount.
 *
 * Kept as the single seam where a discount would be applied once real
 * cryptographic verification exists; until then it must return findings
 * unchanged so that no attacker-authorable signal can suppress detections.
 */
export function applyProvenanceDiscount(findings, provenance) {
  if (!provenance?.verified) return findings;

  /* c8 ignore start -- unreachable until signature verification lands */
  const discountFactor = Math.min(0.3, provenance.slsaLevel * 0.1);
  return findings.map((f) => ({
    ...f,
    confidenceScore: f.confidenceScore
      ? Math.round(f.confidenceScore * (1 - discountFactor))
      : f.confidenceScore,
    context: { ...(f.context || {}), provenance_verified: true, slsa_level: provenance.slsaLevel },
    evidence: [...(f.evidence || []), `provenance: verified (SLSA ${provenance.slsaLevel})`],
  }));
  /* c8 ignore stop */
}

export function _clearBundleCache() {
  bundleCache.clear();
}
