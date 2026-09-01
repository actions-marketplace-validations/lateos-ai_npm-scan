import { verifyProvenance, fetchProvenanceFromRegistry } from './lib/slsa-verifier.js';

export const name = 'tier1-slsa-attestation';

const DETECTOR = 'tier1-slsa-attestation';
const ID = 'TIER1-SLSA-ATTESTATION';

function finding(
  severity,
  confidence,
  confidenceScore,
  message,
  evidence,
  recommendation,
  context
) {
  return {
    detector: DETECTOR,
    id: ID,
    severity,
    confidence,
    confidenceScore,
    message,
    evidence,
    locations: [{ file: 'package.json', line: 1 }],
    ...(context ? { context } : {}),
    recommendation,
  };
}

export async function scan(pkgJson, _jsFiles, registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  const version = pkgJson?.version;
  if (!pkgName || !version) return [];

  const meta = registryMeta || (await fetchProvenanceFromRegistry(pkgName, version));
  if (!meta) return [];

  const prov = await verifyProvenance(pkgName, version, meta);

  // Attestation exists but its subject does not name this package: the
  // attestation was minted for something else and is being presented for this
  // tarball. Treat as tampering, not as missing provenance.
  if (prov.error === 'subject_mismatch') {
    return [
      finding(
        'high',
        'HIGH',
        85,
        `Package ${pkgName}@${version} carries a provenance attestation for a different subject`,
        [
          'attestation subject does not reference this package@version',
          'attestation may have been copied from an unrelated package',
        ],
        'INVESTIGATE - Provenance does not correspond to this package'
      ),
    ];
  }

  // Attestation names this package but does not bind to the tarball the
  // registry is serving. This is the signal that the published artifact was
  // swapped after the attestation was minted.
  if (prov.error === 'digest_unbound') {
    return [
      finding(
        'high',
        'HIGH',
        80,
        `Package ${pkgName}@${version} provenance does not match the published tarball digest`,
        [
          'attestation subject digest != dist.integrity',
          'published artifact differs from the attested build output',
        ],
        'INVESTIGATE - Attested build output does not match the tarball being served'
      ),
    ];
  }

  if (prov.error === 'malformed_statement' || prov.error === 'no_slsa_predicate') {
    return [
      finding(
        'low',
        'LOW',
        25,
        `Package ${pkgName}@${version} has an attestation that could not be parsed (${prov.error})`,
        [`error: ${prov.error}`],
        'MONITOR - Attestation present but unreadable'
      ),
    ];
  }

  if (prov.error === 'attestation_fetch_failed') {
    return [
      finding(
        'low',
        'LOW',
        10,
        `Could not retrieve provenance attestation for ${pkgName}@${version}`,
        ['registry advertised an attestation but the document could not be fetched'],
        'MONITOR - Attestation retrieval failed; re-scan when the registry is reachable'
      ),
    ];
  }

  if (prov.error === 'no_attestations') {
    // The common case for most of npm. Informational only: absence of
    // provenance is not evidence of compromise, and weighting it higher puts a
    // permanent risk floor under every scan.
    return [
      finding(
        'low',
        'LOW',
        15,
        `Package ${pkgName}@${version} has no SLSA provenance attestation`,
        ['no build provenance published for this version'],
        'MONITOR - No build provenance available; verify through other means'
      ),
    ];
  }

  const findings = [];

  // Provenance is present and binds to the tarball, but is NOT cryptographically
  // verified — no signature, cert chain, or transparency-log check. Reported as
  // informational and deliberately does NOT set provenance_verified, so no
  // confidence discount is granted anywhere downstream.
  findings.push(
    finding(
      'low',
      'LOW',
      10,
      `Package ${pkgName}@${version} has SLSA L${prov.slsaLevel} provenance (structurally checked, signature NOT verified)`,
      [
        `slsa_level: ${prov.slsaLevel}`,
        `build_type: ${prov.buildType || 'unknown'}`,
        `builder: ${prov.builderId || 'unknown'}`,
        `source_repo: ${prov.sourceRepo || 'unknown'}`,
        'tarball digest binding: OK',
        'signature verification: NOT PERFORMED',
      ],
      'INFO - Provenance present and bound to tarball; signature not verified',
      {
        provenance_present: true,
        digest_bound: true,
        slsa_level: prov.slsaLevel,
        signature_verified: false,
      }
    )
  );

  // Build claims name a repository other than the one the package declares.
  if (prov.claimsMatchRepo === false) {
    findings.push(
      finding(
        'medium',
        'MEDIUM',
        60,
        `Package ${pkgName}@${version} was built from a different repository than it declares`,
        [
          `provenance source repo: ${prov.sourceRepo}`,
          `declared repository: ${meta.repository?.url || meta.repository || 'unset'}`,
        ],
        'INVESTIGATE - Build source does not match declared repository'
      )
    );
  }

  return findings;
}
