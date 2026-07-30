import thresholds from './config/thresholds.js';
import { verifyProvenance, fetchProvenanceFromRegistry } from './lib/slsa-verifier.js';

const cfg = thresholds['TIER1-SLSA-ATTESTATION'];

export const name = 'tier1-slsa-attestation';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  const version = pkgJson?.version;
  if (!pkgName || !version) return [];

  const meta = registryMeta || (await fetchProvenanceFromRegistry(pkgName, version));
  if (!meta) return [];

  const provenance = await verifyProvenance(pkgName, version, meta);
  const findings = [];

  if (provenance.error === 'no_attestations') {
    findings.push({
      detector: 'tier1-slsa-attestation',
      id: 'TIER1-SLSA-ATTESTATION',
      severity: 'medium',
      confidence: 'MEDIUM',
      confidenceScore: 40,
      message: `Package ${pkgName}@${version} has no SLSA provenance attestation`,
      evidence: [
        'package lacks SLSA provenance attestation in registry metadata',
        'cannot verify build integrity or publisher identity',
      ],
      locations: [{ file: 'package.json', line: 1 }],
      recommendation: 'MONITOR - Package without build provenance; verify through other means',
    });
  } else if (provenance.verified) {
    findings.push({
      detector: 'tier1-slsa-attestation',
      id: 'TIER1-SLSA-ATTESTATION',
      severity: 'low',
      confidence: 'HIGH',
      confidenceScore: 20,
      message: `Package ${pkgName}@${version} has valid SLSA L${provenance.slsaLevel} provenance`,
      evidence: [
        `slsa_level: ${provenance.slsaLevel}`,
        `publisher: ${provenance.publisher || 'unknown'}`,
        `build_type: ${provenance.buildType || 'unknown'}`,
      ],
      locations: [{ file: 'package.json', line: 1 }],
      context: {
        provenance_verified: true,
        slsa_level: provenance.slsaLevel,
        publisher: provenance.publisher,
      },
      recommendation: 'PASS - Build provenance verified',
    });
  } else if (provenance.error) {
    findings.push({
      detector: 'tier1-slsa-attestation',
      id: 'TIER1-SLSA-ATTESTATION',
      severity: 'low',
      confidence: 'LOW',
      confidenceScore: 10,
      message: `SLSA provenance check unable to verify: ${provenance.error}`,
      evidence: [`error: ${provenance.error}`],
      locations: [{ file: 'package.json', line: 1 }],
    });
  }

  return findings;
}
