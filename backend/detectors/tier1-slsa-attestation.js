// D8: SLSA Attestation Mismatch Detector
// TODO: Implement after npm SLSA attestation API stabilizes
// Blockers:
//   - npm registry SLSA attestation API not yet widely adopted (as of June 2026)
//   - Requires npm auth token to fetch provenance
//   - May have rate limits

export const name = 'tier1-slsa-attestation';

export async function scan(_pkgJson, _jsFiles, _registryMeta, _allFiles) {
  return [];
}
