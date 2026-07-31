export async function verifyProvenance(pkgName, version, registryMeta) {
  if (!registryMeta || !pkgName || !version) {
    return { verified: false, publisher: null, slsaLevel: 0, buildType: null };
  }

  const result = {
    verified: false,
    publisher: null,
    slsaLevel: 0,
    buildType: null,
    error: null,
  };

  const dist = registryMeta.dist || {};
  const attestations = dist.attestations || registryMeta.attestations || [];

  if (!attestations.length) {
    result.error = 'no_attestations';
    return result;
  }

  for (const att of attestations) {
    if (att.predicateType && att.predicateType.includes('slsa')) {
      result.slsaLevel = extractSlsaLevel(att);
    }

    if (att.predicate?.buildType) {
      result.buildType = att.predicate.buildType;
    }

    if (att.subject && Array.isArray(att.subject)) {
      for (const sub of att.subject) {
        if (sub.name === pkgName || sub.name === `${pkgName}@${version}`) {
          result.verified = true;
        }
      }
    }

    if (att.predicate?.runDetails?.builder?.id) {
      result.publisher = att.predicate.runDetails.builder.id;
    }
  }

  return result;
}

function extractSlsaLevel(attestation) {
  const slsaMap = {
    'https://slsa.dev/provenance/v0.2': 2,
    'https://slsa.dev/provenance/v1': 3,
  };
  return slsaMap[attestation.predicateType] || 0;
}

export async function fetchProvenanceFromRegistry(pkgName, version) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}/${encodeURIComponent(version)}`;
    const response = await fetch(url);
    if (!response.ok) return null;
    const data = await response.json();
    return data;
  } catch {
    return null;
  }
}

export function applyProvenanceDiscount(findings, provenance) {
  if (!provenance || !provenance.verified || findings.length === 0) return findings;

  const discountFactor = Math.min(0.3, provenance.slsaLevel * 0.1);
  const discounted = [];

  for (const f of findings) {
    const fCopy = { ...f };
    if (fCopy.confidenceScore) {
      fCopy.confidenceScore = Math.round(fCopy.confidenceScore * (1 - discountFactor));
    }
    if (fCopy.context) {
      fCopy.context = {
        ...fCopy.context,
        provenance_verified: true,
        slsa_level: provenance.slsaLevel,
      };
    } else {
      fCopy.context = { provenance_verified: true, slsa_level: provenance.slsaLevel };
    }
    fCopy.evidence = [
      ...(fCopy.evidence || []),
      `provenance: verified (SLSA ${provenance.slsaLevel})`,
    ];
    discounted.push(fCopy);
  }

  return discounted;
}
