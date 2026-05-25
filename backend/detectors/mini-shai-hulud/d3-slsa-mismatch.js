export async function checkSlsaMismatch(packageName, version, burstWindow, timeMap = {}, config = {}) {
  if (!burstWindow?.triggered) return { triggered: false };

  const anomalies = [];
  const publishTime = timeMap?.[version];
  if (!publishTime) return { triggered: false };

  try {
    const url = `https://registry.npmjs.org/-/npm/v1/attestations/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}`;
    const res = await fetch(url);
    if (!res.ok) return { triggered: false };

    const data = await res.json();
    const attestations = data?.attestations || [];
    if (attestations.length === 0) return { triggered: false };

    const publishMs = new Date(publishTime).getTime();
    if (Number.isNaN(publishMs)) return { triggered: false };

    // Check if this is the first-ever attested version for this package
    const allVersions = Object.keys(timeMap).filter(v => v !== 'created' && v !== 'modified');
    const currentIdx = allVersions.indexOf(version);
    let prevHadAttestation = false;

    if (currentIdx > 0) {
      const priorVersions = allVersions.slice(0, currentIdx).slice(-2);
      for (const pv of priorVersions) {
        try {
          const purl = `https://registry.npmjs.org/-/npm/v1/attestations/${encodeURIComponent(packageName)}/${encodeURIComponent(pv)}`;
          const pres = await fetch(purl);
          if (pres.ok) {
            const pdata = await pres.json();
            if (pdata?.attestations?.length > 0) {
              prevHadAttestation = true;
              break;
            }
          }
        } catch {
          // skip prior version check
        }
      }

      if (!prevHadAttestation && priorVersions.length > 0) {
        anomalies.push(`First-ever SLSA attestation for ${packageName}, published in burst window`);
      }
    }

    for (const att of attestations) {
      const ts = att?.timestamp;
      if (ts) {
        const attMs = new Date(ts).getTime();
        if (!Number.isNaN(attMs) && attMs >= publishMs && (attMs - publishMs) < 60000) {
          const gapMs = attMs - publishMs;
          anomalies.push(`Sub-60s attestation gap for ${version}: ${gapMs}ms`);
        }
      }

      const builderId = att?.predicate?.runDetails?.builder?.id;
      if (builderId) {
        const knownPrefixes = ['https://github.com/', 'https://gitlab.com/', 'https://circleci.com/'];
        const isKnown = knownPrefixes.some(p => builderId.startsWith(p));
        if (!isKnown) {
          anomalies.push(`Unrecognized builder ID for ${version}: ${builderId}`);
        }
      }
    }
  } catch {
    return { triggered: false };
  }

  return { triggered: anomalies.length > 0, anomalies };
}
