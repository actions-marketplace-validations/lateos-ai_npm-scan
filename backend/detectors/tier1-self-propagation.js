import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const THRESHOLDS = {
  flag_threshold: 75,
  warn_threshold: 60,
  burst_window_minutes: 60,
  min_packages_burst: 3,
  identical_payload_weight: 40,
};

function parseTimeStamps(registryMeta) {
  const timeData = registryMeta?.time;
  if (!timeData || typeof timeData !== 'object') return [];
  return Object.entries(timeData)
    .map(([ver, ts]) => ({
      version: ver,
      time: new Date(ts).getTime(),
    }))
    .filter((e) => !isNaN(e.time))
    .sort((a, b) => a.time - b.time);
}

function findBursts(entries, windowMs) {
  const bursts = [];
  for (let i = 0; i < entries.length; i++) {
    const windowEnd = entries[i].time + windowMs;
    const group = [];
    for (let j = i; j < entries.length && entries[j].time <= windowEnd; j++) {
      group.push(entries[j]);
    }
    if (group.length >= 3) {
      bursts.push({
        startVersion: group[0].version,
        endVersion: group[group.length - 1].version,
        count: group.length,
        windowMinutes: windowMs / 60000,
        versions: group.map((e) => e.version),
      });
    }
  }
  return bursts;
}

function computeConfidence(bursts, findings) {
  let base = 40;
  if (bursts.length > 0) {
    base += 20 + Math.min(bursts[0].count * 5, 25);
  }
  if (findings.length > 0) {
    base += THRESHOLDS.identical_payload_weight;
  }
  return Math.min(100, Math.max(0, base));
}

function severityLabel(score) {
  if (score >= 80) return 'high';
  if (score >= 60) return 'medium';
  return 'low';
}

function confidenceLabel(score) {
  if (score >= 80) return 'HIGH';
  if (score >= 60) return 'MEDIUM';
  return 'LOW';
}

export const name = 'tier1-self-propagation';

export async function scan(pkgJson, _jsFiles, registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  if (!pkgName) return [];
  if (KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const entries = parseTimeStamps(registryMeta);
  if (entries.length < 3) return [];

  const windowMs = (THRESHOLDS.burst_window_minutes || 60) * 60 * 1000;
  const bursts = findBursts(entries, windowMs);
  if (bursts.length === 0) return [];

  const burst = bursts[0];
  const confidenceScore = computeConfidence(bursts, []);
  if (confidenceScore < THRESHOLDS.warn_threshold) return [];

  const relatedPackages = [];
  const maintainer =
    registryMeta?.maintainer || registryMeta?.versions?.[pkgJson.version]?._npmUser?.name;
  const namespaces = registryMeta?.namespacePackages || [];
  if (namespaces.length > 0) {
    for (const np of namespaces) {
      if (np !== pkgName) relatedPackages.push(np);
    }
  }

  return [
    {
      detector: 'tier1-self-propagation',
      id: 'TIER1-SELF-PROPAGATION',
      severity: severityLabel(confidenceScore),
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype: 'self_propagation_burst',
      message: `Self-propagation burst detected: ${burst.count} versions in ${burst.windowMinutes} minutes`,
      evidence: [
        `burst: ${burst.count} versions in ${burst.windowMinutes}min`,
        `window: ${burst.startVersion} -> ${burst.endVersion}`,
        `related_packages: ${relatedPackages.length}`,
        `maintainer: ${maintainer || 'unknown'}`,
      ],
      locations: [{ file: 'package.json', line: 1, column: 1 }],
      crossFiles: relatedPackages.slice(0, 10),
      reference: 'D10: @redhat-cloud-services Miasma self-propagation',
    },
  ];
}
