import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

function parseVersion(v) {
  if (!v || typeof v !== 'string') {
    return null;
  }
  const parts = v.split('.');
  if (parts.length !== 3) {
    return null;
  }
  const [major, minor, patch] = parts.map(Number);
  if (isNaN(major) || isNaN(minor) || isNaN(patch)) {
    return null;
  }
  return { major, minor, patch, full: v };
}

function extractTimeMap(registryMeta) {
  if (!registryMeta || typeof registryMeta !== 'object') {
    return null;
  }
  const time = registryMeta.time;
  if (!time || typeof time !== 'object') {
    return null;
  }
  return time;
}

export const name = 'tier1-version-backfill';

export async function scan(pkgJson, _jsFiles, registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const timeMap = extractTimeMap(registryMeta);
  if (!timeMap) {
    return [];
  }

  const versionTimestamps = [];
  for (const [ver, timestamp] of Object.entries(timeMap)) {
    if (ver === 'created' || ver === 'modified') {
      continue;
    }
    const parsed = parseVersion(ver);
    if (!parsed) {
      continue;
    }
    const ts = new Date(timestamp).getTime();
    if (isNaN(ts)) {
      continue;
    }
    versionTimestamps.push({ ...parsed, ts });
  }

  if (versionTimestamps.length < 8) {
    return [];
  }

  versionTimestamps.sort((a, b) => a.ts - b.ts);

  const earliest = versionTimestamps[0].ts;
  const latest = versionTimestamps[versionTimestamps.length - 1].ts;
  const spreadMs = latest - earliest;

  if (spreadMs >= TWENTY_FOUR_HOURS_MS) {
    return [];
  }

  const _majors = new Set(versionTimestamps.map((v) => v.major));
  const minors = new Set(versionTimestamps.map((v) => v.minor));
  const maxMajor = Math.max(...versionTimestamps.map((v) => v.major));
  const minMajor = Math.min(...versionTimestamps.map((v) => v.major));
  const majorSpan = maxMajor - minMajor;

  const wideRange = majorSpan >= 1 || minors.size >= 4;
  if (!wideRange) {
    return [];
  }

  const confidenceScore = 80;
  const severity = 'high';

  const evidence = [
    `versions_count: ${versionTimestamps.length}`,
    `time_spread_ms: ${spreadMs}`,
    `time_spread_hours: ${(spreadMs / (60 * 60 * 1000)).toFixed(1)}`,
    `major_range: ${minMajor}–${maxMajor}`,
    `unique_minors: ${minors.size}`,
    `earliest: ${versionTimestamps[0].full} (${new Date(earliest).toISOString()})`,
    `latest: ${versionTimestamps[versionTimestamps.length - 1].full} (${new Date(latest).toISOString()})`,
  ];

  return [
    {
      detector: 'tier1-version-backfill',
      id: 'TIER1-VERSION-BACKFILL',
      severity,
      confidence: 'HIGH',
      confidenceScore,
      subtype: 'version_history_backfill',
      message: `Version history was backfilled in a single publish burst — package age signals should not be trusted`,
      evidence,
      locations: [{ file: 'package.json', line: 3, column: 10 }],
      crossFiles: [],
      reference: 'OpenSourceMalware 2026-07-09 campaign',
    },
  ];
}
