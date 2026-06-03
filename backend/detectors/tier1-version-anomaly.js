import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const SENTINEL_PATTERNS = new Set(['99.99.99', '11.11.11', '10.10.10']);

function parseVersion(v) {
  if (!v || typeof v !== 'string') return null;
  const parts = v.split('.');
  if (parts.length !== 3) return null;
  const [major, minor, patch] = parts.map(Number);
  if (isNaN(major) || isNaN(minor) || isNaN(patch)) return null;
  return { major, minor, patch, full: v };
}

function versionScore(v) {
  return v.major * 10000 + v.minor * 100 + v.patch;
}

function extractVersions(registryMeta) {
  if (Array.isArray(registryMeta)) {
    return registryMeta.map(v => parseVersion(v)).filter(Boolean);
  }
  if (registryMeta && typeof registryMeta === 'object') {
    const versions = registryMeta.versions || registryMeta.time;
    if (versions && typeof versions === 'object') {
      return Object.keys(versions).map(v => parseVersion(v)).filter(Boolean);
    }
  }
  return [];
}

function computeStats(scores) {
  if (scores.length < 2) return null;
  const mean = scores.reduce((s, v) => s + v, 0) / scores.length;
  const variance = scores.reduce((s, v) => s + (v - mean) ** 2, 0) / scores.length;
  const stddev = Math.sqrt(variance);
  return { mean, stddev, max: Math.max(...scores), min: Math.min(...scores) };
}

export function analyzeAnomaly(packageName, versionStr, versionHistory) {
  const current = parseVersion(versionStr);
  if (!current) return null;

  const historical = extractVersions(versionHistory);
  const currentScore = versionScore(current);
  const isSentinel = SENTINEL_PATTERNS.has(versionStr);

  if (!historical || historical.length < 2) {
    if (isSentinel) {
      return {
        flagged: true,
        confidenceScore: 60,
        confidence: 'MEDIUM',
        zScore: null,
        baselineMax: 'unknown',
        baselineMean: 'unknown',
        reason: `Version ${versionStr} matches known dependency confusion pattern (no registry data to confirm)`,
        attackPattern: 'SENTINEL_PATTERN_ONLY',
      };
    }
    return null;
  }

  const scores = historical.map(versionScore).sort((a, b) => a - b);
  const recentScores = scores.slice(-50);
  if (recentScores.length < 2) {
    if (isSentinel) {
      return {
        flagged: true,
        confidenceScore: 60,
        confidence: 'MEDIUM',
        zScore: null,
        baselineMax: 'unknown',
        baselineMean: 'unknown',
        reason: `Version ${versionStr} matches known dependency confusion pattern (insufficient history)`,
        attackPattern: 'SENTINEL_PATTERN_ONLY',
      };
    }
    return null;
  }

  const stats = computeStats(recentScores);
  if (!stats) return null;

  const zScore = stats.stddev > 0 ? (currentScore - stats.mean) / stats.stddev : 0;
  const baselineMaxVer = historical.find(v => versionScore(v) === stats.max)?.full || 'unknown';
  const baselineMeanVal = (stats.mean / 10000).toFixed(1);
  const prevMaxMajor = Math.floor(stats.max / 10000);
  const isNormalMajorBump = current.major === prevMaxMajor + 1 && current.minor === 0 && current.patch === 0;
  const isReasonableVersion = current.major <= prevMaxMajor + 2 && current.major >= Math.floor(stats.min / 10000);
  const ratio = stats.max > 0 ? currentScore / stats.max : 0;

  let flagged = false;
  let confidenceScore = 0;
  let attackPattern = '';
  let reason = '';

  if (isSentinel) {
    flagged = true;
    confidenceScore = 92;
    attackPattern = 'DEPENDENCY_CONFUSION_HIGH_VERSION';
    reason = `Version ${versionStr} matches known dependency confusion sentinel pattern; z-score ${zScore.toFixed(1)} vs baseline mean ${baselineMeanVal}`;
  } else if (zScore > 10 && !isNormalMajorBump) {
    flagged = true;
    confidenceScore = 90;
    attackPattern = 'Z_SCORE_EXTREME';
    reason = `Version ${versionStr} has z-score ${zScore.toFixed(1)} vs baseline mean ${baselineMeanVal} — extreme anomaly`;
  } else if (zScore > 5 && !isNormalMajorBump) {
    flagged = true;
    confidenceScore = 85;
    attackPattern = 'Z_SCORE_ANOMALY';
    reason = `Version ${versionStr} has z-score ${zScore.toFixed(1)} vs baseline mean ${baselineMeanVal} — strong anomaly`;
  } else if (zScore > 3 && !isNormalMajorBump) {
    flagged = true;
    confidenceScore = 72;
    attackPattern = 'Z_SCORE_ELEVATED';
    reason = `Version ${versionStr} has z-score ${zScore.toFixed(1)} vs baseline mean ${baselineMeanVal} — elevated anomaly`;
  } else if (ratio > 10 && !isNormalMajorBump) {
    flagged = true;
    confidenceScore = 75;
    attackPattern = 'MAJOR_VERSION_JUMP';
    reason = `Version ${versionStr} exceeds max historical version (${baselineMaxVer}) by factor of ${ratio.toFixed(1)}`;
  } else if (zScore > 2 && !isReasonableVersion) {
    flagged = true;
    confidenceScore = 55;
    attackPattern = 'SUSPICIOUS_VERSION';
    reason = `Version ${versionStr} has z-score ${zScore.toFixed(1)} and is outside expected version range`;
  }

  if (!flagged) return null;

  return {
    flagged,
    confidenceScore: Math.min(100, confidenceScore),
    confidence: confidenceScore >= 80 ? 'HIGH' : confidenceScore >= 60 ? 'MEDIUM' : 'LOW',
    zScore: Math.round(zScore * 10) / 10,
    baselineMax: baselineMaxVer,
    baselineMean: baselineMeanVal,
    reason,
    attackPattern,
  };
}

function severityLabel(sc) {
  if (sc >= 90) return 'critical';
  if (sc >= 70) return 'high';
  if (sc >= 50) return 'medium';
  return 'low';
}

function confidenceLabel(sc) {
  if (sc >= 80) return 'HIGH';
  if (sc >= 60) return 'MEDIUM';
  return 'LOW';
}

export const name = 'tier1-version-anomaly';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  const version = pkgJson?.version;

  if (!pkgName || !version) return [];
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const result = analyzeAnomaly(pkgName, version, registryMeta);
  if (!result) return [];

  return [{
    detector: 'tier1-version-anomaly',
    id: 'TIER1-VERSION-ANOMALY',
    severity: severityLabel(result.confidenceScore),
    confidence: confidenceLabel(result.confidenceScore),
    confidenceScore: result.confidenceScore,
    subtype: result.attackPattern.toLowerCase(),
    message: `Version anomaly detected in "${pkgName}": ${result.reason}`,
    evidence: [
      `version: ${version}`,
      `baseline_max: ${result.baselineMax}`,
      `baseline_mean: ${result.baselineMean}`,
      `z_score: ${result.zScore ?? 'N/A'}`,
      `attack_pattern: ${result.attackPattern}`,
    ],
    crossFiles: [],
    locations: [{ file: 'package.json', line: 3, column: 10 }],
    reference: '176-package dependency confusion campaign',
  }];
}
