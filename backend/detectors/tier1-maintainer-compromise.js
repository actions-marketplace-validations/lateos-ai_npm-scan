import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const THRESHOLDS = {
  flag_threshold: 75,
  warn_threshold: 60,
  velocity_burst_multiplier: 5,
  burst_window_hours: 24,
  min_velocity_baseline: 0.5,
  duplicate_version_weight: 40,
  unusual_timing_weight: 25,
  cross_package_burst_weight: 50,
};

function parseVersionHistory(registryMeta) {
  const timeData = registryMeta?.time;
  if (!timeData || typeof timeData !== 'object') return [];

  return Object.entries(timeData)
    .map(([ver, ts]) => ({
      version: ver,
      time: new Date(ts).getTime(),
      date: new Date(ts),
    }))
    .filter((e) => !isNaN(e.time))
    .sort((a, b) => a.time - b.time);
}

function getHour(date) {
  return date.getUTCHours();
}

function calculateVelocity(history) {
  if (history.length < 2) return { perWeek: 0, perDay: 0 };
  const firstTime = history[0].time;
  const lastTime = history[history.length - 1].time;
  const spanMs = lastTime - firstTime;
  const spanDays = spanMs / (1000 * 60 * 60 * 24);
  if (spanDays < 1) return { perWeek: history.length, perDay: history.length };
  const perDay = history.length / Math.max(spanDays, 1);
  const perWeek = perDay * 7;
  return { perWeek, perDay };
}

function detectBursts(history) {
  const bursts = [];
  const windowMs = (THRESHOLDS.burst_window_hours || 24) * 60 * 60 * 1000;

  for (let i = 0; i < history.length; i++) {
    const windowEnd = history[i].time + windowMs;
    const group = [];
    for (let j = i; j < history.length && history[j].time <= windowEnd; j++) {
      group.push(history[j]);
    }
    if (group.length >= 3) {
      const groupHour = group.map((e) => getHour(e.date));
      const timings = groupHour.filter((h) => h >= 0 && h <= 5);
      bursts.push({
        count: group.length,
        windowHours: windowMs / (1000 * 60 * 60),
        versions: group.map((e) => e.version),
        unusualTimings: [...new Set(timings)]
          .sort()
          .map((h) => `${String(h).padStart(2, '0')}:00 UTC`),
        startTime: group[0].date.toISOString(),
        endTime: group[group.length - 1].date.toISOString(),
      });
    }
  }
  return bursts;
}

function computeConfidence(bursts, velocity, unusualTimingsCount) {
  if (bursts.length === 0) return 0;
  let base = 40;

  const burst = bursts[0];
  const burstMultiplier =
    velocity.perWeek > 0
      ? burst.count / Math.max(velocity.perWeek, THRESHOLDS.min_velocity_baseline)
      : burst.count;

  if (burstMultiplier >= THRESHOLDS.velocity_burst_multiplier) {
    base += Math.min(burstMultiplier * 3, 30);
  }

  if (unusualTimingsCount > 0) {
    base += Math.min(unusualTimingsCount * THRESHOLDS.unusual_timing_weight, 20);
  }

  if (burst.count >= 10) {
    base += 15;
  }

  return Math.min(100, Math.max(0, base));
}

function severityLabel(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  return 'medium';
}

function confidenceLabel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  return 'MEDIUM';
}

export const name = 'tier1-maintainer-compromise';

export async function scan(pkgJson, _jsFiles, registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  if (!pkgName) return [];
  if (KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const history = parseVersionHistory(registryMeta);
  if (history.length < 3) return [];

  const velocity = calculateVelocity(history);
  const bursts = detectBursts(history);
  if (bursts.length === 0) return [];

  const burst = bursts[0];
  const unusualTimings = burst.unusualTimings;
  const burstMultiplier =
    velocity.perWeek > 0
      ? burst.count / Math.max(velocity.perWeek, THRESHOLDS.min_velocity_baseline)
      : burst.count;

  const crossPackageBurst = registryMeta?.crossPackageBurst || false;

  const confidenceScore = computeConfidence(bursts, velocity, unusualTimings.length);
  if (confidenceScore < THRESHOLDS.warn_threshold) return [];

  return [
    {
      detector: 'tier1-maintainer-compromise',
      id: 'TIER1-MAINTAINER-COMPROMISE',
      severity: severityLabel(confidenceScore),
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype: 'maintainer_compromise_burst',
      message: `Maintainer compromise detected: ${burst.count} versions in ${burst.windowHours}h window (${burstMultiplier.toFixed(1)}x normal velocity)`,
      evidence: [
        `normal_velocity: ${velocity.perWeek.toFixed(1)}/week (${velocity.perDay.toFixed(1)}/day)`,
        `burst_count: ${burst.count} in ${burst.windowHours}h`,
        `burst_multiplier: ${burstMultiplier.toFixed(1)}x`,
        `unusual_timings: ${unusualTimings.length > 0 ? unusualTimings.join(', ') : 'none'}`,
        `cross_package: ${crossPackageBurst}`,
        `versions: ${burst.versions.slice(0, 5).join(', ')}${burst.versions.length > 5 ? `... (+${burst.versions.length - 5} more)` : ''}`,
      ],
      locations: [{ file: 'package.json', line: 1, column: 1 }],
      crossFiles: [],
      reference: 'D13: @redhat-cloud-services maintainer compromise',
    },
  ];
}
