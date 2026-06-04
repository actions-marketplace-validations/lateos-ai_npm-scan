export async function checkBurstPublish(registryMeta, config = {}) {
  const windowMinutes = config.burstWindowMinutes ?? 30;
  const threshold = config.burstVersionThreshold ?? 3;

  const times = registryMeta?.time || {};
  const entries = Object.entries(times)
    .filter(([v]) => v !== 'created' && v !== 'modified')
    .filter(([, t]) => t)
    .map(([v, t]) => [v, new Date(t).getTime()])
    .filter(([, ts]) => !Number.isNaN(ts))
    .sort((a, b) => a[1] - b[1]);

  if (entries.length === 0) {
    return { triggered: false };
  }

  const windowMs = windowMinutes * 60 * 1000;

  for (let i = 0; i < entries.length; i++) {
    const windowStart = entries[i][1];
    const windowEnd = windowStart + windowMs;
    const inWindow = [];

    for (let j = i; j < entries.length; j++) {
      if (entries[j][1] <= windowEnd) {
        inWindow.push(entries[j][0]);
      } else {
        break;
      }
    }

    if (inWindow.length >= threshold) {
      return {
        triggered: true,
        windowStart: new Date(windowStart).toISOString(),
        windowEnd: new Date(windowEnd).toISOString(),
        versionCount: inWindow.length,
        versions: inWindow,
      };
    }
  }

  return { triggered: false };
}
