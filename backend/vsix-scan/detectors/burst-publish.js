export async function checkBurstPublish(versionHistory, config = {}) {
  const windowMinutes = config.burstWindowMinutes ?? 30;
  const threshold = config.burstVersionThreshold ?? 2;
  const hotPullMinutes = config.hotPullMinutes ?? 20;

  const entries = versionHistory
    .filter(v => v.publishedAt)
    .map(v => ({ version: v.version, time: new Date(v.publishedAt).getTime() }))
    .filter(e => !Number.isNaN(e.time))
    .sort((a, b) => a.time - b.time);

  if (entries.length < threshold) return { triggered: false };

  const windowMs = windowMinutes * 60 * 1000;
  let burstFound = false;
  let burstWindowStart = null;
  let burstWindowEnd = null;
  let burstVersionCount = 0;
  let burstVersions = [];

  for (let i = 0; i < entries.length; i++) {
    const start = entries[i].time;
    const end = start + windowMs;
    const inWindow = entries.filter(e => e.time >= start && e.time <= end);

    if (inWindow.length >= threshold) {
      burstFound = true;
      burstWindowStart = new Date(start).toISOString();
      burstWindowEnd = new Date(end).toISOString();
      burstVersionCount = inWindow.length;
      burstVersions = inWindow.map(e => e.version);
      break;
    }
  }

  let hotPullDetected = false;
  for (let i = 1; i < entries.length; i++) {
    const gapMinutes = (entries[i].time - entries[i - 1].time) / (1000 * 60);
    if (gapMinutes > 0 && gapMinutes < hotPullMinutes) {
      hotPullDetected = true;
      break;
    }
  }

  return {
    triggered: burstFound || hotPullDetected,
    burstWindow: burstFound
      ? { start: burstWindowStart, end: burstWindowEnd, versionCount: burstVersionCount, versions: burstVersions }
      : null,
    hotPullDetected,
  };
}
