export async function checkMaintainerAnomaly(registryMeta, config = {}) {
  const versions = registryMeta?.versions || {};
  const timeMap = registryMeta?.time || {};

  const sorted = Object.entries(timeMap)
    .filter(([v]) => v !== 'created' && v !== 'modified')
    .filter(([, t]) => t)
    .map(([v, t]) => ({
      version: v,
      time: new Date(t).getTime(),
      user: versions[v]?._npmUser?.name,
    }))
    .filter(e => !Number.isNaN(e.time) && e.user)
    .sort((a, b) => a.time - b.time);

  if (sorted.length < 2) return { triggered: false };

  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const curr = sorted[i];

    if (curr.user !== prev.user) {
      const gapMinutes = (curr.time - prev.time) / (1000 * 60);
      if (gapMinutes <= 10) {
        const newUserVersions = sorted.filter(e => e.user === curr.user);
        if (newUserVersions.length >= 2) {
          return {
            triggered: true,
            signals: [{
              type: 'PUBLISHER_DRIFT_RAPID',
              previousPublisher: prev.user,
              newPublisher: curr.user,
              gapMinutes,
              newUserVersionCount: newUserVersions.length,
              driftVersion: curr.version,
              driftWindowStart: new Date(curr.time).toISOString(),
            }],
          };
        }
      }
    }
  }

  return { triggered: false };
}
