const siblingCache = new Map();

export function clearSiblingCache() {
  siblingCache.clear();
}

function checkBurstOnTimeMap(timeMap, windowMinutes, threshold) {
  const entries = Object.entries(timeMap)
    .filter(([v]) => v !== 'created' && v !== 'modified')
    .filter(([, t]) => t)
    .map(([v, t]) => [v, new Date(t).getTime()])
    .filter(([, ts]) => !Number.isNaN(ts))
    .sort((a, b) => a[1] - b[1]);

  if (entries.length === 0) return null;

  const windowMs = windowMinutes * 60 * 1000;

  for (let i = 0; i < entries.length; i++) {
    const wStart = entries[i][1];
    const wEnd = wStart + windowMs;
    const inWindow = [];

    for (let j = i; j < entries.length; j++) {
      if (entries[j][1] <= wEnd) {
        inWindow.push(entries[j][0]);
      } else {
        break;
      }
    }

    if (inWindow.length >= threshold) {
      return {
        windowStart: new Date(wStart).toISOString(),
        windowEnd: new Date(wEnd).toISOString(),
        versionCount: inWindow.length,
      };
    }
  }

  return null;
}

export async function checkSiblingCompromise(pkgJson, config = {}) {
  const windowMinutes = config.burstWindowMinutes ?? 30;
  const threshold = config.burstVersionThreshold ?? 3;

  const deps = {
    ...pkgJson.dependencies,
    ...pkgJson.devDependencies,
    ...pkgJson.peerDependencies,
  };

  const scopedDeps = {};
  for (const name of Object.keys(deps)) {
    if (name.startsWith('@')) {
      const scope = name.split('/')[0];
      if (!scopedDeps[scope]) scopedDeps[scope] = [];
      scopedDeps[scope].push(name);
    }
  }

  if (Object.keys(scopedDeps).length === 0) return { triggered: false };

  const results = [];

  for (const [scope, packages] of Object.entries(scopedDeps)) {
    if (packages.length < 2) continue;

    const burstSiblings = [];

    for (const pkg of packages) {
      let timeData = siblingCache.get(pkg);
      if (!timeData) {
        try {
          const url = `https://registry.npmjs.org/${encodeURIComponent(pkg)}`;
          const res = await fetch(url);
          if (!res.ok) continue;
          const data = await res.json();
          timeData = data.time || {};
          siblingCache.set(pkg, timeData);
        } catch {
          continue;
        }
      }

      const burstInfo = checkBurstOnTimeMap(timeData, windowMinutes, threshold);
      if (burstInfo) {
        burstSiblings.push({ name: pkg, ...burstInfo });
      }
    }

    if (burstSiblings.length >= 2) {
      const windows = burstSiblings.map(s => ({
        start: new Date(s.windowStart).getTime(),
        end: new Date(s.windowEnd).getTime(),
      }));

      const overlapStart = Math.max(...windows.map(w => w.start));
      const overlapEnd = Math.min(...windows.map(w => w.end));

      if (overlapStart < overlapEnd) {
        results.push({
          triggered: true,
          scope,
          siblingPackages: burstSiblings.map(s => s.name),
          windowStart: new Date(overlapStart).toISOString(),
          windowEnd: new Date(overlapEnd).toISOString(),
        });
      }
    }
  }

  if (results.length === 0) return { triggered: false };
  return { triggered: true, results };
}
