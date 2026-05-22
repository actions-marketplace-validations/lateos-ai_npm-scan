import { MegalodonSignal } from './types.js';

export function detectVelocitySpike(times, windowHours = 6, threshold = 3) {
  const filtered = {};
  for (const [v, t] of Object.entries(times)) {
    if (v === 'created' || v === 'modified') continue;
    filtered[v] = t;
  }

  const entries = Object.entries(filtered)
    .filter(([, t]) => t)
    .map(([v, t]) => [v, new Date(t).getTime()])
    .filter(([, ts]) => !Number.isNaN(ts))
    .sort((a, b) => a[1] - b[1]);

  if (entries.length === 0) {
    return { triggered: false, versionsInWindow: [], windowStartISO: null };
  }

  const windowMs = windowHours * 3_600_000;

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
      let display = inWindow.slice(0, 10);
      let suffix = '';
      if (inWindow.length > 10) {
        suffix = ` +${inWindow.length - 10} more`;
      }
      return {
        triggered: true,
        versionsInWindow: display.join(', ') + suffix,
        windowStartISO: new Date(windowStart).toISOString(),
        _allVersions: inWindow,
      };
    }
  }

  return { triggered: false, versionsInWindow: [], windowStartISO: null };
}

export async function scan(registryMeta) {
  const times = registryMeta?.time || {};
  const result = detectVelocitySpike(times);

  if (!result.triggered) return [];

  return [{
    signal: MegalodonSignal.PUBLISH_VELOCITY,
    file: 'registry.npmjs.org',
    excerpt: result.versionsInWindow,
    detail: `Version publish velocity spike: ${result.versionsInWindow} versions in window starting ${result.windowStartISO}`,
    _windowStartISO: result.windowStartISO,
    _allVersions: result._allVersions,
  }];
}
