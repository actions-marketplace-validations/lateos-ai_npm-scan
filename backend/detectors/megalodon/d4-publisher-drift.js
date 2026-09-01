import { MegalodonSignal } from './types.js';

export async function scan(registryMeta, velocityResult) {
  const evidence = [];
  const versions = registryMeta?.versions || {};
  const timeMap = registryMeta?.time || {};

  const filteredTimes = {};
  for (const [v, t] of Object.entries(timeMap)) {
    if (v === 'created' || v === 'modified') {
      continue;
    }
    if (t) {
      filteredTimes[v] = t;
    }
  }

  const sortedVersions = Object.entries(filteredTimes)
    .filter(([, t]) => t && !Number.isNaN(new Date(t).getTime()))
    .sort((a, b) => new Date(a[1]).getTime() - new Date(b[1]).getTime())
    .map(([v]) => v);

  if (sortedVersions.length === 0) {
    return [];
  }

  if (velocityResult?.triggered) {
    const windowStartISO = velocityResult.windowStartISO;
    const allInWindow = velocityResult._allVersions || [];

    const priorPublishers = new Set();
    for (const v of sortedVersions) {
      if (new Date(filteredTimes[v]).getTime() >= new Date(windowStartISO).getTime()) {
        break;
      }
      const user = versions[v]?._npmUser?.name;
      if (user) {
        priorPublishers.add(user);
      }
    }

    if (priorPublishers.size === 0 && allInWindow.length > 0) {
      const firstUser = versions[allInWindow[0]]?._npmUser?.name;
      if (firstUser) {
        priorPublishers.add(firstUser);
      }
    }

    const suspiciousPublishers = [];
    const affectedVersions = [];
    for (const v of allInWindow) {
      const user = versions[v]?._npmUser?.name;
      if (user && !priorPublishers.has(user)) {
        if (!suspiciousPublishers.includes(user)) {
          suspiciousPublishers.push(user);
        }
        if (!affectedVersions.includes(v)) {
          affectedVersions.push(v);
        }
      }
    }

    if (suspiciousPublishers.length > 0) {
      const detail = `Drift detected: known publishers [${[...priorPublishers].join(', ')}], new publisher(s) [${suspiciousPublishers.join(', ')}] in versions [${affectedVersions.join(', ')}]`;

      const firstSuspiciousVer = allInWindow.find((v) => affectedVersions.includes(v));
      let ageNote = '';
      if (firstSuspiciousVer && suspiciousPublishers[0]) {
        ageNote = await checkAccountAge(suspiciousPublishers[0], filteredTimes[firstSuspiciousVer]);
      }

      evidence.push({
        signal: MegalodonSignal.PUBLISHER_DRIFT,
        file: 'registry.npmjs.org',
        excerpt: `publisher drift: ${suspiciousPublishers.join(', ')}`,
        detail: detail + (ageNote ? ' | ' + ageNote : ''),
        _severityHint: 'HIGH',
      });
    }
  } else {
    if (sortedVersions.length < 4) {
      return [];
    }

    const last3 = sortedVersions.slice(-3);
    const prior = sortedVersions.slice(0, -3);

    const priorPublishers = new Set();
    for (const v of prior) {
      const user = versions[v]?._npmUser?.name;
      if (user) {
        priorPublishers.add(user);
      }
    }

    const suspiciousPublishers = [];
    const affectedVersions = [];
    for (const v of last3) {
      const user = versions[v]?._npmUser?.name;
      if (user && !priorPublishers.has(user)) {
        if (!suspiciousPublishers.includes(user)) {
          suspiciousPublishers.push(user);
        }
        if (!affectedVersions.includes(v)) {
          affectedVersions.push(v);
        }
      }
    }

    if (suspiciousPublishers.length > 0) {
      const detail = `Drift (fallback): known publishers [${[...priorPublishers].join(', ')}], new publisher(s) [${suspiciousPublishers.join(', ')}] in last 3 versions [${affectedVersions.join(', ')}]`;

      let ageNote = '';
      if (suspiciousPublishers[0] && affectedVersions[0]) {
        ageNote = await checkAccountAge(
          suspiciousPublishers[0],
          filteredTimes[affectedVersions[0]]
        );
      }

      evidence.push({
        signal: MegalodonSignal.PUBLISHER_DRIFT,
        file: 'registry.npmjs.org',
        excerpt: `publisher drift: ${suspiciousPublishers.join(', ')}`,
        detail: detail + (ageNote ? ' | ' + ageNote : ''),
        _severityHint: 'MEDIUM',
      });
    }
  }

  return evidence;
}

async function checkAccountAge(npmUser, firstSuspiciousTime) {
  try {
    const url = `https://registry.npmjs.org/-/user/org.couchdb.user/${encodeURIComponent(npmUser)}`;
    const res = await fetch(url);
    if (!res.ok) {
      return '';
    }
    const data = await res.json();
    const created = data?.date;
    if (!created) {
      return '';
    }
    const createdDate = new Date(created).getTime();
    const firstPub = new Date(firstSuspiciousTime).getTime();
    const daysDiff = (firstPub - createdDate) / (1000 * 60 * 60 * 24);
    if (!Number.isNaN(daysDiff) && daysDiff >= 0 && daysDiff <= 30) {
      return `Publisher account created ${Math.round(daysDiff)} days before first suspicious publish`;
    }
  } catch {
    /* ignore fetch errors */
  }
  return '';
}
