import { createRequire } from 'module';
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const require = createRequire(import.meta.url);
const TOP_PACKAGES = require('../../src/config/top-5000.json');
const TOP_SET = new Set(TOP_PACKAGES);

function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Int32Array(n + 1);
  let curr = new Int32Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + cost
      );
      if (curr[j] < rowMin) rowMin = curr[j];
    }
    if (rowMin > 2) return 3;
    const tmp = prev; prev = curr; curr = tmp;
  }
  return prev[n];
}

function jaroWinkler(a, b) {
  if (a === b) return 1;
  const m = a.length, n = b.length;
  if (m === 0 || n === 0) return 0;
  const matchDist = Math.floor(Math.max(m, n) / 2) - 1;
  const aMatch = new Array(m).fill(false);
  const bMatch = new Array(n).fill(false);
  let matches = 0;
  for (let i = 0; i < m; i++) {
    const start = Math.max(0, i - matchDist);
    const end = Math.min(n, i + matchDist + 1);
    for (let j = start; j < end; j++) {
      if (bMatch[j] || a[i] !== b[j]) continue;
      aMatch[i] = true;
      bMatch[j] = true;
      matches++;
      break;
    }
  }
  if (matches === 0) return 0;
  let t = 0, k = 0;
  for (let i = 0; i < m; i++) {
    if (!aMatch[i]) continue;
    while (!bMatch[k]) k++;
    if (a[i] !== b[k]) t++;
    k++;
  }
  const jaro = (matches / m + matches / n + (matches - t / 2) / matches) / 3;
  let prefix = 0;
  const limit = Math.min(4, m, n);
  for (let i = 0; i < limit; i++) {
    if (a[i] === b[i]) prefix++;
    else break;
  }
  return jaro + prefix * 0.1 * (1 - jaro);
}

function soundex(s) {
  if (!s) return '';
  s = s.toLowerCase();
  const first = s[0];
  const rest = s.slice(1)
    .replace(/[aeiouyhw]/g, '')
    .replace(/[bfpv]/g, '1')
    .replace(/[cgjkqsxz]/g, '2')
    .replace(/[dt]/g, '3')
    .replace(/l/g, '4')
    .replace(/[mn]/g, '5')
    .replace(/r/g, '6')
    .replace(/(\d)\1+/g, '$1');
  return (first + rest + '000').slice(0, 4);
}

function homoglyphScore(a, b) {
  if (a.length !== b.length) return 0;
  const map = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't', '8': 'b', '@': 'a' };
  let swaps = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] === b[i]) continue;
    const na = map[a[i]] || a[i];
    const nb = map[b[i]] || b[i];
    if (na === b[i] || a[i] === nb || na === nb) swaps++;
    else return 0;
  }
  return swaps > 0 ? 1 - swaps / a.length : 0;
}

function computeConfidence(dist, phonetic, homoglyph, registryMeta) {
  let subtype, base;
  if (dist === 1) {
    subtype = 'edit_distance_1';
    base = 75;
  } else if (dist === 2) {
    subtype = 'edit_distance_2';
    base = 45;
  } else if (phonetic > 0.85) {
    subtype = 'phonetic_match';
    base = 50;
  } else if (homoglyph > 0.7) {
    subtype = 'homoglyph_swap';
    base = 60;
  } else {
    return null;
  }
  let score = base;
  if (registryMeta) {
    const age = registryMeta.age || 0;
    const downloads = registryMeta.weeklyDownloads || 0;
    if (age < 30) score += 15;
    if (downloads < 1000) score += 10;
    if (age > 365 && downloads > 100000) score -= 30;
  }
  score = Math.max(50, Math.min(100, score));
  return { subtype, score };
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

export const name = 'tier1-typosquat';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const findings = [];
  const pkgName = pkgJson?.name;
  if (!pkgName) return findings;

  if (KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return findings;

  const namesToCheck = [];
  let scopedName = null;

  if (pkgName.startsWith('@')) {
    const parts = pkgName.split('/');
    if (parts.length === 2) {
      scopedName = parts[1];
      namesToCheck.push(pkgName, scopedName);
    }
  } else {
    namesToCheck.push(pkgName);
  }

  let best = null;
  let bestScore = 0;

  for (const checkName of namesToCheck) {
    for (const target of TOP_PACKAGES) {
      if (checkName === target) {
        if (pkgName.startsWith('@') && checkName === scopedName && !KNOWN_REPUTABLE_PACKAGES.has(scopedName)) {
          let score = 80;
          if (registryMeta) {
            if ((registryMeta.age || 0) < 30) score += 15;
            if ((registryMeta.weeklyDownloads || 0) < 1000) score += 10;
          }
          score = Math.max(50, Math.min(100, score));
          if (score > bestScore) {
            bestScore = score;
            best = { target, dist: 0, phonetic: 1, homoglyph: 0, subtype: 'edit_distance_1', isScopeSquat: true };
          }
        }
        continue;
      }
      if (Math.abs(checkName.length - target.length) > 2) continue;
      const dist = levenshtein(checkName, target);
      if (dist > 2) continue;
      const phonetic = jaroWinkler(checkName, target);
      const homoglyph = homoglyphScore(checkName, target);
      const conf = computeConfidence(dist, phonetic, homoglyph, registryMeta);
      if (!conf || conf.score <= bestScore) continue;
      bestScore = conf.score;
      best = { target, dist, phonetic, homoglyph, subtype: conf.subtype, isScopeSquat: false };
    }
  }

  if (best) {
    findings.push({
      detector: 'tier1-typosquat',
      id: 'TIER1-TYPOSQUAT',
      severity: severityLabel(bestScore),
      confidence: confidenceLabel(bestScore),
      confidenceScore: bestScore,
      subtype: best.subtype,
      message: `Package name "${pkgName}" is typo of "${best.target}"${best.dist > 0 ? ` (distance ${best.dist})` : ''}`,
      evidence: [
        `distance: ${best.dist}`,
        `phonetic_score: ${(best.phonetic || 1).toFixed(2)}`,
        `similar_package: ${best.target}`,
        `age_days: ${registryMeta?.age || 0}`,
        `weekly_downloads: ${registryMeta?.weeklyDownloads || 0}`,
      ],
      crossFiles: [],
      locations: [{ file: 'package.json', line: 2, column: 10 }],
      reference: 'Campaign 2: Cloud-Secret Typosquatting',
    });
  }

  return findings;
}
