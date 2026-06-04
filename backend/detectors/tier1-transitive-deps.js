import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const THRESHOLDS = {
  flag_threshold: 80,
  warn_threshold: 50,
  new_package_days: 7,
  unknown_depth_weight: 45,
  typosquat_depth_weight: 50,
  different_maintainer_weight: 35,
};

const SUSPICIOUS_NAMES = /(?:plain-crypto|crypto-js|secure-crypto|crypto-lib|cryptography)/i;

function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const m = a.length,
    n = b.length;
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
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      if (curr[j] < rowMin) rowMin = curr[j];
    }
    if (rowMin > 2) return 3;
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[n];
}

function isTyposquat(name, popularNames) {
  for (const popular of popularNames) {
    if (Math.abs(name.length - popular.length) > 2) continue;
    const dist = levenshtein(name, popular);
    if (dist <= 2 && name !== popular) return popular;
  }
  return null;
}

const POPULAR_PACKAGES = [
  'crypto-js',
  'crypto',
  'bcrypt',
  'jsonwebtoken',
  'json5',
  'lodash',
  'axios',
  'express',
  'moment',
  'chalk',
  'react',
  'vue',
  'angular',
  'next',
  'nuxt',
  'typescript',
  'eslint',
  'prettier',
  'webpack',
  'babel',
  'mongoose',
  'redis',
  'mysql',
  'postgres',
  'passport',
];

function collectDependencies(pkgJson) {
  const deps = {};
  const allDeps = {
    ...(pkgJson?.dependencies || {}),
    ...(pkgJson?.devDependencies || {}),
  };
  for (const [name, version] of Object.entries(allDeps)) {
    deps[name] = { version, depth: 0, isDirect: true };
  }
  return deps;
}

function computeConfidence(findings) {
  if (findings.length === 0) return 0;
  const maxScore = Math.max(...findings.map((f) => f.weight));
  let base = maxScore;
  if (findings.length > 1) base += 15;
  return Math.min(100, Math.max(0, base));
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

export const name = 'tier1-transitive-deps';

export async function scan(pkgJson, _jsFiles, _registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const deps = collectDependencies(pkgJson);
  const depNames = Object.keys(deps);
  if (depNames.length === 0) return [];

  const findings = [];

  for (const [depName, depInfo] of Object.entries(deps)) {
    let weight = 0;
    const reasons = [];

    if (SUSPICIOUS_NAMES.test(depName)) {
      weight += 55;
      reasons.push('suspicious_naming: matches known malicious pattern');
    }

    const typosquatTarget = isTyposquat(depName, POPULAR_PACKAGES);
    if (typosquatTarget) {
      weight += THRESHOLDS.typosquat_depth_weight;
      reasons.push(`typosquat: "${depName}" similar to "${typosquatTarget}"`);
    }

    if (depInfo.isDirect) {
      const depVersion = depInfo.version || '';
      if (depVersion.includes('x') || depVersion === '*' || /^\d+\.\d+\.\d+$/.test(depVersion)) {
        const parts = depVersion.split('.');
        if (parts.length === 3) {
          const major = parseInt(parts[0], 10);
          if (major >= 99) {
            weight += 55;
            reasons.push(`version_anomaly: suspicious version ${depVersion}`);
          }
        }
      }
    }

    if (weight > 0) {
      findings.push({
        package: depName,
        depth: depInfo.depth,
        isDirect: depInfo.isDirect,
        weight,
        reasons,
      });
    }
  }

  if (findings.length === 0) return [];

  const confidenceScore = computeConfidence(findings);
  if (confidenceScore < THRESHOLDS.warn_threshold) return [];

  const topFindings = findings.sort((a, b) => b.weight - a.weight).slice(0, 5);

  return [
    {
      detector: 'tier1-transitive-deps',
      id: 'TIER1-TRANSITIVE-DEPS',
      severity: severityLabel(confidenceScore),
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype: 'transitive_injection',
      message: `${findings.length} suspicious transitive dependenc${findings.length > 1 ? 'ies' : 'y'} detected`,
      evidence: topFindings.map((f) => `${f.package} (depth ${f.depth}): ${f.reasons.join('; ')}`),
      locations: [{ file: 'package.json', line: 1, column: 1 }],
      crossFiles: topFindings.map((f) => f.package),
      reference: 'D12: Axios backdoor transitive injection',
    },
  ];
}
