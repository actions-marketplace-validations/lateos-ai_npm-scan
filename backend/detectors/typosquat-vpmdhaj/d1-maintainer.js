const BLOCKED_MAINTAINERS = ['vpmdhaj'];
const VPMDHAJ_PREFIX_RE = /^vpmdhaj-/;
const TYPOSQUAT_TARGETS = [
  'opensearch-setup',
  'env-config-manager',
  'express',
  'lodash',
  'axios',
  'react',
  'vue',
  'angular',
  'babel',
  'webpack',
  'typescript',
  'moment',
  'dotenv',
];

function levenshteinDistance(a, b) {
  const m = a.length,
    n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) {
    dp[i][0] = i;
  }
  for (let j = 0; j <= n; j++) {
    dp[0][j] = j;
  }
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

export function scanMaintainerAnomaly(pkgJson, registryMeta) {
  const pkgName = pkgJson?.name || '';
  const currentVersion = pkgJson?.version || '';
  const versionMeta = registryMeta?.versions?.[currentVersion];
  const publisherName = versionMeta?._npmUser?.name || '';

  if (BLOCKED_MAINTAINERS.includes(publisherName)) {
    return {
      triggered: true,
      stopCondition: true,
      maintainer: publisherName,
      suspiciousAliases: [],
      reason: 'Blocked maintainer detected',
    };
  }

  if (VPMDHAJ_PREFIX_RE.test(pkgName)) {
    return {
      triggered: true,
      stopCondition: true,
      maintainer: publisherName || 'unknown',
      suspiciousAliases: [pkgName],
      reason: 'Package name matches vpmdhaj attacker namespace',
    };
  }

  const suspiciousAliases = [];
  for (const target of TYPOSQUAT_TARGETS) {
    if (pkgName.includes(target) && pkgName !== target && !pkgName.startsWith('@')) {
      const dist = levenshteinDistance(pkgName.toLowerCase(), target.toLowerCase());
      if (dist <= 2 && dist > 0) {
        suspiciousAliases.push(pkgName);
      }
    }
  }
  if (pkgName.toLowerCase().includes('opensearch')) {
    suspiciousAliases.push(pkgName);
  }
  if (pkgName.toLowerCase().includes('env-config') || pkgName.toLowerCase().includes('envconfig')) {
    suspiciousAliases.push(pkgName);
  }

  if (suspiciousAliases.length > 0) {
    return {
      triggered: true,
      stopCondition: false,
      maintainer: publisherName || 'unknown',
      suspiciousAliases,
      reason: 'Package name typosquats popular package',
    };
  }

  return {
    triggered: false,
    stopCondition: false,
    maintainer: '',
    suspiciousAliases: [],
    reason: '',
  };
}

export { BLOCKED_MAINTAINERS };
