const LURE_PATTERNS = [
  /solidity/i,
  /defi/i,
  /solana/i,
  /sui\b/i,
  /move-lang/i,
  /^eth-/i,
  /prompt-engineering/i,
  /token-usage/i,
  /dev-env-bootstrap/i,
];

export function scanLureName(pkgJson, registryMeta) {
  const pkgName = pkgJson?.name || '';
  const matchedPattern = LURE_PATTERNS.find((p) => p.test(pkgName));
  if (!matchedPattern) {
    return { triggered: false };
  }

  const timeMap = registryMeta?.time || {};
  const versions = Object.keys(timeMap).filter((v) => v !== 'created' && v !== 'modified');
  const firstVersion =
    versions.length > 0
      ? versions.sort((a, b) => new Date(timeMap[a]) - new Date(timeMap[b]))[0]
      : null;

  if (!firstVersion) {
    return { triggered: false };
  }

  const firstPubDate = new Date(timeMap[firstVersion]);
  const now = new Date();
  const daysSinceFirstPub = (now - firstPubDate) / (1000 * 60 * 60 * 24);

  if (daysSinceFirstPub < 30 && versions.length <= 2) {
    return {
      triggered: true,
      packageName: pkgName,
      matchedPattern: matchedPattern.source,
      firstPublished: timeMap[firstVersion],
      ageDays: Math.round(daysSinceFirstPub),
      versionCount: versions.length,
    };
  }

  return { triggered: false };
}
