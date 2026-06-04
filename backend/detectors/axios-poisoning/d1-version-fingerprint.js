const BLOCKED_VERSIONS = new Map([['axios', ['1.14.1', '0.30.4']]]);

export function scanVersionBlocklist(pkgJson) {
  const pkgName = pkgJson?.name || '';
  const pkgVersion = pkgJson?.version || '';

  const blocked = BLOCKED_VERSIONS.get(pkgName);
  if (!blocked) {
    return { triggered: false, stopCondition: false, matchedVersion: null };
  }

  if (blocked.includes(pkgVersion)) {
    return {
      triggered: true,
      stopCondition: true,
      matchedVersion: pkgVersion,
      reason: `Known compromised version in registry poisoning campaign`,
    };
  }

  return { triggered: false, stopCondition: false, matchedVersion: null };
}

export { BLOCKED_VERSIONS };
