const BLOCKED_VERSIONS = new Set(['9.1.6', '9.2.3', '12.0.1']);

const SAFE_PINS = {
  '9.1.6': '9.1.5',
  '9.2.3': '9.1.5',
  '12.0.1': '12.0.0',
};

export function scanVersionBlocklist(pkgJson, _registryMeta) {
  const pkgName = pkgJson?.name || '';
  if (pkgName !== 'node-ipc') {
    return { triggered: false };
  }

  const version = pkgJson?.version || '';
  if (BLOCKED_VERSIONS.has(version)) {
    return {
      triggered: true,
      version,
      safePin: SAFE_PINS[version],
      maliciousVersions: ['9.1.6', '9.2.3', '12.0.1'],
    };
  }

  return { triggered: false, version };
}
