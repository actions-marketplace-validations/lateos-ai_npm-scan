const KNOWN_DECOYS = ['plain-crypto-js'];

export function scanDecoyDependency(pkgJson) {
  const deps = { ...pkgJson?.dependencies, ...pkgJson?.devDependencies, ...pkgJson?.peerDependencies };
  const findings = [];

  for (const depName of KNOWN_DECOYS) {
    if (deps[depName]) {
      findings.push({
        injectedDependency: depName,
        pattern: 'Pre-staged decoy for supply chain attack',
      });
    }
  }

  if (findings.length > 0) {
    return {
      triggered: true,
      findings,
    };
  }

  return { triggered: false, findings: [] };
}
