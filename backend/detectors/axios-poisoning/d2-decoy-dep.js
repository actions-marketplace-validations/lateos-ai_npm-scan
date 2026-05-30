const KNOWN_DECOYS = ['plain-crypto-js'];
const CRYPTO_KEYWORDS = ['crypto', 'encrypt', 'decrypt', 'cipher', 'hash', 'aes', 'rsa', 'hmac'];

export function scanDecoyDependency(pkgJson) {
  const deps = { ...pkgJson?.dependencies, ...pkgJson?.devDependencies, ...pkgJson?.peerDependencies };
  const pkgName = pkgJson?.name || '';
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

  const cryptoDeps = Object.keys(deps).filter(d => CRYPTO_KEYWORDS.some(k => d.toLowerCase().includes(k)));
  const pkgNameLower = pkgName.toLowerCase();
  const wordBoundaryCrypto = new RegExp(`\\b(?:${CRYPTO_KEYWORDS.join('|')})\\b`);
  const isCryptoPkg = wordBoundaryCrypto.test(pkgNameLower);

  if (cryptoDeps.length > 0 && !isCryptoPkg) {
    const suspicious = cryptoDeps.filter(d => !KNOWN_DECOYS.includes(d));
    if (suspicious.length > 0) {
      return {
        triggered: true,
        findings: suspicious.map(d => ({
          injectedDependency: d,
          pattern: `Crypto-related dependency in non-crypto package ${pkgName}`,
        })),
      };
    }
  }

  return { triggered: false, findings: [] };
}
