export function scanUnauthorizedPublisher(pkgJson, registryMeta) {
  const pkgName = pkgJson?.name || '';
  if (pkgName !== 'node-ipc') {
    return { triggered: false };
  }

  const publisherAccount =
    registryMeta?.versions?.[pkgJson?.version]?._npmUser?.name ||
    registryMeta?.versions?.[Object.keys(registryMeta.versions || {})[0]]?._npmUser?.name ||
    null;

  if (publisherAccount === 'atiertant') {
    return {
      triggered: true,
      publisher: publisherAccount,
      package: pkgName,
      detail:
        'Account atiertant has no prior release history on node-ipc — account recovery via expired email domain takeover',
    };
  }

  return { triggered: false, publisher: publisherAccount };
}
