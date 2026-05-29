export function scanPublisherBlocklist(pkgJson, registryMeta) {
  const publisherAccount = registryMeta?.versions?.[pkgJson?.version]?._npmUser?.name
    || registryMeta?.versions?.[Object.keys(registryMeta.versions || {})[0]]?._npmUser?.name
    || null;

  if (publisherAccount === 'asdxzxc') {
    return { triggered: true, publisher: publisherAccount };
  }
  return { triggered: false, publisher: publisherAccount };
}
