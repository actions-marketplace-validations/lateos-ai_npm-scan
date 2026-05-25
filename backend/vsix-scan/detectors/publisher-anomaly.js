export async function checkPublisherAnomaly(extensionMetadata, publisherProfile, versionHistory, config = {}) {
  const signals = [];

  const crossNamespaceThreshold = config.crossNamespaceThreshold ?? 3;
  const crossNamespaceDays = config.crossNamespaceDays ?? 14;
  const newAccountAgeDays = config.newAccountAgeDays ?? 30;
  const highInstallThreshold = config.highInstallThreshold ?? 100000;
  const addPublishWindowMinutes = config.addPublishWindowMinutes ?? 15;

  const versions = versionHistory || [];
  if (versions.length === 0) return { triggered: false, signals: [] };

  const publishers = [...new Set(versions.map(v => v.publishedBy).filter(Boolean))];
  if (publishers.length === 0) return { triggered: false, signals: [] };

  const sortedVersions = [...versions]
    .filter(v => v.publishedAt)
    .sort((a, b) => new Date(a.publishedAt) - new Date(b.publishedAt));

  const extPublisher = publishers[0];
  const allSame = publishers.every(p => p === extPublisher);

  if (!allSame) {
    for (const pub of publishers) {
      if (pub !== extPublisher) {
        signals.push({
          type: 'PUBLISHER_ACCOUNT_SUBSTITUTION',
          expectedPublisher: extPublisher,
          unexpectedPublisher: pub,
        });
      }
    }
  }

  const extInstallCount = extensionMetadata?.statistics?.find(s => s.statisticName === 'install')?.value || 0;

  const extAgeDays = publisherProfile?.dateCreated
    ? (Date.now() - new Date(publisherProfile.dateCreated).getTime()) / (1000 * 60 * 60 * 24)
    : null;

  if (extAgeDays !== null && extAgeDays < newAccountAgeDays && extInstallCount >= highInstallThreshold) {
    signals.push({
      type: 'NEW_ACCOUNT_HIGH_INSTALL',
      accountAgeDays: Math.round(extAgeDays),
      installCount: extInstallCount,
    });
  }

  if (sortedVersions.length >= 2) {
    const sorted = sortedVersions;
    for (let i = 1; i < sorted.length; i++) {
      const prev = sorted[i - 1];
      const curr = sorted[i];
      if (curr.publishedBy !== prev.publishedBy) {
        const gapMinutes = (new Date(curr.publishedAt) - new Date(prev.publishedAt)) / (1000 * 60);
        if (gapMinutes <= addPublishWindowMinutes) {
          signals.push({
            type: 'ADD_PUBLISH_RAPID',
            version: curr.version,
            previousPublisher: prev.publishedBy,
            newPublisher: curr.publishedBy,
            gapMinutes: Math.round(gapMinutes * 100) / 100,
          });
        }
      }
    }
  }

  return { triggered: signals.length > 0, signals };
}
