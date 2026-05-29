const COMPROMISED_VERSIONS = {
  '9.1.6': { safePin: '9.1.5', ranges: ['~9.1.x', '^9.1', '^9'] },
  '9.2.3': { safePin: '9.1.5', ranges: ['~9.2.x', '^9.2'] },
  '12.0.1': { safePin: '12.0.0', ranges: ['~12.0.x', '^12'] },
};

const LOCKFILE_PATTERNS = [
  /package-lock\.json$/i,
  /yarn\.lock$/i,
  /pnpm-lock\.yaml$/i,
  /pnpm-lock\.yml$/i,
];

export function scanBlastRadius(allFiles) {
  const matches = [];

  for (const file of allFiles) {
    const path = file.path?.replace(/\\/g, '/') || '';
    const isLockfile = LOCKFILE_PATTERNS.some(p => p.test(path));
    if (!isLockfile) continue;

    const content = file.content || '';
    const hasNodeIpc = /\bnode-ipc\b/i.test(content);
    if (!hasNodeIpc) continue;

    for (const [badVersion, info] of Object.entries(COMPROMISED_VERSIONS)) {
      const versionInQuotes = `"${badVersion}"`;
      if (content.includes(versionInQuotes)) {
        matches.push({
          file: path,
          compromisedVersion: badVersion,
          safePin: info.safePin,
          detail: `node-ipc resolved to compromised version ${badVersion} in lockfile. Pin to ${info.safePin}.`,
        });
      }
    }
  }

  return { triggered: matches.length > 0, matches };
}
