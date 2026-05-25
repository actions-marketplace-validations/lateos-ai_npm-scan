import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

let iocsData = null;
let iocsLoaded = false;
let iocLoadError = null;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const IOC_PATH = join(__dirname, '..', 'vsix-iocs.json');

function loadIOCData() {
  if (iocsLoaded) return iocsData;
  iocsLoaded = true;
  try {
    iocsData = JSON.parse(readFileSync(IOC_PATH, 'utf8'));
  } catch (err) {
    iocLoadError = err;
    iocsData = null;
  }
  return iocsData;
}

export function getIOCLoadError() {
  return iocLoadError;
}

export function reloadIOCData() {
  iocsLoaded = false;
  iocLoadError = null;
  return loadIOCData();
}

export async function checkKnownIOC(extensionId, version, publisherAccount, orphanCommits = [], versionHistory = []) {
  const data = loadIOCData();
  if (!data) return { triggered: false, matches: [] };

  const matches = [];
  const iocs = data.iocs || [];

  for (const ioc of iocs) {
    switch (ioc.type) {
      case 'extensionId': {
        if (ioc.value === extensionId) {
          if (!ioc.maliciousVersions || ioc.maliciousVersions.length === 0 || ioc.maliciousVersions.includes(version)) {
            matches.push({
              type: 'extensionId',
              value: extensionId,
              maliciousVersion: version,
              wave: ioc.wave,
              cve: ioc.cve,
              exposureWindowStart: ioc.exposureWindowStart,
              exposureWindowEnd: ioc.exposureWindowEnd,
            });
          }
        }
        break;
      }

      case 'publisherAccount': {
        if (ioc.value === publisherAccount) {
          const pubTime = versionHistory.length > 0
            ? new Date(versionHistory[versionHistory.length - 1]?.publishedAt).getTime()
            : null;

          const windowStart = new Date(ioc.compromiseWindowStart).getTime();
          const windowEnd = ioc.compromiseWindowEnd
            ? new Date(ioc.compromiseWindowEnd).getTime()
            : Infinity;

          if (pubTime && !Number.isNaN(pubTime) && pubTime >= windowStart && pubTime <= windowEnd) {
            matches.push({
              type: 'publisherAccount',
              value: publisherAccount,
              wave: ioc.wave,
              compromiseWindowStart: ioc.compromiseWindowStart,
              compromiseWindowEnd: ioc.compromiseWindowEnd,
            });
          }
        }
        break;
      }

      case 'orphanCommitHash': {
        for (const commit of orphanCommits) {
          if (ioc.value === commit || (ioc.value === 'PLACEHOLDER_UPDATE_FROM_THREAT_INTEL')) {
            continue;
          }
          if (ioc.value && commit && ioc.value.toLowerCase() === commit.toLowerCase()) {
            matches.push({
              type: 'orphanCommitHash',
              value: commit,
              repo: ioc.repo,
              wave: ioc.wave,
            });
          }
        }
        break;
      }
    }
  }

  return { triggered: matches.length > 0, matches };
}
