import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

let iocsData = null;
let iocsLoaded = false;
let iocLoadError = null;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const IOC_PATH = join(__dirname, 'iocs.json');

function loadIOCData() {
  if (iocsLoaded) {
    return iocsData;
  }
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

export async function checkIOC(pkgName, pkgVersion, sha512, publisherAccount, timeMap = {}) {
  const data = loadIOCData();
  if (!data) {
    return { triggered: false, matches: [] };
  }

  const matches = [];
  const allIOCs = [];

  allIOCs.push(...(data.iocs || []));

  for (const waveKey of Object.keys(data.waves || {})) {
    const wave = data.waves[waveKey];
    const waveNum = waveKey === 'wave1' ? 1 : waveKey === 'wave2' ? 2 : 3;
    for (const ioc of wave.iocs || []) {
      allIOCs.push({ ...ioc, wave: waveNum });
    }
  }

  for (const ioc of allIOCs) {
    switch (ioc.type) {
      case 'packageName': {
        if (ioc.value === pkgName) {
          if (
            !ioc.maliciousVersions ||
            ioc.maliciousVersions.length === 0 ||
            ioc.maliciousVersions.includes(pkgVersion)
          ) {
            matches.push({ type: 'packageName', value: pkgName, wave: ioc.wave });
          }
        }
        break;
      }

      case 'packageScope': {
        if (pkgName.startsWith(ioc.value)) {
          matches.push({ type: 'packageScope', value: ioc.value, wave: ioc.wave });
        }
        break;
      }

      case 'sha512': {
        if (ioc.value === sha512 && ioc.package === pkgName) {
          matches.push({ type: 'sha512', value: sha512, wave: ioc.wave, package: pkgName });
        }
        break;
      }

      case 'publisherAccount': {
        if (ioc.value === publisherAccount) {
          const pubTime = new Date(timeMap?.[pkgVersion]).getTime();
          const windowStart = new Date(ioc.compromiseWindowStart).getTime();
          const windowEnd = ioc.compromiseWindowEnd
            ? new Date(ioc.compromiseWindowEnd).getTime()
            : Infinity;

          if (!Number.isNaN(pubTime) && pubTime >= windowStart && pubTime <= windowEnd) {
            matches.push({ type: 'publisherAccount', value: publisherAccount, wave: ioc.wave });
          }
        }
        break;
      }
    }
  }

  return { triggered: matches.length > 0, matches };
}
