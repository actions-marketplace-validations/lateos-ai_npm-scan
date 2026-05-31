import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const INTERNAL_SUFFIX_RE = /\.(?:internal|local|corp|intra|priv|lan)(?:[.:/]|$)/i;
const CORPORATE_RE = /(?:github-ent|jira-ent|github\.enterprise|internal-gitlab|gitlab\.internal|jenkins\.internal|confluence\.internal)/i;
const PRIVATE_IP_RE = /^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/;

function extractDomain(url) {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    const m = url.match(/^(?:https?:\/\/)?([^\/\s:]+)/);
    return m ? m[1] : null;
  }
}

function isInternalUrl(url) {
  if (!url) return false;
  const domain = extractDomain(url);
  if (!domain) return false;
  if (INTERNAL_SUFFIX_RE.test(domain)) return true;
  if (CORPORATE_RE.test(domain)) return true;
  if (PRIVATE_IP_RE.test(domain)) return true;
  return false;
}

function parseSemver(version) {
  if (!version) return null;
  const parts = version.replace(/^[~^]/, '').split('.');
  const m = parseInt(parts[0], 10);
  const n = parseInt(parts[1], 10);
  const p = parseInt(parts[2], 10);
  if (isNaN(m) || isNaN(n) || isNaN(p)) return null;
  return { major: m, minor: n, patch: p };
}

function detectSemverInflation(currentVer, registryMeta) {
  if (!currentVer || !registryMeta) return null;

  const age = registryMeta.age;
  if (age !== undefined && age < 7) return null;

  const previousVer = registryMeta.previousVersion || null;
  if (!previousVer) return null;

  const cur = parseSemver(currentVer);
  const prev = parseSemver(previousVer);
  if (!cur || !prev) return null;

  const majorJump = cur.major - prev.major;
  const minorJump = cur.minor - prev.minor;
  const patchJump = cur.patch - prev.patch;

  if (majorJump > 10) return { type: 'major', from: previousVer, to: currentVer, jump: majorJump };
  if (minorJump > 20) return { type: 'minor', from: previousVer, to: currentVer, jump: minorJump };
  if (patchJump > 50) return { type: 'patch', from: previousVer, to: currentVer, jump: patchJump };

  return null;
}

export const name = 'tier1-metadata-spoof';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const fieldUrls = [];

  function addField(field, value) {
    if (value && typeof value === 'string') {
      fieldUrls.push({ field, value });
    }
  }

  if (pkgJson.repository) {
    const v = typeof pkgJson.repository === 'string' ? pkgJson.repository : pkgJson.repository.url;
    addField('repository.url', v);
  }

  addField('homepage', pkgJson.homepage);

  if (pkgJson.bugs) {
    const v = typeof pkgJson.bugs === 'string' ? pkgJson.bugs : pkgJson.bugs.url;
    addField('bugs.url', v);
  }

  if (pkgJson.funding) {
    const arr = Array.isArray(pkgJson.funding) ? pkgJson.funding : [pkgJson.funding];
    for (let i = 0; i < arr.length; i++) {
      if (arr[i] && arr[i].url) addField(`funding[${i}].url`, arr[i].url);
    }
  }

  if (pkgJson.author && typeof pkgJson.author === 'object' && pkgJson.author.url) {
    addField('author.url', pkgJson.author.url);
  }

  const internalFields = fieldUrls.filter(f => isInternalUrl(f.value));
  const hasInternalUrls = internalFields.length > 0;

  const currentVersion = pkgJson?.version;
  const semverInflation = detectSemverInflation(currentVersion, registryMeta);

  if (!hasInternalUrls && !semverInflation) return [];

  let baseScore = 0;
  let subtype = '';
  let primaryMessage = '';
  const evidence = [];
  const locations = [];

  if (hasInternalUrls) {
    baseScore = 65;
    subtype = 'internal_url_in_repo';

    for (const f of internalFields) {
      const domain = extractDomain(f.value);
      evidence.push(`url: ${f.field} = ${f.value}`);

      let pattern = '';
      if (PRIVATE_IP_RE.test(domain)) pattern = 'private IP';
      else if (CORPORATE_RE.test(domain)) pattern = 'corporate domain';
      else pattern = 'internal domain';
      evidence.push(`pattern: ${domain} (${pattern})`);

      locations.push({ field: f.field, value: f.value });
    }

    if (internalFields.length > 1) {
      baseScore += 20;
      evidence.push('coordinated: multiple internal URLs');
    }

    primaryMessage = `Package metadata contains spoofed internal URL${internalFields.length > 1 ? 's' : ''}`;
  }

  if (semverInflation) {
    const semverMsg = `semver: ${semverInflation.from} \u2192 ${semverInflation.to} (${semverInflation.type} jump of ${semverInflation.jump})`;

    if (hasInternalUrls) {
      baseScore = Math.round(baseScore * 1.3);
      evidence.push(semverMsg);
      evidence.push(`${semverInflation.type} version jump (${semverInflation.jump}) without changelog`);
      locations.push({ field: 'version', old: semverInflation.from, new: semverInflation.to });
      primaryMessage += ' + unjustified semver jump';
    } else {
      baseScore = 40;
      subtype = 'semver_inflation';
      evidence.push(semverMsg);
      locations.push({ field: 'version', old: semverInflation.from, new: semverInflation.to });
      primaryMessage = 'Unjustified semver version jump detected';
    }
  }

  const confidenceScore = Math.max(50, Math.min(90, baseScore));

  function severityLabel(sc) {
    if (sc >= 70) return 'high';
    return 'medium';
  }

  function confidenceLabel(sc) {
    if (sc >= 80) return 'HIGH';
    if (sc >= 60) return 'MEDIUM';
    return 'LOW';
  }

  return [{
    detector: 'tier1-metadata-spoof',
    id: 'TIER1-METADATA-SPOOF',
    severity: severityLabel(confidenceScore),
    confidence: confidenceLabel(confidenceScore),
    confidenceScore,
    subtype,
    message: primaryMessage,
    evidence,
    locations,
    reference: 'Campaign 1',
  }];
}
