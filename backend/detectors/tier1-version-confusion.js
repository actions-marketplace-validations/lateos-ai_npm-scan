import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const SENTINEL_EXACT = ['99.99.99'];
const SENTINEL_FAMILY = ['9.9.9', '9.9.10', '10.10.10', '11.11.11'];

function severityLabel(score) {
  if (score >= 80) {
    return 'high';
  }
  if (score >= 60) {
    return 'medium';
  }
  return 'low';
}

function confidenceLabel(score) {
  if (score >= 80) {
    return 'HIGH';
  }
  if (score >= 60) {
    return 'MEDIUM';
  }
  return 'LOW';
}

function parseVersion(version) {
  if (!version || typeof version !== 'string') {
    return null;
  }
  const parts = version.split('.');
  if (parts.length !== 3) {
    return null;
  }
  const [major, minor, patch] = parts.map(Number);
  if (isNaN(major) || isNaN(minor) || isNaN(patch)) {
    return null;
  }
  return { major, minor, patch };
}

function matchesHeuristic(parsed) {
  return parsed.major >= 9 && parsed.minor >= 5 && parsed.patch >= 5 && parsed.major !== 1;
}

export const name = 'tier1-version-confusion';

export async function scan(pkgJson, _jsFiles, _registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  const version = pkgJson?.version;

  if (!pkgName || !version) {
    return [];
  }
  if (KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const parsed = parseVersion(version);
  if (!parsed) {
    return [];
  }

  const vStr = version;

  // Priority: SENTINEL_EXACT > SENTINEL_FAMILY > HEURISTIC
  if (SENTINEL_EXACT.includes(vStr)) {
    const score = 85;
    return [
      {
        detector: 'tier1-version-confusion',
        id: 'TIER1-VERSION-CONFUSION',
        severity: severityLabel(score),
        confidence: confidenceLabel(score),
        confidenceScore: score,
        subtype: 'sentinel_exact',
        message: `Package "${pkgName}" uses exact sentinel version ${vStr} — dependency confusion indicator`,
        evidence: [`version: ${vStr}`, `sentinel: exact match`],
        crossFiles: [],
        locations: [{ file: 'package.json', line: 3, column: 10 }],
        reference: 'Sonatype-2026-003429',
      },
    ];
  }

  if (SENTINEL_FAMILY.includes(vStr)) {
    const score = 65;
    return [
      {
        detector: 'tier1-version-confusion',
        id: 'TIER1-VERSION-CONFUSION',
        severity: severityLabel(score),
        confidence: confidenceLabel(score),
        confidenceScore: score,
        subtype: 'sentinel_family',
        message: `Package "${pkgName}" uses sentinel family version ${vStr} — dependency confusion indicator`,
        evidence: [`version: ${vStr}`, `sentinel: family match`],
        crossFiles: [],
        locations: [{ file: 'package.json', line: 3, column: 10 }],
        reference: 'Sonatype-2026-003429',
      },
    ];
  }

  if (matchesHeuristic(parsed)) {
    const score = 62;
    return [
      {
        detector: 'tier1-version-confusion',
        id: 'TIER1-VERSION-CONFUSION',
        severity: severityLabel(score),
        confidence: confidenceLabel(score),
        confidenceScore: score,
        subtype: 'high_version_heuristic',
        message: `Package "${pkgName}" version ${vStr} matches high-version heuristic — possible dependency confusion`,
        evidence: [
          `version: ${vStr}`,
          `major: ${parsed.major}, minor: ${parsed.minor}, patch: ${parsed.patch}`,
        ],
        crossFiles: [],
        locations: [{ file: 'package.json', line: 3, column: 10 }],
        reference: 'Microsoft Scope Confusion',
      },
    ];
  }

  return [];
}
