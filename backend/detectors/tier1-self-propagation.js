import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import thresholds from './config/thresholds.js';

const THRESHOLDS = {
  flag_threshold: 75,
  warn_threshold: 60,
  burst_window_minutes: 60,
  min_packages_burst: 3,
  identical_payload_weight: 40,
};

const WORM_THRESHOLDS = thresholds['TIER1-WORM-PROPAGATION'];
const WORM_PATTERN_WEIGHTS = WORM_THRESHOLDS.pattern_weights;
const WORM_PATTERN_CONFIDENCE = WORM_THRESHOLDS.pattern_confidence;

function parseTimeStamps(registryMeta) {
  const timeData = registryMeta?.time;
  if (!timeData || typeof timeData !== 'object') return [];
  return Object.entries(timeData)
    .map(([ver, ts]) => ({
      version: ver,
      time: new Date(ts).getTime(),
    }))
    .filter((e) => !isNaN(e.time))
    .sort((a, b) => a.time - b.time);
}

function findBursts(entries, windowMs) {
  const bursts = [];
  for (let i = 0; i < entries.length; i++) {
    const windowEnd = entries[i].time + windowMs;
    const group = [];
    for (let j = i; j < entries.length && entries[j].time <= windowEnd; j++) {
      group.push(entries[j]);
    }
    if (group.length >= 3) {
      bursts.push({
        startVersion: group[0].version,
        endVersion: group[group.length - 1].version,
        count: group.length,
        windowMinutes: windowMs / 60000,
        versions: group.map((e) => e.version),
      });
    }
  }
  return bursts;
}

function computeConfidence(bursts, findings) {
  let base = 40;
  if (bursts.length > 0) {
    base += 20 + Math.min(bursts[0].count * 5, 25);
  }
  if (findings.length > 0) {
    base += THRESHOLDS.identical_payload_weight;
  }
  return Math.min(100, Math.max(0, base));
}

function severityLabel(score) {
  if (score >= 80) return 'high';
  if (score >= 60) return 'medium';
  return 'low';
}

function confidenceLabel(score) {
  if (score >= 80) return 'HIGH';
  if (score >= 60) return 'MEDIUM';
  return 'LOW';
}

function extractLines(content, matchIndex) {
  if (!content) return 1;
  const before = content.slice(0, matchIndex);
  return (before.match(/\n/g) || []).length + 1;
}

function scanWormPatterns(jsFiles, allFiles) {
  const files = allFiles || jsFiles || [];
  if (!files.length) return [];

  const wormFindings = [];
  let wormAggregatedRisk = 0;

  const wormPatterns = {
    npmrc_exfil: /(process\.env\.NPM_TOKEN|fs\.readFileSync.*\.npmrc|npm\s+(whoami|publish|token))/g,
    github_ssh_exfil: /(fs\.readFileSync.*\.ssh|fs\.readFileSync.*id_rsa|gh\s+auth)/g,
    cloud_cred_exfil: /(~\/\.aws\/credentials|~\/\.config\/gcloud|AZURE_CLIENT_ID|GOOGLE_APPLICATION_CREDENTIALS)/g,
    self_publish: /\b(npm\s+publish|npm\s+version\s+(patch|minor|major)|npm\s+dist-tag\s+add)\b/g,
    immediate_exfil_no_delay: /(?:fetch|axios|request)\s*\([^)]*\)\s*;?\s*(?:\n|$)/g,
  };

  const source = files.map((f) => f.content || '').join('\n');

  for (const [patternName, regex] of Object.entries(wormPatterns)) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const weight = WORM_PATTERN_WEIGHTS[patternName] || 80;
      const confidence = WORM_PATTERN_CONFIDENCE[patternName] || 0.9;
      wormFindings.push({
        detector: 'tier1-self-propagation',
        id: 'TIER1-WORM-PROPAGATION',
        severity: weight >= 90 ? 'critical' : 'high',
        confidence: confidence >= 0.95 ? 'CRITICAL' : 'HIGH',
        confidenceScore: weight,
        message: `Worm-capable self-propagation pattern: ${patternName.replace(/_/g, ' ')}`,
        evidence: [
          `pattern: ${patternName}`,
          `match: ${match[0].slice(0, 120)}`,
          `confidence: ${confidence}`,
        ],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
        recommendation: 'BLOCK - Package contains credential scraping and auto-publish capability',
      });
      wormAggregatedRisk += weight;
    }
  }

  if (wormFindings.length === 0) return [];

  const overallWormScore = Math.min(100, Math.max(0, wormAggregatedRisk));
  return [
    {
      detector: 'tier1-self-propagation',
      id: 'TIER1-WORM-PROPAGATION',
      severity: overallWormScore >= WORM_THRESHOLDS.flag_threshold ? 'critical' : 'high',
      confidence: overallWormScore >= 90 ? 'CRITICAL' : 'HIGH',
      confidenceScore: overallWormScore,
      message: `Worm-capable self-propagation patterns detected (aggregated risk: ${wormAggregatedRisk})`,
      evidence: [
        `total_pattern_matches: ${wormFindings.length}`,
        `aggregated_risk: ${wormAggregatedRisk}`,
        ...wormFindings.map((f) => {
          const loc = f.locations?.[0];
          return `${f.message}${loc ? ' @ ' + (loc.file || '') + ':' + (loc.line || '') : ''}`;
        }),
      ],
      locations: wormFindings.flatMap((f) => f.locations || []),
      recommendation: 'BLOCK - Worm-capable package',
      detail: wormFindings.map((f) => ({
        type: f.evidence?.find((e) => e.startsWith('pattern:'))?.replace('pattern: ', '') || 'unknown',
        confidence: f.confidenceScore,
        risk: f.confidenceScore,
      })),
    },
  ];
}

export const name = 'tier1-self-propagation';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  if (!pkgName) return [];

  // Run worm pattern detection on source files (applies to all packages)
  const wormResults = scanWormPatterns(jsFiles, allFiles);

  // Run existing burst detection on registry metadata (skip reputable packages)
  const entries = parseTimeStamps(registryMeta);
  let burstResults = [];
  if (entries.length >= 3 && !KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    const windowMs = (THRESHOLDS.burst_window_minutes || 60) * 60 * 1000;
    const bursts = findBursts(entries, windowMs);
    if (bursts.length > 0) {
      const burst = bursts[0];
      const confidenceScore = computeConfidence(bursts, []);
      if (confidenceScore >= THRESHOLDS.warn_threshold) {
        const relatedPackages = [];
        const maintainer =
          registryMeta?.maintainer || registryMeta?.versions?.[pkgJson.version]?._npmUser?.name;
        const namespaces = registryMeta?.namespacePackages || [];
        if (namespaces.length > 0) {
          for (const np of namespaces) {
            if (np !== pkgName) relatedPackages.push(np);
          }
        }
        burstResults.push({
          detector: 'tier1-self-propagation',
          id: 'TIER1-SELF-PROPAGATION',
          severity: severityLabel(confidenceScore),
          confidence: confidenceLabel(confidenceScore),
          confidenceScore,
          subtype: 'self_propagation_burst',
          message: `Self-propagation burst detected: ${burst.count} versions in ${burst.windowMinutes} minutes`,
          evidence: [
            `burst: ${burst.count} versions in ${burst.windowMinutes}min`,
            `window: ${burst.startVersion} -> ${burst.endVersion}`,
            `related_packages: ${relatedPackages.length}`,
            `maintainer: ${maintainer || 'unknown'}`,
          ],
          locations: [{ file: 'package.json', line: 1, column: 1 }],
          crossFiles: relatedPackages.slice(0, 10),
          reference: 'D10: @redhat-cloud-services Miasma self-propagation',
        });
      }
    }
  }

  return [...wormResults, ...burstResults];
}
