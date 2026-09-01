import path from 'path';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D15-MEMORY-EXTRACTION'];
const PATTERN_WEIGHTS = cfg.pattern_weights;

const CODE_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.rs',
  '.c',
  '.cc',
  '.cpp',
  '.h',
  '.hpp',
  '.ts',
]);

function isCodeFile(f) {
  const fp = (f.path || f.name || '').toLowerCase();
  return CODE_EXTENSIONS.has(path.extname(fp));
}

function concatSources(jsFiles, allFiles) {
  const files = allFiles || jsFiles || [];
  const sources = [];
  for (const f of files) {
    if (f.content && isCodeFile(f)) sources.push(f.content);
  }
  return sources.join('\n');
}

function extractLines(content, matchIndex) {
  if (!content) return 1;
  const before = content.slice(0, matchIndex);
  return (before.match(/\n/g) || []).length + 1;
}

export const name = 'tier1-memory-extraction';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  if (!source) return [];

  const findings = [];
  let aggregatedRisk = 0;

  // Pattern 1: OIDC/GitHub token access
  const oidcPatterns = [
    /process\.env\.OIDC_TOKEN/g,
    /process\.env\.GITHUB_TOKEN/g,
    /process\.env\.CI_JOB_JWT/g,
    /process\.env\.ACTIONS_ID_TOKEN/g,
    /process\.env\[['"][A-Z_]*TOKEN['"]\]/g,
  ];

  for (const regex of oidcPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.oidc_token_access;
      findings.push({
        detector: 'tier1-memory-extraction',
        id: 'D15-MEMORY-EXTRACTION',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'OIDC token access pattern detected',
        evidence: [`pattern: oidc_token_access`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 2: Process memory introspection APIs
  const memPatterns = [/\bptrace\s*\(/g, /\/proc\/self\/mem/g, /\bmemfd_create\b/g];

  for (const regex of memPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.memory_introspection;
      findings.push({
        detector: 'tier1-memory-extraction',
        id: 'D15-MEMORY-EXTRACTION',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Process memory introspection API detected',
        evidence: [`pattern: memory_introspection`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  if (findings.length === 0) return [];

  const overallScore = Math.min(100, Math.max(0, aggregatedRisk));
  let severity;
  if (overallScore >= cfg.flag_threshold) {
    severity = 'critical';
  } else if (overallScore >= cfg.warn_threshold) {
    severity = 'high';
  } else if (overallScore >= 30) {
    severity = 'medium';
  } else {
    severity = 'low';
  }

  function confidenceLabel(sc) {
    if (sc >= 80) return 'HIGH';
    if (sc >= 50) return 'MEDIUM';
    return 'LOW';
  }

  const hasOidc = findings.some((f) => f.evidence?.some((e) => e.includes('oidc_token_access')));

  let recommendation = 'PASS';
  if (hasOidc) {
    recommendation = 'BLOCK - OIDC token access with credential extraction detected';
  } else if (overallScore > cfg.warn_threshold) {
    recommendation = 'WARN - Suspicious memory access patterns detected';
  }

  return [
    {
      detector: 'tier1-memory-extraction',
      id: 'D15-MEMORY-EXTRACTION',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Memory Credential Extraction detected (aggregated risk: ${aggregatedRisk})`,
      evidence: [
        `total_findings: ${findings.length}`,
        `aggregated_risk: ${aggregatedRisk}`,
        ...findings.map((f) => {
          const loc = f.locations?.[0];
          return `${f.message}${loc ? ' @ ' + (loc.file || '') + (loc.line ? ':' + loc.line : '') : ''}`;
        }),
      ],
      locations: findings.flatMap((f) => f.locations || []),
      recommendation,
      detail: findings.map((f) => ({
        type:
          f.evidence?.find((e) => e.startsWith('pattern:'))?.replace('pattern: ', '') || 'unknown',
        pattern: f.evidence?.find((e) => e.startsWith('pattern:'))?.replace('pattern: ', ''),
        confidence: f.confidenceScore,
        risk: f.confidenceScore,
        location: f.locations?.[0] || null,
      })),
    },
  ];
}
