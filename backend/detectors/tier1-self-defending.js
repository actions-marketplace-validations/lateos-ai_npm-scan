import path from 'path';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D18-SELF-DEFENDING'];
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

function matchAllSafe(regex, str) {
  const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
  const fresh = new RegExp(regex.source, flags);
  const results = [];
  let m;
  while ((m = fresh.exec(str)) !== null) {
    results.push(m);
    if (m.index === fresh.lastIndex) fresh.lastIndex++;
  }
  return results;
}

export const name = 'tier1-self-defending';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  if (!source) return [];

  const findings = [];
  let aggregatedRisk = 0;

  // Pattern 1: Debugger detection
  const debuggerPatterns = [
    /process\.argv.*inspect/gi,
    /process\.argv.*debug\b/gi,
    /--inspect|--debug-brk/gi,
    /debugging\s*[=:].*true/gi,
    /process\.env\.NODE_DEBUG/gi,
    /typeof\s+global\.v8debug\b/gi,
  ];

  for (const regex of debuggerPatterns) {
    for (const match of matchAllSafe(regex, source)) {
      const risk = PATTERN_WEIGHTS.debugger_detection;
      findings.push({
        detector: 'tier1-self-defending',
        id: 'D18-SELF-DEFENDING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Debugger detection pattern detected',
        evidence: [`pattern: debugger_detection`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 2: Try-catch execution guards
  const guardPatterns = [
    /if\s*\(\s*process\.env\..*SANDBOX/gi,
    /if\s*\(\s*process\.env\..*TEST\b/gi,
    /typeof\s+require\b.*undefined/gi,
    /process\.env\.CI\s*[=!]/gi,
    /process\.env\.npm_lifecycle_event\s*[=!]/gi,
  ];

  for (const regex of guardPatterns) {
    for (const match of matchAllSafe(regex, source)) {
      const risk = PATTERN_WEIGHTS.execution_guard;
      findings.push({
        detector: 'tier1-self-defending',
        id: 'D18-SELF-DEFENDING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Execution guard pattern detected',
        evidence: [`pattern: execution_guard`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 3: Package validation checks
  const validationPatterns = [
    /require\s*\(\s*['"].*package\.json['"]\s*\)/gi,
    /JSON\.parse.*fs\.readFileSync.*package\.json/gi,
    /crypto\.createHash.*JSON\.stringify.*pjson/gi,
    /checksum|integrity/i,
  ];

  for (const regex of validationPatterns) {
    for (const match of matchAllSafe(regex, source)) {
      const risk = PATTERN_WEIGHTS.package_validation;
      findings.push({
        detector: 'tier1-self-defending',
        id: 'D18-SELF-DEFENDING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Package validation check detected',
        evidence: [`pattern: package_validation`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 4: Environment detection
  const envPatterns = [
    /process\.env\.TRAVIS\b|process\.env\.CIRCLE\b|process\.env\.GITHUB_ACTIONS\b/gi,
    /process\.env\.npm_lifecycle_event\s*[=!]/gi,
    /process\.env\.npm_config_user_agent/gi,
  ];

  for (const regex of envPatterns) {
    for (const match of matchAllSafe(regex, source)) {
      const risk = PATTERN_WEIGHTS.environment_detection;
      findings.push({
        detector: 'tier1-self-defending',
        id: 'D18-SELF-DEFENDING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Environment detection pattern detected',
        evidence: [`pattern: environment_detection`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 5: Anti-tamper execution paths
  const antitamperPatterns = [
    /throw\s+new\s+Error.*integrity/i,
    /throw\s+new\s+Error.*modified/i,
    /throw\s+new\s+Error.*tamper/i,
  ];

  for (const regex of antitamperPatterns) {
    for (const match of matchAllSafe(regex, source)) {
      const risk = PATTERN_WEIGHTS.anti_tamper;
      findings.push({
        detector: 'tier1-self-defending',
        id: 'D18-SELF-DEFENDING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Anti-tamper logic detected',
        evidence: [`pattern: antitamper_logic`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 6: File modification detection
  const filemodPatterns = [/fs\.statSync|fs\.stat\s*\(/gi, /mtimeMs|mtime|birthtime/gi];

  for (const regex of filemodPatterns) {
    for (const match of matchAllSafe(regex, source)) {
      const risk = PATTERN_WEIGHTS.file_modification_detection;
      findings.push({
        detector: 'tier1-self-defending',
        id: 'D18-SELF-DEFENDING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'File modification detection pattern detected',
        evidence: [`pattern: file_modification_detection`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
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

  const hasPackageValidation = findings.some((f) =>
    f.evidence?.some((e) => e.includes('package_validation'))
  );
  const hasAntiTamper = findings.some((f) =>
    f.evidence?.some((e) => e.includes('antitamper_logic'))
  );
  const hasDebugger = findings.some((f) =>
    f.evidence?.some((e) => e.includes('debugger_detection'))
  );

  let recommendation = 'PASS';
  if (hasPackageValidation && hasAntiTamper) {
    recommendation = 'BLOCK - Self-defending code with integrity checks detected';
  } else if (hasDebugger && hasAntiTamper) {
    recommendation = 'BLOCK - Anti-debugging with tamper protection detected';
  } else if (hasPackageValidation) {
    recommendation = 'BLOCK - Package integrity validation detected';
  } else if (overallScore > cfg.warn_threshold) {
    recommendation = 'WARN - Self-defending/anti-analysis code patterns detected';
  }

  return [
    {
      detector: 'tier1-self-defending',
      id: 'D18-SELF-DEFENDING',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Self-Defending Code detected (aggregated risk: ${aggregatedRisk})`,
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
