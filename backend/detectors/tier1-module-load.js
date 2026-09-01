import path from 'path';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D19-MODULE-LOAD'];
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

export const name = 'tier1-module-load';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  if (!source) return [];

  const findings = [];
  let aggregatedRisk = 0;

  // Pattern 1: IIFE (Immediately Invoked Function Expression)
  const iifePatterns = [
    /\(\s*function\s*\([^)]*\)\s*\{[\s\S]*?\}\s*\)\s*\(/g,
    /\(\s*async\s+function\s*\([^)]*\)\s*\{[\s\S]*?\}\s*\)\s*\(/g,
    /\(\s*\(\s*\)\s*=>\s*\{[\s\S]*?\}\s*\)\s*\(/g,
    /\(\s*async\s*\(\s*\)\s*=>\s*\{[\s\S]*?\}\s*\)\s*\(/g,
  ];

  for (const regex of iifePatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.iife_pattern;
      findings.push({
        detector: 'tier1-module-load',
        id: 'D19-MODULE-LOAD',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'IIFE (Immediately Invoked Function Expression) detected',
        evidence: [`pattern: iife_pattern`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 2: Top-level await
  const topAwaitPatterns = [/^const\s+\w+\s*=\s*await\s+/gm];

  for (const regex of topAwaitPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.toplevel_await;
      findings.push({
        detector: 'tier1-module-load',
        id: 'D19-MODULE-LOAD',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Top-level await expression detected',
        evidence: [`pattern: toplevel_await`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 3: Module hooks (process.nextTick, setImmediate at top level)
  const hookPatterns = [/^process\.nextTick\s*\(/gm, /^setImmediate\s*\(/gm];

  for (const regex of hookPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.module_hook;
      findings.push({
        detector: 'tier1-module-load',
        id: 'D19-MODULE-LOAD',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Module hook detected (top-level timer/microtask)',
        evidence: [`pattern: module_hook`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 4: Constructor execution
  const constructorPatterns = [/new\s+\(\s*function\s*\([^)]*\)\s*\{[\s\S]*?\}\s*\)/g];

  for (const regex of constructorPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.constructor_execution;
      findings.push({
        detector: 'tier1-module-load',
        id: 'D19-MODULE-LOAD',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Constructor execution pattern detected',
        evidence: [`pattern: constructor_execution`, `match: ${match[0].slice(0, 120)}`],
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

  const hasIIFE = findings.some((f) => f.evidence?.some((e) => e.includes('iife_pattern')));
  const hasConstructor = findings.some((f) =>
    f.evidence?.some((e) => e.includes('constructor_execution'))
  );

  let recommendation = 'PASS';
  if (hasIIFE && hasConstructor) {
    recommendation = 'BLOCK - IIFE with constructor execution detected';
  } else if (hasIIFE) {
    recommendation = 'WARN - IIFE pattern detected at module load';
  } else if (overallScore > cfg.warn_threshold) {
    recommendation = 'REVIEW - Suspicious module-load execution patterns detected';
  }

  return [
    {
      detector: 'tier1-module-load',
      id: 'D19-MODULE-LOAD',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Module-Load Execution detected (aggregated risk: ${aggregatedRisk})`,
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
