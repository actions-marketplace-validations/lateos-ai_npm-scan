import path from 'path';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D21-SELF-CLEANING'];
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

export const name = 'tier1-self-cleaning';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  if (!source) return [];

  const findings = [];
  let aggregatedRisk = 0;

  // Pattern 1: Self-deletion via fs.unlink
  const unlinkPatterns = [
    /\bfs\.unlink\s*\(\s*__filename/gi,
    /\bfs\.unlinkSync\s*\(\s*__filename/gi,
    /\bfs\.unlink\s*\(\s*module\.filename/gi,
    /\bfs\.unlinkSync\s*\(\s*module\.filename/gi,
  ];

  for (const regex of unlinkPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.self_deletion;
      findings.push({
        detector: 'tier1-self-cleaning',
        id: 'D21-SELF-CLEANING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Self-deletion via fs.unlink detected',
        evidence: [`pattern: self_deletion`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 2: Package.json manipulation
  const pjsonPatterns = [
    /\bfs\.writeFileSync.*package\.json/gi,
    /\bfs\.writeFile\s*\(\s*['"]package\.json/gi,
    /delete\s+.*scripts\.postinstall|delete\s+.*scripts\.preinstall/gi,
  ];

  for (const regex of pjsonPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.package_json_manipulation;
      findings.push({
        detector: 'tier1-self-cleaning',
        id: 'D21-SELF-CLEANING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Package.json manipulation detected',
        evidence: [`pattern: package_json_manipulation`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 3: File replacement/swapping
  const swapPatterns = [
    /\bfs\.renameSync|\bfs\.rename\s*\(/gi,
    /\bfs\.copyFileSync|\bfs\.copyFile\s*\(/gi,
  ];

  for (const regex of swapPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.file_swap;
      findings.push({
        detector: 'tier1-self-cleaning',
        id: 'D21-SELF-CLEANING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'File replacement/swapping detected',
        evidence: [`pattern: file_swap`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 4: Log/cache clearing
  const clearPatterns = [
    /\bfs\.rmSync|\bfs\.rmdirSync/gi,
    /\bfs\.unlink.*\.log|\bfs\.unlink.*\.cache|\bfs\.unlink.*\.tmp/gi,
  ];

  for (const regex of clearPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.log_cache_clear;
      findings.push({
        detector: 'tier1-self-cleaning',
        id: 'D21-SELF-CLEANING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Log/cache clearing detected',
        evidence: [`pattern: log_cache_clear`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 5: Git history removal
  const gitPatterns = [
    /child_process\.exec.*git\s+reset|child_process\.exec.*git\s+clean/gi,
    /child_process\.exec.*rm\s+-rf\s+\.git/gi,
  ];

  for (const regex of gitPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.git_history_removal;
      findings.push({
        detector: 'tier1-self-cleaning',
        id: 'D21-SELF-CLEANING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Git history removal detected',
        evidence: [`pattern: git_history_removal`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 6: Timestamp manipulation
  const timestampPatterns = [/\bfs\.utimesSync|\bfs\.utimes\s*\(/gi];

  for (const regex of timestampPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.timestamp_manipulation;
      findings.push({
        detector: 'tier1-self-cleaning',
        id: 'D21-SELF-CLEANING',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Timestamp manipulation detected',
        evidence: [`pattern: timestamp_manipulation`, `match: ${match[0].slice(0, 120)}`],
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

  const hasSelfDelete = findings.some((f) => f.evidence?.some((e) => e.includes('self_deletion')));
  const hasPjsonManip = findings.some((f) =>
    f.evidence?.some((e) => e.includes('package_json_manipulation'))
  );
  const hasGitRemoval = findings.some((f) =>
    f.evidence?.some((e) => e.includes('git_history_removal'))
  );

  let recommendation = 'PASS';
  if (hasSelfDelete && hasPjsonManip) {
    recommendation = 'BLOCK - Self-deletion with package.json manipulation detected';
  } else if (hasSelfDelete) {
    recommendation = 'BLOCK - Self-deletion after execution detected';
  } else if (hasPjsonManip) {
    recommendation = 'BLOCK - Package.json manipulation to remove traces detected';
  } else if (hasGitRemoval) {
    recommendation = 'WARN - Git history removal detected';
  } else if (overallScore > cfg.warn_threshold) {
    recommendation = 'REVIEW - Evidence removal patterns detected';
  }

  return [
    {
      detector: 'tier1-self-cleaning',
      id: 'D21-SELF-CLEANING',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Self-Cleaning Code detected (aggregated risk: ${aggregatedRisk})`,
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
