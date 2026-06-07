import path from 'path';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D20-PROFILING-RECON'];
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

export const name = 'tier1-profiling-recon';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  if (!source) return [];

  const findings = [];
  let aggregatedRisk = 0;

  // Pattern 1: OS/platform enumeration
  const platformPatterns = [
    /\bos\.platform\s*\(\s*\)/g,
    /\bos\.arch\s*\(\s*\)/g,
    /\bprocess\.platform\b/g,
    /\bprocess\.arch\b/g,
    /\bprocess\.version\b/g,
    /\bos\.type\s*\(\s*\)/g,
  ];

  for (const regex of platformPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.platform_enumeration;
      findings.push({
        detector: 'tier1-profiling-recon',
        id: 'D20-PROFILING-RECON',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'LOW',
        confidenceScore: risk,
        message: 'Platform enumeration detected',
        evidence: [`pattern: platform_enumeration`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 2: User/home directory enumeration
  const userPatterns = [
    /\bos\.homedir\s*\(\s*\)/g,
    /\bprocess\.env\.HOME\b|\bprocess\.env\.USERPROFILE\b|\bprocess\.env\.USERNAME\b/g,
    /\bos\.userInfo\s*\(\s*\)/g,
    /child_process\.exec.*\bwhoami\b/gi,
  ];

  for (const regex of userPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.user_enumeration;
      findings.push({
        detector: 'tier1-profiling-recon',
        id: 'D20-PROFILING-RECON',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'User/home directory enumeration detected',
        evidence: [`pattern: user_enumeration`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 3: Network/connectivity checks
  const networkPatterns = [
    /\bdns\.lookup\b|\bdns\.resolve\b/g,
    /\bsocket\.connect\b|\bnet\.connect\b/g,
  ];

  for (const regex of networkPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.network_check;
      findings.push({
        detector: 'tier1-profiling-recon',
        id: 'D20-PROFILING-RECON',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Network connectivity check detected',
        evidence: [`pattern: network_check`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 4: Cloud provider detection
  const cloudPatterns = [
    /\bprocess\.env\.AWS_REGION\b|\bprocess\.env\.GCP_PROJECT\b|\bprocess\.env\.AZURE_SUBSCRIPTION\b/g,
    /metadata\.google\.internal/g,
    /\bkubernetes\b|\bK8S\b/i,
  ];

  for (const regex of cloudPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.cloud_detection;
      findings.push({
        detector: 'tier1-profiling-recon',
        id: 'D20-PROFILING-RECON',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Cloud provider detection detected',
        evidence: [`pattern: cloud_detection`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 5: Directory scanning
  const scanPatterns = [/\bfs\.readdirSync\s*\(/g, /\bfs\.readdir\s*\(/g];

  for (const regex of scanPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.directory_scan;
      findings.push({
        detector: 'tier1-profiling-recon',
        id: 'D20-PROFILING-RECON',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Directory scanning detected',
        evidence: [`pattern: directory_scan`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 6: Installed packages/tools detection
  const toolsPatterns = [/\brequire\.resolve\s*\(/g, /\bfs\.existsSync\s*\(\s*['"].*node_modules/g];

  for (const regex of toolsPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match.index === regex.lastIndex || regex.lastIndex <= match.index) {
        regex.lastIndex = match.index + (match[0].length || 1);
      }
      const risk = PATTERN_WEIGHTS.tools_detection;
      findings.push({
        detector: 'tier1-profiling-recon',
        id: 'D20-PROFILING-RECON',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Installed tools detection detected',
        evidence: [`pattern: tools_detection`, `match: ${match[0].slice(0, 120)}`],
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

  const hasCloudDetect = findings.some((f) =>
    f.evidence?.some((e) => e.includes('cloud_detection'))
  );
  const hasDirScan = findings.some((f) => f.evidence?.some((e) => e.includes('directory_scan')));
  const hasUserEnum = findings.some((f) => f.evidence?.some((e) => e.includes('user_enumeration')));

  let recommendation = 'PASS';
  if (hasCloudDetect && (hasDirScan || hasUserEnum)) {
    recommendation = 'BLOCK - Cloud environment profiling with recon detected';
  } else if (hasCloudDetect) {
    recommendation = 'WARN - Cloud provider detection in install script';
  } else if (overallScore > cfg.warn_threshold) {
    recommendation = 'REVIEW - Profiling and reconnaissance patterns detected';
  }

  return [
    {
      detector: 'tier1-profiling-recon',
      id: 'D20-PROFILING-RECON',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Profiling & Reconnaissance detected (aggregated risk: ${aggregatedRisk})`,
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
