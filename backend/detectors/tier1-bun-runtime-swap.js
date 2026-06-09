import path from 'path';
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D24-BUN-RUNTIME-SWAP'];
const PATTERN_WEIGHTS = cfg.pattern_weights;

const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts']);

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

function scanScripts(scripts) {
  if (!scripts) return '';
  return Object.values(scripts).filter(Boolean).join('\n');
}

export const name = 'tier1-bun-runtime-swap';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  const scriptSource = scanScripts(pkgJson?.scripts);
  const combinedSource = [source, scriptSource].filter(Boolean).join('\n');
  if (!combinedSource) return [];

  const findings = [];
  let aggregatedRisk = 0;
  const seen = new Set();

  function tryAdd(type, patterns) {
    if (seen.has(type)) return;
    const weight = PATTERN_WEIGHTS[type];
    for (const regex of patterns) {
      for (const match of matchAllSafe(regex, combinedSource)) {
        seen.add(type);
        findings.push({
          detector: 'tier1-bun-runtime-swap',
          id: 'D24-BUN-RUNTIME-SWAP',
          severity: weight >= 50 ? 'high' : 'medium',
          confidence: weight >= 85 ? 'HIGH' : 'MEDIUM',
          confidenceScore: weight,
          message: `${type.replace(/_/g, ' ')} detected`,
          evidence: [`pattern: ${type}`, `match: ${match[0].slice(0, 120)}`],
          locations: [{ file: 'install.js', line: extractLines(combinedSource, match.index) }],
        });
        aggregatedRisk += weight;
        return;
      }
    }
  }

  tryAdd('bun_binary_execution', [
    /bun\s+run(?!\s+test)/,
    /bun\s+execute/,
    /spawn.*['"]bun['"]/,
    /child_process\.spawn\s*\(\s*['"]bun['"]/,
    /child_process\.exec\s*\(\s*['"]bun/,
    /require\s*\(\s*['"]bun['"]\)/,
  ]);

  tryAdd('bun_api_usage', [
    /Bun\.serve\s*\(/,
    /Bun\.file\s*\(/,
    /Bun\.write\s*\(/,
    /Bun\.spawn\s*\(/,
    /Bun\.shell\s*\(/,
    /import\s+Bun\s+from\s+['"]bun['"]/,
  ]);

  tryAdd('process_argv_swap', [
    /process\.argv\[0\].*=.*bun/,
    /process\.mainModule.*bun/,
    /process\.execPath.*bun/,
  ]);

  tryAdd('bun_downloader', [
    /curl.*https:\/\/bun\.sh/,
    /wget.*https:\/\/bun\.sh/,
    /fetch.*https:\/\/github\.com\/oven-sh\/bun.*releases/,
    /download.*bun.*binary|install.*bun.*runtime/i,
  ]);

  tryAdd('bun_credential_combo', [
    /bun\s+run.*AWS|bun\s+run.*GITHUB|bun\s+run.*fetch.*env/,
    /Bun\.spawn.*AWS|Bun\.spawn.*credential|Bun\.spawn.*token/i,
  ]);

  tryAdd('node_to_bun_swap', [
    /child_process\.spawn.*node.*bun/,
    /spawn.*node.*then.*bun/,
    /spawn\s*\(\s*['"]node['"].*['"]bun['"]/,
  ]);

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

  const hasDownloader = findings.some((f) => f.evidence?.some((e) => e.includes('bun_downloader')));
  const hasCredCombo = findings.some((f) =>
    f.evidence?.some((e) => e.includes('bun_credential_combo'))
  );
  const hasExec = findings.some((f) => f.evidence?.some((e) => e.includes('bun_binary_execution')));
  const hasSwap = findings.some((f) => f.evidence?.some((e) => e.includes('node_to_bun_swap')));

  let recommendation = 'PASS';
  if (hasCredCombo) {
    recommendation = 'BLOCK - Bun execution with credential access (evasion attack)';
  } else if (hasDownloader) {
    recommendation = 'BLOCK - Bun runtime downloader detected';
  } else if (hasExec && hasSwap) {
    recommendation = 'BLOCK - Node.js to Bun runtime swap detected';
  } else if (hasExec) {
    recommendation = 'BLOCK - Bun binary execution (bypasses Node monitoring)';
  } else if (overallScore >= cfg.warn_threshold) {
    recommendation = 'WARN - Bun runtime usage detected';
  }

  return [
    {
      detector: 'tier1-bun-runtime-swap',
      id: 'D24-BUN-RUNTIME-SWAP',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Bun Runtime Swap detected (aggregated risk: ${aggregatedRisk})`,
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
