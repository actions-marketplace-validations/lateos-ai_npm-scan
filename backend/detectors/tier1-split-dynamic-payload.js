import path from 'path';
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D25-SPLIT-DYNAMIC-PAYLOAD'];
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

export const name = 'tier1-split-dynamic-payload';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  if (!source) return [];

  const findings = [];
  let aggregatedRisk = 0;
  const seen = new Set();

  function tryAdd(type, patterns) {
    if (seen.has(type)) return;
    const weight = PATTERN_WEIGHTS[type];
    for (const regex of patterns) {
      for (const match of matchAllSafe(regex, source)) {
        seen.add(type);
        findings.push({
          detector: 'tier1-split-dynamic-payload',
          id: 'D25-SPLIT-DYNAMIC-PAYLOAD',
          severity: weight >= 50 ? 'high' : 'medium',
          confidence: weight >= 85 ? 'HIGH' : 'MEDIUM',
          confidenceScore: weight,
          message: `${type.replace(/_/g, ' ')} detected`,
          evidence: [`pattern: ${type}`, `match: ${match[0].slice(0, 120)}`],
          locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
        });
        aggregatedRisk += weight;
        return;
      }
    }
  }

  tryAdd('syspath_searching', [
    /sys\.path/,
    /sys\.path\.append|sys\.path\.insert/,
    /os\.path\.join.*sys\.path/,
    /__import__\s*\(/,
    /importlib\.import_module/,
  ]);

  tryAdd('dynamic_require', [
    /require\s*\(\s*\$\{|require\s*\(\s*`.*\$/,
    /require\s*\(\s*\w+\s*\+\s*['"]/,
    /require\s*\(\s*path\.join.*\)/,
    /require\.resolve\s*\(\s*\w+\s*\)/,
  ]);

  tryAdd('eval_with_fetched_code', [
    /eval\s*\(\s*fetch|eval\s*\(\s*.*http/,
    /eval\s*\(\s*fs\.readFileSync/,
    /Function\s*\(\s*fetch|Function\s*\(\s*.*http/,
    /new\s+Function\s*\(\s*['"]/,
    /eval\s*\(\s*Buffer\./,
  ]);

  tryAdd('buffer_assembly', [
    /Buffer\.concat\s*\(/,
    /\.join\s*\(\s*['"]['"]\s*\)/,
    /split\s*\(\s*['"]['"]\s*\).*join/,
    /\.flatMap\s*\(\s*Buffer/,
  ]);

  tryAdd('multifile_traversal', [
    /require\s*\(\s*['"]\.\.\//,
    /require\s*\(\s*['"]\.\./,
    /fs\.readFileSync.*\.\.\//,
  ]);

  tryAdd('obfuscated_assembly', [
    /Buffer\.from\s*\(\s*['"]/,
    /atob\s*\(/,
    /JSON\.parse\s*\(\s*JSON\.stringify\s*\(/,
    /btoa\s*\(/,
  ]);

  tryAdd('dynamic_discovery', [
    /fs\.readdirSync.*filter|fs\.readdirSync.*map/,
    /glob\s*\(|minimatch\(/,
    /walkSync\s*\(/,
    /fs\.readdirSync\s*\(\s*['"]\./,
  ]);

  tryAdd('payload_assembly_chain', [
    /fs\.readdirSync.*eval|glob.*eval|walkSync.*eval/,
    /Buffer\.concat.*eval|eval.*Buffer\.concat/,
    /require\s*\(\s*\w+.*eval\s*\(/,
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

  const hasEvalFetch = findings.some((f) =>
    f.evidence?.some((e) => e.includes('eval_with_fetched_code'))
  );
  const hasAssemblyChain = findings.some((f) =>
    f.evidence?.some((e) => e.includes('payload_assembly_chain'))
  );
  const hasSyspath = findings.some((f) => f.evidence?.some((e) => e.includes('syspath_searching')));
  const hasDynamicReq = findings.some((f) =>
    f.evidence?.some((e) => e.includes('dynamic_require'))
  );

  let recommendation = 'PASS';
  if (hasAssemblyChain) {
    recommendation = 'BLOCK - Complete payload discovery to assembly to execution chain detected';
  } else if (hasEvalFetch) {
    recommendation = 'BLOCK - Dynamic payload assembly with eval of fetched code detected';
  } else if (hasSyspath && hasDynamicReq) {
    recommendation = 'BLOCK - Python-style sys.path dynamic loading detected';
  } else if (overallScore >= cfg.flag_threshold) {
    recommendation = 'BLOCK - Split/dynamic payload assembly detected';
  } else if (overallScore >= cfg.warn_threshold) {
    recommendation = 'WARN - Dynamic code loading patterns detected';
  }

  return [
    {
      detector: 'tier1-split-dynamic-payload',
      id: 'D25-SPLIT-DYNAMIC-PAYLOAD',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Split/Dynamic Payload detected (aggregated risk: ${aggregatedRisk})`,
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
