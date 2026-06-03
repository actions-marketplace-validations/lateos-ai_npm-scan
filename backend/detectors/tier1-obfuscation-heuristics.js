import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import { shannonEntropy, isMinified } from './lib/entropy-analyzer.js';
import { detectPatterns } from './lib/ast-patterns.js';

const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];
const ENTROPY_THRESHOLD = 5.3;
const PAYLOAD_SIZE_THRESHOLD = 100000;

function analyze(code, label) {
  if (!code || code.length < 20) return null;

  const entropy = shannonEntropy(code);
  const patterns = detectPatterns(code);
  const minified = isMinified(code);
  const payloadSize = code.length;

  let score = 0;
  let flags = [];

  if (entropy > ENTROPY_THRESHOLD) {
    score += 35;
    flags.push(`Entropy ${entropy} exceeds threshold ${ENTROPY_THRESHOLD}`);
  }

  if (entropy > 5.8) {
    score += 15;
    flags.push(`High entropy ${entropy} — strong obfuscation indicator`);
  }

  const patternCount = patterns.length;
  if (patternCount >= 3) {
    score += 30;
    flags.push(`${patternCount} obfuscation patterns detected`);
  } else if (patternCount >= 1) {
    score += 20;
    flags.push(`${patternCount} obfuscation patterns detected`);
  }

  if (minified) {
    score += 10;
    flags.push('Minified code — reduced readability');
  }

  if (payloadSize > PAYLOAD_SIZE_THRESHOLD) {
    score += 15;
    flags.push(`Payload size ${payloadSize} bytes exceeds ${PAYLOAD_SIZE_THRESHOLD} byte threshold`);
  }

  if (patterns.includes('XOR_CIPHER') && patterns.length >= 2) {
    score += 10;
    flags.push('ctf-scramble-v2 style XOR cipher detected');
  }

  if (patterns.includes('EVAL_USAGE') && entropy > 5.0) {
    score += 15;
    flags.push('eval() with high-entropy code');
  }

  score = Math.max(0, Math.min(100, score));

  if (score < 40) return null;

  return {
    flagged: true,
    confidenceScore: score,
    confidence: score >= 80 ? 'HIGH' : score >= 60 ? 'MEDIUM' : 'LOW',
    entropy,
    patterns,
    patternCount,
    payloadSize,
    flags,
  };
}

function severityLabel(sc) {
  if (sc >= 90) return 'critical';
  if (sc >= 70) return 'high';
  if (sc >= 50) return 'medium';
  return 'low';
}

function confidenceLabel(sc) {
  if (sc >= 80) return 'HIGH';
  if (sc >= 60) return 'MEDIUM';
  return 'LOW';
}

export const name = 'tier1-obfuscation-heuristics';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const findings = [];
  const scripts = pkgJson?.scripts || {};

  for (const [hookName, scriptContent] of Object.entries(scripts)) {
    if (!LIFECYCLE_SCRIPTS.includes(hookName)) continue;
    const result = analyze(scriptContent, hookName);
    if (!result) continue;

    findings.push({
      detector: 'tier1-obfuscation-heuristics',
      id: 'TIER1-OBFUSCATION-HEURISTICS',
      severity: severityLabel(result.confidenceScore),
      confidence: confidenceLabel(result.confidenceScore),
      confidenceScore: result.confidenceScore,
      subtype: 'obfuscated_lifecycle_script',
      message: `Obfuscation detected in ${hookName} script: ${result.flags[0] || 'obfuscation patterns found'}`,
      evidence: [
        `script: ${hookName}`,
        `entropy: ${result.entropy}`,
        `patterns: ${result.patterns.join(', ') || 'none'}`,
        `pattern_count: ${result.patternCount}`,
        `payload_size_bytes: ${result.payloadSize}`,
        ...result.flags,
      ],
      crossFiles: [],
      locations: [{ file: 'package.json', line: 3, column: 10 }],
      reference: 'Mini Shai-Hulud obfuscation campaign',
    });
  }

  for (const f of jsFiles || []) {
    const content = f.content || '';
    if (content.length < 100) continue;

    const result = analyze(content, f.path || 'unknown.js');
    if (!result) continue;

    if (result.confidenceScore < 50) continue;

    findings.push({
      detector: 'tier1-obfuscation-heuristics',
      id: 'TIER1-OBFUSCATION-HEURISTICS',
      severity: severityLabel(result.confidenceScore),
      confidence: confidenceLabel(result.confidenceScore),
      confidenceScore: result.confidenceScore,
      subtype: 'obfuscated_js_file',
      message: `Obfuscation detected in ${f.path || 'file'}: ${result.flags[0] || 'obfuscation patterns found'}`,
      evidence: [
        `file: ${f.path || 'unknown.js'}`,
        `entropy: ${result.entropy}`,
        `patterns: ${result.patterns.join(', ') || 'none'}`,
        `pattern_count: ${result.patternCount}`,
        `payload_size_bytes: ${result.payloadSize}`,
        ...result.flags,
      ],
      crossFiles: [],
      locations: [{ file: f.path || 'unknown.js', line: 0, column: 0 }],
      reference: 'Mini Shai-Hulud obfuscation campaign',
    });
  }

  return findings;
}
