import path from 'path';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D17-PRIVILEGE-ESCALATION'];
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

export const name = 'tier1-privilege-escalation';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);

  const findings = [];
  let aggregatedRisk = 0;

  // Pattern 1: Capability requests (CAP_*)
  const capPatterns = [
    /\bCAP_SYS_ADMIN\b/g,
    /\bCAP_SYS_MODULE\b/g,
    /\bCAP_NET_ADMIN\b/g,
    /\bCAP_SYS_RESOURCE\b/g,
    /\bCAP_SYS_PTRACE\b/g,
    /\bcap_set_proc\b/g,
    /\bprctl\b.*\bPR_SET_KEEPCAPS\b/g,
  ];

  for (const regex of capPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.capability_request;
      findings.push({
        detector: 'tier1-privilege-escalation',
        id: 'D17-PRIVILEGE-ESCALATION',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Linux capability request detected',
        evidence: [`pattern: capability_request`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 2: Kernel exploit references (capped at 3 matches)
  const exploitPatterns = [
    /\bkernel\b.*\bexploit\b/gi,
    /\bprivilege\b.*\bescalation\b/gi,
    /\bbecome\b.*\broot\b/gi,
  ];
  let exploitMatches = 0;
  const MAX_EXPLOIT_MATCHES = 3;

  for (const regex of exploitPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null && exploitMatches < MAX_EXPLOIT_MATCHES) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.exploit_reference;
      findings.push({
        detector: 'tier1-privilege-escalation',
        id: 'D17-PRIVILEGE-ESCALATION',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Kernel exploit reference detected',
        evidence: [`pattern: exploit_reference`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
      exploitMatches++;
    }
  }

  // Pattern 3: setuid/setgid/setcap usage
  const setuidPatterns = [
    /\bsetuid\s*\(\s*0\s*\)/g,
    /\bsetgid\s*\(\s*0\s*\)/g,
    /\bsetcap\s+/g,
    /chmod.*4755|chmod.*2755/g,
    /\bsetfsgid\b|\bsetfsuid\b/g,
  ];

  for (const regex of setuidPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.setuid_attempt;
      findings.push({
        detector: 'tier1-privilege-escalation',
        id: 'D17-PRIVILEGE-ESCALATION',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'setuid/setgid privilege escalation detected',
        evidence: [`pattern: setuid_attempt`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 4: sudo/su bypass patterns
  const sudoPatterns = [/\bsudo\b.*NOPASSWD/g, /\bsudoers\b.*\bappend\b/g, /\/etc\/sudoers\b/g];

  for (const regex of sudoPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.sudo_bypass;
      findings.push({
        detector: 'tier1-privilege-escalation',
        id: 'D17-PRIVILEGE-ESCALATION',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'sudo bypass pattern detected',
        evidence: [`pattern: sudo_bypass`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 5: Kernel memory access
  const kmemPatterns = [
    /\/dev\/mem\b/g,
    /\/dev\/kmem\b/g,
    /\bmmap\b.*\bdev\/mem\b/g,
    /\bptrace\b.*\bPTRACE_PEEKDATA\b/g,
  ];

  for (const regex of kmemPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.kernel_memory_access;
      findings.push({
        detector: 'tier1-privilege-escalation',
        id: 'D17-PRIVILEGE-ESCALATION',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Kernel memory access pattern detected',
        evidence: [`pattern: kernel_memory_access`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 6: Kernel module loading
  const kmodPatterns = [
    /\binsmod\b|\bmodprobe\b/g,
    /\binit_module\b.*\bsyscall\b/g,
    /\bfinit_module\b/g,
  ];

  for (const regex of kmodPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.kernel_module_load;
      findings.push({
        detector: 'tier1-privilege-escalation',
        id: 'D17-PRIVILEGE-ESCALATION',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Kernel module loading detected',
        evidence: [`pattern: kernel_module_load`, `match: ${match[0].slice(0, 120)}`],
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

  const hasKmod = findings.some((f) => f.evidence?.some((e) => e.includes('kernel_module_load')));
  const hasPrivesc = findings.some((f) => f.evidence?.some((e) => e.includes('exploit_reference')));
  const hasSudoBypass = findings.some((f) => f.evidence?.some((e) => e.includes('sudo_bypass')));

  let recommendation = 'PASS';
  if (hasKmod && hasPrivesc) {
    recommendation = 'BLOCK - Kernel module loading with exploit reference detected';
  } else if (hasSudoBypass) {
    recommendation = 'BLOCK - Sudo bypass attempt detected';
  } else if (hasKmod) {
    recommendation = 'BLOCK - Unauthorized kernel module loading detected';
  } else if (hasPrivesc || overallScore > cfg.warn_threshold) {
    recommendation = 'WARN - Suspicious privilege escalation patterns detected';
  }

  return [
    {
      detector: 'tier1-privilege-escalation',
      id: 'D17-PRIVILEGE-ESCALATION',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Privilege Escalation detected (aggregated risk: ${aggregatedRisk})`,
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
