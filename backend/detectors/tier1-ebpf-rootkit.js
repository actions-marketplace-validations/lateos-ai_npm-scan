import path from 'path';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D16-EBPF-ROOTKIT'];
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

export const name = 'tier1-ebpf-rootkit';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  const postinstallScript = pkgJson?.scripts?.postinstall || pkgJson?.scripts?.install || '';
  const binaryContent = source;

  const findings = [];
  let aggregatedRisk = 0;

  // Pattern 1: eBPF bytecode / references
  const ebpfPatterns = [
    /eBPF/g,
    /bpf\s*\(/g,
    /BPF_PROG_LOAD/g,
    /BPF_MAP_CREATE/g,
    /BPF_PROG_ATTACH/g,
    /bpf_prog_get|bpf_map_get/g,
  ];

  for (const regex of ebpfPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.ebpf_bytecode;
      findings.push({
        detector: 'tier1-ebpf-rootkit',
        id: 'D16-EBPF-ROOTKIT',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'eBPF bytecode or bpf syscall reference detected',
        evidence: [`pattern: ebpf_bytecode`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: binaryContent ? 'binary' : 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 2: bpf() syscall in postinstall / source
  const bpfPatterns = [
    /bpf\s*\(/g,
    /BPF_PROG_LOAD/g,
    /BPF_MAP_CREATE/g,
    /BPF_PROG_ATTACH/g,
    /bpf_prog_get|bpf_map_get/g,
  ];

  for (const regex of bpfPatterns) {
    regex.lastIndex = 0;
    const text = postinstallScript;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const risk = PATTERN_WEIGHTS.bpf_syscall;
      findings.push({
        detector: 'tier1-ebpf-rootkit',
        id: 'D16-EBPF-ROOTKIT',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'bpf syscall usage in postinstall script',
        evidence: [`pattern: bpf_syscall`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'postinstall', line: 1 }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 3: Kernel hook patterns
  const hookPatterns = [
    /\bkprobes\//g,
    /\btracepoints?\//g,
    /\bsys_enter\b|\bsys_exit\b/g,
    /\bBPF_KPROBE\b/g,
    /\btracepoint__sys_/g,
  ];

  for (const regex of hookPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.kernel_hook;
      findings.push({
        detector: 'tier1-ebpf-rootkit',
        id: 'D16-EBPF-ROOTKIT',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Kernel hook pattern detected',
        evidence: [`pattern: kernel_hook`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 4: Syscall hooking specifics
  const syscallPatterns = [
    /\bsys_open\b|\bsys_openat\b/g,
    /\bsys_write\b|\bsys_writev\b/g,
    /\bsys_read\b|\bsys_readv\b/g,
    /\bsys_connect\b|\bsys_sendto\b/g,
    /\bsys_execve\b|\bsys_fork\b/g,
  ];

  for (const regex of syscallPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.syscall_hook;
      findings.push({
        detector: 'tier1-ebpf-rootkit',
        id: 'D16-EBPF-ROOTKIT',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'HIGH',
        confidenceScore: risk,
        message: 'Syscall hook pattern detected',
        evidence: [`pattern: syscall_hook`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 5: Process/file/network hiding intent
  const hidingPatterns = [
    /\brootkit\b/gi,
    /\bhide\s*_\s*(process|file|network)\b/gi,
    /\bkernel\s+hook\b/gi,
  ];

  for (const regex of hidingPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.hiding_intent;
      findings.push({
        detector: 'tier1-ebpf-rootkit',
        id: 'D16-EBPF-ROOTKIT',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Process/file/network hiding intent detected',
        evidence: [`pattern: hiding_intent`, `match: ${match[0].slice(0, 120)}`],
        locations: [{ file: 'install.js', line }],
      });
      aggregatedRisk += risk;
    }
  }

  // Pattern 6: Rust/C FFI for kernel interaction
  const ffiPatterns = [/extern\s+"C"\s*\{/g, /libc::/g];

  for (const regex of ffiPatterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(source)) !== null) {
      const line = extractLines(source, match.index);
      const risk = PATTERN_WEIGHTS.kernel_ffi;
      findings.push({
        detector: 'tier1-ebpf-rootkit',
        id: 'D16-EBPF-ROOTKIT',
        severity: risk >= 50 ? 'high' : 'medium',
        confidence: 'MEDIUM',
        confidenceScore: risk,
        message: 'Kernel FFI pattern detected (Rust/C unsafe)',
        evidence: [`pattern: kernel_ffi`, `match: ${match[0].slice(0, 120)}`],
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

  const hasSyscallHook = findings.some((f) => f.evidence?.some((e) => e.includes('syscall_hook')));
  const hasKernelHook = findings.some((f) => f.evidence?.some((e) => e.includes('kernel_hook')));
  const hasBpf = findings.some((f) =>
    f.evidence?.some((e) => e.includes('bpf_syscall') || e.includes('ebpf_bytecode'))
  );
  const hasHiding = findings.some((f) => f.evidence?.some((e) => e.includes('hiding_intent')));

  let recommendation = 'PASS';
  if ((hasSyscallHook || hasKernelHook) && hasBpf) {
    recommendation = 'BLOCK - eBPF rootkit with kernel hooks + bpf syscalls detected';
  } else if (hasHiding && hasBpf) {
    recommendation = 'BLOCK - eBPF rootkit with hiding intent detected';
  } else if (hasSyscallHook || hasKernelHook) {
    recommendation = 'WARN - Kernel hook patterns detected without bpf syscall';
  } else if (overallScore > cfg.warn_threshold) {
    recommendation = 'REVIEW - Suspicious eBPF/kernel patterns detected';
  }

  return [
    {
      detector: 'tier1-ebpf-rootkit',
      id: 'D16-EBPF-ROOTKIT',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `eBPF Rootkit detected (aggregated risk: ${aggregatedRisk})`,
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
