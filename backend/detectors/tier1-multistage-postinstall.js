const SCAN_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare'];

const REMOTE_FETCH_RE = /\b(?:fetch|axios\.get|axios\.post|http\.get|https\.get)\(|\b(?:curl|wget)\s/;
const BINARY_EXEC_RE = /\b(?:execFile|execFileSync|execSync|exec|spawnSync|spawn)\s*\(/;
const DETACHED_RE = /detached\s*:\s*true/;

function severityLabel(score) {
  if (score >= 95) return 'critical';
  if (score >= 80) return 'high';
  if (score >= 60) return 'medium';
  return 'low';
}

function confidenceLabel(score) {
  if (score >= 95) return 'CRITICAL';
  if (score >= 80) return 'HIGH';
  if (score >= 60) return 'MEDIUM';
  return 'LOW';
}

export const name = 'tier1-multistage-postinstall';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const scripts = pkgJson?.scripts;
  if (!scripts || typeof scripts !== 'object') return [];

  const findings = [];

  for (const hookName of SCAN_HOOKS) {
    const content = scripts[hookName];
    if (!content || typeof content !== 'string') continue;

    const hasRemoteFetch = REMOTE_FETCH_RE.test(content);
    const hasBinaryExec = BINARY_EXEC_RE.test(content);
    const hasDetached = DETACHED_RE.test(content);

    const signalA = hasRemoteFetch && hasBinaryExec;
    const signalB = hasDetached;

    if (!signalA && !signalB) continue;

    let confidenceScore;
    let subtype;

    if (signalA && signalB) {
      confidenceScore = 95;
      subtype = 'two_stage_plus_detached';
    } else if (signalA) {
      confidenceScore = 82;
      subtype = 'two_stage_download_exec';
    } else {
      confidenceScore = 78;
      subtype = 'detached_background_process';
    }

    const evidence = [`hook: ${hookName}`];
    if (hasRemoteFetch) evidence.push('pattern: remote fetch call');
    if (hasBinaryExec) evidence.push('pattern: binary execution call');
    if (hasDetached) evidence.push('pattern: detached background process');

    findings.push({
      detector: 'tier1-multistage-postinstall',
      id: 'TIER1-MULTISTAGE-POSTINSTALL',
      severity: severityLabel(confidenceScore),
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype,
      message: `Multi-stage install hook detected in "${hookName}" — ${subtype}`,
      evidence,
      locations: [{
        file: 'package.json',
        field: `scripts.${hookName}`,
        value: content.length > 200 ? `${content.slice(0, 200)}...` : content,
      }],
      crossFiles: [],
      reference: 'Sonatype-2026-003429',
    });
  }

  return findings;
}
