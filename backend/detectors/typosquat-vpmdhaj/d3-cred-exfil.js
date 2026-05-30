const AWS_IMDS_RE = /169\.254\.169\.254/;
const ECS_CRED_RE = /AWS_CONTAINER_AUTHORIZATION_TOKEN|AWS_CONTAINER_CREDENTIALS_FULL_URI/;
const VAULT_CRED_RE = /VAULT_ADDR|VAULT_TOKEN/;
const GITHUB_TOKEN_RE = /GITHUB_TOKEN|GH_TOKEN/;
const AWS_ACCESS_KEY_RE = /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN/;
const BASE64_OBFUSCATION_RE = /Buffer\.from\([^)]+['"]base64['"]\)|btoa\(|atob\(/;
const HTTP_POST_EXFIL_RE = /(?:fetch|axios|request|got|curl)\s*\([^)]*(?:https?:\/\/[^'"\s)\]]+)[^)]*(?:method\s*[:=]\s*['"]POST['"]|\.post\s*\()/;
const DOMAIN_EXFIL_RE = /(?:fetch|axios|request|got|curl)\s*\(['"](?:https?:\/\/)?[^'"\s)\]]*\.[^'"\s)\]]{2,}[^)]*\)/;

const TARGET_ENV_VARS = {
  AWS: ['AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_CONTAINER_AUTHORIZATION_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'],
  VAULT: ['VAULT_ADDR', 'VAULT_TOKEN'],
  GITHUB: ['GITHUB_TOKEN', 'GH_TOKEN'],
};

export function scanCredExfil(files = [], pkgJson) {
  const code = files.map(f => f.content || '').join('\n');
  if (!code) return { triggered: false, targets: [], exfilMethod: null, detectedEnvVars: [] };

  const targets = [];
  const detectedEnvVars = [];

  if (AWS_IMDS_RE.test(code)) targets.push('AWS_IMDSv2');
  if (ECS_CRED_RE.test(code)) {
    targets.push('ECS_TASK_ROLE');
    for (const v of TARGET_ENV_VARS.AWS) {
      if (code.includes(v)) detectedEnvVars.push(v);
    }
  }
  if (VAULT_CRED_RE.test(code)) {
    targets.push('VAULT_CREDENTIALS');
    for (const v of TARGET_ENV_VARS.VAULT) {
      if (code.includes(v)) detectedEnvVars.push(v);
    }
  }
  if (GITHUB_TOKEN_RE.test(code)) {
    targets.push('GITHUB_TOKEN');
    for (const v of TARGET_ENV_VARS.GITHUB) {
      if (code.includes(v)) detectedEnvVars.push(v);
    }
  }
  if (AWS_ACCESS_KEY_RE.test(code)) {
    targets.push('AWS_ACCESS_KEYS');
    for (const v of TARGET_ENV_VARS.AWS) {
      if (code.includes(v) && !detectedEnvVars.includes(v)) detectedEnvVars.push(v);
    }
  }

  if (targets.length === 0) return { triggered: false, targets: [], exfilMethod: null, detectedEnvVars: [] };

  let exfilMethod = null;
  if (HTTP_POST_EXFIL_RE.test(code)) {
    exfilMethod = 'HTTP POST to attacker domain';
  } else if (DOMAIN_EXFIL_RE.test(code)) {
    exfilMethod = 'HTTP request to external domain';
  } else if (BASE64_OBFUSCATION_RE.test(code)) {
    exfilMethod = 'Base64 obfuscation of credential strings';
  }

  return {
    triggered: true,
    targets,
    exfilMethod: exfilMethod || 'Suspicious credential access pattern',
    detectedEnvVars,
  };
}
