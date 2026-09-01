import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const HOOK_NAMES = [
  'postinstall',
  'preinstall',
  'install',
  'prepare',
  'preuninstall',
  'postuninstall',
];

const CURL_WGET_RE = /\b(?:curl|wget|powershell|bash|sh)\b/i;
const CHILD_PROC_RE = /\b(?:exec|execSync|spawn|spawnSync|fork)\s*\(/g;
const EVAL_RE = /\beval\s*\(/g;
const FUNCTION_CTOR_RE = /\bFunction\s*\(/g;
const ZERO_EVAL_RE = /\(0,\s*eval\)\s*\(/g;
const URL_RE = /https?:\/\/([^'"\s)\]]+)/gi;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const INTERNAL_DOMAIN_RE = /(?:github-ent|jira\.internal|docs\.internal)/i;
const ENV_EXFIL_RE = /process\.env\.(?:AWS_[A-Z_]+|NPM_TOKEN|NPM_AUTH_TOKEN|GIT_TOKEN|SSH_KEY)/g;
const HEX_STRING_RE = /(?:0x[0-9a-fA-F]{2,}|\\x[0-9a-fA-F]{2})/g;
const B64_RE = /['"`]([A-Za-z0-9+/]{20,}={0,2})['"`]/g;
const REQUIRE_RE = /\brequire\s*\(/g;

function shannonEntropy(s) {
  const len = s.length;
  if (len === 0) {
    return 0;
  }
  const freq = {};
  for (const ch of s) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isObfuscated(content) {
  if (!content) {
    return false;
  }
  const noWhitespace = !/\s/.test(content.trim());
  const identifiers = content.match(/\b[a-zA-Z_$][\w$]*\b/g);
  let avgIdLen = 0;
  if (identifiers && identifiers.length > 0) {
    avgIdLen = identifiers.reduce((s, id) => s + id.length, 0) / identifiers.length;
  }
  if (noWhitespace && identifiers && identifiers.length > 0 && avgIdLen < 3) {
    return true;
  }
  if (noWhitespace && /^[a-zA-Z_$][\w$]*\([^)]*\)$/.test(content.trim())) {
    return true;
  }
  HEX_STRING_RE.lastIndex = 0;
  if (HEX_STRING_RE.test(content)) {
    return true;
  }
  B64_RE.lastIndex = 0;
  if (B64_RE.test(content)) {
    return true;
  }
  if (shannonEntropy(content) > 5.5) {
    return true;
  }
  return false;
}

function extractUrls(content) {
  const urls = [];
  let match;
  URL_RE.lastIndex = 0;
  while ((match = URL_RE.exec(content)) !== null) {
    urls.push(match[1]);
  }
  return urls;
}

export const name = 'tier1-lifecycle-hook';

export async function scan(pkgJson, _jsFiles, _registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const scripts = pkgJson?.scripts || {};
  const hooks = {};

  for (const [name, val] of Object.entries(scripts)) {
    if (HOOK_NAMES.includes(name) || /^(pre|post)/.test(name)) {
      hooks[name] = val;
    }
  }

  if (Object.keys(hooks).length === 0) {
    return [];
  }

  const findings = [];

  for (const [hookName, scriptContent] of Object.entries(hooks)) {
    const content = typeof scriptContent === 'string' ? scriptContent : '';
    if (!content) {
      continue;
    }

    const truncated = content.length > 10240 ? content.slice(0, 10240) : content;

    const obfuscated = isObfuscated(truncated);
    const hasEval =
      EVAL_RE.test(truncated) || FUNCTION_CTOR_RE.test(truncated) || ZERO_EVAL_RE.test(truncated);
    const hasNetwork = CURL_WGET_RE.test(truncated) || CHILD_PROC_RE.test(truncated);
    const hasUrls = URL_RE.test(truncated) || IP_RE.test(truncated);
    const urls = extractUrls(truncated);
    const hasInternal = INTERNAL_DOMAIN_RE.test(truncated);
    const envExfil = ENV_EXFIL_RE.test(truncated);
    const silent = !REQUIRE_RE.test(truncated);

    let baseScore = 0;
    let subtype = '';
    let severity = 'medium';
    const evidence = [`hook: ${hookName}`];

    if (hasEval || (obfuscated && hasNetwork)) {
      baseScore = 90;
      subtype = 'obfuscated_install';
      severity = 'critical';
      evidence.push('patterns: eval, obfuscated code');
    }

    if (hasUrls) {
      const urlBase = hasInternal ? 90 : 70;
      if (urlBase > baseScore) {
        baseScore = urlBase;
        subtype = hasInternal ? 'obfuscated_install' : 'encoded_payload_postinstall';
        severity = hasInternal ? 'critical' : 'high';
      }
      const domainInfo = hasInternal ? 'internal domain' : 'external URL';
      evidence.push(`patterns: hardcoded ${domainInfo} in hook`);
      if (urls.length > 0) {
        evidence.push(`target: ${urls[0]}`);
      }
    }

    if (envExfil) {
      const envScore = 90;
      if (envScore > baseScore) {
        baseScore = envScore;
        subtype = hasUrls ? 'hidden_preinstall' : 'encoded_payload_postinstall';
        severity = 'critical';
      }
      evidence.push('pattern: process.env exfiltration');
    }

    if (obfuscated && hasEval && hasNetwork && !hasUrls && !envExfil) {
      if (baseScore < 90) {
        baseScore = 90;
        subtype = 'obfuscated_install';
        severity = 'critical';
      }
    }

    if (obfuscated) {
      const entropy = shannonEntropy(truncated);
      evidence.push(`entropy: ${entropy.toFixed(2)} (suspicious)`);
    }

    if (silent && baseScore >= 70) {
      subtype = 'silent_eval_in_hook';
      evidence.push('silent: no explicit require()');
      baseScore = Math.min(100, Math.round(baseScore * 2.5));
    }

    if (baseScore === 0) {
      continue;
    }

    const confidenceScore = Math.max(50, Math.min(100, baseScore));

    function confidenceLabel(score) {
      if (score >= 95) {
        return 'CRITICAL';
      }
      if (score >= 80) {
        return 'HIGH';
      }
      return 'MEDIUM';
    }

    findings.push({
      detector: 'tier1-lifecycle-hook',
      id: 'TIER1-LIFECYCLE-HOOK',
      severity,
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype,
      message: `Suspicious lifecycle hook "${hookName}"`,
      evidence,
      locations: [
        {
          file: 'package.json',
          field: `scripts.${hookName}`,
          value: content.length > 200 ? `${content.slice(0, 200)}...` : content,
        },
      ],
      crossFiles: [],
      reference: 'Campaign 1',
    });
  }

  return findings;
}
