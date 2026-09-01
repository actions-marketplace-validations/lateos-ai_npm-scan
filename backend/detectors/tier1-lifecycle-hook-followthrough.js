import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import { isObfuscated, shannonEntropy } from './lib/obfuscation-check.js';
import { extractPaasDomains, PAAS_CONFIDENCE_BOOST } from './lib/paas-domains.js';

const HOOK_NAMES = [
  'postinstall',
  'preinstall',
  'install',
  'prepare',
  'preuninstall',
  'postuninstall',
];

const HOOK_INDIRECTION_RE = /^\s*(?:node|sh|bash)\s+([^\s;&|]+)\s*$/;
const REQUIRE_RE = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const SPAWN_NODE_RE = /(?:spawn|exec|execSync)\s*\(\s*['"]node['"]\s*,\s*\[\s*['"]([^'"]+)['"]/g;
const EXEC_NODE_STR_RE = /(?:exec|execSync|spawn)\s*\(\s*['"]node\s+([^'"]+)['"]/g;
const CHILD_PROC_RE = /\b(?:exec|execSync|spawn|spawnSync|fork)\s*\(/g;
const EVAL_RE = /\beval\s*\(/g;
const FUNCTION_CTOR_RE = /\bFunction\s*\(/g;
const ZERO_EVAL_RE = /\(0,\s*eval\)\s*\(/g;
const URL_RE = /https?:\/\/([^'"\s)\]]+)/gi;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const ENV_EXFIL_RE = /process\.env\.(?:AWS_[A-Z_]+|NPM_TOKEN|NPM_AUTH_TOKEN|GIT_TOKEN|SSH_KEY)/g;
const CURL_WGET_RE = /\b(?:curl|wget|powershell)\b/i;
const HTTP_REQUEST_RE = /\b(?:https?\.request|fetch|axios|got|superagent)\s*\(/g;
const FS_READ_RE = /\bfs\.(?:readFile|readFileSync|readdir|readdirSync)\s*\(/g;
const IDENTITY_PATH_RE =
  /(?:\.gitconfig|\.ssh\/[a-zA-Z_]+\.pub|\.aws\/config|\.config\/git\/config|\.config\/gcloud\/properties|resolv\.conf|\.git\/config|\.git\/logs\/HEAD)/g;
const HOSTNAME_RE = /hostname\s*:\s*['"]([^'"]+)['"]/g;

function extractUrls(content) {
  const urls = [];
  let match;
  URL_RE.lastIndex = 0;
  while ((match = URL_RE.exec(content)) !== null) {
    urls.push(match[1]);
  }
  return urls;
}

function resolveFileFromAllFiles(relativePath, allFiles) {
  if (!allFiles || !Array.isArray(allFiles)) {
    return null;
  }
  const normalized = relativePath.replace(/^\.?\//, '');
  for (const f of allFiles) {
    const fPath = (f.path || f.name || '').replace(/^\.?\//, '');
    if (fPath === normalized || fPath.endsWith('/' + normalized) || fPath === relativePath) {
      return f;
    }
  }
  return null;
}

function getReferencedPaths(content) {
  const refs = [];
  let match;
  REQUIRE_RE.lastIndex = 0;
  while ((match = REQUIRE_RE.exec(content)) !== null) {
    const ref = match[1];
    if (ref.startsWith('.') || ref.startsWith('/')) {
      refs.push(ref.replace(/^\.?\//, ''));
    }
  }
  SPAWN_NODE_RE.lastIndex = 0;
  while ((match = SPAWN_NODE_RE.exec(content)) !== null) {
    refs.push(match[1].replace(/^\.?\//, ''));
  }
  EXEC_NODE_STR_RE.lastIndex = 0;
  while ((match = EXEC_NODE_STR_RE.exec(content)) !== null) {
    refs.push(match[1].replace(/^\.?\//, ''));
  }
  return [...new Set(refs)];
}

function analyzeContent(content) {
  const truncated = content.length > 10240 ? content.slice(0, 10240) : content;
  const obfuscated = isObfuscated(truncated);
  const hasEval =
    EVAL_RE.test(truncated) || FUNCTION_CTOR_RE.test(truncated) || ZERO_EVAL_RE.test(truncated);
  const hasChildProc = CHILD_PROC_RE.test(truncated);
  const hasCurlWget = CURL_WGET_RE.test(truncated);
  HTTP_REQUEST_RE.lastIndex = 0;
  const hasHttpRequest = HTTP_REQUEST_RE.test(truncated);
  const hasNetwork = hasCurlWget || hasChildProc || hasHttpRequest;
  const hasUrls = URL_RE.test(truncated) || IP_RE.test(truncated);
  const urls = extractUrls(truncated);
  const envExfil = ENV_EXFIL_RE.test(truncated);
  const paasDomains = extractPaasDomains(truncated);

  FS_READ_RE.lastIndex = 0;
  IDENTITY_PATH_RE.lastIndex = 0;
  const hasFsRead = FS_READ_RE.test(truncated);
  const hasIdentityPath = IDENTITY_PATH_RE.test(truncated);

  HOSTNAME_RE.lastIndex = 0;
  const hostnames = [];
  let hMatch;
  while ((hMatch = HOSTNAME_RE.exec(truncated)) !== null) {
    hostnames.push(hMatch[1]);
  }
  for (const h of hostnames) {
    const paasFromHostname = extractPaasDomains(`https://${h}/`);
    paasDomains.push(...paasFromHostname);
  }

  return {
    obfuscated,
    hasEval,
    hasNetwork,
    hasUrls,
    urls,
    envExfil,
    paasDomains: [...new Set(paasDomains)],
    truncated,
    hasFsRead,
    hasIdentityPath,
  };
}

function scoreContent(analysis) {
  const {
    obfuscated,
    hasEval,
    hasNetwork,
    hasUrls,
    envExfil,
    paasDomains,
    hasFsRead,
    hasIdentityPath,
  } = analysis;
  let baseScore = 0;
  let subtype = '';
  let severity = 'medium';

  if (hasEval || (obfuscated && hasNetwork)) {
    baseScore = 90;
    subtype = 'obfuscated_install';
    severity = 'critical';
  }

  if (hasUrls) {
    const urlBase = 70;
    if (urlBase > baseScore) {
      baseScore = urlBase;
      subtype = 'encoded_payload_postinstall';
      severity = 'high';
    }
  }

  if (envExfil) {
    if (90 > baseScore) {
      baseScore = 90;
      subtype = hasUrls ? 'hidden_preinstall' : 'encoded_payload_postinstall';
      severity = 'critical';
    }
  }

  if (hasFsRead && hasIdentityPath && hasNetwork) {
    if (85 > baseScore) {
      baseScore = 85;
      subtype = 'identity_recon_exfil';
      severity = 'high';
    }
  } else if (hasFsRead && hasIdentityPath) {
    if (75 > baseScore) {
      baseScore = 75;
      subtype = 'identity_recon_exfil';
      severity = 'high';
    }
  }

  if (hasNetwork && baseScore === 0) {
    baseScore = 65;
    subtype = 'hook_indirection';
    severity = 'medium';
  }

  if (obfuscated && hasEval && hasNetwork && !hasUrls && !envExfil) {
    if (baseScore < 90) {
      baseScore = 90;
      subtype = 'obfuscated_install';
      severity = 'critical';
    }
  }

  if (paasDomains.length > 0 && baseScore > 0) {
    baseScore = Math.min(100, baseScore + PAAS_CONFIDENCE_BOOST);
  }

  return { baseScore, subtype, severity };
}

export const name = 'tier1-lifecycle-hook-followthrough';

export async function scan(pkgJson, _jsFiles, _registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const scripts = pkgJson?.scripts || {};
  const hooks = {};

  for (const [hookName, val] of Object.entries(scripts)) {
    if (HOOK_NAMES.includes(hookName) || /^(pre|post)/.test(hookName)) {
      hooks[hookName] = val;
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

    const indirectionMatch = HOOK_INDIRECTION_RE.exec(content);
    if (!indirectionMatch) {
      continue;
    }

    const referencedPath = indirectionMatch[1];
    const resolvedFile = resolveFileFromAllFiles(referencedPath, allFiles);
    if (!resolvedFile || !resolvedFile.content) {
      continue;
    }

    const analysis = analyzeContent(resolvedFile.content);
    const { baseScore, subtype, severity } = scoreContent(analysis);

    if (baseScore === 0) {
      continue;
    }

    const evidence = [
      `hook: ${hookName}`,
      `indirection: ${content.trim()}`,
      `resolved_file: ${referencedPath}`,
    ];

    if (analysis.obfuscated) {
      const entropy = shannonEntropy(analysis.truncated);
      evidence.push(`entropy: ${entropy.toFixed(2)} (suspicious)`);
    }
    if (analysis.hasUrls && analysis.urls.length > 0) {
      evidence.push(`target: ${analysis.urls[0]}`);
    }
    if (analysis.envExfil) {
      evidence.push('pattern: process.env exfiltration');
    }
    if (analysis.hasFsRead && analysis.hasIdentityPath) {
      evidence.push('pattern: identity/credential-adjacent file read');
    }
    if (analysis.paasDomains.length > 0) {
      evidence.push(`paas_domain: ${analysis.paasDomains[0]}`);
    }

    const chainFiles = [referencedPath];
    const level1Refs = getReferencedPaths(resolvedFile.content);
    for (const ref of level1Refs) {
      const level2File = resolveFileFromAllFiles(ref, allFiles);
      if (!level2File || !level2File.content) {
        continue;
      }
      const level2Analysis = analyzeContent(level2File.content);
      const level2Score = scoreContent(level2Analysis);
      if (level2Score.baseScore > 0) {
        chainFiles.push(ref);
        evidence.push(`chain_level_2: ${ref}`);
        if (level2Analysis.paasDomains.length > 0) {
          evidence.push(`paas_domain: ${level2Analysis.paasDomains[0]}`);
        }
      }
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
      detector: 'tier1-lifecycle-hook-followthrough',
      id: 'TIER1-HOOK-FOLLOWTHROUGH',
      severity,
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype: subtype || 'hook_indirection',
      message: `Lifecycle hook "${hookName}" delegates to "${referencedPath}" which contains suspicious patterns`,
      evidence,
      locations: [
        {
          file: 'package.json',
          field: `scripts.${hookName}`,
          value: content.length > 200 ? `${content.slice(0, 200)}...` : content,
        },
        {
          file: resolvedFile.path || resolvedFile.name || referencedPath,
          field: 'content',
        },
      ],
      crossFiles: chainFiles,
      reference: 'OpenSourceMalware 2026-07-09 campaign',
    });
  }

  return findings;
}
