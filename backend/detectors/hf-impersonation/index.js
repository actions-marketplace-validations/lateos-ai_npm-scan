import { KNOWN_HF_ORGS } from './known-orgs.js';
import { jaroWinkler } from './jaro-winkler.js';
import { simhash, similarity as simhashSimilarity } from './simhash.js';

const HF_URL_PATTERN = /(?:huggingface\.co|hf\.co)\/([^/\s"'>]+)\/([^/\s"'>]+)/g;
const FROM_PRETRAINED_PATTERN = /from_pretrained\(\s*["']([^"']+\/[^"']+)["']/g;
const HUB_DOWNLOAD_SINGLE = /hub\.download\(\s*["']([^"']+\/[^"']+)["']/g;
const HUB_DOWNLOAD_DOUBLE = /hub\.download\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']/g;

const LIFECYCLE_SCRIPTS = new Set(['postinstall', 'prepare', 'install']);
const API_BASE = 'https://huggingface.co';

const SEVERITY_SCORE = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const _SEVERITY_LABELS = ['none', 'low', 'medium', 'high', 'critical'];

const HF_ARTIFACT_LIBS = new Set([
  'transformers',
  'diffusers',
  'sentence-transformers',
  'gguf',
  'safetensors',
]);
const SUSPICIOUS_EXTENSIONS = /\.(exe|msi|bat|ps1|dll)$/i;

const _cache = new Map();
const CACHE_TTL = 3600 * 1000;
let _lastFetchTime = 0;

function severityIndex(sev) {
  return SEVERITY_SCORE[sev] || 0;
}

function _maxSeverity(a, b) {
  return severityIndex(a) >= severityIndex(b) ? a : b;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchWithCache(url) {
  const cached = _cache.get(url);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL) {
    return cached.data;
  }
  const now = Date.now();
  const elapsed = now - _lastFetchTime;
  if (elapsed < 100) {
    await sleep(100 - elapsed);
  }
  _lastFetchTime = Date.now();
  let res;
  try {
    res = await fetch(url);
    if (res.status === 429) {
      const retryAfter = parseInt(res.headers.get('Retry-After') || '5', 10);
      await sleep(retryAfter * 1000);
      res = await fetch(url);
    }
    if (!res.ok) {
      console.debug(`HF API warning: ${url} returned ${res.status}`);
      return null;
    }
    const data = await res.json();
    _cache.set(url, { data, fetchedAt: Date.now() });
    return data;
  } catch (err) {
    console.debug(`HF API warning: ${err.message}`);
    return null;
  }
}

async function fetchReadme(url) {
  const cached = _cache.get(url);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL) {
    return cached.data;
  }
  const now = Date.now();
  const elapsed = now - _lastFetchTime;
  if (elapsed < 100) {
    await sleep(100 - elapsed);
  }
  _lastFetchTime = Date.now();
  try {
    const res = await fetch(url);
    if (res.status === 429) {
      const retryAfter = parseInt(res.headers.get('Retry-After') || '5', 10);
      await sleep(retryAfter * 1000);
      const retryRes = await fetch(url);
      if (!retryRes.ok) {
        return null;
      }
      const text = await retryRes.text();
      _cache.set(url, { data: text, fetchedAt: Date.now() });
      return text;
    }
    if (!res.ok) {
      return null;
    }
    const text = await res.text();
    _cache.set(url, { data: text, fetchedAt: Date.now() });
    return text;
  } catch (err) {
    console.debug(`HF README warning: ${err.message}`);
    return null;
  }
}

function findClosestOrg(spoofedOrg) {
  const lowerOrg = String(spoofedOrg).toLowerCase();
  let best = { org: null, score: 0 };
  for (const known of KNOWN_HF_ORGS) {
    const score = jaroWinkler(lowerOrg, known.toLowerCase());
    if (score >= 0.82 && score > best.score) {
      best = { org: known, score };
    }
  }
  return best;
}

function extractHFTuples(pkgJson, allFiles) {
  const tuples = new Set();
  let postinstallFetchFlag = false;

  const scripts = pkgJson?.scripts || {};
  let m;
  for (const [hook, script] of Object.entries(scripts)) {
    if (typeof script !== 'string') {
      continue;
    }

    HF_URL_PATTERN.lastIndex = 0;
    while ((m = HF_URL_PATTERN.exec(script)) !== null) {
      tuples.add(`${m[1]}/${m[2]}`);
      if (LIFECYCLE_SCRIPTS.has(hook)) {
        postinstallFetchFlag = true;
      }
    }

    FROM_PRETRAINED_PATTERN.lastIndex = 0;
    while ((m = FROM_PRETRAINED_PATTERN.exec(script)) !== null) {
      tuples.add(m[1]);
      if (LIFECYCLE_SCRIPTS.has(hook)) {
        postinstallFetchFlag = true;
      }
    }

    HUB_DOWNLOAD_SINGLE.lastIndex = 0;
    while ((m = HUB_DOWNLOAD_SINGLE.exec(script)) !== null) {
      tuples.add(m[1]);
      if (LIFECYCLE_SCRIPTS.has(hook)) {
        postinstallFetchFlag = true;
      }
    }

    HUB_DOWNLOAD_DOUBLE.lastIndex = 0;
    while ((m = HUB_DOWNLOAD_DOUBLE.exec(script)) !== null) {
      tuples.add(`${m[1]}/${m[2]}`);
      if (LIFECYCLE_SCRIPTS.has(hook)) {
        postinstallFetchFlag = true;
      }
    }
  }

  if (allFiles) {
    for (const file of allFiles) {
      if (!file.path?.match(/\.(js|ts|jsx|tsx|mjs|cjs)$/i)) {
        continue;
      }
      const content = typeof file.content === 'string' ? file.content : '';

      HF_URL_PATTERN.lastIndex = 0;
      while ((m = HF_URL_PATTERN.exec(content)) !== null) {
        tuples.add(`${m[1]}/${m[2]}`);
      }

      FROM_PRETRAINED_PATTERN.lastIndex = 0;
      while ((m = FROM_PRETRAINED_PATTERN.exec(content)) !== null) {
        tuples.add(m[1]);
      }

      HUB_DOWNLOAD_SINGLE.lastIndex = 0;
      while ((m = HUB_DOWNLOAD_SINGLE.exec(content)) !== null) {
        tuples.add(m[1]);
      }

      HUB_DOWNLOAD_DOUBLE.lastIndex = 0;
      while ((m = HUB_DOWNLOAD_DOUBLE.exec(content)) !== null) {
        tuples.add(`${m[1]}/${m[2]}`);
      }
    }
  }

  return { tuples, postinstallFetchFlag };
}

function buildHFOrgSpoofFinding(
  referencedRepo,
  org,
  canonicalOrg,
  similarityScore,
  postinstallFetchFlag,
  tags,
  hfMeta
) {
  const finding = {
    id: 'HF_ORG_SPOOF',
    severity: 'high',
    title: 'HuggingFace org impersonation',
    description: `Repository "${referencedRepo}" references org "${org}" which is similar to known HF org "${canonicalOrg.org}" (similarity: ${similarityScore.toFixed(3)})`,
    evidence: JSON.stringify({
      referencedRepo,
      canonicalOrg: canonicalOrg.org,
      similarityScore,
      tags: tags || [],
    }),
    referencedRepo,
    canonicalOrg: canonicalOrg.org,
    similarityScore,
    tags: tags || [],
    ipiClass: 'SUPPLY_CHAIN',
  };
  if (hfMeta) {
    finding.hfMeta = hfMeta;
  }
  return finding;
}

async function runStage2(spoofFindings, orgsToCheck, postinstallFetchFlag) {
  const newFindings = [];

  for (const [
    referencedRepo,
    { org, canonicalOrg, similarityScore: _similarityScore, finding: _finding },
  ] of orgsToCheck) {
    const tags = [];
    let hfMeta = null;

    const modelUrl = `${API_BASE}/api/models/${referencedRepo}`;
    const canonicalUrl =
      canonicalOrg.org !== org
        ? `${API_BASE}/api/models/${canonicalOrg.org}/${referencedRepo.split('/')[1]}`
        : null;
    const userUrl = `${API_BASE}/api/users/${org}`;

    const spoofedModel = await fetchWithCache(modelUrl);
    const _canonicalModel = canonicalUrl ? await fetchWithCache(canonicalUrl) : null;
    const userData = await fetchWithCache(userUrl);

    // Org age check for NEW_ORG tag
    if (userData?.dateCreated) {
      const created = new Date(userData.dateCreated);
      const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
      hfMeta = {
        orgAgeDays: Math.round(ageDays),
        repoDownloads: spoofedModel?.downloads ?? 0,
      };
      if (ageDays < 30) {
        tags.push('NEW_ORG');
      }
    }

    // README clone check
    if (canonicalOrg.org !== org) {
      const readmeSpoof = await fetchReadme(`${API_BASE}/${referencedRepo}/resolve/main/README.md`);
      const readmeCanonical = await fetchReadme(
        `${API_BASE}/${canonicalOrg.org}/${referencedRepo.split('/')[1]}/resolve/main/README.md`
      );

      if (readmeSpoof && readmeCanonical) {
        const fp1 = simhash(readmeSpoof);
        const fp2 = simhash(readmeCanonical);
        const simScore = simhashSimilarity(fp1, fp2);

        if (simScore >= 0.9) {
          const readmeFinding = {
            id: 'HF_README_CLONE',
            severity: 'high',
            title: 'HuggingFace README clone',
            description: `README of "${referencedRepo}" is highly similar (${(simScore * 100).toFixed(1)}%) to canonical org "${canonicalOrg.org}/${referencedRepo.split('/')[1]}"`,
            evidence: JSON.stringify({
              referencedRepo,
              canonicalOrg: canonicalOrg.org,
              similarityScore: simScore,
              tags: [],
            }),
            referencedRepo,
            canonicalOrg: canonicalOrg.org,
            similarityScore: simScore,
            tags: [],
            ipiClass: 'SUPPLY_CHAIN',
          };
          if (hfMeta) {
            readmeFinding.hfMeta = hfMeta;
          }
          newFindings.push(readmeFinding);
        }
      }
    }

    // Artifact mismatch check
    if (spoofedModel?.cardData?.library_name && spoofedModel?.siblings) {
      const libName = spoofedModel.cardData.library_name;
      if (HF_ARTIFACT_LIBS.has(libName)) {
        for (const sibling of spoofedModel.siblings) {
          const fn = sibling.rfilename || '';
          if (SUSPICIOUS_EXTENSIONS.test(fn)) {
            const artifactFinding = {
              id: 'HF_ARTIFACT_MISMATCH',
              severity: 'critical',
              title: 'HF artifact mismatch — suspicious binary in model repo',
              description: `Model "${referencedRepo}" declares library "${libName}" but contains suspicious file "${fn}"`,
              evidence: JSON.stringify({
                referencedRepo,
                artifactConflict: { declaredType: libName, suspiciousFilename: fn },
                tags: [],
              }),
              referencedRepo,
              artifactConflict: { declaredType: libName, suspiciousFilename: fn },
              tags: [],
              ipiClass: 'SUPPLY_CHAIN',
            };
            if (hfMeta) {
              artifactFinding.hfMeta = hfMeta;
            }
            newFindings.push(artifactFinding);
            break;
          }
        }
      }
    }

    // Apply NEW_ORG and POSTINSTALL_FETCH tags to all findings for this repo
    const repoSpoofFindings = spoofFindings.filter((f) => f.referencedRepo === referencedRepo);
    for (const sf of repoSpoofFindings) {
      if (tags.length > 0) {
        if (!sf.tags) {
          sf.tags = [];
        }
        for (const t of tags) {
          if (!sf.tags.includes(t)) {
            sf.tags.push(t);
          }
        }
      }
      if (hfMeta) {
        sf.hfMeta = hfMeta;
      }
    }
    for (const nf of newFindings) {
      if (nf.referencedRepo === referencedRepo) {
        if (tags.length > 0) {
          if (!nf.tags) {
            nf.tags = [];
          }
          for (const t of tags) {
            if (!nf.tags.includes(t)) {
              nf.tags.push(t);
            }
          }
        }
      }
    }
  }

  // POSTINSTALL_FETCH escalation
  if (postinstallFetchFlag) {
    const allStage2Findings = [...spoofFindings, ...newFindings];
    const escalatedRepos = new Set();
    for (const f of allStage2Findings) {
      if (f.referencedRepo) {
        escalatedRepos.add(f.referencedRepo);
      }
    }
    for (const f of allStage2Findings) {
      if (escalatedRepos.has(f.referencedRepo)) {
        if (severityIndex(f.severity) < severityIndex('critical')) {
          f.severity = 'critical';
        }
        if (!f.tags) {
          f.tags = [];
        }
        if (!f.tags.includes('POSTINSTALL_ESCALATED')) {
          f.tags.push('POSTINSTALL_ESCALATED');
        }
      }
    }
  }

  return newFindings;
}

export async function scan(pkgJson, files = [], _registryMeta = null, allFiles = null) {
  const { tuples, postinstallFetchFlag } = extractHFTuples(pkgJson, allFiles || files);

  if (tuples.size === 0) {
    return [];
  }

  // Stage 1: org spoof detection (local only)
  const spoofFindings = [];
  const orgsToCheck = []; // [referencedRepo, { org, canonicalOrg, similarityScore, finding }]

  for (const tuple of tuples) {
    const parts = tuple.split('/');
    if (parts.length < 2) {
      continue;
    }
    const org = parts[0];

    const canonicalOrg = findClosestOrg(org);
    if (!canonicalOrg.org) {
      continue;
    }
    if (org.toLowerCase() === canonicalOrg.org.toLowerCase()) {
      continue;
    }

    const finding = buildHFOrgSpoofFinding(
      tuple,
      org,
      canonicalOrg,
      canonicalOrg.score,
      postinstallFetchFlag,
      []
    );
    spoofFindings.push(finding);
    orgsToCheck.push([tuple, { org, canonicalOrg, similarityScore: canonicalOrg.score, finding }]);
  }

  if (spoofFindings.length === 0) {
    return [];
  }

  // Stage 2: network checks
  const stage2Findings = await runStage2(spoofFindings, orgsToCheck, postinstallFetchFlag);

  // Deduplicate POSTINSTALL_ESCALATED tag in evidence
  for (const f of [...spoofFindings, ...stage2Findings]) {
    if (f.tags && f.tags.length > 0) {
      try {
        const ev = JSON.parse(f.evidence);
        ev.tags = [...f.tags];
        f.evidence = JSON.stringify(ev);
      } catch {
        // evidence wasn't JSON, leave as-is
      }
    }
  }

  return [...spoofFindings, ...stage2Findings];
}

export function clearCache() {
  _cache.clear();
  _lastFetchTime = 0;
}

export { KNOWN_HF_ORGS, jaroWinkler, simhash, simhashSimilarity };
