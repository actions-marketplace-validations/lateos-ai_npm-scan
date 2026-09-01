/**
 * Tarball-to-Git commit differential validator.
 *
 * The gap this closes: npm provenance binds an attestation to a *tarball*, and
 * never binds the tarball to its *source*. A package built by CI from a dirty
 * working tree — a patch that exists in no commit — produces a genuine
 * attestation whose subject digest matches perfectly, so the scanner reported
 * `digestBound: true`, `claimsMatchRepo: true`, `error: null` and a single
 * informational finding (gap-analysis finding G2.1).
 *
 * This module answers the question provenance cannot: does the code that
 * shipped correspond to a commit? It is deliberately independent of
 * attestation state — per the requirement, a desync is reported *regardless of
 * OIDC provenance validity*, because valid provenance over tampered output is
 * exactly the attack.
 *
 * Cost control: this is the only network-bound check in the detector suite, so
 * it is opt-in (`enabled: false` by default) and short-circuits before any I/O
 * when disabled. The source provider is injectable so tests stay hermetic.
 */
import crypto from 'crypto';
import zlib from 'zlib';
import { Readable } from 'stream';
import { pipeline } from 'stream/promises';
import { Parser } from 'tar';
import * as walk from 'acorn-walk';
import { parseSource } from '../detectors/lib/ast-parse.js';
import {
  CAPABILITY,
  buildRuntimeIndex,
  classifyNode,
} from '../detectors/lib/runtime-primitives.js';

export const ERR_TARBALL_GIT_DESYNC = 'ERR_TARBALL_GIT_DESYNC';

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_SOURCE_BYTES = 80 * 1024 * 1024;
const MAX_ENTRY_BYTES = 512000;

/**
 * Directories whose contents are normally build output and legitimately absent
 * from git. Files here are *skipped*, not treated as clean — the result
 * reports the skip count so a caller can tell "verified" from "not checked".
 */
const GENERATED_DIRS = [
  'dist/',
  'build/',
  'out/',
  'es/',
  'esm/',
  'cjs/',
  'umd/',
  'types/',
  'coverage/',
  'node_modules/',
];

const GENERATED_FILE_RE = /(?:\.min\.js|\.map|\.d\.ts|\.tsbuildinfo)$/i;

/** Files never worth diffing: metadata npm rewrites, or docs. */
const IGNORED_BASENAMES = new Set([
  'package.json',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'readme.md',
  'readme',
  'license',
  'license.md',
  'licence',
  'changelog.md',
  '.npmignore',
  '.gitignore',
]);

const SENSITIVE_CAPABILITIES = new Set([
  CAPABILITY.EXEC,
  CAPABILITY.FFI,
  CAPABILITY.NET_CONNECT,
  CAPABILITY.FS_WRITE,
]);

const SCRIPT_EXT_RE = /\.(?:js|mjs|cjs|ts|mts|cts|sh|bash|ps1)$/i;

/* ------------------------------------------------------------------ *
 * path + content normalization                                        *
 * ------------------------------------------------------------------ */

/**
 * npm tarballs root everything at `package/`; GitHub source archives root at
 * `<repo>-<ref>/`. Strip one leading segment from each so paths are comparable.
 */
export function normalizeEntryPath(entryPath, { stripRoot = true } = {}) {
  let p = String(entryPath || '')
    .replace(/\\/g, '/')
    .replace(/^\.\//, '');
  if (stripRoot) {
    const slash = p.indexOf('/');
    if (slash > -1) {
      p = p.slice(slash + 1);
    }
  }
  return p.replace(/^\/+/, '');
}

/** Line-ending and trailing-whitespace insensitive hash. */
export function contentHash(content) {
  const normalized = String(content ?? '')
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+$/gm, '')
    .replace(/\n+$/, '');
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

function isGenerated(p) {
  const lower = p.toLowerCase();
  return (
    GENERATED_DIRS.some((d) => lower.startsWith(d) || lower.includes('/' + d)) ||
    GENERATED_FILE_RE.test(lower)
  );
}

function isIgnored(p) {
  const base = p.split('/').pop().toLowerCase();
  return IGNORED_BASENAMES.has(base);
}

/* ------------------------------------------------------------------ *
 * source reference resolution                                         *
 * ------------------------------------------------------------------ */

/**
 * Parse a repository field into host/owner/repo. Handles the shorthand and
 * URL forms npm accepts.
 */
export function parseRepository(repository) {
  if (!repository) {
    return null;
  }
  const raw = typeof repository === 'string' ? repository : repository.url || '';
  if (!raw) {
    return null;
  }
  let s = String(raw)
    .trim()
    .replace(/^git\+/, '')
    .replace(/^git@([^:/]+):/, 'https://$1/')
    .replace(/^(?:git|ssh):\/\/(?:git@)?/, 'https://')
    .replace(/\.git$/, '')
    .replace(/\/+$/, '');

  // bare "owner/repo" shorthand
  if (/^[\w.-]+\/[\w.-]+$/.test(s)) {
    s = `https://github.com/${s}`;
  }

  let url;
  try {
    url = new URL(s);
  } catch {
    return null;
  }
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 2) {
    return null;
  }
  return {
    host: url.hostname.toLowerCase(),
    owner: parts[0],
    repo: parts[1],
    url: `https://${url.hostname}/${parts[0]}/${parts[1]}`,
  };
}

/**
 * Candidate refs to try, most authoritative first:
 *   1. the commit the attestation says CI built
 *   2. the commit the publisher declared (`gitHead`)
 *   3. conventional release tags for the version
 */
export function candidateRefs(pkgJson, registryMeta, provenance) {
  const refs = [];
  const push = (value, source) => {
    if (value && !refs.some((r) => r.ref === value)) {
      refs.push({ ref: String(value), source });
    }
  };

  push(provenance?.sourceCommit, 'attestation_git_commit');
  push(registryMeta?.gitHead, 'registry_git_head');

  const version = pkgJson?.version || registryMeta?.version;
  if (version) {
    push(`v${version}`, 'version_tag');
    push(`${version}`, 'version_tag');
    const name = String(pkgJson?.name || '')
      .split('/')
      .pop();
    if (name) {
      push(`${name}@${version}`, 'monorepo_tag');
      push(`${name}-v${version}`, 'monorepo_tag');
    }
  }
  return refs;
}

/* ------------------------------------------------------------------ *
 * default source provider (GitHub codeload)                           *
 * ------------------------------------------------------------------ */

async function readTarGzToMap(buffer) {
  const files = new Map();
  const parser = new Parser({
    onReadEntry(entry) {
      if (entry.type !== 'File') {
        entry.resume();
        return;
      }
      const chunks = [];
      let size = 0;
      let truncated = false;
      entry.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_ENTRY_BYTES) {
          truncated = true;
          return;
        }
        chunks.push(chunk);
      });
      entry.on('end', () => {
        if (truncated) {
          return;
        }
        const p = normalizeEntryPath(entry.path);
        if (p) {
          files.set(p, Buffer.concat(chunks).toString('utf8'));
        }
      });
    },
  });

  await pipeline(Readable.from(buffer), zlib.createGunzip(), parser);
  return files;
}

/**
 * Fetch a repository tree from GitHub. Returns null when the ref does not
 * exist or the host is not GitHub — callers treat null as "unverifiable",
 * never as "clean".
 */
export function createGitHubSourceProvider(options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = options.fetch || globalThis.fetch;

  return async function githubSourceProvider({ host, owner, repo, ref }) {
    if (host !== 'github.com') {
      return null;
    }
    const url = `https://codeload.github.com/${encodeURIComponent(owner)}/${encodeURIComponent(
      repo
    )}/tar.gz/${encodeURIComponent(ref)}`;
    try {
      const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
      if (!res.ok) {
        return null;
      }
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > MAX_SOURCE_BYTES) {
        return null;
      }
      return await readTarGzToMap(buf);
    } catch {
      return null;
    }
  };
}

/* ------------------------------------------------------------------ *
 * sensitive-node extraction                                           *
 * ------------------------------------------------------------------ */

/**
 * Capability-bearing nodes in a source file. Used both to decide whether a
 * file is worth diffing and to describe what a desync actually introduced.
 */
export function sensitiveNodes(content) {
  const parsed = parseSource(content);
  if (!parsed.ast) {
    return [];
  }
  const index = buildRuntimeIndex(parsed.ast);
  const found = new Map();
  walk.full(parsed.ast, (node) => {
    const hit = classifyNode(node, index);
    if (hit && SENSITIVE_CAPABILITIES.has(hit.capability)) {
      const key = `${hit.runtime}:${hit.capability}:${hit.path}`;
      if (!found.has(key)) {
        found.set(key, { runtime: hit.runtime, capability: hit.capability, path: hit.path });
      }
    }
  });
  return [...found.values()];
}

/** Files a lifecycle hook or a bin entry executes. */
function executableTargets(pkgJson) {
  const targets = new Set();
  const add = (v) => {
    if (typeof v === 'string' && v) {
      targets.add(normalizeEntryPath(v, { stripRoot: false }).replace(/^\.\//, ''));
    }
  };
  if (typeof pkgJson?.bin === 'string') {
    add(pkgJson.bin);
  } else if (pkgJson?.bin && typeof pkgJson.bin === 'object') {
    Object.values(pkgJson.bin).forEach(add);
  }
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish']) {
    const script = pkgJson?.scripts?.[hook];
    if (typeof script !== 'string') {
      continue;
    }
    const re = /(?:^|[\s;&|])(?:node|nodejs|sh|bash|bun|deno|qjs)\s+([^\s;&|'"]+)/g;
    let m;
    while ((m = re.exec(script)) !== null) {
      add(m[1]);
    }
  }
  return targets;
}

/* ------------------------------------------------------------------ *
 * main comparison                                                     *
 * ------------------------------------------------------------------ */

/**
 * Compare a published tarball's file tree against its Git source tree.
 *
 * @param {object} pkgJson   manifest from inside the tarball
 * @param {Array}  files     [{ path, content }] from the tarball
 * @param {object} registryMeta
 * @param {object} [options]
 * @param {boolean} [options.enabled=false]
 * @param {Function} [options.sourceProvider] async ({host,owner,repo,ref}) => Map|null
 * @param {object} [options.provenance] optional { sourceCommit } hint
 * @returns {Promise<{status:string, findings:Array, compared:number, skipped:number, source:object|null, reason:string|null}>}
 */
export async function compareTarballToGit(pkgJson, files, registryMeta, options = {}) {
  const result = {
    status: 'unverifiable',
    findings: [],
    compared: 0,
    skipped: 0,
    source: null,
    reason: null,
  };

  if (options.enabled !== true) {
    result.reason = 'disabled';
    return result;
  }

  const repoInfo = parseRepository(pkgJson?.repository || registryMeta?.repository);
  if (!repoInfo) {
    result.reason = 'no_repository_declared';
    return result;
  }

  const provider = options.sourceProvider || createGitHubSourceProvider(options);
  const refs = candidateRefs(pkgJson, registryMeta, options.provenance);
  if (refs.length === 0) {
    result.reason = 'no_candidate_refs';
    return result;
  }

  let sourceFiles = null;
  let usedRef = null;
  for (const candidate of refs) {
    const tree = await provider({ ...repoInfo, ref: candidate.ref });
    if (tree && tree.size > 0) {
      sourceFiles = tree;
      usedRef = candidate;
      break;
    }
  }

  if (!sourceFiles) {
    result.reason = 'source_unavailable';
    return result;
  }

  result.source = {
    ...repoInfo,
    ref: usedRef.ref,
    refSource: usedRef.source,
    files: sourceFiles.size,
  };

  const execTargets = executableTargets(pkgJson);
  const desyncs = [];

  for (const file of files || []) {
    const rawPath = file.path || file.name || '';
    const relPath = normalizeEntryPath(rawPath, { stripRoot: options.stripTarballRoot !== false });
    if (!relPath || isIgnored(relPath)) {
      continue;
    }

    const isExecutable = execTargets.has(relPath) || SCRIPT_EXT_RE.test(relPath);
    if (!isExecutable) {
      continue;
    }

    if (isGenerated(relPath)) {
      result.skipped++;
      continue;
    }

    const sourceContent = sourceFiles.get(relPath);
    const tarballSensitive = sensitiveNodes(file.content || '');

    if (sourceContent === undefined) {
      // Absent from source entirely.
      const declaredExecutable = execTargets.has(relPath);
      if (declaredExecutable || tarballSensitive.length > 0) {
        desyncs.push({
          kind: 'absent_from_source',
          path: relPath,
          severity: 'critical',
          capabilities: tarballSensitive,
          detail: declaredExecutable
            ? `executable script "${relPath}" is present in the tarball but absent from ${usedRef.ref}`
            : `"${relPath}" carries ${tarballSensitive.map((c) => c.capability).join('/')} code but is absent from ${usedRef.ref}`,
        });
      } else {
        result.skipped++;
      }
      continue;
    }

    result.compared++;

    if (contentHash(sourceContent) === contentHash(file.content || '')) {
      continue;
    }

    // Content differs. Only escalate when the tarball gained capability the
    // source does not have — reformatting and version stamping are not attacks.
    const sourceSensitive = sensitiveNodes(sourceContent);
    const sourceKeys = new Set(sourceSensitive.map((c) => `${c.capability}:${c.path}`));
    const added = tarballSensitive.filter((c) => !sourceKeys.has(`${c.capability}:${c.path}`));

    if (added.length > 0) {
      desyncs.push({
        kind: 'sensitive_nodes_added',
        path: relPath,
        severity: 'critical',
        capabilities: added,
        detail: `"${relPath}" differs from ${usedRef.ref} and introduces ${added
          .map((c) => `${c.path} (${c.capability})`)
          .join(', ')}`,
      });
    } else if (execTargets.has(relPath)) {
      desyncs.push({
        kind: 'executable_modified',
        path: relPath,
        severity: 'high',
        capabilities: [],
        detail: `executable script "${relPath}" differs from ${usedRef.ref}`,
      });
    }
  }

  result.findings = desyncs;
  result.status = desyncs.length > 0 ? 'desync' : 'clean';
  return result;
}
