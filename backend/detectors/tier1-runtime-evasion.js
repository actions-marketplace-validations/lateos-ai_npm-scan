/**
 * D29 — Alternative-runtime evasion (Mini Shai-Hulud / Miasma, ChainDrop).
 *
 * Node-shaped detection is the assumption this detector removes. A payload
 * that never names a Node API used to be largely invisible: a behaviourally
 * identical credential stealer scored HIGH in Node idiom, HIGH in Bun idiom
 * and *zero findings* in Deno idiom (gap-analysis finding G1.1).
 *
 * Three things are covered:
 *   1. Downloading a non-Node runtime binary (bun/deno/qjs) from a lifecycle
 *      hook, including hooks that indirect through a script file
 *      (`"preinstall": "node setup.mjs"`).
 *   2. Process primitives and network calls from those runtimes reached at
 *      module load of a package entry point.
 *   3. Native FFI dynamic linking (`bun:ffi` dlopen, `Deno.dlopen`).
 *
 * Capability classification is delegated to lib/runtime-primitives.js, so
 * adding a runtime is a registry edit rather than a change here. Parsing goes
 * through lib/ast-parse.js, which accepts hashbangs and modern syntax — an
 * `#!/usr/bin/env bun` line previously made a file unparsable and therefore
 * silently clean (G1.4).
 *
 * All analysis is local AST work — no lookups, no network, no telemetry.
 */
import path from 'path';
import * as walk from 'acorn-walk';
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import { parseSource, lineOf, PARSE_FAILURE_WEIGHT } from './lib/ast-parse.js';
import {
  CAPABILITY,
  ALT_RUNTIMES,
  buildRuntimeIndex,
  classifyNode,
} from './lib/runtime-primitives.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D29-RUNTIME-EVASION'];
const PATTERN_WEIGHTS = cfg.pattern_weights;

const PARSABLE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);
// Bun and Deno execute TypeScript with no build step, so a `.ts` entry is a
// working package for those runtimes. It is still worth a regex pass even
// though acorn will not parse the type annotations (G1.3 / G1.6).
const SCANNABLE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.sh']);

const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

/**
 * Runtime binary downloads. Kept as text patterns because these appear in
 * shell strings inside package.json scripts as often as in JS source.
 */
const RUNTIME_DOWNLOAD_PATTERNS = [
  { runtime: 'bun', re: /https?:\/\/bun\.sh\/install/i },
  { runtime: 'bun', re: /github\.com\/oven-sh\/bun\/releases/i },
  { runtime: 'deno', re: /https?:\/\/deno\.land\/(x\/install|install)/i },
  { runtime: 'deno', re: /github\.com\/denoland\/deno(land)?\/releases/i },
  { runtime: 'deno', re: /https?:\/\/deno\.sh\/install/i },
  { runtime: 'qjs', re: /bellard\.org\/quickjs/i },
  { runtime: 'qjs', re: /github\.com\/quickjs-ng\/quickjs\/releases/i },
  // generic fetch-and-install of a named runtime
  {
    runtime: 'any',
    re: /\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n;|&]{0,120}\b(bun|deno|qjs|quickjs)\b/i,
  },
  {
    runtime: 'any',
    re: /\b(bun|deno|qjs)\b[^\n;|&]{0,40}\b(?:install|download|releases\/download)\b/i,
  },
];

/** Env var names worth escalating an ENV_READ over. */
const CREDENTIAL_ENV_RE =
  /\b(?:AWS_(?:SECRET|ACCESS|SESSION)\w*|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SSH_\w+|GITLAB_TOKEN|DOCKER_\w*PASS\w*|STRIPE_\w+|SLACK_TOKEN)\b/;

/**
 * Credential *files*. Reading `~/.aws/credentials` through a runtime file API
 * is the same act as reading the env var, and is the ChainDrop shape — the
 * path arrives as a string literal rather than an env name, so it needs its
 * own test.
 */
const CREDENTIAL_PATH_RE =
  /\.aws[\\/]credentials|\.aws[\\/]config|\.ssh[\\/]|\.npmrc|\.netrc|\.docker[\\/]config\.json|\.kube[\\/]config|\.git-credentials|\.config[\\/]gh[\\/]hosts|id_rsa|id_ed25519/i;

/**
 * Cheap gate before any parsing. A file matching none of these markers cannot
 * produce a D29 signal, so it never reaches acorn. Keep in sync with the AST
 * checks below — a mismatch silently disables a signal.
 */
const PREFILTER =
  /\bBun\s*\.|\bDeno\s*\.|['"]bun:(?:ffi|sqlite|jsc)['"]|['"]bun['"]|\bstd\s*\.\s*(?:popen|urlGet)\b|\bdlopen\b|\bbun\b|\bdeno\b|\bqjs\b|\bquickjs\b/i;

function extOf(file) {
  return path.extname((file?.path || file?.name || '').toLowerCase());
}

function isParsable(file) {
  return PARSABLE_EXTENSIONS.has(extOf(file));
}

function isScannable(file) {
  return SCANNABLE_EXTENSIONS.has(extOf(file));
}

function normalizePath(p) {
  return String(p || '').replace(/\\/g, '/');
}

function basename(p) {
  return normalizePath(p).split('/').pop();
}

/**
 * Files a lifecycle hook reaches: the hook body itself, plus any script file
 * it names (`node setup.mjs`, `sh install.sh`, `bun run boot.ts`).
 */
function resolveInstallTimeContext(pkgJson) {
  const hookSources = [];
  const referenced = new Set();

  for (const hook of LIFECYCLE_HOOKS) {
    const script = pkgJson?.scripts?.[hook];
    if (typeof script !== 'string' || !script) {
      continue;
    }
    hookSources.push({ hook, script });
    const re = /(?:^|[\s;&|])(?:node|nodejs|sh|bash|zsh|bun|deno|qjs|npx)\s+([^\s;&|'"]+)/g;
    let m;
    while ((m = re.exec(script)) !== null) {
      const target = basename(m[1]);
      if (target && /\.(js|mjs|cjs|ts|mts|cts|sh)$/i.test(target)) {
        referenced.add(target.toLowerCase());
      }
    }
  }

  return { hookSources, referenced };
}

/** Entry points a consumer reaches with a bare `require()` / `import`. */
function resolveEntryPoints(pkgJson) {
  const entries = new Set();
  const add = (v) => {
    if (typeof v === 'string' && v) {
      entries.add(basename(v).toLowerCase());
    }
  };
  add(pkgJson?.main);
  add(pkgJson?.module);
  add(pkgJson?.browser);
  if (typeof pkgJson?.bin === 'string') {
    add(pkgJson.bin);
  } else if (pkgJson?.bin && typeof pkgJson.bin === 'object') {
    Object.values(pkgJson.bin).forEach(add);
  }
  const exp = pkgJson?.exports;
  const walkExports = (node) => {
    if (typeof node === 'string') {
      add(node);
    } else if (node && typeof node === 'object') {
      Object.values(node).forEach(walkExports);
    }
  };
  walkExports(exp);
  if (entries.size === 0) {
    entries.add('index.js');
  }
  return entries;
}

function contextOf(file, installCtx, entryPoints) {
  const base = basename(file.path || file.name || '').toLowerCase();
  if (installCtx.referenced.has(base)) {
    return 'lifecycle';
  }
  if (entryPoints.has(base)) {
    return 'entry';
  }
  return 'module';
}

/** Scan text (script body or source) for runtime-binary download patterns. */
function findRuntimeDownloads(text) {
  const hits = [];
  for (const { runtime, re } of RUNTIME_DOWNLOAD_PATTERNS) {
    const match = re.exec(text);
    if (match) {
      hits.push({ runtime, match: match[0], index: match.index });
    }
  }
  return hits;
}

function analyzeFile(file, context) {
  const content = file.content || '';
  const filePath = file.path || file.name || 'unknown.js';
  const signals = [];

  if (!content || content.length > cfg.max_file_bytes) {
    return signals;
  }
  if (!PREFILTER.test(content)) {
    return signals;
  }

  const add = (type, detail, offset, extra = {}) =>
    signals.push({ type, detail, file: filePath, line: lineOf(content, offset), ...extra });

  // --- runtime binary downloads (text-level, any scannable file) -----------
  for (const hit of findRuntimeDownloads(content)) {
    add(
      context === 'lifecycle' ? 'runtime_download_install_time' : 'runtime_download',
      `${hit.runtime === 'any' ? 'alternative runtime' : hit.runtime} binary fetched: ${hit.match.slice(0, 100)}`,
      hit.index,
      { runtime: hit.runtime }
    );
    break; // one download signal per file is enough
  }

  if (!isParsable(file)) {
    // TypeScript and shell files still contribute the text-level signals above.
    return signals;
  }

  const parsed = parseSource(content);
  if (parsed.degraded) {
    // Signal, not silence. Weighted low on its own: minified/exotic sources
    // legitimately fail to parse, so this only ever nudges an existing case.
    add('unparsable_source', `source could not be parsed (${parsed.reason})`, 0);
    return signals;
  }

  const index = buildRuntimeIndex(parsed.ast);
  const seenTypes = new Set();

  const record = (type, detail, node, extra) => {
    if (seenTypes.has(type)) {
      return;
    }
    seenTypes.add(type);
    add(type, detail, node.start ?? 0, extra);
  };

  walk.full(parsed.ast, (node) => {
    const hit = classifyNode(node, index);
    if (!hit || !ALT_RUNTIMES.has(hit.runtime)) {
      return;
    }

    const where = `${hit.path} (${hit.runtime})`;

    switch (hit.capability) {
      case CAPABILITY.EXEC:
        record(
          context === 'entry' || context === 'lifecycle'
            ? 'alt_runtime_exec_entry'
            : 'alt_runtime_exec',
          `${where} spawns a process`,
          node,
          { runtime: hit.runtime }
        );
        break;
      case CAPABILITY.FFI:
        record('alt_runtime_ffi', `${where} loads native code via FFI`, node, {
          runtime: hit.runtime,
        });
        break;
      case CAPABILITY.NET_CONNECT:
        record(
          context === 'entry' || context === 'lifecycle'
            ? 'alt_runtime_network_entry'
            : 'alt_runtime_network',
          `${where} opens an outbound connection`,
          node,
          { runtime: hit.runtime }
        );
        break;
      case CAPABILITY.NET_LISTEN:
        record('alt_runtime_listen', `${where} listens for connections`, node, {
          runtime: hit.runtime,
        });
        break;
      case CAPABILITY.ENV_READ: {
        const slice = content.slice(node.start, Math.min(content.length, node.end + 60));
        const credential = CREDENTIAL_ENV_RE.test(slice);
        record(
          credential ? 'alt_runtime_credential_access' : 'alt_runtime_env_read',
          credential ? `${where} reads a credential env var` : `${where} reads environment`,
          node,
          { runtime: hit.runtime }
        );
        break;
      }
      case CAPABILITY.FS_READ: {
        const slice = content.slice(node.start, Math.min(content.length, node.end + 20));
        if (CREDENTIAL_PATH_RE.test(slice)) {
          record('alt_runtime_credential_access', `${where} reads a credential file`, node, {
            runtime: hit.runtime,
          });
        } else {
          record('alt_runtime_fs_read', `${where} reads from disk`, node, { runtime: hit.runtime });
        }
        break;
      }
      case CAPABILITY.FINGERPRINT:
        record('runtime_fingerprint', `${where} fingerprints the runtime`, node, {
          runtime: hit.runtime,
        });
        break;
      default:
        break;
    }
  });

  return signals;
}

function confidenceLabel(score) {
  if (score >= 80) {
    return 'HIGH';
  }
  if (score >= 50) {
    return 'MEDIUM';
  }
  return 'LOW';
}

export const name = 'tier1-runtime-evasion';

export function scan(pkgJson, jsFiles, _registryMeta, allFiles) {
  if (cfg.enabled === false) {
    return [];
  }
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const files = allFiles || jsFiles || [];
  if (files.length === 0 && !pkgJson?.scripts) {
    return [];
  }

  const installCtx = resolveInstallTimeContext(pkgJson);
  const entryPoints = resolveEntryPoints(pkgJson);
  const signals = [];

  // Lifecycle hook bodies are install-time by definition.
  for (const { hook, script } of installCtx.hookSources) {
    for (const hit of findRuntimeDownloads(script)) {
      signals.push({
        type: 'runtime_download_install_time',
        detail: `${hook} hook fetches ${hit.runtime === 'any' ? 'an alternative runtime' : hit.runtime} binary: ${hit.match.slice(0, 100)}`,
        file: 'package.json',
        line: 1,
        runtime: hit.runtime,
      });
      break;
    }
    // `bun run` / `deno run` used directly as the hook interpreter
    if (/(?:^|[\s;&|])(bun|deno|qjs)\s+(?:run|x|install|add)\b/i.test(script)) {
      signals.push({
        type: 'alt_runtime_hook_interpreter',
        detail: `${hook} hook invokes an alternative runtime directly: ${script.slice(0, 100)}`,
        file: 'package.json',
        line: 1,
      });
    }
  }

  for (const file of files) {
    if (!isScannable(file)) {
      continue;
    }
    signals.push(...analyzeFile(file, contextOf(file, installCtx, entryPoints)));
  }

  if (signals.length === 0) {
    return [];
  }

  // Nothing fires without an anchor. Bun.file/Bun.serve and a runtime
  // fingerprint are what legitimate Bun and Deno tooling does all day; they
  // modulate severity once real evasion machinery is present but never
  // establish it on their own. This gate is what keeps the detector off
  // ordinary Bun-based packages.
  const anchors = new Set(cfg.anchor_signals);
  if (!signals.some((s) => anchors.has(s.type))) {
    return [];
  }

  let score = 0;
  const counted = new Set();
  const scored = [];
  for (const signal of signals) {
    if (counted.has(signal.type)) {
      continue;
    }
    counted.add(signal.type);
    score +=
      signal.type === 'unparsable_source'
        ? PARSE_FAILURE_WEIGHT
        : PATTERN_WEIGHTS[signal.type] || 0;
    scored.push(signal);
  }

  if (score < cfg.warn_threshold) {
    return [];
  }

  const overallScore = Math.min(100, score);
  const runtimes = [...new Set(signals.map((s) => s.runtime).filter((r) => r && r !== 'any'))];
  const hasDownload =
    counted.has('runtime_download_install_time') || counted.has('runtime_download');
  const hasFfi = counted.has('alt_runtime_ffi');
  const hasExec = counted.has('alt_runtime_exec_entry') || counted.has('alt_runtime_exec');
  const hasCredential = counted.has('alt_runtime_credential_access');

  let severity;
  let recommendation;
  if (hasCredential && (hasExec || hasDownload)) {
    severity = 'critical';
    recommendation = 'BLOCK - Alternative runtime execution with credential access';
  } else if (counted.has('runtime_download_install_time')) {
    severity = 'critical';
    recommendation = 'BLOCK - Lifecycle hook downloads an alternative runtime binary';
  } else if (hasFfi) {
    severity = 'critical';
    recommendation = 'BLOCK - Native FFI dynamic linking via alternative runtime';
  } else if (score >= cfg.flag_threshold) {
    severity = 'critical';
    recommendation = 'BLOCK - Alternative runtime evasion pattern detected';
  } else {
    severity = 'high';
    recommendation = 'WARN - Alternative runtime primitives used outside a declared runtime';
  }

  return [
    {
      detector: 'tier1-runtime-evasion',
      id: 'D29-RUNTIME-EVASION',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Alternative runtime evasion detected${runtimes.length ? ` (${runtimes.join(', ')})` : ''} (aggregated risk: ${score})`,
      evidence: [
        `aggregated_risk: ${score}`,
        `runtimes: ${runtimes.length ? runtimes.join(', ') : 'unspecified'}`,
        `signals: ${scored.map((s) => s.type).join(', ')}`,
        ...scored.map((s) => `${s.type}: ${s.detail} @ ${s.file}:${s.line}`),
      ],
      locations: scored.map((s) => ({ file: s.file, line: s.line })),
      recommendation,
      detail: scored.map((s) => ({
        type: s.type,
        description: s.detail,
        runtime: s.runtime || null,
        risk: s.type === 'unparsable_source' ? PARSE_FAILURE_WEIGHT : PATTERN_WEIGHTS[s.type] || 0,
        location: { file: s.file, line: s.line },
      })),
      reference: 'Mini Shai-Hulud / Miasma alternative-runtime evasion',
    },
  ];
}
