/**
 * D28 — "AI Slop" / WEL1DROPPER campaign (800-package flood, Aug 2026).
 *
 * The campaign's defining trait is that it has no lifecycle hooks. The README
 * tells the victim to `require()`/`import` the package explicitly, so hook-only
 * scanners see a clean package.json. The module-load body then runs a staged
 * downloader: hex/base64 string-array obfuscation, a process.platform/arch
 * fingerprint, and out-of-band stage-2 resolution over DNS TXT records.
 *
 * All analysis is local AST work — no lookups, no network, no telemetry.
 */
import path from 'path';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import { shannonEntropy, highEntropyStrings, isMinified } from './lib/entropy-analyzer.js';
import { extractPaasDomains } from './lib/paas-domains.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D28-AI-SLOP-DROPPER'];
const PATTERN_WEIGHTS = cfg.pattern_weights;

const PARSABLE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);
const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

/**
 * Cheap gate run before any parsing. A file that matches none of these markers
 * cannot produce a D28 signal, so it never reaches acorn — this keeps the
 * detector off the hot path for the overwhelming majority of files.
 *
 * Decode calls (Buffer.from/atob/fromCharCode) are deliberately absent: they
 * are ubiquitous in legitimate code, and every signal that depends on them also
 * requires an encoded literal, which the literal markers already catch.
 */
const PREFILTER = new RegExp(
  [
    // environment fingerprinting
    'process\\s*\\.\\s*(?:platform|arch)',
    'os\\s*\\.\\s*(?:platform|arch|type|release)\\s*\\(',
    // out-of-band DNS resolution
    '\\bresolve(?:Txt|Any)\\b',
    '\\bresolve\\s*\\([^)]*[\'"](?:TXT|ANY)[\'"]',
    // runs of encoded literals, i.e. the string-array shape (matching the
    // 6-char floor of HEX_LITERAL, not a single long literal)
    '(?:[\'"][0-9a-fA-F]{6,}[\'"]\\s*,\\s*){3,}',
    `(?:['"][A-Za-z0-9+/]{${cfg.base64_min_length},}={0,2}['"]\\s*,\\s*){3,}`,
    // a single literal long enough for the entropy rule
    `['"][A-Za-z0-9+/]{${cfg.min_literal_length},}={0,2}['"]`,
  ].join('|')
);

const FUNCTION_TYPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
]);

const HEX_LITERAL = new RegExp(`^[0-9a-fA-F]{6,}$`);
const BASE64_SHAPE = new RegExp(`^[A-Za-z0-9+/]{${cfg.base64_min_length},}={0,2}$`);

/**
 * Base64 *shape* alone matches ordinary camelCase identifiers, so an encoded
 * literal must also be random enough to be payload rather than a method name.
 */
function isEncodedLiteral(value) {
  if (HEX_LITERAL.test(value)) {
    return true;
  }
  return BASE64_SHAPE.test(value) && shannonEntropy(value) >= cfg.base64_min_entropy;
}

const DECODE_CALLEES = new Set(['atob', 'unescape', 'decodeURIComponent', 'parseInt']);
const EXEC_CALLEES = new Set(['eval', 'exec', 'execSync', 'spawn', 'spawnSync', 'runInNewContext']);

const NETWORK_METHODS = new Set([
  'resolveTxt',
  'resolveAny',
  'resolve',
  'resolve4',
  'lookup',
  'request',
  'get',
  'post',
  'connect',
  'createConnection',
]);
const NETWORK_OBJECTS = new Set([
  'dns',
  'dnsPromises',
  'resolver',
  'http',
  'https',
  'net',
  'tls',
  'axios',
  'got',
  'request',
  'fetch',
]);
const NETWORK_GLOBALS = new Set([
  'fetch',
  'axios',
  'got',
  'request',
  'XMLHttpRequest',
  'WebSocket',
]);

function isCodeFile(file) {
  const filePath = (file.path || file.name || '').toLowerCase();
  return PARSABLE_EXTENSIONS.has(path.extname(filePath));
}

function lineOf(content, offset) {
  if (!content) {
    return 1;
  }
  return (content.slice(0, offset).match(/\n/g) || []).length + 1;
}

function parse(code) {
  for (const sourceType of ['module', 'script']) {
    try {
      return acorn.parse(code, {
        ecmaVersion: 2022,
        sourceType,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
      });
    } catch {
      // try the next source type; unparsable files are simply skipped
    }
  }
  return null;
}

/** Innermost enclosing function node, or null for module scope. */
function innermostFunction(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    if (FUNCTION_TYPES.has(ancestors[i].type)) {
      return ancestors[i];
    }
  }
  return null;
}

/** Every scope enclosing a node, innermost first, with module scope as null. */
function scopeChain(ancestors) {
  const chain = [];
  for (let i = ancestors.length - 1; i >= 0; i--) {
    if (FUNCTION_TYPES.has(ancestors[i].type)) {
      chain.push(ancestors[i]);
    }
  }
  chain.push(null);
  return chain;
}

function isFingerprintNode(node) {
  if (node.type === 'MemberExpression') {
    const obj = node.object;
    const prop = node.property;
    if (obj?.type === 'Identifier' && obj.name === 'process' && prop?.type === 'Identifier') {
      return prop.name === 'platform' || prop.name === 'arch';
    }
  }
  if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
    const obj = node.callee.object;
    const prop = node.callee.property;
    if (obj?.type === 'Identifier' && obj.name === 'os' && prop?.type === 'Identifier') {
      return ['platform', 'arch', 'type', 'release'].includes(prop.name);
    }
  }
  return false;
}

function calleeNames(node) {
  const callee = node.callee;
  if (!callee) {
    return { object: null, method: null };
  }
  if (callee.type === 'Identifier') {
    return { object: null, method: callee.name };
  }
  if (callee.type === 'MemberExpression' && callee.property?.type === 'Identifier') {
    let object = null;
    if (callee.object?.type === 'Identifier') {
      object = callee.object.name;
    } else if (
      callee.object?.type === 'MemberExpression' &&
      callee.object.property?.type === 'Identifier'
    ) {
      object = callee.object.property.name;
    }
    return { object, method: callee.property.name };
  }
  return { object: null, method: null };
}

function isNetworkCall(node) {
  const { object, method } = calleeNames(node);
  if (!method) {
    return false;
  }
  if (!object) {
    return NETWORK_GLOBALS.has(method);
  }
  return NETWORK_OBJECTS.has(object) && NETWORK_METHODS.has(method);
}

function isDnsOobCall(node) {
  const { object, method } = calleeNames(node);
  if (method === 'resolveTxt' || method === 'resolveAny') {
    return true;
  }
  if (method === 'resolve' && object && NETWORK_OBJECTS.has(object)) {
    const kind = node.arguments?.[1];
    return kind?.type === 'Literal' && /^(TXT|ANY)$/i.test(String(kind.value));
  }
  return false;
}

/** `Buffer.from(x, 'hex'|'base64')`, `atob(...)`, `parseInt(x, 16)`, ... */
function isDecodeCall(node) {
  const { object, method } = calleeNames(node);
  if (object === 'Buffer' && method === 'from') {
    const enc = node.arguments?.[1];
    return enc?.type === 'Literal' && /^(hex|base64|base64url)$/i.test(String(enc.value));
  }
  if (object === 'String' && method === 'fromCharCode') {
    return true;
  }
  if (!object && method && DECODE_CALLEES.has(method)) {
    if (method === 'parseInt') {
      const radix = node.arguments?.[1];
      return radix?.type === 'Literal' && Number(radix.value) === 16;
    }
    return true;
  }
  return false;
}

function isDynamicExecution(node) {
  if (node.type === 'NewExpression') {
    return node.callee?.type === 'Identifier' && node.callee.name === 'Function';
  }
  if (node.type !== 'CallExpression') {
    return false;
  }
  const { method } = calleeNames(node);
  return Boolean(method && EXEC_CALLEES.has(method));
}

/** Does this subtree decode data and then hand it to an execution sink? */
function subtreeAssemblesPayload(node) {
  let decodes = false;
  let executes = false;
  walk.simple(node, {
    CallExpression(n) {
      if (isDecodeCall(n)) {
        decodes = true;
      }
      if (isDynamicExecution(n)) {
        executes = true;
      }
    },
    NewExpression(n) {
      if (isDynamicExecution(n)) {
        executes = true;
      }
    },
  });
  return decodes && executes;
}

function referencesIdentifier(node, names) {
  let found = false;
  walk.simple(node, {
    Identifier(n) {
      if (names.has(n.name)) {
        found = true;
      }
    },
  });
  return found;
}

/**
 * Per-file AST pass. Returns the raw signal set; scoring happens once per
 * package so a signal seen in two files is not double-counted.
 */
function analyzeFile(file) {
  const content = file.content || '';
  const filePath = file.path || file.name || 'unknown.js';
  const signals = [];

  if (!content || content.length > cfg.max_file_bytes || !PREFILTER.test(content)) {
    return signals;
  }

  const ast = parse(content);
  if (!ast) {
    return signals;
  }

  const add = (type, detail, offset) =>
    signals.push({ type, detail, file: filePath, line: lineOf(content, offset) });

  // --- encoded string arrays (hex/base64 literal blocks) --------------------
  const encodedArrayNames = new Set();
  walk.ancestor(ast, {
    ArrayExpression(node, _state, ancestors) {
      const literals = node.elements.filter(
        (el) => el?.type === 'Literal' && typeof el.value === 'string'
      );
      if (node.elements.length < cfg.min_encoded_array_size) {
        return;
      }
      const encoded = literals.filter((el) => isEncodedLiteral(el.value));
      if (encoded.length / node.elements.length < cfg.encoded_array_ratio) {
        return;
      }
      const declarator = ancestors.find((a) => a.type === 'VariableDeclarator');
      if (declarator?.id?.type === 'Identifier') {
        encodedArrayNames.add(declarator.id.name);
      }
      add(
        'encoded_string_array',
        `${encoded.length}/${node.elements.length} literals are hex/base64 encoded`,
        node.start
      );
    },
  });

  // --- decoder function indexing into one of those arrays -------------------
  if (encodedArrayNames.size > 0) {
    walk.simple(ast, {
      FunctionDeclaration: checkDecoder,
      FunctionExpression: checkDecoder,
      ArrowFunctionExpression: checkDecoder,
    });
  }

  function checkDecoder(fn) {
    if (signals.some((s) => s.type === 'string_array_decoder')) {
      return;
    }
    let indexesArray = false;
    let decodes = false;
    walk.simple(fn, {
      MemberExpression(n) {
        if (n.computed && n.object?.type === 'Identifier' && encodedArrayNames.has(n.object.name)) {
          indexesArray = true;
        }
      },
      CallExpression(n) {
        if (isDecodeCall(n)) {
          decodes = true;
        }
      },
    });
    if (indexesArray && decodes) {
      add(
        'string_array_decoder',
        `decoder resolves indices of ${[...encodedArrayNames].join(', ')}`,
        fn.start
      );
    }
  }

  // --- high-entropy string literals (non-minified files only) ---------------
  if (!isMinified(content)) {
    const literals = [];
    walk.simple(ast, {
      Literal(node) {
        if (typeof node.value === 'string') {
          literals.push(node.value);
        }
      },
      TemplateElement(node) {
        if (node.value?.cooked) {
          literals.push(node.value.cooked);
        }
      },
    });
    const hot = highEntropyStrings(literals, {
      minLength: cfg.min_literal_length,
      threshold: cfg.entropy_threshold,
    });
    if (hot.length >= cfg.min_high_entropy_literals) {
      const peak = hot.reduce((a, b) => (b.entropy > a.entropy ? b : a));
      add(
        'high_entropy_literals',
        `${hot.length} literals above ${cfg.entropy_threshold} bits (peak ${peak.entropy})`,
        0
      );
    }
  }

  // --- environment fingerprinting ------------------------------------------
  // Module-scope fingerprints are tracked by the variable they land in, so
  // coupling can require the network call to actually reference that value.
  const fingerprintScopes = [];
  const moduleFingerprintNames = new Set();
  walk.ancestor(ast, {
    MemberExpression: collectFingerprint,
    CallExpression: collectFingerprint,
  });

  function collectFingerprint(node, _state, ancestors) {
    if (!isFingerprintNode(node)) {
      return;
    }
    const scope = innermostFunction(ancestors);
    fingerprintScopes.push({ scope, node });
    if (scope === null) {
      const declarator = ancestors.find((a) => a.type === 'VariableDeclarator');
      if (declarator?.id?.type === 'Identifier') {
        moduleFingerprintNames.add(declarator.id.name);
      }
    }
  }

  if (fingerprintScopes.length > 0) {
    add(
      'env_fingerprint',
      `${fingerprintScopes.length} process.platform/arch or os.* read(s)`,
      fingerprintScopes[0].node.start
    );
  }

  // --- network + DNS out-of-band resolution ---------------------------------
  walk.ancestor(ast, {
    CallExpression(node, _state, ancestors) {
      const isNet = isNetworkCall(node);
      const isDns = isDnsOobCall(node);
      if (!isNet && !isDns) {
        return;
      }

      if (isDns && !signals.some((s) => s.type === 'dns_txt_oob')) {
        const { object, method } = calleeNames(node);
        add('dns_txt_oob', `${object ? object + '.' : ''}${method}() lookup`, node.start);
      }

      // stage-2 assembly: TXT records decoded and executed, either inside the
      // lookup's own callback or in the function awaiting its result
      if (isDns && !signals.some((s) => s.type === 'dns_payload_assembly')) {
        const callback = node.arguments?.find((a) => FUNCTION_TYPES.has(a?.type));
        const region = callback || innermostFunction(ancestors);
        if (region && subtreeAssemblesPayload(region)) {
          add(
            'dns_payload_assembly',
            'DNS TXT response decoded and passed to a dynamic execution sink',
            node.start
          );
        }
      }

      if (signals.some((s) => s.type === 'fingerprint_network_coupling')) {
        return;
      }
      const chain = scopeChain(ancestors);
      const enclosing = innermostFunction(ancestors);
      for (const fp of fingerprintScopes) {
        // fingerprint sits in this call's scope or an enclosing one
        if (!chain.includes(fp.scope)) {
          continue;
        }
        // module-scope fingerprints only count when the value is actually
        // referenced here — otherwise every `const isWin = ...` would couple
        if (fp.scope === null && moduleFingerprintNames.size > 0) {
          const region = enclosing || node;
          if (!referencesIdentifier(region, moduleFingerprintNames)) {
            continue;
          }
        }
        add(
          'fingerprint_network_coupling',
          'environment fingerprint and network/DNS call share a scope chain',
          node.start
        );
        break;
      }
    },
  });

  // --- serverless PaaS stage host ------------------------------------------
  const paas = extractPaasDomains(content);
  if (paas.length > 0) {
    add('paas_stage_resolution', `serverless PaaS host(s): ${paas.join(', ')}`, 0);
  }

  return signals;
}

/**
 * README instructs explicit require()/import of this package while package.json
 * declares no install hooks — the campaign's entry-point laundering.
 */
function detectReadmeDirectedEntry(pkgJson, files) {
  const scripts = pkgJson?.scripts || {};
  if (LIFECYCLE_HOOKS.some((hook) => scripts[hook])) {
    return null;
  }

  const readme = files.find((f) =>
    /(^|[\\/])readme(\.md|\.markdown)?$/i.test(f.path || f.name || '')
  );
  if (!readme?.content) {
    return null;
  }

  const pkgName = pkgJson?.name;
  const selfLoad = pkgName
    ? new RegExp(
        `(?:require\\s*\\(\\s*['"\`]${pkgName.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&')}['"\`]|import\\s+(?:[^;'"\`]*\\s+from\\s+)?['"\`]${pkgName.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&')}['"\`])`
      )
    : /require\s*\(\s*['"`][^'"`]+['"`]\s*\)|import\s+['"`][^'"`]+['"`]/;

  const match = selfLoad.exec(readme.content);
  if (!match) {
    return null;
  }
  return {
    type: 'readme_directed_entry',
    detail: 'README directs explicit require()/import while package.json declares no install hooks',
    file: readme.path || readme.name || 'README.md',
    line: lineOf(readme.content, match.index),
  };
}

function isSafelistedNetworkUtility(pkgJson) {
  const name = (pkgJson?.name || '').toLowerCase();
  if (cfg.network_utility_safelist.includes(name)) {
    return true;
  }
  const haystack = [name, pkgJson?.description || '', ...(pkgJson?.keywords || [])]
    .join(' ')
    .toLowerCase();
  return cfg.network_utility_keywords.some((kw) => haystack.includes(kw));
}

function confidenceLabel(score) {
  if (score >= 80) {
    return 'HIGH';
  }
  if (score >= 55) {
    return 'MEDIUM';
  }
  return 'LOW';
}

export const name = 'tier1-ai-slop-dropper';

export function scan(pkgJson, jsFiles, _registryMeta, allFiles) {
  if (cfg.enabled === false) {
    return [];
  }
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const files = allFiles || jsFiles || [];
  if (files.length === 0) {
    return [];
  }

  const signals = [];
  for (const file of files) {
    if (!isCodeFile(file)) {
      continue;
    }
    signals.push(...analyzeFile(file));
  }

  // Nothing fires without an anchor signal. The supporting signals are all
  // things legitimate packages do: Next.js couples process.platform with its
  // dev-server network code, prettier ships 4.7-bit HTML attribute tables, and
  // every npm README shows a require() example. They modulate severity once
  // real dropper machinery is present; they never establish it.
  const anchors = new Set(cfg.anchor_signals);
  if (!signals.some((s) => anchors.has(s.type))) {
    return [];
  }

  const readmeSignal = detectReadmeDirectedEntry(pkgJson, files);
  if (readmeSignal) {
    signals.push(readmeSignal);
  }

  const safelisted = isSafelistedNetworkUtility(pkgJson);

  let score = 0;
  const counted = new Set();
  const scored = [];
  for (const signal of signals) {
    if (counted.has(signal.type)) {
      continue;
    }
    // genuine DNS/mail utilities resolve TXT records for a living; payload
    // assembly is never excused
    if (safelisted && signal.type === 'dns_txt_oob') {
      continue;
    }
    counted.add(signal.type);
    score += PATTERN_WEIGHTS[signal.type] || 0;
    scored.push(signal);
  }

  // re-check after suppression: a safelisted utility whose only anchor was the
  // TXT lookup has nothing left to anchor on
  if (![...counted].some((type) => anchors.has(type)) || score < cfg.warn_threshold) {
    return [];
  }

  const overallScore = Math.min(100, score);
  const hasAssembly = counted.has('dns_payload_assembly');
  const hasObfuscation = counted.has('encoded_string_array') || counted.has('string_array_decoder');
  const hasOob = counted.has('dns_txt_oob') || hasAssembly;

  let severity;
  let recommendation;
  if (hasAssembly) {
    severity = 'critical';
    recommendation = 'BLOCK - DNS TXT out-of-band stage-2 payload assembly detected (WEL1DROPPER)';
  } else if (score >= cfg.flag_threshold) {
    severity = 'critical';
    recommendation =
      hasObfuscation && hasOob
        ? 'BLOCK - Obfuscated dropper with out-of-band DNS resolution detected (AI Slop campaign)'
        : 'BLOCK - AI Slop dropper pattern detected';
  } else {
    severity = 'high';
    recommendation = 'WARN - Dropper-adjacent obfuscation/fingerprinting patterns detected';
  }

  return [
    {
      detector: 'tier1-ai-slop-dropper',
      id: 'D28-AI-SLOP-DROPPER',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `AI Slop / WEL1DROPPER dropper pattern detected (aggregated risk: ${score})`,
      evidence: [
        `aggregated_risk: ${score}`,
        `signals: ${scored.map((s) => s.type).join(', ')}`,
        ...(safelisted ? ['dns_txt_oob suppressed: package is a safelisted network utility'] : []),
        ...scored.map((s) => `${s.type}: ${s.detail} @ ${s.file}:${s.line}`),
      ],
      locations: scored.map((s) => ({ file: s.file, line: s.line })),
      recommendation,
      detail: scored.map((s) => ({
        type: s.type,
        description: s.detail,
        risk: PATTERN_WEIGHTS[s.type] || 0,
        location: { file: s.file, line: s.line },
      })),
      reference: 'AI Slop / WEL1DROPPER 800-package campaign',
    },
  ];
}
