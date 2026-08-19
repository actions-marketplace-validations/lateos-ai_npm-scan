/**
 * Constant-folds path expressions in an AST back to a comparable string.
 *
 * Every path check in the scanner used to be a literal substring or regex test
 * against raw source, so all three of these reached the same file while
 * defeating the check (gap-analysis finding G3.6):
 *
 *   ['.','claude'].join('') + '/' + ['mcp','json'].join('.')
 *   path.join(__dirname, '..','..','..', '.cursor', 'rules', 'a.md')
 *   String.fromCharCode(46,99,108,97,117,100,101)
 *
 * Roots that are only knowable at runtime fold to a stable placeholder token
 * (`<cwd>`, `<home>`, `<dirname>`) rather than failing the whole expression —
 * `path.join(process.cwd(), '.cursor', 'rules')` is exactly the shape we need
 * to catch, and its first segment is never a literal.
 */

const SYMBOLIC = {
  __dirname: '<dirname>',
  __filename: '<dirname>',
};

const SYMBOLIC_CALLS = {
  'process.cwd': '<cwd>',
  'os.homedir': '<home>',
  'os.tmpdir': '<tmp>',
};

const SYMBOLIC_MEMBERS = {
  'process.env.HOME': '<home>',
  'process.env.USERPROFILE': '<home>',
  'process.env.HOMEPATH': '<home>',
  'process.env.APPDATA': '<home>',
  'process.env.INIT_CWD': '<cwd>',
  'process.env.PWD': '<cwd>',
};

const JOINING_CALLS = new Set(['join', 'resolve']);

/** Dotted static member path, or null when any link is dynamic. */
function dottedPath(node) {
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
  const base = dottedPath(node.object);
  return base ? `${base}.${node.property.name}` : null;
}

/**
 * Collapse `.` and `..` and duplicate separators. Leading `..` segments are
 * preserved — escaping the package root is itself a signal the caller wants.
 */
export function normalizePath(raw) {
  if (!raw) {
    return raw;
  }
  const value = String(raw).replace(/\\/g, '/');
  const absolute = value.startsWith('/');
  const segments = value.split('/');
  const out = [];
  for (const seg of segments) {
    if (seg === '' || seg === '.') {
      continue;
    }
    if (seg === '..') {
      // A placeholder root is opaque: `<cwd>/..` cannot be simplified further.
      if (
        out.length > 0 &&
        out[out.length - 1] !== '..' &&
        !/^<[a-z]+>$/.test(out[out.length - 1])
      ) {
        out.pop();
        continue;
      }
      out.push('..');
      continue;
    }
    out.push(seg);
  }
  const joined = out.join('/');
  return absolute ? '/' + joined : joined;
}

/**
 * Fold an expression node into a path string.
 *
 * @param {object} node
 * @param {object} [options]
 * @param {number} [options.depth] internal recursion guard
 * @returns {{value: string, confidence: 'exact'|'partial'}|null}
 */
export function resolvePathExpr(node, options = {}) {
  const depth = options.depth ?? 0;
  if (!node || depth > 12) {
    return null;
  }
  const recurse = (n) => resolvePathExpr(n, { ...options, depth: depth + 1 });

  switch (node.type) {
    case 'Literal':
      return typeof node.value === 'string'
        ? { value: node.value, confidence: 'exact' }
        : typeof node.value === 'number'
          ? { value: String(node.value), confidence: 'exact' }
          : null;

    case 'Identifier': {
      const sym = SYMBOLIC[node.name];
      if (sym) {
        return { value: sym, confidence: 'partial' };
      }
      // Follow a single-assignment local binding: assembling the path into a
      // variable and passing the variable is the natural way to write this,
      // and was itself a bypass while only the call argument was inspected.
      const bound = options.bindings?.get(node.name);
      if (bound) {
        const seen = options.seen || new Set();
        if (seen.has(node.name)) {
          return null;
        }
        seen.add(node.name);
        return resolvePathExpr(bound, { ...options, seen, depth: depth + 1 });
      }
      return null;
    }

    case 'TemplateLiteral': {
      let out = '';
      let confidence = 'exact';
      const quasis = node.quasis || [];
      const exprs = node.expressions || [];
      for (let i = 0; i < quasis.length; i++) {
        out += quasis[i]?.value?.cooked ?? '';
        if (i < exprs.length) {
          const part = recurse(exprs[i]);
          if (!part) {
            return null;
          }
          if (part.confidence === 'partial') {
            confidence = 'partial';
          }
          out += part.value;
        }
      }
      return { value: out, confidence };
    }

    case 'BinaryExpression': {
      if (node.operator !== '+') {
        return null;
      }
      const left = recurse(node.left);
      const right = recurse(node.right);
      if (!left || !right) {
        return null;
      }
      return {
        value: left.value + right.value,
        confidence:
          left.confidence === 'partial' || right.confidence === 'partial' ? 'partial' : 'exact',
      };
    }

    case 'MemberExpression': {
      const path = dottedPath(node);
      const sym = path && SYMBOLIC_MEMBERS[path];
      return sym ? { value: sym, confidence: 'partial' } : null;
    }

    case 'CallExpression':
      return resolveCall(node, recurse);

    default:
      return null;
  }
}

function resolveCall(node, recurse) {
  const callee = node.callee;
  const path = dottedPath(callee);

  // process.cwd() / os.homedir() / os.tmpdir()
  if (path && SYMBOLIC_CALLS[path]) {
    return { value: SYMBOLIC_CALLS[path], confidence: 'partial' };
  }

  // String.fromCharCode(46, 99, ...)
  if (path === 'String.fromCharCode') {
    const codes = [];
    for (const arg of node.arguments || []) {
      if (arg?.type !== 'Literal' || typeof arg.value !== 'number') {
        return null;
      }
      codes.push(arg.value);
    }
    return codes.length ? { value: String.fromCharCode(...codes), confidence: 'exact' } : null;
  }

  const method = callee?.type === 'MemberExpression' ? callee.property?.name : null;

  // ['.','claude'].join('')  — literal array receiver
  if (method === 'join' && callee.object?.type === 'ArrayExpression') {
    const sepNode = node.arguments?.[0];
    const sep =
      sepNode === undefined
        ? ','
        : sepNode?.type === 'Literal' && typeof sepNode.value === 'string'
          ? sepNode.value
          : null;
    if (sep === null) {
      return null;
    }
    const parts = [];
    let confidence = 'exact';
    for (const el of callee.object.elements || []) {
      const part = recurse(el);
      if (!part) {
        return null;
      }
      if (part.confidence === 'partial') {
        confidence = 'partial';
      }
      parts.push(part.value);
    }
    return { value: parts.join(sep), confidence };
  }

  // path.join(...) / path.resolve(...) — also matches a namespace-renamed
  // import, since only the method name is required to be `join`/`resolve`.
  if (method && JOINING_CALLS.has(method)) {
    const parts = [];
    let confidence = 'exact';
    for (const arg of node.arguments || []) {
      const part = recurse(arg);
      if (!part) {
        return null;
      }
      if (part.confidence === 'partial') {
        confidence = 'partial';
      }
      parts.push(part.value);
    }
    if (parts.length === 0) {
      return null;
    }
    return { value: normalizePath(parts.join('/')), confidence };
  }

  // 'a/b'.concat('c')
  if (method === 'concat') {
    const base = recurse(callee.object);
    if (!base) {
      return null;
    }
    let out = base.value;
    let confidence = base.confidence;
    for (const arg of node.arguments || []) {
      const part = recurse(arg);
      if (!part) {
        return null;
      }
      if (part.confidence === 'partial') {
        confidence = 'partial';
      }
      out += part.value;
    }
    return { value: out, confidence };
  }

  return null;
}

/**
 * True when the expression is assembled from anything other than a single
 * string literal. Used to separate "wrote to a hardcoded path" from "computed
 * a path at runtime", which is the more deliberate act.
 */
export function isDynamicExpr(node) {
  return Boolean(node) && node.type !== 'Literal';
}

/**
 * Map of variable name -> initializer, for names declared exactly once in the
 * file. Names declared or reassigned more than once are dropped rather than
 * guessed at, so resolution never invents a path the code does not produce.
 *
 * @param {object} ast
 * @returns {Map<string, object>}
 */
export function collectBindings(ast) {
  const inits = new Map();
  const counts = new Map();

  const visit = (node) => {
    if (!node || typeof node.type !== 'string') {
      return;
    }
    if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
      const nm = node.id.name;
      counts.set(nm, (counts.get(nm) || 0) + 1);
      if (node.init) {
        inits.set(nm, node.init);
      }
    }
    if (node.type === 'AssignmentExpression' && node.left?.type === 'Identifier') {
      const nm = node.left.name;
      counts.set(nm, (counts.get(nm) || 0) + 1);
    }
    for (const key of Object.keys(node)) {
      if (key === 'type' || key === 'start' || key === 'end' || key === 'loc') {
        continue;
      }
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(visit);
      } else if (child && typeof child.type === 'string') {
        visit(child);
      }
    }
  };

  visit(ast);

  for (const [nm, count] of counts) {
    if (count > 1) {
      inits.delete(nm);
    }
  }
  return inits;
}
