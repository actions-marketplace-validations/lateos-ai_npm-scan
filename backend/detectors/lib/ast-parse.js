/**
 * Shared, hardened source parsing for AST detectors.
 *
 * Replaces the per-detector `acorn.parse(code, { ecmaVersion: 2022 })` calls
 * that each rolled their own options and their own failure semantics.
 *
 * Two properties matter here, both of them security properties:
 *
 * 1. `ecmaVersion: 'latest'` + `allowHashBang`. At ecmaVersion 2022 acorn
 *    rejects a leading `#!` outright (allowHashBang only defaults on from
 *    2023), so an 18-character hashbang line was enough to make a file
 *    unparsable — and therefore invisible — to every AST detector. Import
 *    attributes, import assertions and `using` declarations failed the same
 *    way. See docs/security/gap-analysis-2026-08.md and the G1.4 finding.
 *
 * 2. Parse failure is a *signal*, never silence. `parseSource` always returns
 *    an object; callers must branch on `degraded` rather than on a null AST.
 *    A file that cannot be parsed inside an otherwise suspicious package is
 *    more interesting than one that parses clean, not less.
 *
 * The module-level cache exists so that several detectors walking the same
 * tarball parse each file once. It is bounded and content-keyed.
 */
import * as acorn from 'acorn';

/** Suggested score contribution when a caller chooses to weight a parse failure. */
export const PARSE_FAILURE_WEIGHT = 15;

const BASE_OPTIONS = {
  ecmaVersion: 'latest',
  allowHashBang: true,
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  allowSuperOutsideMethod: true,
};

// Bounded content-addressed cache. Tarballs are scanned and discarded, so a
// simple size cap is sufficient; there is no eviction policy beyond "drop it
// all", which keeps the hot path free of bookkeeping.
const MAX_CACHE_ENTRIES = 400;
const MAX_CACHEABLE_BYTES = 512000;
const cache = new Map();

function cacheKey(code) {
  // Length prefix makes collisions between distinct sources of different size
  // impossible, and keeps the key cheap for the common (small file) case.
  return `${code.length}:${code}`;
}

/**
 * Parse JavaScript source with progressive fallbacks.
 *
 * Order matters: `module` first because published npm code is increasingly
 * ESM and a script-mode parse of ESM fails on the first `import`; `script`
 * second for CommonJS with top-level `return`; then a hashbang-stripped retry
 * as a belt-and-braces path for parsers/versions that still object to `#!`.
 *
 * @param {string} code
 * @param {object} [options]
 * @param {boolean} [options.cache=true]
 * @returns {{ast: object|null, sourceType: string|null, degraded: boolean, reason: string|null}}
 */
export function parseSource(code, options = {}) {
  const useCache = options.cache !== false;

  if (typeof code !== 'string' || code.length === 0) {
    return { ast: null, sourceType: null, degraded: true, reason: 'empty_source' };
  }

  let key = null;
  if (useCache && code.length <= MAX_CACHEABLE_BYTES) {
    key = cacheKey(code);
    const hit = cache.get(key);
    if (hit) {
      return hit;
    }
  }

  let result = null;
  let lastError = null;

  for (const sourceType of ['module', 'script']) {
    try {
      const ast = acorn.parse(code, { ...BASE_OPTIONS, sourceType });
      result = { ast, sourceType, degraded: false, reason: null };
      break;
    } catch (err) {
      lastError = err;
    }
  }

  // Hashbang fallback: replace the shebang with a line comment so byte offsets
  // — and therefore every reported line number — stay exactly aligned.
  if (!result && /^#!/.test(code)) {
    const stripped = code.replace(/^#![^\n]*/, (m) => '//' + m.slice(2));
    for (const sourceType of ['module', 'script']) {
      try {
        const ast = acorn.parse(stripped, { ...BASE_OPTIONS, sourceType });
        result = { ast, sourceType, degraded: false, reason: null };
        break;
      } catch (err) {
        lastError = err;
      }
    }
  }

  if (!result) {
    result = {
      ast: null,
      sourceType: null,
      degraded: true,
      reason: lastError?.message ? `parse_error: ${lastError.message}` : 'parse_error',
    };
  }

  if (key) {
    if (cache.size >= MAX_CACHE_ENTRIES) {
      cache.clear();
    }
    cache.set(key, result);
  }

  return result;
}

/** Line number (1-indexed) for a character offset. */
export function lineOf(content, offset) {
  if (!content || !offset) {
    return 1;
  }
  return (content.slice(0, offset).match(/\n/g) || []).length + 1;
}

export function _clearParseCache() {
  cache.clear();
}

export function _cacheSize() {
  return cache.size;
}
