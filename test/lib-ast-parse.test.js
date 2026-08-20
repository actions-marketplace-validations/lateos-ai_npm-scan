import { test } from 'node:test';
import assert from 'assert/strict';
import {
  parseSource,
  lineOf,
  _clearParseCache,
  _cacheSize,
} from '../backend/detectors/lib/ast-parse.js';
import {
  buildRuntimeIndex,
  classifyNode,
  memberPath,
  CAPABILITY,
} from '../backend/detectors/lib/runtime-primitives.js';
import * as walk from 'acorn-walk';

/* ------------------------------------------------------------------ *
 * G1.4 — syntax that used to make a file silently unparsable          *
 * ------------------------------------------------------------------ */

test('ast-parse: parses a hashbang, which ecmaVersion 2022 rejected outright', () => {
  const r = parseSource('#!/usr/bin/env bun\nconst a = 1;\n');
  assert.equal(r.degraded, false);
  assert.ok(r.ast);
});

test('ast-parse: parses import attributes (ES2025)', () => {
  const r = parseSource('import c from "./c.json" with { type: "json" };');
  assert.equal(r.degraded, false);
});

test('ast-parse: parses using declarations', () => {
  const r = parseSource('using h = open();');
  assert.equal(r.degraded, false);
});

test('ast-parse: parses both module and script sources', () => {
  assert.equal(parseSource('export const a = 1;').sourceType, 'module');
  assert.equal(parseSource('return 1;').degraded, false);
});

test('ast-parse: hashbang line numbers stay aligned after the fallback', () => {
  const src = '#!/usr/bin/env bun\n\nconst target = 1;\n';
  const r = parseSource(src);
  assert.equal(r.degraded, false);
  let offset = null;
  walk.simple(r.ast, {
    VariableDeclaration(n) {
      offset = n.start;
    },
  });
  assert.equal(lineOf(src, offset), 3);
});

test('ast-parse: reports failure as a signal, never as silence', () => {
  const r = parseSource('const const const');
  assert.equal(r.degraded, true);
  assert.equal(r.ast, null);
  assert.ok(r.reason.startsWith('parse_error'));
});

test('ast-parse: empty input is degraded, not a crash', () => {
  assert.equal(parseSource('').reason, 'empty_source');
  assert.equal(parseSource(null).degraded, true);
});

test('ast-parse: repeat parses of identical content are cached', () => {
  _clearParseCache();
  const src = 'const cached = 1;';
  const a = parseSource(src);
  const b = parseSource(src);
  assert.equal(a.ast, b.ast, 'expected the same AST object from cache');
  assert.equal(_cacheSize(), 1);
  _clearParseCache();
  assert.equal(_cacheSize(), 0);
});

/* ------------------------------------------------------------------ *
 * runtime-primitives                                                  *
 * ------------------------------------------------------------------ */

function classifyAll(src) {
  const { ast } = parseSource(src);
  const index = buildRuntimeIndex(ast);
  const out = [];
  walk.full(ast, (node) => {
    const hit = classifyNode(node, index);
    if (hit) {
      out.push(`${hit.runtime}/${hit.capability}`);
    }
  });
  return out;
}

test('runtime-primitives: resolves tagged templates (Bun.$)', () => {
  assert.ok(classifyAll('await Bun.$`id`;').includes('bun/exec'));
});

test('runtime-primitives: resolves a tagged template through an import binding', () => {
  assert.ok(classifyAll('import { $ } from "bun"; await $`id`;').includes('bun/exec'));
});

test('runtime-primitives: resolves constructor calls (new Deno.Command)', () => {
  assert.ok(classifyAll('new Deno.Command("sh");').includes('deno/exec'));
});

test('runtime-primitives: resolves bare-specifier imports (bun:ffi)', () => {
  assert.ok(classifyAll('import { dlopen } from "bun:ffi"; dlopen("l",{});').includes('bun/ffi'));
});

test('runtime-primitives: resolves inline requires', () => {
  assert.ok(classifyAll('require("child_process").execSync("id");').includes('node/exec'));
});

test('runtime-primitives: resolves through a namespace binding', () => {
  assert.ok(
    classifyAll('const cp = require("child_process"); cp.execSync("id");').includes('node/exec')
  );
});

test('runtime-primitives: strips the node: specifier prefix', () => {
  assert.ok(
    classifyAll('const cp = require("node:child_process"); cp.exec("id");').includes('node/exec')
  );
});

test('runtime-primitives: memberPath refuses computed access', () => {
  const { ast } = parseSource('a[b].c;');
  let node = null;
  walk.simple(ast, {
    MemberExpression(n) {
      node = node || n;
    },
  });
  assert.equal(memberPath(node), null);
});

test('runtime-primitives: globalThis-prefixed access normalizes to the bare primitive', () => {
  assert.ok(classifyAll('globalThis.Bun.spawn(["id"]);').includes('bun/exec'));
});

test('runtime-primitives: capability is exposed for cross-runtime comparison', () => {
  const nodeExec = classifyAll('require("child_process").execSync("id")');
  const bunExec = classifyAll('await Bun.$`id`');
  const denoExec = classifyAll('new Deno.Command("id")');
  assert.ok(nodeExec.some((c) => c.endsWith(CAPABILITY.EXEC)));
  assert.ok(bunExec.some((c) => c.endsWith(CAPABILITY.EXEC)));
  assert.ok(denoExec.some((c) => c.endsWith(CAPABILITY.EXEC)));
});

test('runtime-primitives: ordinary code classifies as nothing', () => {
  assert.deepEqual(classifyAll('const add = (a, b) => a + b; export default add;'), []);
});
