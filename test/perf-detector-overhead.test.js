import { test } from 'node:test';
import assert from 'assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runAll } from '../backend/detectors/index.js';
import { scan as d29 } from '../backend/detectors/tier1-runtime-evasion.js';
import { scan as d30 } from '../backend/detectors/tier1-workspace-persistence.js';
import thresholds from '../backend/detectors/config/thresholds.js';
import { parseSource, _clearParseCache, _cacheSize } from '../backend/detectors/lib/ast-parse.js';

/**
 * Acceptance criterion: the new AST rules must add < 5% to scan time.
 *
 * Measured as the new detectors' own cost over a corpus, divided by the full
 * pipeline's cost over that same corpus. This is deliberately *not* measured
 * by differencing two full-pipeline runs: the pipeline takes several seconds
 * and varies by more than 5% run to run, so differencing cannot resolve a
 * sub-1% signal — it measures machine noise, not the detectors. The direct
 * ratio measures exactly the quantity being claimed and is stable.
 *
 * `min` of several iterations is used rather than mean; it is the most stable
 * timing statistic, since noise only ever adds time.
 */

const NEW_DETECTORS = ['D29-RUNTIME-EVASION', 'D30-WORKSPACE-PERSISTENCE'];
const BUDGET_PERCENT = 5;
const CORPUS_TARGET = 150;

/** Real published JS, so prefilter hit rates reflect reality. */
function collectRealFiles(dir, out, limit) {
  if (out.length >= limit) {
    return out;
  }
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (out.length >= limit) {
      break;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectRealFiles(full, out, limit);
    } else if (/\.(js|mjs|cjs)$/.test(entry.name)) {
      try {
        const content = fs.readFileSync(full, 'utf8');
        if (content.length > 200 && content.length < 200000) {
          out.push({ path: full.split(path.sep).join('/'), content });
        }
      } catch {
        /* unreadable file, skip */
      }
    }
  }
  return out;
}

function syntheticFiles(count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push({
      path: `lib/module-${i}.js`,
      content:
        `const helper${i} = require('./helper-${i}');\n` +
        `function transform${i}(input) {\n` +
        `  return input.map((x) => ({ ...x, id: x.id + ${i} })).filter(Boolean);\n}\n`.repeat(20) +
        `module.exports = { transform${i} };\n`,
    });
  }
  return out;
}

function buildCorpus() {
  const real = collectRealFiles('node_modules', [], CORPUS_TARGET);
  return real.length >= 40 ? real : syntheticFiles(CORPUS_TARGET);
}

const PKG = { name: 'perf-corpus-fixture', version: '1.0.0', main: 'index.js' };

function minOf(iterations, fn) {
  const samples = [];
  for (let i = 0; i < iterations; i++) {
    _clearParseCache();
    const started = process.hrtime.bigint();
    fn();
    samples.push(Number(process.hrtime.bigint() - started) / 1e6);
  }
  return Math.min(...samples);
}

async function minOfAsync(iterations, fn) {
  const samples = [];
  for (let i = 0; i < iterations; i++) {
    _clearParseCache();
    const started = process.hrtime.bigint();
    await fn();
    samples.push(Number(process.hrtime.bigint() - started) / 1e6);
  }
  return Math.min(...samples);
}

test('perf: D29 + D30 cost less than 5% of a full pipeline scan', async (t) => {
  const files = buildCorpus();
  if (files.length < 40) {
    t.skip('no usable corpus available');
    return;
  }

  for (const id of NEW_DETECTORS) {
    thresholds[id].enabled = true;
  }

  // Warm up JIT and module initialization before any measurement.
  d29(PKG, [], null, files);
  d30(PKG, [], null, files);
  await runAll(PKG, files, null, files);

  const newCost = minOf(4, () => {
    d29(PKG, [], null, files);
    d30(PKG, [], null, files);
  });
  const pipelineCost = await minOfAsync(2, () => runAll(PKG, files, null, files));

  const overhead = (newCost / pipelineCost) * 100;
  t.diagnostic(
    `corpus=${files.length} files  D29+D30=${newCost.toFixed(1)}ms  ` +
      `pipeline=${pipelineCost.toFixed(1)}ms  overhead=${overhead.toFixed(2)}%`
  );

  assert.ok(
    overhead < BUDGET_PERCENT,
    `overhead ${overhead.toFixed(2)}% exceeds the ${BUDGET_PERCENT}% budget ` +
      `(${newCost.toFixed(1)}ms of ${pipelineCost.toFixed(1)}ms over ${files.length} files)`
  );
});

test('perf: prefilters keep almost all files away from the parser', (t) => {
  const files = buildCorpus();
  if (files.length < 40) {
    t.skip('no usable corpus available');
    return;
  }

  // The prefilters are what make the budget achievable: a file matching no
  // marker is rejected on a single regex test and never parsed. If the
  // prefilter is ever loosened, this per-file cost is the early warning.
  const perFileCost = minOf(2, () => {
    for (const file of files) {
      d29(PKG, [], null, [file]);
    }
  });
  t.diagnostic(
    `per-file D29 sweep over ${files.length} files = ${perFileCost.toFixed(1)}ms ` +
      `(${(perFileCost / files.length).toFixed(3)}ms/file)`
  );
  assert.ok(
    perFileCost / files.length < 2,
    `D29 averaged ${(perFileCost / files.length).toFixed(3)}ms per file`
  );
});

test('perf: the shared parse cache prevents re-parsing across detectors', () => {
  _clearParseCache();
  const source = 'const a = 1;\nfunction b() { return a; }\n';

  const first = parseSource(source);
  assert.equal(_cacheSize(), 1);

  // A second detector asking for the same file gets the same AST object back
  // rather than paying for another acorn parse.
  const second = parseSource(source);
  assert.equal(first.ast, second.ast);
  assert.equal(_cacheSize(), 1);

  _clearParseCache();
});

test('perf: the parse cache stays bounded under many distinct files', () => {
  _clearParseCache();
  for (let i = 0; i < 1200; i++) {
    parseSource(`const v${i} = ${i};`);
  }
  // Bounded, not unbounded growth across a large tarball.
  assert.ok(_cacheSize() <= 400, `cache grew to ${_cacheSize()} entries`);
  _clearParseCache();
});

test('perf: detectors skip files larger than the configured cap', () => {
  const cap = thresholds['D29-RUNTIME-EVASION'].max_file_bytes;
  assert.equal(typeof cap, 'number');
  assert.ok(cap > 0 && cap <= 1024 * 1024, 'file cap should be present and modest');
  assert.equal(thresholds['D30-WORKSPACE-PERSISTENCE'].max_file_bytes, cap);
});
