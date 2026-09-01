#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { runAll } from '../detectors/index.js';
import whitelist from '../detectors/config/whitelist.json' with { type: 'json' };

const WHITELIST_MAP = new Map();
for (const entry of whitelist.packages) {
  WHITELIST_MAP.set(entry.name, new Set(entry.detectors));
}

async function detectFalsePositives(topPackagesFile, confidenceThreshold = 70) {
  const absPath = resolve(topPackagesFile);
  if (!existsSync(absPath)) {
    console.error(`[ERROR] Top packages file not found: ${absPath}`);
    console.error('       Run fetch-top-packages.js first');
    process.exit(1);
  }

  const text = readFileSync(absPath, 'utf-8');
  const lines = text.split('\n').filter((l) => l.trim());
  console.log(`[INFO] Loaded ${lines.length} packages from ${topPackagesFile}`);

  const falsePositives = [];
  let count = 0;
  let skipped = 0;

  for (const line of lines) {
    const pkg = JSON.parse(line);
    count += 1;

    const pkgName = pkg.name;
    const whitelistedDetectors = WHITELIST_MAP.get(pkgName);

    if (whitelistedDetectors) {
      skipped += 1;
      if (count % 200 === 0 || count <= 5) {
        console.log(`[SKIP] ${pkgName} (whitelisted for ${[...whitelistedDetectors].join(', ')})`);
      }
    } else {
      if (count % 100 === 0) {
        console.log(`[PROGRESS] Processed ${count}/${lines.length} packages...`);
      }
    }

    try {
      const pkgJson = { name: pkgName, version: pkg.version };
      const findings = await runAll(pkgJson, [], null, []);

      for (const detection of findings) {
        if (detection.confidenceScore < confidenceThreshold) {
          continue;
        }
        if (whitelistedDetectors && whitelistedDetectors.has(detection.id)) {
          continue;
        }

        falsePositives.push({
          package: pkgName,
          version: pkg.version,
          detector: detection.id,
          confidence: detection.confidenceScore,
          severity: detection.severity,
          subtype: detection.subtype,
          message: detection.message,
          evidence: detection.evidence,
          timestamp: new Date().toISOString(),
        });

        if (falsePositives.length <= 10) {
          console.log(
            `[FLAG] ${pkgName}@${pkg.version}: ${detection.id} (${detection.confidenceScore}%)`
          );
        }
      }
    } catch (err) {
      console.error(`[ERROR] ${pkgName}: ${err.message}`);
    }
  }

  const outPath = resolve('false-positives.jsonl');
  const outputData = falsePositives.map((fp) => JSON.stringify(fp)).join('\n') + '\n';
  writeFileSync(outPath, outputData, 'utf-8');

  const scannedCount = count - skipped;
  console.log(`\n[SUMMARY] Scanned ${scannedCount} packages (skipped ${skipped} whitelisted)`);
  console.log(
    `[SUMMARY] Found ${falsePositives.length} potential false positives (${((falsePositives.length / scannedCount) * 100).toFixed(1)}% FP rate)`
  );
  console.log(`[INFO] Written to ${outPath}`);

  return falsePositives;
}

const topPackagesFile = process.argv[2] || 'top-packages.jsonl';
const confidenceThreshold = parseInt(process.argv[3]) || 70;

detectFalsePositives(topPackagesFile, confidenceThreshold)
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`[FATAL] ${err.message}`);
    process.exit(1);
  });
