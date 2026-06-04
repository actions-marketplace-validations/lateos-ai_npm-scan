#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { runAll } from '../detectors/index.js';

const CAMPAIGN_FIXTURES = {
  'campaign-1': 'fixtures/campaigns/campaign-1-dependency-confusion.jsonl',
  'campaign-2': 'fixtures/campaigns/campaign-2-mini-shai-hulud.jsonl',
  'campaign-3': 'fixtures/campaigns/campaign-3-bitwarden-impersonation.jsonl',
};

function loadFixture(filePath) {
  const abs = resolve(filePath);
  if (!existsSync(abs)) {
    console.error(`[ERROR] Fixture not found: ${abs}`);
    return [];
  }
  const text = readFileSync(abs, 'utf-8');
  return text
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

async function fetchNpmMetadata(pkgName, version) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}/${version}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) {
      return null;
    }
    return await response.json();
  } catch {
    console.warn(`  [WARN] Registry fetch failed for ${pkgName}@${version}; using fixture data`);
    return null;
  }
}

function constructRegistryMeta(pkg, liveMeta) {
  if (liveMeta) {
    return liveMeta;
  }
  if (pkg.mockRegistryMeta) {
    return pkg.mockRegistryMeta;
  }
  return null;
}

function constructPkgJson(pkg) {
  const base = { name: pkg.package, version: pkg.version };
  if (pkg.mockPackageJson) {
    return { ...base, ...pkg.mockPackageJson };
  }
  return base;
}

async function validateDetectors(campaigns, outputFile) {
  const allResults = [];

  const campaignKeys = campaigns === 'all' ? Object.keys(CAMPAIGN_FIXTURES) : [campaigns];

  for (const campaignKey of campaignKeys) {
    const fixturePath = CAMPAIGN_FIXTURES[campaignKey];
    if (!fixturePath) {
      console.error(`[ERROR] Unknown campaign: ${campaignKey}`);
      continue;
    }

    console.log(`\n[${new Date().toISOString()}] Validating ${campaignKey}...`);
    const packages = loadFixture(fixturePath);
    console.log(`  Loaded ${packages.length} packages from fixture`);

    for (const pkg of packages) {
      try {
        const pkgJson = constructPkgJson(pkg);
        const liveMeta = await fetchNpmMetadata(pkg.package, pkg.version);
        const registryMeta = constructRegistryMeta(pkg, liveMeta);

        const findings = await runAll(pkgJson, [], registryMeta, []);

        const detectedIds = [...new Set(findings.map((f) => f.id))];

        const result = {
          package: pkg.package,
          version: pkg.version,
          campaign_id: pkg.campaign_id,
          campaign_name: pkg.campaign_name,
          attack_vector: pkg.attack_vector,
          expected_detectors: pkg.expected_detectors,
          detected_detectors: detectedIds,
          detection_count: findings.length,
          detections: findings.map((f) => ({
            id: f.id,
            detector: f.detector,
            severity: f.severity,
            confidence: f.confidence,
            confidenceScore: f.confidenceScore,
            subtype: f.subtype,
            message: f.message,
          })),
          metadata_available: !!liveMeta,
          registry_source: liveMeta ? 'live' : 'fixture',
          timestamp: new Date().toISOString(),
        };

        allResults.push(result);

        const expectedCount = pkg.expected_detectors.length;
        const hitCount = detectedIds.filter((id) => pkg.expected_detectors.includes(id)).length;
        console.log(
          `  ${hitCount > 0 ? '✓' : '✗'} ${pkg.package}@${pkg.version}: ${hitCount}/${expectedCount} expected detectors fired`
        );
        for (const f of findings) {
          console.log(`      ${f.id} (${f.confidenceScore}%, ${f.severity})`);
        }
      } catch (err) {
        console.error(`  ✗ ${pkg.package}@${pkg.version}: ${err.message}`);
        allResults.push({
          package: pkg.package,
          version: pkg.version,
          campaign_id: pkg.campaign_id,
          error: err.message,
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  if (outputFile) {
    const lines = allResults.map((r) => JSON.stringify(r)).join('\n') + '\n';
    writeFileSync(outputFile, lines, 'utf-8');
  }

  const processed = allResults.filter((r) => !r.error).length;
  const errors = allResults.filter((r) => r.error).length;
  console.log(`\n[SUMMARY] Processed ${processed} packages, ${errors} errors`);
  console.log(`[INFO] Results written to ${outputFile}`);

  return allResults;
}

const args = process.argv.slice(2);
const campaignArg = args[0] || 'all';
const outputArg = args[1] ? resolve(args[1]) : resolve('validation-results.jsonl');

validateDetectors(campaignArg, outputArg)
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`[ERROR] ${err.message}`);
    process.exit(1);
  });
