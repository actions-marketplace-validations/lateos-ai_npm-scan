#!/usr/bin/env node
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function analyzeFalsePositives(fpFile) {
  const analysis = {
    total_fps: 0,
    scanned_packages: 0,
    fp_rate: '0%',
    detectors: {},
    high_fp_detectors: [],
    recommendations: [],
    per_package: {},
  };

  const absPath = resolve(fpFile);
  if (!existsSync(absPath)) {
    console.error(`[ERROR] False positives file not found: ${absPath}`);
    process.exit(1);
  }

  const text = readFileSync(absPath, 'utf-8');
  const lines = text.split('\n').filter((l) => l.trim());

  for (const line of lines) {
    const fp = JSON.parse(line);
    analysis.total_fps += 1;

    const detector = fp.detector;
    if (!analysis.detectors[detector]) {
      analysis.detectors[detector] = {
        fp_count: 0,
        avg_confidence: 0,
        confidences: [],
        severities: [],
        examples: [],
        unique_packages: new Set(),
      };
    }

    analysis.detectors[detector].fp_count += 1;
    analysis.detectors[detector].confidences.push(fp.confidence);
    analysis.detectors[detector].severities.push(fp.severity);
    analysis.detectors[detector].unique_packages.add(fp.package);

    if (analysis.detectors[detector].examples.length < 5) {
      analysis.detectors[detector].examples.push({
        package: fp.package,
        version: fp.version,
        confidence: fp.confidence,
        subtype: fp.subtype,
      });
    }

    if (!analysis.per_package[fp.package]) {
      analysis.per_package[fp.package] = [];
    }
    analysis.per_package[fp.package].push({
      detector: fp.detector,
      confidence: fp.confidence,
      version: fp.version,
    });
  }

  for (const [detectorName, stats] of Object.entries(analysis.detectors)) {
    stats.avg_confidence =
      stats.confidences.length > 0
        ? (stats.confidences.reduce((a, b) => a + b, 0) / stats.confidences.length).toFixed(1)
        : '0.0';
    stats.unique_package_count = stats.unique_packages.size;
    delete stats.unique_packages;

    const fpShare = ((stats.fp_count / analysis.total_fps) * 100).toFixed(1);

    if (stats.fp_count >= 5) {
      analysis.high_fp_detectors.push(detectorName);
      analysis.recommendations.push({
        detector: detectorName,
        fp_count: stats.fp_count,
        unique_packages: stats.unique_package_count,
        share_of_total_fps: fpShare + '%',
        avg_confidence: stats.avg_confidence,
        severity_distribution: stats.severities.reduce((acc, s) => {
          acc[s] = (acc[s] || 0) + 1;
          return acc;
        }, {}),
        suggested_action: `Increase confidence threshold from current to ${Math.min(100, Math.ceil(parseFloat(stats.avg_confidence)) + 5)}`,
        examples: stats.examples,
      });
    }
  }

  return analysis;
}

const fpFile = process.argv[2] || 'false-positives.jsonl';

console.log(`[INFO] Analyzing ${fpFile}...`);
const analysis = analyzeFalsePositives(fpFile);

console.log('\n=== FALSE POSITIVE ANALYSIS ===');
console.log(`Total FPs: ${analysis.total_fps}`);
console.log(`Detectors with FPs: ${Object.keys(analysis.detectors).length}`);

if (analysis.high_fp_detectors.length > 0) {
  console.log(`\nHigh-FP detectors (>= 5 FPs): ${analysis.high_fp_detectors.join(', ')}`);
} else {
  console.log('\nNo high-FP detectors found (all < 5 FPs) — thresholds are well-calibrated');
}

console.log('\n=== PER-DETECTOR BREAKDOWN ===');
console.log('Detector                          FPs  UniquePkgs  AvgConf  Top Examples');
console.log('─'.repeat(90));
for (const [name, stats] of Object.entries(analysis.detectors).sort(
  (a, b) => b[1].fp_count - a[1].fp_count
)) {
  const dName = name.padEnd(32).slice(0, 32);
  const examples = stats.examples
    .slice(0, 2)
    .map((e) => e.package)
    .join(', ');
  console.log(
    `${dName} ${String(stats.fp_count).padStart(4)} ${String(stats.unique_package_count).padStart(11)} ` +
      `${stats.avg_confidence.padStart(7)}  ${examples}`
  );
}

if (analysis.recommendations.length > 0) {
  console.log('\n=== RECOMMENDATIONS ===');
  for (const rec of analysis.recommendations) {
    console.log(`\n${rec.detector}:`);
    console.log(
      `  FPs: ${rec.fp_count} (${rec.share_of_total_fps} of total) across ${rec.unique_packages} unique packages`
    );
    console.log(`  Avg confidence: ${rec.avg_confidence}`);
    console.log(`  Severity breakdown: ${JSON.stringify(rec.severity_distribution)}`);
    console.log(`  Suggestion: ${rec.suggested_action}`);
    console.log(`  Examples:`);
    for (const ex of rec.examples.slice(0, 3)) {
      console.log(`    ${ex.package}@${ex.version} (${ex.confidence}%) [${ex.subtype}]`);
    }
  }
} else {
  console.log('\n=== RECOMMENDATIONS ===');
  console.log('No threshold adjustments needed — FP rates are within acceptable bounds.');
}

const outPath = resolve('fp-analysis.json');
writeFileSync(outPath, JSON.stringify(analysis, null, 2), 'utf-8');
console.log(`\n[INFO] Full analysis written to ${outPath}`);

process.exit(0);
