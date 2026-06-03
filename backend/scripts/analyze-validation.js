#!/usr/bin/env node
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

async function analyzeValidation(resultsFile) {
  const stats = {
    total_packages: 0,
    total_detections: 0,
    total_expected: 0,
    total_matched: 0,
    campaigns: {},
    detectors: {},
    detection_matrix: {},
  };

  const absPath = resolve(resultsFile);
  if (!existsSync(absPath)) {
    console.error(`[ERROR] Results file not found: ${absPath}`);
    process.exit(1);
  }

  const text = readFileSync(absPath, 'utf-8');
  const lines = text.split('\n').filter(l => l.trim());

  for (const line of lines) {
    const result = JSON.parse(line);
    if (result.error) continue;

    stats.total_packages += 1;
    stats.total_detections += result.detection_count;

    const campaignId = result.campaign_id;
    if (!stats.campaigns[campaignId]) {
      stats.campaigns[campaignId] = {
        name: result.campaign_name,
        total: 0,
        detected: 0,
        detection_rate: 0,
        total_expected: 0,
        total_matched: 0,
        avg_confidence: 0,
        confidences: [],
      };
    }

    const campaign = stats.campaigns[campaignId];
    campaign.total += 1;
    campaign.total_expected += result.expected_detectors.length;

    const matched = result.expected_detectors.filter(
      id => result.detected_detectors.includes(id)
    );
    campaign.total_matched += matched.length;
    stats.total_expected += result.expected_detectors.length;
    stats.total_matched += matched.length;

    if (matched.length > 0) {
      campaign.detected += 1;
    }

    for (const detection of result.detections) {
      const detectorName = detection.id || detection.detector;
      if (!stats.detectors[detectorName]) {
        stats.detectors[detectorName] = {
          total_hits: 0,
          expected_count: 0,
          avg_confidence: 0,
          confidences: [],
          severities: [],
        };
      }

      stats.detectors[detectorName].total_hits += 1;
      stats.detectors[detectorName].confidences.push(detection.confidenceScore);
      stats.detectors[detectorName].severities.push(detection.severity);

      if (result.expected_detectors.includes(detectorName)) {
        stats.detectors[detectorName].expected_count += 1;
      }

      if (!stats.detection_matrix[campaignId]) {
        stats.detection_matrix[campaignId] = {};
      }
      if (!stats.detection_matrix[campaignId][detectorName]) {
        stats.detection_matrix[campaignId][detectorName] = 0;
      }
      stats.detection_matrix[campaignId][detectorName] += 1;
    }
  }

  for (const campaignId of Object.keys(stats.campaigns)) {
    const campaign = stats.campaigns[campaignId];
    campaign.detection_rate = campaign.total > 0
      ? ((campaign.detected / campaign.total) * 100).toFixed(1) + '%'
      : '0%';
    campaign.expected_match_rate = campaign.total_expected > 0
      ? ((campaign.total_matched / campaign.total_expected) * 100).toFixed(1) + '%'
      : '0%';
  }

  for (const detectorName of Object.keys(stats.detectors)) {
    const detector = stats.detectors[detectorName];
    detector.avg_confidence = detector.confidences.length > 0
      ? (detector.confidences.reduce((a, b) => a + b, 0) / detector.confidences.length).toFixed(1)
      : '0.0';
    detector.precision = detector.total_hits > 0
      ? ((detector.expected_count / detector.total_hits) * 100).toFixed(1) + '%'
      : '0%';
  }

  return stats;
}

const resultsFile = process.argv[2] || 'validation-results.jsonl';

console.log(`[INFO] Analyzing ${resultsFile}...`);
const stats = await analyzeValidation(resultsFile);

console.log('\n=== CAMPAIGN DETECTION RATES ===');
console.log('Campaign                         Packages  Detected  Rate     Expected  Matched  Match%');
console.log('─'.repeat(95));
for (const [id, campaign] of Object.entries(stats.campaigns)) {
  const name = campaign.name.padEnd(33).slice(0, 33);
  console.log(
    `${name} ${String(campaign.total).padStart(8)} ${String(campaign.detected).padStart(9)} ` +
    `${campaign.detection_rate.padStart(7)} ${String(campaign.total_expected).padStart(9)} ` +
    `${String(campaign.total_matched).padStart(8)} ${campaign.expected_match_rate.padStart(7)}`
  );
}
console.log(`\nTotal: ${stats.total_packages} packages, ${stats.total_detections} detections`);

console.log('\n=== DETECTOR PERFORMANCE ===');
console.log('Detector                          Hits  Expected  Precision  Avg Confidence');
console.log('─'.repeat(80));
for (const [name, detector] of Object.entries(stats.detectors).sort(
  (a, b) => b[1].total_hits - a[1].total_hits
)) {
  const dName = name.padEnd(32).slice(0, 32);
  console.log(
    `${dName} ${String(detector.total_hits).padStart(5)} ${String(detector.expected_count).padStart(9)} ` +
    `${detector.precision.padStart(10)} ${detector.avg_confidence.padStart(14)}`
  );
}

console.log('\n=== DETECTION MATRIX (Hits per Campaign × Detector) ===');
console.log(JSON.stringify(stats.detection_matrix, null, 2));

writeFileSync('detection-rates.json', JSON.stringify(stats, null, 2), 'utf-8');
console.log('\n[INFO] Full results written to detection-rates.json');

process.exit(0);
