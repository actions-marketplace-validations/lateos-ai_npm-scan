import { checkBurstPublish } from './detectors/burst-publish.js';
import { checkPublisherAnomaly } from './detectors/publisher-anomaly.js';
import { checkActivationEventRisk } from './detectors/activation-event-risk.js';
import { checkOrphanCommitFetch } from './detectors/orphan-commit-fetch.js';
import { checkKnownIOC } from './detectors/known-ioc.js';
import { checkExfilPattern } from './detectors/exfil-pattern.js';
import { getExtensionMetadata, getVersionHistory, getPublisherProfile, getOpenVsxMetadata, getOpenVsxVersionHistory } from './marketplace-client.js';

const SEVERITY_SCORE = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SEVERITY_LABELS = ['none', 'low', 'medium', 'high', 'critical'];

export async function vsixScan(extensionId, options = {}) {
  const { publisherId, extensionName } = parseExtensionId(extensionId);

  const marketplaceMeta = options.marketplaceMeta || (options.skipNetwork ? null : await getExtensionMetadata(publisherId, extensionName));
  const marketplaceVersions = options.marketplaceVersions || (marketplaceMeta ? await getVersionHistory(publisherId, extensionName) : []);
  const openVsxVersions = options.openVsxVersions || (options.skipNetwork ? [] : await getOpenVsxVersionHistory(publisherId, extensionName));
  const publisherProfile = options.publisherProfile || (options.skipNetwork ? null : await getPublisherProfile(publisherId));

  const allVersions = mergeVersionHistories(marketplaceVersions, openVsxVersions);
  const manifest = options.manifest || extractManifest(marketplaceMeta, extensionId);

  const config = options.config || {};

  const activationResult = await checkActivationEventRisk(
    manifest,
    allVersions,
    options.priorVersions || [],
  );

  const burstResult = await checkBurstPublish(allVersions, config);

  const publisherResult = await checkPublisherAnomaly(
    manifest || {},
    publisherProfile || {},
    allVersions,
    config,
  );

  const orphanResult = await checkOrphanCommitFetch(options.extensionFiles || []);

  const iocResult = await checkKnownIOC(
    extensionId,
    options.version || (allVersions.length > 0 ? allVersions[allVersions.length - 1].version : 'unknown'),
    publisherId,
    orphanResult.signals
      .filter(s => s.type === 'ORPHAN_COMMIT_GITHUB_API')
      .map(s => s.indicator),
    allVersions,
  );

  const exfilResult = await checkExfilPattern(options.extensionFiles || []);

  const triggeredSignals = [];
  if (burstResult.triggered) triggeredSignals.push('VSIX_BURST_PUBLISH');
  if (publisherResult.triggered) triggeredSignals.push('VSIX_PUBLISHER_ANOMALY');
  if (activationResult.triggered) triggeredSignals.push('VSIX_ACTIVATION_EVENT_RISK');
  if (orphanResult.triggered) triggeredSignals.push('VSIX_ORPHAN_COMMIT_FETCH');
  if (iocResult.triggered) triggeredSignals.push('VSIX_KNOWN_IOC');
  if (exfilResult.triggered) triggeredSignals.push('VSIX_EXFIL_PATTERN');

  if (triggeredSignals.length === 0) return [];

  const registryLabels = [];
  if (marketplaceVersions.length > 0) registryLabels.push('marketplace');
  if (openVsxVersions.length > 0) registryLabels.push('open-vsx');

  const maxSeverity = triggeredSignals.reduce((max, s) => {
    if (s === 'VSIX_KNOWN_IOC' || s === 'VSIX_ORPHAN_COMMIT_FETCH') return Math.max(max, 4);
    if (s === 'VSIX_BURST_PUBLISH' || s === 'VSIX_PUBLISHER_ANOMALY' || s === 'VSIX_EXFIL_PATTERN') return Math.max(max, 3);
    if (s === 'VSIX_ACTIVATION_EVENT_RISK') return Math.max(max, 3);
    return max;
  }, 0);

  const finalSeverity = SEVERITY_LABELS[maxSeverity] || 'high';

  const latestVersion = allVersions.length > 0 ? allVersions[allVersions.length - 1].version : 'unknown';
  let exposureWindowMinutes = null;
  if (burstResult.hotPullDetected && allVersions.length >= 2) {
    const sorted = [...allVersions].sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));
    const gap = (new Date(sorted[0].publishedAt) - new Date(sorted[1].publishedAt)) / (1000 * 60);
    exposureWindowMinutes = Math.round(gap);
  }

  const evidence = {
    extensionId,
    maliciousVersion: latestVersion,
    registries: registryLabels,
    exposureWindowMinutes,
    triggeredSignals,
    burstWindow: burstResult.burstWindow,
    hotPullDetected: burstResult.hotPullDetected,
    publisherSignals: publisherResult.triggered ? publisherResult.signals : null,
    activationEvents: manifest?.activationEvents || null,
    activationRisk: activationResult.triggered ? { riskLevel: activationResult.riskLevel, why: activationResult.why } : null,
    orphanCommitIndicators: orphanResult.triggered ? orphanResult.indicators : null,
    iocMatches: iocResult.triggered ? iocResult.matches : null,
    exfilPatterns: exfilResult.triggered ? exfilResult.exfilPatterns : null,
    antiAnalysisTechniques: exfilResult.triggered ? exfilResult.antiAnalysisTechniques : null,
  };

  const remediationGuidance = buildRemediation(triggeredSignals, extensionId);

  return [{
    id: 'VSIX_SCAN',
    severity: finalSeverity,
    title: `VS Code extension risk: ${extensionId}`,
    description: `${triggeredSignals.length} signal(s): ${triggeredSignals.join(', ')}`,
    evidence: JSON.stringify(evidence),
    mitigation: remediationGuidance,
  }];
}

function parseExtensionId(id) {
  const idx = id.indexOf('.');
  if (idx === -1 || idx === 0 || idx === id.length - 1) {
    throw new Error(`Invalid extension ID: ${id}. Expected format: publisher.extension-name`);
  }
  return { publisherId: id.slice(0, idx), extensionName: id.slice(idx + 1) };
}

function mergeVersionHistories(marketplace, openVsx) {
  const seen = new Set();
  const merged = [];

  for (const v of marketplace) {
    if (!seen.has(v.version)) {
      seen.add(v.version);
      merged.push({ ...v, registries: ['marketplace'] });
    }
  }

  for (const v of openVsx) {
    if (!seen.has(v.version)) {
      seen.add(v.version);
      merged.push({ ...v, registries: ['open-vsx'] });
    } else {
      const existing = merged.find(m => m.version === v.version);
      if (existing) {
        existing.registries.push('open-vsx');
      }
    }
  }

  return merged.sort((a, b) => new Date(a.publishedAt) - new Date(b.publishedAt));
}

function extractManifest(marketplaceMeta, extensionId) {
  if (!marketplaceMeta?.results?.[0]?.extensions?.[0]) return {};
  const ext = marketplaceMeta.results[0].extensions[0];
  const manifestStr = ext.galleryApiUrl || ext.manifest;
  if (!manifestStr) return {};

  try {
    if (typeof manifestStr === 'object') return manifestStr;
    return JSON.parse(manifestStr);
  } catch {
    return {};
  }
}

function buildRemediation(triggeredSignals, extensionId) {
  const parts = [];
  if (triggeredSignals.includes('VSIX_KNOWN_IOC')) {
    parts.push(`Extension ${extensionId} matches known campaign IOC. Remove immediately.`);
  }
  if (triggeredSignals.includes('VSIX_BURST_PUBLISH')) {
    parts.push('Suspicious publish velocity detected. Verify publisher release history.');
  }
  if (triggeredSignals.includes('VSIX_PUBLISHER_ANOMALY')) {
    parts.push('Publisher account anomaly detected. Verify publisher identity.');
  }
  if (triggeredSignals.includes('VSIX_ACTIVATION_EVENT_RISK')) {
    parts.push('Risky activation events detected. Review extension activation scope.');
  }
  if (triggeredSignals.includes('VSIX_ORPHAN_COMMIT_FETCH')) {
    parts.push('Dangling orphan commit fetch detected — technical signature of Nx Console attack.');
  }
  if (triggeredSignals.includes('VSIX_EXFIL_PATTERN')) {
    parts.push('Credential exfiltration patterns detected. Revoke all tokens.');
  }
  return parts.join(' ');
}
