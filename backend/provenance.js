import { createHash, createHmac } from 'crypto';

const PROVENANCE_VERSION = 'aureus-v1.7';

const HMAC_KEY = process.env.AUREUS_HMAC_KEY || '@lateos/npm-scan:provenance:v1';

export function hashContent(content) {
  return createHash('sha256').update(JSON.stringify(content)).digest('hex');
}

export function signManifest(manifest, key = HMAC_KEY) {
  return createHmac('sha256', key).update(JSON.stringify(manifest)).digest('hex');
}

export function buildDetectionRule({ ruleId, ruleName, severity, cveReferences = [], campaignName }) {
  return {
    rule_id: ruleId,
    rule_name: ruleName,
    severity,
    cve_references: cveReferences,
    campaign_name: campaignName,
  };
}

export function buildScanMetadata({ scannerVersion, packageAnalyzed }) {
  return {
    scan_timestamp: new Date().toISOString(),
    scanner_version: scannerVersion || '@lateos/npm-scan',
    pipeline_version: PROVENANCE_VERSION,
    package_analyzed: packageAnalyzed,
  };
}

export function buildDetectionResult({ triggered, severity, indicators = [] }) {
  return {
    triggered,
    severity,
    indicators,
  };
}

export function buildAuditTrail({ detectionLogic, ruleProvenanceUrl, campaignSourceUrl }) {
  const contentHash = hashContent(detectionLogic);
  const manifest = { contentHash, ruleProvenanceUrl, campaignSourceUrl, generatedAt: new Date().toISOString() };
  return {
    content_hash: contentHash,
    rule_provenance_url: ruleProvenanceUrl,
    campaign_source_url: campaignSourceUrl,
    hmac_signature: signManifest(manifest),
    _manifest: manifest,
  };
}

export function buildDetectionRecord({ rule, scanMetadata, detectionResult, auditTrail }) {
  return {
    detection_rule: rule,
    scan_metadata: scanMetadata,
    detection_result: detectionResult,
    audit_trail: auditTrail,
  };
}

export function attachProvenance(evidence, { ruleId, ruleName, severity, campaignName, pkgName, pkgVersion, triggered, indicators, ruleProvenanceUrl, campaignSourceUrl }) {
  const rule = buildDetectionRule({ ruleId, ruleName, severity, campaignName });
  const scanMetadata = buildScanMetadata({
    scannerVersion: '@lateos/npm-scan',
    packageAnalyzed: `${pkgName}@${pkgVersion}`,
  });
  const detectionResult = buildDetectionResult({ triggered, severity, indicators });
  const auditTrail = buildAuditTrail({
    detectionLogic: { rule, indicators },
    ruleProvenanceUrl,
    campaignSourceUrl,
  });
  const record = buildDetectionRecord({ rule, scanMetadata, detectionResult, auditTrail });
  return { ...evidence, _provenance: record };
}

export { PROVENANCE_VERSION };
