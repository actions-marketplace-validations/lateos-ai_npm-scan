import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const THRESHOLDS = {
  flag_threshold: 70,
  warn_threshold: 50,
  known_c2_endpoints: [
    'filev2.getsession.org',
    'api.signal.org',
    '*.briarproject.org',
    'api.ricochet.im',
  ],
  onion_pattern_weight: 30,
  encoded_url_weight: 35,
  env_var_c2_weight: 40,
};

const KNOWN_C2_RE =
  /(?:filev2\.getsession\.org|api\.signal\.org|(?:[\w-]+\.)?briarproject\.org|api\.ricochet\.im|signal-cli|signal-desktop|tor\s*(?:proxy|socks|connect|bridge))/gi;
const ONION_RE = /(?:[a-z2-7]{16,56}\.onion|\.onion|tor\s*(?:proxy|socks|connect|bridge))/gi;
const ENCODED_URL_RE =
  /(?:atob|Buffer\.from|decodeURIComponent)\s*\((?:['"`][A-Za-z0-9+/=]{20,}['"`]|['"`](?:[0-9a-fA-F]{2,})['"`])/gi;
const HEX_DOMAIN_RE = /(?:0x[0-9a-fA-F]{2,}){4,}/g;
const SESSION_RE = /session|oxen|filev2|getsession/i;
const SIGNAL_RE = /signal|signal-cli|signal-desktop/i;
const BRIAR_RE = /briar|briarproject/i;

function detectC2InContent(content) {
  const findings = [];

  let match;
  KNOWN_C2_RE.lastIndex = 0;
  while ((match = KNOWN_C2_RE.exec(content)) !== null) {
    findings.push({
      type: 'known_endpoint',
      endpoint: match[0],
      weight: 80,
    });
  }

  ONION_RE.lastIndex = 0;
  while ((match = ONION_RE.exec(content)) !== null) {
    findings.push({
      type: 'onion_service',
      pattern: match[0],
      weight: THRESHOLDS.onion_pattern_weight,
    });
  }

  ENCODED_URL_RE.lastIndex = 0;
  while ((match = ENCODED_URL_RE.exec(content)) !== null) {
    findings.push({
      type: 'encoded_url',
      snippet: match[0].substring(0, 60),
      weight: THRESHOLDS.encoded_url_weight,
      encoding: match[0].includes('atob')
        ? 'base64'
        : match[0].includes('Buffer.from')
          ? 'hex_or_other'
          : 'other',
    });
  }

  HEX_DOMAIN_RE.lastIndex = 0;
  while ((match = HEX_DOMAIN_RE.exec(content)) !== null) {
    findings.push({
      type: 'hex_encoded_domain',
      snippet: match[0].substring(0, 40),
      weight: THRESHOLDS.encoded_url_weight,
      encoding: 'hex',
    });
  }

  return findings;
}

function computeConfidence(c2Findings, hasSession, hasSignal, hasBriar) {
  let base = 0;

  const totalWeight = c2Findings.reduce((s, f) => s + f.weight, 0);
  base += Math.min(totalWeight, 80);

  if (c2Findings.length === 0) {
    base = 20;
  }

  if (hasSession) base += 20;
  if (hasSignal) base += 20;
  if (hasBriar) base += 15;

  if (c2Findings.length > 0) {
    base += 20;
  }

  if (c2Findings.length > 1) {
    base += Math.min(c2Findings.length * 5, 15);
  }

  return Math.min(100, Math.max(0, base));
}

function severityLabel(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  return 'medium';
}

function confidenceLabel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  return 'MEDIUM';
}

export const name = 'tier1-encrypted-c2';

export async function scan(pkgJson, jsFiles, _registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const allContents = [];
  if (pkgJson?.scripts && typeof pkgJson.scripts === 'object') {
    for (const val of Object.values(pkgJson.scripts)) {
      if (typeof val === 'string') {
        allContents.push({ source: 'package.json scripts', content: val });
      }
    }
  }

  const files = jsFiles || [];
  for (const f of files) {
    if (f?.content) {
      allContents.push({ source: f.path || f.name || 'unknown', content: f.content });
    }
  }

  if (allContents.length === 0) return [];

  const hasSession = SESSION_RE.test(JSON.stringify(allContents.map((c) => c.content)));
  const hasSignal = SIGNAL_RE.test(JSON.stringify(allContents.map((c) => c.content)));
  const hasBriar = BRIAR_RE.test(JSON.stringify(allContents.map((c) => c.content)));

  const allFindings = [];
  for (const { source, content } of allContents) {
    const c2Findings = detectC2InContent(content);
    if (c2Findings.length > 0) {
      allFindings.push({ source, c2Findings });
    }
  }

  const flatC2 = allFindings.flatMap((f) => f.c2Findings);
  const totalSignals =
    flatC2.length + (hasSession ? 1 : 0) + (hasSignal ? 1 : 0) + (hasBriar ? 1 : 0);
  if (totalSignals === 0) return [];

  const confidenceScore = computeConfidence(flatC2, hasSession, hasSignal, hasBriar);
  if (confidenceScore < THRESHOLDS.warn_threshold) return [];

  const endpointTypes = [...new Set(flatC2.map((f) => f.type))];
  const primaryType = endpointTypes.includes('known_endpoint')
    ? 'known_endpoint'
    : endpointTypes.includes('onion_service')
      ? 'onion_service'
      : endpointTypes.includes('encoded_url')
        ? 'encoded_url'
        : endpointTypes.includes('hex_encoded_domain')
          ? 'hex_encoded_domain'
          : 'protocol_signal';

  const evidence = flatC2.map((f) => {
    if (f.type === 'known_endpoint') return `c2_endpoint: ${f.endpoint}`;
    if (f.type === 'onion_service') return `onion_pattern: ${f.pattern}`;
    return `encoded: ${f.snippet}`;
  });

  if (hasSession) evidence.push('protocol: Session/Oxen messenger');
  if (hasSignal) evidence.push('protocol: Signal messenger');
  if (hasBriar) evidence.push('protocol: Briar project');

  const locations =
    allFindings.length > 0
      ? allFindings.map((f) => ({ file: f.source, line: 1, column: 1 })).slice(0, 5)
      : [{ file: 'package.json', line: 1, column: 1 }];

  return [
    {
      detector: 'tier1-encrypted-c2',
      id: 'TIER1-ENCRYPTED-C2',
      severity: severityLabel(confidenceScore),
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype: primaryType,
      message: `${flatC2.length > 0 ? flatC2.length + ' encrypted C2 signal(s)' : 'Encrypted C2 protocol(s) detected'}${hasSession || hasSignal || hasBriar ? ' (' + [hasSession ? 'Session' : '', hasSignal ? 'Signal' : '', hasBriar ? 'Briar' : ''].filter(Boolean).join(', ') + ')' : ''}`,
      evidence: evidence.slice(0, 8),
      locations,
      crossFiles: [],
      reference: 'D11: TanStack Mini Shai-Hulud encrypted C2',
    },
  ];
}
