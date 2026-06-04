const GCP_PATTERNS = [
  'metadata.google.internal',
  'computeMetadata/v1',
  'metadata.google.internal/computeMetadata',
];

const AZURE_PATTERNS = ['169.254.169.254/metadata/instance', '169.254.169.254/metadata/identity'];

const AZURE_IP = '169.254.169.254';
const METADATA_HEADER_RE = /Metadata\s*:\s*true/i;

function severityLabel(score) {
  if (score >= 80) {
    return 'high';
  }
  return 'medium';
}

function confidenceLabel(score) {
  if (score >= 80) {
    return 'HIGH';
  }
  if (score >= 60) {
    return 'MEDIUM';
  }
  return 'LOW';
}

function hasGcpPattern(text) {
  return GCP_PATTERNS.some((p) => text.includes(p));
}

function hasAzurePath(text) {
  return AZURE_PATTERNS.some((p) => text.includes(p));
}

function hasAzureHeaderPattern(text) {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes(AZURE_IP)) {
      continue;
    }
    const start = Math.max(0, i - 5);
    const end = Math.min(lines.length, i + 6);
    for (let j = start; j < end; j++) {
      if (METADATA_HEADER_RE.test(lines[j])) {
        return true;
      }
    }
  }
  return false;
}

function hasAzurePattern(text) {
  return hasAzurePath(text) || hasAzureHeaderPattern(text);
}

function collectTexts(pkgJson, jsFiles) {
  const texts = [];

  if (pkgJson?.scripts && typeof pkgJson.scripts === 'object') {
    for (const value of Object.values(pkgJson.scripts)) {
      if (typeof value === 'string') {
        texts.push(value);
      }
    }
  }

  if (jsFiles && Array.isArray(jsFiles)) {
    for (const file of jsFiles) {
      if (file?.content && typeof file.content === 'string') {
        texts.push(file.content);
      }
    }
  }

  return texts;
}

export const name = 'tier1-cloud-imds';

export async function scan(pkgJson, jsFiles, _registryMeta, _allFiles) {
  const texts = collectTexts(pkgJson, jsFiles);
  if (texts.length === 0) {
    return [];
  }

  let hasGcp = false;
  let hasAzure = false;

  for (const text of texts) {
    if (!hasGcp && hasGcpPattern(text)) {
      hasGcp = true;
    }
    if (!hasAzure && hasAzurePattern(text)) {
      hasAzure = true;
    }
    if (hasGcp && hasAzure) {
      break;
    }
  }

  if (!hasGcp && !hasAzure) {
    return [];
  }

  let confidenceScore;
  let subtype;

  if (hasGcp && hasAzure) {
    confidenceScore = 92;
    subtype = 'multi_cloud_imds';
  } else if (hasGcp) {
    confidenceScore = 82;
    subtype = 'gcp_metadata';
  } else {
    confidenceScore = 82;
    subtype = 'azure_imds';
  }

  return [
    {
      detector: 'tier1-cloud-imds',
      id: 'TIER1-CLOUD-IMDS',
      severity: severityLabel(confidenceScore),
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype,
      message:
        hasGcp && hasAzure
          ? `Package references both GCP metadata and Azure IMDS endpoints — cloud credential harvesting`
          : hasGcp
            ? `Package references GCP metadata server endpoint — cloud credential harvesting`
            : `Package references Azure IMDS endpoint — cloud credential harvesting`,
      evidence: [
        ...(hasGcp ? ['gcp: metadata.google.internal / computeMetadata/v1 pattern detected'] : []),
        ...(hasAzure ? ['azure: 169.254.169.254/metadata pattern detected'] : []),
      ],
      crossFiles: [],
      locations: [{ file: '', line: 0 }],
      reference: 'Miasma Cloud IMDS',
    },
  ];
}
