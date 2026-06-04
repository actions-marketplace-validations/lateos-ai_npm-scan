import { MegalodonSignal } from './types.js';

const CRED_PATTERNS = [
  { pattern: /\bAWS_(SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)\b/, label: 'AWS credential' },
  { pattern: /\bGOOGLE_APPLICATION_CREDENTIALS\b/, label: 'GCP credential' },
  {
    pattern: /\bAZURE_(CLIENT_SECRET|TENANT_ID|CLIENT_ID|SUBSCRIPTION_ID)\b/,
    label: 'Azure credential',
  },
  { pattern: /\bGH_(TOKEN|PAT)\b/, label: 'GitHub PAT' },
  { pattern: /\bGITHUB_TOKEN\b/, label: 'GitHub token' },
  { pattern: /\bNPM_TOKEN\b/, label: 'npm token' },
  { pattern: /\bDISCORD_TOKEN\b/, label: 'Discord token' },
  { pattern: /\bSLACK_TOKEN\b/, label: 'Slack token' },
  { pattern: /\bSTRIPE_(SECRET|PUBLISHABLE)_KEY\b/, label: 'Stripe key' },
  { pattern: /\bTWILIO_(ACCOUNT_SID|AUTH_TOKEN)\b/, label: 'Twilio credential' },
  { pattern: /\bDB_(USERNAME|PASSWORD|URL)\b/, label: 'Database credential' },
  { pattern: /\bMONGO_(URI|URL|CONNECTION)\b/, label: 'MongoDB connection' },
];

const OUTBOUND_NET_RE =
  /curl\s+|wget\s+|fetch\s*\(|https?\.request\s*\(|http\.request\s*\(|got\s*\(|axios\s*\.|request\s*\(|node-fetch|\.post\s*\(|\.get\s*\(/i;

const TARGET_EXTENSIONS = ['.sh', '.bash', '.yml', '.yaml', '.js'];

function isTargetFile(f) {
  const ext = f.path.slice(f.path.lastIndexOf('.')).toLowerCase();
  return TARGET_EXTENSIONS.includes(ext);
}

export async function scan(allFiles) {
  const evidence = [];
  const targetFiles = allFiles.filter(isTargetFile);

  for (const f of targetFiles) {
    const content = f.content;
    let score = 0;
    const matched = [];

    for (const cp of CRED_PATTERNS) {
      const re = new RegExp(cp.pattern.source, 'gi');
      let m;
      while ((m = re.exec(content)) !== null) {
        if (!matched.some((ex) => ex.label === cp.label)) {
          matched.push({ label: cp.label, match: m[0] });
        }
        score += 3;
      }
    }

    if (score > 0) {
      const hasNetwork = OUTBOUND_NET_RE.test(content);
      if (hasNetwork) {
        evidence.push({
          signal: MegalodonSignal.CREDENTIAL_HARVEST,
          file: f.path,
          excerpt: matched
            .map((m) => m.label)
            .join(', ')
            .slice(0, 120),
          detail: `Credential env vars (${matched.map((m) => m.label).join(', ')}) co-occur with outbound network call (score: ${score})`,
        });
      }
    }
  }

  return evidence;
}
