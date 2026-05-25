const CREDENTIAL_FILE_PATTERNS = [
  /~\/\.npmrc/,
  /~\/\.gitconfig/,
  /~\/\.aws\/credentials/,
  /~\/\.ssh\/id_\w+/,
  /~\/\.vault-token/,
  /~\/\.claude\/settings\.json/,
  /~\/Library\/Application\s+Support\/1Password\//,
  /\/etc\/vault\/token/,
  /\/proc\/\*\/mem/,
  /\$GITHUB_ENV/,
  /\$GITHUB_TOKEN/,
  /\$NPM_TOKEN/,
  /\$NODE_AUTH_TOKEN/,
  /GH_TOKEN/,
];

const EXFIL_CHANNEL_PATTERNS = [
  /(?:[a-z0-9_-]{40,})\.[a-z0-9_-]+\.(?:com|io|org|net|app|dev|xyz)(?:\/[^\s"')\]]{0,50})?/i,
  /\/gists\b.*authorization/i,
  /\/repos\/[^/]+\/[^/]+\/git\/refs/i,
  /AES-256-GCM/,
  /RSA\/(?:PKCS|OAEP)/,
];

const ANTI_ANALYSIS_PATTERNS = [
  { pattern: /os\.cpus\(\)\.length\s*<\s*4/, label: 'CPU core count check (< 4)' },
  { pattern: /Intl\.DateTimeFormat.*(?:timeZone|locale)/, label: 'Timezone/locale check' },
  { pattern: /Intl\.DateTimeFormat.*\b(?:ru|rus|kz|by|cn|cns)\b/i, label: 'CIS/locale filtering' },
  { pattern: /\bspawn\(\s*[^,]+,\s*\{[^}]*detached:\s*true\s*\}/, label: 'Detached process spawn' },
  { pattern: /\bBUN_INSTALL\b/, label: 'BUN_INSTALL env reference' },
  { pattern: /~\/\.bun\/bin\/bun/, label: 'Bun binary path' },
  { pattern: /\bBun\.file\(/, label: 'Bun.file() API' },
  { pattern: /\bBun\.serve\(/, label: 'Bun.serve() API' },
];

function truncateSnippet(str, maxLen = 200) {
  if (!str || str.length <= maxLen) return str || '';
  return str.slice(0, maxLen) + '...';
}

export async function checkExfilPattern(extensionFiles = []) {
  const signals = [];
  const exfilPatterns = [];
  const antiAnalysisTechniques = [];

  for (const file of extensionFiles) {
    const content = typeof file.content === 'string' ? file.content : '';
    if (!content) continue;
    const path = file.path || '';

    for (const cp of CREDENTIAL_FILE_PATTERNS) {
      const match = content.match(cp);
      if (match) {
        const snippet = truncateSnippet(match[0]);
        if (!exfilPatterns.some(e => e.includes(snippet))) {
          exfilPatterns.push(`${path}: ${snippet}`);
          signals.push({ type: 'CREDENTIAL_FILE_TARGET', pattern: cp.source, file: path });
        }
      }
    }

    for (const ep of EXFIL_CHANNEL_PATTERNS) {
      const match = content.match(ep);
      if (match) {
        const snippet = truncateSnippet(match[0]);
        exfilPatterns.push(`${path}: ${snippet}`);
        signals.push({ type: 'EXFIL_CHANNEL', pattern: ep.source, file: path });
      }
    }

    for (const ap of ANTI_ANALYSIS_PATTERNS) {
      if (ap.pattern.test(content)) {
        if (!antiAnalysisTechniques.includes(ap.label)) {
          antiAnalysisTechniques.push(ap.label);
          signals.push({ type: 'ANTI_ANALYSIS', technique: ap.label, file: path });
        }
      }
    }
  }

  return {
    triggered: signals.length > 0,
    signals,
    exfilPatterns,
    antiAnalysisTechniques,
  };
}
