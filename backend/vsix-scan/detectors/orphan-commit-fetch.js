const GITHUB_COMMIT_SHA_PATTERN =
  /api\.github\.com\/repos\/[^/]+\/[^/]+\/git\/commits\/[a-f0-9]{40}/;
const NPX_GIT_URL_PATTERN = /npx\s+.*github\.com.*#[a-f0-9]{8,}/;
const MCP_KEYWORDS = ['mcp', 'model-context-protocol', 'claude', 'setup', 'init'];
const _EXTERNAL_FETCH_PATTERN =
  /(?:https?:\/\/)[^\s"')\]]+(?:\.com|\.io|\.org|\.dev|\.app|\.net)[^\s"')\]]*/;
const NON_NPMJS_FETCH =
  /(?:fetch|curl|wget)\s*\(?\s*["']https?:\/\/(?!(?:.*npmjs\.org|.*npm\.js\.org|.*github\.com))[^"']+/;
const BUN_PATTERNS = [/bun\s+install/, /install\s+.*bun/, /\bbunx\b/, /\.bun\/bin\//];
const _NPX_GIT_SHORT = /npx\s+.*github\.com.*#[a-f0-9]{8,}/;

export async function checkOrphanCommitFetch(extensionFiles = []) {
  const signals = [];
  const indicators = [];

  for (const file of extensionFiles) {
    const content = typeof file.content === 'string' ? file.content : '';
    if (!content) {
      continue;
    }
    const path = file.path || '';

    if (GITHUB_COMMIT_SHA_PATTERN.test(content)) {
      const matches = content.match(GITHUB_COMMIT_SHA_PATTERN);
      if (matches) {
        indicators.push(`${path}: GitHub git commit SHA reference`);
        signals.push({
          type: 'ORPHAN_COMMIT_GITHUB_API',
          indicator: 'GitHub API direct commit SHA resolution',
          file: path,
        });
      }
    }

    if (NPX_GIT_URL_PATTERN.test(content)) {
      const matches = content.match(NPX_GIT_URL_PATTERN);
      if (matches) {
        indicators.push(`${path}: npx with git URL`);
        signals.push({
          type: 'NPX_GIT_URL',
          indicator: 'npx resolves from git URL (non-registry)',
          file: path,
        });
      }
    }

    const hasMCPKeywords = MCP_KEYWORDS.some((kw) => new RegExp(`\\b${kw}\\b`, 'i').test(content));
    const hasExternalFetch = NON_NPMJS_FETCH.test(content);

    if (hasMCPKeywords && hasExternalFetch) {
      indicators.push(`${path}: MCP-adjacent keywords + external fetch`);
      signals.push({
        type: 'MCP_DISGUISED_EXFIL',
        indicator: 'Shell command disguised as MCP setup',
        file: path,
      });
    }

    for (const bp of BUN_PATTERNS) {
      if (bp.test(content)) {
        indicators.push(`${path}: Bun installation pattern`);
        signals.push({
          type: 'BUN_INSTALL',
          indicator: `Bun runtime install pattern: ${bp.source}`,
          file: path,
        });
        break;
      }
    }
  }

  return { triggered: signals.length > 0, signals, indicators };
}
