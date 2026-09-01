const OHNO_WHATS_GOING_ON_RE = /OhNoWhatsGoingOnWithGitHub/;
const GITHUB_COMMIT_SCRAPE_RE = /api\.github\.com\/repos\/[^/]+\/[^/]+\/commits/;
const GITHUB_GRAPHQL_RE = /api\.github\.com\/graphql/;
const GITHUB_TOKEN_ACCESS_RE = /process\.env\.(?:GH_TOKEN|GITHUB_TOKEN|GITHUB_ACTOR)/;
const COMMIT_PARSE_LOOP_RE = /commits?\s*\.\s*(?:map|filter|forEach|for\s*\(|while\s*\()/;

export function scanC2DeadDrop(files = []) {
  const code = files.map((f) => f.content || '').join('\n');
  if (!code) {
    return { triggered: false, matches: [] };
  }

  const matches = [];

  if (OHNO_WHATS_GOING_ON_RE.test(code)) {
    matches.push({
      type: 'ioc_keyword',
      value: 'OhNoWhatsGoingOnWithGitHub',
      attackVector: 'GitHub commit scraping for token recovery',
    });
  }

  const hasTokenAccess = GITHUB_TOKEN_ACCESS_RE.test(code);
  const hasGithubApi = GITHUB_COMMIT_SCRAPE_RE.test(code) || GITHUB_GRAPHQL_RE.test(code);
  const hasCommitParseLoop = COMMIT_PARSE_LOOP_RE.test(code);

  if (hasTokenAccess && hasGithubApi) {
    matches.push({
      type: 'token_exfil_github_api',
      value: 'Credential access followed by GitHub API call',
      attackVector: 'Credential/token extraction followed by GitHub API calls',
    });
  }

  if (hasCommitParseLoop && hasGithubApi) {
    matches.push({
      type: 'commit_scraping',
      value: 'Commit message parsing with GitHub API',
      attackVector: 'Commit scraping for secret detection',
    });
  }

  return {
    triggered: matches.length > 0,
    matches,
  };
}
