const EXFIL_PATTERNS = [
  /NPM_TOKEN|NODE_AUTH_TOKEN|GH_TOKEN|GITHUB_TOKEN|npm_token|node_auth_token/i,
  /~\/(\.npmrc|\.gitconfig|\.aws\/credentials)/,
  /\/run\/secrets\//,
  /\$GITHUB_ENV/,
  /process\.env\.(NPM_TOKEN|NODE_AUTH_TOKEN|GH_TOKEN|GITHUB_TOKEN)/,
  /Buffer\.from\s*\([^)]*\)\s*\.\s*toString\s*\(\s*['"]base64['"]\s*\)/,
  /\batob\s*\(/,
  /\bbtoa\s*\(/,
];

const SUSPICIOUS_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];

const MAX_SNIPPET_LENGTH = 200;

function truncateSnippet(text) {
  if (text.length <= MAX_SNIPPET_LENGTH) return text;
  return text.slice(0, MAX_SNIPPET_LENGTH - 3) + '...';
}

export function checkTokenExfil(allFiles, pkgJson) {
  const scripts = pkgJson?.scripts || {};
  const snippets = [];

  for (const hook of SUSPICIOUS_SCRIPTS) {
    const scriptContent = scripts[hook];
    if (!scriptContent) continue;

    for (const pattern of EXFIL_PATTERNS) {
      if (pattern.test(scriptContent)) {
        snippets.push(truncateSnippet(scriptContent));
        break;
      }
    }
  }

  return { triggered: snippets.length > 0, snippets };
}
