const CRED_PATH_PATTERNS = /\.aws\/|id_rsa|\.env|keystore|credentials|\.npmrc|\.ssh\//i;
const C2_PATTERNS = [/ddjidd564\.github\.io/i, /gist\.github\.com/i];

function scanContent(content, filePath) {
  const matches = [];
  const hasC2 = C2_PATTERNS.some((p) => p.test(content));
  if (!hasC2) {
    return matches;
  }

  const hasCredPath = CRED_PATH_PATTERNS.test(content);
  if (hasCredPath) {
    matches.push({ file: filePath });
  }
  return matches;
}

export function scanGistsExfil(allFiles, pkgJson) {
  const matches = [];

  const scripts = pkgJson?.scripts || {};
  for (const [hook, scriptContent] of Object.entries(scripts)) {
    if (/preinstall|install|postinstall|prepare/.test(hook)) {
      matches.push(...scanContent(scriptContent, `script:${hook}`));
    }
  }

  for (const file of allFiles) {
    const path = file.path || '';
    if (path.endsWith('.js') || path.endsWith('.mjs') || path.endsWith('.cjs')) {
      matches.push(...scanContent(file.content || '', path));
    }
  }

  return { triggered: matches.length > 0, matches };
}
