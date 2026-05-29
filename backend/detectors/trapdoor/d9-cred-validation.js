const CRED_VALIDATION_PATTERNS = [
  /sts\.amazonaws\.com/i,
  /api\.github\.com\/user/i,
];

export function scanCredValidation(allFiles, pkgJson) {
  const matches = [];

  const scripts = pkgJson?.scripts || {};
  for (const [hook, content] of Object.entries(scripts)) {
    if (/preinstall|install|postinstall|prepare/.test(hook)) {
      for (const pattern of CRED_VALIDATION_PATTERNS) {
        if (pattern.test(content)) {
          matches.push({ file: `script:${hook}`, pattern: pattern.source });
        }
      }
    }
  }

  for (const file of allFiles) {
    const path = file.path || '';
    if (!path.endsWith('.js') && !path.endsWith('.mjs') && !path.endsWith('.cjs')) continue;
    const content = file.content || '';
    for (const pattern of CRED_VALIDATION_PATTERNS) {
      if (pattern.test(content)) {
        matches.push({ file: path, pattern: pattern.source });
      }
    }
  }

  return { triggered: matches.length > 0, matches };
}
