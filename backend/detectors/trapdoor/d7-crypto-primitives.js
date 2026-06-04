export function scanCryptoPrimitives(allFiles, pkgJson) {
  const matches = [];

  const scripts = pkgJson?.scripts || {};
  const scriptEntries = Object.entries(scripts)
    .filter(([hook]) => /preinstall|install|postinstall|prepare/.test(hook))
    .map(([hook, content]) => ({ file: `script:${hook}`, content }));

  const jsFiles = allFiles
    .filter((f) => f.path?.endsWith('.js') || f.path?.endsWith('.mjs') || f.path?.endsWith('.cjs'))
    .map((f) => ({ file: f.path, content: f.content || '' }));

  for (const { file, content } of [...scriptEntries, ...jsFiles]) {
    const hasFernet = /Fernet/i.test(content);
    const hasECDH = /\bECDH\b|\bcreateECDH\b/i.test(content);
    if (hasFernet && hasECDH) {
      matches.push({ file });
    }
  }

  return { triggered: matches.length > 0, matches };
}
