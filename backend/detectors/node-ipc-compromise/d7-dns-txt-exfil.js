const EXFIL_ZONE = /bt\.node\.js/i;
const RESOLVE_TXT_DYNAMIC = /\bresolveTxt\s*\(/;

export function scanDnsTxtExfil(allFiles, pkgJson) {
  const matches = [];

  const sources = [];

  const scripts = pkgJson?.scripts || {};
  for (const [hook, content] of Object.entries(scripts)) {
    if (/preinstall|install|postinstall|prepare/.test(hook)) {
      sources.push({ file: `script:${hook}`, content });
    }
  }

  for (const file of allFiles) {
    const path = file.path || '';
    if (!path.endsWith('.js') && !path.endsWith('.mjs') && !path.endsWith('.cjs')) continue;
    sources.push({ file: path, content: file.content || '' });
  }

  for (const { file, content } of sources) {
    if (EXFIL_ZONE.test(content)) {
      matches.push({
        file,
        finding: 'exfil-zone',
        value: 'bt.node.js',
        detail: 'DNS TXT exfiltration zone reference found',
      });
    }

    if (RESOLVE_TXT_DYNAMIC.test(content)) {
      matches.push({
        file,
        finding: 'resolve-txt',
        detail: 'resolveTxt() call detected — potential DNS TXT tunneling',
      });
    }
  }

  return { triggered: matches.length > 0, matches };
}
