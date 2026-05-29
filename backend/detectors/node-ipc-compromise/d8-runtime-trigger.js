export function scanRuntimeTrigger(allFiles, pkgJson) {
  const matches = [];

  const sources = [];

  const scripts = pkgJson?.scripts || {};
  for (const [hook, content] of Object.entries(scripts)) {
    sources.push({ file: `script:${hook}`, content });
  }

  for (const file of allFiles) {
    const path = file.path || '';
    if (!path.endsWith('.js') && !path.endsWith('.mjs') && !path.endsWith('.cjs')) continue;
    sources.push({ file: path, content: file.content || '' });
  }

  for (const { file, content } of sources) {
    if (/\bsetImmediate\s*\(/.test(content)) {
      matches.push({
        file,
        detail: 'setImmediate() call found — node-ipc malware fires at require() time, not via postinstall',
      });
    }
  }

  return { triggered: matches.length > 0, matches };
}
