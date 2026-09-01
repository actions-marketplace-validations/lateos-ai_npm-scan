const PUBLIC_RESOLVERS = new Set(['1.1.1.1', '8.8.8.8', '8.8.4.4', '9.9.9.9']);

const IP_PATTERN = /setServers\(\s*\[?\s*['"`](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['"`]/;

export function scanDnsC2Pattern(allFiles, pkgJson) {
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
    if (!path.endsWith('.js') && !path.endsWith('.mjs') && !path.endsWith('.cjs')) {
      continue;
    }
    sources.push({ file: path, content: file.content || '' });
  }

  for (const { file, content } of sources) {
    const hasDnsResolver = /\bdns\.promises\s*\.\s*Resolver\b/.test(content);
    if (!hasDnsResolver) {
      continue;
    }

    const ipMatch = content.match(IP_PATTERN);
    if (!ipMatch) {
      continue;
    }

    const customIP = ipMatch[1];
    if (PUBLIC_RESOLVERS.has(customIP)) {
      continue;
    }

    const hasResolveTxt = /\bresolveTxt\b/.test(content);

    matches.push({
      file,
      customResolverIP: customIP,
      hasResolveTxt,
      detail: `Custom DNS resolver at ${customIP}${hasResolveTxt ? ' with resolveTxt() — TXT tunneling fingerprint' : ''}`,
    });
  }

  return { triggered: matches.length > 0, matches };
}
