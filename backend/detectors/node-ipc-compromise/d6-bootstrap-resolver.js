const BOOTSTRAP_DOMAIN = /sh\.azurestaticprovider\.net/i;
const C2_IP = /37\.16\.75\.69/;

export function scanBootstrapResolver(allFiles, pkgJson) {
  const matches = [];

  const sources = [];

  const scripts = pkgJson?.scripts || {};
  for (const [hook, content] of Object.entries(scripts)) {
    sources.push({ file: `script:${hook}`, content });
  }

  for (const file of allFiles) {
    const path = file.path || '';
    sources.push({ file: path, content: file.content || '' });
  }

  for (const { file, content } of sources) {
    if (BOOTSTRAP_DOMAIN.test(content)) {
      matches.push({
        file,
        finding: 'c2-domain',
        value: 'sh.azurestaticprovider.net',
        detail: 'Bootstrap resolver domain — lookalike, not a Microsoft domain',
      });
    }

    if (C2_IP.test(content)) {
      matches.push({
        file,
        finding: 'c2-ip',
        value: '37.16.75.69',
        detail: 'Known C2 IP address for DNS TXT tunneling',
      });
    }
  }

  return { triggered: matches.length > 0, matches };
}
