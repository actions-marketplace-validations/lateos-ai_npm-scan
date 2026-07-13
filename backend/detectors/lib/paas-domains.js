const PAAS_SUFFIXES = ['.run.app', '.web.app', '.vercel.app', '.netlify.app', '.workers.dev'];

const PAAS_EXTRACT_RE =
  /https?:\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)*(?:\.run\.app|\.web\.app|\.vercel\.app|\.netlify\.app|\.workers\.dev))/gi;

export function isServerlessPaasDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    return false;
  }
  const lower = domain.toLowerCase();
  return PAAS_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}

export function extractPaasDomains(content) {
  const found = [];
  if (!content || typeof content !== 'string') {
    return found;
  }
  let match;
  PAAS_EXTRACT_RE.lastIndex = 0;
  while ((match = PAAS_EXTRACT_RE.exec(content)) !== null) {
    found.push(match[1]);
  }
  return [...new Set(found)];
}

export const PAAS_CONFIDENCE_BOOST = 15;
