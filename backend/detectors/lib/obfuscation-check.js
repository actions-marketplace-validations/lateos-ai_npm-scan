import { shannonEntropy } from './entropy-analyzer.js';

const HEX_STRING_RE = /(?:0x[0-9a-fA-F]{2,}|\\x[0-9a-fA-F]{2})/g;
const B64_RE = /['"`]([A-Za-z0-9+/]{20,}={0,2})['"`]/g;

export function isObfuscated(content) {
  if (!content) {
    return false;
  }
  const noWhitespace = !/\s/.test(content.trim());
  const identifiers = content.match(/\b[a-zA-Z_$][\w$]*\b/g);
  let avgIdLen = 0;
  if (identifiers && identifiers.length > 0) {
    avgIdLen = identifiers.reduce((s, id) => s + id.length, 0) / identifiers.length;
  }
  if (noWhitespace && identifiers && identifiers.length > 0 && avgIdLen < 3) {
    return true;
  }
  if (noWhitespace && /^[a-zA-Z_$][\w$]*\([^)]*\)$/.test(content.trim())) {
    return true;
  }
  HEX_STRING_RE.lastIndex = 0;
  if (HEX_STRING_RE.test(content)) {
    return true;
  }
  B64_RE.lastIndex = 0;
  if (B64_RE.test(content)) {
    return true;
  }
  if (shannonEntropy(content) > 5.5) {
    return true;
  }
  return false;
}

export { shannonEntropy };
