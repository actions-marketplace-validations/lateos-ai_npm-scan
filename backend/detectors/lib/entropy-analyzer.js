export function shannonEntropy(str) {
  const len = str.length;
  if (len === 0) {
    return 0;
  }
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Filter a list of string literals down to those long and random enough to be
 * encoded payload rather than prose. Hex-only alphabets top out at 4.0 bits, so
 * a threshold above that deliberately selects base64/randomized encodings.
 */
export function highEntropyStrings(literals, options = {}) {
  const minLength = options.minLength ?? 40;
  const threshold = options.threshold ?? 4.5;
  const out = [];
  for (const value of literals || []) {
    if (typeof value !== 'string' || value.length < minLength) {
      continue;
    }
    const entropy = shannonEntropy(value);
    if (entropy > threshold) {
      out.push({ value, entropy });
    }
  }
  return out;
}

export function isMinified(code) {
  if (code.length < 100) {
    return false;
  }
  const lines = code.split('\n');
  if (lines.length <= 3 && code.length > 1000) {
    return true;
  }
  const tokens = code.match(/\b[a-zA-Z_$][\w$]*\b/g) || [];
  if (tokens.length < 10) {
    return false;
  }
  const avgLen = tokens.reduce((s, t) => s + t.length, 0) / tokens.length;
  return avgLen < 3;
}
