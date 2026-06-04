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
