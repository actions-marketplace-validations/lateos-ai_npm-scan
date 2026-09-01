function hashToken(str) {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) + hash + str.charCodeAt(i);
    hash = hash & hash;
  }
  return hash >>> 0;
}

export function simhash(text) {
  const v = new Array(64).fill(0);
  const tokens = text.toLowerCase().split(/\s+/).filter(Boolean);

  for (const token of tokens) {
    const h = hashToken(token);
    for (let i = 0; i < 64; i++) {
      if ((h >> i) & 1) {
        v[i] += 1;
      } else {
        v[i] -= 1;
      }
    }
  }

  let fingerprint = 0n;
  for (let i = 0; i < 64; i++) {
    if (v[i] > 0) {
      fingerprint |= 1n << BigInt(i);
    }
  }
  return fingerprint;
}

export function hammingDistance(a, b) {
  let xor = a ^ b;
  let count = 0;
  while (xor > 0n) {
    count += Number(xor & 1n);
    xor >>= 1n;
  }
  return count;
}

export function similarity(a, b) {
  return 1 - hammingDistance(a, b) / 64;
}
