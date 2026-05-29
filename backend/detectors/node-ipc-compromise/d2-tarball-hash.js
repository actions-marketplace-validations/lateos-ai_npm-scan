import { createHash } from 'crypto';

const MALICIOUS_HASHES = new Set([
  '449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e',
  'c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea',
  '78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981',
]);

export function scanTarballHash(allFiles) {
  const matches = [];

  for (const file of allFiles) {
    const path = file.path || '';
    if (!path.endsWith('.tgz') && !path.endsWith('.tar.gz')) continue;

    const content = file.content || '';
    const hash = createHash('sha256').update(content, 'utf8').digest('hex');

    if (MALICIOUS_HASHES.has(hash)) {
      matches.push({
        file: path,
        sha256: hash,
        version: hash === '449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e'
          ? '9.1.6' : hash === 'c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea'
          ? '9.2.3' : '12.0.1',
      });
    }
  }

  return { triggered: matches.length > 0, matches };
}
