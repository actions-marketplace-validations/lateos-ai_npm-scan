import { createHash } from 'crypto';

const INJECTED_PAYLOAD_HASH = '3427a90c8cb9af764445448648176e120ebc6af0a538158340cf6220de4d01b7';

const _IIFE_BOUNDARY = /}\)\(\);\s*$/;

export function scanInjectedPayloadHash(allFiles) {
  const matches = [];

  for (const file of allFiles) {
    const path = file.path?.replace(/\\/g, '/') || '';
    if (!path.endsWith('node-ipc.cjs')) {
      continue;
    }

    const content = file.content || '';

    if (content.includes(INJECTED_PAYLOAD_HASH)) {
      matches.push({
        file: path,
        finding: 'hash-string-present',
        sha256: INJECTED_PAYLOAD_HASH,
        detail: 'Known injected payload SHA-256 found within node-ipc.cjs content',
      });
    }

    const fileHash = createHash('sha256').update(content, 'utf8').digest('hex');
    if (fileHash === INJECTED_PAYLOAD_HASH) {
      matches.push({
        file: path,
        finding: 'file-hash-match',
        sha256: fileHash,
        detail: 'node-ipc.cjs SHA-256 matches known injected payload hash',
      });
    }
  }

  return { triggered: matches.length > 0, matches };
}
