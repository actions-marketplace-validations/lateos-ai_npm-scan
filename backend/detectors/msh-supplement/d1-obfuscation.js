const CTF_SCRAMBLE_RE = /require\(['"](ctf-scramble-v2|ctf-scramble-v\d+)['"]\)/;
const CTF_SCRAMBLE_ESM_RE = /(?:from|import)\s+['"](ctf-scramble-v2|ctf-scramble-v\d+)['"]/;

export function scanCtfScramble(files = []) {
  for (const file of files) {
    const content = file.content || '';
    if (CTF_SCRAMBLE_RE.test(content) || CTF_SCRAMBLE_ESM_RE.test(content)) {
      const match = content.match(CTF_SCRAMBLE_RE) || content.match(CTF_SCRAMBLE_ESM_RE);
      return {
        triggered: true,
        stopCondition: true,
        filePath: file.path,
        patternMatched: match ? match[1] : 'ctf-scramble-v2',
      };
    }
  }
  return { triggered: false, stopCondition: false };
}
