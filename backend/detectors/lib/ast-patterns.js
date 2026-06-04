const PATTERNS = [
  { id: 'EVAL_USAGE', re: /\beval\s*\(/ },
  { id: 'FUNCTION_CONSTRUCTOR', re: /Function\s*\(/ },
  {
    id: 'STRING_REVERSAL_CHAIN',
    re: /\.split\s*\(\s*['"]\s*['"]\s*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(/,
  },
  { id: 'XOR_CIPHER', re: /charCodeAt\s*\([^)]*\)\s*\^\s*\w+/ },
  { id: 'BITWISE_LOOP', re: /for\s*\([^;]+;[^;]+\)\s*\{[^}]{20,}\^[^}]*\}/ },
  { id: 'DYNAMIC_REQUIRE', re: /require\s*\(\s*(?:Buffer\.from|atob|decodeURIComponent)/ },
  { id: 'BASE64_LITERAL', re: /['"][A-Za-z0-9+/]{60,}={0,2}['"]/ },
  { id: 'OBFUSCATED_STRING', re: /(?:\\x[0-9a-fA-F]{2}){8,}/ },
  { id: 'UNICODE_ESCAPE', re: /(?:\\u[0-9a-fA-F]{4}){8,}/ },
];

export function detectPatterns(code) {
  const detected = [];
  for (const { id, re } of PATTERNS) {
    if (re.test(code)) {
      detected.push(id);
    }
  }
  return detected;
}
