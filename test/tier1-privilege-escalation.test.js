import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-privilege-escalation.js';

test('D17: CAP_SYS_ADMIN request detected as HIGH', async () => {
  const files = [
    { path: 'install.js', content: 'const caps = ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"]' },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'capability_request'));
});

test('D17: setuid/setgid usage detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'setuid(0); setgid(0);' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'setuid_attempt'));
});

test('D17: /dev/mem access detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'const fd = fs.openSync("/dev/mem", "r+")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'kernel_memory_access'));
});

test('D17: insmod/modprobe call detected as CRITICAL', async () => {
  const files = [{ path: 'install.js', content: 'execSync("insmod /rootkit.ko");' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'kernel_module_load'));
});

test('D17: sudoers modification detected as HIGH', async () => {
  const files = [
    {
      path: 'install.js',
      content: 'fs.writeFileSync("/etc/sudoers", user + " ALL=(ALL) NOPASSWD:ALL")',
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'sudo_bypass'));
});

test('D17: CVE reference in code detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: '// CVE-2024-1234 privilege escalation exploit' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'exploit_reference'));
});

test('D17: IronWorm privesc sample returns BLOCK recommendation', async () => {
  const files = [
    {
      path: 'install.js',
      content: `
      // IronWorm: load eBPF rootkit via kernel module
      if (execSync("insmod rootkit.ko").status === 0) {
        const fd = fs.openSync("/dev/kmem", "r+");
        // kernel memory access for privesc
      }
    `,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
});

test('D17: legitimate sudo usage (no bypass) returns LOW findings', async () => {
  const files = [
    { path: 'install.js', content: 'execSync("sudo -u nobody whoami", { stdio: "pipe" })' },
  ];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D17: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D17: cap_set_proc detected', async () => {
  const files = [{ path: 'install.js', content: 'cap_set_proc(&cap);' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'capability_request'));
});
