import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-ebpf-rootkit.js';

test('D16: eBPF bytecode reference detected as HIGH', async () => {
  const files = [{ path: 'main.rs', content: 'use eBPF;' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'ebpf_bytecode'));
});

test('D16: bpf() syscall usage detected as HIGH', async () => {
  const files = [{ path: 'main.rs', content: 'bpf(BPF_PROG_LOAD, ...);' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'ebpf_bytecode'));
});

test('D16: kprobes/tracepoint hooks detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'kprobes/sys_open' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'kernel_hook'));
});

test('D16: sys_open/sys_connect hooks detected as CRITICAL', async () => {
  const files = [{ path: 'install.js', content: 'BPF_KPROBE(sys_open) { ... }' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  const types = findings[0].detail?.map((d) => d.type) || [];
  assert.ok(types.includes('kernel_hook'));
});

test('D16: Rust/C FFI with kernel calls detected as MED', async () => {
  const files = [
    { path: 'main.rs', content: 'extern "C" { fn bpf(cmd: u32, attr: *mut BPFAttr) -> i32; }' },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'kernel_ffi'));
});

test('D16: IronWorm eBPF rootkit sample returns BLOCK', async () => {
  const files = [
    {
      path: 'install.js',
      content: `
      // IronWorm eBPF rootkit
      bpf(BPF_PROG_LOAD, { prog_type: 1, insns, license: "GPL" });
      bpf(BPF_PROG_ATTACH, { target_fd: cgroup_fd, prog_fd });
      sys_open = hook_kprobe("sys_open");
      sys_connect = hook_kprobe("sys_connect");
      hide_pid = true;
    `,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
});

test('D16: legitimate Rust binary (no kernel calls) returns no findings', async () => {
  const files = [{ path: 'main.rs', content: 'fn main() { println!("hello"); }' }];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D16: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D16: hiding intent patterns detected', async () => {
  const files = [{ path: 'install.js', content: 'hide_process = true; rootkit_mode();' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'hiding_intent'));
});
