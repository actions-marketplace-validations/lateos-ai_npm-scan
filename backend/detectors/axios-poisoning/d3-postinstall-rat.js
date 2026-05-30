const SUSPICIOUS_HOOKS = ['postinstall', 'install', 'preinstall'];
const TEMP_DIR_RE = /(?:os\.tmpdir|tmpdir|temp|%TEMP%|\/tmp|\/var\/tmp)/;
const POWERSHELL_RE = /powershell|pwsh|cmd\.exe|Invoke-Expression|IEX\s*\(/;
const LAUNCHD_RE = /\/Library\/Launch(Daemons|Agents)\/|launchctl\s+(load|start|submit)/;
const SYSTEMD_SERVICE_RE = /\/etc\/systemd\/system\/|systemctl\s+(enable|start|daemon-reload)/;
const CRON_PERSIST_RE = /crontab\s+-[ei]|@reboot\s+|@daily\s+|@hourly\s+/;
const DLL_LOAD_RE = /LoadLibrary|dlopen|LoadLibraryEx|lib\.(?:LoadLibrary|dlopen)/;
const PROCESS_INJECT_RE = /CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtCreateThreadEx/;
const NET_CALLBACK_RE = /(?:https?:\/\/|wss?:\/\/|ws:\/\/)(?:[^\s'"]*\.[^\s'"]{2,})/;
const BINARY_DROP_RE = /(?:fs\.writeFileSync|writeFile|writeFileSync)\s*\([^)]*(?:\.exe|\.dll|\.bin|\.bat|\.ps1)/;

const SUSPICIOUS_HOOK_PATTERNS = [
  /curl|wget|fetch|https?:\/\//,
  /powershell|cmd\.exe|bash\b|sh\b/,
  /process\.exit|fs\.chmod|exec(?:Sync)?\s*\(/,
  /spawn|fork|detached/,
  /systemd|launchctl|crontab|schtasks/,
  /LoadLibrary|dlopen/,
  /eval|Function\s*\(/,
  /__dirname|__filename/,
];

export function scanPostinstallRAT(pkgJson, files = []) {
  const scripts = pkgJson?.scripts || {};
  const code = files.map(f => f.content || '').join('\n');

  const activeHooks = [];
  for (const hook of SUSPICIOUS_HOOKS) {
    if (scripts[hook]) {
      activeHooks.push({ hook, command: scripts[hook] });
    }
  }

  if (activeHooks.length === 0) {
    return { triggered: false, platforms: [], c2Indicators: [], payloadType: null, hooks: [], hasBinaryDrop: false };
  }

  const combined = code + '\n' + activeHooks.map(h => h.command).join('\n');

  const hasSuspiciousCode = SUSPICIOUS_HOOK_PATTERNS.some(p => p.test(combined));

  if (activeHooks.length > 0 && !hasSuspiciousCode) {
    return { triggered: false, platforms: [], c2Indicators: [], payloadType: null, hooks: [], hasBinaryDrop: false };
  }

  const platforms = [];
  let c2Indicators = [];
  let hasBinaryDrop = false;

  if (POWERSHELL_RE.test(combined)) platforms.push('windows');
  if (LAUNCHD_RE.test(combined)) platforms.push('macos');
  if (SYSTEMD_SERVICE_RE.test(combined) || CRON_PERSIST_RE.test(combined)) platforms.push('linux');
  if (TEMP_DIR_RE.test(combined) && (POWERSHELL_RE.test(combined) || BINARY_DROP_RE.test(combined))) {
    if (!platforms.includes('windows')) platforms.push('windows');
    if (!platforms.includes('linux')) platforms.push('linux');
    if (!platforms.includes('macos')) platforms.push('macos');
  }

  if (DLL_LOAD_RE.test(combined)) platforms.push('windows');
  if (PROCESS_INJECT_RE.test(combined)) platforms.push('windows');

  if (NET_CALLBACK_RE.test(combined)) {
    const urls = combined.match(NET_CALLBACK_RE);
    c2Indicators = urls ? [...new Set(urls.map(u => u.replace(/['")]/g, '')))] : ['Network callback to external server'];
  }

  if (BINARY_DROP_RE.test(combined)) hasBinaryDrop = true;

  let payloadType = null;
  if (platforms.length >= 2 && c2Indicators.length > 0 && hasBinaryDrop) {
    payloadType = 'cross_platform_RAT';
  } else if (c2Indicators.length > 0) {
    payloadType = 'network_backdoor';
  } else if (platforms.length > 0) {
    payloadType = 'platform_persistence';
  }

  if (payloadType) {
    return {
      triggered: true,
      payloadType,
      platforms: [...new Set(platforms)],
      c2Indicators,
      hooks: activeHooks.map(h => h.hook),
      hasBinaryDrop,
    };
  }

  if (activeHooks.length > 0) {
    return {
      triggered: true,
      payloadType: 'suspicious_lifecycle_hook',
      platforms: ['unknown'],
      c2Indicators: [],
      hooks: activeHooks.map(h => h.hook),
      hasBinaryDrop: false,
    };
  }

  return { triggered: false, platforms: [], c2Indicators: [], payloadType: null, hooks: [], hasBinaryDrop: false };
}
