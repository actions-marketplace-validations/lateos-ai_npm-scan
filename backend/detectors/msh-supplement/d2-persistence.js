const DAEMON_RE = /\b(daemon|fork)\s*\(/;
const SPAWN_DETACHED_RE = /spawn\s*\([^)]*detached\s*:\s*true/;
const SYSTEMD_RE = /\/etc\/systemd\/system\/|systemctl\s+(enable|start)/;
const CRON_RE = /crontab\s+-e|\/etc\/cron\b/;
const LAUNCHD_RE = /\/Library\/LaunchDaemons\/|launchctl\s+(load|start)/;
const TASK_SCHED_RE = /schtasks\.exe|New-ScheduledTask|Register-ScheduledJob/;
const CI_GUARD_RE = /!process\.env\.CI|process\.env\.CI\s*===?\s*undefined/;

export function scanPersistence(pkgJson, files = []) {
  const allScripts = [];
  const hooks = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'];
  for (const hook of hooks) {
    const script = pkgJson?.scripts?.[hook];
    if (script) {
      allScripts.push({ hook, content: script });
    }
  }

  const code = files.map(f => f.content || '').join('\n');
  const codeWithScripts = code + '\n' + allScripts.map(s => s.content).join('\n');

  const detectedApis = [];
  let hasCiGuard = false;
  let hasDaemon = false;

  if (DAEMON_RE.test(codeWithScripts)) detectedApis.push('daemon');
  if (SPAWN_DETACHED_RE.test(codeWithScripts)) detectedApis.push('spawn_detached');
  if (SYSTEMD_RE.test(codeWithScripts)) detectedApis.push('systemd');
  if (CRON_RE.test(codeWithScripts)) detectedApis.push('cron');
  if (LAUNCHD_RE.test(codeWithScripts)) detectedApis.push('launchd');
  if (TASK_SCHED_RE.test(codeWithScripts)) detectedApis.push('task_scheduler');
  if (CI_GUARD_RE.test(codeWithScripts)) hasCiGuard = true;

  if (DAEMON_RE.test(codeWithScripts) || SPAWN_DETACHED_RE.test(codeWithScripts)) hasDaemon = true;

  if (hasDaemon || detectedApis.length > 0) {
    return {
      triggered: true,
      detectedApis,
      hasCiGuard,
      hooks: allScripts.map(s => s.hook),
      context: hasCiGuard ? 'Spawns background process when CI env var absent' : 'Suspicious persistence/detached process detected',
    };
  }

  return { triggered: false, detectedApis: [], hasCiGuard: false, hooks: [] };
}
