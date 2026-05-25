import { checkBurstPublish } from './d1-burst-publish.js';
import { checkSiblingCompromise, clearSiblingCache } from './d2-sibling-compromise.js';
import { checkSlsaMismatch } from './d3-slsa-mismatch.js';
import { checkMaintainerAnomaly } from './d4-maintainer-anomaly.js';
import { checkIOC } from './d5-ioc-check.js';
import { checkTokenExfil } from './d6-token-exfil.js';

export async function scan(pkgJson, files = [], registryMeta = null, allFiles = null) {
  const config = {};

  const burstResult = await checkBurstPublish(registryMeta, config);
  const maintainerResult = await checkMaintainerAnomaly(registryMeta, config);

  const pkgName = pkgJson?.name || '';
  const pkgVersion = pkgJson?.version || '';
  const sha512 = registryMeta?.versions?.[pkgVersion]?.dist?.integrity || null;
  const publisherAccount = registryMeta?.versions?.[pkgVersion]?._npmUser?.name || null;
  const timeMap = registryMeta?.time || {};

  const iocResult = await checkIOC(pkgName, pkgVersion, sha512, publisherAccount, timeMap);
  const exfilResult = checkTokenExfil(allFiles || files, pkgJson);

  let siblingResult = { triggered: false };
  let slsaResult = { triggered: false };

  if (burstResult.triggered) {
    siblingResult = await checkSiblingCompromise(pkgJson, config);
    slsaResult = await checkSlsaMismatch(pkgName, pkgVersion, burstResult, timeMap, config);
  }

  const nxDownstreamResult = checkNxConsoleDownstream(pkgJson, allFiles || files);

  const triggeredChecks = [];
  if (burstResult.triggered) triggeredChecks.push('D1_BURST');
  if (siblingResult.triggered) triggeredChecks.push('D2_SIBLING');
  if (slsaResult.triggered) triggeredChecks.push('D3_SLSA');
  if (maintainerResult.triggered) triggeredChecks.push('D4_MAINTAINER');
  if (iocResult.triggered) triggeredChecks.push('D5_IOC');
  if (exfilResult.triggered) triggeredChecks.push('D6_EXFIL');
  if (nxDownstreamResult.triggered) triggeredChecks.push('D7_NX_CONSOLE');

  if (triggeredChecks.length === 0) return [];

  let waveAttribution = 'unknown';
  if (pkgName.startsWith('@tanstack')) {
    waveAttribution = 'wave1-tanstack';
  } else if (pkgName.startsWith('@antv')) {
    waveAttribution = 'wave2-antv';
  } else if (nxDownstreamResult.triggered) {
    waveAttribution = 'wave3-nx-console';
  } else if (iocResult.matches && iocResult.matches.length > 0) {
    const waves = [...new Set(iocResult.matches.map(m => m.wave))];
    if (waves.length === 1) {
      waveAttribution = waves[0] === 1 ? 'wave1-tanstack' : waves[0] === 2 ? 'wave2-antv' : 'wave3-nx-console';
    }
  }

  const isCritical = slsaResult.triggered || iocResult.triggered || nxDownstreamResult.triggered;

  const evidence = {
    campaign: 'MINI_SHAI_HULUD',
    waveAttribution,
    triggeredChecks,
    burstWindow: burstResult.triggered
      ? { start: burstResult.windowStart, end: burstResult.windowEnd, versionCount: burstResult.versionCount }
      : null,
    siblingPackages: siblingResult.triggered
      ? siblingResult.results.flatMap(r => r.siblingPackages)
      : null,
    attestationAnomalies: slsaResult.triggered ? slsaResult.anomalies : null,
    iocMatches: iocResult.triggered ? iocResult.matches : null,
    installScriptSnippets: exfilResult.triggered ? exfilResult.snippets : null,
    nxConsoleDownstream: nxDownstreamResult.triggered
      ? { nxDeps: nxDownstreamResult.nxDeps, vsCodeExtensions: nxDownstreamResult.vsCodeExtensions }
      : null,
  };

  return [{
    id: 'MINI_SHAI_HULUD',
    severity: isCritical ? 'critical' : 'high',
    title: 'Mini Shai-Hulud worm campaign',
    description: `${triggeredChecks.length} signal(s): ${triggeredChecks.join(', ')}`,
    evidence: JSON.stringify(evidence),
    mitigation: 'Revoke all npm tokens immediately. Rotate CI/CD secrets. Audit maintainer access on all scoped packages. Review recent version publish history for anomalous bursts. Check for postinstall scripts accessing credentials or environment variables. If Wave 1 (TanStack scope): inspect GitHub Actions workflow logs for unauthorized build steps. If Wave 2 (atool/AntV scope): rotate all npm tokens associated with @antv/* packages. If Wave 3 (Nx Console): remove nrwl.angular-console extension immediately, revoke all npm tokens used in CI/CD, and audit @nx/* dependency versions.',
  }];
}

function checkNxConsoleDownstream(pkgJson, allFiles) {
  const deps = { ...pkgJson?.dependencies, ...pkgJson?.devDependencies, ...pkgJson?.peerDependencies };
  const nxDeps = Object.keys(deps).filter(d => d.startsWith('@nx/') || d.startsWith('nrwl/'));
  if (nxDeps.length === 0) return { triggered: false, nxDeps: [], vsCodeExtensions: [] };

  let vsCodeExtensions = [];
  if (allFiles && Array.isArray(allFiles)) {
    for (const file of allFiles) {
      if (file.path && (file.path.endsWith('.vscode/extensions.json') || file.path.endsWith('.vscode/extensions.json'))) {
        try {
          const content = typeof file.content === 'string' ? file.content : '';
          const parsed = JSON.parse(content);
          const allExts = [
            ...(parsed.recommendations || []),
            ...(parsed.unwantedRecommendations || []),
          ];
          const matched = allExts.filter(e => e.includes('nrwl.angular-console'));
          if (matched.length > 0) {
            vsCodeExtensions = matched;
          }
        } catch {
          // non-JSON extensions.json, skip
        }
      }
    }
  }

  return { triggered: true, nxDeps, vsCodeExtensions };
}

export { clearSiblingCache } from './d2-sibling-compromise.js';
