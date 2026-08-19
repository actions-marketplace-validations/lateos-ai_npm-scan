/**
 * D31 — Tarball/Git source desync (ERR_TARBALL_GIT_DESYNC).
 *
 * Thin detector wrapper around validators/git-diff.js so the differential
 * engine reaches findings through the normal pipeline.
 *
 * Two deliberate properties:
 *
 * 1. **Provenance is never consulted.** A valid OIDC/SLSA attestation over a
 *    tarball built from a dirty tree is exactly the attack this detects — the
 *    attestation is minted over the build *output*, so its digest binds
 *    perfectly while the code corresponds to no commit. Suppressing on
 *    provenance would disable the check precisely when it matters.
 *
 * 2. **Opt-in.** This is the only network-bound detector in the suite. It
 *    short-circuits before any I/O unless explicitly enabled, so the default
 *    scan path carries no added cost.
 */
import { compareTarballToGit, ERR_TARBALL_GIT_DESYNC } from '../validators/git-diff.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D31-TARBALL-GIT-DESYNC'];

export const name = 'tier1-tarball-git-desync';

function finding(
  severity,
  confidence,
  confidenceScore,
  message,
  evidence,
  locations,
  recommendation,
  context
) {
  return {
    detector: 'tier1-tarball-git-desync',
    id: ERR_TARBALL_GIT_DESYNC,
    severity,
    confidence,
    confidenceScore,
    message,
    evidence,
    locations,
    recommendation,
    ...(context ? { context } : {}),
    reference: 'Tarball/Git source differential (ChainDrop-class)',
  };
}

/**
 * @param {object} pkgJson
 * @param {Array} jsFiles
 * @param {object} registryMeta
 * @param {Array} allFiles
 * @param {object} [options] forwarded to compareTarballToGit; `enabled` and
 *   `sourceProvider` are the two a caller normally sets.
 */
export async function scan(pkgJson, jsFiles, registryMeta, allFiles, options = {}) {
  const enabled = options.enabled ?? cfg.enabled === true;
  if (!enabled) {
    return [];
  }

  const files = allFiles || jsFiles || [];
  if (files.length === 0) {
    return [];
  }

  const result = await compareTarballToGit(pkgJson, files, registryMeta, {
    ...options,
    enabled: true,
  });

  if (result.status === 'unverifiable') {
    if (cfg.report_unverifiable === false) {
      return [];
    }
    return [
      finding(
        'low',
        'LOW',
        15,
        `Could not verify ${pkgJson?.name || 'package'} against its Git source (${result.reason})`,
        [
          `reason: ${result.reason}`,
          'tarball contents were not compared to any commit',
          'absence of a desync finding is not evidence the tarball matches source',
        ],
        [{ file: 'package.json', line: 1 }],
        'MONITOR - Source comparison unavailable; verify through other means',
        { git_diff_status: 'unverifiable', reason: result.reason }
      ),
    ];
  }

  if (result.status === 'clean') {
    return [];
  }

  const critical = result.findings.filter((f) => f.severity === 'critical');
  const severity = critical.length > 0 ? 'critical' : 'high';
  const confidenceScore = critical.length > 0 ? 95 : 75;

  const capabilities = [
    ...new Set(result.findings.flatMap((f) => (f.capabilities || []).map((c) => c.capability))),
  ];

  return [
    finding(
      severity,
      'HIGH',
      confidenceScore,
      `Published tarball for ${pkgJson?.name || 'package'}@${pkgJson?.version || '?'} does not match its Git source (${result.findings.length} file(s))`,
      [
        `source: ${result.source.url} @ ${result.source.ref} (via ${result.source.refSource})`,
        `files_compared: ${result.compared}`,
        `files_skipped: ${result.skipped}`,
        ...(capabilities.length ? [`capabilities_introduced: ${capabilities.join(', ')}`] : []),
        'provenance state deliberately not consulted: a valid attestation over a dirty build is the attack',
        ...result.findings.map((f) => `${f.kind}: ${f.detail}`),
      ],
      result.findings.map((f) => ({ file: f.path, line: 1 })),
      severity === 'critical'
        ? 'BLOCK - Tarball contains executable code absent from the attested source commit'
        : 'INVESTIGATE - Published executable scripts differ from the Git source',
      {
        git_diff_status: 'desync',
        source_repo: result.source.url,
        source_ref: result.source.ref,
        ref_source: result.source.refSource,
        files_compared: result.compared,
        files_skipped: result.skipped,
        desync_files: result.findings.map((f) => ({
          path: f.path,
          kind: f.kind,
          severity: f.severity,
          capabilities: f.capabilities,
        })),
      }
    ),
  ];
}

export { ERR_TARBALL_GIT_DESYNC };
