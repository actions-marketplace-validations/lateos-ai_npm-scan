/**
 * Detector confidence thresholds (calibrated post-validation)
 *
 * Format: { detector: { flag_threshold, warn_threshold } }
 * Thresholds calibrated against:
 *   - 3 real May 2026 attack campaigns (validation)
 *   - Top 1,000 npm packages (false positive calibration)
 */

export default {
  'TIER1-VERSION-ANOMALY': {
    flag_threshold: 72,
    warn_threshold: 60,
    notes:
      'Sentinel patterns (99.99.99/11.11.11/10.10.10) always flag at 92 regardless of threshold',
  },
  'TIER1-OBFUSCATION-HEURISTICS': {
    flag_threshold: 75,
    warn_threshold: 60,
    notes: 'Increased from 70 post-FP analysis; bundlers (webpack, terser) exempt via whitelist',
  },
  'TIER1-BINARY-EMBED': {
    flag_threshold: 80,
    warn_threshold: 65,
    notes:
      'High threshold justified; platform-specific binary sets are rare in legitimate packages',
  },
  'TIER1-LIFECYCLE-HOOK': {
    flag_threshold: 65,
    warn_threshold: 50,
    notes: 'Moderate threshold; lifecycle hooks common but uncommon in top 1K packages',
  },
  'TIER1-INFOSTEALER': {
    flag_threshold: 72,
    warn_threshold: 55,
    notes: 'Pattern-based; calibrated for C2 signatures, credential exfil patterns',
  },
  'TIER1-TYPOSQUAT': {
    flag_threshold: 85,
    warn_threshold: 70,
    notes:
      'Calibrated to 85 post-FP analysis on top 1,000 packages; 46 edit-distance=1 FPs eliminated at this threshold',
  },
  'TIER1-METADATA-SPOOF': {
    flag_threshold: 70,
    warn_threshold: 55,
    notes: 'Namespace/repo URL spoofing; moderate threshold for legitimate clones',
  },
  'TIER1-VERSION-CONFUSION': {
    flag_threshold: 75,
    warn_threshold: 60,
    notes: 'High-version heuristics (major >= 9); tuned to avoid FP on pre-release tags',
  },
  'TIER1-CLOUD-IMDS': {
    flag_threshold: 80,
    warn_threshold: 65,
    notes: 'IMDS endpoint targeting is rarely legitimate; high threshold',
  },
  'TIER1-MULTISTAGE-POSTINSTALL': {
    flag_threshold: 75,
    warn_threshold: 60,
    notes: 'Two-stage download+exec patterns; moderate threshold',
  },
  'TIER1-SLSA-ATTESTATION': {
    flag_threshold: 85,
    warn_threshold: 70,
    notes: 'Placeholder; threshold TBD when API stabilizes',
  },
};
