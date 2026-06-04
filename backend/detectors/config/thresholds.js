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
  'TIER1-SELF-PROPAGATION': {
    flag_threshold: 75,
    warn_threshold: 60,
    burst_window_minutes: 60,
    min_packages_burst: 3,
    identical_payload_weight: 40,
    notes: 'D10: Detects burst republish patterns (Miasma campaign)',
  },
  'TIER1-ENCRYPTED-C2': {
    flag_threshold: 70,
    warn_threshold: 50,
    known_c2_endpoints: [
      'filev2.getsession.org',
      'api.signal.org',
      '*.briarproject.org',
      'api.ricochet.im',
    ],
    onion_pattern_weight: 30,
    encoded_url_weight: 35,
    env_var_c2_weight: 40,
    notes: 'D11: Detects Session/Oxen, Signal, Briar, Tor C2 channels',
  },
  'TIER1-TRANSITIVE-DEPS': {
    flag_threshold: 80,
    warn_threshold: 50,
    new_package_days: 7,
    unknown_depth_weight: 45,
    typosquat_depth_weight: 50,
    different_maintainer_weight: 35,
    notes: 'D12: Deep dependency tree analysis for injection attacks',
  },
  'TIER1-MAINTAINER-COMPROMISE': {
    flag_threshold: 75,
    warn_threshold: 60,
    velocity_burst_multiplier: 5,
    burst_window_hours: 24,
    min_velocity_baseline: 0.5,
    duplicate_version_weight: 40,
    unusual_timing_weight: 25,
    cross_package_burst_weight: 50,
    notes: 'D13: Version velocity anomaly and maintainer compromise detection',
  },
};
