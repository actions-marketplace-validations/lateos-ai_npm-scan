/**
 * Registry of agent and editor workspace surfaces.
 *
 * Split into bands because an injected *instruction* and an injected *server
 * command* are different attacks and must not share a severity:
 *
 *   exec          config an agent or editor RUNS. Needs no lifecycle hook,
 *                 survives `--ignore-scripts`, executes with full developer
 *                 privileges the next time the tool starts.  -> critical
 *   agent_read    prose an agent READS. Requires the agent to comply.  -> high
 *   editor_config editor state that shapes behaviour but does not directly
 *                 execute.  -> medium
 *
 * Patterns are matched against a normalized, forward-slashed path and anchored
 * at a segment boundary, so they match both a file shipped inside a tarball
 * (`.claude/mcp.json`) and a folded write target (`<home>/.claude/mcp.json`).
 */

export const BAND = {
  EXEC: 'exec',
  AGENT_READ: 'agent_read',
  EDITOR_CONFIG: 'editor_config',
};

export const BAND_SEVERITY = {
  [BAND.EXEC]: 'critical',
  [BAND.AGENT_READ]: 'high',
  [BAND.EDITOR_CONFIG]: 'medium',
};

export const BAND_WEIGHT = {
  [BAND.EXEC]: 70,
  [BAND.AGENT_READ]: 45,
  [BAND.EDITOR_CONFIG]: 30,
};

/** Ordered most-specific-first; first match wins. */
const SURFACES = [
  // ---- executable config (critical) ---------------------------------------
  { band: BAND.EXEC, label: 'MCP server config', re: /(^|\/)\.mcp\.json$/i },
  {
    band: BAND.EXEC,
    label: 'MCP server config',
    re: /(^|\/)\.(claude|cursor|vscode|windsurf)\/mcp\.json$/i,
  },
  {
    band: BAND.EXEC,
    label: 'Claude Code settings (hooks)',
    re: /(^|\/)\.claude\/settings(\.local)?\.json$/i,
  },
  { band: BAND.EXEC, label: 'Claude Code hook script', re: /(^|\/)\.claude\/hooks(\/|$)/i },
  {
    band: BAND.EXEC,
    label: 'VS Code task/launch config',
    re: /(^|\/)\.vscode\/(tasks|launch)\.json$/i,
  },
  {
    band: BAND.EXEC,
    label: 'devcontainer lifecycle config',
    re: /(^|\/)\.devcontainer\/devcontainer\.json$/i,
  },
  {
    band: BAND.EXEC,
    label: 'GitHub Actions workflow',
    re: /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i,
  },

  // ---- agent-read prose (high) --------------------------------------------
  { band: BAND.AGENT_READ, label: 'Cursor rules', re: /(^|\/)\.cursor\/rules(\/|$)/i },
  { band: BAND.AGENT_READ, label: 'Cursor rules', re: /(^|\/)\.cursorrules$/i },
  { band: BAND.AGENT_READ, label: 'Windsurf rules', re: /(^|\/)\.windsurfrules$/i },
  {
    band: BAND.AGENT_READ,
    label: 'Copilot instructions',
    re: /(^|\/)\.github\/copilot-instructions\.md$/i,
  },
  { band: BAND.AGENT_READ, label: 'agent context file', re: /(^|\/)(CLAUDE|AGENTS)\.md$/i },
  { band: BAND.AGENT_READ, label: 'agent context file', re: /(^|\/)\.claude\.md$/i },
  { band: BAND.AGENT_READ, label: 'Claude Code context file', re: /(^|\/)\.claude\/[^/]+\.md$/i },

  // ---- broader directory catch-alls (medium) ------------------------------
  { band: BAND.EDITOR_CONFIG, label: 'Claude Code workspace file', re: /(^|\/)\.claude(\/|$)/i },
  { band: BAND.EDITOR_CONFIG, label: 'Cursor workspace file', re: /(^|\/)\.cursor(\/|$)/i },
  { band: BAND.EDITOR_CONFIG, label: 'VS Code workspace file', re: /(^|\/)\.vscode(\/|$)/i },
  {
    band: BAND.EDITOR_CONFIG,
    label: 'GitHub workspace file',
    re: /(^|\/)\.github\/workflows(\/|$)/i,
  },
];

/**
 * Cheap substring prefilter — a source file containing none of these markers
 * cannot produce a surface match, so it never needs parsing.
 */
export const SURFACE_MARKERS = [
  '.claude',
  '.cursor',
  '.vscode',
  '.windsurf',
  '.github',
  '.mcp',
  '.devcontainer',
  'cursorrules',
  'windsurfrules',
  'CLAUDE.md',
  'AGENTS.md',
  'copilot-instructions',
];

/**
 * @param {string} filePath
 * @returns {{band: string, label: string, severity: string, weight: number}|null}
 */
export function matchSurface(filePath) {
  if (!filePath) {
    return null;
  }
  const normalized = String(filePath).replace(/\\/g, '/');
  for (const surface of SURFACES) {
    if (surface.re.test(normalized)) {
      return {
        band: surface.band,
        label: surface.label,
        severity: BAND_SEVERITY[surface.band],
        weight: BAND_WEIGHT[surface.band],
      };
    }
  }
  return null;
}

/** True when any surface marker appears in the source text. */
export function hasSurfaceMarker(content) {
  if (!content) {
    return false;
  }
  return SURFACE_MARKERS.some((m) => content.includes(m));
}

export { SURFACES };
