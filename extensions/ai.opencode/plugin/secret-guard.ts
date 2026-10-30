/**
 * secret-guard opencode plugin — pipes tool.execute.before/after into
 * secret_guard.py so the same pattern matcher works across runtimes.
 *
 * Install: add to ~/.config/opencode/opencode.json
 *   "plugin": ["/path/to/agent-plugin-secret-guard/extensions/ai.opencode/plugin/secret-guard.ts"]
 *
 * Or run `install.sh opencode`, which copies this file to
 * ~/.config/opencode/plugin/secret-guard.ts (core in plugin/scripts/) and
 * adds it to opencode.json.
 *
 * before: a deny throws, which blocks the tool. If the core cannot run at
 * all, the call is blocked too (fail closed, like the core's PreToolUse).
 * after: a leak warning is appended to the tool output the model sees.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
// Installed copy: plugin/scripts/; repo checkout: <repo>/scripts/.
const GUARD = [join(HERE, "scripts", "secret_guard.py"), join(HERE, "..", "..", "..", "scripts", "secret_guard.py")]
  .find((p) => existsSync(p)) ?? join(HERE, "scripts", "secret_guard.py");

/** opencode tool name → name the core's tool families recognize. */
const TOOL_MAP: Record<string, string> = { read: "Read", write: "Write", edit: "Edit" };

/** opencode args are camelCase; the core reads snake_case keys. */
function toToolInput(args: Record<string, unknown> = {}): Record<string, unknown> {
  const ti: Record<string, unknown> = { ...args };
  if (typeof ti.filePath === "string" && ti.file_path === undefined) ti.file_path = ti.filePath;
  if (typeof ti.newString === "string" && ti.new_string === undefined) ti.new_string = ti.newString;
  return ti;
}

type Verdict = { permissionDecision?: string; permissionDecisionReason?: string; additionalContext?: string };

function callGuard(payload: Record<string, unknown>): Verdict | null | undefined {
  const r = spawnSync("python3", [GUARD], { input: JSON.stringify(payload), encoding: "utf8", timeout: 10_000 });
  if (r.error || r.status === null) return undefined; // core did not run
  const line = (r.stdout ?? "").trim().split("\n").pop() ?? "";
  if (!line) return null;
  try {
    return JSON.parse(line).hookSpecificOutput ?? null;
  } catch {
    return null;
  }
}

const SecretGuard = async () => ({
  "tool.execute.before": async (
    input: { tool: string; sessionID: string; callID: string },
    output: { args: Record<string, unknown> }
  ) => {
    const v = callGuard({
      hook_event_name: "PreToolUse",
      tool_name: TOOL_MAP[input.tool] ?? input.tool,
      tool_input: toToolInput(output.args),
    });
    if (v === undefined) throw new Error("secret-guard could not run python3 " + GUARD);
    if (v?.permissionDecision === "deny") {
      throw new Error(v.permissionDecisionReason ?? "blocked by secret-guard");
    }
  },
  "tool.execute.after": async (
    input: { tool: string; sessionID: string; callID: string; args?: Record<string, unknown> },
    output: { title: string; output: string; metadata: unknown }
  ) => {
    const v = callGuard({
      hook_event_name: "PostToolUse",
      tool_name: TOOL_MAP[input.tool] ?? input.tool,
      tool_input: toToolInput(input.args),
      tool_response: { output: output.output },
    });
    if (v?.additionalContext) output.output = `${output.output ?? ""}\n\n${v.additionalContext}`;
  },
});

export default SecretGuard;
