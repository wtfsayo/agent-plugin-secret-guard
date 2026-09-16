/**
 * secret-guard opencode plugin — pipes tool.execute.before/after into
 * secret_guard.py so the same pattern matcher works across runtimes.
 *
 * Install: add to ~/.config/opencode/opencode.json
 *   "plugin": ["/path/to/agent-plugin-secret-guard/extensions/ai.opencode/plugin/secret-guard.ts"]
 *
 * Or run `install.sh opencode` which symlinks this into
 * ~/.config/opencode/plugin/secret-guard.ts and adds it to opencode.json.
 */

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = join(HERE, "..", "..", "..", "scripts", "secret_guard.py");

function call_guard(event: "PreToolUse" | "PostToolUse", tool: string, input: unknown) {
  const payload = JSON.stringify({
    hook_event_name: event,
    tool_name: tool,
    tool_input: input,
  });
  const r = spawnSync("python3", [GUARD], {
    input: payload,
    encoding: "utf8",
    timeout: 10_000,
  });
  if (r.error || r.status === null) return null;
  const stdout = (r.stdout ?? "") + (r.stderr ?? "");
  // Guard emits {"hookSpecificOutput":{...}} for allow/deny/context.
  const m = stdout.match(/\{[\s\S]*"hookSpecificOutput"[\s\S]*\}/);
  if (!m) return null;
  try {
    return JSON.parse(m[0]).hookSpecificOutput ?? null;
  } catch {
    return null;
  }
}

const SecretGuard = async () => ({
  "tool.execute.before": async (
    input: { tool: string; sessionID: string; callID: string },
    output: { args: any }
  ) => {
    const decision = call_guard("PreToolUse", input.tool, output.args);
    if (decision?.permissionDecision === "deny") {
      throw new Error(decision.permissionDecisionReason ?? "blocked by secret-guard");
    }
  },
  "tool.execute.after": async (
    input: { tool: string; sessionID: string; callID: string; args: any },
    output: { title: string; output: string; metadata: any }
  ) => {
    const ctx = call_guard("PostToolUse", input.tool, {
      ...input.args,
      __output: output.output,
    });
    if (ctx?.additionalContext) {
      // No supported output channel for PostToolUse context in this hook spec;
      // rely on the guard's stderr/log for visibility.
    }
  },
});

export default SecretGuard;
