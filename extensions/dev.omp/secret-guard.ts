/**
 * secret-guard — omp (oh-my-pi) adapter.
 *
 * Translates omp's `tool_call` / `tool_result` hook events into the
 * Droid-shaped JSON payload that `scripts/secret_guard.py` understands,
 * and translates its verdicts back:
 *
 *   PreToolUse  → permissionDecision "deny"  → { block: true, reason }
 *   PostToolUse → additionalContext          → appended text block on the result
 *
 * Install layout (install.sh omp):
 *   ~/.omp/agent/hooks/pre/secret-guard.ts   ← this file
 *   ~/.omp/agent/hooks/scripts/secret_guard.py + secret_patterns.py + helpers
 *
 * Escape hatch: OMP_SECRET_GUARD=off (also honors the core's
 * DROID_SECRET_GUARD/DEVIN_SECRET_GUARD=off). Fail-open like the core:
 * spawn errors, timeouts, and unparseable output never block a tool.
 */
import type { HookAPI, ToolCallEvent, ToolResultEvent } from "@oh-my-pi/pi-coding-agent";
import * as path from "node:path";

const SCRIPT = path.join(import.meta.dir, "..", "scripts", "secret_guard.py");
const TIMEOUT_MS = 10_000;

/** omp tool name → canonical name the core's family sets recognize
 *  (_SHELL_TOOLS is lowercase; _FILE_READ/_FILE_WRITE are capitalized). */
const TOOL_MAP: Record<string, string> = {
	bash: "bash",
	read: "Read",
	write: "Write",
	edit: "Edit",
	ast_edit: "Edit",
	memory_edit: "Edit",
};

interface CoreOutput {
	hookSpecificOutput?: {
		hookEventName?: string;
		permissionDecision?: string;
		permissionDecisionReason?: string;
		additionalContext?: string;
	};
}

/**
 * omp uses `path` where the core expects `file_path`, and the hashline/patch
 * edit forms carry their payload in `input` — surface it as `new_string` so
 * the write-family literal-secret scan sees it.
 */
function toToolInput(toolName: string, input: Record<string, unknown>): Record<string, unknown> {
	const ti = { ...input };
	if (typeof ti.path === "string" && ti.file_path === undefined) {
		ti.file_path = ti.path;
	}
	if (toolName === "edit" && typeof ti.input === "string" && ti.new_string === undefined) {
		ti.new_string = ti.input;
	}
	return ti;
}

async function runCore(payload: Record<string, unknown>): Promise<CoreOutput | null> {
	try {
		const proc = Bun.spawn(["python3", SCRIPT], {
			stdin: "pipe",
			stdout: "pipe",
			stderr: "pipe",
		});
		proc.stdin.write(JSON.stringify(payload));
		proc.stdin.end();
		const timer = setTimeout(() => proc.kill(), TIMEOUT_MS);
		const stdout = await new Response(proc.stdout).text();
		await proc.exited;
		clearTimeout(timer);
		const line = stdout.trim();
		if (!line) return null;
		return JSON.parse(line) as CoreOutput;
	} catch {
		return null; // fail-open: never break a session over a guard error
	}
}

export default function secretGuard(pi: HookAPI): void {
	if (process.env.OMP_SECRET_GUARD === "off") return;

	pi.on("tool_call", async (event: ToolCallEvent) => {
		const toolName = TOOL_MAP[event.toolName] ?? event.toolName;
		const out = await runCore({
			hook_event_name: "PreToolUse",
			tool_name: toolName,
			tool_input: toToolInput(event.toolName, event.input ?? {}),
		});
		const decision = out?.hookSpecificOutput;
		if (decision?.permissionDecision === "deny") {
			return { block: true, reason: decision.permissionDecisionReason ?? "Blocked by secret-guard" };
		}
		return undefined;
	});

	pi.on("tool_result", async (event: ToolResultEvent) => {
		const text = (event.content ?? [])
			.filter((b: { type: string }) => b.type === "text")
			.map((b: { text: string }) => b.text)
			.join("\n");
		if (!text) return undefined;
		const out = await runCore({
			hook_event_name: "PostToolUse",
			tool_name: TOOL_MAP[event.toolName] ?? event.toolName,
			tool_input: toToolInput(event.toolName, event.input ?? {}),
			tool_response: { output: text, error: event.isError ? text : "" },
		});
		const warning = out?.hookSpecificOutput?.additionalContext;
		if (!warning) return undefined;
		return { content: [...event.content, { type: "text", text: `\n${warning}` }] };
	});
}
