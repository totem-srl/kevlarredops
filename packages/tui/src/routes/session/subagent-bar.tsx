import { createMemo, createSignal, For, Show } from "solid-js"
import { useRouteData } from "../../context/route"
import { useRoute } from "../../context/route"
import { useSync } from "../../context/sync"
import { useTheme } from "../../context/theme"
import { Spinner } from "../../component/spinner"
import { SplitBorder } from "../../ui/border"
import { Locale } from "../../util/locale"
import { useTerminalDimensions } from "@opentui/solid"
import type { ToolPart } from "@pentestcode/sdk/v2"

type Status = "running" | "done" | "error"

type Entry = {
  sessionID: string
  label: string
  description: string
  status: Status
  detail?: string
}

const MAX_ROWS = 6

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined
}

// Live list of the root session's subagents, always visible at the bottom.
// Click a row to open that subagent's session and watch its actions in real
// time. Derived entirely from data the TUI already syncs (task tool parts +
// child session busy/idle status) — no new server/event plumbing.
export function SubagentBar() {
  const route = useRouteData("session")
  const sync = useSync()
  const { navigate } = useRoute()
  const { theme } = useTheme()
  const [hover, setHover] = createSignal<string | null>(null)
  useTerminalDimensions()

  const childActivity = (childID: string): string | undefined => {
    const status = sync.data.session_status[childID]
    if (status?.type === "retry") return `retrying (attempt ${status.attempt})`
    const msgs = sync.data.message[childID] ?? []
    const tools = msgs.flatMap((m) =>
      (sync.data.part[m.id] ?? []).filter((p): p is ToolPart => p.type === "tool"),
    )
    const current = tools.findLast(
      (t) => (t.state.status === "running" || t.state.status === "completed") && stringValue((t.state as any).title),
    )
    if (current) {
      const title = stringValue((current.state as any).title)
      return `${Locale.titlecase(current.tool)}${title ? ` ${Locale.truncate(title, 40)}` : ""}`
    }
    if (tools.length > 0) return `${tools.length} tool call${tools.length === 1 ? "" : "s"}`
    return undefined
  }

  const subagents = createMemo<Entry[]>(() => {
    const msgs = sync.data.message[route.sessionID] ?? []
    const byChild = new Map<string, Entry>()
    for (const m of msgs) {
      for (const part of sync.data.part[m.id] ?? []) {
        if (part.type !== "tool" || part.tool !== "task") continue
        const state = (part as ToolPart).state
        // Pending tasks have no child session yet; skip until spawned. This
        // also narrows the union so metadata/input are accessible below.
        if (state.status === "pending") continue
        const childID = stringValue(state.metadata?.sessionId)
        if (!childID) continue
        // Child-session liveness is the source of truth for "running", not the task
        // part's status: a background subagent's part flips to "completed" the moment
        // it's dispatched while the child keeps working, so keying off the part alone
        // would drop it immediately. A present session_status entry means busy (idle
        // deletes it — see session/status.ts), matching the nav's isActiveChild.
        const childStatus = sync.data.session_status[childID]
        const childActive = childStatus !== undefined && childStatus.type !== "idle"

        let status: Status
        if (state.status === "running" || childActive) status = "running"
        else if (state.status === "error") status = "error"
        else status = "done"

        byChild.set(childID, {
          sessionID: childID,
          label: Locale.titlecase(stringValue(state.input?.subagent_type) ?? "Agent"),
          description: stringValue(state.input?.description) ?? "",
          status,
          detail: status === "running" ? childActivity(childID) : undefined,
        })
      }
    }
    // Only live subagents. Finished ones are removed as soon as they complete —
    // the bar tracks in-flight work, not history. Completed subagents stay
    // reachable through the session list for reviewing their results.
    return Array.from(byChild.values()).filter((e) => e.status === "running")
  })

  const shown = createMemo(() => subagents().slice(0, MAX_ROWS))
  const overflow = createMemo(() => subagents().length - shown().length)

  const icon = (status: Status) => (status === "done" ? "✓" : status === "error" ? "✗" : "·")
  const iconColor = (status: Status) =>
    status === "done" ? theme.success : status === "error" ? theme.error : theme.textMuted

  return (
    <Show when={subagents().length > 0}>
      <box flexShrink={0}>
        <box
          paddingTop={1}
          paddingBottom={1}
          paddingLeft={2}
          paddingRight={1}
          {...SplitBorder}
          border={["left"]}
          borderColor={theme.border}
          flexShrink={0}
          backgroundColor={theme.backgroundPanel}
          flexDirection="column"
        >
          <text fg={theme.textMuted}>
            Subagents ({subagents().length} running) — click to view
          </text>
          <For each={shown()}>
            {(entry) => (
              <box
                flexDirection="row"
                gap={1}
                onMouseOver={() => setHover(entry.sessionID)}
                onMouseOut={() => setHover(null)}
                onMouseUp={() => navigate({ type: "session", sessionID: entry.sessionID })}
                backgroundColor={hover() === entry.sessionID ? theme.backgroundElement : theme.backgroundPanel}
              >
                <Show when={entry.status === "running"} fallback={<text fg={iconColor(entry.status)}>{icon(entry.status)}</text>}>
                  <Spinner />
                </Show>
                <text fg={theme.text} wrapMode="none">
                  <b>{entry.label}</b>
                </text>
                <text fg={theme.textMuted} wrapMode="none">
                  {[Locale.truncate(entry.description, 48), entry.detail && `↳ ${entry.detail}`]
                    .filter(Boolean)
                    .join("  ")}
                </text>
              </box>
            )}
          </For>
          <Show when={overflow() > 0}>
            <text fg={theme.textMuted}>… and {overflow()} more</text>
          </Show>
        </box>
      </box>
    </Show>
  )
}
