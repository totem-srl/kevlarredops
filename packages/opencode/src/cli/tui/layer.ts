import { run as runTui, type TuiInput } from "@pentestcode/tui"
import { Global } from "@pentestcode/core/global"
import { AppNodeBuilder } from "@pentestcode/core/effect/app-node-builder"
import { Effect } from "effect"

export function run(input: TuiInput) {
  return runTui(input).pipe(Effect.provide(AppNodeBuilder.build(Global.node)))
}
