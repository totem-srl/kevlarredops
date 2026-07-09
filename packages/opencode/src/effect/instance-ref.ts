import { Context } from "effect"
import type { InstanceContext } from "@/project/instance-context"
import type { WorkspaceV2 } from "@pentestcode/core/workspace"

export const InstanceRef = Context.Reference<InstanceContext | undefined>("~pentestcode/InstanceRef", {
  defaultValue: () => undefined,
})

export const WorkspaceRef = Context.Reference<WorkspaceV2.ID | undefined>("~pentestcode/WorkspaceRef", {
  defaultValue: () => undefined,
})
