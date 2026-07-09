import { AgentV2 } from "@pentestcode/core/agent"
import { AISDK } from "@pentestcode/core/aisdk"
import { Catalog } from "@pentestcode/core/catalog"
import { CommandV2 } from "@pentestcode/core/command"
import { Credential } from "@pentestcode/core/credential"
import { AppNodeBuilder } from "@pentestcode/core/effect/app-node-builder"
import { LayerNodePlatform } from "@pentestcode/core/effect/app-node-platform"
import { LayerNode } from "@pentestcode/core/effect/layer-node"
import { EventV2 } from "@pentestcode/core/event"
import { FileSystem } from "@pentestcode/core/filesystem"
import { FSUtil } from "@pentestcode/core/fs-util"
import { Integration } from "@pentestcode/core/integration"
import { Location } from "@pentestcode/core/location"
import { Npm } from "@pentestcode/core/npm"
import { PluginV2 } from "@pentestcode/core/plugin"
import { Reference } from "@pentestcode/core/reference"
import { SkillV2 } from "@pentestcode/core/skill"
import { Effect, Layer } from "effect"
import { tempLocationLayer } from "../fixture/location"

const npmLayer = Layer.succeed(
  Npm.Service,
  Npm.Service.of({
    add: () => Effect.succeed({ directory: "", entrypoint: undefined }),
    install: () => Effect.void,
    which: () => Effect.succeed(undefined),
  }),
)

export const PluginTestLayer = AppNodeBuilder.build(
  LayerNode.group([
    FileSystem.node,
    FSUtil.node,
    Location.node,
    Npm.node,
    Credential.node,
    EventV2.node,
    LayerNodePlatform.httpClient,
    PluginV2.node,
    AgentV2.node,
    AISDK.node,
    Catalog.node,
    CommandV2.node,
    Integration.node,
    Reference.node,
    SkillV2.node,
  ]),
  [
    [Location.node, tempLocationLayer],
    [Npm.node, npmLayer],
  ],
)
