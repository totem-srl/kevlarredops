export * as PublicEventManifest from "./public-event-manifest"

import { Event } from "@pentestcode/schema/event"
import { EventManifest } from "@pentestcode/schema/event-manifest"

export const Definitions = EventManifest.ServerDefinitions
export const Latest = Event.latest(Definitions)
