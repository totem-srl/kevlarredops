import path from "path"
import fs from "node:fs"
import os from "node:os"
import { afterAll } from "bun:test"

const testHome = fs.mkdtempSync(path.join(os.tmpdir(), "pentestcode-core-test-"))
process.env.OPENCODE_TEST_HOME = testHome
afterAll(() => fs.rmSync(testHome, { recursive: true, force: true }))

process.env.OPENCODE_DB = ":memory:"
process.env.OPENCODE_MODELS_PATH = path.join(import.meta.dir, "plugin", "fixtures", "models-dev.json")
process.env.OPENCODE_DISABLE_MODELS_FETCH = "true"
