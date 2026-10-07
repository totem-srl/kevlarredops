import { expect, test } from "bun:test"

const legacy = await import("../src/client")
const v2 = await import("../src/v2/client")
const directory = "/owned lab/è#%"

function lab() {
  const requests: { url: URL; headers: Headers; method: string }[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push({ url: new URL(request.url), headers: request.headers, method: request.method })
      return Response.json({ id: "ses_owned", title: "owned lab" })
    },
  })
  return { server, requests, baseUrl: `http://127.0.0.1:${server.port}` }
}

test("legacy writes send the canonical directory header to the server", async () => {
  const fixture = lab()
  try {
    const client = legacy.createOpencodeClient({ baseUrl: fixture.baseUrl, directory })
    await client.session.create({ body: { title: "owned lab" } })
    expect(fixture.requests).toHaveLength(1)
    expect(fixture.requests[0]?.method).toBe("POST")
    expect(fixture.requests[0]?.headers.get("x-pentestcode-directory")).toBe(encodeURIComponent(directory))
    expect(fixture.requests[0]?.headers.has("x-opencode-directory")).toBe(false)
  } finally {
    await fixture.server.stop(true)
  }
})

test("legacy reads preserve configured directory query encoding", async () => {
  const fixture = lab()
  try {
    const client = legacy.createOpencodeClient({ baseUrl: fixture.baseUrl, directory })
    await client.session.list()
    expect(fixture.requests[0]?.url.searchParams.get("directory")).toBe(directory)
    expect(fixture.requests[0]?.headers.has("x-pentestcode-directory")).toBe(false)
    expect(fixture.requests[0]?.headers.has("x-opencode-directory")).toBe(false)
  } finally {
    await fixture.server.stop(true)
  }
})

test("v2 writes send canonical directory and workspace headers", async () => {
  const fixture = lab()
  try {
    const client = v2.createOpencodeClient({
      baseUrl: fixture.baseUrl,
      directory,
      experimental_workspaceID: "wrk_owned",
    })
    await client.session.create({ title: "owned lab" })
    expect(fixture.requests[0]?.headers.get("x-pentestcode-directory")).toBe(encodeURIComponent(directory))
    expect(fixture.requests[0]?.headers.get("x-pentestcode-workspace")).toBe("wrk_owned")
    expect(fixture.requests[0]?.headers.has("x-opencode-directory")).toBe(false)
    expect(fixture.requests[0]?.headers.has("x-opencode-workspace")).toBe(false)
  } finally {
    await fixture.server.stop(true)
  }
})

test("v2 reads preserve explicit directory queries over configured defaults", async () => {
  const fixture = lab()
  try {
    const client = v2.createOpencodeClient({
      baseUrl: fixture.baseUrl,
      directory,
      experimental_workspaceID: "wrk_owned",
    })
    await client.session.list({ directory: "/explicit lab" })
    expect(fixture.requests[0]?.url.searchParams.get("directory")).toBe("/explicit lab")
    expect(fixture.requests[0]?.url.searchParams.get("workspace")).toBe("wrk_owned")
    expect(fixture.requests[0]?.headers.has("x-pentestcode-directory")).toBe(false)
    expect(fixture.requests[0]?.headers.has("x-pentestcode-workspace")).toBe(false)
  } finally {
    await fixture.server.stop(true)
  }
})
