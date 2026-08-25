import { describe, expect, test } from "bun:test"
import { extractForms, extractLinks } from "@/scanner/crawl"
import { BUILTIN_WORDLIST } from "@/scanner/dir-fuzzer"
import { TOP_PORTS } from "@/scanner/port-scanner"

const BASE = new URL("https://target.test/")

describe("crawl extractors", () => {
  const html = `
    <a href="/login">Login</a>
    <a href="https://other.test/evil">external</a>
    <a href="#anchor">anchor</a>
    <img src="/logo.png">
    <form action="/search" method="GET"><input name="q"><input type="hidden" name="csrf"></form>
    <form action="" method="POST"><input name="email"><input name="password"></form>
  `

  test("extractLinks keeps same-origin http(s) links only", () => {
    const links = extractLinks(html, BASE)
    const hrefs = links.map((u) => u.toString())
    expect(hrefs).toContain("https://target.test/login")
    expect(hrefs.some((h) => h.startsWith("https://other.test"))).toBe(false)
  })

  test("extractForms captures action/method/inputs with default action", () => {
    const forms = extractForms(html)
    expect(forms).toHaveLength(2)
    expect(forms[0]).toMatchObject({ action: "/search", method: "GET" })
    expect(forms[0]?.inputs).toEqual(["q", "csrf"])
    expect(forms[1]?.method.toUpperCase()).toBe("POST")
    expect(forms[1]?.inputs).toEqual(["email", "password"])
  })
})

describe("scanner datasets", () => {
  test("wordlist and port list are non-trivial", () => {
    expect(BUILTIN_WORDLIST.length).toBeGreaterThan(50)
    expect(TOP_PORTS.length).toBeGreaterThan(20)
    expect(TOP_PORTS).toContain(80)
    expect(TOP_PORTS).toContain(443)
    expect(TOP_PORTS).toContain(8080)
  })
})
