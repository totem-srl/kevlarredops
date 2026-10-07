import { describe, expect, test } from "bun:test"
import { ScopeMatcher } from "@pentestcode/core/engagement/scope-matcher"

// Regression: the dev.3 range-3 session flooded almost every python-in-bash command
// with warnings about json.load, sys.stdin, socket.socket, and s.recv. Code tokens
// must not be treated as hosts; actual internal network targets still require scope.
describe("extractTargetsFromCommand — no code-token false positives", () => {
  const codeCommands = [
    `python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('x'))"`,
    `python3 - <<'EOF'\ns=socket.socket(); s.settimeout(5); s.connect((h,p)); s.recv(4096); s.sendall(b'x'); s.close()\nEOF`,
    `cat data | tr a.b c.d && foo.decode() && bar.append(x) && obj.read()`,
    `urllib.request.urlopen(req); r.status; hits.append((u,p))`,
  ]
  for (const cmd of codeCommands) {
    test(`no targets from: ${cmd.slice(0, 40)}…`, () => {
      expect(ScopeMatcher.extractTargetsFromCommand(cmd)).toEqual([])
    })
  }

  test("SMTP EHLO identifies the sender rather than a remote target", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`smtp EHLO t.local`)).toEqual([])
  })
})

describe("extractTargetsFromCommand — real targets still extracted", () => {
  test("internal targets used by network tools are not implicitly authorized", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`curl http://mail-dmz.range3.local/`)).toContain("mail-dmz.range3.local")
    expect(ScopeMatcher.extractTargetsFromCommand(`ssh user@queue-dmz.internal`)).toContain("queue-dmz.internal")
  })
  test("code tokens remain filtered alongside a network command", () => {
    expect(
      ScopeMatcher.extractTargetsFromCommand(`nmap dc01.corp.local; python3 -c "print(json.load(sys.stdin))"`),
    ).toEqual(["dc01.corp.local"])
  })
  test("IPv4 addresses", () => {
    const t = ScopeMatcher.extractTargetsFromCommand(`curl http://172.50.1.10:3000/ ; nmap 172.50.2.20`)
    expect(t).toContain("172.50.1.10")
    expect(t).toContain("172.50.2.20")
  })
  test("CIDR", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`nmap 172.50.1.0/24`)).toContain("172.50.1.0/24")
  })
  test("genuine public-TLD domain", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`curl https://evil.com/x`)).toContain("evil.com")
    expect(ScopeMatcher.extractTargetsFromCommand(`nmap target.example.org`)).toContain("target.example.org")
  })
  test("user@host with public TLD", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`ssh admin@box.attacker.io`)).toContain("box.attacker.io")
  })
  test("invalid octets are not IPs", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`echo 999.999.1.1`)).toEqual([])
  })
})
