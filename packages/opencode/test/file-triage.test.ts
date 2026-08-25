import { describe, expect, test } from "bun:test"
import { sniffMagic, shannonEntropy, extractStrings } from "@/tool/file-triage"

describe("sniffMagic", () => {
  test("identifies ELF, PE, PNG and shebang scripts", () => {
    expect(sniffMagic(new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]))).toContain("ELF")
    expect(sniffMagic(new Uint8Array([0x4d, 0x5a, 0x90, 0]))).toContain("PE")
    expect(sniffMagic(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toContain("PNG")
    expect(sniffMagic(new Uint8Array([0x23, 0x21, 0x2f, 0x62]))).toContain("Script")
    expect(sniffMagic(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))).toBeUndefined()
  })
})

describe("shannonEntropy", () => {
  test("constant bytes have zero entropy; random-ish bytes approach 8", () => {
    expect(shannonEntropy(new Uint8Array(64).fill(0x41))).toBe(0)
    const spread = new Uint8Array(4096)
    for (let i = 0; i < spread.length; i++) spread[i] = (i * 251) % 256
    expect(shannonEntropy(spread)).toBeGreaterThan(7.5)
  })
})

describe("extractStrings", () => {
  test("collects printable runs above min length", () => {
    const text = "ok\x00hello world\x01ab\x00another one"
    const strings = extractStrings(new Uint8Array(Buffer.from(text)), 6)
    expect(strings).toContain("hello world")
    expect(strings.some((s) => s.startsWith("another"))).toBe(true)
    expect(strings.every((s) => s.length >= 6)).toBe(true)
  })
})
