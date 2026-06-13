import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeHookOn } from "../src/hookon.js";

// Mirror of xahc's encode-side test over the SAME committed file. xahc asserts
// encode_hook_on(names) == hex; here we assert decodeHookOn(hex).firesOn == set(names).
// Both passing over one shared vectors file = the two independent HookOn
// implementations agree, with no cross-repo import. Drift on either side fails
// its own suite locally.
const VECTORS_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "hookon-vectors.json");

describe("HookOn shared vectors (cross-repo contract with xahc)", () => {
  const data = JSON.parse(readFileSync(VECTORS_PATH, "utf8")) as {
    vectors: { names: string[]; hex: string }[];
  };

  it("has vectors", () => {
    expect(data.vectors.length).toBeGreaterThan(0);
  });

  for (const v of data.vectors) {
    it(`decodes ${v.hex.slice(-8)} -> {${v.names.join(",")}}`, () => {
      const got = [...decodeHookOn(v.hex).firesOn].sort();
      const want = [...v.names].sort();
      expect(got).toEqual(want);
    });
  }
});
