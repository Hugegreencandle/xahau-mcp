import { describe, it, expect } from "vitest";
import { scaffoldHook, type Archetype } from "../src/scaffold.js";

const ALL: Archetype[] = ["accept_all", "firewall", "payment_limit", "require_dest_tag", "state_counter", "notary"];

describe("scaffold_hook", () => {
  it("every archetype emits a structurally valid C hook skeleton", () => {
    for (const a of ALL) {
      const s = scaffoldHook({ archetype: a });
      expect(s.language).toBe("c");
      expect(s.source).toContain('#include "hookapi.h"');
      expect(s.source).toMatch(/int64_t hook\(uint32_t reserved\)/);
      expect(s.source).toContain("_g(1,1)");                 // guard present
      expect(s.source).toMatch(/accept\(|rollback\(/);        // an exit path
      expect(s.buildInstructions).toMatch(/Hooks Builder|wasmcc/);
      expect(s.notes.join(" ")).toMatch(/analyze_hook|execute_hook/); // verify-before-deploy nudge
    }
  });

  it("firewall embeds the chosen tx type", () => {
    const s = scaffoldHook({ archetype: "firewall", blockTxType: "Import" });
    expect(s.source).toContain("ttIMPORT");
    expect(s.source).toMatch(/rollback\(/);
  });

  it("payment_limit embeds the cap + reads sfAmount", () => {
    const s = scaffoldHook({ archetype: "payment_limit", maxDrops: "5000000" });
    expect(s.source).toContain("5000000");
    expect(s.source).toContain("sfAmount");
  });

  it("state_counter uses state + state_set", () => {
    const s = scaffoldHook({ archetype: "state_counter" });
    expect(s.source).toContain("state_set(");
    expect(s.source).toMatch(/state\(/);
  });
});
