import { describe, it, expect } from "vitest";
import { readWasm, hexToBytes } from "../src/wasm.js";
import { runHook } from "../src/sandbox.js";

const HEADER = "0061736d01000000"; // wasm magic + version 1

describe("H2 — section vector counts can't OOM the parser", () => {
  it("import section with a huge count > section size is refused, not allocated", () => {
    // import section (id 2), size 4, count uleb = 0xFFFFFF7F (~268M) but 0 bytes follow
    const info = readWasm(hexToBytes(HEADER + "0204FFFFFF7F"));
    expect(info.valid).toBe(false);
    expect(info.reason).toMatch(/import vector count exceeds section size/);
  });

  it("export section with a huge count is refused", () => {
    const info = readWasm(hexToBytes(HEADER + "0704FFFFFF7F"));
    expect(info.valid).toBe(false);
    expect(info.reason).toMatch(/export vector count exceeds section size/);
  });
});

describe("H1 — every loop must be guarded before we execute untrusted bytecode", () => {
  it("refuses a module with more loops than _g guard call-sites (the one-guarded+one-unguarded bypass)", () => {
    // import env._g (func 0); code one func: loop{ call _g } end ; loop{} end  → 2 loops, 1 guard call
    const IMPORT_G = "020A0103656E76025F670000";
    const CODE_TWO_LOOPS = "0A0C010A00034010000B03400B0B";
    const r = runHook(hexToBytes(HEADER + IMPORT_G + CODE_TWO_LOOPS));
    expect(r.exit).toBe("halted");
    expect(r.returnString).toMatch(/unguarded loop \(2 loop\(s\) vs 1 _g/);
  });

  it("refuses a module whose opcode scan bailed (counts unverifiable)", () => {
    // code section, one func: loop 0x40, then unknown opcode 0xFF, end → scanComplete=false
    const SCAN_BAILS = "0A070105000340FF0B";
    const info = readWasm(hexToBytes(HEADER + SCAN_BAILS));
    expect(info.scanComplete).toBe(false);
    const r = runHook(hexToBytes(HEADER + SCAN_BAILS));
    expect(r.exit).toBe("halted");
    expect(r.returnString).toMatch(/opcode scan incomplete/);
  });
});

describe("M1 — declared memory is capped before instantiation", () => {
  it("refuses a module declaring more memory pages than the cap", () => {
    // memory section (id 5): count 1, limits flags 0, min = 65536 pages (4 GiB)
    const bytes = hexToBytes(HEADER + "050501008080" + "04");
    const info = readWasm(bytes);
    expect(info.memory?.min).toBe(65536);
    const r = runHook(bytes);
    expect(r.exit).toBe("halted");
    expect(r.returnString).toMatch(/memory pages/);
  });
});

describe("M2 — oversized bytecode is refused before compile", () => {
  it("refuses a module larger than the byte cap", () => {
    const r = runHook(new Uint8Array(200_000));
    expect(r.exit).toBe("halted");
    expect(r.returnString).toMatch(/cap.*refusing to compile|refusing to compile/);
  });
});
