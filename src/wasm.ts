// Zero-dependency WebAssembly module reader for Hook CreateCode.
// We PARSE structure only (never execute): magic/version, section walk, LEB128,
// imports/exports/memory/custom sections, and a best-effort opcode walk of the
// Code section to count `loop` opcodes and calls to the `_g` guard import.
// Everything is graceful: a malformed module returns { valid:false, reason } rather than throwing,
// because reporting a broken hook is part of the job.

export interface WasmImport { module: string; name: string; kind: "func" | "table" | "memory" | "global"; }
export interface WasmExport { name: string; kind: "func" | "table" | "memory" | "global"; index: number; }
export interface WasmInfo {
  valid: boolean;
  reason?: string;
  version: number;
  byteSize: number;
  imports: WasmImport[];
  exports: WasmExport[];
  memory: { min: number; max: number | null } | null;
  customSections: { name: string; byteLength: number }[];
  funcImportCount: number;
  guardImportIndex: number | null; // function index of `_g`, or null if not imported
  guardCallCount: number;
  loopCount: number;
  instructionCount: number; // total opcodes across all function bodies (fee/complexity proxy)
  scanComplete: boolean; // false if the opcode walk bailed (counts are then lower bounds)
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) throw new Error("invalid hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}
export function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

class Reader {
  p = 0;
  constructor(public buf: Uint8Array) {}
  get done(): boolean { return this.p >= this.buf.length; }
  u8(): number { return this.buf[this.p++]; }
  bytes(n: number): Uint8Array { const b = this.buf.subarray(this.p, this.p + n); this.p += n; return b; }
  uleb(): number {
    let result = 0, shift = 0, byte: number;
    do {
      byte = this.buf[this.p++];
      result |= (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    return result >>> 0;
  }
  // signed LEB skip (value not needed) — advances cursor past a varint
  skipVarint(): void { while (this.buf[this.p++] & 0x80) {} }
  name(): string {
    const len = this.uleb();
    return Buffer.from(this.bytes(len)).toString("utf-8");
  }
}

const KIND = ["func", "table", "memory", "global"] as const;

export function readWasm(bytes: Uint8Array): WasmInfo {
  const info: WasmInfo = {
    valid: false, version: 0, byteSize: bytes.length, imports: [], exports: [],
    memory: null, customSections: [], funcImportCount: 0, guardImportIndex: null,
    guardCallCount: 0, loopCount: 0, instructionCount: 0, scanComplete: true,
  };
  try {
    if (bytes.length < 8 || bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
      info.reason = "not a WebAssembly module (bad magic)";
      return info;
    }
    info.version = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
    const r = new Reader(bytes);
    r.p = 8;
    let codeSection: Uint8Array | null = null;
    while (!r.done) {
      const id = r.u8();
      const size = r.uleb();
      const body = r.bytes(size);
      const s = new Reader(body);
      switch (id) {
        case 0: { // custom
          const name = s.name();
          info.customSections.push({ name, byteLength: body.length - s.p });
          break;
        }
        case 2: { // import
          const count = s.uleb();
          for (let i = 0; i < count; i++) {
            const module = s.name();
            const name = s.name();
            const k = s.u8();
            const kind = KIND[k] ?? "func";
            info.imports.push({ module, name, kind });
            if (kind === "func") {
              if (name === "_g") info.guardImportIndex = info.funcImportCount;
              info.funcImportCount++;
              s.uleb(); // type index
            } else if (kind === "table") { s.u8(); readLimits(s); }
            else if (kind === "memory") { readLimits(s); }
            else if (kind === "global") { s.u8(); s.u8(); } // valtype + mut
          }
          break;
        }
        case 5: { // memory
          const count = s.uleb();
          if (count > 0) info.memory = readLimits(s);
          break;
        }
        case 7: { // export
          const count = s.uleb();
          for (let i = 0; i < count; i++) {
            const name = s.name();
            const k = s.u8();
            const index = s.uleb();
            info.exports.push({ name, kind: KIND[k] ?? "func", index });
          }
          break;
        }
        case 10: codeSection = body; break;
      }
    }
    if (codeSection) scanCode(codeSection, info);
    info.valid = true;
    return info;
  } catch (e) {
    info.reason = `parse error: ${(e as Error).message}`;
    return info;
  }
}

function readLimits(s: Reader): { min: number; max: number | null } {
  const flags = s.u8();
  const min = s.uleb();
  const max = flags & 1 ? s.uleb() : null;
  return { min, max };
}

// Best-effort linear opcode walk to count `loop` (0x03) and `call _g`.
// Skips operands for standard opcodes to keep alignment; bails (scanComplete=false)
// on an unrecognized opcode so counts become lower bounds rather than garbage.
function scanCode(code: Uint8Array, info: WasmInfo): void {
  const s = new Reader(code);
  const funcCount = s.uleb();
  for (let f = 0; f < funcCount; f++) {
    const bodySize = s.uleb();
    const end = s.p + bodySize;
    // locals
    const localGroups = s.uleb();
    for (let i = 0; i < localGroups; i++) { s.uleb(); s.u8(); }
    walkExpr(s, end, info);
    s.p = end; // resync to declared body end regardless
  }
}

function walkExpr(s: Reader, end: number, info: WasmInfo): void {
  while (s.p < end) {
    const op = s.buf[s.p++];
    info.instructionCount++;
    switch (op) {
      case 0x03: info.loopCount++; s.u8(); break; // loop blocktype
      case 0x02: case 0x04: s.u8(); break;        // block / if blocktype (1-byte common case)
      case 0x0c: case 0x0d: s.uleb(); break;       // br / br_if
      case 0x0e: { const n = s.uleb(); for (let i = 0; i <= n; i++) s.uleb(); break; } // br_table
      case 0x10: { const idx = s.uleb(); if (info.guardImportIndex !== null && idx === info.guardImportIndex) info.guardCallCount++; break; } // call
      case 0x11: s.uleb(); s.uleb(); break;        // call_indirect
      case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: s.uleb(); break; // local/global
      case 0x3f: case 0x40: s.u8(); break;          // memory.size/grow
      case 0x41: case 0x42: s.skipVarint(); break;  // i32/i64.const
      case 0x43: s.p += 4; break;                   // f32.const
      case 0x44: s.p += 8; break;                   // f64.const
      case 0xfc: s.uleb(); s.uleb(); break;         // bulk-memory prefix (best effort)
      default:
        if (op >= 0x28 && op <= 0x3e) { s.uleb(); s.uleb(); break; } // mem load/store: align+offset
        if (
          (op >= 0x45 && op <= 0xc4) || // comparisons / numeric / conversions (no immediate)
          op === 0x00 || op === 0x01 || op === 0x05 || op === 0x0b || // unreachable/nop/else/end
          op === 0x0f || op === 0x1a || op === 0x1b // return/drop/select
        ) break;
        // unknown opcode — stop walking this function to avoid miscounting
        info.scanComplete = false;
        s.p = end;
        return;
    }
  }
}
