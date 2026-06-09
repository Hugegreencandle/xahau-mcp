// Minimal valid-WASM emitter for tests. Produces real modules (validated with the built-in
// WebAssembly API) so the hand-rolled reader can be cross-checked, with optional guarded/unguarded
// loops to exercise loop/guard counting. Hook func type is () -> ().
function uleb(n: number): number[] {
  const out: number[] = [];
  do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n);
  return out;
}
function section(id: number, body: number[]): number[] {
  return [id, ...uleb(body.length), ...body];
}
function name(s: string): number[] {
  const bytes = [...Buffer.from(s, "utf-8")];
  return [...uleb(bytes.length), ...bytes];
}
function vec(items: number[][]): number[] {
  return [...uleb(items.length), ...items.flat()];
}

export interface HookOpts {
  imports?: { module: string; name: string }[]; // function imports, in order
  exportHook?: boolean;
  exportCbak?: boolean;
  loop?: "none" | "guarded" | "unguarded";
  memPages?: number;
}

export function buildHookWasm(opts: HookOpts = {}): Uint8Array {
  const imports = opts.imports ?? [{ module: "env", name: "_g" }, { module: "env", name: "accept" }];
  const guardIdx = imports.findIndex((i) => i.name === "_g");
  // type section: one type, () -> ()
  const types = section(1, vec([[0x60, 0x00, 0x00]]));
  // import section: each func import uses type index 0
  const imp = section(2, vec(imports.map((i) => [...name(i.module), ...name(i.name), 0x00, 0x00])));
  // function section: one local function (the hook body), type 0
  const localFuncIdx = imports.length; // imported funcs occupy 0..n-1
  const funcs = section(3, vec([[0x00]]));
  // memory section: one memory, min = memPages (default 1)
  const mem = section(5, vec([[0x00, ...uleb(opts.memPages ?? 1)]]));
  // export section
  const exps: number[][] = [];
  if (opts.exportHook !== false) exps.push([...name("hook"), 0x00, ...uleb(localFuncIdx)]);
  if (opts.exportCbak) exps.push([...name("cbak"), 0x00, ...uleb(localFuncIdx)]);
  const exp = section(7, vec(exps));
  // code section: body for the local func
  const body: number[] = [];
  if (opts.loop && opts.loop !== "none") {
    body.push(0x03, 0x40); // loop, blocktype empty
    if (opts.loop === "guarded" && guardIdx >= 0) {
      body.push(0x41, 0x01, 0x41, 0x01, 0x10, ...uleb(guardIdx), 0x1a); // i32.const 1, i32.const 1, call _g, drop
    }
    body.push(0x0b); // end loop
  }
  body.push(0x0b); // end function
  const func1 = [...uleb(0), ...body]; // 0 local-groups
  const code = section(10, vec([[...uleb(func1.length), ...func1]]));
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...types, ...imp, ...funcs, ...mem, ...exp, ...code]);
}

export const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
