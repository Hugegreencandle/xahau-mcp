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

// A hook that actually CALLS accept/rollback with a return code, for the VM (sandbox) tests.
// Uses two func types: type0 ()->() for hook(); type1 (i32,i32,i64)->i64 for accept/rollback.
// Optionally calls one extra (unsupported) import first to exercise unsupported-call tracking.
export function buildExitHook(fn: "accept" | "rollback", code: number, opts: { extraImport?: string } = {}): Uint8Array {
  if (code < 0 || code > 63) throw new Error("test code must be 0..63 (single-byte sLEB)");
  const imports: { name: string; type: number }[] = [];
  if (opts.extraImport) imports.push({ name: opts.extraImport, type: 0 }); // ()->()
  imports.push({ name: fn, type: 1 }); // (i32,i32,i64)->i64
  const fnIdx = imports.findIndex((i) => i.name === fn);
  const extraIdx = opts.extraImport ? 0 : -1;

  const types = section(1, vec([
    [0x60, 0x00, 0x00], // type0 () -> ()
    [0x60, 0x03, 0x7f, 0x7f, 0x7e, 0x01, 0x7e], // type1 (i32,i32,i64) -> i64
  ]));
  const imp = section(2, vec(imports.map((i) => [...name("env"), ...name(i.name), 0x00, ...uleb(i.type)])));
  const localFuncIdx = imports.length;
  const funcs = section(3, vec([[0x00]])); // hook : type0
  const mem = section(5, vec([[0x00, 0x01]]));
  const exp = section(7, vec([[...name("hook"), 0x00, ...uleb(localFuncIdx)], [...name("memory"), 0x02, 0x00]]));
  const body: number[] = [];
  if (extraIdx >= 0) body.push(0x10, ...uleb(extraIdx)); // call unsupported (()->()), no stack effect
  body.push(0x41, 0x00, 0x41, 0x00, 0x42, code & 0x7f, 0x10, ...uleb(fnIdx), 0x1a); // i32.const0,i32.const0,i64.const code, call fn, drop
  body.push(0x0b);
  const func1 = [...uleb(0), ...body];
  const code10 = section(10, vec([[...uleb(func1.length), ...func1]]));
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...types, ...imp, ...funcs, ...mem, ...exp, ...code10]);
}
