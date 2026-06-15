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
  loop?: "none" | "guarded" | "unguarded" | "guarded-spin";
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
    if ((opts.loop === "guarded" || opts.loop === "guarded-spin") && guardIdx >= 0) {
      // guarded-spin uses maxiter=0 (no per-guard cap) so only the VM's own budget can stop it
      const maxiter = opts.loop === "guarded-spin" ? 0x00 : 0x01;
      body.push(0x41, 0x01, 0x41, maxiter, 0x10, ...uleb(guardIdx), 0x1a); // i32.const 1, i32.const maxiter, call _g, drop
    }
    if (opts.loop === "guarded-spin") body.push(0x0c, 0x00); // br 0 — branch back: actually spins
    body.push(0x0b); // end loop
  }
  body.push(0x0b); // end function
  const func1 = [...uleb(0), ...body]; // 0 local-groups
  const code = section(10, vec([[...uleb(func1.length), ...func1]]));
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...types, ...imp, ...funcs, ...mem, ...exp, ...code]);
}

export const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

// A hook whose decision DEPENDS on input: accepts iff otxn_type() == acceptTxValue, else rollbacks.
// Exercises the fuzzer's per-axis boundary detection over the txType axis.
// Imports: env.otxn_type ()->i64 (type1), env.accept/env.rollback (i32,i32,i64)->i64 (type2).
export function buildBranchOnTxTypeHook(acceptTxValue: number): Uint8Array {
  if (acceptTxValue < 0 || acceptTxValue > 63) throw new Error("acceptTxValue must be 0..63 (single-byte sLEB i64.const)");
  // imports order: otxn_type(0), accept(1), rollback(2)
  const imports = [
    { name: "otxn_type", type: 1 },
    { name: "accept", type: 2 },
    { name: "rollback", type: 2 },
  ];
  const otxnIdx = 0, acceptIdx = 1, rollbackIdx = 2;
  const localFuncIdx = imports.length; // hook()

  const types = section(1, vec([
    [0x60, 0x00, 0x00], // type0 () -> ()  (hook)
    [0x60, 0x00, 0x01, 0x7e], // type1 () -> i64  (otxn_type)
    [0x60, 0x03, 0x7f, 0x7f, 0x7e, 0x01, 0x7e], // type2 (i32,i32,i64) -> i64 (accept/rollback)
  ]));
  const imp = section(2, vec(imports.map((i) => [...name("env"), ...name(i.name), 0x00, ...uleb(i.type)])));
  const funcs = section(3, vec([[0x00]])); // hook : type0
  const mem = section(5, vec([[0x00, 0x01]]));
  const exp = section(7, vec([[...name("hook"), 0x00, ...uleb(localFuncIdx)], [...name("memory"), 0x02, 0x00]]));

  const body: number[] = [];
  // otxn_type()  -> i64 on stack
  body.push(0x10, ...uleb(otxnIdx));
  // i64.const acceptTxValue
  body.push(0x42, acceptTxValue & 0x7f);
  // i64.eq -> i32
  body.push(0x51);
  // if (blocktype empty 0x40) ... else ... end
  body.push(0x04, 0x40);
  //   accept(0,0,1) drop
  body.push(0x41, 0x00, 0x41, 0x00, 0x42, 0x01, 0x10, ...uleb(acceptIdx), 0x1a);
  body.push(0x05); // else
  //   rollback(0,0,0) drop
  body.push(0x41, 0x00, 0x41, 0x00, 0x42, 0x00, 0x10, ...uleb(rollbackIdx), 0x1a);
  body.push(0x0b); // end if
  body.push(0x0b); // end function

  const func1 = [...uleb(0), ...body];
  const code10 = section(10, vec([[...uleb(func1.length), ...func1]]));
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...types, ...imp, ...funcs, ...mem, ...exp, ...code10]);
}

// A hook that reads a field/param/state via a read host fn into a fixed-size guest buffer, then
// branches on the SIGN of the return code: rollback(0) if rc < 0 (the defensive "read failed"
// pattern), else accept(1). This is the exact verdict-flip path for the TOO_SMALL truncation bug —
// real xahaud returns TOO_SMALL (-4) when the buffer is too small (→ rollback), whereas the old
// sandbox silently truncated and returned a positive length (→ accept).
//
// The read fn is invoked as `readFn(write_ptr=0, write_len=wl, a3, a4)`. The 4-arg type covers the
// common read signatures: otxn_field(wp,wl,fid) ignores the extra 4th arg (JS), state(wp,wl,kp,kl)
// and hook_param(wp,wl,kp,kl) use both. So pass a3=fid for otxn_field, or a3=key_ptr / a4=key_len
// for state / hook_param.
// Imports: env.<readFn>(i32,i32,i32,i32)->i64 (type2), env.accept/env.rollback (i32,i32,i64)->i64 (type1).
export function buildReadFieldHook(readFn = "otxn_field", wl = 4, a3 = 6, a4 = 0): Uint8Array {
  for (const n of [wl, a3, a4]) if (n < 0 || n > 63) throw new Error("wl/a3/a4 must be 0..63 (single-byte i32.const)");
  // imports order: readFn(0), accept(1), rollback(2)
  const imports = [
    { name: readFn, type: 2 }, // (i32,i32,i32,i32)->i64
    { name: "accept", type: 1 }, // (i32,i32,i64)->i64
    { name: "rollback", type: 1 },
  ];
  const readIdx = 0, acceptIdx = 1, rollbackIdx = 2;
  const localFuncIdx = imports.length;

  const types = section(1, vec([
    [0x60, 0x00, 0x00], // type0 () -> ()  (hook)
    [0x60, 0x03, 0x7f, 0x7f, 0x7e, 0x01, 0x7e], // type1 (i32,i32,i64) -> i64 (accept/rollback)
    [0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7e], // type2 (i32,i32,i32,i32) -> i64 (read fn)
  ]));
  const imp = section(2, vec(imports.map((i) => [...name("env"), ...name(i.name), 0x00, ...uleb(i.type)])));
  const funcs = section(3, vec([[0x00]])); // hook : type0
  const mem = section(5, vec([[0x00, 0x01]]));
  const exp = section(7, vec([[...name("hook"), 0x00, ...uleb(localFuncIdx)], [...name("memory"), 0x02, 0x00]]));

  const body: number[] = [];
  // readFn(write_ptr=0, write_len=wl, a3, a4)  -> i64 rc on stack
  body.push(0x41, 0x00, 0x41, wl & 0x7f, 0x41, a3 & 0x7f, 0x41, a4 & 0x7f, 0x10, ...uleb(readIdx));
  // rc < 0 ?  (i64.const 0, i64.lt_s)
  body.push(0x42, 0x00, 0x53);
  // if (blocktype empty) rollback(0,0,0) drop  else  accept(0,0,1) drop  end
  body.push(0x04, 0x40);
  body.push(0x41, 0x00, 0x41, 0x00, 0x42, 0x00, 0x10, ...uleb(rollbackIdx), 0x1a);
  body.push(0x05); // else
  body.push(0x41, 0x00, 0x41, 0x00, 0x42, 0x01, 0x10, ...uleb(acceptIdx), 0x1a);
  body.push(0x0b); // end if
  body.push(0x0b); // end function

  const func1 = [...uleb(0), ...body];
  const code10 = section(10, vec([[...uleb(func1.length), ...func1]]));
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...types, ...imp, ...funcs, ...mem, ...exp, ...code10]);
}

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
