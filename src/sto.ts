// Minimal STObject byte-walker: given a serialized object and a target sfield code
// ((typeCode << 16) | fieldCode, the value Hooks' slot_subfield/sto_subfield take), return the
// byte range of that field's VALUE. Self-contained (decodes field headers + per-type lengths);
// returns null for fields/types it can't size exactly (caller then reports unsupported — never guesses).

export interface FieldRange { start: number; len: number; typeCode: number; fieldCode: number; }

function readVL(b: Uint8Array, p: number): { len: number; headerLen: number } | null {
  const b1 = b[p];
  if (b1 === undefined) return null;
  if (b1 <= 192) return { len: b1, headerLen: 1 };
  if (b1 <= 240) { const b2 = b[p + 1]; if (b2 === undefined) return null; return { len: 193 + (b1 - 193) * 256 + b2, headerLen: 2 }; }
  if (b1 <= 254) { const b2 = b[p + 1], b3 = b[p + 2]; if (b2 === undefined || b3 === undefined) return null; return { len: 12481 + (b1 - 241) * 65536 + b2 * 256 + b3, headerLen: 3 }; }
  return null;
}

// returns value length and how many header bytes precede the value, for the field whose
// TYPE byte is `typeCode`, with the cursor `p` pointing at the first value byte.
function valueLength(b: Uint8Array, p: number, typeCode: number): { len: number; vlHeader: number } | null {
  switch (typeCode) {
    case 16: return { len: 1, vlHeader: 0 }; // UInt8
    case 1: return { len: 2, vlHeader: 0 }; // UInt16
    case 2: return { len: 4, vlHeader: 0 }; // UInt32
    case 3: return { len: 8, vlHeader: 0 }; // UInt64
    case 4: return { len: 16, vlHeader: 0 }; // Hash128
    case 17: return { len: 20, vlHeader: 0 }; // Hash160
    case 5: return { len: 32, vlHeader: 0 }; // Hash256
    case 6: return { len: (b[p] & 0x80) ? 48 : 8, vlHeader: 0 }; // Amount: issued=48, native=8
    case 7: case 8: case 19: { const vl = readVL(b, p); return vl ? { len: vl.len, vlHeader: vl.headerLen } : null; } // Blob / AccountID / Vector256
    case 14: case 15: { // STObject (end 0xE1) / STArray (end 0xF1)
      const end = typeCode === 14 ? 0xe1 : 0xf1;
      const sub = skipInner(b, p, end);
      return sub === null ? null : { len: sub, vlHeader: 0 };
    }
    default: return null; // PathSet (18) and anything else: not sized here
  }
}

// length in bytes of an STObject/STArray body up to and including its end marker, starting at p
function skipInner(b: Uint8Array, p: number, endByte: number): number | null {
  let cur = p;
  for (let guard = 0; guard < 100000; guard++) {
    if (cur >= b.length) return null;
    if (b[cur] === endByte) return cur - p + 1;
    const hdr = parseHeader(b, cur);
    if (!hdr) return null;
    const vl = valueLength(b, hdr.next, hdr.typeCode);
    if (!vl) return null;
    cur = hdr.next + vl.vlHeader + vl.len;
  }
  return null;
}

function parseHeader(b: Uint8Array, p: number): { typeCode: number; fieldCode: number; next: number } | null {
  const h = b[p];
  if (h === undefined) return null;
  let typeCode = h >> 4;
  let fieldCode = h & 0x0f;
  let q = p + 1;
  if (typeCode === 0) { typeCode = b[q++]; if (typeCode === undefined) return null; }
  if (fieldCode === 0) { fieldCode = b[q++]; if (fieldCode === undefined) return null; }
  return { typeCode, fieldCode, next: q };
}

export interface FullField { code: number; typeCode: number; fieldCode: number; start: number; end: number; }

/** Walk every top-level field, returning its FULL byte range (header + value). null if unparseable. */
export function stoFields(blob: Uint8Array): FullField[] | null {
  const out: FullField[] = [];
  let p = 0;
  for (let guard = 0; guard < 100000 && p < blob.length; guard++) {
    const start = p;
    const hdr = parseHeader(blob, p);
    if (!hdr) return null;
    const vl = valueLength(blob, hdr.next, hdr.typeCode);
    if (!vl) return null;
    const end = hdr.next + vl.vlHeader + vl.len;
    out.push({ code: (hdr.typeCode << 16) | hdr.fieldCode, typeCode: hdr.typeCode, fieldCode: hdr.fieldCode, start, end });
    p = end;
  }
  return out;
}

/** sto_emplace: return `blob` with `fieldBytes` (a complete serialized field, header+value) inserted/
 *  replaced at its canonical position. Returns null if the source or field bytes can't be parsed. */
export function stoEmplace(blob: Uint8Array, fieldBytes: Uint8Array): Uint8Array | null {
  const fields = stoFields(blob);
  const fhdr = parseHeader(fieldBytes, 0);
  if (!fields || !fhdr) return null;
  const newCode = (fhdr.typeCode << 16) | fhdr.fieldCode;
  const kept = fields.filter((f) => f.code !== newCode);
  // canonical order: ascending sfield code (type, then field)
  const segs: Uint8Array[] = [];
  let inserted = false;
  for (const f of kept) {
    if (!inserted && newCode < f.code) { segs.push(fieldBytes); inserted = true; }
    segs.push(blob.slice(f.start, f.end));
  }
  if (!inserted) segs.push(fieldBytes);
  return concat(segs);
}

/** sto_erase: return `blob` with the field of `sfieldCode` removed. null if unparseable or absent. */
export function stoErase(blob: Uint8Array, sfieldCode: number): Uint8Array | null {
  const fields = stoFields(blob);
  if (!fields) return null;
  if (!fields.some((f) => f.code === sfieldCode)) return null;
  return concat(fields.filter((f) => f.code !== sfieldCode).map((f) => blob.slice(f.start, f.end)));
}

/** Encode a field header from a type/field code (inverse of parseHeader). */
export function encodeFieldHeader(typeCode: number, fieldCode: number): number[] {
  const out: number[] = [(typeCode < 16 ? typeCode : 0) << 4 | (fieldCode < 16 ? fieldCode : 0)];
  if (typeCode >= 16) out.push(typeCode);
  if (fieldCode >= 16) out.push(fieldCode);
  return out;
}

/** Encode a variable-length prefix (inverse of readVL). */
export function encodeVL(len: number): number[] {
  if (len <= 192) return [len];
  if (len <= 12480) { const x = len - 193; return [193 + (x >> 8), x & 0xff]; }
  const x = len - 12481;
  return [241 + (x >> 16), (x >> 8) & 0xff, x & 0xff];
}

/** Build a complete serialized field (header [+ VL prefix] + value) for an sfield code. */
export function buildField(sfieldCode: number, value: Uint8Array): Uint8Array {
  const t = (sfieldCode >> 16) & 0xffff, f = sfieldCode & 0xffff;
  const hdr = encodeFieldHeader(t, f);
  const vl = (t === 7 || t === 8 || t === 19) ? encodeVL(value.length) : [];
  return new Uint8Array([...hdr, ...vl, ...value]);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Find the value byte-range of the field with the given sfield code ((type<<16)|field). */
export function stoFieldRange(blob: Uint8Array, sfieldCode: number): FieldRange | null {
  const wantType = (sfieldCode >> 16) & 0xffff;
  const wantField = sfieldCode & 0xffff;
  let p = 0;
  for (let guard = 0; guard < 100000 && p < blob.length; guard++) {
    const hdr = parseHeader(blob, p);
    if (!hdr) return null;
    const vl = valueLength(blob, hdr.next, hdr.typeCode);
    if (!vl) return null;
    const valStart = hdr.next + vl.vlHeader;
    if (hdr.typeCode === wantType && hdr.fieldCode === wantField) {
      return { start: valStart, len: vl.len, typeCode: hdr.typeCode, fieldCode: hdr.fieldCode };
    }
    p = valStart + vl.len;
  }
  return null;
}
