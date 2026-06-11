import { describe, it, expect } from "vitest";
import {
  evernodeHostDiagnostics, decodeHostAddrState, decodeTokenIdState, hostAddrKey, tokenIdKey,
  EVK, EVERNODE_GOVERNOR, EVERNODE_HOOK_NAMESPACE,
  type HostDeps,
} from "../src/evernodeHost.js";

const noSleep = (_ms: number) => Promise.resolve();

// REAL mainnet host registration state, captured live 2026-06-11 via
// ledger_entry hook_state(governor rBvKgF3jSZWdJcwSsmoJspoXLLDVLDp6jg, ns 01EAF0…) for host
// rGC8fvcc9QnTzsyXURKdwwgV9RGYW8z12A (accountId ABDF5B6904B912CDEE3498CC1490421EDFB3BA16). 143 bytes.
const HOST_STATE_HEX =
  "18BAE4EB1CA81D3FEDF97670E1FCA60EF73782012D7887C55454B9EE49A371A746520000000000000000200000000000000000000000000000000000000000000000000076D3360000000000F40100000000000003000000010000004D5B2A6A00000000000C012A35EA65000000000000000000000000000000000000FC01C88FAE69000000000080C6A47E8D4353";
const HOST_ADDR = "rGC8fvcc9QnTzsyXURKdwwgV9RGYW8z12A";
const HOST_ACCOUNT_ID = "ABDF5B6904B912CDEE3498CC1490421EDFB3BA16";
// Live config values (same capture): momentSize=3600s, heartbeatFreq=1 moment, timestamp moments.
const CONFIG: Record<string, string> = {
  [EVK.MOMENT_SIZE]: "100E",
  [EVK.HOST_HEARTBEAT_FREQ]: "0100",
  [EVK.MOMENT_BASE_INFO]: "16937A65000000000000000001",
  [EVK.EVR_ISSUER_ADDR]: "A3B6B1B61181DB9C81EED4F3D5109F6CFC31109B", // rEvernodee8dJLaFsujS6q1EiXvZYmHXr8
};

const RIPPLE_EPOCH = 946684800;
const reg = decodeHostAddrState(Uint8Array.from(Buffer.from(HOST_STATE_HEX, "hex")));

function deps(over: Partial<HostDeps> = {}): HostDeps {
  return {
    getAccountInfo: async () => ({ account_data: { Balance: "21746096608", Flags: 0 } }),
    getHookState: async (key: string) => {
      if (key === hostAddrKey(HOST_ACCOUNT_ID)) return HOST_STATE_HEX;
      return CONFIG[key] ?? null;
    },
    getLines: async () => [{ currency: "EVR", account: "rEvernodee8dJLaFsujS6q1EiXvZYmHXr8", balance: "123.45" }],
    getUriTokens: async () => [{ index: reg.uriTokenId, URI: "00" }],
    // "now" 30 min after the recorded heartbeat -> inside the active window
    getCloseTime: async () => reg.lastHeartbeatIndex + 1800 - RIPPLE_EPOCH,
    sleep: noSleep,
    ...over,
  };
}

describe("decodeHostAddrState — real mainnet entry", () => {
  it("decodes the live FR host correctly", () => {
    expect(reg.countryCode).toBe("FR");
    expect(reg.uriTokenId).toBe("18BAE4EB1CA81D3FEDF97670E1FCA60EF73782012D7887C55454B9EE49A371A7");
    expect(reg.maxInstances).toBe(3);
    expect(reg.activeInstances).toBe(1);
    expect(reg.version).toMatch(/^\d+\.\d+\.\d+$/);
    // heartbeat is a plausible 2024-2030 UNIX timestamp (timestamp-type moments on mainnet)
    expect(reg.lastHeartbeatIndex).toBeGreaterThan(1_700_000_000);
    expect(reg.lastHeartbeatIndex).toBeLessThan(1_900_000_000);
    expect(reg.reputation).not.toBeNull();
    expect(reg.leaseAmountEvr).toMatch(/^\d+(\.\d+)?$/);
  });

  it("state keys assemble to 32 bytes", () => {
    expect(hostAddrKey(HOST_ACCOUNT_ID)).toHaveLength(64);
    expect(tokenIdKey(reg.uriTokenId)).toHaveLength(64);
    expect(hostAddrKey(HOST_ACCOUNT_ID).startsWith("45565203")).toBe(true);
    expect(tokenIdKey(reg.uriTokenId).startsWith("45565202")).toBe(true);
  });
});

describe("evernode_host_diagnostics", () => {
  it("healthy registered host: registration PASS, heartbeat ACTIVE, EVR trustline PASS", async () => {
    const r = await evernodeHostDiagnostics(HOST_ADDR, "mainnet", deps());
    expect(r.isRegisteredHost).toBe(true);
    expect(r.heartbeat!.active).toBe(true);
    expect(r.heartbeat!.momentSizeSeconds).toBe(3600);
    expect(r.heartbeat!.heartbeatFreqMoments).toBe(1);
    expect(r.balances.evr).toBe("123.45");
    expect(r.balances.evrIssuer).toBe("rEvernodee8dJLaFsujS6q1EiXvZYmHXr8");
    expect(r.checks.find((c) => c.name === "registration")!.status).toBe("PASS");
    expect(r.checks.find((c) => c.name === "heartbeat")!.status).toBe("PASS");
    expect(r.checks.find((c) => c.name === "registration URIToken")!.status).toBe("PASS");
    expect(r.summary).toMatch(/Evernode host \(FR/);
  });

  it("stale heartbeat: INACTIVE by the on-chain rule + warning", async () => {
    const r = await evernodeHostDiagnostics(HOST_ADDR, "mainnet", deps({
      // "now" 3 moments after the last heartbeat -> outside the freq=1 window
      getCloseTime: async () => reg.lastHeartbeatIndex + 3 * 3600 + 600 - RIPPLE_EPOCH,
    }));
    expect(r.heartbeat!.active).toBe(false);
    expect(r.heartbeat!.momentsMissed).toBeGreaterThanOrEqual(2);
    expect(r.checks.find((c) => c.name === "heartbeat")!.status).toBe("FAIL");
    expect(r.warnings.join(" ")).toMatch(/INACTIVE/);
  });

  it("not a registered host: FAIL + pointer to the installer", async () => {
    const r = await evernodeHostDiagnostics("rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6", "mainnet", deps({
      getHookState: async (key: string) => CONFIG[key] ?? null, // no host entry
    }));
    expect(r.isRegisteredHost).toBe(false);
    expect(r.summary).toMatch(/NOT a registered Evernode host/);
    expect(r.checks.find((c) => c.name === "registration")!.status).toBe("FAIL");
  });

  it("missing EVR trustline: FAIL check + warning", async () => {
    const r = await evernodeHostDiagnostics(HOST_ADDR, "mainnet", deps({ getLines: async () => [] }));
    expect(r.checks.find((c) => c.name === "EVR trustline")!.status).toBe("FAIL");
    expect(r.warnings.join(" ")).toMatch(/EVR trustline/);
  });

  it("missing registration URIToken (no transfer pending): warning", async () => {
    const r = await evernodeHostDiagnostics(HOST_ADDR, "mainnet", deps({ getUriTokens: async () => [] }));
    expect(r.checks.find((c) => c.name === "registration URIToken")!.status).toBe("WARN");
    expect(r.warnings.join(" ")).toMatch(/URIToken/);
  });

  it("low XAH balance: heuristic warning, clearly labeled", async () => {
    const r = await evernodeHostDiagnostics(HOST_ADDR, "mainnet", deps({
      getAccountInfo: async () => ({ account_data: { Balance: "500000", Flags: 0 } }),
    }));
    const c = r.checks.find((x) => x.name === "XAH balance")!;
    expect(c.status).toBe("WARN");
    expect(c.detail).toMatch(/heuristic/);
  });

  it("config unreadable: liveness skipped honestly, diagnostics still returned", async () => {
    const r = await evernodeHostDiagnostics(HOST_ADDR, "mainnet", deps({
      getHookState: async (key: string) => (key === hostAddrKey(HOST_ACCOUNT_ID) ? HOST_STATE_HEX : null),
    }));
    expect(r.isRegisteredHost).toBe(true);
    expect(r.heartbeat).toBeNull();
    expect(r.notes.join(" ")).toMatch(/not evaluated/);
  });
});

describe("decodeTokenIdState", () => {
  it("decodes a synthetic specs entry", () => {
    const buf = Buffer.alloc(124, 0);
    Buffer.from(HOST_ACCOUNT_ID, "hex").copy(buf, 0);
    buf.write("AMD Ryzen 9 5950X", 20, "utf-8");
    buf.writeUInt16LE(16, 60); // cpuCount
    buf.writeUInt16LE(3400, 62); // MHz
    buf.writeUInt32LE(65536, 68); // ram
    buf.writeUInt32LE(2_000_000, 72); // disk
    buf.write("host@example.com", 76, "utf-8");
    buf.writeBigInt64LE(0n, 116); // accumulated reward XFL (zero)
    const t = decodeTokenIdState(Uint8Array.from(buf));
    expect(t.cpuModelName).toBe("AMD Ryzen 9 5950X");
    expect(t.cpuCount).toBe(16);
    expect(t.ramMb).toBe(65536);
    expect(t.email).toBe("host@example.com");
    expect(t.accumulatedRewardEvr).toBe("0");
  });
});

describe("constants", () => {
  it("governor + namespace match canonical evernode definitions", () => {
    expect(EVERNODE_GOVERNOR.mainnet).toBe("rBvKgF3jSZWdJcwSsmoJspoXLLDVLDp6jg");
    expect(EVERNODE_HOOK_NAMESPACE).toBe("01EAF09326B4911554384121FF56FA8FECC215FDDE2EC35D9E59F2C53EC665A0");
  });
});
