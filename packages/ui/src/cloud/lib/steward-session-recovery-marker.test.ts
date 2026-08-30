// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionLogout,
  beginStewardSessionRecovery,
  completeStewardSessionLogout,
  completeStewardSessionRecovery,
  completeStewardSessionRecoverySnapshot,
  hasStewardSessionRecovery,
  readStewardSessionLogoutIntents,
  readStewardSessionRecovery,
  rejectStewardSessionRecovery,
} from "./steward-session-recovery-marker";

const TENANT = "elizacloud";

function createMemoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() {
      return values.size;
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => {
      values.delete(key);
    },
    setItem: (key, value) => {
      values.set(key, String(value));
    },
  };
}

let storage: Storage;

beforeEach(() => {
  storage = createMemoryStorage();
  vi.stubGlobal("localStorage", storage);
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: storage,
  });
});

afterEach(() => {
  for (const intent of readStewardSessionLogoutIntents(TENANT).intents) {
    completeStewardSessionLogout(intent);
  }
  completeStewardSessionRecoverySnapshot(readStewardSessionRecovery(TENANT));
  storage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Steward session recovery receipts", () => {
  it("survives sessionStorage loss and a simulated tab remount", () => {
    const receipt = beginStewardSessionRecovery(TENANT, "oauth");
    window.sessionStorage.clear();

    const afterTabClose = readStewardSessionRecovery(TENANT);
    expect(afterTabClose.receipts).toEqual([receipt.receipt]);
    expect(afterTabClose.hasOAuth).toBe(true);
  });

  it("a definitive rejection removes only its own concurrent receipt", () => {
    const first = beginStewardSessionRecovery(TENANT, "oauth");
    const second = beginStewardSessionRecovery(TENANT, "provider");

    rejectStewardSessionRecovery(first);

    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      receipts: [second.receipt],
      hasOAuth: false,
    });
  });

  it("success clears its preexisting snapshot but preserves a newer intent", () => {
    const old = beginStewardSessionRecovery(TENANT, "oauth");
    const successful = beginStewardSessionRecovery(TENANT, "provider");
    const concurrentNewer = beginStewardSessionRecovery(TENANT, "oauth");

    completeStewardSessionRecovery(successful);

    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([
      concurrentNewer.receipt,
    ]);
    expect(hasStewardSessionRecovery(TENANT)).toBe(true);
    expect(readStewardSessionRecovery(TENANT).receipts).not.toContain(
      old.receipt,
    );
  });

  it("a cookie recovery clears only the receipts in its exact snapshot", () => {
    const first = beginStewardSessionRecovery(TENANT, "provider");
    const snapshot = readStewardSessionRecovery(TENANT);
    const later = beginStewardSessionRecovery(TENANT, "provider");

    completeStewardSessionRecoverySnapshot(snapshot);

    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([
      later.receipt,
    ]);
    expect(readStewardSessionRecovery(TENANT).receipts).not.toContain(
      first.receipt,
    );
  });

  it("fails closed when a receipt cannot be persisted durably", () => {
    storage.setItem = () => {
      throw new DOMException("Storage denied", "SecurityError");
    };

    expect(() => beginStewardSessionRecovery(TENANT, "provider")).toThrow(
      "durable recovery storage is unavailable",
    );
    expect(readStewardSessionRecovery(TENANT).receipts).toHaveLength(0);
  });

  it("reports storage as unavailable when marker enumeration fails", () => {
    const receipt = beginStewardSessionRecovery(TENANT, "provider");
    const workingKey = storage.key.bind(storage);
    storage.key = () => {
      throw new DOMException("Storage denied", "SecurityError");
    };

    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      receipts: [],
      storageAvailable: false,
    });
    expect(hasStewardSessionRecovery(TENANT)).toBe(true);

    storage.key = workingKey;
    expect(receipt.receipt).toEqual(expect.any(String));
  });

  it("uses origin-independent getRandomValues receipts when randomUUID is unavailable across module instances", async () => {
    const originalCrypto = globalThis.crypto;
    let entropy = 0;
    vi.stubGlobal("crypto", {
      subtle: originalCrypto.subtle,
      getRandomValues: <T extends ArrayBufferView | null>(array: T): T => {
        entropy += 1;
        if (array instanceof Uint32Array) array.fill(entropy);
        return array;
      },
    });
    const moduleA = await import("./steward-session-recovery-marker");
    vi.resetModules();
    const moduleB = await import("./steward-session-recovery-marker");

    const receiptA = moduleA.beginStewardSessionRecovery(TENANT, "provider");
    const receiptB = moduleB.beginStewardSessionRecovery(TENANT, "provider");

    expect(receiptA.receipt).not.toBe(receiptB.receipt);
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual(
      [receiptA.receipt, receiptB.receipt].sort(),
    );
  });

  it("retries a receipt collision observed from another module instance", async () => {
    const originalCrypto = globalThis.crypto;
    let entropyCall = 0;
    vi.stubGlobal("crypto", {
      subtle: originalCrypto.subtle,
      getRandomValues: <T extends ArrayBufferView | null>(array: T): T => {
        entropyCall += 1;
        if (array instanceof Uint32Array) {
          // Module B first reproduces module A's candidate, then receives a
          // new origin-independent value. The durable key, not module-local
          // counters, is the collision fence.
          array.fill(entropyCall <= 2 ? 7 : 8);
        }
        return array;
      },
    });
    const moduleA = await import("./steward-session-recovery-marker");
    const receiptA = moduleA.beginStewardSessionRecovery(TENANT, "provider");
    vi.resetModules();
    const moduleB = await import("./steward-session-recovery-marker");
    const receiptB = moduleB.beginStewardSessionRecovery(TENANT, "provider");

    expect(entropyCall).toBe(3);
    expect(receiptB.receipt).not.toBe(receiptA.receipt);
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual(
      [receiptA.receipt, receiptB.receipt].sort(),
    );
  });

  it("fails closed before persistence when secure receipt entropy is unavailable", () => {
    vi.stubGlobal("crypto", {});

    expect(() => beginStewardSessionRecovery(TENANT, "provider")).toThrow(
      "secure random receipt generation is unavailable",
    );
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([]);
  });

  it("keeps logout intent separate from cookie-first login receipts while blocking passive writers", () => {
    const login = beginStewardSessionRecovery(TENANT, "provider");
    const logout = beginStewardSessionLogout(
      TENANT,
      "logout",
      "cloud.eliza.app",
    );

    expect(readStewardSessionLogoutIntents(TENANT).intents).toEqual([logout]);
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      receipts: [login.receipt],
      storageAvailable: false,
    });
    expect(hasStewardSessionRecovery(TENANT)).toBe(true);

    completeStewardSessionLogout(logout);
    expect(readStewardSessionLogoutIntents(TENANT).intents).toEqual([]);
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      receipts: [],
      storageAvailable: true,
    });
  });
});
