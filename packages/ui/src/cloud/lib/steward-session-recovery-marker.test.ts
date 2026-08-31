// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionLogout,
  beginStewardSessionRecovery,
  completeStewardSessionLogout,
  completeStewardSessionRecovery,
  completeStewardSessionRecoveryReceipt,
  completeStewardSessionRecoverySnapshot,
  createStewardSessionRecoveryPublicationFence,
  createStewardSessionRecoverySnapshotPublicationFence,
  doesStewardSessionRecoverySnapshotMatchToken,
  hasStewardSessionRecovery,
  isStewardSessionRecoveryReceiptLive,
  isStewardSessionRecoverySnapshotLive,
  markStewardSessionRecoveryCookiePending,
  readStewardSessionLogoutIntents,
  readStewardSessionRecovery,
  rejectStewardSessionRecovery,
} from "./steward-session-recovery-marker";

const TENANT = "elizacloud";

function makeJwt(
  userId: string,
  tenantId = TENANT,
  extra: Record<string, unknown> = {},
): string {
  const payload = btoa(JSON.stringify({ sub: userId, tenantId, ...extra }))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `header.${payload}.signature`;
}

function findRecoveryMarkerKey(receipt: string): string {
  const key = Array.from({ length: storage.length }, (_, index) =>
    storage.key(index),
  ).find(
    (candidate) =>
      candidate?.includes("steward.server-session-recovery") &&
      candidate.endsWith(`:${receipt}`),
  );
  if (!key) throw new Error(`Missing recovery marker for ${receipt}`);
  return key;
}

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
    expect(afterTabClose).toMatchObject({
      currentReceiptPhase: "reserved",
      expectedIdentity: null,
    });
    expect(
      doesStewardSessionRecoverySnapshotMatchToken(
        afterTabClose,
        makeJwt("stale-account-a"),
      ),
    ).toBe(false);
  });

  it("arms only the exact current reservation and binds refresh recovery to the attempted identity", () => {
    const attemptedB = makeJwt("account-b");
    const rotatedB = makeJwt("account-b", TENANT, { rotation: 2 });
    const staleA = makeJwt("account-a");
    const recovery = beginStewardSessionRecovery(TENANT, "provider");

    markStewardSessionRecoveryCookiePending(recovery, attemptedB);

    const pending = readStewardSessionRecovery(TENANT);
    expect(pending).toMatchObject({
      generation: recovery.receipt,
      currentReceiptKind: "provider",
      currentReceiptPhase: "cookie_pending",
      expectedIdentity: { userId: "account-b", tenantId: TENANT },
    });
    expect(
      doesStewardSessionRecoverySnapshotMatchToken(pending, rotatedB),
    ).toBe(true);
    expect(doesStewardSessionRecoverySnapshotMatchToken(pending, staleA)).toBe(
      false,
    );
  });

  it("never replaces an existing cookie-recovery identity binding", () => {
    const recovery = beginStewardSessionRecovery(TENANT, "provider");
    const accountB = makeJwt("account-b");
    const accountC = makeJwt("account-c");
    markStewardSessionRecoveryCookiePending(recovery, accountB);

    expect(() =>
      markStewardSessionRecoveryCookiePending(recovery, accountC),
    ).toThrow("could not be persisted");

    const pending = readStewardSessionRecovery(TENANT);
    expect(pending.expectedIdentity).toEqual({
      userId: "account-b",
      tenantId: TENANT,
    });
    expect(
      doesStewardSessionRecoverySnapshotMatchToken(pending, accountB),
    ).toBe(true);
    expect(
      doesStewardSessionRecoverySnapshotMatchToken(pending, accountC),
    ).toBe(false);
  });

  it("rolls A back to reserved when B supersedes its dispatch transition", () => {
    const accountA = beginStewardSessionRecovery(TENANT, "provider");
    const accountAKey = findRecoveryMarkerKey(accountA.receipt);
    const reservedRaw = storage.getItem(accountAKey);
    const setItem = storage.setItem.bind(storage);
    let accountB: ReturnType<typeof beginStewardSessionRecovery> | undefined;
    storage.setItem = (key, value) => {
      setItem(key, value);
      if (
        key === accountAKey &&
        String(value).includes("cookie_pending") &&
        !accountB
      ) {
        accountB = beginStewardSessionRecovery(TENANT, "provider");
      }
    };

    expect(() =>
      markStewardSessionRecoveryCookiePending(accountA, makeJwt("account-a")),
    ).toThrow("superseded during cookie mutation dispatch");

    expect(storage.getItem(accountAKey)).toBe(reservedRaw);
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      generation: accountB?.receipt,
      currentReceiptPhase: "reserved",
      expectedIdentity: null,
    });
    expect(isStewardSessionRecoveryReceiptLive(accountA)).toBe(false);
  });

  it("treats legacy and partial v2 markers as block-only reservations", () => {
    const legacyReceipt = "legacy-receipt";
    const markerPrefix = `eliza.steward.server-session-recovery.v2:${encodeURIComponent(TENANT)}`;
    const generationKey = `eliza.steward.server-session-generation.v1:${encodeURIComponent(TENANT)}`;
    window.localStorage.setItem(
      `${markerPrefix}:${legacyReceipt}`,
      JSON.stringify({
        kind: "provider",
        expectedIdentity: { userId: "account-b", tenantId: TENANT },
      }),
    );
    window.localStorage.setItem(generationKey, legacyReceipt);

    const legacy = readStewardSessionRecovery(TENANT);
    expect(legacy).toMatchObject({
      receipts: [legacyReceipt],
      generation: legacyReceipt,
      currentReceiptPhase: "reserved",
    });
    expect(
      doesStewardSessionRecoverySnapshotMatchToken(
        legacy,
        makeJwt("account-b"),
      ),
    ).toBe(false);

    window.localStorage.removeItem(generationKey);
    const missingGeneration = readStewardSessionRecovery(TENANT);
    expect(missingGeneration).toMatchObject({
      receipts: [legacyReceipt],
      generation: null,
      currentReceiptPhase: null,
      expectedIdentity: null,
    });
    expect(
      doesStewardSessionRecoverySnapshotMatchToken(
        missingGeneration,
        makeJwt("account-b"),
      ),
    ).toBe(false);
  });

  it("never revives pending A after newer reserved B is rejected", () => {
    const accountA = beginStewardSessionRecovery(TENANT, "provider");
    markStewardSessionRecoveryCookiePending(accountA, makeJwt("account-a"));
    const accountB = beginStewardSessionRecovery(TENANT, "provider");

    rejectStewardSessionRecovery(accountB);

    const afterB = readStewardSessionRecovery(TENANT);
    expect(afterB).toMatchObject({
      receipts: [accountA.receipt],
      generation: accountB.receipt,
      currentReceiptPhase: null,
      expectedIdentity: null,
    });
    expect(isStewardSessionRecoveryReceiptLive(accountA)).toBe(false);
    expect(
      doesStewardSessionRecoverySnapshotMatchToken(
        afterB,
        makeJwt("account-a"),
      ),
    ).toBe(false);
  });

  it("keeps Telegram recovery distinct from generic cookie publication", () => {
    const recovery = beginStewardSessionRecovery(TENANT, "telegram");
    markStewardSessionRecoveryCookiePending(recovery, makeJwt("account-b"));

    const pending = readStewardSessionRecovery(TENANT);
    expect(pending).toMatchObject({
      currentReceiptKind: "telegram",
      currentReceiptPhase: "cookie_pending",
    });
    expect(
      doesStewardSessionRecoverySnapshotMatchToken(
        pending,
        makeJwt("account-b"),
      ),
    ).toBe(false);
  });

  it("rolls a failed dispatch-phase persistence back to the exact reservation", () => {
    const recovery = beginStewardSessionRecovery(TENANT, "provider");
    const key = findRecoveryMarkerKey(recovery.receipt);
    const reservedRaw = storage.getItem(key);
    const setItem = storage.setItem.bind(storage);
    let pendingWrites = 0;
    storage.setItem = (candidate, value) => {
      setItem(candidate, value);
      if (candidate === key && String(value).includes("cookie_pending")) {
        pendingWrites += 1;
        throw new DOMException("Storage denied", "SecurityError");
      }
    };

    expect(() =>
      markStewardSessionRecoveryCookiePending(recovery, makeJwt("account-b")),
    ).toThrow("could not be persisted");
    expect(pendingWrites).toBe(1);
    expect(storage.getItem(key)).toBe(reservedRaw);
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      currentReceiptPhase: "reserved",
      expectedIdentity: null,
    });
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

  it.each(["complete", "reject"] as const)(
    "keeps an empty snapshot invalid after a newer receipt is %s",
    (outcome) => {
      const empty = readStewardSessionRecovery(TENANT);
      expect(isStewardSessionRecoverySnapshotLive(empty)).toBe(true);

      const newer = beginStewardSessionRecovery(TENANT, "provider");
      if (outcome === "complete") {
        completeStewardSessionRecovery(newer);
      } else {
        rejectStewardSessionRecovery(newer);
      }

      const after = readStewardSessionRecovery(TENANT);
      expect(after.receipts).toEqual([]);
      expect(after.generation).toBe(newer.receipt);
      expect(isStewardSessionRecoverySnapshotLive(empty)).toBe(false);
    },
  );

  it("confirms exact receipt removal before authenticated publication", () => {
    const recovery = beginStewardSessionRecovery(TENANT, "provider");
    const publication = createStewardSessionRecoveryPublicationFence(recovery);

    expect(publication.finalizeBeforePublish()).toEqual(expect.any(Function));
    expect(publication.isFinalized()).toBe(true);
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      receipts: [],
      generation: recovery.receipt,
    });
  });

  it("exposes a pre-durable rollback that rearms the exact recovery marker", () => {
    const recovery = beginStewardSessionRecovery(TENANT, "provider");
    const publication = createStewardSessionRecoveryPublicationFence(recovery);
    const rollback = publication.finalizeBeforePublish();
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([]);

    rollback.beforeDurableRestore?.();

    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([
      recovery.receipt,
    ]);
    expect(publication.isFinalized()).toBe(false);
    expect(() => rollback(false)).not.toThrow();
  });

  it("rejects publication when durable receipt removal fails", () => {
    const recovery = beginStewardSessionRecovery(TENANT, "provider");
    const publication = createStewardSessionRecoveryPublicationFence(recovery);
    const remove = storage.removeItem.bind(storage);
    storage.removeItem = (key) => {
      if (key.endsWith(`:${recovery.receipt}`)) {
        throw new DOMException("Storage denied", "SecurityError");
      }
      remove(key);
    };

    expect(() => publication.finalizeBeforePublish()).toThrow(
      "could not be retired",
    );
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([
      recovery.receipt,
    ]);
  });

  it("restores exact raw proof after transient rollback enumeration failure", () => {
    const recovery = beginStewardSessionRecovery(TENANT, "provider");
    const publication = createStewardSessionRecoveryPublicationFence(recovery);
    const markerKey = Array.from({ length: storage.length }, (_, index) =>
      storage.key(index),
    ).find((key) => key?.endsWith(`:${recovery.receipt}`));
    expect(markerKey).toBeTruthy();
    const rawMarker = storage.getItem(markerKey as string);
    const rollback = publication.finalizeBeforePublish();
    expect(storage.getItem(markerKey as string)).toBeNull();

    const key = storage.key.bind(storage);
    let enumerationFailed = false;
    storage.key = (index) => {
      if (!enumerationFailed) {
        enumerationFailed = true;
        throw new DOMException("Transient storage failure", "SecurityError");
      }
      return key(index);
    };

    expect(() => rollback(false)).not.toThrow();
    expect(enumerationFailed).toBe(true);
    expect(storage.getItem(markerKey as string)).toBe(rawMarker);
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([
      recovery.receipt,
    ]);
  });

  it("does not restore A when reentrant successor B starts during silent removal", () => {
    const recovery = beginStewardSessionRecovery(TENANT, "provider");
    const publication = createStewardSessionRecoveryPublicationFence(recovery);
    const remove = storage.removeItem.bind(storage);
    let successor: ReturnType<typeof beginStewardSessionRecovery> | undefined;
    storage.removeItem = (key) => {
      remove(key);
      if (key.endsWith(`:${recovery.receipt}`)) {
        successor = beginStewardSessionRecovery(TENANT, "provider");
      }
    };

    expect(() => publication.finalizeBeforePublish()).toThrow("superseded");
    expect(successor?.preexistingReceipts).toEqual([]);
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      generation: successor?.receipt,
      receipts: [successor?.receipt],
    });
  });

  it("commits an exact cookie-recovery snapshot before publication", () => {
    beginStewardSessionRecovery(TENANT, "provider");
    const latest = beginStewardSessionRecovery(TENANT, "oauth");
    const snapshot = readStewardSessionRecovery(TENANT);
    const publication =
      createStewardSessionRecoverySnapshotPublicationFence(snapshot);

    expect(publication.finalizeBeforePublish()).toEqual(expect.any(Function));
    expect(publication.isFinalized()).toBe(true);
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      generation: latest.receipt,
      receipts: [],
    });
  });

  it("rejects an empty snapshot after a newer completed login", () => {
    const snapshot = readStewardSessionRecovery(TENANT);
    const newer = beginStewardSessionRecovery(TENANT, "provider");
    completeStewardSessionRecovery(newer);
    const publication =
      createStewardSessionRecoverySnapshotPublicationFence(snapshot);

    expect(() => publication.finalizeBeforePublish()).toThrow("superseded");
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      generation: newer.receipt,
      receipts: [],
    });
  });

  it("invalidates an empty snapshot across independently evaluated module instances", async () => {
    const moduleA = await import("./steward-session-recovery-marker");
    const emptyA = moduleA.readStewardSessionRecovery(TENANT);
    vi.resetModules();
    const moduleB = await import("./steward-session-recovery-marker");

    const newerB = moduleB.beginStewardSessionRecovery(TENANT, "provider");
    moduleB.completeStewardSessionRecovery(newerB);

    expect(moduleB.readStewardSessionRecovery(TENANT).receipts).toEqual([]);
    expect(moduleA.isStewardSessionRecoverySnapshotLive(emptyA)).toBe(false);
  });

  it("invalidates even an empty snapshot while a newer receipt remains live", () => {
    const empty = readStewardSessionRecovery(TENANT);
    expect(isStewardSessionRecoverySnapshotLive(empty)).toBe(true);

    beginStewardSessionRecovery(TENANT, "provider");

    expect(isStewardSessionRecoverySnapshotLive(empty)).toBe(false);
  });

  it("supersedes an individual receipt only for receipts outside its initial ancestry", () => {
    const older = beginStewardSessionRecovery(TENANT, "provider");
    const accountA = beginStewardSessionRecovery(TENANT, "provider");

    rejectStewardSessionRecovery(older);
    expect(isStewardSessionRecoveryReceiptLive(accountA)).toBe(true);

    const accountB = beginStewardSessionRecovery(TENANT, "provider");
    expect(isStewardSessionRecoveryReceiptLive(accountA)).toBe(false);
    expect(isStewardSessionRecoveryReceiptLive(accountB)).toBe(true);
  });

  it.each(["complete", "reject"] as const)(
    "does not revive receipt A after newer receipt B is %s",
    (outcome) => {
      const accountA = beginStewardSessionRecovery(TENANT, "provider");
      const accountB = beginStewardSessionRecovery(TENANT, "provider");
      expect(isStewardSessionRecoveryReceiptLive(accountA)).toBe(false);

      if (outcome === "complete") {
        completeStewardSessionRecoveryReceipt(accountB);
      } else {
        rejectStewardSessionRecovery(accountB);
      }

      expect(readStewardSessionRecovery(TENANT).receipts).toEqual([
        accountA.receipt,
      ]);
      expect(isStewardSessionRecoveryReceiptLive(accountA)).toBe(false);
    },
  );

  it("fails closed when a receipt cannot be persisted durably", () => {
    storage.setItem = () => {
      throw new DOMException("Storage denied", "SecurityError");
    };

    expect(() => beginStewardSessionRecovery(TENANT, "provider")).toThrow(
      "durable recovery storage is unavailable",
    );
    expect(readStewardSessionRecovery(TENANT).receipts).toHaveLength(0);
  });

  it("fails closed and leaves a conservative marker when generation persistence fails", () => {
    const persist = storage.setItem.bind(storage);
    let writes = 0;
    storage.setItem = (key, value) => {
      writes += 1;
      if (writes === 2) {
        throw new DOMException("Storage denied", "SecurityError");
      }
      persist(key, value);
    };

    expect(() => beginStewardSessionRecovery(TENANT, "provider")).toThrow(
      "durable recovery generation storage is unavailable",
    );
    expect(readStewardSessionRecovery(TENANT).receipts).toHaveLength(1);
    expect(hasStewardSessionRecovery(TENANT)).toBe(true);
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
      generation: logout.receipt,
      storageAvailable: false,
    });
    expect(hasStewardSessionRecovery(TENANT)).toBe(true);

    completeStewardSessionLogout(logout);
    expect(readStewardSessionLogoutIntents(TENANT).intents).toEqual([]);
    expect(readStewardSessionRecovery(TENANT)).toMatchObject({
      receipts: [],
      generation: logout.receipt,
      storageAvailable: true,
    });
  });
});
