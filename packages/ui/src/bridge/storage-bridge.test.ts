// @vitest-environment jsdom

/**
 * Covers the storage bridge's platform routing for non-credential keys:
 * web passthrough, electrobun desktop secure-store reads/writes/removals,
 * native synced-key mirroring between localStorage and Capacitor
 * Preferences, registerSyncedKey, and sessionStorage isolation.
 * Harness is deterministic: the real bridge module runs against in-memory
 * stand-ins for the native-only Capacitor/desktop boundaries.
 */
import {
  STEWARD_TOKEN_KEY,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Captured before any test can install the storage-bridge proxy so
// assertions can observe the raw underlying store, bypassing interception.
const rawStorage = window.localStorage;
const rawGetItem = rawStorage.getItem.bind(rawStorage) as (
  key: string,
) => string | null;
const rawSetItem = rawStorage.setItem.bind(rawStorage) as (
  key: string,
  value: string,
) => void;

// Mutable knobs read inside hoisted vi.mock factories; the `mock` prefix is
// vitest's sanctioned way for factories to close over module-level state.
const mockRuntime = { native: false, electrobun: false };
const mockPreferences = new Map<string, string>();
const mockDesktopStore = new Map<string, string>();
const mockDesktopSecure = {
  available: true,
  abortOnSet: null as AbortController | null,
  compareAndRestoreCalls: [] as Array<{
    kind: string;
    rollbackReceipt: string;
  }>,
  receiptSequence: 0,
  rejectSets: false,
  failRemovals: false,
  revisions: new Map<string, number>(),
  rollbacks: new Map<
    string,
    {
      predecessor: string | null;
      receipt: string;
      revision: number;
    }
  >(),
};

vi.mock("@capacitor/core", () => ({
  Capacitor: {
    getPlatform: () => (mockRuntime.native ? "android" : "web"),
    isNativePlatform: () => mockRuntime.native,
  },
}));

vi.mock("@capacitor/preferences", () => ({
  Preferences: {
    get: async ({ key }: { key: string }) => ({
      value: mockPreferences.get(key) ?? null,
    }),
    set: async ({ key, value }: { key: string; value: string }) => {
      mockPreferences.set(key, value);
    },
    remove: async ({ key }: { key: string }) => {
      mockPreferences.delete(key);
    },
  },
}));

vi.mock("@elizaos/logger", () => ({
  logger: { error: () => undefined },
}));

vi.mock("../first-run/mobile-runtime-mode", () => ({
  MOBILE_RUNTIME_MODE_STORAGE_KEY: "eliza:mobile-runtime-mode",
}));

vi.mock("./electrobun-runtime", () => ({
  isElectrobunRuntime: () => mockRuntime.electrobun,
}));

vi.mock("./electrobun-rpc", () => ({
  desktopSecureStoreGet: async (kind: string) => {
    if (!mockDesktopSecure.available) {
      return { ok: false as const, reason: "unavailable" as const };
    }
    return mockDesktopStore.has(kind)
      ? { ok: true as const, value: mockDesktopStore.get(kind) }
      : { ok: false as const, reason: "not_found" as const };
  },
  desktopSecureStoreSet: async (kind: string, value: string) => {
    if (mockDesktopSecure.rejectSets) {
      return { ok: false as const, reason: "denied" as const };
    }
    const predecessor = mockDesktopStore.get(kind) ?? null;
    mockDesktopStore.set(kind, value);
    const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
    mockDesktopSecure.revisions.set(kind, revision);
    mockDesktopSecure.receiptSequence += 1;
    const rollbackReceipt = `mock-receipt-${mockDesktopSecure.receiptSequence}`;
    mockDesktopSecure.rollbacks.set(kind, {
      predecessor,
      receipt: rollbackReceipt,
      revision,
    });
    mockDesktopSecure.abortOnSet?.abort();
    return { ok: true as const, rollbackReceipt };
  },
  desktopSecureStoreDelete: async (kind: string) => {
    if (mockDesktopSecure.failRemovals) {
      return { ok: false as const, reason: "denied" as const };
    }
    mockDesktopStore.delete(kind);
    mockDesktopSecure.revisions.set(
      kind,
      (mockDesktopSecure.revisions.get(kind) ?? 0) + 1,
    );
    mockDesktopSecure.rollbacks.delete(kind);
    return { ok: true as const };
  },
  desktopSecureStoreCompareAndRestore: async (
    kind: string,
    rollbackReceipt: string,
  ) => {
    mockDesktopSecure.compareAndRestoreCalls.push({
      kind,
      rollbackReceipt,
    });
    const rollback = mockDesktopSecure.rollbacks.get(kind);
    const currentValue = mockDesktopStore.get(kind) ?? null;
    if (
      !rollback ||
      rollback.receipt !== rollbackReceipt ||
      rollback.revision !== mockDesktopSecure.revisions.get(kind)
    ) {
      return { ok: true as const, restored: false, value: currentValue };
    }
    if (rollback.predecessor === null) {
      mockDesktopStore.delete(kind);
    } else {
      mockDesktopStore.set(kind, rollback.predecessor);
    }
    mockDesktopSecure.revisions.set(kind, rollback.revision + 1);
    mockDesktopSecure.rollbacks.delete(kind);
    return {
      ok: true as const,
      restored: true,
      value: rollback.predecessor,
    };
  },
}));

vi.mock("../surface-realm-channel", () => ({
  runAsPrivilegedShell: (operation: () => unknown) => operation(),
}));

// The bridge keeps module-singleton state (proxy install flag, caches), so
// the module is imported exactly once and sections below progress the
// runtime knobs monotonically: web -> electrobun -> native.
let bridge: typeof import("./storage-bridge");

// Deferred native writes are scheduled with setTimeout(0); give them a macrotask.
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

beforeAll(async () => {
  bridge = await import("./storage-bridge");
});

beforeEach(() => {
  mockPreferences.clear();
  mockDesktopStore.clear();
  mockDesktopSecure.available = true;
  mockDesktopSecure.abortOnSet = null;
  mockDesktopSecure.compareAndRestoreCalls.length = 0;
  mockDesktopSecure.receiptSequence = 0;
  mockDesktopSecure.rejectSets = false;
  mockDesktopSecure.failRemovals = false;
  mockDesktopSecure.revisions.clear();
  mockDesktopSecure.rollbacks.clear();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe("storage bridge on the web runtime", () => {
  it("skips initialization entirely", async () => {
    rawSetItem("eliza.web.sentinel", "untouched");
    await bridge.initializeStorageBridge();
    expect(bridge.isStorageBridgeInitialized()).toBe(false);
    expect(rawGetItem("eliza.web.sentinel")).toBe("untouched");
  });

  it("round-trips values through localStorage alone", async () => {
    await bridge.setStorageValue("eliza.web.plain", "value-one");
    expect(rawGetItem("eliza.web.plain")).toBe("value-one");
    expect(await bridge.getStorageValue("eliza.web.plain")).toBe("value-one");

    await bridge.removeStorageValue("eliza.web.plain");
    expect(rawGetItem("eliza.web.plain")).toBeNull();
    expect(await bridge.getStorageValue("eliza.web.plain")).toBeNull();
  });

  it("removes a missing key without throwing", async () => {
    await expect(
      bridge.removeStorageValue("eliza.web.never-written"),
    ).resolves.toBeUndefined();
  });

  it("keeps registered keys local even after registerSyncedKey", async () => {
    bridge.registerSyncedKey("eliza.test.web-registered");
    await bridge.setStorageValue("eliza.test.web-registered", "local-only");
    expect(window.localStorage.getItem("eliza.test.web-registered")).toBe(
      "local-only",
    );
    await settle();
    expect(mockPreferences.size).toBe(0);
  });
});

describe("storage bridge on the electrobun desktop runtime", () => {
  beforeAll(() => {
    mockRuntime.electrobun = true;
  });

  it("initializes immediately because no cold native plugin must warm up", async () => {
    await bridge.initializeStorageBridge();
    expect(bridge.isStorageBridgeInitialized()).toBe(true);
  });

  it("persists session credentials only in the desktop secure store", async () => {
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "desktop-secret");
    expect(mockDesktopStore.get("session.steward_token")).toBe(
      "desktop-secret",
    );
    expect(rawGetItem(STEWARD_TOKEN_KEY)).toBeNull();
    // The installed proxy serves the live credential from its in-memory
    // cache; plaintext must only be absent from the RAW store above.
    expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
      "desktop-secret",
    );
    expect(await bridge.getStorageValue(STEWARD_TOKEN_KEY)).toBe(
      "desktop-secret",
    );
  });

  it("rejects an awaited write the desktop store refused", async () => {
    mockDesktopSecure.rejectSets = true;
    await expect(
      bridge.setStorageValue(STEWARD_TOKEN_KEY, "refused-write"),
    ).rejects.toThrow("Protected storage rejected write");
    expect(mockDesktopStore.has("session.steward_token")).toBe(false);
    expect(rawGetItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("reads a never-stored credential as null", async () => {
    expect(await bridge.getStorageValue("eliza.device.auth")).toBeNull();
  });

  it("removes a credential and tolerates removing it again", async () => {
    await bridge.setStorageValue("eliza.device.auth", "doomed-secret");
    await bridge.removeStorageValue("eliza.device.auth");
    expect(mockDesktopStore.has("session.device_auth")).toBe(false);
    expect(await bridge.getStorageValue("eliza.device.auth")).toBeNull();

    await expect(
      bridge.removeStorageValue("eliza.device.auth"),
    ).resolves.toBeUndefined();
  });

  it("rolls an aborted Steward write back through one host CAS request", async () => {
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "prior-token");
    const controller = new AbortController();
    mockDesktopSecure.abortOnSet = controller;

    await expect(
      writeStoredStewardToken("aborted-token", { signal: controller.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });

    expect(mockDesktopSecure.compareAndRestoreCalls).toEqual([
      {
        kind: "session.steward_token",
        rollbackReceipt: "mock-receipt-2",
      },
    ]);
    expect(mockDesktopStore.get("session.steward_token")).toBe("prior-token");
    expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("prior-token");
  });

  it("fails closed when the desktop secure store is unavailable", async () => {
    mockDesktopSecure.available = false;
    await expect(bridge.getStorageValue(STEWARD_TOKEN_KEY)).rejects.toThrow(
      "Desktop protected storage is unavailable",
    );
  });

  it("leaves ordinary keys in localStorage untouched by the secure store", async () => {
    await bridge.setStorageValue("eliza.desktop.plain", "ordinary");
    expect(window.localStorage.getItem("eliza.desktop.plain")).toBe("ordinary");
    expect(mockDesktopStore.size).toBe(0);
  });
});

describe("storage bridge on the native android runtime", () => {
  beforeAll(() => {
    mockRuntime.electrobun = false;
    mockRuntime.native = true;
  });

  it("mirrors synced localStorage writes into Capacitor Preferences and back out on removal", async () => {
    window.localStorage.setItem("eliza:first-run-complete", "resume-flag");
    expect(rawGetItem("eliza:first-run-complete")).toBe("resume-flag");
    await vi.waitFor(() => {
      expect(mockPreferences.get("eliza:first-run-complete")).toBe(
        "resume-flag",
      );
    });

    window.localStorage.removeItem("eliza:first-run-complete");
    expect(window.localStorage.getItem("eliza:first-run-complete")).toBeNull();
    await vi.waitFor(() => {
      expect(mockPreferences.has("eliza:first-run-complete")).toBe(false);
    });
  });

  it("never syncs unregistered keys to Preferences", async () => {
    window.localStorage.setItem("eliza.test.unregistered", "stays-local");
    await settle();
    expect(mockPreferences.size).toBe(0);
    expect(window.localStorage.getItem("eliza.test.unregistered")).toBe(
      "stays-local",
    );

    window.localStorage.removeItem("eliza.test.unregistered");
    await settle();
    expect(mockPreferences.size).toBe(0);
  });

  it("serves synced keys from Preferences even when localStorage is empty", async () => {
    mockPreferences.set("eliza.device.identity", "from-preferences");
    expect(await bridge.getStorageValue("eliza.device.identity")).toBe(
      "from-preferences",
    );
    expect(
      await bridge.getStorageValue("eliza.device.missing-synced"),
    ).toBeNull();
  });

  it("extends the synced set at runtime via registerSyncedKey", async () => {
    bridge.registerSyncedKey("eliza.test.native-registered");
    window.localStorage.setItem(
      "eliza.test.native-registered",
      "late-addition",
    );
    await vi.waitFor(() => {
      expect(mockPreferences.get("eliza.test.native-registered")).toBe(
        "late-addition",
      );
    });

    window.localStorage.removeItem("eliza.test.native-registered");
    await vi.waitFor(() => {
      expect(mockPreferences.has("eliza.test.native-registered")).toBe(false);
    });
  });

  it("keeps sessionStorage writes out of the native sync path", async () => {
    window.localStorage.setItem("eliza:first-run-complete", "disk-value");
    window.sessionStorage.setItem("eliza:first-run-complete", "session-value");
    await settle();

    expect(window.sessionStorage.getItem("eliza:first-run-complete")).toBe(
      "session-value",
    );
    expect(window.localStorage.getItem("eliza:first-run-complete")).toBe(
      "disk-value",
    );
    expect(mockPreferences.get("eliza:first-run-complete")).toBe("disk-value");
  });
});
