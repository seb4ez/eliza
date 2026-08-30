// @vitest-environment jsdom

import {
  registerStewardTokenPersistence,
  STEWARD_SESSION_CHANGE_EVENT,
  STEWARD_TOKEN_KEY,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enqueueStewardSessionMutation } from "../../lib/steward-session-mutation-queue";
import {
  beginStewardSessionRecovery,
  completeStewardSessionRecovery,
  completeStewardSessionRecoverySnapshot,
  isStewardSessionRecoveryReceiptLive,
  readStewardSessionRecovery,
  type StewardSessionRecoveryReceipt,
} from "../../lib/steward-session-recovery-marker";
import {
  exchangeStewardCodeViaApi,
  syncStewardSessionCookie,
} from "./steward-session";

const TENANT = "elizacloud";
const originalFetch = globalThis.fetch;

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
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
  completeStewardSessionRecoverySnapshot(readStewardSessionRecovery(TENANT));
  globalThis.fetch = originalFetch;
  storage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function runProviderTransaction(
  recovery: StewardSessionRecoveryReceipt,
  token: string,
): Promise<boolean> {
  return enqueueStewardSessionMutation(async (mutationLease) => {
    if (!isStewardSessionRecoveryReceiptLive(recovery)) return false;
    await syncStewardSessionCookie(token, null, {
      mutationLease,
      validate: () => isStewardSessionRecoveryReceiptLive(recovery),
    });
    if (!isStewardSessionRecoveryReceiptLive(recovery)) return false;
    completeStewardSessionRecovery(recovery);
    return true;
  });
}

async function runOAuthTransaction(
  recovery: StewardSessionRecoveryReceipt,
  code: string,
): Promise<boolean> {
  return enqueueStewardSessionMutation(async (mutationLease) => {
    if (!isStewardSessionRecoveryReceiptLive(recovery)) return false;
    const result = await exchangeStewardCodeViaApi(code, { mutationLease });
    if (!result.token || !isStewardSessionRecoveryReceiptLive(recovery)) {
      return false;
    }
    await writeStoredStewardToken(result.token, {
      validate: () => isStewardSessionRecoveryReceiptLive(recovery),
    });
    if (!isStewardSessionRecoveryReceiptLive(recovery)) return false;
    completeStewardSessionRecovery(recovery);
    return true;
  });
}

describe("full Steward session transactions", () => {
  it("keeps provider C as server and local authority when provider B was already in flight", async () => {
    const tokenB = "provider-token-b";
    const tokenC = "provider-token-c";
    const serverOrder: string[] = [];
    let releaseB: (response: Response) => void = () => {};
    globalThis.fetch = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body)) as { token: string };
        serverOrder.push(body.token);
        if (body.token === tokenB) {
          return await new Promise<Response>((resolve) => {
            releaseB = resolve;
          });
        }
        return Response.json({ ok: true });
      },
    ) as unknown as typeof fetch;

    const recoveryB = beginStewardSessionRecovery(TENANT, "provider");
    const transactionB = runProviderTransaction(recoveryB, tokenB);
    await vi.waitFor(() => expect(serverOrder).toEqual([tokenB]));

    const recoveryC = beginStewardSessionRecovery(TENANT, "provider");
    const transactionC = runProviderTransaction(recoveryC, tokenC);
    await Promise.resolve();
    expect(serverOrder).toEqual([tokenB]);

    releaseB(Response.json({ ok: true }));
    await expect(Promise.all([transactionB, transactionC])).resolves.toEqual([
      false,
      true,
    ]);

    expect(serverOrder).toEqual([tokenB, tokenC]);
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(tokenC);
    expect(readStewardSessionRecovery(TENANT).receipts).toHaveLength(0);
  });

  it("keeps OAuth B as server and local authority when OAuth A settles late", async () => {
    const serverOrder: string[] = [];
    let releaseA: (response: Response) => void = () => {};
    globalThis.fetch = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body)) as { code: string };
        serverOrder.push(body.code);
        if (body.code === "oauth-code-a") {
          return await new Promise<Response>((resolve) => {
            releaseA = resolve;
          });
        }
        return Response.json({ ok: true, token: "oauth-token-b" });
      },
    ) as unknown as typeof fetch;

    const recoveryA = beginStewardSessionRecovery(TENANT, "oauth");
    const transactionA = runOAuthTransaction(recoveryA, "oauth-code-a");
    await vi.waitFor(() => expect(serverOrder).toEqual(["oauth-code-a"]));

    const recoveryB = beginStewardSessionRecovery(TENANT, "oauth");
    const transactionB = runOAuthTransaction(recoveryB, "oauth-code-b");
    await Promise.resolve();
    expect(serverOrder).toEqual(["oauth-code-a"]);

    releaseA(Response.json({ ok: true, token: "oauth-token-a" }));
    await expect(Promise.all([transactionA, transactionB])).resolves.toEqual([
      false,
      true,
    ]);

    expect(serverOrder).toEqual(["oauth-code-a", "oauth-code-b"]);
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe("oauth-token-b");
    expect(readStewardSessionRecovery(TENANT).receipts).toHaveLength(0);
  });

  it("compensates OAuth A when receipt B appears during protected publication", async () => {
    const persistenceStarted = deferred<void>();
    const releasePersistence = deferred<void>();
    const unregisterPersistence = registerStewardTokenPersistence(
      async (token) => {
        persistenceStarted.resolve();
        await releasePersistence.promise;
        storage.setItem(STEWARD_TOKEN_KEY, token);
        return async () => undefined;
      },
    );
    globalThis.fetch = vi.fn(async () =>
      Response.json({ ok: true, token: "oauth-token-a" }),
    ) as unknown as typeof fetch;
    const authorityEvents: Event[] = [];
    const onAuthority = (event: Event) => authorityEvents.push(event);
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    const recoveryA = beginStewardSessionRecovery(TENANT, "oauth");
    let recoveryB: StewardSessionRecoveryReceipt | undefined;

    try {
      const transactionA = runOAuthTransaction(recoveryA, "oauth-code-a");
      await persistenceStarted.promise;
      recoveryB = beginStewardSessionRecovery(TENANT, "oauth");
      releasePersistence.resolve();

      await expect(transactionA).resolves.toBe(false);
      expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(authorityEvents).toEqual([]);
      expect(readStewardSessionRecovery(TENANT).receipts).toEqual(
        [recoveryA.receipt, recoveryB.receipt].sort(),
      );
    } finally {
      unregisterPersistence();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    }
  });
});
