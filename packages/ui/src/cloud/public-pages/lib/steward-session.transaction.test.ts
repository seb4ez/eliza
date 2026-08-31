// @vitest-environment jsdom

import {
  registerStewardTokenPersistence,
  STEWARD_SESSION_CHANGE_EVENT,
  STEWARD_TOKEN_KEY,
  StewardSessionError,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enqueueStewardSessionMutation } from "../../lib/steward-session-mutation-queue";
import {
  beginStewardSessionRecovery,
  completeStewardSessionRecoverySnapshot,
  createStewardSessionRecoveryPublicationFence,
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

function publicationFence(recovery: StewardSessionRecoveryReceipt): {
  validate(): boolean;
  finalizeBeforePublish(): (durableRestored: boolean) => void;
  isFinalized(): boolean;
  publishChange(): boolean;
} {
  return createStewardSessionRecoveryPublicationFence(recovery);
}

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
    const fence = publicationFence(recovery);
    if (!fence.validate()) return false;
    await syncStewardSessionCookie(token, null, {
      mutationLease,
      validate: fence.validate,
      finalizeBeforePublish: fence.finalizeBeforePublish,
    });
    const published =
      fence.isFinalized() &&
      fence.publishChange() &&
      fence.validate() &&
      storage.getItem(STEWARD_TOKEN_KEY) === token;
    if (!published) return false;
    window.dispatchEvent(
      new CustomEvent("steward-token-sync", { detail: { token } }),
    );
    return fence.validate() && storage.getItem(STEWARD_TOKEN_KEY) === token;
  });
}

async function runOAuthTransaction(
  recovery: StewardSessionRecoveryReceipt,
  code: string,
): Promise<boolean> {
  return enqueueStewardSessionMutation(async (mutationLease) => {
    const fence = publicationFence(recovery);
    if (!fence.validate()) return false;
    const result = await exchangeStewardCodeViaApi(code, { mutationLease });
    if (!result.token || !fence.validate()) {
      return false;
    }
    const writeAuthority = await writeStoredStewardToken(result.token, {
      validate: fence.validate,
      finalizeBeforePublish: fence.finalizeBeforePublish,
    });
    return (
      Boolean(writeAuthority) &&
      fence.isFinalized() &&
      fence.publishChange() &&
      fence.validate() &&
      storage.getItem(STEWARD_TOKEN_KEY) === result.token
    );
  });
}

describe("logout cooldown session establishment", () => {
  it("preserves the structured cooldown and never publishes a provider token", async () => {
    globalThis.fetch = vi.fn(async () =>
      Response.json(
        {
          error:
            "You signed out moments ago. Wait 4 seconds, then sign in again to create a new session.",
          code: "logout_cooldown",
          retryAfterSeconds: 4,
          retryAtEpochSeconds: 2_000_000_004,
        },
        { status: 409, headers: { "Retry-After": "4" } },
      ),
    ) as unknown as typeof fetch;

    let failure: unknown;
    try {
      await syncStewardSessionCookie("ambiguous-provider-token");
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(StewardSessionError);
    expect(failure).toMatchObject({
      code: "logout_cooldown",
      status: 409,
      retryAfterSeconds: 4,
      retryAtEpochSeconds: 2_000_000_004,
    });
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("never returns an OAuth token when nonce establishment is in cooldown", async () => {
    globalThis.fetch = vi.fn(async () =>
      Response.json(
        {
          error:
            "You signed out moments ago. Wait 3 seconds, then sign in again to create a new session.",
          code: "logout_cooldown",
          retryAfterSeconds: 3,
        },
        { status: 409, headers: { "Retry-After": "3" } },
      ),
    ) as unknown as typeof fetch;

    await expect(
      exchangeStewardCodeViaApi("consumed-oauth-code"),
    ).rejects.toMatchObject({
      code: "logout_cooldown",
      status: 409,
      retryAfterSeconds: 3,
    });
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });
});

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

  it("retires A before its authority event and preserves reentrant login B", async () => {
    globalThis.fetch = vi.fn(async () =>
      Response.json({ ok: true }),
    ) as unknown as typeof fetch;
    const recoveryA = beginStewardSessionRecovery(TENANT, "provider");
    let recoveryB: StewardSessionRecoveryReceipt | undefined;
    let receiptsAtPublication: readonly string[] | undefined;
    const onAuthority = () => {
      receiptsAtPublication = readStewardSessionRecovery(TENANT).receipts;
      recoveryB = beginStewardSessionRecovery(TENANT, "provider");
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority, {
      once: true,
    });

    try {
      await expect(
        runProviderTransaction(recoveryA, "provider-token-a"),
      ).resolves.toBe(false);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    }

    expect(receiptsAtPublication).toEqual([]);
    expect(recoveryB).toBeDefined();
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([
      recoveryB?.receipt,
    ]);
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe("provider-token-a");
  });

  it("suppresses token-sync when recovery publication reentrantly starts B", async () => {
    globalThis.fetch = vi.fn(async () =>
      Response.json({ ok: true }),
    ) as unknown as typeof fetch;
    const recoveryA = beginStewardSessionRecovery(TENANT, "provider");
    let recoveryB: StewardSessionRecoveryReceipt | undefined;
    const eventOrder: string[] = [];
    const onAuthority = () => eventOrder.push("authority");
    const onRecovery = () => {
      eventOrder.push("recovery");
      recoveryB = beginStewardSessionRecovery(TENANT, "provider");
    };
    const onTokenSync = () => eventOrder.push("token-sync");
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    window.addEventListener(
      "eliza-steward-session-recovery-change",
      onRecovery,
      { once: true },
    );
    window.addEventListener("steward-token-sync", onTokenSync);

    try {
      await expect(
        runProviderTransaction(recoveryA, "provider-token-a"),
      ).resolves.toBe(false);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
      window.removeEventListener(
        "eliza-steward-session-recovery-change",
        onRecovery,
      );
      window.removeEventListener("steward-token-sync", onTokenSync);
    }

    expect(eventOrder).toEqual(["authority", "recovery"]);
    expect(recoveryB?.preexistingReceipts).toEqual([]);
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([
      recoveryB?.receipt,
    ]);
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe("provider-token-a");
  });

  it("finishes fenced cleanup when the authority event aborts its signal", async () => {
    globalThis.fetch = vi.fn(async () =>
      Response.json({ ok: true }),
    ) as unknown as typeof fetch;
    const recovery = beginStewardSessionRecovery(TENANT, "provider");
    const fence = publicationFence(recovery);
    const controller = new AbortController();
    const eventOrder: string[] = [];
    const onAuthority = () => {
      eventOrder.push("authority");
      controller.abort();
    };
    const onRecovery = () => eventOrder.push("recovery");
    const onTokenSync = () => eventOrder.push("token-sync");
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority, {
      once: true,
    });
    window.addEventListener(
      "eliza-steward-session-recovery-change",
      onRecovery,
      { once: true },
    );
    window.addEventListener("steward-token-sync", onTokenSync, { once: true });

    try {
      await expect(
        enqueueStewardSessionMutation(async (mutationLease) => {
          await syncStewardSessionCookie("provider-token-a", null, {
            signal: controller.signal,
            mutationLease,
            validate: () => !controller.signal.aborted && fence.validate(),
            finalizeBeforePublish: fence.finalizeBeforePublish,
          });
          expect(fence.isFinalized()).toBe(true);
          expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe("provider-token-a");
          expect(fence.publishChange()).toBe(true);
          window.dispatchEvent(new CustomEvent("steward-token-sync"));
        }),
      ).resolves.toBeUndefined();
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
      window.removeEventListener(
        "eliza-steward-session-recovery-change",
        onRecovery,
      );
      window.removeEventListener("steward-token-sync", onTokenSync);
    }

    expect(controller.signal.aborted).toBe(true);
    expect(eventOrder).toEqual(["authority", "recovery", "token-sync"]);
    expect(readStewardSessionRecovery(TENANT).receipts).toEqual([]);
  });

  it("suppresses unfenced A token-sync when its authority event starts B", async () => {
    globalThis.fetch = vi.fn(async () =>
      Response.json({ ok: true }),
    ) as unknown as typeof fetch;
    const recoveryA = beginStewardSessionRecovery(TENANT, "provider");
    let recoveryB: StewardSessionRecoveryReceipt | undefined;
    const tokenSync = vi.fn();
    const onAuthority = () => {
      recoveryB = beginStewardSessionRecovery(TENANT, "provider");
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority, {
      once: true,
    });
    window.addEventListener("steward-token-sync", tokenSync);

    try {
      await expect(
        enqueueStewardSessionMutation((mutationLease) =>
          syncStewardSessionCookie("provider-token-a", null, {
            mutationLease,
            validate: () =>
              readStewardSessionRecovery(TENANT).generation ===
              recoveryA.receipt,
          }),
        ),
      ).resolves.toBeUndefined();
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
      window.removeEventListener("steward-token-sync", tokenSync);
    }

    expect(recoveryB).toBeDefined();
    expect(tokenSync).not.toHaveBeenCalled();
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe("provider-token-a");
  });
});
