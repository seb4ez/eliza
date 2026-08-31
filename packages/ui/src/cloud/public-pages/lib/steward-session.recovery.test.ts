/**
 * Verifies login-page cookie-session recovery without reading HttpOnly tokens:
 * one rejected refresh may lose a rotation race, while two rejected refreshes
 * clear the stale server session before the user starts a new login.
 */
// @vitest-environment jsdom

import {
  registerStewardTokenPersistence,
  registerStewardTokenRemoval,
  STEWARD_CSRF_HEADER,
  STEWARD_SESSION_CHANGE_EVENT,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  STEWARD_TOKEN_KEY,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enqueueStewardSessionMutation } from "../../lib/steward-session-mutation-queue";
import {
  beginStewardSessionRecovery,
  completeStewardSessionRecovery,
  readStewardSessionRecovery,
  rejectStewardSessionRecovery,
} from "../../lib/steward-session-recovery-marker";
import {
  confirmTelegramAccountClaim,
  recoverStewardEmailSessionViaCookie,
  recoverStewardSessionViaCookie,
  refreshStewardSessionViaCookie,
} from "./steward-session";

const originalFetch = globalThis.fetch;

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

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function tokenForEmail(email: string): string {
  const payload = btoa(JSON.stringify({ email }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return `header.${payload}.signature`;
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

it("marks cookie refresh as an admitted serialized session mutation", async () => {
  let refreshInit: RequestInit | undefined;
  globalThis.fetch = vi.fn(
    async (_input: RequestInfo | URL, init?: RequestInit) => {
      refreshInit = init;
      return jsonResponse({
        ok: true,
        token: tokenForEmail("person@example.com"),
      });
    },
  ) as unknown as typeof fetch;

  await expect(refreshStewardSessionViaCookie()).resolves.toMatchObject({
    ok: true,
  });
  expect(new Headers(refreshInit?.headers).get(STEWARD_CSRF_HEADER)).toBe(
    STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  );
});

describe("recoverStewardEmailSessionViaCookie", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    storage.clear();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("never deletes a stale marker session whose refresh cookie stays expired", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse(
          { error: "Refresh token rejected", code: "invalid_token" },
          401,
        ),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const recovery = recoverStewardEmailSessionViaCookie("person@example.com", {
      intervalMs: 100,
      timeoutMs: 250,
    });
    await vi.advanceTimersByTimeAsync(250);

    await expect(recovery).resolves.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(
      fetchMock.mock.calls.every(([, init]) => init?.method === "POST"),
    ).toBe(true);
  });

  it("accepts the challenged account when its cookie arrives after two rejected refreshes", async () => {
    vi.useFakeTimers();
    const expectedToken = tokenForEmail("person@example.com");
    const fetchMock = vi
      .fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse({ ok: true, token: expectedToken }),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          { error: "Refresh token rejected", code: "invalid_token" },
          401,
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          { error: "Refresh token rejected", code: "missing_token" },
          401,
        ),
      );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const recovery = recoverStewardEmailSessionViaCookie("person@example.com", {
      intervalMs: 100,
      timeoutMs: 500,
    });
    await vi.advanceTimersByTimeAsync(200);

    await expect(recovery).resolves.toEqual({ ok: true, token: expectedToken });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(
      fetchMock.mock.calls.every(([, init]) => init?.method === "POST"),
    ).toBe(true);
  });

  it("cancels an in-flight refresh when the caller aborts", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(
              new DOMException("The operation was aborted.", "AbortError"),
            );
          });
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const controller = new AbortController();
    const recovery = recoverStewardEmailSessionViaCookie("person@example.com", {
      signal: controller.signal,
      intervalMs: 100,
      timeoutMs: 10_000,
    });

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    controller.abort();

    await expect(recovery).resolves.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("abandons a hung refresh at the recovery deadline and clears its timer", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(
              new DOMException("The operation was aborted.", "AbortError"),
            );
          });
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const recovery = recoverStewardEmailSessionViaCookie("person@example.com", {
      intervalMs: 100,
      timeoutMs: 250,
    });
    await vi.advanceTimersByTimeAsync(250);

    await expect(recovery).resolves.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("returns null without fetching for an already-aborted caller signal", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse({ ok: true, token: tokenForEmail("person@example.com") }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const controller = new AbortController();
    controller.abort();

    await expect(
      recoverStewardEmailSessionViaCookie("person@example.com", {
        signal: controller.signal,
      }),
    ).resolves.toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("rejects a session that resolves only after the caller aborted", async () => {
    vi.useFakeTimers();
    let releaseFetch: ((response: Response) => void) | undefined;
    const fetchMock = vi.fn(
      (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Promise<Response>((resolve) => {
          releaseFetch = resolve;
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const controller = new AbortController();
    const recovery = recoverStewardEmailSessionViaCookie("person@example.com", {
      signal: controller.signal,
      intervalMs: 100,
      timeoutMs: 10_000,
    });

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    controller.abort();
    releaseFetch?.(
      jsonResponse({ ok: true, token: tokenForEmail("person@example.com") }),
    );

    await expect(recovery).resolves.toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not accept another account before the challenged session arrives", async () => {
    vi.useFakeTimers();
    const otherToken = tokenForEmail("other@example.com");
    const expectedToken = tokenForEmail("person@example.com");
    const fetchMock = vi
      .fn(async () => jsonResponse({ ok: true, token: expectedToken }))
      .mockResolvedValueOnce(jsonResponse({ ok: true, token: otherToken }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const recovery = recoverStewardEmailSessionViaCookie(
      " PERSON@example.com ",
      { intervalMs: 100, timeoutMs: 500 },
    );
    await vi.advanceTimersByTimeAsync(100);

    await expect(recovery).resolves.toEqual({ ok: true, token: expectedToken });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("never writes or announces recovery A when login B starts during its refresh", async () => {
    const accountA = tokenForEmail("person@example.com");
    const accountB = tokenForEmail("other@example.com");
    const serverRefresh = deferred<Response>();
    const fetchMock = vi.fn(() => serverRefresh.promise);
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const tokenWrites = vi.spyOn(storage, "setItem");
    const syncEvents: Event[] = [];
    const onSync = (event: Event) => syncEvents.push(event);
    window.addEventListener("steward-token-sync", onSync);

    const recoveryA = recoverStewardEmailSessionViaCookie(
      "person@example.com",
      { intervalMs: 10_000, timeoutMs: 20_000 },
    );
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());

    const loginBReceipt = beginStewardSessionRecovery("elizacloud", "provider");
    const loginB = enqueueStewardSessionMutation(async () => {
      await writeStoredStewardToken(accountB);
      completeStewardSessionRecovery(loginBReceipt);
    });

    serverRefresh.resolve(jsonResponse({ ok: true, token: accountA }));
    await loginB;
    try {
      await expect(recoveryA).resolves.toBeNull();
      expect(fetchMock).toHaveBeenCalledOnce();
      expect(tokenWrites).not.toHaveBeenCalledWith(STEWARD_TOKEN_KEY, accountA);
      expect(syncEvents).toEqual([]);
      expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(accountB);
    } finally {
      window.removeEventListener("steward-token-sync", onSync);
    }
  });

  it("compensates recovery A when login B starts during durable token persistence", async () => {
    const accountA = tokenForEmail("person@example.com");
    const persistenceStarted = deferred<void>();
    const releasePersistence = deferred<void>();
    const unregisterPersistence = registerStewardTokenPersistence(
      async (token) => {
        if (token === accountA) {
          persistenceStarted.resolve();
          await releasePersistence.promise;
        }
        storage.setItem(STEWARD_TOKEN_KEY, token);
        return async () => undefined;
      },
    );
    globalThis.fetch = vi.fn(async () =>
      jsonResponse({ ok: true, token: accountA }),
    ) as unknown as typeof fetch;
    const authorityEvents: Event[] = [];
    const syncEvents: Event[] = [];
    const onAuthority = (event: Event) => authorityEvents.push(event);
    const onSync = (event: Event) => syncEvents.push(event);
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    window.addEventListener("steward-token-sync", onSync);

    let loginBReceipt:
      | ReturnType<typeof beginStewardSessionRecovery>
      | undefined;
    try {
      const recoveryA = recoverStewardEmailSessionViaCookie(
        "person@example.com",
        { intervalMs: 10_000, timeoutMs: 20_000 },
      );
      await persistenceStarted.promise;

      loginBReceipt = beginStewardSessionRecovery("elizacloud", "provider");
      releasePersistence.resolve();

      await expect(recoveryA).resolves.toBeNull();
      expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(authorityEvents).toEqual([]);
      expect(syncEvents).toEqual([]);
    } finally {
      if (loginBReceipt) completeStewardSessionRecovery(loginBReceipt);
      unregisterPersistence();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
      window.removeEventListener("steward-token-sync", onSync);
    }
  });

  it("never adopts or retires a pending login B receipt", async () => {
    const accountA = tokenForEmail("person@example.com");
    const loginBReceipt = beginStewardSessionRecovery("elizacloud", "provider");
    const fetchMock = vi.fn(async () =>
      jsonResponse({ ok: true, token: accountA }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      await expect(
        recoverStewardEmailSessionViaCookie("person@example.com", {
          intervalMs: 10_000,
          timeoutMs: 20_000,
        }),
      ).resolves.toBeNull();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([
        loginBReceipt.receipt,
      ]);
      expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    } finally {
      rejectStewardSessionRecovery(loginBReceipt);
    }
  });

  it("commits a clean recovery snapshot before its authority event and preserves reentrant login B", async () => {
    const accountA = tokenForEmail("person@example.com");
    globalThis.fetch = vi.fn(async () =>
      jsonResponse({ ok: true, token: accountA }),
    ) as unknown as typeof fetch;
    let loginBReceipt:
      | ReturnType<typeof beginStewardSessionRecovery>
      | undefined;
    let receiptsAtPublication: readonly string[] | undefined;
    const onAuthority = () => {
      receiptsAtPublication = readStewardSessionRecovery("elizacloud").receipts;
      loginBReceipt = beginStewardSessionRecovery("elizacloud", "provider");
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority, {
      once: true,
    });

    try {
      await expect(
        recoverStewardEmailSessionViaCookie("person@example.com", {
          intervalMs: 10_000,
          timeoutMs: 20_000,
        }),
      ).resolves.toBeNull();
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    }

    expect(receiptsAtPublication).toEqual([]);
    expect(loginBReceipt).toBeDefined();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([
      loginBReceipt?.receipt,
    ]);
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(accountA);
  });

  it("returns null when token-sync queues login B before the outer await resumes", async () => {
    const accountA = tokenForEmail("person@example.com");
    globalThis.fetch = vi.fn(async () =>
      jsonResponse({ ok: true, token: accountA }),
    ) as unknown as typeof fetch;
    let loginBReceipt:
      | ReturnType<typeof beginStewardSessionRecovery>
      | undefined;
    const onSync = () => {
      queueMicrotask(() => {
        loginBReceipt = beginStewardSessionRecovery("elizacloud", "provider");
      });
    };
    window.addEventListener("steward-token-sync", onSync, { once: true });

    try {
      await expect(
        recoverStewardEmailSessionViaCookie("person@example.com", {
          intervalMs: 10_000,
          timeoutMs: 20_000,
        }),
      ).resolves.toBeNull();
    } finally {
      window.removeEventListener("steward-token-sync", onSync);
    }

    expect(loginBReceipt?.preexistingReceipts).toEqual([]);
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([
      loginBReceipt?.receipt,
    ]);
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(accountA);
  });

  it("compensates recovery when snapshot receipt retirement fails", async () => {
    const accountA = tokenForEmail("person@example.com");
    const recovery = beginStewardSessionRecovery("elizacloud", "provider");
    globalThis.fetch = vi.fn(async () =>
      jsonResponse({ ok: true, token: accountA }),
    ) as unknown as typeof fetch;
    const remove = storage.removeItem.bind(storage);
    storage.removeItem = (key) => {
      if (key.endsWith(`:${recovery.receipt}`)) {
        throw new DOMException("Storage denied", "SecurityError");
      }
      remove(key);
    };
    const authorityEvents: Event[] = [];
    const onAuthority = (event: Event) => authorityEvents.push(event);
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);

    try {
      await expect(
        recoverStewardEmailSessionViaCookie("person@example.com", {
          intervalMs: 10,
          timeoutMs: 50,
        }),
      ).resolves.toBeNull();
      expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([
        recovery.receipt,
      ]);
      expect(authorityEvents).toEqual([]);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    }
  });
});

describe("recoverStewardSessionViaCookie", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    storage.clear();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("returns the first healthy refresh without clearing the session", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse({ ok: true, token: "fresh-token" }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await expect(recoverStewardSessionViaCookie()).resolves.toEqual({
      ok: true,
      token: "fresh-token",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ method: "POST" });
  });

  it("retries once when another tab may have won refresh-token rotation", async () => {
    const fetchMock = vi
      .fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse({ ok: true }),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          { error: "Refresh token rejected", code: "invalid_token" },
          401,
        ),
      )
      .mockResolvedValueOnce(jsonResponse({ ok: true, token: "winner-token" }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await expect(recoverStewardSessionViaCookie()).resolves.toEqual({
      ok: true,
      token: "winner-token",
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(
      fetchMock.mock.calls.every(([, init]) => init?.method === "POST"),
    ).toBe(true);
  });

  it("stops before retry or cleanup when the recovery authority is revoked", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse(
          { error: "Refresh token rejected", code: "invalid_token" },
          401,
        ),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const controller = new AbortController();

    const recovery = recoverStewardSessionViaCookie({
      signal: controller.signal,
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    controller.abort();
    await vi.advanceTimersByTimeAsync(100);

    await expect(recovery).resolves.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: "POST",
      signal: controller.signal,
    });
  });

  it("clears a dead cookie session after two rejected refreshes", async () => {
    const rejected = () =>
      jsonResponse(
        { error: "Refresh token rejected", code: "invalid_token" },
        401,
      );
    const fetchMock = vi
      .fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse({ ok: true }),
      )
      .mockResolvedValueOnce(rejected())
      .mockResolvedValueOnce(rejected())
      .mockResolvedValueOnce(jsonResponse({ ok: true }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await expect(recoverStewardSessionViaCookie()).resolves.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[2]?.[1]).toMatchObject({
      method: "DELETE",
      credentials: "include",
      headers: expect.objectContaining({
        [STEWARD_CSRF_HEADER]: STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
      }),
    });
  });

  it("preserves the browser token while an ambiguity receipt is reconciled", async () => {
    const rejected = () =>
      jsonResponse(
        { error: "Refresh token rejected", code: "missing_token" },
        401,
      );
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => rejected(),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    window.localStorage.setItem(STEWARD_TOKEN_KEY, "previous-account-token");

    await expect(
      recoverStewardSessionViaCookie({ rejectedSession: "preserve" }),
    ).resolves.toBeNull();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(
      fetchMock.mock.calls.every(([, init]) => init?.method === "POST"),
    ).toBe(true);
    expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
      "previous-account-token",
    );
  });

  it("finishes durable token removal when lifecycle aborts after DELETE dispatch", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const rejected = () =>
      jsonResponse(
        { error: "Refresh token rejected", code: "invalid_token" },
        401,
      );
    const fetchMock = vi
      .fn(async (_input: RequestInfo | URL, _init?: RequestInit) => rejected())
      .mockResolvedValueOnce(rejected())
      .mockResolvedValueOnce(rejected())
      .mockImplementationOnce(
        (_input: RequestInfo | URL, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener(
              "abort",
              () =>
                reject(
                  new DOMException("The operation was aborted.", "AbortError"),
                ),
              { once: true },
            );
          }),
      );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    window.localStorage.setItem(STEWARD_TOKEN_KEY, "retired-session-token");

    let finishRemoval: (() => void) | undefined;
    const removalStarted = vi.fn();
    const unregisterRemoval = registerStewardTokenRemoval(
      () =>
        new Promise<void>((resolve) => {
          removalStarted();
          finishRemoval = () => {
            window.localStorage.removeItem(STEWARD_TOKEN_KEY);
            resolve();
          };
        }),
    );
    const controller = new AbortController();

    try {
      const recovery = recoverStewardSessionViaCookie({
        signal: controller.signal,
      });
      await vi.advanceTimersByTimeAsync(100);
      await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
      expect(fetchMock.mock.calls[2]?.[1]).toMatchObject({
        method: "DELETE",
        signal: controller.signal,
      });

      controller.abort();
      await vi.waitFor(() => expect(removalStarted).toHaveBeenCalledOnce());
      let recoverySettled = false;
      void recovery.then(() => {
        recoverySettled = true;
      });
      await Promise.resolve();
      expect(recoverySettled).toBe(false);
      expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
        "retired-session-token",
      );

      finishRemoval?.();
      await expect(recovery).resolves.toBeNull();
      expect(recoverySettled).toBe(true);
      expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    } finally {
      unregisterRemoval();
    }
  });

  it("preserves non-auth refresh failures for the login boundary", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse(
          { error: "Steward upstream unavailable", code: "internal_error" },
          502,
        ),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await expect(recoverStewardSessionViaCookie()).rejects.toThrow(
      "Steward upstream unavailable",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("refreshStewardSessionViaCookie", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.unstubAllGlobals();
  });

  it("still exposes a rejected token as a typed failure to non-recovery callers", async () => {
    globalThis.fetch = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse(
          { error: "Refresh token rejected", code: "invalid_token" },
          401,
        ),
    ) as unknown as typeof fetch;

    await expect(refreshStewardSessionViaCookie()).rejects.toMatchObject({
      status: 401,
      code: "invalid_token",
    });
  });
});

describe("confirmTelegramAccountClaim recovery", () => {
  const continuation = "telegram-claim-test-token-00000001";

  afterEach(() => {
    globalThis.fetch = originalFetch;
    storage.clear();
    vi.unstubAllGlobals();
  });

  it("retires its receipt on an explicit HTTP 500 response", async () => {
    storage.setItem(STEWARD_TOKEN_KEY, "steward-token");
    globalThis.fetch = vi.fn(async () =>
      jsonResponse(
        { error: "Telegram confirmation unavailable", code: "internal_error" },
        500,
      ),
    ) as unknown as typeof fetch;

    await expect(
      confirmTelegramAccountClaim("steward-token", continuation),
    ).rejects.toMatchObject({ status: 500, code: "internal_error" });
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
  });

  it("preserves its receipt when transport loses the response after dispatch", async () => {
    storage.setItem(STEWARD_TOKEN_KEY, "steward-token");
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError("response lost after commit");
    }) as unknown as typeof fetch;

    await expect(
      confirmTelegramAccountClaim("steward-token", continuation),
    ).rejects.toThrow("response lost after commit");
    expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(1);
  });
});
