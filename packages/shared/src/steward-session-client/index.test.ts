/** Tests the shared Steward browser-session contract with deterministic DOM state. */
// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clearStoredStewardToken,
  configureStoredStewardTokenScope,
  exchangeStewardCode,
  hasStewardAuthedCookie,
  readStoredStewardToken,
  registerStewardTokenCompareAndRestore,
  registerStewardTokenPersistence,
  registerStewardTokenRemoval,
  replaceStoredStewardTokenIfCurrent,
  STEWARD_CSRF_HEADER,
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_REFRESH_TOKEN_KEY,
  STEWARD_SESSION_CHANGE_EVENT,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  STEWARD_TOKEN_KEY,
  STEWARD_TOKEN_SCOPE_KEY,
  type StewardSessionChangeDetail,
  StewardSessionError,
  sanitizeTelegramAccountClaimContinuation,
  stewardAuthedCookieName,
  syncStewardSession,
  writeStoredStewardToken,
} from "./index";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function installLocalStorageOverride(
  overrides: Partial<
    Pick<Storage, "clear" | "getItem" | "key" | "removeItem" | "setItem">
  >,
): () => void {
  const original = window.localStorage;
  const replacement = {
    clear: overrides.clear ?? original.clear.bind(original),
    getItem: overrides.getItem ?? original.getItem.bind(original),
    key: overrides.key ?? original.key.bind(original),
    get length() {
      return original.length;
    },
    removeItem: overrides.removeItem ?? original.removeItem.bind(original),
    setItem: overrides.setItem ?? original.setItem.bind(original),
  } satisfies Storage;
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: replacement,
  });
  return () => {
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: original,
    });
  };
}

describe("Steward session client CSRF marker header", () => {
  it("syncStewardSession sends the marker header with its JSON POST", async () => {
    let seen: RequestInit | undefined;
    const fetchImpl = (async (_input: unknown, init?: RequestInit) => {
      seen = init;
      return jsonResponse({ ok: true, userId: "u", stewardUserId: "s" });
    }) as typeof fetch;

    await syncStewardSession("token", null, { fetchImpl });

    const headers = new Headers(seen?.headers);
    expect(headers.get(STEWARD_CSRF_HEADER)).toBe(STEWARD_CSRF_HEADER_VALUE);
    expect(headers.get("content-type")).toBe("application/json");
  });

  it("exchangeStewardCode sends the marker header with its JSON POST", async () => {
    let seen: RequestInit | undefined;
    const fetchImpl = (async (_input: unknown, init?: RequestInit) => {
      seen = init;
      return jsonResponse({ ok: true, userId: "u", stewardUserId: "s" });
    }) as typeof fetch;

    await exchangeStewardCode("one-time-code", {
      fetchImpl,
      codeVerifier: "verifier",
    });

    const headers = new Headers(seen?.headers);
    expect(headers.get(STEWARD_CSRF_HEADER)).toBe(STEWARD_CSRF_HEADER_VALUE);
  });

  it("emits the mutation protocol only when a serialized caller opts in", async () => {
    let seen: RequestInit | undefined;
    const fetchImpl = (async (_input: unknown, init?: RequestInit) => {
      seen = init;
      return jsonResponse({ ok: true, userId: "u", stewardUserId: "s" });
    }) as typeof fetch;

    await syncStewardSession("token", null, {
      fetchImpl,
      sessionMutationProtocol: STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
    });

    expect(new Headers(seen?.headers).get(STEWARD_CSRF_HEADER)).toBe(
      STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
    );
  });

  it("preserves structured logout cooldown timing without treating it as session_ended", async () => {
    const fetchImpl = (async () =>
      jsonResponse(
        {
          error:
            "You signed out moments ago. Wait 4 seconds, then sign in again to create a new session.",
          code: "logout_cooldown",
          retryAfterSeconds: 4,
          retryAtEpochSeconds: 2_000_000_004,
        },
        409,
      )) as unknown as typeof fetch;

    let failure: unknown;
    try {
      await syncStewardSession("ambiguous-token", null, { fetchImpl });
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
  });
});

describe("Telegram account-claim credential", () => {
  it("accepts opaque tokens and rejects guessable platform ids", () => {
    expect(
      sanitizeTelegramAccountClaimContinuation(
        "  opaque-telegram-claim-token  ",
      ),
    ).toBe("opaque-telegram-claim-token");
    expect(
      sanitizeTelegramAccountClaimContinuation("platform:telegram:123456789"),
    ).toBeNull();
    expect(sanitizeTelegramAccountClaimContinuation("short")).toBeNull();
    expect(sanitizeTelegramAccountClaimContinuation(null)).toBeNull();
  });
});

function stubDocumentCookie(cookie: string): void {
  vi.stubGlobal("document", { cookie });
}

describe("steward session marker cookie", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses rollout-isolated v2 markers in production and unset environments", () => {
    expect(stewardAuthedCookieName()).toBe("__Host-steward-authed-v2");
    expect(stewardAuthedCookieName("production")).toBe(
      "__Host-steward-authed-v2",
    );
  });

  it("suffixes non-production marker cookies by environment", () => {
    expect(stewardAuthedCookieName("staging")).toBe(
      "__Host-steward-authed-v2-staging",
    );
    expect(stewardAuthedCookieName("dev")).toBe("__Host-steward-authed-v2-dev");
    expect(stewardAuthedCookieName("local")).toBe("steward-authed-v2-local");
  });

  it("never treats a v1 marker alone as automatic-refresh authority", () => {
    stubDocumentCookie("steward-authed=1");
    expect(hasStewardAuthedCookie("production")).toBe(false);

    stubDocumentCookie("steward-authed-staging=1; steward-authed=1");
    expect(hasStewardAuthedCookie("staging")).toBe(false);
  });

  it("keeps v2 authentication alive after a late v1 logout", () => {
    stubDocumentCookie("__Host-steward-authed-v2=1");
    expect(hasStewardAuthedCookie("production")).toBe(true);
  });

  it("does not let a late v1 login cross the v2 logout tombstone", () => {
    stubDocumentCookie("__Host-steward-authed-v2=0; steward-authed=1");
    expect(hasStewardAuthedCookie("production")).toBe(false);
  });

  it("fails closed instead of falling back on a malformed v2 marker", () => {
    stubDocumentCookie("__Host-steward-authed-v2=maybe; steward-authed=1");
    expect(hasStewardAuthedCookie("production")).toBe(false);
  });

  it("ignores an unprefixed domain-cookie lookalike", () => {
    stubDocumentCookie("steward-authed-v2=1; __Host-steward-authed-v2=0");
    expect(hasStewardAuthedCookie("production")).toBe(false);
  });

  it("fails closed on duplicate exact host-bound markers", () => {
    stubDocumentCookie(
      "__Host-steward-authed-v2=0; __Host-steward-authed-v2=1",
    );
    expect(hasStewardAuthedCookie("production")).toBe(false);
  });

  it("infers staging markers only for the exact develop Pages hostname", () => {
    vi.stubGlobal("window", {
      location: { hostname: "develop.eliza-app.pages.dev" },
    });
    stubDocumentCookie("__Host-steward-authed-v2-staging=1");
    expect(hasStewardAuthedCookie()).toBe(true);

    stubDocumentCookie("steward-authed-staging=1");
    expect(hasStewardAuthedCookie()).toBe(false);

    vi.stubGlobal("window", {
      location: { hostname: "preview.develop.eliza-app.pages.dev" },
    });
    expect(hasStewardAuthedCookie()).toBe(false);
  });

  it("infers the explicit non-prefixed local marker on loopback", () => {
    vi.stubGlobal("window", {
      location: { hostname: "127.0.0.1" },
    });
    stubDocumentCookie("steward-authed-v2-local=1");
    expect(hasStewardAuthedCookie()).toBe(true);

    stubDocumentCookie("__Host-steward-authed-v2=1");
    expect(hasStewardAuthedCookie()).toBe(false);
  });
});

describe("Steward session storage transitions", () => {
  afterEach(() => {
    localStorage.clear();
    const globalSlot = globalThis as Record<PropertyKey, unknown>;
    delete globalSlot[Symbol.for("elizaos.app.boot-config")];
    delete globalSlot.__ELIZAOS_APP_BOOT_CONFIG__;
  });

  function setLocalCloudTarget(cloudApiBase: string): void {
    configureStoredStewardTokenScope(cloudApiBase);
  }

  it("quarantines a loopback token after switching Cloud environments", async () => {
    setLocalCloudTarget("https://api.eliza.app/api/v1");
    await writeStoredStewardToken("production-token");

    expect(readStoredStewardToken()).toBe("production-token");
    expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:production",
    );

    setLocalCloudTarget("https://api-staging.eliza.app/api/v1");

    expect(readStoredStewardToken()).toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("production-token");
  });

  it("binds a new loopback login to the newly configured environment", async () => {
    setLocalCloudTarget("https://api.eliza.app");
    await writeStoredStewardToken("production-token");
    setLocalCloudTarget("https://cloud-staging.eliza.app");

    await writeStoredStewardToken("staging-token");

    expect(readStoredStewardToken()).toBe("staging-token");
    expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:staging",
    );
  });

  it("fails closed for a legacy unscoped token on a configured loopback app", () => {
    setLocalCloudTarget("https://api-staging.eliza.app");
    localStorage.setItem(STEWARD_TOKEN_KEY, "legacy-production-token");

    expect(readStoredStewardToken()).toBeNull();
  });

  it("keeps custom loopback targets isolated by exact origin", async () => {
    setLocalCloudTarget("http://127.0.0.1:8787/api/v1");
    await writeStoredStewardToken("self-hosted-token");
    expect(readStoredStewardToken()).toBe("self-hosted-token");

    setLocalCloudTarget("http://127.0.0.1:8788/api/v1");
    expect(readStoredStewardToken()).toBeNull();
  });

  it("does not publish a new scope before protected persistence succeeds", async () => {
    setLocalCloudTarget("https://api.eliza.app");
    await writeStoredStewardToken("production-token");
    setLocalCloudTarget("https://api-staging.eliza.app");
    let rejectPersistence: (error: Error) => void = () => {};
    const pendingPersistence = new Promise<void>((_resolve, reject) => {
      rejectPersistence = reject;
    });
    const unregister = registerStewardTokenPersistence(async (token) => {
      await pendingPersistence;
      window.localStorage.setItem(STEWARD_TOKEN_KEY, token);
    });

    try {
      const write = writeStoredStewardToken("staging-token");
      await Promise.resolve();
      expect(readStoredStewardToken()).toBeNull();
      expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
        "eliza-cloud:production",
      );

      rejectPersistence(new Error("protected write rejected"));
      await expect(write).rejects.toMatchObject({
        name: "StewardTokenPersistenceError",
      });

      expect(readStoredStewardToken()).toBeNull();
      expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
        "eliza-cloud:production",
      );
    } finally {
      unregister();
    }
  });

  it("restores the exact previous token and scope when scope publication fails after durable persistence", async () => {
    setLocalCloudTarget("https://api.eliza.app");
    await writeStoredStewardToken("production-token");
    setLocalCloudTarget("https://api-staging.eliza.app");
    const commit = vi.fn(async () => undefined);
    const unregister = registerStewardTokenPersistence(async (token) => {
      window.localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return commit;
    });
    const originalStorage = window.localStorage;
    let rejectedNewScope = false;
    const failingStorage = {
      clear: originalStorage.clear.bind(originalStorage),
      getItem: originalStorage.getItem.bind(originalStorage),
      key: originalStorage.key.bind(originalStorage),
      get length() {
        return originalStorage.length;
      },
      removeItem: originalStorage.removeItem.bind(originalStorage),
      setItem(key: string, value: string) {
        if (
          key === STEWARD_TOKEN_SCOPE_KEY &&
          value === "eliza-cloud:staging" &&
          !rejectedNewScope
        ) {
          rejectedNewScope = true;
          originalStorage.setItem(key, value);
          throw new Error("scope storage unavailable");
        }
        originalStorage.setItem(key, value);
      },
    } satisfies Storage;
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: failingStorage,
    });
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      await expect(
        writeStoredStewardToken("staging-token"),
      ).rejects.toMatchObject({ name: "StewardTokenPersistenceError" });
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
      Object.defineProperty(window, "localStorage", {
        configurable: true,
        value: originalStorage,
      });
      unregister();
    }

    expect(commit).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("production-token");
    expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:production",
    );
    expect(readStoredStewardToken()).toBeNull();
    expect(transitions).toEqual([]);
  });

  it("preserves a newer renderer token and scope when the failed writer loses its rollback CAS", async () => {
    setLocalCloudTarget("https://api.eliza.app");
    await writeStoredStewardToken("production-token");
    setLocalCloudTarget("https://api-staging.eliza.app");
    const unregisterPersistence = registerStewardTokenPersistence(
      async (token) => {
        window.localStorage.setItem(STEWARD_TOKEN_KEY, token);
      },
    );
    const unregisterCompare = registerStewardTokenCompareAndRestore(
      async () => {
        // Renderer B wins while A is unwinding its failed scope publication.
        window.localStorage.setItem(STEWARD_TOKEN_KEY, "newer-token-b");
        window.localStorage.setItem(
          STEWARD_TOKEN_SCOPE_KEY,
          "eliza-cloud:staging",
        );
        return false;
      },
    );
    const originalStorage = window.localStorage;
    let rejectedAttemptScope = false;
    const failingStorage = {
      clear: originalStorage.clear.bind(originalStorage),
      getItem: originalStorage.getItem.bind(originalStorage),
      key: originalStorage.key.bind(originalStorage),
      get length() {
        return originalStorage.length;
      },
      removeItem: originalStorage.removeItem.bind(originalStorage),
      setItem(key: string, value: string) {
        if (
          key === STEWARD_TOKEN_SCOPE_KEY &&
          value === "eliza-cloud:staging" &&
          !rejectedAttemptScope
        ) {
          rejectedAttemptScope = true;
          originalStorage.setItem(key, value);
          throw new Error("scope storage unavailable");
        }
        originalStorage.setItem(key, value);
      },
    } satisfies Storage;
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: failingStorage,
    });

    try {
      await expect(
        writeStoredStewardToken("attempt-token-a"),
      ).rejects.toMatchObject({ name: "StewardTokenPersistenceError" });
    } finally {
      Object.defineProperty(window, "localStorage", {
        configurable: true,
        value: originalStorage,
      });
      unregisterCompare();
      unregisterPersistence();
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("newer-token-b");
    expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:staging",
    );
  });

  it("publishes ordered typed transitions after canonical writes and clears", async () => {
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      await writeStoredStewardToken("steward-token");
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("steward-token");
      await clearStoredStewardToken();
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(transitions).toHaveLength(2);
    expect(transitions[0]?.state).toBe("present");
    expect(transitions[1]?.state).toBe("cleared");
    expect(transitions[1]?.sessionEpoch).toBeGreaterThan(
      transitions[0]?.sessionEpoch ?? 0,
    );
  });

  it("does not clear or publish when exact removal authority is superseded", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "token-a");
    localStorage.setItem(STEWARD_TOKEN_SCOPE_KEY, "scope-a");
    localStorage.setItem(STEWARD_REFRESH_TOKEN_KEY, "legacy-refresh-a");
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    const removal = vi.fn(async () => {
      localStorage.setItem(STEWARD_TOKEN_KEY, "token-b");
      localStorage.setItem(STEWARD_TOKEN_SCOPE_KEY, "scope-b");
      return false;
    });
    const unregister = registerStewardTokenRemoval(removal);

    try {
      await expect(
        clearStoredStewardToken({
          expectedToken: "token-a",
          validate: () => true,
        }),
      ).resolves.toBe(false);
    } finally {
      unregister();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(removal).toHaveBeenCalledWith({
      expectedToken: "token-a",
      validate: expect.any(Function),
    });
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-b");
    expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe("scope-b");
    expect(localStorage.getItem(STEWARD_REFRESH_TOKEN_KEY)).toBe(
      "legacy-refresh-a",
    );
    expect(transitions).toEqual([]);
  });

  it("keeps terminal teardown acquired without publishing when authority changes after CAS", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "terminal-token-a");
    localStorage.setItem(STEWARD_TOKEN_SCOPE_KEY, "scope-a");
    let authoritative = true;
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    const unregister = registerStewardTokenRemoval(async () => {
      localStorage.removeItem(STEWARD_TOKEN_KEY);
      authoritative = false;
      return true;
    });

    try {
      await expect(
        clearStoredStewardToken({
          expectedToken: "terminal-token-a",
          validate: () => authoritative,
        }),
      ).resolves.toBe(true);
    } finally {
      unregister();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBeNull();
    expect(transitions).toEqual([]);
  });

  it("treats an exact absent token as distinct from unconditional removal", async () => {
    const removal = vi.fn().mockResolvedValue(true);
    const unregister = registerStewardTokenRemoval(removal);

    try {
      await expect(
        clearStoredStewardToken({
          expectedToken: null,
          validate: () => true,
        }),
      ).resolves.toBe(true);
    } finally {
      unregister();
    }

    expect(removal).toHaveBeenCalledWith({
      expectedToken: null,
      validate: expect.any(Function),
    });
  });

  it("restores an already-published predecessor through its exact write handle", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    let receiptLive = true;
    const restorePredecessor = vi.fn(async () => {
      if (!receiptLive) return false;
      receiptLive = false;
      localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
      return true;
    });
    const unregister = registerStewardTokenPersistence(async (token) => {
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return {
        commit: async () => undefined,
        restorePredecessor,
      };
    });

    try {
      const authority = await writeStoredStewardToken("token-a");
      expect(authority).not.toBeNull();
      await expect(authority?.restorePredecessor()).resolves.toBe(true);
      await expect(authority?.restorePredecessor()).resolves.toBe(true);
    } finally {
      unregister();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-old");
    expect(restorePredecessor).toHaveBeenCalledOnce();
    expect(transitions.map(({ state }) => state)).toEqual([
      "present",
      "present",
    ]);
  });

  it("provides an exact browser fallback authority for a published write", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "browser-token-old");

    const authority = await writeStoredStewardToken("browser-token-a");

    expect(authority).not.toBeNull();
    await expect(authority?.restorePredecessor()).resolves.toBe(true);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("browser-token-old");
  });

  it("fences same-value ABA from an older browser fallback authority", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "browser-token-old");
    const oldAuthority = await writeStoredStewardToken("same-browser-token-a");

    await writeStoredStewardToken("browser-token-b");
    await writeStoredStewardToken("same-browser-token-a");

    await expect(oldAuthority?.restorePredecessor()).resolves.toBe(false);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
      "same-browser-token-a",
    );
  });

  it("finalizes subordinate state and commits recovery before publishing", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
    let liveClientToken = "token-old";
    const order: string[] = [];
    const listener = () => {
      order.push(
        `event:${localStorage.getItem(STEWARD_TOKEN_KEY)}:${liveClientToken}`,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const authority = await writeStoredStewardToken("token-b", {
        finalizeBeforePublish: () => {
          order.push(`finalize:${localStorage.getItem(STEWARD_TOKEN_KEY)}`);
          liveClientToken = "token-b";
          return () => {
            liveClientToken = "token-old";
          };
        },
        commitBeforePublish: () => {
          order.push(`commit:${liveClientToken}`);
          return true;
        },
      });

      expect(authority).not.toBeNull();
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(order).toEqual([
      "finalize:token-b",
      "commit:token-b",
      "event:token-b:token-b",
    ]);
  });

  it("restores durable state before rolling back an unpublished finalizer", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
    let liveClientToken = "token-old";
    const rollbackObservations: Array<string | null> = [];
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const authority = await writeStoredStewardToken("token-b", {
        finalizeBeforePublish: () => {
          liveClientToken = "token-b";
          return () => {
            rollbackObservations.push(localStorage.getItem(STEWARD_TOKEN_KEY));
            liveClientToken = "token-old";
          };
        },
        commitBeforePublish: () => false,
      });

      expect(authority).toBeNull();
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-old");
    expect(liveClientToken).toBe("token-old");
    expect(rollbackObservations).toEqual(["token-old"]);
    expect(transitions).toEqual([]);
  });

  it("rearms durable recovery markers before awaiting host predecessor restore", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
    const order: string[] = [];
    const unregister = registerStewardTokenPersistence(async (token) => {
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return {
        commit: async () => undefined,
        restorePredecessor: async () => {
          order.push("durable-restore");
          localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
          return true;
        },
      };
    });

    try {
      const authority = await writeStoredStewardToken("token-b", {
        finalizeBeforePublish: () => {
          const rollback = ((_durableRestored: boolean) => {
            order.push("live-rollback");
          }) as ((durableRestored: boolean) => void) & {
            beforeDurableRestore?: () => void;
          };
          rollback.beforeDurableRestore = () => {
            order.push("marker-restore");
          };
          return rollback;
        },
        commitBeforePublish: () => false,
      });
      expect(authority).toBeNull();
    } finally {
      unregister();
    }

    expect(order).toEqual([
      "marker-restore",
      "durable-restore",
      "live-rollback",
    ]);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-old");
  });

  it("clears staged live authority when durable compensation loses", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
    let liveClientToken: string | null = "token-old";
    const rollbackStates: boolean[] = [];
    const unregister = registerStewardTokenPersistence(async (token) => {
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return {
        commit: async () => undefined,
        restorePredecessor: async () => false,
      };
    });

    try {
      await expect(
        writeStoredStewardToken("token-a", {
          finalizeBeforePublish: () => {
            liveClientToken = "token-a";
            return (durableRestored) => {
              rollbackStates.push(durableRestored);
              liveClientToken = durableRestored ? "token-old" : null;
            };
          },
          commitBeforePublish: () => false,
        }),
      ).rejects.toMatchObject({ name: "StewardTokenPersistenceError" });
    } finally {
      unregister();
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-a");
    expect(liveClientToken).toBeNull();
    expect(rollbackStates).toEqual([false]);
  });

  it("defers a restored predecessor event until its live pair is coherent", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
    let liveClientToken = "token-old";
    const observations: string[] = [];
    const listener = () => {
      observations.push(
        `${localStorage.getItem(STEWARD_TOKEN_KEY)}:${liveClientToken}`,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const authority = await writeStoredStewardToken("token-a", {
        finalizeBeforePublish: () => {
          liveClientToken = "token-a";
          return () => {
            liveClientToken = "token-old";
          };
        },
      });
      expect(observations).toEqual(["token-a:token-a"]);

      await expect(
        authority?.restorePredecessor({ deferPublication: true }),
      ).resolves.toBe(true);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-old");
      expect(liveClientToken).toBe("token-old");
      expect(observations).toEqual(["token-a:token-a"]);

      expect(authority?.publish?.()).toBe(true);
      expect(observations).toEqual(["token-a:token-a", "token-old:token-old"]);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("finishes durable predecessor cleanup when live rollback throws", async () => {
    setLocalCloudTarget("https://api.eliza.app");
    await writeStoredStewardToken("production-token-old");
    setLocalCloudTarget("https://api-staging.eliza.app");
    const rollbackStates: boolean[] = [];
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const authority = await writeStoredStewardToken("staging-token-a", {
        finalizeBeforePublish: () => (durableRestored) => {
          rollbackStates.push(durableRestored);
          throw new Error("live client rollback failed");
        },
      });
      transitions.length = 0;

      await expect(authority?.restorePredecessor()).rejects.toMatchObject({
        name: "StewardTokenPersistenceError",
        cause: expect.any(AggregateError),
      });
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
      "production-token-old",
    );
    expect(localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:production",
    );
    expect(rollbackStates).toEqual([true]);
    expect(transitions).toEqual([]);
  });

  it("runs finalization and receipt commit for a same-token login", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "same-token");
    const finalizeBeforePublish = vi.fn(() => undefined);
    const commitBeforePublish = vi.fn(() => true);
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const authority = await writeStoredStewardToken("same-token", {
        finalizeBeforePublish,
        commitBeforePublish,
      });

      expect(authority).not.toBeNull();
      await expect(
        authority?.restorePredecessor({ deferPublication: true }),
      ).resolves.toBe(true);
      expect(authority?.publish?.()).toBe(true);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(finalizeBeforePublish).toHaveBeenCalledOnce();
    expect(commitBeforePublish).toHaveBeenCalledOnce();
    expect(transitions).toEqual([]);
  });

  it("does not let an old receipt roll back a same-value ABA successor", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
    let receiptLive = true;
    const restorePredecessor = vi.fn(async () => {
      if (!receiptLive) return false;
      localStorage.setItem(STEWARD_TOKEN_KEY, "token-old");
      return true;
    });
    const unregister = registerStewardTokenPersistence(async (token) => {
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return {
        commit: async () => undefined,
        restorePredecessor,
      };
    });

    try {
      const authority = await writeStoredStewardToken("same-bytes-a");
      expect(authority).not.toBeNull();
      localStorage.setItem(STEWARD_TOKEN_KEY, "token-b");
      localStorage.setItem(STEWARD_TOKEN_KEY, "same-bytes-a");
      receiptLive = false;

      await expect(authority?.restorePredecessor()).resolves.toBe(false);
    } finally {
      unregister();
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("same-bytes-a");
    expect(restorePredecessor).toHaveBeenCalledOnce();
  });

  it("does not advance authority when the same token is persisted again", async () => {
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      await writeStoredStewardToken("same-token");
      await writeStoredStewardToken("same-token");
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(transitions.map(({ state }) => state)).toEqual(["present"]);
  });

  it("rejects a stale refresh replacement after canonical logout", async () => {
    await writeStoredStewardToken("refresh-source-token");
    await clearStoredStewardToken();

    await expect(
      replaceStoredStewardTokenIfCurrent(
        "refresh-source-token",
        "stale-refreshed-token",
      ),
    ).resolves.toBe(false);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("revalidates a cached token through the registered durable host", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "cached-token");
    const persist = vi.fn().mockResolvedValue(undefined);
    const unregister = registerStewardTokenPersistence(persist);

    try {
      await writeStoredStewardToken("cached-token");
    } finally {
      unregister();
    }

    expect(persist).toHaveBeenCalledWith("cached-token", {
      previousScope: null,
      requiredScope: null,
    });
  });

  it("publishes canonical invalidation before stale refresh-key cleanup can fail", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "steward-token");
    localStorage.setItem(STEWARD_REFRESH_TOKEN_KEY, "legacy-refresh-token");
    const storageFailure = new Error("legacy refresh storage unavailable");
    const originalStorage = window.localStorage;
    const restoreStorage = installLocalStorageOverride({
      removeItem(key) {
        if (key === STEWARD_REFRESH_TOKEN_KEY) throw storageFailure;
        originalStorage.removeItem(key);
      },
    });
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      await expect(clearStoredStewardToken()).rejects.toThrow(storageFailure);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
      restoreStorage();
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(localStorage.getItem(STEWARD_REFRESH_TOKEN_KEY)).toBe(
      "legacy-refresh-token",
    );
    expect(transitions.map(({ state }) => state)).toEqual(["cleared"]);
  });

  it("fails fast without publishing when canonical storage mutations fail", async () => {
    const storageFailure = new Error("canonical storage unavailable");
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    const restoreSetFailure = installLocalStorageOverride({
      setItem() {
        throw storageFailure;
      },
    });

    try {
      await expect(
        writeStoredStewardToken("steward-token"),
      ).rejects.toMatchObject({
        name: "StewardTokenPersistenceError",
        message: storageFailure.message,
        cause: storageFailure,
      });
    } finally {
      restoreSetFailure();
    }

    const restoreRemoveFailure = installLocalStorageOverride({
      removeItem() {
        throw storageFailure;
      },
    });
    try {
      await expect(clearStoredStewardToken()).rejects.toMatchObject({
        name: "StewardTokenRemovalError",
        message: storageFailure.message,
        cause: storageFailure,
      });
    } finally {
      restoreRemoveFailure();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(transitions).toEqual([]);
  });

  it("publishes present only after the host confirms durable persistence", async () => {
    let releasePersistence: () => void = () => {};
    const persistence = new Promise<void>((resolve) => {
      releasePersistence = resolve;
    });
    let releaseCommit: () => void = () => {};
    const commitWait = new Promise<void>((resolve) => {
      releaseCommit = resolve;
    });
    const commit = vi.fn(() => commitWait);
    const unregister = registerStewardTokenPersistence(async (token) => {
      await persistence;
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return commit;
    });
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const write = writeStoredStewardToken("durable-token");
      await Promise.resolve();
      expect(transitions).toEqual([]);
      releasePersistence();
      await vi.waitFor(() => expect(commit).toHaveBeenCalledOnce());
      expect(transitions).toEqual([]);
      releaseCommit();
      await write;
      expect(transitions.map(({ state }) => state)).toEqual(["present"]);
    } finally {
      unregister();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it.each([null, "prior-token"])(
    "rolls an aborted deferred persistence back to %s without publishing",
    async (previousToken) => {
      if (previousToken !== null) {
        localStorage.setItem(STEWARD_TOKEN_KEY, previousToken);
      }
      let markPersistenceStarted: () => void = () => {};
      const persistenceStarted = new Promise<void>((resolve) => {
        markPersistenceStarted = resolve;
      });
      let releasePersistence: () => void = () => {};
      const persistenceWait = new Promise<void>((resolve) => {
        releasePersistence = resolve;
      });
      const commit = vi.fn(async () => undefined);
      const unregisterPersistence = registerStewardTokenPersistence(
        async (token) => {
          markPersistenceStarted();
          await persistenceWait;
          localStorage.setItem(STEWARD_TOKEN_KEY, token);
          return commit;
        },
      );
      const transitions: StewardSessionChangeDetail[] = [];
      const listener = (event: Event) => {
        transitions.push(
          (event as CustomEvent<StewardSessionChangeDetail>).detail,
        );
      };
      window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
      const controller = new AbortController();

      try {
        const write = writeStoredStewardToken("aborted-token", {
          signal: controller.signal,
        });
        await persistenceStarted;
        controller.abort();
        releasePersistence();

        await expect(write).rejects.toMatchObject({ name: "AbortError" });
        expect(commit).not.toHaveBeenCalled();
        expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(previousToken);
        expect(transitions).toEqual([]);
      } finally {
        unregisterPersistence();
        window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
      }
    },
  );

  it("compensates when external authority changes during protected persistence", async () => {
    let authoritative = true;
    let markPersistenceStarted: () => void = () => {};
    const persistenceStarted = new Promise<void>((resolve) => {
      markPersistenceStarted = resolve;
    });
    let releasePersistence: () => void = () => {};
    const persistenceWait = new Promise<void>((resolve) => {
      releasePersistence = resolve;
    });
    const commit = vi.fn(async () => undefined);
    const unregister = registerStewardTokenPersistence(async (token) => {
      markPersistenceStarted();
      await persistenceWait;
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return commit;
    });
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const write = writeStoredStewardToken("account-a", {
        validate: () => authoritative,
      });
      await persistenceStarted;
      authoritative = false;
      releasePersistence();

      await write;
      expect(commit).not.toHaveBeenCalled();
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(transitions).toEqual([]);
    } finally {
      unregister();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("compensates when external authority changes during receipt commit", async () => {
    let authoritative = true;
    let markCommitStarted: () => void = () => {};
    const commitStarted = new Promise<void>((resolve) => {
      markCommitStarted = resolve;
    });
    let releaseCommit: () => void = () => {};
    const commitWait = new Promise<void>((resolve) => {
      releaseCommit = resolve;
    });
    const unregister = registerStewardTokenPersistence(async (token) => {
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return async (validate) => {
        expect(validate?.()).toBe(true);
        markCommitStarted();
        await commitWait;
      };
    });
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const write = writeStoredStewardToken("account-a", {
        validate: () => authoritative,
      });
      await commitStarted;
      authoritative = false;
      releaseCommit();

      await write;
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(transitions).toEqual([]);
    } finally {
      unregister();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("does not publish a refreshed replacement superseded during persistence", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-old");
    let authoritative = true;
    let markPersistenceStarted: () => void = () => {};
    const persistenceStarted = new Promise<void>((resolve) => {
      markPersistenceStarted = resolve;
    });
    let releasePersistence: () => void = () => {};
    const persistenceWait = new Promise<void>((resolve) => {
      releasePersistence = resolve;
    });
    const commit = vi.fn(async () => undefined);
    const unregister = registerStewardTokenPersistence(async (token) => {
      markPersistenceStarted();
      await persistenceWait;
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
      return commit;
    });
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const replacement = replaceStoredStewardTokenIfCurrent(
        "account-a-old",
        "account-a-refreshed",
        { validate: () => authoritative },
      );
      await persistenceStarted;
      authoritative = false;
      releasePersistence();

      await expect(replacement).resolves.toBe(false);
      expect(commit).not.toHaveBeenCalled();
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-a-old");
      expect(transitions).toEqual([]);
    } finally {
      unregister();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("lets a newer queued write survive an aborted predecessor rollback", async () => {
    let markFirstStarted: () => void = () => {};
    const firstStarted = new Promise<void>((resolve) => {
      markFirstStarted = resolve;
    });
    let releaseFirst: () => void = () => {};
    const firstWait = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const unregisterPersistence = registerStewardTokenPersistence(
      async (token) => {
        if (token === "aborted-token") {
          markFirstStarted();
          await firstWait;
        }
        localStorage.setItem(STEWARD_TOKEN_KEY, token);
      },
    );
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    const controller = new AbortController();

    try {
      const first = writeStoredStewardToken("aborted-token", {
        signal: controller.signal,
      });
      await firstStarted;
      controller.abort();
      const second = writeStoredStewardToken("newer-token");
      releaseFirst();

      await expect(first).rejects.toMatchObject({ name: "AbortError" });
      await second;
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("newer-token");
      expect(transitions.map(({ state }) => state)).toEqual(["present"]);
    } finally {
      unregisterPersistence();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("preserves a newer browser value when aborted-write rollback loses its CAS", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "prior-token");
    let markAttemptPersisted: () => void = () => {};
    const attemptPersisted = new Promise<void>((resolve) => {
      markAttemptPersisted = resolve;
    });
    let releasePersistence: () => void = () => {};
    const persistenceWait = new Promise<void>((resolve) => {
      releasePersistence = resolve;
    });
    const unregisterPersistence = registerStewardTokenPersistence(
      async (token) => {
        localStorage.setItem(STEWARD_TOKEN_KEY, token);
        markAttemptPersisted();
        await persistenceWait;
      },
    );
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    const controller = new AbortController();

    try {
      const write = writeStoredStewardToken("aborted-token", {
        signal: controller.signal,
      });
      await attemptPersisted;
      localStorage.setItem(STEWARD_TOKEN_KEY, "external-newer-token");
      controller.abort();
      releasePersistence();

      await expect(write).rejects.toMatchObject({ name: "AbortError" });
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
        "external-newer-token",
      );
      expect(transitions).toEqual([]);
    } finally {
      unregisterPersistence();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("does not publish cleared until the host confirms durable removal", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "steward-token");
    let releaseRemoval: () => void = () => {};
    const removal = new Promise<void>((resolve) => {
      releaseRemoval = resolve;
    });
    const unregister = registerStewardTokenRemoval(() => removal);
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      const clear = clearStoredStewardToken();
      await Promise.resolve();
      expect(transitions).toEqual([]);
      releaseRemoval();
      await clear;
      expect(transitions.map(({ state }) => state)).toEqual(["cleared"]);
    } finally {
      unregister();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("does not disguise a failed canonical read as a missing session", () => {
    const storageFailure = new Error("canonical storage unavailable");
    const restoreStorage = installLocalStorageOverride({
      getItem() {
        throw storageFailure;
      },
    });

    try {
      expect(() => readStoredStewardToken()).toThrow(storageFailure);
    } finally {
      restoreStorage();
    }
  });
});
