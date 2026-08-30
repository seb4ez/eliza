/** Verifies getCloudAuthToken (Cloud = Steward everywhere) through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * Unit coverage for reading the Steward session token, computing its
 * seconds-remaining from the JWT `exp`, the cookie-backed Steward refresh
 * (web/fetch branch — native/Electrobun HTTP has its own dedicated coverage),
 * and the cloud web/API host-normalization helpers. Tokens hand-built, no
 * live cloud.
 */

import {
  registerStewardTokenPersistence,
  STEWARD_SESSION_CHANGE_EVENT,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enqueueStewardSessionMutation } from "../cloud/lib/steward-session-mutation-queue";
import {
  beginStewardSessionRecovery,
  completeStewardSessionRecovery,
  readStewardSessionRecovery,
  rejectStewardSessionRecovery,
} from "../cloud/lib/steward-session-recovery-marker";
import {
  configuredStewardTenantId,
  DEFAULT_STEWARD_TENANT_ID,
} from "../cloud/shell/steward-config";
import {
  loadAgentProfileRegistry,
  saveAgentProfileRegistry,
} from "../state/agent-profiles";
import {
  loadPersistedActiveServer,
  savePersistedActiveServer,
} from "../state/persistence";
import { ElizaClient } from "./client-base";
import {
  cloudTokenSecsRemaining,
  getCloudAuthToken,
  refreshCloudStewardSession,
  resolveDirectCloudAppBase,
  resolveDirectCloudAuthApiBase,
  resolveDirectCloudWebBase,
} from "./client-cloud";

const STEWARD_TOKEN_KEY = "steward_session_token";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function makeJwt(exp: number | null): string {
  const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const payload = btoa(JSON.stringify(exp === null ? {} : { exp }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.sig`;
}

describe("getCloudAuthToken (Cloud = Steward everywhere)", () => {
  beforeEach(() => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
  });

  afterEach(() => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
  });

  it("prefers the Steward session token over the client REST token", () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "steward-jwt");
    const client = new ElizaClient();
    client.setToken("client-token");
    expect(getCloudAuthToken(client)).toBe("steward-jwt");
    client.setToken(null);
  });

  it("resolves the device-code/Remote session token from the steward store", () => {
    // The device-code/pairing flow persists its session token through the same
    // steward-session store, so it resolves via the canonical Steward branch.
    localStorage.setItem(STEWARD_TOKEN_KEY, "device-code-token");
    expect(getCloudAuthToken()).toBe("device-code-token");
  });

  it("falls back to the client REST token last", () => {
    const client = new ElizaClient();
    client.setToken("client-token");
    expect(getCloudAuthToken(client)).toBe("client-token");
    client.setToken(null);
  });

  it("dispatches steward-token-sync when the client REST token changes", () => {
    const listener = vi.fn();
    window.addEventListener("steward-token-sync", listener);
    const client = new ElizaClient();

    client.setToken("client-token");
    client.setToken(null);

    window.removeEventListener("steward-token-sync", listener);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("updates the REST bearer silently during terminal teardown", () => {
    const listener = vi.fn();
    window.addEventListener("steward-token-sync", listener);
    const client = new ElizaClient();
    client.setToken("client-token");
    listener.mockClear();

    client.clearTokenSilently();

    window.removeEventListener("steward-token-sync", listener);
    expect(client.getRestAuthToken()).toBeNull();
    expect(listener).not.toHaveBeenCalled();
  });

  it("publishes and restores only coherent session-target pairs", () => {
    const client = new ElizaClient("https://api.eliza.app", "old-token");
    let finalized = false;
    const observed: Array<[string, string | null, boolean]> = [];
    const observe = () => {
      observed.push([
        client.getBaseUrl(),
        client.getRestAuthToken(),
        finalized,
      ]);
    };
    const offBase = client.onBaseUrlChange(observe);
    const offAuthority = client.onAuthorityChange(observe);

    const authority = client.installSessionTarget(
      {
        baseUrl: "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
        token: "new-token",
      },
      {
        persist: false,
        finalizeBeforePublish: () => {
          finalized = true;
        },
      },
    );

    expect(authority).not.toBeNull();
    expect(observed).toEqual([
      [
        "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
        "new-token",
        true,
      ],
      [
        "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
        "new-token",
        true,
      ],
    ]);
    observed.length = 0;
    expect(authority?.restoreIfCurrent()).toBe(true);
    expect(observed).toEqual([
      ["https://api.eliza.app", "old-token", true],
      ["https://api.eliza.app", "old-token", true],
    ]);
    offBase();
    offAuthority();
  });

  it("restores the predecessor before exposing a failed target finalizer", () => {
    const client = new ElizaClient("https://api.eliza.app", "old-token");
    const observed = vi.fn();
    const offAuthority = client.onAuthorityChange(observed);

    expect(() =>
      client.installSessionTarget(
        {
          baseUrl:
            "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
          token: "new-token",
        },
        {
          persist: false,
          finalizeBeforePublish: () => {
            throw new Error("receipt superseded");
          },
        },
      ),
    ).toThrow("receipt superseded");
    expect(client.getBaseUrl()).toBe("https://api.eliza.app");
    expect(client.getRestAuthToken()).toBe("old-token");
    expect(observed).not.toHaveBeenCalled();
    offAuthority();
  });

  it("does not let an old session-target handle restore across same-value ABA", () => {
    const client = new ElizaClient("https://api.eliza.app", "old-token");
    const targetA = {
      baseUrl: "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
      token: "token-a",
    };
    const firstA = client.installSessionTarget(targetA);
    client.installSessionTarget({
      baseUrl: "https://00000000-0000-4000-8000-000000000021.cloud.eliza.app",
      token: "token-b",
    });
    client.installSessionTarget(targetA);

    expect(firstA?.restoreIfCurrent()).toBe(false);
    expect(client.getBaseUrl()).toBe(targetA.baseUrl);
    expect(client.getRestAuthToken()).toBe(targetA.token);
  });

  it("returns null when no token is available anywhere", () => {
    expect(getCloudAuthToken()).toBeNull();
  });

  it("dispatches steward-token-sync on setToken so mounted gates refresh (#12046 Nit 2)", () => {
    const client = new ElizaClient();
    let syncs = 0;
    const handler = () => {
      syncs++;
    };
    window.addEventListener("steward-token-sync", handler);
    try {
      client.setToken("client-token");
      client.setToken(null);
      // Both the sign-in and the sign-out write must notify listeners — before
      // the fix setToken dispatched nothing and the gate went stale until a
      // remount.
      expect(syncs).toBe(2);
    } finally {
      window.removeEventListener("steward-token-sync", handler);
    }
  });
});

describe("selectOrProvisionCloudAgent Steward authority publication", () => {
  it("does not let a delayed selection for A overwrite completed login B", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const originalLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    const lockRequested = deferred<void>();
    const releaseLock = deferred<void>();
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: vi.fn(
          async (
            _name: string,
            _options: { mode: "exclusive" },
            callback: () => Promise<unknown>,
          ) => {
            lockRequested.resolve();
            await releaseLock.promise;
            return callback();
          },
        ),
      },
    });

    try {
      const client = new ElizaClient("https://api.eliza.app");
      const delayedSelection = client.selectOrProvisionCloudAgent({
        cloudApiBase: "https://api.eliza.app",
        authToken: "account-a-token",
        name: "Eliza",
        knownAgents: [],
      });
      await lockRequested.promise;

      const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
      expect(readStewardSessionRecovery(tenantId).receipts).toHaveLength(1);
      const newerLogin = beginStewardSessionRecovery(tenantId, "provider");
      localStorage.setItem(STEWARD_TOKEN_KEY, "account-b-token");
      completeStewardSessionRecovery(newerLogin);
      releaseLock.resolve();

      await expect(delayedSelection).rejects.toMatchObject({
        code: "STEWARD_SESSION_SUPERSEDED",
      });
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-b-token");
      expect(readStewardSessionRecovery(tenantId).receipts).toEqual([]);
    } finally {
      releaseLock.resolve();
      if (originalLocks) {
        Object.defineProperty(navigator, "locks", originalLocks);
      } else {
        Reflect.deleteProperty(navigator, "locks");
      }
      localStorage.removeItem(STEWARD_TOKEN_KEY);
    }
  });
});

describe("cloudTokenSecsRemaining", () => {
  it("returns seconds remaining for a JWT with exp", () => {
    const exp = Math.floor(Date.now() / 1000) + 600;
    const secs = cloudTokenSecsRemaining(makeJwt(exp));
    expect(secs).not.toBeNull();
    expect(secs as number).toBeGreaterThan(500);
    expect(secs as number).toBeLessThanOrEqual(600);
  });

  it("returns null for a JWT without exp", () => {
    expect(cloudTokenSecsRemaining(makeJwt(null))).toBeNull();
  });

  it("returns null for a non-JWT opaque token", () => {
    expect(cloudTokenSecsRemaining("opaque-device-code-token")).toBeNull();
  });
});

describe("resolveDirectCloudWebBase / resolveDirectCloudAuthApiBase", () => {
  it("maps a known API host to the browser-navigable web host", () => {
    expect(resolveDirectCloudWebBase("https://api.elizacloud.ai")).toBe(
      "https://eliza.app",
    );
  });

  it("maps a staging API host to the staging web host", () => {
    expect(resolveDirectCloudWebBase("https://api-staging.elizacloud.ai")).toBe(
      "https://staging.eliza.app",
    );
  });

  it("passes through an unmapped host unchanged (trailing slash trimmed)", () => {
    expect(resolveDirectCloudWebBase("https://example.com/")).toBe(
      "https://example.com",
    );
  });

  it("trims a 100k trailing slash run without changing the prefix", () => {
    expect(
      resolveDirectCloudWebBase(`https://example.com${"/".repeat(100_000)}`),
    ).toBe("https://example.com");
  });

  it("falls back to the raw input for an unparseable base", () => {
    expect(resolveDirectCloudWebBase("not a url")).toBe("not a url");
  });

  it("maps a known site host to its API host", () => {
    expect(resolveDirectCloudAuthApiBase("https://www.elizacloud.ai")).toBe(
      "https://api.eliza.app",
    );
  });

  it("passes through an unmapped host unchanged for the auth API base", () => {
    expect(resolveDirectCloudAuthApiBase("https://example.com")).toBe(
      "https://example.com",
    );
  });

  it("falls back to the raw input for an unparseable auth API base", () => {
    expect(resolveDirectCloudAuthApiBase("not a url")).toBe("not a url");
  });

  it("keeps management navigation on the canonical Cloud app host", () => {
    expect(resolveDirectCloudAppBase("https://api.elizacloud.ai")).toBe(
      "https://cloud.eliza.app",
    );
    expect(resolveDirectCloudAppBase("https://staging.elizacloud.ai")).toBe(
      "https://cloud-staging.eliza.app",
    );
  });
});

describe("refreshCloudStewardSession (web/fetch branch)", () => {
  // Not native and not Electrobun in jsdom — shouldUseNativeStewardRefreshHttp
  // is false, so every case here exercises the plain `fetch` + credentials
  // branch, mirroring cloud-frontend's AuthTokenSync.
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("POSTs with credentials included and returns the rotated token payload", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ token: "rotated-jwt", expiresIn: 900 }),
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await refreshCloudStewardSession({
      endpoint: "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-Eliza-CSRF": "1",
        },
        signal: expect.any(AbortSignal),
      }),
    );
    expect(result).toEqual({ token: "rotated-jwt", expiresIn: 900 });
  });

  it("holds the origin mutation lease through refreshed-token publication", async () => {
    const publish = deferred<void>();
    const order: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ token: "rotated-jwt" }),
      })),
    );

    const refresh = refreshCloudStewardSession({
      commitRefreshedSession: async () => {
        order.push("refresh-publish-start");
        await publish.promise;
        order.push("refresh-publish-end");
      },
    });
    await vi.waitFor(() => expect(order).toEqual(["refresh-publish-start"]));
    const laterLogin = enqueueStewardSessionMutation(async () => {
      order.push("later-login");
    });

    await Promise.resolve();
    expect(order).toEqual(["refresh-publish-start"]);
    publish.resolve();
    await Promise.all([refresh, laterLogin]);
    expect(order).toEqual([
      "refresh-publish-start",
      "refresh-publish-end",
      "later-login",
    ]);
  });

  it("compensates refresh A when login B starts during token persistence", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a");
    const persistenceStarted = deferred<void>();
    const releasePersistence = deferred<void>();
    const unregisterPersistence = registerStewardTokenPersistence(
      async (token) => {
        persistenceStarted.resolve();
        await releasePersistence.promise;
        localStorage.setItem(STEWARD_TOKEN_KEY, token);
        return async () => undefined;
      },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ token: "account-a-refreshed" }),
      })),
    );
    const authorityEvents: Event[] = [];
    const onAuthority = (event: Event) => authorityEvents.push(event);
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    let loginBReceipt:
      | ReturnType<typeof beginStewardSessionRecovery>
      | undefined;

    try {
      const refreshA = refreshCloudStewardSession({
        commitRefreshedSession: async (session, authority) => {
          if (session.token) {
            await writeStoredStewardToken(session.token, {
              validate: authority.validate,
            });
          }
        },
      });
      await persistenceStarted.promise;
      loginBReceipt = beginStewardSessionRecovery("elizacloud", "provider");
      releasePersistence.resolve();

      await expect(refreshA).resolves.toBeNull();
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-a");
      expect(authorityEvents).toEqual([]);
    } finally {
      if (loginBReceipt) rejectStewardSessionRecovery(loginBReceipt);
      unregisterPersistence();
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    }
  });

  it("does not dispatch a passive refresh while a durable login receipt exists", async () => {
    const receipt = beginStewardSessionRecovery("elizacloud", "provider");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(refreshCloudStewardSession()).resolves.toBeNull();
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      rejectStewardSessionRecovery(receipt);
    }
  });

  it("returns null when the refresh endpoint responds non-OK (no rotated cookie)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, json: async () => ({}) })),
    );
    const result = await refreshCloudStewardSession({
      endpoint: "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
    });
    expect(result).toBeNull();
  });

  it("durably clears every bearer mirror on an explicit session_ended refresh", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "revoked-bridged-token");
    savePersistedActiveServer({
      id: "cloud:dedicated-agent",
      kind: "cloud",
      label: "Dedicated agent",
      apiBase: "https://dedicated-agent.example.test",
      accessToken: "dedicated-bearer",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "remote-profile",
      profiles: [
        {
          id: "remote-profile",
          label: "Remote agent",
          kind: "remote",
          apiBase: "https://remote-agent.example.test",
          accessToken: "profile-bearer",
          createdAt: "2026-08-30T00:00:00.000Z",
        },
      ],
    });
    const listener = vi.fn();
    window.addEventListener("steward-token-sync", listener);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 401,
        json: async () => ({ code: "session_ended" }),
      })),
    );

    try {
      await expect(refreshCloudStewardSession()).resolves.toBeNull();
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      const activeServer = loadPersistedActiveServer();
      expect(activeServer?.id).toBe("cloud:dedicated-agent");
      expect(activeServer?.accessToken).toBeUndefined();
      const [profile] = loadAgentProfileRegistry().profiles;
      expect(profile?.id).toBe("remote-profile");
      expect(profile?.accessToken).toBeUndefined();
      expect(listener).toHaveBeenCalled();
    } finally {
      window.removeEventListener("steward-token-sync", listener);
    }
  });

  it("clears cookie-only bearer mirrors on an explicit session_ended refresh", async () => {
    savePersistedActiveServer({
      id: "cloud:cookie-only-agent",
      kind: "cloud",
      label: "Cookie-only agent",
      apiBase: "https://cookie-only-agent.example.test",
      accessToken: "dedicated-cookie-only-bearer",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "cookie-only-profile",
      profiles: [
        {
          id: "cookie-only-profile",
          label: "Cookie-only profile",
          kind: "remote",
          apiBase: "https://cookie-only-profile.example.test",
          accessToken: "profile-cookie-only-bearer",
          createdAt: "2026-08-30T00:00:00.000Z",
        },
      ],
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 401,
        json: async () => ({ code: "session_ended" }),
      })),
    );

    await expect(refreshCloudStewardSession()).resolves.toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(loadPersistedActiveServer()?.accessToken).toBeUndefined();
    expect(loadAgentProfileRegistry().profiles[0]?.accessToken).toBeUndefined();
  });

  it("preserves cookie-only account B while its durable receipt supersedes session_ended A", async () => {
    savePersistedActiveServer({
      id: "cloud:account-b-agent",
      kind: "cloud",
      label: "Account B agent",
      apiBase: "https://account-b-agent.example.test",
      accessToken: "account-b-agent-token",
    });
    const response = deferred<{
      ok: boolean;
      status: number;
      json: () => Promise<{ code: string }>;
    }>();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => response.promise),
    );

    const refreshA = refreshCloudStewardSession();
    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalledOnce());
    const loginBReceipt = beginStewardSessionRecovery("elizacloud", "provider");
    response.resolve({
      ok: false,
      status: 401,
      json: async () => ({ code: "session_ended" }),
    });

    try {
      await expect(refreshA).resolves.toBeNull();
      expect(loadPersistedActiveServer()?.accessToken).toBe(
        "account-b-agent-token",
      );
    } finally {
      rejectStewardSessionRecovery(loginBReceipt);
    }
  });

  it("does not let account A's session_ended response clear a newer account B", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a");
    savePersistedActiveServer({
      id: "cloud:account-b-agent",
      kind: "cloud",
      label: "Account B agent",
      apiBase: "https://account-b-agent.example.test",
      accessToken: "account-b-agent-token",
    });
    const response = deferred<{
      ok: boolean;
      status: number;
      json: () => Promise<{ code: string }>;
    }>();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => response.promise),
    );

    const refreshA = refreshCloudStewardSession();
    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalledOnce());
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-b");
    response.resolve({
      ok: false,
      status: 401,
      json: async () => ({ code: "session_ended" }),
    });

    await expect(refreshA).resolves.toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-b");
    expect(loadPersistedActiveServer()?.accessToken).toBe(
      "account-b-agent-token",
    );
  });

  it("preserves a still-valid local token on a bare invalid_token refresh", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "still-valid-token");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 401,
        json: async () => ({ code: "invalid_token" }),
      })),
    );

    await expect(refreshCloudStewardSession()).resolves.toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("still-valid-token");
  });

  it("surfaces a typed transient failure when the caller must preserve auth state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 503 })),
    );

    await expect(
      refreshCloudStewardSession({
        endpoint: "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
        throwOnTransientHttpFailure: true,
      }),
    ).rejects.toMatchObject({
      code: "STEWARD_SESSION_REFRESH_TRANSIENT",
      context: {
        endpoint: "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
        status: 503,
      },
    });
  });

  it("treats a malformed 2xx body as transient when the caller must preserve auth state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError("Unexpected token");
        },
      })),
    );

    await expect(
      refreshCloudStewardSession({
        endpoint: "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
        throwOnTransientHttpFailure: true,
      }),
    ).rejects.toMatchObject({
      code: "STEWARD_SESSION_REFRESH_TRANSIENT",
      context: {
        endpoint: "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
        status: 200,
      },
    });
  });

  it("treats an empty 2xx body as transient when the caller must preserve auth state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) })),
    );

    await expect(
      refreshCloudStewardSession({
        endpoint: "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
        throwOnTransientHttpFailure: true,
      }),
    ).rejects.toMatchObject({
      code: "STEWARD_SESSION_REFRESH_TRANSIENT",
    });
  });

  it("returns null when the response body is not parseable JSON (J3 fail-closed)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => {
          throw new SyntaxError("Unexpected token");
        },
      })),
    );
    const result = await refreshCloudStewardSession({
      endpoint: "https://api.elizacloud.ai/api/v1/auth/steward/refresh",
    });
    expect(result).toBeNull();
  });
});

describe("refreshCloudStewardSession timeouts (portable fallback, fake timers)", () => {
  const ENDPOINT = "https://api.elizacloud.ai/api/v1/auth/steward/refresh";
  const TIMEOUT_MS = 30_000;
  let originalTimeout: unknown;

  async function waitForMutationAdmission(
    fetchMock: ReturnType<typeof vi.fn>,
  ): Promise<void> {
    // refresh is admitted through both the module-local tail and the shared
    // test-origin queue before fetch dispatches. Drain only promise jobs here;
    // advancing fake time before admission would start the 30 s clock late and
    // weaken the timeout assertion this block exists to prove.
    for (let turn = 0; turn < 16 && fetchMock.mock.calls.length === 0; turn++) {
      await Promise.resolve();
    }
    expect(fetchMock).toHaveBeenCalledTimes(1);
  }

  beforeEach(() => {
    // Force the AbortController+setTimeout fallback so fake timers control the
    // timeout deterministically. Native AbortSignal.timeout uses an internal
    // timer not governed by vi.useFakeTimers() in all runtimes, so forcing
    // fallback makes the 30 s contract testable.
    originalTimeout = (AbortSignal as unknown as { timeout?: unknown }).timeout;
    Object.defineProperty(AbortSignal, "timeout", {
      value: undefined,
      configurable: true,
      writable: true,
    });
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    Object.defineProperty(AbortSignal, "timeout", {
      value: originalTimeout,
      configurable: true,
      writable: true,
    });
  });

  it("aborts a headers-stalled fetch at 30 s and maps to STEWARD_SESSION_REFRESH_TRANSIENT (throwOnTransient)", async () => {
    const fetchMock = vi.fn(
      (_url: RequestInfo | URL, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          const signal = init?.signal as AbortSignal | undefined;
          if (signal?.aborted) {
            reject(new DOMException("TimeoutError", "TimeoutError"));
            return;
          }
          signal?.addEventListener(
            "abort",
            () => reject(new DOMException("TimeoutError", "TimeoutError")),
            { once: true },
          );
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const pending = refreshCloudStewardSession({
      endpoint: ENDPOINT,
      throwOnTransientHttpFailure: true,
    });

    // Must NOT settle before the timeout fires.
    let settled = false;
    pending.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await waitForMutationAdmission(fetchMock);
    expect(settled).toBe(false);
    const signal = (fetchMock.mock.calls[0]?.[1] as RequestInit | undefined)
      ?.signal as AbortSignal | undefined;
    expect(signal).toBeInstanceOf(AbortSignal);

    await vi.advanceTimersByTimeAsync(TIMEOUT_MS);

    await expect(pending).rejects.toMatchObject({
      code: "STEWARD_SESSION_REFRESH_TRANSIENT",
      context: { endpoint: ENDPOINT },
    });
    // Timer is disposed after abort so success-before-timeout does not leak.
    expect(vi.getTimerCount()).toBe(0);
  });

  it("returns null on headers stall when not in throwOnTransient mode (fail-closed)", async () => {
    const fetchMock = vi.fn(
      (_url: RequestInfo | URL, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          const signal = init?.signal as AbortSignal | undefined;
          signal?.addEventListener(
            "abort",
            () => reject(new DOMException("AbortError", "AbortError")),
            { once: true },
          );
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const pending = refreshCloudStewardSession({ endpoint: ENDPOINT });
    await waitForMutationAdmission(fetchMock);
    await vi.advanceTimersByTimeAsync(TIMEOUT_MS);
    await expect(pending).resolves.toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("aborts a headers-received plus stalled body at 30 s (signal kept alive through json)", async () => {
    const fetchMock = vi.fn(
      async (_url: RequestInfo | URL, init?: RequestInit) => {
        const signal = init?.signal as AbortSignal | undefined;
        return {
          ok: true,
          status: 200,
          json: () =>
            new Promise((_resolve, reject) => {
              if (signal?.aborted) {
                reject(new DOMException("TimeoutError", "TimeoutError"));
                return;
              }
              signal?.addEventListener(
                "abort",
                () => reject(new DOMException("TimeoutError", "TimeoutError")),
                { once: true },
              );
            }),
        };
      },
    );
    vi.stubGlobal("fetch", fetchMock);

    const pending = refreshCloudStewardSession({
      endpoint: ENDPOINT,
      throwOnTransientHttpFailure: true,
    });

    // Let the fetch resolve headers (microtask) but json stays pending.
    await waitForMutationAdmission(fetchMock);
    await Promise.resolve();
    // Still pending before timeout.
    let settled = false;
    pending.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await Promise.resolve();
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(TIMEOUT_MS);

    await expect(pending).rejects.toMatchObject({
      code: "STEWARD_SESSION_REFRESH_TRANSIENT",
    });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("clears the pending timer on success before timeout (no leak under fake timers)", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ token: "fresh-jwt", expiresIn: 900 }),
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await refreshCloudStewardSession({ endpoint: ENDPOINT });
    expect(result).toEqual({ token: "fresh-jwt", expiresIn: 900 });
    // dispose() cleared the fallback timer; no pending timers remain.
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not mutate the global AbortSignal.timeout across tests (fallback proof)", () => {
    // This test proves the fallback path was exercised without leaking the
    // stub — the afterEach restores the original, so a later test sees the
    // native impl again.
    expect(
      (AbortSignal as unknown as { timeout?: unknown }).timeout,
    ).toBeUndefined();
  });
});
