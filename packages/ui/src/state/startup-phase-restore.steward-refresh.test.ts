/**
 * Exercises Cloud session restoration with real jsdom storage and a bounded
 * fetch double. Steward JWT refresh and agent-local loopback credentials stay
 * isolated so neither credential is sent to the wrong trust boundary.
 */
// @vitest-environment jsdom

import {
  registerStewardTokenPersistence,
  STEWARD_TENANT_ID,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionRecovery,
  rejectStewardSessionRecovery,
  type StewardSessionRecoveryReceipt,
} from "../cloud/lib/steward-session-recovery-marker";
import {
  loadPersistedActiveServer,
  type PersistedActiveServer,
  savePersistedActiveServer,
} from "./persistence";
import { applyRestoredConnection } from "./startup-phase-restore";

const STEWARD_TOKEN_KEY = "steward_session_token";
const STEWARD_REFRESH_PATH = "/api/auth/steward-refresh";
const CLOUD_AGENT_ID = "11111111-1111-4111-8111-111111111111";
const CLOUD_AGENT_API_BASE = `https://api.eliza.app/api/v1/eliza/agents/${CLOUD_AGENT_ID}`;

/** Build a minimal (unsigned) JWT whose payload carries the given `exp`. */
function makeJwt(expSecondsFromNow: number | null): string {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  const header = enc({ alg: "none", typ: "JWT" });
  const payload = enc(
    expSecondsFromNow === null
      ? {}
      : { exp: Math.floor(Date.now() / 1000) + expSecondsFromNow },
  );
  return `${header}.${payload}.sig`;
}

/** A cloud active-server with a concrete (non-agentless) apiBase so the restore
 * backfill returns immediately without any network round-trip. */
function cloudServer(
  overrides: Partial<PersistedActiveServer> = {},
): PersistedActiveServer {
  return {
    id: `cloud:${CLOUD_AGENT_ID}`,
    kind: "cloud",
    label: "Eliza Cloud",
    apiBase: CLOUD_AGENT_API_BASE,
    ...overrides,
  };
}

function fakeClient() {
  return { setBaseUrl: vi.fn(), setToken: vi.fn() };
}

function fakeClientWithStagedAuthority() {
  const base = fakeClient();
  let revision = 0;
  const stageSessionTarget = vi.fn(
    (target: { baseUrl: string; token: string }) => {
      const installedRevision = ++revision;
      let live = true;
      base.setToken(null);
      base.setBaseUrl(target.baseUrl);
      base.setToken(target.token);
      const consume = () => {
        if (!live || revision !== installedRevision) return false;
        live = false;
        revision += 1;
        return true;
      };
      return {
        publish: vi.fn(() => live && revision === installedRevision),
        restoreIfCurrent: vi.fn(() => consume()),
        clearIfCurrent: vi.fn(() => {
          if (!consume()) return false;
          base.setToken(null);
          return true;
        }),
      };
    },
  );
  return {
    ...base,
    stageSessionTarget,
    installNewerTarget(baseUrl: string, token: string) {
      revision += 1;
      base.setBaseUrl(baseUrl);
      base.setToken(token);
    },
  };
}

describe("applyRestoredConnection — cloud Steward token refresh at restore", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    localStorage.clear();
    fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    vi.useRealTimers();
    globalThis.fetch = realFetch;
    // biome-ignore lint/suspicious/noDocumentCookie: jsdom has no Cookie Store API.
    document.cookie = "steward-authed=; Max-Age=0; path=/";
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("refreshes an EXPIRED stored JWT before setting it, and sets the refreshed token", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(-60));
    const fresh = makeJwt(3600);
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ token: fresh }),
    });

    const client = fakeClient();
    await applyRestoredConnection({
      restoredActiveServer: cloudServer(),
      clientRef: client,
    });

    // A single refresh POST to the same-origin endpoint (web / jsdom).
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(STEWARD_REFRESH_PATH);
    expect(init).toMatchObject({ method: "POST", credentials: "include" });
    // The client receives the REFRESHED token, not the expired one.
    expect(client.setToken).toHaveBeenCalledWith(fresh);
    // The fresh token is mirrored back to localStorage.
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(fresh);
  });

  it("refreshes a NEAR-EXPIRY stored JWT (inside the refresh-ahead margin)", async () => {
    // 30s of life left is under the 120s refresh-ahead margin.
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(30));
    const fresh = makeJwt(3600);
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ token: fresh }),
    });

    const client = fakeClient();
    await applyRestoredConnection({
      restoredActiveServer: cloudServer(),
      clientRef: client,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(client.setToken).toHaveBeenCalledWith(fresh);
  });

  it("does not reinstall an expired bearer when refresh succeeds after the startup timeout", async () => {
    vi.useFakeTimers();
    const expired = makeJwt(-60);
    const fresh = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, expired);
    let resolveFetch!: (value: {
      ok: boolean;
      json: () => Promise<{ token: string }>;
    }) => void;
    let markJsonRead!: () => void;
    const jsonRead = new Promise<void>((resolve) => {
      markJsonRead = resolve;
    });
    fetchMock.mockReturnValue(
      new Promise((resolve) => {
        resolveFetch = resolve;
      }),
    );
    const client = fakeClient();

    const restore = applyRestoredConnection({
      restoredActiveServer: cloudServer(),
      clientRef: client,
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(4_000);
    await restore;

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(client.setToken).toHaveBeenLastCalledWith(null);
    resolveFetch({
      ok: true,
      json: async () => {
        markJsonRead();
        return { token: fresh };
      },
    });
    await jsonRead;
    for (let i = 0; i < 5; i += 1) await Promise.resolve();

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(client.setToken).toHaveBeenLastCalledWith(null);
  });

  it("does not publish a cookie-recovered bearer after startup stopped waiting", async () => {
    vi.useFakeTimers();
    // biome-ignore lint/suspicious/noDocumentCookie: jsdom has no Cookie Store API.
    document.cookie = "steward-authed=1; path=/";
    const fresh = makeJwt(3600);
    let resolveFetch!: (value: {
      ok: boolean;
      json: () => Promise<{ token: string }>;
    }) => void;
    let markJsonRead!: () => void;
    const jsonRead = new Promise<void>((resolve) => {
      markJsonRead = resolve;
    });
    fetchMock.mockReturnValue(
      new Promise((resolve) => {
        resolveFetch = resolve;
      }),
    );
    const client = fakeClient();

    const restore = applyRestoredConnection({
      restoredActiveServer: cloudServer(),
      clientRef: client,
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(4_000);
    await restore;

    resolveFetch({
      ok: true,
      json: async () => {
        markJsonRead();
        return { token: fresh };
      },
    });
    await jsonRead;
    for (let i = 0; i < 5; i += 1) await Promise.resolve();

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(client.setToken).toHaveBeenLastCalledWith(null);
  });

  it("stops publishing restored client state when refresh authority changes during the durable write", async () => {
    const expired = makeJwt(-60);
    localStorage.setItem(STEWARD_TOKEN_KEY, expired);
    const fresh = makeJwt(3600);
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ token: fresh }),
    });
    let newerLogin: StewardSessionRecoveryReceipt | null = null;
    const unregisterPersistence = registerStewardTokenPersistence(
      async (token) => {
        localStorage.setItem(STEWARD_TOKEN_KEY, token);
        newerLogin = beginStewardSessionRecovery(STEWARD_TENANT_ID, "provider");
      },
    );
    const client = fakeClientWithStagedAuthority();

    try {
      await applyRestoredConnection({
        restoredActiveServer: cloudServer(),
        clientRef: client,
      });
    } finally {
      unregisterPersistence();
      if (newerLogin) rejectStewardSessionRecovery(newerLogin);
    }

    // Base + provisional A were published before the refresh. Once the newer
    // login marker invalidates the refresh, its exact client authority clears A
    // fail-closed while the fenced token write restores durable predecessor A.
    expect(client.setToken).toHaveBeenCalledTimes(3);
    expect(client.setToken).toHaveBeenLastCalledWith(null);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(expired);
  });

  it("does not clear a newer same-tab client target when restore authority is superseded", async () => {
    const expired = makeJwt(-60);
    localStorage.setItem(STEWARD_TOKEN_KEY, expired);
    const fresh = makeJwt(3600);
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ token: fresh }),
    });
    const client = fakeClientWithStagedAuthority();
    let newerLogin: StewardSessionRecoveryReceipt | null = null;
    const unregisterPersistence = registerStewardTokenPersistence(
      async (token) => {
        localStorage.setItem(STEWARD_TOKEN_KEY, token);
        newerLogin = beginStewardSessionRecovery(STEWARD_TENANT_ID, "provider");
        client.installNewerTarget(
          "https://api.eliza.app/api/v1/eliza/agents/22222222-2222-4222-8222-222222222222",
          "account-b",
        );
      },
    );

    try {
      await applyRestoredConnection({
        restoredActiveServer: cloudServer(),
        clientRef: client,
      });
    } finally {
      unregisterPersistence();
      if (newerLogin) rejectStewardSessionRecovery(newerLogin);
    }

    expect(client.setToken).toHaveBeenLastCalledWith("account-b");
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(expired);
  });

  it("does NOT refresh a comfortably-valid stored JWT (instant restore)", async () => {
    const valid = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, valid);

    const client = fakeClient();
    await applyRestoredConnection({
      restoredActiveServer: cloudServer(),
      clientRef: client,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(client.setBaseUrl).toHaveBeenCalledWith(CLOUD_AGENT_API_BASE);
    expect(client.setToken).toHaveBeenCalledWith(valid);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(valid);
  });

  it("does NOT refresh an opaque (non-JWT) token; uses it as-is", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "opaque-device-code-token");

    const client = fakeClient();
    await applyRestoredConnection({
      restoredActiveServer: cloudServer(),
      clientRef: client,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(client.setToken).toHaveBeenCalledWith("opaque-device-code-token");
  });

  it("keeps a local-Docker paired bearer ahead of the Cloud Steward session", async () => {
    const steward = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, steward);
    const client = fakeClient();

    await applyRestoredConnection({
      restoredActiveServer: cloudServer({
        apiBase: "http://127.0.0.1:43123",
        accessToken: "paired-agent-token",
      }),
      clientRef: client,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(client.setBaseUrl).toHaveBeenCalledWith("http://127.0.0.1:43123");
    expect(client.setToken).toHaveBeenCalledWith("paired-agent-token");
  });

  it("never sends a Steward session to a tokenless loopback target", async () => {
    const steward = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, steward);
    const client = fakeClient();

    await applyRestoredConnection({
      restoredActiveServer: cloudServer({
        apiBase: "http://localhost:43123",
        accessToken: undefined,
      }),
      clientRef: client,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(client.setBaseUrl).toHaveBeenCalledWith("http://localhost:43123");
    expect(client.setToken).toHaveBeenCalledWith(null);
    expect(client.setToken).not.toHaveBeenCalledWith(steward);
  });

  it("leaves the session UNAUTHENTICATED and drops the shared selection when refresh fails", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(-60));
    savePersistedActiveServer(
      cloudServer({ accessToken: "expired-steward-token" }),
    );
    fetchMock.mockResolvedValue({ ok: false, json: async () => ({}) });

    const client = fakeClient();
    await applyRestoredConnection({
      // A normal persisted record mirrors the now-expired Steward bearer.
      restoredActiveServer: cloudServer({
        accessToken: "expired-steward-token",
      }),
      clientRef: client,
    });

    // Exactly one refresh attempt — no retry loop.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    // The dead credential is dropped and the client is left unauthenticated.
    expect(client.setToken).toHaveBeenLastCalledWith(null);
    expect(client.setBaseUrl).toHaveBeenLastCalledWith(null);
    expect(client.setToken).not.toHaveBeenLastCalledWith(
      "expired-steward-token",
    );
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(loadPersistedActiveServer()).toBeNull();
  });

  it("falls back to the provision-time token when refresh fails but the JWT is still (barely) alive", async () => {
    // 30s left → attempts refresh, but the token is not yet expired, so a
    // failed refresh keeps it rather than dropping to unauthenticated.
    const nearExpiry = makeJwt(30);
    localStorage.setItem(STEWARD_TOKEN_KEY, nearExpiry);
    fetchMock.mockResolvedValue({ ok: false, json: async () => ({}) });

    const client = fakeClient();
    await applyRestoredConnection({
      restoredActiveServer: cloudServer(),
      clientRef: client,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(client.setToken).toHaveBeenCalledWith(nearExpiry);
    // Still-alive token is retained for the useCloudState lifecycle refresh.
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(nearExpiry);
  });
});
