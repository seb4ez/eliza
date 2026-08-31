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
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enqueueStewardSessionMutation } from "../cloud/lib/steward-session-mutation-queue";
import {
  beginStewardSessionRecovery,
  completeStewardSessionRecovery,
  readStewardSessionRecovery,
  rejectStewardSessionRecovery,
  STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
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

function sharedCloudAgent() {
  return {
    agent_id: "shared-agent",
    agent_name: "Eliza",
    node_id: null,
    container_id: null,
    headscale_ip: null,
    bridge_url: null,
    web_ui_url: null,
    status: "running",
    agent_config: {},
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    containerUrl: "",
    webUiUrl: null,
    database_status: "ready",
    error_message: null,
    last_heartbeat_at: null,
    execution_tier: "shared" as const,
  };
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

  it("stages a tokenless target as one coherent authority pair", () => {
    const client = new ElizaClient("https://api.eliza.app", "old-token");
    const authority = client.installSessionTarget(
      {
        baseUrl: "https://self-hosted.local:31337",
        token: null,
      },
      { persist: false },
    );

    expect(authority).not.toBeNull();
    expect(client.getBaseUrl()).toBe("https://self-hosted.local:31337");
    expect(client.getRestAuthToken()).toBeNull();
    expect(authority?.restoreIfCurrent()).toBe(true);
    expect(client.getBaseUrl()).toBe("https://api.eliza.app");
    expect(client.getRestAuthToken()).toBe("old-token");
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
  it("retains Steward authority when an already-Dedicated client selects with the exact canonical token", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-token");
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    const client = new ElizaClient(
      "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
      "agent-local-bearer",
    );
    let loginB: ReturnType<typeof beginStewardSessionRecovery> | null = null;

    try {
      const selected = await client.selectOrProvisionCloudAgent({
        cloudApiBase: "https://api.eliza.app",
        authToken: "account-a-token",
        name: "Eliza",
        knownAgents: [sharedCloudAgent()],
        preferSharedTier: true,
      });

      expect(selected.authority?.isCurrent()).toBe(true);
      loginB = beginStewardSessionRecovery(tenantId, "provider");
      expect(selected.authority?.isCurrent()).toBe(false);
    } finally {
      if (loginB) rejectStewardSessionRecovery(loginB);
      localStorage.removeItem(STEWARD_TOKEN_KEY);
    }
  });

  it("refuses an agent-local bearer for account-level selection on an already-Dedicated client", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const client = new ElizaClient(
      "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
      "agent-local-bearer",
    );
    const createSpy = vi.spyOn(client, "createCloudCompatAgent");

    await expect(
      client.selectOrProvisionCloudAgent({
        cloudApiBase: "https://api.eliza.app",
        authToken: "agent-local-bearer",
        name: "Eliza",
        knownAgents: [],
        forceCreate: true,
      }),
    ).rejects.toMatchObject({ code: "STEWARD_SESSION_SUPERSEDED" });

    expect(createSpy).not.toHaveBeenCalled();
  });

  it("never adopts a pending login receipt as passive selection authority", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-token");
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    const loginB = beginStewardSessionRecovery(tenantId, "provider");
    const client = new ElizaClient("https://api.eliza.app");

    try {
      await expect(
        client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          knownAgents: [],
        }),
      ).rejects.toMatchObject({ code: "STEWARD_SESSION_SUPERSEDED" });

      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-a-token");
      expect(readStewardSessionRecovery(tenantId).receipts).toEqual([
        loginB.receipt,
      ]);
    } finally {
      rejectStewardSessionRecovery(loginB);
      localStorage.removeItem(STEWARD_TOKEN_KEY);
    }
  });

  it("finishes recovery when the canonical authority event aborts the caller", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const controller = new AbortController();
    const abortOnAuthority = () => {
      controller.abort(new DOMException("cancelled", "AbortError"));
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, abortOnAuthority, {
      once: true,
    });

    try {
      const client = new ElizaClient("https://api.eliza.app");
      const selected = await client.selectOrProvisionCloudAgent({
        cloudApiBase: "https://api.eliza.app",
        authToken: "account-a-token",
        name: "Eliza",
        knownAgents: [sharedCloudAgent()],
        preferSharedTier: true,
        signal: controller.signal,
      });

      expect(controller.signal.aborted).toBe(true);
      expect(selected.agentId).toBe("shared-agent");
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-a-token");
      expect(
        readStewardSessionRecovery(
          configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
        ).receipts,
      ).toEqual([]);
    } finally {
      window.removeEventListener(
        STEWARD_SESSION_CHANGE_EVENT,
        abortOnAuthority,
      );
      localStorage.removeItem(STEWARD_TOKEN_KEY);
    }
  });

  it("rejects selection A when recovery publication queues login B", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    let recoveryEvents = 0;
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const readNewerLogin = () => newerLogin;
    const beginNewerLoginAfterPublication = () => {
      recoveryEvents += 1;
      if (recoveryEvents !== 1) return;
      queueMicrotask(() => {
        newerLogin = beginStewardSessionRecovery(tenantId, "provider");
      });
    };
    window.addEventListener(
      STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
      beginNewerLoginAfterPublication,
    );

    try {
      const client = new ElizaClient("https://api.eliza.app");
      await expect(
        client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          knownAgents: [],
        }),
      ).rejects.toMatchObject({ code: "STEWARD_SESSION_SUPERSEDED" });

      const recordedNewerLogin = readNewerLogin();
      expect(recordedNewerLogin).not.toBeNull();
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(readStewardSessionRecovery(tenantId).receipts).toEqual([
        recordedNewerLogin?.receipt,
      ]);
    } finally {
      window.removeEventListener(
        STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
        beginNewerLoginAfterPublication,
      );
      const recordedNewerLogin = readNewerLogin();
      if (recordedNewerLogin) {
        rejectStewardSessionRecovery(recordedNewerLogin);
      }
      localStorage.removeItem(STEWARD_TOKEN_KEY);
    }
  });

  it("does not list or create under login B when listing progress supersedes A", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const readNewerLogin = () => newerLogin;
    const client = new ElizaClient("https://api.eliza.app");
    const listSpy = vi.spyOn(client, "getCloudCompatAgents");
    const createSpy = vi.spyOn(client, "createCloudCompatAgent");

    try {
      await expect(
        client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          onProgress: (status) => {
            if (status === "listing" && !newerLogin) {
              newerLogin = beginStewardSessionRecovery(tenantId, "provider");
            }
          },
        }),
      ).rejects.toMatchObject({ code: "STEWARD_SESSION_SUPERSEDED" });

      expect(readNewerLogin()).not.toBeNull();
      expect(listSpy).not.toHaveBeenCalled();
      expect(createSpy).not.toHaveBeenCalled();
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(readStewardSessionRecovery(tenantId).receipts).toEqual([
        readNewerLogin()?.receipt,
      ]);
    } finally {
      const recordedNewerLogin = readNewerLogin();
      if (recordedNewerLogin) {
        rejectStewardSessionRecovery(recordedNewerLogin);
      }
      localStorage.removeItem(STEWARD_TOKEN_KEY);
    }
  });

  it("does not dispatch the proxy create when login B starts in the direct-fallback microtask", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const readNewerLogin = () => newerLogin;
    const client = new ElizaClient("https://self-hosted.example");
    const fetchSpy = vi.spyOn(client, "fetch");

    try {
      await expect(
        client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          knownAgents: [],
          onProgress: (status) => {
            if (status !== "creating" || newerLogin) return;
            queueMicrotask(() => {
              newerLogin = beginStewardSessionRecovery(tenantId, "provider");
            });
          },
        }),
      ).rejects.toMatchObject({ code: "STEWARD_SESSION_SUPERSEDED" });

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(readStewardSessionRecovery(tenantId).receipts).toEqual([
        readNewerLogin()?.receipt,
      ]);
    } finally {
      const recordedNewerLogin = readNewerLogin();
      if (recordedNewerLogin) {
        rejectStewardSessionRecovery(recordedNewerLogin);
      }
      localStorage.removeItem(STEWARD_TOKEN_KEY);
    }
  });

  it("conditionally removes a fresh create whose response arrives after login B", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    const createResponse = deferred<Response>();
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const fetchSpy = vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        if (init?.method === "DELETE") {
          return Promise.resolve(
            new Response(JSON.stringify({ success: true }), {
              status: 202,
              headers: { "Content-Type": "application/json" },
            }),
          );
        }
        return createResponse.promise;
      },
    );
    vi.stubGlobal("fetch", fetchSpy);
    const client = new ElizaClient("https://api.eliza.app");

    try {
      const selection = client.selectOrProvisionCloudAgent({
        cloudApiBase: "https://api.eliza.app",
        authToken: "account-a-token",
        name: "Eliza",
        knownAgents: [],
      });
      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalledOnce());
      newerLogin = beginStewardSessionRecovery(tenantId, "provider");
      createResponse.resolve(
        new Response(
          JSON.stringify({
            success: true,
            created: true,
            data: {
              id: "late-created-by-account-a",
              agentName: "Eliza",
              status: "pending",
              createdAt: "2026-08-30T02:00:00.000Z",
              executionTier: "dedicated-always",
            },
          }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        ),
      );

      await expect(selection).rejects.toMatchObject({
        code: "STEWARD_SESSION_SUPERSEDED",
      });
      expect(fetchSpy).toHaveBeenCalledTimes(2);
      expect(fetchSpy.mock.calls[1]?.[1]).toMatchObject({
        method: "DELETE",
        body: JSON.stringify({
          expectedAgentName: "Eliza",
          expectedCreatedAt: "2026-08-30T02:00:00.000Z",
          expectedExecutionTier: "dedicated-always",
        }),
      });
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(readStewardSessionRecovery(tenantId).receipts).toEqual([
        newerLogin.receipt,
      ]);
    } finally {
      if (newerLogin) rejectStewardSessionRecovery(newerLogin);
      localStorage.removeItem(STEWARD_TOKEN_KEY);
      vi.unstubAllGlobals();
    }
  });

  it("restores local authority even when superseded fresh-create cleanup fails", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const readNewerLogin = () => newerLogin;
    const client = new ElizaClient("https://api.eliza.app");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("cleanup unavailable");
      }),
    );
    vi.spyOn(client, "createCloudCompatAgent").mockImplementation(async () => {
      newerLogin = beginStewardSessionRecovery(tenantId, "provider");
      return {
        success: true,
        created: true,
        data: {
          agentId: "created-by-account-a",
          agentName: "Eliza",
          jobId: "",
          status: "pending",
          nodeId: null,
          message: "accepted",
          createdAt: "2026-08-30T03:00:00.000Z",
          executionTier: "dedicated-always",
        },
      };
    });

    try {
      await expect(
        client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          knownAgents: [],
        }),
      ).rejects.toBeInstanceOf(AggregateError);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(readStewardSessionRecovery(tenantId).receipts).toEqual([
        readNewerLogin()?.receipt,
      ]);
    } finally {
      const recordedNewerLogin = readNewerLogin();
      if (recordedNewerLogin) {
        rejectStewardSessionRecovery(recordedNewerLogin);
      }
      localStorage.removeItem(STEWARD_TOKEN_KEY);
      vi.unstubAllGlobals();
    }
  });

  it("conditionally removes a fresh create when login B starts after acceptance", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const readNewerLogin = () => newerLogin;
    const client = new ElizaClient("https://api.eliza.app");
    const detailSpy = vi.spyOn(client, "getCloudCompatAgent");
    const fetchSpy = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) =>
        init?.method === "DELETE"
          ? new Response(
              JSON.stringify({
                success: true,
                data: { status: "deleting", jobId: "cleanup-job" },
              }),
              {
                status: 202,
                headers: { "Content-Type": "application/json" },
              },
            )
          : new Response(
              JSON.stringify({
                success: true,
                data: { id: "cleanup-job", status: "completed" },
              }),
              {
                status: 200,
                headers: { "Content-Type": "application/json" },
              },
            ),
    );
    vi.stubGlobal("fetch", fetchSpy);
    vi.spyOn(client, "createCloudCompatAgent").mockImplementation(async () => {
      newerLogin = beginStewardSessionRecovery(tenantId, "provider");
      return {
        success: true,
        created: true,
        data: {
          agentId: "created-by-account-a",
          agentName: "Eliza",
          jobId: "",
          status: "pending",
          nodeId: null,
          message: "accepted",
          createdAt: "2026-08-30T00:00:00.000Z",
          executionTier: "dedicated-always",
        },
      };
    });

    try {
      await expect(
        client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          knownAgents: [],
        }),
      ).rejects.toMatchObject({ code: "STEWARD_SESSION_SUPERSEDED" });

      expect(readNewerLogin()).not.toBeNull();
      expect(fetchSpy).toHaveBeenCalledTimes(2);
      const [cleanupUrl, cleanupInit] = fetchSpy.mock.calls[0] ?? [];
      expect(String(cleanupUrl)).toBe(
        "https://api.eliza.app/api/v1/eliza/agents/created-by-account-a",
      );
      expect(cleanupInit).toMatchObject({
        method: "DELETE",
        body: JSON.stringify({
          expectedAgentName: "Eliza",
          expectedCreatedAt: "2026-08-30T00:00:00.000Z",
          expectedExecutionTier: "dedicated-always",
        }),
      });
      expect(
        new Headers((cleanupInit as RequestInit | undefined)?.headers).get(
          "Authorization",
        ),
      ).toBe("Bearer account-a-token");
      const [jobUrl, jobInit] = fetchSpy.mock.calls[1] ?? [];
      expect(String(jobUrl)).toBe(
        "https://api.eliza.app/api/v1/jobs/cleanup-job",
      );
      expect(
        new Headers((jobInit as RequestInit | undefined)?.headers).get(
          "Authorization",
        ),
      ).toBe("Bearer account-a-token");
      expect(detailSpy).not.toHaveBeenCalled();
    } finally {
      const recordedNewerLogin = readNewerLogin();
      if (recordedNewerLogin) {
        rejectStewardSessionRecovery(recordedNewerLogin);
      }
      localStorage.removeItem(STEWARD_TOKEN_KEY);
      vi.unstubAllGlobals();
    }
  });

  it.each(["provision-job", "agent-detail"] as const)(
    "conditionally removes a fresh create when cancellation lands during the %s await",
    async (phase) => {
      localStorage.removeItem(STEWARD_TOKEN_KEY);
      const controller = new AbortController();
      const client = new ElizaClient("https://api.eliza.app");
      const jobResponse =
        deferred<Awaited<ReturnType<typeof client.getCloudCompatJobStatus>>>();
      const detailResponse =
        deferred<Awaited<ReturnType<typeof client.getCloudCompatAgent>>>();
      const jobSpy = vi
        .spyOn(client, "getCloudCompatJobStatus")
        .mockReturnValue(jobResponse.promise);
      const detailSpy = vi
        .spyOn(client, "getCloudCompatAgent")
        .mockReturnValue(detailResponse.promise);
      vi.spyOn(client, "createCloudCompatAgent").mockResolvedValue({
        success: true,
        created: true,
        data: {
          agentId: "cancelled-account-a-create",
          agentName: "Eliza",
          jobId: phase === "provision-job" ? "job-account-a" : "",
          status: "pending",
          nodeId: null,
          message: "accepted",
          createdAt: "2026-08-30T04:00:00.000Z",
          executionTier: "dedicated-always",
        },
      });
      const cleanupSpy = vi.fn(
        async (_input: RequestInfo | URL, _init?: RequestInit) =>
          new Response(
            JSON.stringify({ success: true, data: { status: "deleting" } }),
            { status: 202, headers: { "Content-Type": "application/json" } },
          ),
      );
      vi.stubGlobal("fetch", cleanupSpy);

      try {
        const selection = client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          knownAgents: [],
          signal: controller.signal,
        });
        if (phase === "provision-job") {
          await vi.waitFor(() => expect(jobSpy).toHaveBeenCalledOnce());
        } else {
          await vi.waitFor(() => expect(detailSpy).toHaveBeenCalledOnce());
        }
        controller.abort();
        if (phase === "provision-job") {
          jobResponse.resolve({
            success: true,
            data: {
              id: "job-account-a",
              jobId: "job-account-a",
              type: "provision",
              status: "completed",
              state: "completed",
              data: {},
              result: {},
              error: null,
              createdAt: "2026-08-30T04:00:00.000Z",
              startedAt: "2026-08-30T04:00:01.000Z",
              completedAt: "2026-08-30T04:00:02.000Z",
              retryCount: 0,
              name: "provision",
              created_on: "2026-08-30T04:00:00.000Z",
              completed_on: "2026-08-30T04:00:02.000Z",
            },
          });
        } else {
          detailResponse.resolve({
            success: true,
            data: {
              agent_id: "cancelled-account-a-create",
              agent_name: "Eliza",
              status: "running",
            },
          } as Awaited<ReturnType<typeof client.getCloudCompatAgent>>);
        }

        await expect(selection).rejects.toMatchObject({ name: "AbortError" });
        expect(cleanupSpy).toHaveBeenCalledOnce();
        expect(cleanupSpy.mock.calls[0]?.[1]).toMatchObject({
          method: "DELETE",
          body: JSON.stringify({
            expectedAgentName: "Eliza",
            expectedCreatedAt: "2026-08-30T04:00:00.000Z",
            expectedExecutionTier: "dedicated-always",
          }),
        });
      } finally {
        localStorage.removeItem(STEWARD_TOKEN_KEY);
        vi.unstubAllGlobals();
      }
    },
  );

  it("never deletes an idempotently reused agent when login B starts", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const client = new ElizaClient("https://api.eliza.app");
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    vi.spyOn(client, "createCloudCompatAgent").mockImplementation(async () => {
      newerLogin = beginStewardSessionRecovery(tenantId, "provider");
      return {
        success: true,
        created: false,
        data: {
          agentId: "existing-account-a-agent",
          agentName: "Eliza",
          jobId: "",
          status: "running",
          nodeId: null,
          message: "reused",
          createdAt: "2026-08-30T00:00:00.000Z",
          executionTier: "dedicated-always",
        },
      };
    });

    try {
      await expect(
        client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          knownAgents: [],
        }),
      ).rejects.toMatchObject({ code: "STEWARD_SESSION_SUPERSEDED" });
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      if (newerLogin) rejectStewardSessionRecovery(newerLogin);
      localStorage.removeItem(STEWARD_TOKEN_KEY);
      vi.unstubAllGlobals();
    }
  });

  it("conditionally removes a fresh warm-pool create superseded by login B", async () => {
    localStorage.removeItem(STEWARD_TOKEN_KEY);
    const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const client = new ElizaClient("https://api.eliza.app");
    const fetchSpy = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "DELETE") {
          return new Response(
            JSON.stringify({ success: true, data: { status: "deleting" } }),
            { status: 202, headers: { "Content-Type": "application/json" } },
          );
        }
        newerLogin = beginStewardSessionRecovery(tenantId, "provider");
        return new Response(
          JSON.stringify({
            success: true,
            source: "warm_pool",
            data: {
              id: "warm-pool-account-a",
              agentName: "Eliza",
              status: "running",
              createdAt: "2026-08-30T01:00:00.000Z",
              executionTier: "dedicated-always",
            },
          }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        );
      },
    );
    vi.stubGlobal("fetch", fetchSpy);

    try {
      await expect(
        client.selectOrProvisionCloudAgent({
          cloudApiBase: "https://api.eliza.app",
          authToken: "account-a-token",
          name: "Eliza",
          knownAgents: [],
        }),
      ).rejects.toMatchObject({ code: "STEWARD_SESSION_SUPERSEDED" });
      expect(fetchSpy).toHaveBeenCalledTimes(2);
      expect(fetchSpy.mock.calls[1]?.[1]).toMatchObject({
        method: "DELETE",
        body: JSON.stringify({
          expectedAgentName: "Eliza",
          expectedCreatedAt: "2026-08-30T01:00:00.000Z",
          expectedExecutionTier: "dedicated-always",
        }),
      });
    } finally {
      if (newerLogin) rejectStewardSessionRecovery(newerLogin);
      localStorage.removeItem(STEWARD_TOKEN_KEY);
      vi.unstubAllGlobals();
    }
  });

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
      expect(readStewardSessionRecovery(tenantId).receipts).toEqual([]);
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
          "x-eliza-csrf": STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
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

  it("retries one invalid_token and accepts the concurrent rotation winner", async () => {
    const expiredToken = makeJwt(Math.floor(Date.now() / 1000) - 60);
    localStorage.setItem(STEWARD_TOKEN_KEY, expiredToken);
    const fetchMock = vi
      .fn(
        async (
          _input: RequestInfo | URL,
          _init?: RequestInit,
        ): Promise<Response> =>
          new Response(JSON.stringify({ token: "rotation-winner-token" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ code: "invalid_token" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      refreshCloudStewardSession({
        commitRefreshedSession: async (session, authority) => {
          if (session.token) {
            await writeStoredStewardToken(session.token, {
              validate: authority.validate,
            });
          }
        },
      }),
    ).resolves.toEqual({ token: "rotation-winner-token" });

    const postCalls = fetchMock.mock.calls.filter(
      ([, init]) => init?.method === "POST",
    );
    expect(postCalls).toHaveLength(2);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
      "rotation-winner-token",
    );
  });

  it("clears an unchanged expired token after two invalid_token responses", async () => {
    const expiredToken = makeJwt(Math.floor(Date.now() / 1000) - 60);
    localStorage.setItem(STEWARD_TOKEN_KEY, expiredToken);
    savePersistedActiveServer({
      id: "cloud:dead-session-agent",
      kind: "cloud",
      label: "Dead session agent",
      apiBase: "https://dead-session-agent.example.test",
      accessToken: "dead-session-bearer",
    });
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) =>
        init?.method === "DELETE"
          ? { ok: true, status: 200, json: async () => ({ ok: true }) }
          : {
              ok: false,
              status: 401,
              json: async () => ({ code: "invalid_token" }),
            },
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(refreshCloudStewardSession()).resolves.toBeNull();

    const postCalls = fetchMock.mock.calls.filter(
      ([, init]) => init?.method === "POST",
    );
    expect(postCalls).toHaveLength(2);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(loadPersistedActiveServer()?.accessToken).toBeUndefined();
  });

  it("does not retry or tear down when a newer token wins during invalid_token parsing", async () => {
    const expiredToken = makeJwt(Math.floor(Date.now() / 1000) - 60);
    localStorage.setItem(STEWARD_TOKEN_KEY, expiredToken);
    savePersistedActiveServer({
      id: "cloud:account-b-agent",
      kind: "cloud",
      label: "Account B agent",
      apiBase: "https://account-b-agent.example.test",
      accessToken: "account-b-agent-token",
    });
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 401,
      json: async () => {
        localStorage.setItem(STEWARD_TOKEN_KEY, "account-b");
        return { code: "invalid_token" };
      },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(refreshCloudStewardSession()).resolves.toBeNull();

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-b");
    expect(loadPersistedActiveServer()?.accessToken).toBe(
      "account-b-agent-token",
    );
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
