/** Verifies cloud restore routes the client without waiting on the Steward refresh through the package's configured test harness. */
// @vitest-environment jsdom
//
// Boot parallelization of the restoring-session phase: (1) a cloud restore
// derives a missing per-agent base synchronously from the persisted id and
// routes the client while the Steward-token refresh round-trip is still in
// flight (client mutations still land base → token), and (2) a desktop local
// restore issues ONE runtime-mode RPC shared by the agent-autostart gate and
// the embedded-local target reclassification.
// Real restore module under test; only the network / desktop-bridge
// boundaries are stubbed.

import {
  readStoredStewardToken,
  STEWARD_ACTIVE_SCOPE_KEY,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { client } from "../api";
import {
  beginStewardSessionRecovery,
  rejectStewardSessionRecovery,
} from "../cloud/lib/steward-session-recovery-marker";
import {
  DEFAULT_BOOT_CONFIG,
  setBootConfig,
} from "../config/boot-config-store";
import type { PersistedActiveServer } from "./persistence";
import {
  clearPersistedActiveServer,
  loadPersistedActiveServer,
  savePersistedActiveServer,
  savePersistedFirstRunComplete,
} from "./persistence";
import {
  applyRestoredConnection,
  type RestoringSessionDeps,
  reconcileMobileRestoredActiveServer,
  runRestoringSession,
} from "./startup-phase-restore";

const STEWARD_TOKEN_KEY = "steward_session_token";
const AGENT_ID = "11111111-1111-4111-8111-111111111111";
const SHARED_AGENT_ID = "22222222-2222-4222-8222-222222222222";
const STAGING_AGENT_ID = "33333333-3333-4333-8333-333333333333";

function failWindowStorageEnumeration(): ReturnType<typeof vi.spyOn> {
  let methodOwner: object | null = window.localStorage;
  while (methodOwner && !Object.hasOwn(methodOwner, "key")) {
    methodOwner = Object.getPrototypeOf(methodOwner) as object | null;
  }
  if (!methodOwner) throw new Error("jsdom Storage.key owner was not found");
  return vi
    .spyOn(methodOwner as Pick<Storage, "key">, "key")
    .mockImplementation(() => {
      throw new Error("recovery enumeration unavailable");
    });
}

/** Build a minimal (unsigned) JWT whose payload carries the given `exp`. */
function makeJwt(expSecondsFromNow: number): string {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "none", typ: "JWT" })}.${enc({
    exp: Math.floor(Date.now() / 1000) + expSecondsFromNow,
  })}.sig`;
}

type BridgeRpcOptions = { rpcMethod?: string };
type BridgeRpcResult =
  | { status: "timeout" }
  | { status: "ok"; value: { mode?: string } };

const bridgeMock = vi.hoisted(() => ({
  getBackendStartupTimeoutMs: vi.fn(() => 180_000),
  invokeDesktopBridgeRequestWithTimeout: vi.fn(
    async (_options: { rpcMethod?: string }): Promise<BridgeRpcResult> => ({
      status: "timeout",
    }),
  ),
  isElectrobunRuntime: vi.fn(() => true),
  scanProviderCredentials: vi.fn(async () => []),
}));

const firstRunBootstrapMock = vi.hoisted(() => ({
  detectExistingFirstRunConnection: vi.fn(async () => null),
}));

vi.mock("../bridge", () => bridgeMock);
vi.mock("./first-run-bootstrap", () => firstRunBootstrapMock);

function makeDeps(): RestoringSessionDeps {
  return {
    setStartupError: vi.fn(),
    setAuthRequired: vi.fn(),
    setConnected: vi.fn(),
    setFirstRunOptions: vi.fn(),
    setFirstRunComplete: vi.fn(),
    setFirstRunLoading: vi.fn(),
    firstRunCompletionCommittedRef: { current: false },
    uiLanguage: "en",
  };
}

function fakeClientWithStagedAuthority() {
  const base = { setBaseUrl: vi.fn(), setToken: vi.fn() };
  let revision = 0;
  const stageSessionTarget = vi.fn(
    (target: { baseUrl: string; token: string | null }) => {
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
        isCurrent: vi.fn(() => live && revision === installedRevision),
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

describe("cloud restore routes the client without waiting on the Steward refresh", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  const realFetch = globalThis.fetch;
  const realLocation = window.location;
  const pendingRequests: Array<{
    url: string;
    init?: RequestInit;
    resolve: (r: Response) => void;
  }> = [];

  beforeEach(() => {
    localStorage.clear();
    window.localStorage.clear();
    setBootConfig(DEFAULT_BOOT_CONFIG);
    pendingRequests.length = 0;
    fetchMock = vi.fn(
      (input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((resolve) => {
          pendingRequests.push({
            url:
              typeof input === "string"
                ? input
                : input instanceof URL
                  ? input.href
                  : input.url,
            init,
            resolve,
          });
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    vi.useRealTimers();
    globalThis.fetch = realFetch;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: realLocation,
    });
    setBootConfig(DEFAULT_BOOT_CONFIG);
    localStorage.clear();
    window.localStorage.clear();
    vi.restoreAllMocks();
  });

  it("clears the inherited credential before routing while Steward refresh is in flight", async () => {
    // A near-expiry stored JWT forces the refresh POST…
    const nearExpiry = makeJwt(30);
    localStorage.setItem(STEWARD_TOKEN_KEY, nearExpiry);
    const fresh = makeJwt(3600);
    // …and a MISSING apiBase forces the backfill, which derives the dedicated
    // `<agentId>.cloud.eliza.app` base purely from the persisted id.
    const restored: PersistedActiveServer = {
      id: `cloud:${AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
    };

    const clientRef = { setBaseUrl: vi.fn(), setToken: vi.fn() };
    const done = applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef,
    });

    // The startup-latency contract keeps base routing outside the refresh
    // round-trip, but the selected record's known token must replace any old
    // live bearer before that base becomes observable.
    await vi.waitFor(() => {
      expect(
        pendingRequests.some((r) => r.url.includes("steward-refresh")),
      ).toBe(true);
      expect(clientRef.setBaseUrl).toHaveBeenCalledTimes(1);
    });
    // The backfill is derivation-only: the refresh POST is the sole network
    // round-trip in the whole cloud restore (no agent lookup to wait behind).
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(clientRef.setToken).toHaveBeenCalledTimes(2);
    expect(clientRef.setToken).toHaveBeenNthCalledWith(1, null);
    expect(clientRef.setToken).toHaveBeenLastCalledWith(nearExpiry);
    expect(clientRef.setBaseUrl).toHaveBeenLastCalledWith(
      `https://${AGENT_ID}.cloud.eliza.app`,
    );
    expect(clientRef.setToken.mock.invocationCallOrder[0]).toBeLessThan(
      clientRef.setBaseUrl.mock.invocationCallOrder[0] as number,
    );
    expect(clientRef.setBaseUrl.mock.invocationCallOrder[0]).toBeLessThan(
      clientRef.setToken.mock.invocationCallOrder[1] as number,
    );

    // Settle the refresh; the restore completes with the fresh token.
    for (const req of pendingRequests) {
      req.resolve({
        ok: true,
        status: 200,
        json: async () => ({ token: fresh }),
      } as unknown as Response);
    }
    await done;

    // Terminal state replaces the provisional credential with the refreshed
    // Steward token without re-pointing the already safe base.
    expect(clientRef.setBaseUrl).toHaveBeenCalledTimes(1);
    expect(clientRef.setToken).toHaveBeenLastCalledWith(fresh);
  });

  it("does not publish, probe, or restore account A while cold-start recovery B is unresolved", async () => {
    const accountA = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, accountA);
    const sharedApiBase = `https://api.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`;
    savePersistedActiveServer({
      id: `cloud:${SHARED_AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: sharedApiBase,
      accessToken: accountA,
    });
    savePersistedFirstRunComplete(true);
    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    const dispatch = vi.fn();
    const ctxRef: { current: null } = { current: null };

    try {
      await runRestoringSession(makeDeps(), dispatch, ctxRef, {
        current: false,
      });

      expect(fetchMock).not.toHaveBeenCalled();
      expect(pendingRequests).toHaveLength(0);
      expect(dispatch).toHaveBeenCalledWith({
        type: "NO_SESSION",
        hadPriorFirstRun: false,
      });
      expect(dispatch).not.toHaveBeenCalledWith(
        expect.objectContaining({ type: "SESSION_RESTORED" }),
      );
      expect(ctxRef.current).toBeNull();
      expect(readStoredStewardToken()).toBe(accountA);
    } finally {
      rejectStewardSessionRecovery(loginB);
    }
  });

  it("does not copy raw account A into the first-run client while recovery B owns an invalid saved target", async () => {
    const accountA = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, accountA);
    savePersistedActiveServer({
      id: "cloud:https://api.elizacloud.ai",
      kind: "cloud",
      label: "Eliza Cloud",
      accessToken: accountA,
    });
    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    const stageTarget = vi.spyOn(client, "stageSessionTarget");
    const setToken = vi.spyOn(client, "setToken");

    try {
      await runRestoringSession(
        makeDeps(),
        vi.fn(),
        { current: null },
        { current: false },
      );

      expect(stageTarget).not.toHaveBeenCalled();
      expect(setToken).not.toHaveBeenCalledWith(accountA);
      expect(fetchMock).not.toHaveBeenCalled();
      expect(readStoredStewardToken()).toBe(accountA);
    } finally {
      rejectStewardSessionRecovery(loginB);
    }
  });

  it("quarantines a native owner key before publication when recovery B is already pending", async () => {
    const nativeOwnerKey = "eliza_native-owner-key";
    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    const clientRef = fakeClientWithStagedAuthority();

    try {
      const result = await applyRestoredConnection({
        restoredActiveServer: {
          id: `cloud:${AGENT_ID}`,
          kind: "cloud",
          label: "Eliza Cloud",
          apiBase: `https://${AGENT_ID}.cloud.eliza.app`,
          accessToken: nativeOwnerKey,
        },
        clientRef,
      });

      expect(result.status).toBe("steward-recovery-pending");
      expect(clientRef.stageSessionTarget).not.toHaveBeenCalled();
      expect(clientRef.setToken).not.toHaveBeenCalledWith(nativeOwnerKey);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      rejectStewardSessionRecovery(loginB);
    }
  });

  it("quarantines a native owner key when recovery storage is unavailable", async () => {
    const nativeOwnerKey = "eliza_native-owner-key";
    window.localStorage.setItem("unrelated-startup-fixture", "1");
    // jsdom may return a fresh Storage wrapper for each localStorage access.
    // Patch the realm's shared prototype so the production read cannot escape
    // the simulated enumeration failure through a different wrapper instance.
    const storageKeySpy = failWindowStorageEnumeration();
    const clientRef = fakeClientWithStagedAuthority();

    const result = await applyRestoredConnection({
      restoredActiveServer: {
        id: `cloud:${AGENT_ID}`,
        kind: "cloud",
        label: "Eliza Cloud",
        apiBase: `https://${AGENT_ID}.cloud.eliza.app`,
        accessToken: nativeOwnerKey,
      },
      clientRef,
    });

    expect(storageKeySpy).toHaveBeenCalled();
    expect(result.status).toBe("steward-recovery-pending");
    expect(clientRef.stageSessionTarget).not.toHaveBeenCalled();
    expect(clientRef.setToken).not.toHaveBeenCalledWith(nativeOwnerKey);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not let native owner restore A clear a newer same-tab target B", async () => {
    const nativeOwnerKey = "eliza_native-owner-key";
    const clientRef = fakeClientWithStagedAuthority();
    const restore = applyRestoredConnection({
      restoredActiveServer: {
        id: `cloud:${AGENT_ID}`,
        kind: "cloud",
        label: "Eliza Cloud",
        apiBase: `https://${AGENT_ID}.cloud.eliza.app`,
        accessToken: nativeOwnerKey,
      },
      clientRef,
    });
    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    clientRef.installNewerTarget(
      `https://api.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`,
      "account-b",
    );

    try {
      const result = await restore;

      expect(result.status).toBe("steward-recovery-pending");
      expect(clientRef.setToken).toHaveBeenLastCalledWith("account-b");
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      rejectStewardSessionRecovery(loginB);
    }
  });

  it("fences an in-flight native owner tier repair when recovery B starts", async () => {
    const nativeOwnerKey = "eliza_native-owner-key";
    const dedicatedApiBase = `https://${AGENT_ID}.cloud.eliza.app`;
    const restored: PersistedActiveServer = {
      id: `cloud:${AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: dedicatedApiBase,
      accessToken: nativeOwnerKey,
    };
    savePersistedActiveServer(restored);
    const clientRef = fakeClientWithStagedAuthority();
    const result = await applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef,
    });
    if (result.status !== "applied") {
      throw new Error("native owner restore was unexpectedly quarantined");
    }
    await vi.waitFor(() => expect(pendingRequests).toHaveLength(1));

    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    clientRef.installNewerTarget(
      `https://api.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`,
      "account-b",
    );
    try {
      pendingRequests[0].resolve({
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          data: { executionTier: "shared" },
        }),
      } as Response);
      await vi.waitFor(() => expect(result.authority.isCurrent()).toBe(false));
      for (let index = 0; index < 5; index += 1) await Promise.resolve();

      expect(clientRef.setToken).toHaveBeenLastCalledWith("account-b");
      expect(loadPersistedActiveServer()).toEqual(restored);
    } finally {
      rejectStewardSessionRecovery(loginB);
    }
  });

  it("keeps a real staged agent bearer current while its owner-key tier lookup is fenced", async () => {
    const nativeOwnerKey = "eliza_native-owner-key";
    const agentBearer = "dedicated-agent-bearer";
    const dedicatedApiBase = `https://${AGENT_ID}.cloud.eliza.app`;
    const restored: PersistedActiveServer = {
      id: `cloud:${AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: dedicatedApiBase,
      accessToken: agentBearer,
    };
    client.setBaseUrl(null, { persist: false });
    client.setToken(null);
    setBootConfig({ ...DEFAULT_BOOT_CONFIG, apiToken: nativeOwnerKey });
    savePersistedActiveServer(restored);

    const result = await applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef: client,
    });
    if (result.status !== "applied") {
      throw new Error("real native owner restore was unexpectedly quarantined");
    }
    await vi.waitFor(() => expect(pendingRequests).toHaveLength(1));
    expect(client.getBaseUrl()).toBe(dedicatedApiBase);
    expect(client.getRestAuthToken()).toBe(agentBearer);
    expect(result.authority.isCurrent()).toBe(true);
    expect(pendingRequests[0].init).toEqual(
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: `Bearer ${nativeOwnerKey}`,
        }),
      }),
    );

    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    const accountBBase = `https://api.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`;
    const accountBTarget = client.installSessionTarget(
      { baseUrl: accountBBase, token: "account-b" },
      { persist: false },
    );
    try {
      expect(accountBTarget?.isCurrent()).toBe(true);
      pendingRequests[0].resolve({
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          data: { executionTier: "shared" },
        }),
      } as Response);
      for (let index = 0; index < 8; index += 1) await Promise.resolve();

      expect(result.authority.isCurrent()).toBe(false);
      expect(accountBTarget?.isCurrent()).toBe(true);
      expect(client.getBaseUrl()).toBe(accountBBase);
      expect(client.getRestAuthToken()).toBe("account-b");
      expect(loadPersistedActiveServer()).toEqual(restored);
    } finally {
      rejectStewardSessionRecovery(loginB);
      client.setBaseUrl(null, { persist: false });
      client.setToken(null);
    }
  });

  it("retires restore A and its tier repair when B reinstalls the same account and agent target", async () => {
    const baseA = `https://${AGENT_ID}.cloud.eliza.app`;
    const tokenA = "same-agent-bearer";
    const stewardToken = makeJwt(3_600);
    const restored: PersistedActiveServer = {
      id: `cloud:${AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: baseA,
      accessToken: tokenA,
    };
    localStorage.setItem(STEWARD_TOKEN_KEY, stewardToken);
    client.setBaseUrl(null, { persist: false });
    client.setToken(null);
    savePersistedActiveServer(restored);

    try {
      const result = await applyRestoredConnection({
        restoredActiveServer: restored,
        clientRef: client,
      });
      if (result.status !== "applied") {
        throw new Error(
          "independent agent restore was unexpectedly quarantined",
        );
      }
      expect(result.authority.isCurrent()).toBe(true);
      await vi.waitFor(() => expect(pendingRequests).toHaveLength(1));

      // B can legitimately choose the same account, agent and token. Its
      // target revision still supersedes A even though every value is equal.
      const targetB = client.installSessionTarget(
        { baseUrl: baseA, token: tokenA },
        { persist: false },
      );
      expect(targetB?.isCurrent()).toBe(true);
      expect(result.authority.isCurrent()).toBe(false);

      pendingRequests[0].resolve({
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          data: { executionTier: "shared" },
        }),
      } as Response);
      for (let index = 0; index < 8; index += 1) await Promise.resolve();

      expect(targetB?.isCurrent()).toBe(true);
      expect(client.getBaseUrl()).toBe(baseA);
      expect(client.getRestAuthToken()).toBe(tokenA);
      expect(loadPersistedActiveServer()).toEqual(restored);
    } finally {
      client.setBaseUrl(null, { persist: false });
      client.setToken(null);
    }
  });

  it("does not revive restore A after an A-to-B-to-A target value cycle", async () => {
    const baseA = `https://${AGENT_ID}.cloud.eliza.app`;
    const tokenA = "agent-a-bearer";
    const restored: PersistedActiveServer = {
      id: `cloud:${AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: baseA,
      accessToken: tokenA,
    };
    client.setBaseUrl(null, { persist: false });
    client.setToken(null);

    try {
      const result = await applyRestoredConnection({
        restoredActiveServer: restored,
        clientRef: client,
      });
      if (result.status !== "applied") {
        throw new Error(
          "independent agent restore was unexpectedly quarantined",
        );
      }
      expect(result.authority.isCurrent()).toBe(true);

      client.installSessionTarget(
        {
          baseUrl: `https://${SHARED_AGENT_ID}.cloud.eliza.app`,
          token: "agent-b-bearer",
        },
        { persist: false },
      );
      const replacementA = client.installSessionTarget(
        { baseUrl: baseA, token: tokenA },
        { persist: false },
      );

      expect(replacementA?.isCurrent()).toBe(true);
      expect(client.getBaseUrl()).toBe(baseA);
      expect(client.getRestAuthToken()).toBe(tokenA);
      expect(result.authority.isCurrent()).toBe(false);
    } finally {
      client.setBaseUrl(null, { persist: false });
      client.setToken(null);
    }
  });

  it("bounds native owner-key rotation by the startup refresh timeout", async () => {
    vi.useFakeTimers();
    const nearExpiry = makeJwt(30);
    const nativeOwnerKey = "eliza_native-owner-key";
    localStorage.setItem(STEWARD_TOKEN_KEY, nearExpiry);
    const clientRef = fakeClientWithStagedAuthority();
    let settled = false;
    const restore = applyRestoredConnection({
      restoredActiveServer: {
        id: `cloud:${AGENT_ID}`,
        kind: "cloud",
        label: "Eliza Cloud",
        apiBase: `https://${AGENT_ID}.cloud.eliza.app`,
        accessToken: nativeOwnerKey,
      },
      clientRef,
    }).then((result) => {
      settled = true;
      return result;
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(pendingRequests).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(3_999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const result = await restore;

    expect(result.status).toBe("applied");
    expect(clientRef.setToken).toHaveBeenLastCalledWith(nativeOwnerKey);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();

    // Release the still-running transport after proving the publication fence
    // returned at 4s; even a late successful rotation must not reinstall A.
    const lateFresh = makeJwt(3_600);
    for (const request of pendingRequests) {
      request.resolve({
        ok: true,
        status: 200,
        json: async () => ({ token: lateFresh }),
      } as Response);
    }
    await vi.advanceTimersByTimeAsync(0);
    for (let index = 0; index < 5; index += 1) await Promise.resolve();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(clientRef.setToken).toHaveBeenLastCalledWith(nativeOwnerKey);
  });

  it("preserves a shared adapter with account authority regardless of the create default", async () => {
    const stewardToken = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, stewardToken);
    expect(localStorage.getItem(STEWARD_ACTIVE_SCOPE_KEY)).toBeNull();
    expect(readStoredStewardToken()).toBe(stewardToken);
    const sharedApiBase = `https://api.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`;
    const restored: PersistedActiveServer = {
      id: `cloud:${SHARED_AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: sharedApiBase,
      accessToken: "paired-token",
    };

    const dedicatedClient = { setBaseUrl: vi.fn(), setToken: vi.fn() };
    await applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef: dedicatedClient,
    });
    expect(dedicatedClient.setBaseUrl).toHaveBeenCalledWith(sharedApiBase);
    expect(dedicatedClient.setToken).toHaveBeenLastCalledWith(stewardToken);

    setBootConfig({ ...DEFAULT_BOOT_CONFIG, preferSharedCloudTier: true });
    const sharedClient = { setBaseUrl: vi.fn(), setToken: vi.fn() };
    await applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef: sharedClient,
    });
    expect(sharedClient.setBaseUrl).toHaveBeenCalledWith(sharedApiBase);
    expect(sharedClient.setToken).toHaveBeenLastCalledWith(stewardToken);
  });

  it("canonicalizes a legacy staging shared adapter on the staging control plane", async () => {
    setBootConfig({
      ...DEFAULT_BOOT_CONFIG,
      cloudApiBase: "https://staging.elizacloud.ai",
    });
    const stewardToken = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, stewardToken);
    expect(localStorage.getItem(STEWARD_ACTIVE_SCOPE_KEY)).toBeNull();
    expect(readStoredStewardToken()).toBe(stewardToken);
    const restored: PersistedActiveServer = {
      id: `cloud:${STAGING_AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: `https://api-staging.elizacloud.ai/api/v1/eliza/agents/${STAGING_AGENT_ID}`,
      accessToken: "paired-token",
    };
    const clientRef = fakeClientWithStagedAuthority();

    await applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef,
    });

    expect(clientRef.setBaseUrl).toHaveBeenCalledWith(
      `https://api-staging.eliza.app/api/v1/eliza/agents/${STAGING_AGENT_ID}`,
    );
    expect(clientRef.setToken).toHaveBeenLastCalledWith(stewardToken);
  });

  it("repairs a legacy dedicated-looking staging base when the owner record is shared", async () => {
    setBootConfig({
      ...DEFAULT_BOOT_CONFIG,
      cloudApiBase: "https://staging.elizacloud.ai",
    });
    const stewardToken = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, stewardToken);
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        data: { executionTier: "shared" },
      }),
    } as Response);
    const clientRef = fakeClientWithStagedAuthority();

    await applyRestoredConnection({
      restoredActiveServer: {
        id: `cloud:${SHARED_AGENT_ID}`,
        kind: "cloud",
        label: "Eliza Cloud",
        apiBase: `https://${SHARED_AGENT_ID}.elizacloud.ai`,
      },
      clientRef,
    });

    expect(fetchMock).toHaveBeenCalledWith(
      `https://api-staging.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`,
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: `Bearer ${stewardToken}`,
        }),
      }),
    );
    await vi.waitFor(() => {
      expect(clientRef.setBaseUrl).toHaveBeenLastCalledWith(
        `https://api-staging.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`,
      );
      expect(clientRef.setToken).toHaveBeenLastCalledWith(stewardToken);
    });
    expect(clientRef.setToken).toHaveBeenCalledWith(stewardToken);
  });

  it("uses the refreshed Steward token for legacy tier repair", async () => {
    bridgeMock.isElectrobunRuntime.mockReturnValue(false);
    const expired = makeJwt(-60);
    const fresh = makeJwt(3600);
    localStorage.setItem(STEWARD_TOKEN_KEY, expired);
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      if (url.includes("steward-refresh")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ token: fresh }),
        } as Response;
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          data: { executionTier: "shared" },
        }),
      } as Response;
    });
    const clientRef = fakeClientWithStagedAuthority();

    await applyRestoredConnection({
      restoredActiveServer: {
        id: `cloud:${SHARED_AGENT_ID}`,
        kind: "cloud",
        label: "Eliza Cloud",
        apiBase: `https://${SHARED_AGENT_ID}.elizacloud.ai`,
      },
      clientRef,
    });

    await vi.waitFor(() => {
      expect(clientRef.setBaseUrl).toHaveBeenLastCalledWith(
        `https://api.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`,
      );
    });
    const tierLookup = fetchMock.mock.calls.find(([input]) =>
      String(input).includes(`/api/v1/eliza/agents/${SHARED_AGENT_ID}`),
    );
    expect(tierLookup?.[1]).toEqual(
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: `Bearer ${fresh}`,
        }),
      }),
    );
    expect(tierLookup?.[1]).not.toEqual(
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: `Bearer ${expired}`,
        }),
      }),
    );
    expect(clientRef.setToken).toHaveBeenLastCalledWith(fresh);
  });

  it("keeps the native owner key through tier repair when Steward refresh fails", async () => {
    bridgeMock.isElectrobunRuntime.mockReturnValue(true);
    const nearExpiry = makeJwt(30);
    const nativeOwnerKey = "eliza_native-owner-key";
    localStorage.setItem(STEWARD_TOKEN_KEY, nearExpiry);
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      if (url.includes("steward-refresh")) {
        return {
          ok: false,
          status: 401,
          json: async () => ({}),
        } as Response;
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          data: { executionTier: "shared" },
        }),
      } as Response;
    });
    const clientRef = fakeClientWithStagedAuthority();

    await applyRestoredConnection({
      restoredActiveServer: {
        id: `cloud:${SHARED_AGENT_ID}`,
        kind: "cloud",
        label: "Eliza Cloud",
        apiBase: `https://${SHARED_AGENT_ID}.elizacloud.ai`,
        accessToken: nativeOwnerKey,
      },
      clientRef,
    });

    await vi.waitFor(() => {
      expect(clientRef.setBaseUrl).toHaveBeenLastCalledWith(
        `https://api.eliza.app/api/v1/eliza/agents/${SHARED_AGENT_ID}`,
      );
    });
    const tierLookup = fetchMock.mock.calls.find(([input]) =>
      String(input).includes(`/api/v1/eliza/agents/${SHARED_AGENT_ID}`),
    );
    expect(tierLookup?.[1]).toEqual(
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: `Bearer ${nativeOwnerKey}`,
        }),
      }),
    );
    expect(clientRef.setToken).toHaveBeenLastCalledWith(nativeOwnerKey);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("repairs a previously persisted production ingress in the staging app", async () => {
    setBootConfig({
      ...DEFAULT_BOOT_CONFIG,
      cloudApiBase: "https://staging.elizacloud.ai",
    });
    const restored: PersistedActiveServer = {
      id: `cloud:${STAGING_AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: `https://${STAGING_AGENT_ID}.elizacloud.ai`,
      accessToken: "paired-token",
    };
    const clientRef = { setBaseUrl: vi.fn(), setToken: vi.fn() };

    await applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef,
    });

    expect(clientRef.setBaseUrl).toHaveBeenCalledWith(
      `https://${STAGING_AGENT_ID}.cloud-staging.eliza.app`,
    );
    expect(clientRef.setToken).toHaveBeenCalledWith("paired-token");
  });

  it("keeps staging dedicated ingress when the page is staging but boot defaults to prod", async () => {
    // Regression: agent-subdomain bundles ship cloudApiBase=https://elizacloud.ai.
    // Restore must not rewrite *.staging.elizacloud.ai onto production.
    setBootConfig({
      ...DEFAULT_BOOT_CONFIG,
      cloudApiBase: "https://elizacloud.ai",
    });
    const stagingOrigin = `https://${STAGING_AGENT_ID}.staging.elizacloud.ai`;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: new URL(`${stagingOrigin}/`),
    });
    const restored: PersistedActiveServer = {
      id: `cloud:${STAGING_AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: stagingOrigin,
      accessToken: "paired-token",
    };
    const clientRef = { setBaseUrl: vi.fn(), setToken: vi.fn() };

    await applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef,
    });

    expect(clientRef.setBaseUrl).toHaveBeenCalledWith(stagingOrigin);
    expect(clientRef.setToken).toHaveBeenCalledWith("paired-token");
  });

  it("canonicalizes a legacy staging dedicated base under the prod boot default", async () => {
    setBootConfig({
      ...DEFAULT_BOOT_CONFIG,
      cloudApiBase: "https://elizacloud.ai",
    });
    const stagingOrigin = `https://${STAGING_AGENT_ID}.staging.elizacloud.ai`;
    const restored: PersistedActiveServer = {
      id: `cloud:${STAGING_AGENT_ID}`,
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: stagingOrigin,
      accessToken: "paired-token",
    };
    const clientRef = { setBaseUrl: vi.fn(), setToken: vi.fn() };

    await applyRestoredConnection({
      restoredActiveServer: restored,
      clientRef,
    });

    expect(clientRef.setBaseUrl).toHaveBeenCalledWith(
      `https://${STAGING_AGENT_ID}.cloud-staging.eliza.app`,
    );
    expect(clientRef.setToken).toHaveBeenCalledWith("paired-token");
  });
});

describe("desktop local restore shares one runtime-mode RPC", () => {
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    localStorage.clear();
    clearPersistedActiveServer();
    vi.clearAllMocks();
    bridgeMock.isElectrobunRuntime.mockReturnValue(true);
    bridgeMock.invokeDesktopBridgeRequestWithTimeout.mockResolvedValue({
      status: "timeout",
    });
    // The restore now primes /api/auth/me fire-and-forget; keep the test
    // hermetic (a 503 prime is discarded by design, so it is inert here).
    globalThis.fetch = vi.fn(
      async () =>
        ({
          ok: false,
          status: 503,
          json: async () => ({}),
        }) as unknown as Response,
    ) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    localStorage.clear();
  });

  function rpcCallCount(rpcMethod: string): number {
    return bridgeMock.invokeDesktopBridgeRequestWithTimeout.mock.calls.filter(
      (call) =>
        (call[0] as BridgeRpcOptions | undefined)?.rpcMethod === rpcMethod,
    ).length;
  }
  const modeCalls = () => rpcCallCount("desktopGetRuntimeMode");
  const agentStartCalls = () => rpcCallCount("agentStart");

  it("issues exactly one desktopGetRuntimeMode RPC for autostart gate + target resolution", async () => {
    savePersistedActiveServer({
      id: "local",
      kind: "local",
      label: "Local Agent",
    });
    const dispatch = vi.fn();

    await runRestoringSession(
      makeDeps(),
      dispatch,
      { current: null },
      {
        current: false,
      },
    );

    expect(modeCalls()).toBe(1);
    // Timeout ⇒ mode unknown ⇒ the autostart still fires (unchanged gate).
    expect(agentStartCalls()).toBe(1);
    expect(dispatch).toHaveBeenCalledWith({
      type: "SESSION_RESTORED",
      target: "embedded-local",
    });
  });

  it("keeps the semantics: non-local mode skips agent start AND reclassifies to remote-backend", async () => {
    savePersistedActiveServer({
      id: "local",
      kind: "local",
      label: "Local Agent",
    });
    bridgeMock.invokeDesktopBridgeRequestWithTimeout.mockImplementation(
      async (options: BridgeRpcOptions): Promise<BridgeRpcResult> => {
        if (options.rpcMethod === "desktopGetRuntimeMode") {
          return { status: "ok", value: { mode: "external" } };
        }
        return { status: "timeout" };
      },
    );
    const dispatch = vi.fn();

    await runRestoringSession(
      makeDeps(),
      dispatch,
      { current: null },
      {
        current: false,
      },
    );

    expect(modeCalls()).toBe(1);
    expect(agentStartCalls()).toBe(0);
    expect(dispatch).toHaveBeenCalledWith({
      type: "SESSION_RESTORED",
      target: "remote-backend",
    });
  });
});

describe("mobile restored target reconciliation", () => {
  it("drops a persisted local target after switching away from local mode", () => {
    expect(
      reconcileMobileRestoredActiveServer({
        server: { id: "local", kind: "local", label: "Local Agent" },
        mobileRuntimeMode: "cloud",
        platform: "android",
      }),
    ).toBeNull();
  });

  it("normalizes a legacy local target to the active platform IPC base", () => {
    expect(
      reconcileMobileRestoredActiveServer({
        server: { id: "local", kind: "local", label: "Local Agent" },
        mobileRuntimeMode: "local",
        platform: "android",
      }),
    ).toMatchObject({
      id: "local:android",
      apiBase: "eliza-local-agent://ipc",
    });
  });
});
