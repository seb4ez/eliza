/** Verifies shared→dedicated handoff firing on shared-agent completion through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * Regression for #15310 failure mode #3 and the #15901/#15902/#15903 landing
 * contract of `bindCloudAgent`. The handoff branch was once gated on
 * `selectedAgent.created`, so a re-login that REUSED an existing shared agent
 * (`created:false` — e.g. after a failed first run) never re-entered the
 * upgrade path and stranded the user on the shared adapter.
 *
 * Contract under test:
 *   - created:true                          → handoff fires (unchanged)
 *   - created:false, no pending marker      → handoff fires (#15310 #3)
 *   - created:false, marker for THIS agent  → handoff does NOT fire here —
 *     resumePendingCloudHandoff owns the interrupted-but-live migration and is
 *     invoked at the landing (it verifies the target and re-arms a fresh
 *     create itself when the target is dead); double-firing would provision a
 *     second dedicated agent.
 *   - created:false, marker for a DIFFERENT agent → the stale marker is
 *     cleared and a fresh handoff fires (#15902: a leftover marker must not
 *     suppress the upgrade path or pin the provisioning tile).
 *   - a reused agent that already OWNS a dedicated container (bridgeUrl set)
 *     never mints another dedicated target (#15902 run-2 class).
 *   - EVERY successful landing persists the durable completion flag
 *     (`eliza:first-run-complete`) headlessly (#15903).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  loadPendingCloudHandoff,
  savePendingCloudHandoff,
} from "../cloud/handoff/pending-handoff-store";
import type { FirstRunProfileDraft } from "./first-run";
import type { FirstRunFinishPorts } from "./first-run-finish";
import {
  bindCloudAgent,
  listOrAutoProvisionCloudAgent,
  readActiveCloudAgentId,
  runFirstRunFinish,
} from "./first-run-finish";

const SHARED_AGENT_BASE =
  "https://staging.elizacloud.ai/api/v1/eliza/agents/cad3c071";
const SELECTION_SUPERSEDED_MESSAGE =
  "Cloud agent setup was superseded by a newer login.";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

const clientMock = vi.hoisted(() => ({
  getPersonalSharedEliza: vi.fn(),
  ensurePersonalDedicatedEliza: vi.fn(),
  selectOrProvisionCloudAgent: vi.fn(),
  submitFirstRun: vi.fn(async () => {}),
  setBaseUrl: vi.fn(),
  setToken: vi.fn(),
  stageSessionTarget: vi.fn(),
  getBaseUrl: vi.fn(() => ""),
  createCloudCompatAgent: vi.fn(),
  startCloudAgentHandoff: vi.fn(),
  deleteSharedBridgeAgent: vi.fn(async () => ({ success: true })),
  getCloudCompatAgents: vi.fn(),
  getCloudStatus: vi.fn<
    () => Promise<{ connected: boolean; reason?: string } | null>
  >(async () => null),
  getRestAuthToken: vi.fn(() => null as string | null),
}));

const runCloudAgentHandoffMock = vi.hoisted(() => vi.fn());
const resumePendingCloudHandoffMock = vi.hoisted(() => vi.fn(() => true));
const savePersistedFirstRunCompleteMock = vi.hoisted(() => vi.fn());
const silentlyRepointToDedicatedMock = vi.hoisted(() => vi.fn());
const runAgentSessionRecoveryMock = vi.hoisted(() => vi.fn());
const removeAgentProfileMock = vi.hoisted(() => vi.fn());
const loadPersistedActiveServerMock = vi.hoisted(() =>
  vi.fn<() => { kind: string; id?: string } | null>(() => null),
);

vi.mock("../api", () => ({ client: clientMock }));

vi.mock("../cloud/handoff/silent-repoint", () => ({
  silentlyRepointToDedicated: silentlyRepointToDedicatedMock,
}));

vi.mock("../state/agent-session-recovery-runner", () => ({
  runAgentSessionRecovery: runAgentSessionRecoveryMock,
}));

vi.mock("../cloud/handoff/run-cloud-agent-handoff", () => ({
  runCloudAgentHandoff: runCloudAgentHandoffMock,
}));

vi.mock("../cloud/handoff/resume-pending-handoff", () => ({
  resumePendingCloudHandoff: resumePendingCloudHandoffMock,
}));

const bootConfigMock = vi.hoisted(() => ({
  cloudApiBase: "https://staging.elizacloud.ai",
  preferSharedCloudTier: true,
  autoUpgradeSharedToDedicated: false,
}));

vi.mock("../config/boot-config", () => ({
  getBootConfig: () => bootConfigMock,
}));

vi.mock("../state", () => ({
  addAgentProfile: vi.fn(() => ({ id: "profile-1" })),
  createPersistedActiveServer: vi.fn((v) => ({ label: "Eliza Cloud", ...v })),
  loadPersistedActiveServer: loadPersistedActiveServerMock,
  persistAgentProfileConnectionDurably: vi.fn(
    async (profile, _server, options) => {
      if ((await options?.finalize?.()) === false) return null;
      return {
        id: "profile-1",
        createdAt: "2026-08-30T00:00:00.000Z",
        ...profile,
      };
    },
  ),
  removeAgentProfile: removeAgentProfileMock,
  savePersistedActiveServer: vi.fn(),
  savePersistedFirstRunComplete: savePersistedFirstRunCompleteMock,
}));

vi.mock("./mobile-runtime-mode", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./mobile-runtime-mode")>()),
  persistMobileRuntimeModeForServerTarget: vi.fn(),
}));

function draft(): FirstRunProfileDraft {
  return {
    agentName: "Eliza",
    runtime: "cloud",
    localInference: "cloud-inference",
    remoteApiBase: "",
    remoteToken: "",
  };
}

function ports(): FirstRunFinishPorts {
  return {
    uiLanguage: "en",
    elizaCloudConnected: true,
    handleInteractiveCloudLogin: vi.fn(async () => {}),
    setRuntimeState: vi.fn(),
    setTab: vi.fn(),
    completeFirstRun: vi.fn(),
    onStatus: vi.fn(),
  };
}

function mockSelection(
  created: boolean,
  opts: {
    authority?: {
      isCurrent(): boolean;
      compensateIfSuperseded(): Promise<void>;
    };
    bridgeUrl?: string | null;
    requiresAgentPairing?: boolean;
  } = {},
): void {
  clientMock.selectOrProvisionCloudAgent.mockResolvedValue({
    agentId: "cad3c071",
    apiBase: SHARED_AGENT_BASE,
    bridgeUrl: opts.bridgeUrl ?? null,
    requiresAgentPairing: opts.requiresAgentPairing ?? false,
    created,
    ...(opts.authority ? { authority: opts.authority } : {}),
  });
}

function seedMarker(sharedAgentId: string): void {
  savePendingCloudHandoff({
    sharedAgentId,
    dedicatedAgentId: "dedicated-1",
    sharedApiBase: SHARED_AGENT_BASE,
    cloudApiBase: "https://staging.elizacloud.ai",
    startedAt: Date.now(),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  clientMock.stageSessionTarget.mockImplementation(({ baseUrl, token }) => ({
    publish: () => {
      clientMock.setBaseUrl(baseUrl);
      clientMock.setToken(token);
      return true;
    },
    restoreIfCurrent: () => true,
    clearIfCurrent: () => true,
  }));
  clientMock.getCloudStatus.mockResolvedValue(null);
  clientMock.getRestAuthToken.mockReturnValue(null);
  clientMock.getPersonalSharedEliza.mockResolvedValue({
    personalElizaId: "personal:00000000-0000-5000-8000-000000000001",
    agentId: "personal:00000000-0000-5000-8000-000000000001",
    activeAgentId: "personal:00000000-0000-5000-8000-000000000001",
    agentName: "Eliza",
    apiBase:
      "https://staging.elizacloud.ai/api/v1/eliza/agents/personal%3A00000000-0000-5000-8000-000000000001",
    runtime: "shared",
  });
  clientMock.ensurePersonalDedicatedEliza.mockResolvedValue({
    personalElizaId: "personal:00000000-0000-5000-8000-000000000001",
    agentId: "personal:00000000-0000-5000-8000-000000000001",
    activeAgentId: "00000000-0000-4000-8000-000000000020",
    agentName: "Eliza",
    apiBase: "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
    runtime: "dedicated",
  });
  // This suite's shared-first fixture has NO auto-upgrade (#18204).
  bootConfigMock.autoUpgradeSharedToDedicated = false;
});

afterEach(() => {
  window.localStorage.clear();
  vi.unstubAllGlobals();
});

describe("shared→dedicated handoff firing on shared-agent completion", () => {
  // These tests exercise the EXPLICIT opt-in path: autoUpgradeSharedToDedicated
  // is set to true so the background handoff fires. The default (false) path is
  // covered by the "shared-only onboarding" describe below.
  beforeEach(() => {
    bootConfigMock.autoUpgradeSharedToDedicated = true;
  });

  it("fires for a newly created shared agent (unchanged behavior)", async () => {
    mockSelection(true);
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("done");
    expect(runCloudAgentHandoffMock).toHaveBeenCalledTimes(1);
  });

  it("fires for a REUSED shared agent with no pending marker (#15310 #3)", async () => {
    mockSelection(false);
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("done");
    expect(runCloudAgentHandoffMock).toHaveBeenCalledTimes(1);
  });

  it("does NOT fire when a marker for THIS agent exists — the resume path is invoked instead", async () => {
    seedMarker("cad3c071");
    mockSelection(false);
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("done");
    expect(runCloudAgentHandoffMock).not.toHaveBeenCalled();
    // The interrupted migration is resumed AT the landing, not left for a
    // later boot's 404 path to notice (#15902).
    expect(resumePendingCloudHandoffMock).toHaveBeenCalledTimes(1);
    expect(loadPendingCloudHandoff()?.sharedAgentId).toBe("cad3c071");
  });

  it("clears a stale marker for a DIFFERENT agent and fires a fresh handoff (#15902)", async () => {
    seedMarker("some-other-shared-agent");
    mockSelection(false);
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("done");
    expect(loadPendingCloudHandoff()).toBeNull();
    expect(runCloudAgentHandoffMock).toHaveBeenCalledTimes(1);
    expect(resumePendingCloudHandoffMock).not.toHaveBeenCalled();
  });

  it("never mints another dedicated target for a reused agent that already owns one (bridgeUrl set)", async () => {
    mockSelection(false, { bridgeUrl: "https://cad3c071.elizacloud.ai" });
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("done");
    expect(runCloudAgentHandoffMock).not.toHaveBeenCalled();
    expect(clientMock.createCloudCompatAgent).not.toHaveBeenCalled();
  });

  it("conditionally removes a fresh dedicated target when login B wins during its create POST", async () => {
    let selectionCurrent = true;
    mockSelection(true, {
      authority: {
        isCurrent: () => selectionCurrent,
        compensateIfSuperseded: vi.fn(async () => {}),
      },
    });
    const handoffCapture: { work: (() => Promise<unknown>) | null } = {
      work: null,
    };
    runCloudAgentHandoffMock.mockImplementation(
      (_sharedAgentId, work: () => Promise<unknown>) => {
        handoffCapture.work = work;
      },
    );
    const createResponse = deferred<{
      success: true;
      created: true;
      data: {
        agentId: string;
        agentName: string;
        jobId: string;
        status: string;
        nodeId: null;
        message: string;
        createdAt: string;
        executionTier: "dedicated-always";
      };
    }>();
    clientMock.createCloudCompatAgent.mockReturnValue(createResponse.promise);
    const cleanupSpy = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ success: true }), {
          status: 202,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", cleanupSpy);

    await bindCloudAgent(draft(), "steward-token-a", {}, ports());
    expect(handoffCapture.work).not.toBeNull();
    const handoff = handoffCapture.work?.() ?? Promise.resolve();
    await vi.waitFor(() =>
      expect(clientMock.createCloudCompatAgent).toHaveBeenCalledWith(
        expect.objectContaining({
          forceCreate: true,
          validateAuthority: expect.any(Function),
        }),
      ),
    );
    selectionCurrent = false;
    createResponse.resolve({
      success: true,
      created: true,
      data: {
        agentId: "dedicated-account-a",
        agentName: "Eliza",
        jobId: "job-account-a",
        status: "pending",
        nodeId: null,
        message: "accepted",
        createdAt: "2026-08-30T05:00:00.000Z",
        executionTier: "dedicated-always",
      },
    });

    await expect(handoff).rejects.toThrow(SELECTION_SUPERSEDED_MESSAGE);
    expect(cleanupSpy).toHaveBeenCalledOnce();
    const [cleanupUrl, cleanupInit] = cleanupSpy.mock.calls[0] ?? [];
    expect(String(cleanupUrl)).toContain(
      "/api/v1/eliza/agents/dedicated-account-a",
    );
    expect(new Headers(cleanupInit?.headers).get("Authorization")).toBe(
      "Bearer steward-token-a",
    );
    expect(cleanupInit).toMatchObject({
      method: "DELETE",
      body: JSON.stringify({
        expectedAgentName: "Eliza",
        expectedCreatedAt: "2026-08-30T05:00:00.000Z",
        expectedExecutionTier: "dedicated-always",
      }),
    });
    expect(loadPendingCloudHandoff()).toBeNull();
    expect(clientMock.startCloudAgentHandoff).not.toHaveBeenCalled();
  });

  it.each([
    { created: false, createdAt: "2026-08-30T05:00:00.000Z" },
    { created: true, createdAt: null },
  ])(
    "never deletes a reused or incomplete dedicated create receipt (%o)",
    async ({ created, createdAt }) => {
      let selectionCurrent = true;
      mockSelection(true, {
        authority: {
          isCurrent: () => selectionCurrent,
          compensateIfSuperseded: vi.fn(async () => {}),
        },
      });
      const handoffCapture: { work: (() => Promise<unknown>) | null } = {
        work: null,
      };
      runCloudAgentHandoffMock.mockImplementation(
        (_sharedAgentId, work: () => Promise<unknown>) => {
          handoffCapture.work = work;
        },
      );
      clientMock.createCloudCompatAgent.mockImplementation(async () => {
        selectionCurrent = false;
        return {
          success: true,
          created,
          data: {
            agentId: "ambiguous-account-a",
            agentName: "Eliza",
            jobId: "",
            status: "pending",
            nodeId: null,
            message: "accepted",
            createdAt,
            executionTier: "dedicated-always",
          },
        };
      });
      const cleanupSpy = vi.fn();
      vi.stubGlobal("fetch", cleanupSpy);

      await bindCloudAgent(draft(), "steward-token-a", {}, ports());
      const handoff = handoffCapture.work?.() ?? Promise.resolve();
      await expect(handoff).rejects.toThrow(SELECTION_SUPERSEDED_MESSAGE);
      expect(cleanupSpy).not.toHaveBeenCalled();
      expect(loadPendingCloudHandoff()).toBeNull();
      expect(clientMock.startCloudAgentHandoff).not.toHaveBeenCalled();
    },
  );

  it("conditionally removes a fresh dedicated target when login B wins during the long handoff", async () => {
    let selectionCurrent = true;
    mockSelection(true, {
      authority: {
        isCurrent: () => selectionCurrent,
        compensateIfSuperseded: vi.fn(async () => {}),
      },
    });
    const handoffCapture: {
      validate: (() => boolean) | null;
      work: (() => Promise<unknown>) | null;
    } = { validate: null, work: null };
    runCloudAgentHandoffMock.mockImplementation(
      (
        _sharedAgentId,
        work: () => Promise<unknown>,
        _onSuccess: unknown,
        validate: () => boolean,
      ) => {
        handoffCapture.work = work;
        handoffCapture.validate = validate;
      },
    );
    clientMock.createCloudCompatAgent.mockResolvedValue({
      success: true,
      created: true,
      data: {
        agentId: "dedicated-account-a",
        agentName: "Eliza",
        jobId: "job-account-a",
        status: "pending",
        nodeId: null,
        message: "accepted",
        createdAt: "2026-08-30T05:00:00.000Z",
        executionTier: "dedicated-always",
      },
    });
    clientMock.startCloudAgentHandoff.mockImplementation(async (options) => {
      selectionCurrent = false;
      try {
        await options.onSwitch("https://dedicated-account-a.cloud.eliza.app");
        return { status: "switched", imported: 1 };
      } catch (error) {
        return {
          status: "failed",
          imported: 0,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    });
    const cleanupSpy = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ success: true }), {
          status: 202,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", cleanupSpy);

    await bindCloudAgent(draft(), "steward-token-a", {}, ports());
    expect(handoffCapture.work).not.toBeNull();
    expect(handoffCapture.validate?.()).toBe(true);
    const handoff = handoffCapture.work?.() ?? Promise.resolve();

    await expect(handoff).rejects.toThrow(SELECTION_SUPERSEDED_MESSAGE);
    expect(handoffCapture.validate?.()).toBe(false);
    expect(clientMock.startCloudAgentHandoff).toHaveBeenCalledWith(
      expect.objectContaining({ validateAuthority: expect.any(Function) }),
    );
    expect(silentlyRepointToDedicatedMock).not.toHaveBeenCalled();
    expect(cleanupSpy).toHaveBeenCalledOnce();
    expect(loadPendingCloudHandoff()).toBeNull();
  });
});

describe("shared-only onboarding: no billed dedicated mutation without opt-in (#18204)", () => {
  // This describe uses the suite's explicit preferSharedCloudTier: true fixture
  // with autoUpgradeSharedToDedicated: false (restored by the top-level
  // beforeEach). No background dedicated create may fire on this path — the
  // user stays on the shared agent until they explicitly choose an upgrade
  // through Settings (#15355 confirmation flow).

  it("does NOT fire the handoff for a newly created shared agent", async () => {
    mockSelection(true);
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("done");
    expect(runCloudAgentHandoffMock).not.toHaveBeenCalled();
    expect(clientMock.createCloudCompatAgent).not.toHaveBeenCalled();
  });

  it("does NOT fire the handoff for a reused shared agent with no pending marker", async () => {
    mockSelection(false);
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("done");
    expect(runCloudAgentHandoffMock).not.toHaveBeenCalled();
    expect(clientMock.createCloudCompatAgent).not.toHaveBeenCalled();
  });

  it("does NOT fire the handoff when a stale marker for a different agent exists", async () => {
    seedMarker("some-other-shared-agent");
    mockSelection(false);
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("done");
    expect(runCloudAgentHandoffMock).not.toHaveBeenCalled();
    expect(clientMock.createCloudCompatAgent).not.toHaveBeenCalled();
    // The stale marker is still cleared — it just does not trigger a fresh
    // dedicated mutation without explicit opt-in.
    expect(loadPendingCloudHandoff()).toBeNull();
  });
});

describe("durable first-run completion at the landing (#15903)", () => {
  it("persists eliza:first-run-complete on the fresh-provision landing", async () => {
    mockSelection(true);
    await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(savePersistedFirstRunCompleteMock).toHaveBeenCalledWith(true);
  });

  it("persists eliza:first-run-complete on the returning-account reuse landing", async () => {
    mockSelection(false, { bridgeUrl: "https://cad3c071.elizacloud.ai" });
    const p = ports();
    await bindCloudAgent(draft(), "steward-token", {}, p);
    // The headless persist must not depend on the conductor's completion
    // callback chain — it fires before/with completeFirstRun.
    expect(savePersistedFirstRunCompleteMock).toHaveBeenCalledWith(true);
    expect(p.completeFirstRun).toHaveBeenCalledWith("chat");
  });

  it("persists eliza:first-run-complete before the pair relay unloads the session (navigate mode)", async () => {
    mockSelection(false, { requiresAgentPairing: true });
    runAgentSessionRecoveryMock.mockResolvedValueOnce({
      ok: true,
      mode: "navigate",
    });
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("handoff-started");
    expect(savePersistedFirstRunCompleteMock).toHaveBeenCalledWith(true);
  });

  it("persists eliza:first-run-complete and completes in-process when pairing resolves without a redirect", async () => {
    mockSelection(false, { requiresAgentPairing: true });
    runAgentSessionRecoveryMock.mockResolvedValueOnce({
      ok: true,
      mode: "in-process",
    });
    const p = ports();
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, p);
    expect(outcome.kind).toBe("done");
    expect(savePersistedFirstRunCompleteMock).toHaveBeenCalledWith(true);
    expect(p.completeFirstRun).toHaveBeenCalledWith("chat");
  });

  it("does not persist completion when pairing itself fails", async () => {
    mockSelection(false, { requiresAgentPairing: true });
    runAgentSessionRecoveryMock.mockResolvedValueOnce({
      ok: false,
      message: "device rejected pairing",
    });
    const outcome = await bindCloudAgent(draft(), "steward-token", {}, ports());
    expect(outcome.kind).toBe("error");
    expect(savePersistedFirstRunCompleteMock).not.toHaveBeenCalled();
    // Ordinary first-run pairing has NOT proven any existing pair bearer
    // stale, so it must never opt into the runner's stale-credential purge —
    // a Steward-mint refusal here says nothing about persisted agent
    // credentials and must not destroy them (#16666).
    const runnerDeps = runAgentSessionRecoveryMock.mock.calls.at(-1)?.[0] as {
      clearStalePairCredentials?: unknown;
    };
    expect(runnerDeps.clearStalePairCredentials).toBeUndefined();
  });
});

describe("readActiveCloudAgentId", () => {
  it("returns null when no active server is persisted", () => {
    loadPersistedActiveServerMock.mockReturnValueOnce(null);
    expect(readActiveCloudAgentId()).toBeNull();
  });

  it("returns null for a non-cloud active server", () => {
    loadPersistedActiveServerMock.mockReturnValueOnce({
      kind: "local",
      id: "local:1",
    });
    expect(readActiveCloudAgentId()).toBeNull();
  });

  it("extracts the agent id from a cloud:<id> active server", () => {
    loadPersistedActiveServerMock.mockReturnValueOnce({
      kind: "cloud",
      id: "cloud:cad3c071",
    });
    expect(readActiveCloudAgentId()).toBe("cad3c071");
  });

  it("rejects a malformed id containing a slash", () => {
    loadPersistedActiveServerMock.mockReturnValueOnce({
      kind: "cloud",
      id: "cloud:cad3c071/extra",
    });
    expect(readActiveCloudAgentId()).toBeNull();
  });
});

describe("listOrAutoProvisionCloudAgent / runFirstRunFinish routing", () => {
  beforeEach(() => {
    window.localStorage.setItem("steward_session_token", "steward-jwt");
  });

  it("routes Cloud first run through read-only personal resolution", async () => {
    const outcome = await runFirstRunFinish(
      { ...draft(), runtime: "cloud" },
      ports(),
    );
    expect(outcome.kind).toBe("done");
    expect(clientMock.getPersonalSharedEliza).toHaveBeenCalledWith(
      expect.objectContaining({
        cloudApiBase: "https://staging.elizacloud.ai",
        authToken: "steward-jwt",
      }),
    );
    expect(clientMock.ensurePersonalDedicatedEliza).not.toHaveBeenCalled();
    expect(clientMock.getCloudCompatAgents).not.toHaveBeenCalled();
    expect(clientMock.selectOrProvisionCloudAgent).not.toHaveBeenCalled();
  });

  it("surfaces personal identity failure without provisioning a fallback", async () => {
    clientMock.getPersonalSharedEliza.mockRejectedValueOnce(
      new Error("identity unavailable"),
    );
    await expect(
      listOrAutoProvisionCloudAgent(draft(), ports()),
    ).rejects.toThrow("identity unavailable");
    expect(clientMock.getCloudCompatAgents).not.toHaveBeenCalled();
    expect(clientMock.selectOrProvisionCloudAgent).not.toHaveBeenCalled();
  });

  it("requires cloud login when no auth token is available", async () => {
    window.localStorage.clear();
    const p = ports();
    p.elizaCloudConnected = false;
    const outcome = await listOrAutoProvisionCloudAgent(draft(), p);
    expect(outcome.kind).toBe("needs-cloud-login");
  });

  it("requires renderer auth when the server is connected but has no client token", async () => {
    window.localStorage.clear();
    const p = ports();
    p.handleInteractiveCloudLogin = vi.fn(async () => {
      window.localStorage.setItem(
        "steward_session_token",
        "fresh-client-token",
      );
    });

    const outcome = await listOrAutoProvisionCloudAgent(draft(), p);

    expect(p.handleInteractiveCloudLogin).toHaveBeenCalledWith({
      requireClientAuth: true,
    });
    expect(outcome.kind).toBe("done");
    expect(clientMock.getPersonalSharedEliza).toHaveBeenCalledWith(
      expect.objectContaining({ authToken: "fresh-client-token" }),
    );
    expect(clientMock.ensurePersonalDedicatedEliza).not.toHaveBeenCalled();
    expect(clientMock.selectOrProvisionCloudAgent).not.toHaveBeenCalled();
  });

  it("does not list or provision when required client auth returns no token", async () => {
    window.localStorage.clear();
    const p = ports();

    const outcome = await listOrAutoProvisionCloudAgent(draft(), p);

    expect(p.handleInteractiveCloudLogin).toHaveBeenCalledWith({
      requireClientAuth: true,
    });
    expect(outcome.kind).toBe("needs-cloud-login");
    expect(clientMock.getPersonalSharedEliza).not.toHaveBeenCalled();
    expect(clientMock.ensurePersonalDedicatedEliza).not.toHaveBeenCalled();
    expect(clientMock.selectOrProvisionCloudAgent).not.toHaveBeenCalled();
  });
});
