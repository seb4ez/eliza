/**
 * @vitest-environment jsdom
 *
 * Tests for useAgentSessionRecovery (#15132): the dead-end -> recovering state
 * transition at the top-level auth gate.
 *
 * This is the regression guard for the reported bug: after a container upgrade,
 * an unauthenticated (`remote_auth_required`) state on a cloud-managed dedicated
 * agent with a valid cloud session must transition to "recovering" (transparent
 * re-pair) instead of "idle" (password-wall dead-end).
 */
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// Mock the environment reads the hook makes so we can drive the decision.
const mockCloudToken = vi.fn<() => string | null>();
const mockActiveServer = vi.fn();
const mockBootConfig = vi.fn(() => ({ cloudApiBase: "https://elizacloud.ai" }));
const mockRunRecovery = vi.fn();
const mockSetAgentToken = vi.fn();
const mockPublishAgentTarget = vi.fn(() => true);
const mockRestoreAgentTarget = vi.fn(() => true);
const mockStageAgentTarget = vi.fn((..._args: unknown[]) => ({
  isCurrent: vi.fn(() => true),
  publish: mockPublishAgentTarget,
  restoreIfCurrent: mockRestoreAgentTarget,
  clearIfCurrent: vi.fn(() => true),
}));
const mockPersistCloudPairApiToken = vi.fn();
const mockPersistActiveServerCredential = vi.fn();
const mockCompensateCloudPair = vi.fn(async () => {});
const mockCompensateActiveServer = vi.fn(async () => {});
const mockIsAuthenticated = vi.fn(() => false);
const STEWARD_RECOVERY_CHANGE_EVENT = "eliza-steward-session-recovery-change";
const recoveryState = {
  generation: "generation-a" as string | null,
  receipts: [] as string[],
  storageAvailable: true,
};
const readRecoverySnapshot = () => ({
  tenantId: "tenant-default",
  generation: recoveryState.generation,
  receipts: [...recoveryState.receipts],
  hasOAuth: false,
  storageAvailable: recoveryState.storageAvailable,
});
const mockReadStewardSessionRecovery = vi.fn(readRecoverySnapshot);
const captureStoredAuthority = () => {
  const token = mockCloudToken()?.trim();
  if (
    !token ||
    !recoveryState.storageAvailable ||
    recoveryState.receipts.length > 0
  ) {
    return null;
  }
  const generation = recoveryState.generation;
  return {
    token,
    recoveryGeneration: generation,
    isCurrent: () =>
      recoveryState.storageAvailable &&
      recoveryState.receipts.length === 0 &&
      recoveryState.generation === generation &&
      mockCloudToken()?.trim() === token,
  };
};
const mockCaptureStoredStewardLoginAuthority = vi.fn(captureStoredAuthority);
const mockIsStoredStewardTokenUsable = vi.fn((_token: string) => true);
// Silent cookie->session recovery for the returning-PWA dead-end. Default:
// no cookie (returns null) so pre-existing cases keep their old behavior.
const mockEnsureCloudSession = vi.fn<
  (options?: unknown) => Promise<string | null>
>(async () => Promise.resolve(null));

vi.mock("../api/client-cloud", () => ({
  getCloudAuthToken: () => mockCloudToken(),
  // The recovery resolver/predicate treats a direct cloud shared-agent base as
  // cloud-managed. Our test servers use kind:"cloud"/"local", so this is only
  // consulted for the non-cloud (local) case, where it must return false.
  isDirectCloudSharedAgentBase: () => false,
}));
vi.mock("../state/persistence", () => ({
  loadPersistedActiveServer: () => mockActiveServer(),
}));
vi.mock("../cloud/lib/steward-session-recovery-marker", () => ({
  readStewardSessionRecovery: () => mockReadStewardSessionRecovery(),
  STEWARD_SESSION_RECOVERY_CHANGE_EVENT:
    "eliza-steward-session-recovery-change",
}));
vi.mock("../cloud/shell/steward-config", () => ({
  configuredStewardTenantId: () => "tenant-default",
  DEFAULT_STEWARD_TENANT_ID: "tenant-default",
}));
vi.mock("../config/boot-config", () => ({
  getBootConfig: () => mockBootConfig(),
}));
vi.mock("../state/agent-session-recovery-runner", () => ({
  runAgentSessionRecovery: (...args: unknown[]) => mockRunRecovery(...args),
}));
vi.mock("../components/auth/CloudPairRelay", () => ({
  persistCloudPairApiToken: async (
    token: string,
    agentId: string,
    options?: {
      validate?: () => boolean;
      captureCompensation?: (rollback: () => Promise<void>) => void;
    },
  ) => {
    if (options?.validate?.() === false)
      throw new DOMException("", "AbortError");
    await mockPersistCloudPairApiToken(token, agentId, options);
    if (options?.validate?.() === false) {
      await mockCompensateCloudPair();
      throw new DOMException("", "AbortError");
    }
    options?.captureCompensation?.(mockCompensateCloudPair);
  },
}));
vi.mock("../state/active-server-credential", () => ({
  persistActiveServerCredential: async (
    token: string,
    pairedApiBase?: string,
    options?: {
      validate?: () => boolean;
      finalize?: () => Promise<boolean>;
      compensateFinalization?: () => Promise<void>;
      captureCompensation?: (rollback: () => Promise<void>) => void;
    },
  ) => {
    if (options?.validate?.() === false)
      throw new DOMException("", "AbortError");
    await mockPersistActiveServerCredential(token, pairedApiBase, options);
    if (options?.validate?.() === false) {
      await mockCompensateActiveServer();
      throw new DOMException("", "AbortError");
    }
    const finalized = (await options?.finalize?.()) ?? true;
    if (!finalized || options?.validate?.() === false) {
      await options?.compensateFinalization?.();
      await mockCompensateActiveServer();
      throw new DOMException("", "AbortError");
    }
    options?.captureCompensation?.(async () => {
      await options.compensateFinalization?.();
      await mockCompensateActiveServer();
    });
  },
}));
vi.mock("../api", () => ({
  client: {
    setToken: (token: string) => mockSetAgentToken(token),
    stageSessionTarget: (...args: unknown[]) => mockStageAgentTarget(...args),
  },
}));
vi.mock("../state/cloud-session-refresh-for-repair", () => ({
  ensureCloudSessionForRepair: (options?: unknown) =>
    mockEnsureCloudSession(options),
}));
vi.mock("../state/cloud-steward-login", () => ({
  captureStoredStewardLoginAuthority: () =>
    mockCaptureStoredStewardLoginAuthority(),
  isStoredStewardTokenUsable: (token: string) =>
    mockIsStoredStewardTokenUsable(token),
}));
vi.mock("./useAuthStatus", () => ({
  useIsAuthenticated: () => mockIsAuthenticated(),
}));
const mockClearStalePairCredentialsForAgentDurably = vi.fn<
  (_options: unknown) => Promise<boolean>
>(async () => true);
vi.mock("../state/cloud-pair-token", () => ({
  clearStalePairCredentialsForAgentDurably: (options: unknown) =>
    mockClearStalePairCredentialsForAgentDurably(options),
}));

import { useAgentSessionRecovery } from "./useAgentSessionRecovery";

// Stable navigate identity across re-renders (mirrors the real app's
// module-level `defaultNavigate`). An unstable navigate would churn the effect
// deps and cancel an in-flight async re-pair — which the real app never does.
const STABLE_NAVIGATE = () => {};

function Probe(props: {
  active: boolean;
  reason?: "remote_auth_required" | "remote_password_not_configured";
  onStatus: (s: string) => void;
  onRecovered?: () => void;
  navigate?: (url: string) => void;
}) {
  const status = useAgentSessionRecovery({
    active: props.active,
    reason: props.reason,
    navigate: props.navigate ?? STABLE_NAVIGATE,
    onRecovered: props.onRecovered,
  });
  props.onStatus(status);
  return null;
}

// App-mode host detection reads window.location.hostname; jsdom's default
// (localhost) is neither an app host nor a per-agent host, so the pairing
// hand-off cases below pin it explicitly.
const realLocation = window.location;

function setHostname(hostname: string): void {
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...realLocation, hostname },
  });
}

function cloudServer(agentId: string) {
  return {
    kind: "cloud" as const,
    id: `cloud:${agentId}`,
    label: "Dedicated",
    apiBase: `https://elizacloud.ai/api/v1/eliza/agents/${agentId}`,
  };
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
  delete (globalThis as { Capacitor?: unknown }).Capacitor;
  Object.defineProperty(window, "location", {
    configurable: true,
    value: realLocation,
  });
  vi.clearAllMocks();
  // Restore the default "no cookie" behavior after clearAllMocks wipes it.
  mockEnsureCloudSession.mockImplementation(async () => Promise.resolve(null));
  mockIsAuthenticated.mockReturnValue(false);
  recoveryState.generation = "generation-a";
  recoveryState.receipts = [];
  recoveryState.storageAvailable = true;
  mockReadStewardSessionRecovery.mockImplementation(readRecoverySnapshot);
  mockCaptureStoredStewardLoginAuthority.mockImplementation(
    captureStoredAuthority,
  );
  mockIsStoredStewardTokenUsable.mockReturnValue(true);
});

describe("useAgentSessionRecovery", () => {
  it("transitions dead-end -> recovering for a cloud agent with a valid cloud session", async () => {
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    // Never resolves, keeps the hook in "recovering".
    mockRunRecovery.mockReturnValue(new Promise(() => {}));

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses).toContain("recovering");
    });
    expect(mockRunRecovery).toHaveBeenCalledTimes(1);
    const call = mockRunRecovery.mock.calls[0][0];
    expect(call).toMatchObject({
      agentId: "agent-1",
      cloudApiBase: "https://elizacloud.ai",
      cloudToken: "steward.jwt.token",
    });
  });

  it("quarantines raw account A while a durable login-B receipt exists", async () => {
    mockCloudToken.mockReturnValue("steward.account-a.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    recoveryState.generation = "receipt-b";
    recoveryState.receipts = ["receipt-b"];

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));
    expect(mockCaptureStoredStewardLoginAuthority).not.toHaveBeenCalled();
    expect(mockEnsureCloudSession).not.toHaveBeenCalled();
    expect(mockRunRecovery).not.toHaveBeenCalled();
    expect(mockPersistCloudPairApiToken).not.toHaveBeenCalled();
    expect(mockPersistActiveServerCredential).not.toHaveBeenCalled();
    expect(mockSetAgentToken).not.toHaveBeenCalled();
  });

  it("fails closed when recovery storage cannot prove account authority", async () => {
    mockCloudToken.mockReturnValue("steward.account-a.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    recoveryState.storageAvailable = false;

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));
    expect(mockEnsureCloudSession).not.toHaveBeenCalled();
    expect(mockRunRecovery).not.toHaveBeenCalled();
  });

  it("retires account A when login B begins mid-repair without any local publication", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.account-a.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    const navigate = vi.fn();
    const onRecovered = vi.fn();
    let resolveRecovery!: (value: {
      ok: false;
      reason: "error";
      message: string;
    }) => void;
    mockRunRecovery.mockReturnValue(
      new Promise((resolve) => {
        resolveRecovery = resolve;
      }),
    );
    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        navigate={navigate}
        onRecovered={onRecovered}
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const deps = mockRunRecovery.mock.calls[0][0] as {
      signal: AbortSignal;
      isRecoveryTargetCurrent: () => boolean;
      commitPairedInProcess: (apiToken: string) => Promise<void>;
      navigate: (url: string) => void;
    };
    expect(deps.isRecoveryTargetCurrent()).toBe(true);

    const statusesBeforeLoginB = statuses.length;
    recoveryState.generation = "receipt-b";
    recoveryState.receipts = ["receipt-b"];
    act(() => {
      window.dispatchEvent(new Event(STEWARD_RECOVERY_CHANGE_EVENT));
    });

    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));
    expect(deps.signal.aborted).toBe(true);
    // Even if B's marker later retires and raw token A is still present, the
    // monotonic generation prevents the old A continuation from reviving.
    recoveryState.receipts = [];
    expect(deps.isRecoveryTargetCurrent()).toBe(false);

    await expect(
      deps.commitPairedInProcess("late-agent-a-bearer"),
    ).rejects.toThrow("authority was superseded");
    deps.navigate("https://agent-1.example/pair?token=late-a");
    await act(async () => {
      resolveRecovery({
        ok: false,
        reason: "error",
        message: "late account-A response",
      });
      await Promise.resolve();
    });

    expect(mockPersistCloudPairApiToken).not.toHaveBeenCalled();
    expect(mockPersistActiveServerCredential).not.toHaveBeenCalled();
    expect(mockSetAgentToken).not.toHaveBeenCalled();
    expect(onRecovered).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
    expect(mockClearStalePairCredentialsForAgentDurably).not.toHaveBeenCalled();
    expect(statuses.at(-1)).toBe("idle");
    expect(statuses.slice(statusesBeforeLoginB)).not.toContain(
      "cloud-retry-required",
    );
  });

  it("retires account A on a cross-tab StorageEvent only after re-reading B authority", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.account-a.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));
    const navigate = vi.fn();
    const statuses: string[] = [];

    render(
      <Probe
        active
        reason="remote_auth_required"
        navigate={navigate}
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const deps = mockRunRecovery.mock.calls[0][0] as {
      signal: AbortSignal;
      commitPairedInProcess: (apiToken: string) => Promise<void>;
      navigate: (url: string) => void;
    };

    recoveryState.generation = "cross-tab-b";
    recoveryState.receipts = ["cross-tab-b"];
    act(() => {
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: "eliza.steward.server-session-generation.v1:tenant-default",
          newValue: "cross-tab-b",
        }),
      );
    });

    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));
    expect(deps.signal.aborted).toBe(true);
    deps.navigate("https://agent-1.example/pair?token=late-a");
    await expect(
      deps.commitPairedInProcess("late-account-a-bearer"),
    ).rejects.toThrow("authority was superseded");
    expect(navigate).not.toHaveBeenCalled();
    expect(mockPersistCloudPairApiToken).not.toHaveBeenCalled();
    expect(mockPersistActiveServerCredential).not.toHaveBeenCalled();
    expect(mockStageAgentTarget).not.toHaveBeenCalled();
    expect(mockClearStalePairCredentialsForAgentDurably).not.toHaveBeenCalled();
  });

  it("retires a cancelled target-change result to idle and clears ownership without retrying", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.account-a.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    let resolveRecovery!: (value: {
      ok: false;
      reason: "cancelled";
      message: string;
    }) => void;
    mockRunRecovery.mockReturnValue(
      new Promise((resolve) => {
        resolveRecovery = resolve;
      }),
    );
    const statuses: string[] = [];

    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const { signal } = mockRunRecovery.mock.calls[0][0] as {
      signal: AbortSignal;
    };
    mockActiveServer.mockReturnValue(cloudServer("agent-2"));
    await act(async () => {
      resolveRecovery({
        ok: false,
        reason: "cancelled",
        message: "target changed",
      });
      await Promise.resolve();
    });

    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));
    expect(signal.aborted).toBe(true);
    expect(mockRunRecovery).toHaveBeenCalledTimes(1);
    expect(statuses).not.toContain("cloud-retry-required");
  });

  it.each([
    ["unauthorized", "cloud-reauth-required"],
    ["manage-required", "cloud-manage-required"],
  ] as const)(
    "publishes %s fallback after a real purge invalidates the credential guard",
    async (reason, expectedStatus) => {
      (globalThis as { Capacitor?: unknown }).Capacitor = {
        isNativePlatform: () => true,
      };
      mockCloudToken.mockReturnValue("steward.jwt.token");
      let activeServer: ReturnType<typeof cloudServer> & {
        accessToken?: string;
      } = {
        ...cloudServer("agent-1"),
        accessToken: "rejected-agent-bearer",
      };
      mockActiveServer.mockImplementation(() => activeServer);
      mockClearStalePairCredentialsForAgentDurably.mockImplementationOnce(
        async () => {
          const { accessToken: _rejected, ...scrubbed } = activeServer;
          activeServer = scrubbed;
          return true;
        },
      );
      mockRunRecovery.mockResolvedValue({
        ok: false,
        reason,
        message: "terminal recovery result",
      });
      const statuses: string[] = [];

      render(
        <Probe
          active
          reason="remote_auth_required"
          onStatus={(status) => statuses.push(status)}
        />,
      );

      await waitFor(() => expect(statuses.at(-1)).toBe(expectedStatus));
      expect(mockClearStalePairCredentialsForAgentDurably).toHaveBeenCalledWith(
        expect.objectContaining({
          agentId: "agent-1",
          rejectedToken: "rejected-agent-bearer",
          validate: expect.any(Function),
        }),
      );
      expect(activeServer.accessToken).toBeUndefined();
    },
  );

  it("degrades a rejected purge host to retry without publishing reauth/manage", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.account-a.token");
    mockActiveServer.mockReturnValue({
      ...cloudServer("agent-1"),
      accessToken: "rejected-agent-bearer",
    });
    mockClearStalePairCredentialsForAgentDurably.mockResolvedValueOnce(false);
    mockRunRecovery.mockResolvedValue({
      ok: false,
      reason: "unauthorized",
      message: "terminal recovery result",
    });
    const statuses: string[] = [];

    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => expect(statuses.at(-1)).toBe("cloud-retry-required"));
    expect(statuses).not.toContain("cloud-reauth-required");
    expect(statuses).not.toContain("cloud-manage-required");
    expect(mockClearStalePairCredentialsForAgentDurably).toHaveBeenCalledOnce();
  });

  it("keeps every B mirror and retires A to idle when B wins while durable purge waits", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    let cloudToken = "steward.account-a.token";
    let activeServer = {
      ...cloudServer("agent-1"),
      accessToken: "rejected-agent-a-bearer",
    };
    mockCloudToken.mockImplementation(() => cloudToken);
    mockActiveServer.mockImplementation(() => activeServer);
    let releasePurge!: (cleared: boolean) => void;
    mockClearStalePairCredentialsForAgentDurably.mockImplementationOnce(
      () =>
        new Promise<boolean>((resolve) => {
          releasePurge = resolve;
        }),
    );
    mockRunRecovery.mockResolvedValue({
      ok: false,
      reason: "unauthorized",
      message: "terminal recovery result",
    });
    const statuses: string[] = [];

    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );
    await waitFor(() =>
      expect(
        mockClearStalePairCredentialsForAgentDurably,
      ).toHaveBeenCalledOnce(),
    );

    cloudToken = "steward.account-b.token";
    recoveryState.generation = "generation-b";
    activeServer = {
      ...cloudServer("agent-1"),
      accessToken: "account-b-agent-bearer",
    };
    const pairKey = "eliza:cloud-pair:api-token:agent-1";
    localStorage.setItem(pairKey, "account-b-agent-bearer");
    sessionStorage.setItem(pairKey, "account-b-agent-bearer");
    localStorage.setItem("elizaos:active-server", JSON.stringify(activeServer));
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: "profile-b",
        profiles: [
          {
            id: "profile-b",
            createdAt: "2026-08-31T00:00:00.000Z",
            kind: "cloud",
            label: "Account B agent",
            cloudAgentId: "agent-1",
            apiBase: activeServer.apiBase,
            accessToken: "account-b-agent-bearer",
          },
        ],
      }),
    );
    await act(async () => {
      releasePurge(false);
      await Promise.resolve();
    });

    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));
    expect(statuses).not.toContain("cloud-reauth-required");
    expect(statuses).not.toContain("cloud-manage-required");
    expect(localStorage.getItem(pairKey)).toBe("account-b-agent-bearer");
    expect(sessionStorage.getItem(pairKey)).toBe("account-b-agent-bearer");
    expect(localStorage.getItem("elizaos:active-server")).toContain(
      "account-b-agent-bearer",
    );
    expect(localStorage.getItem("elizaos:agent-profiles")).toContain(
      "account-b-agent-bearer",
    );
  });

  it("uses in-process pairing on native so the WebView stays on the app origin", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses).toContain("recovering");
    });
    expect(mockRunRecovery).toHaveBeenCalledWith(
      expect.objectContaining({
        consumeRedirectInProcess: true,
        signal: expect.any(AbortSignal),
        isRecoveryTargetCurrent: expect.any(Function),
        commitPairedInProcess: expect.any(Function),
      }),
    );
  });

  it("uses in-process pairing on the Eliza app hosts so entry never leaves the origin", async () => {
    // Regression pin for the app-staging pairing dead-end. The chat floor
    // (app-mode.ts) stopped ENTRY from redirecting into the per-agent /pair,
    // but recovery still did: a cold-starting agent cannot redeem the 60s
    // one-time token, the relay answered 403, and the browser rendered
    // "Sign-in link expired" — bouncing the user back through a second full
    // sign-in. On an app host recovery must redeem in-process instead.
    setHostname("app-staging.elizacloud.ai");
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses).toContain("recovering");
    });
    expect(mockRunRecovery).toHaveBeenCalledWith(
      expect.objectContaining({ consumeRedirectInProcess: true }),
    );
  });

  it("keeps the browser navigation hand-off on non-app hosts", async () => {
    // The dedicated per-agent host still has no same-origin chat app to fall
    // back to, so its /pair relay hand-off must stay untouched.
    setHostname("agent-1.elizacloud.ai");
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses).toContain("recovering");
    });
    expect(mockRunRecovery).toHaveBeenCalledWith(
      expect.objectContaining({ consumeRedirectInProcess: false }),
    );
  });

  it("immediately re-probes auth after native pairing installs the fresh bearer", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));
    const onRecovered = vi.fn();

    render(
      <Probe
        active
        reason="remote_auth_required"
        onRecovered={onRecovered}
        onStatus={() => {}}
      />,
    );

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const deps = mockRunRecovery.mock.calls[0][0] as {
      commitPairedInProcess?: (apiToken: string) => Promise<void>;
    };
    await deps.commitPairedInProcess?.("fresh-agent-bearer");
    expect(mockPersistCloudPairApiToken).toHaveBeenCalledWith(
      "fresh-agent-bearer",
      "agent-1",
      expect.objectContaining({
        publishSession: false,
        validate: expect.any(Function),
        captureCompensation: expect.any(Function),
      }),
    );
    expect(mockPersistActiveServerCredential).toHaveBeenCalledWith(
      "fresh-agent-bearer",
      undefined,
      expect.objectContaining({
        validate: expect.any(Function),
        finalize: expect.any(Function),
        compensateFinalization: expect.any(Function),
        captureCompensation: expect.any(Function),
      }),
    );
    expect(mockStageAgentTarget).toHaveBeenCalledWith(
      {
        baseUrl: "https://elizacloud.ai/api/v1/eliza/agents/agent-1",
        token: "fresh-agent-bearer",
      },
      { persist: false },
    );
    expect(mockPublishAgentTarget).toHaveBeenCalledOnce();
    expect(mockSetAgentToken).not.toHaveBeenCalled();
    expect(onRecovered).toHaveBeenCalledOnce();
  });

  it("compensates every account-A byte when login B starts during the pair-key writer", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.account-a.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));
    let releasePairWriter!: () => void;
    let pairBytes = false;
    mockPersistCloudPairApiToken.mockImplementationOnce(
      async () =>
        new Promise<void>((resolve) => {
          pairBytes = true;
          releasePairWriter = resolve;
        }),
    );
    mockCompensateCloudPair.mockImplementationOnce(async () => {
      pairBytes = false;
    });
    const statuses: string[] = [];

    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );
    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const { commitPairedInProcess } = mockRunRecovery.mock.calls[0][0] as {
      commitPairedInProcess: (apiToken: string) => Promise<void>;
    };
    const commit = commitPairedInProcess("paired-account-a-bearer");
    await waitFor(() => expect(pairBytes).toBe(true));

    recoveryState.generation = "login-b";
    recoveryState.receipts = ["login-b"];
    act(() => {
      window.dispatchEvent(new Event(STEWARD_RECOVERY_CHANGE_EVENT));
    });
    releasePairWriter();

    await expect(commit).rejects.toBeTruthy();
    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));
    expect(pairBytes).toBe(false);
    expect(mockPersistActiveServerCredential).not.toHaveBeenCalled();
    expect(mockStageAgentTarget).not.toHaveBeenCalled();
  });

  it("retains pair compensation until an account-B race inside the active/profile writer is rolled back", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.account-a.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));
    let releaseRuntimeWriter!: () => void;
    let pairBytes = false;
    let runtimeBytes = false;
    mockPersistCloudPairApiToken.mockImplementationOnce(async () => {
      pairBytes = true;
    });
    mockCompensateCloudPair.mockImplementationOnce(async () => {
      pairBytes = false;
    });
    mockPersistActiveServerCredential.mockImplementationOnce(
      async () =>
        new Promise<void>((resolve) => {
          runtimeBytes = true;
          releaseRuntimeWriter = resolve;
        }),
    );
    mockCompensateActiveServer.mockImplementationOnce(async () => {
      runtimeBytes = false;
    });
    const statuses: string[] = [];

    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );
    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const { commitPairedInProcess } = mockRunRecovery.mock.calls[0][0] as {
      commitPairedInProcess: (apiToken: string) => Promise<void>;
    };
    const commit = commitPairedInProcess("paired-account-a-bearer");
    await waitFor(() => expect(runtimeBytes).toBe(true));

    recoveryState.generation = "login-b";
    recoveryState.receipts = ["login-b"];
    act(() => {
      window.dispatchEvent(new Event(STEWARD_RECOVERY_CHANGE_EVENT));
    });
    releaseRuntimeWriter();

    await expect(commit).rejects.toBeTruthy();
    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));
    expect(pairBytes).toBe(false);
    expect(runtimeBytes).toBe(false);
    expect(mockStageAgentTarget).not.toHaveBeenCalled();
    expect(mockPublishAgentTarget).not.toHaveBeenCalled();
  });

  it("does not re-pair again when the native auth re-probe transiently leaves the unauthenticated state", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));
    const onRecovered = vi.fn();
    const statuses: string[] = [];

    const view = render(
      <Probe
        active
        reason="remote_auth_required"
        onRecovered={onRecovered}
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const deps = mockRunRecovery.mock.calls[0][0] as {
      commitPairedInProcess?: (apiToken: string) => Promise<void>;
    };
    await deps.commitPairedInProcess?.("fresh-agent-bearer");
    expect(onRecovered).toHaveBeenCalledOnce();

    view.rerender(
      <Probe
        active={false}
        reason={undefined}
        onRecovered={onRecovered}
        onStatus={(status) => statuses.push(status)}
      />,
    );
    await waitFor(() => expect(statuses.at(-1)).toBe("idle"));

    view.rerender(
      <Probe
        active
        reason="remote_auth_required"
        onRecovered={onRecovered}
        onStatus={(status) => statuses.push(status)}
      />,
    );
    await waitFor(() => expect(statuses.at(-1)).toBe("cloud-retry-required"));
    expect(mockRunRecovery).toHaveBeenCalledTimes(1);
  });

  it("aborts the owned recovery transaction when the auth-gate cycle unmounts", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));

    const view = render(
      <Probe active reason="remote_auth_required" onStatus={() => {}} />,
    );

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const { signal } = mockRunRecovery.mock.calls[0][0] as {
      signal: AbortSignal;
    };
    expect(signal.aborted).toBe(false);

    view.unmount();

    expect(signal.aborted).toBe(true);
  });

  it("rejects a late native bearer when the active agent changed before commit", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));
    const onRecovered = vi.fn();

    render(
      <Probe
        active
        reason="remote_auth_required"
        onRecovered={onRecovered}
        onStatus={() => {}}
      />,
    );

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    const deps = mockRunRecovery.mock.calls[0][0] as {
      signal: AbortSignal;
      commitPairedInProcess: (apiToken: string) => Promise<void>;
    };
    mockActiveServer.mockReturnValue(cloudServer("agent-2"));

    await expect(
      deps.commitPairedInProcess("late-agent-1-bearer"),
    ).rejects.toThrow("target changed");
    expect(deps.signal.aborted).toBe(true);
    expect(mockPersistCloudPairApiToken).not.toHaveBeenCalled();
    expect(mockPersistActiveServerCredential).not.toHaveBeenCalled();
    expect(mockSetAgentToken).not.toHaveBeenCalled();
    expect(onRecovered).not.toHaveBeenCalled();
  });

  it("stays idle (wall) when there is no cloud session AND no recoverable cookie", async () => {
    mockCloudToken.mockReturnValue(null);
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    // No shared cookie -> ensureCloudSessionForRepair resolves null (default).

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      // Ends on idle so the notice/wall renders honestly.
      expect(statuses[statuses.length - 1]).toBe("idle");
    });
    expect(mockRunRecovery).not.toHaveBeenCalled();
  });

  it("shows Cloud reauth when a managed native target has no recoverable session", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue(null);
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses[statuses.length - 1]).toBe("cloud-reauth-required");
    });
    expect(mockRunRecovery).not.toHaveBeenCalled();
  });

  it("re-pairs when native SIWE supplies the Cloud token after the initial recovery attempt", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    let cloudToken: string | null = null;
    mockCloudToken.mockImplementation(() => cloudToken);
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => {
      expect(statuses.at(-1)).toBe("cloud-reauth-required");
    });
    expect(mockRunRecovery).not.toHaveBeenCalled();

    cloudToken = "steward.jwt.from-native-siwe";
    act(() => {
      window.dispatchEvent(new CustomEvent("steward-token-sync"));
    });

    await waitFor(() => {
      expect(mockRunRecovery).toHaveBeenCalledTimes(1);
    });
    expect(statuses).toContain("recovering");
    expect(mockRunRecovery.mock.calls[0][0]).toMatchObject({
      agentId: "agent-1",
      cloudToken: "steward.jwt.from-native-siwe",
    });
  });

  it("REGRESSION: returning PWA with no app-origin token but a live Eliza Cloud cookie silently re-pairs instead of dead-ending", async () => {
    // The exact reported dead-end: `getCloudAuthToken()` is null on the agent
    // subdomain (cold PWA relaunch, empty localStorage mirror), but the shared
    // HttpOnly `.elizacloud.ai` session cookie is live. The hook must recover
    // the session from the cookie and re-pair, NOT drop to
    // `CloudHostedAgentAuthNotice`.
    let token: string | null = null;
    mockCloudToken.mockImplementation(() => token);
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockEnsureCloudSession.mockImplementation(async () => {
      // Simulate the cookie refresh landing a fresh app-origin token.
      token = "steward.jwt.recovered";
      // The canonical writer publishes synchronously before the ensure promise
      // resolves. This event must not cancel the attempt that produced it.
      window.dispatchEvent(new CustomEvent("steward-token-sync"));
      return token;
    });
    mockRunRecovery.mockReturnValue(new Promise(() => {})); // stays recovering

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(mockRunRecovery).toHaveBeenCalledTimes(1);
    });
    expect(statuses).toContain("recovering");
    expect(mockEnsureCloudSession).toHaveBeenCalledTimes(1);
    expect(mockRunRecovery.mock.calls[0][0]).toMatchObject({
      agentId: "agent-1",
      cloudApiBase: "https://elizacloud.ai",
      cloudToken: "steward.jwt.recovered",
    });
  });

  it("forces an expired native JWT through one transactional refresh before re-pairing", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    let token = "expired.account-a.jwt";
    mockCloudToken.mockImplementation(() => token);
    mockIsStoredStewardTokenUsable.mockImplementation(
      (candidate) => candidate !== "expired.account-a.jwt",
    );
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockEnsureCloudSession.mockImplementationOnce(async (options) => {
      expect(options).toMatchObject({
        forceRefresh: true,
        validate: expect.any(Function),
      });
      token = "fresh.account-a.jwt";
      return token;
    });
    mockRunRecovery.mockReturnValue(new Promise(() => {}));
    const statuses: string[] = [];

    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    expect(mockEnsureCloudSession).toHaveBeenCalledTimes(1);
    expect(mockRunRecovery.mock.calls[0][0]).toMatchObject({
      agentId: "agent-1",
      cloudToken: "fresh.account-a.jwt",
    });
    expect(mockClearStalePairCredentialsForAgentDurably).not.toHaveBeenCalled();
    expect(statuses).toContain("recovering");
    expect(statuses).not.toContain("cloud-reauth-required");
  });

  it("re-pairs once with an opaque native Steward bearer without refreshing it", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("opaque-native-session");
    mockIsStoredStewardTokenUsable.mockReturnValue(true);
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockReturnValue(new Promise(() => {}));

    render(<Probe active reason="remote_auth_required" onStatus={() => {}} />);

    await waitFor(() => expect(mockRunRecovery).toHaveBeenCalledTimes(1));
    expect(mockEnsureCloudSession).not.toHaveBeenCalled();
    expect(mockRunRecovery.mock.calls[0][0]).toMatchObject({
      cloudToken: "opaque-native-session",
    });
  });

  it("does not attempt a cookie refresh for a self-hosted (non-cloud) server", async () => {
    mockCloudToken.mockReturnValue(null);
    mockActiveServer.mockReturnValue({
      kind: "local" as const,
      id: "local:1",
      label: "Local",
      apiBase: "http://localhost:7777",
    });

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses[statuses.length - 1]).toBe("idle");
    });
    // A self-hosted wall is honest: never touch the cloud cookie refresh.
    expect(mockEnsureCloudSession).not.toHaveBeenCalled();
    expect(mockRunRecovery).not.toHaveBeenCalled();
  });

  it("drops back to idle (wall) when browser recovery fails", async () => {
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockResolvedValue({
      ok: false,
      reason: "unauthorized",
      message: "no",
    });

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      // Ended back on idle so the wall renders.
      expect(statuses[statuses.length - 1]).toBe("idle");
    });
  });

  it("routes a failed managed-native recovery to Cloud reauth, never the wall", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue({
      ...cloudServer("agent-1"),
      accessToken: "rejected-agent-bearer",
    });
    mockRunRecovery.mockResolvedValue({
      ok: false,
      reason: "unauthorized",
      message: "no",
    });

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses[statuses.length - 1]).toBe("cloud-reauth-required");
    });
  });

  it("keeps Cloud auth and offers retry after a transient native recovery failure", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("still-valid.steward.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));
    mockRunRecovery.mockResolvedValue({
      ok: false,
      reason: "error",
      message: "network unavailable",
    });

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => {
      expect(statuses[statuses.length - 1]).toBe("cloud-retry-required");
    });
    expect(mockRunRecovery).toHaveBeenCalledTimes(1);
  });

  it("routes account or agent action failures to Cloud management", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("still-valid.steward.token");
    mockActiveServer.mockReturnValue({
      ...cloudServer("agent-1"),
      accessToken: "rejected-agent-bearer",
    });
    mockRunRecovery.mockResolvedValue({
      ok: false,
      reason: "manage-required",
      message: "Insufficient credits",
    });

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => {
      expect(statuses[statuses.length - 1]).toBe("cloud-manage-required");
    });
  });

  it("keeps the owner-password wall for a native self-hosted target", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue({
      kind: "remote" as const,
      id: "remote:vps",
      label: "VPS",
      apiBase: "https://box.example.com",
    });

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_auth_required"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses[statuses.length - 1]).toBe("idle");
    });
    expect(mockRunRecovery).not.toHaveBeenCalled();
  });

  it("routes resolver-ineligible managed agents to Cloud management without a reload retry loop", async () => {
    (globalThis as { Capacitor?: unknown }).Capacitor = {
      isNativePlatform: () => true,
    };
    mockCloudToken.mockReturnValue("still-valid.steward.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_password_not_configured"
        onStatus={(status) => statuses.push(status)}
      />,
    );

    await waitFor(() => {
      expect(statuses[statuses.length - 1]).toBe("cloud-manage-required");
    });
    expect(mockRunRecovery).not.toHaveBeenCalled();
  });

  it("does not attempt recovery for the password-not-configured wall", async () => {
    mockCloudToken.mockReturnValue("steward.jwt.token");
    mockActiveServer.mockReturnValue(cloudServer("agent-1"));

    const statuses: string[] = [];
    render(
      <Probe
        active
        reason="remote_password_not_configured"
        onStatus={(s) => statuses.push(s)}
      />,
    );

    await waitFor(() => {
      expect(statuses.length).toBeGreaterThan(0);
    });
    expect(statuses).not.toContain("recovering");
    expect(mockRunRecovery).not.toHaveBeenCalled();
  });
});
