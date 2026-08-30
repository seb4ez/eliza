/** Verifies useCloudState — locked Cloud account sign-out through the package's configured test harness. */
// @vitest-environment jsdom
/**
 * Locked mobile Cloud runtime can sign out of the account without disconnecting
 * the required Cloud runtime. This is the Settings escape hatch for switching
 * accounts on mobile cloud/cloud-hybrid builds.
 */

import { cloudPairTokenKeyForAgent } from "@elizaos/shared/contracts";
import { STEWARD_TOKEN_KEY } from "@elizaos/shared/steward-session-client";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  isAndroidCloudAccountSwitchPending,
  signOutAndroidCloud,
} from "../android-cloud/android-cloud-auth";
import { client } from "../api";
import { signOutFromSsoBridgedHost } from "../cloud/sso-bridge/sso-bridge";
import {
  captureFirstRunAccountResetAuthority,
  clearPersistedActiveServer,
  loadPersistedActiveServer,
  loadPersistedFirstRunComplete,
  markFirstRunIncompleteForAccountIfCurrent,
  savePersistedActiveServer,
  savePersistedFirstRunComplete,
} from "./persistence";
import { useCloudState } from "./useCloudState";

const getCloudStatusMock = vi.hoisted(() => vi.fn());
const getCloudCreditsMock = vi.hoisted(() => vi.fn());
const cloudDisconnectMock = vi.hoisted(() => vi.fn());
const signOutFromSsoBridgedHostMock = vi.hoisted(() => vi.fn());
const signOutAndroidCloudMock = vi.hoisted(() => vi.fn());
const nativePlatformState = vi.hoisted(() => ({ enabled: false }));
const isElizaCloudRuntimeLockedMock = vi.hoisted(() => vi.fn());
const isAppModeHostMock = vi.hoisted(() => vi.fn());
const captureManagedCloudAccountBindingAuthorityMock = vi.hoisted(() =>
  vi.fn(),
);
const clearManagedCloudAccountBindingMock = vi.hoisted(() => vi.fn());

vi.mock("./shared-cloud-account-binding", () => ({
  captureManagedCloudAccountBindingAuthority:
    captureManagedCloudAccountBindingAuthorityMock,
  clearManagedCloudAccountBinding: clearManagedCloudAccountBindingMock,
}));

vi.mock("@capacitor/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@capacitor/core")>();
  return {
    ...actual,
    Capacitor: {
      ...actual.Capacitor,
      isNativePlatform: () => nativePlatformState.enabled,
    },
  };
});

vi.mock("../platform/android-runtime", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../platform/android-runtime")>()),
  isAndroidCloudBuild: () => true,
}));

vi.mock("../android-cloud/android-cloud-auth", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("../android-cloud/android-cloud-auth")
  >()),
  signOutAndroidCloud: signOutAndroidCloudMock,
}));

vi.mock("../api", () => ({
  client: {
    getBaseUrl: vi.fn(() => "https://api.eliza.app"),
    setBaseUrl: vi.fn(),
    setToken: vi.fn(),
    getCloudStatus: getCloudStatusMock,
    getCloudCredits: getCloudCreditsMock,
    cloudDisconnect: cloudDisconnectMock,
  },
}));

vi.mock("../cloud/sso-bridge/sso-bridge", () => ({
  signOutFromSsoBridgedHost: signOutFromSsoBridgedHostMock,
}));

vi.mock("../cloud/app-mode/app-mode", () => ({
  isAppModeHost: isAppModeHostMock,
}));

vi.mock("../first-run/mobile-runtime-mode", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("../first-run/mobile-runtime-mode")
  >()),
  isElizaCloudRuntimeLocked: isElizaCloudRuntimeLockedMock,
}));

function makeParams() {
  return {
    setActionNotice: vi.fn(),
    loadWalletConfig: vi.fn(async () => {}),
    t: (key: string) => key,
  };
}

describe("useCloudState — Cloud account sign-out", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    getCloudStatusMock.mockResolvedValue({
      connected: true,
      enabled: true,
      userId: "user-after-poll",
    });
    getCloudCreditsMock.mockResolvedValue({
      balance: 10,
      low: false,
      critical: false,
    });
    cloudDisconnectMock.mockResolvedValue(undefined);
    signOutFromSsoBridgedHostMock.mockResolvedValue({
      sessionGeneration: "logout-generation",
    });
    signOutAndroidCloudMock.mockResolvedValue(undefined);
    captureManagedCloudAccountBindingAuthorityMock.mockResolvedValue({
      activeServerRaw: "account-a-active-server",
      registryRaw: "account-a-registry",
      stewardToken: "account-a-token",
      sessionGeneration: null,
    });
    clearManagedCloudAccountBindingMock.mockImplementation(async () => {
      const firstRunAuthority = captureFirstRunAccountResetAuthority();
      clearPersistedActiveServer();
      markFirstRunIncompleteForAccountIfCurrent(
        firstRunAuthority,
        "test-generation",
        () => true,
      );
    });
    nativePlatformState.enabled = false;
    isElizaCloudRuntimeLockedMock.mockReturnValue(true);
    isAppModeHostMock.mockReturnValue(false);
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-token");
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("clears the account session without calling the locked runtime disconnect path", async () => {
    nativePlatformState.enabled = true;
    savePersistedActiveServer({
      id: "cloud:previous-account-agent",
      kind: "cloud",
      label: "Previous account agent",
      apiBase: "https://previous-account-agent.cloud.eliza.app",
      accessToken: "previous-account-pair-token",
    });
    savePersistedFirstRunComplete(true);
    const params = makeParams();
    const { result } = renderHook(() => useCloudState(params));

    await waitFor(() =>
      expect(result.current.elizaCloudUserId).toBe("user-after-poll"),
    );

    await act(async () => {
      await result.current.handleCloudSignOut();
    });

    expect(captureManagedCloudAccountBindingAuthorityMock).toHaveBeenCalledWith(
      {
        sessionGeneration: null,
        stewardToken: "account-a-token",
        userId: "user-after-poll",
      },
    );
    expect(signOutAndroidCloud).toHaveBeenCalledWith(
      "https://api.eliza.app",
      "account-a-token",
    );
    expect(
      captureManagedCloudAccountBindingAuthorityMock.mock
        .invocationCallOrder[0],
    ).toBeLessThan(signOutAndroidCloudMock.mock.invocationCallOrder[0] ?? 0);
    expect(clearManagedCloudAccountBindingMock).toHaveBeenCalledWith(
      expect.objectContaining({
        activeServerRaw: "account-a-active-server",
        registryRaw: "account-a-registry",
        stewardToken: "account-a-token",
      }),
      { sessionGeneration: null },
    );
    expect(signOutAndroidCloudMock.mock.invocationCallOrder[0]).toBeLessThan(
      clearManagedCloudAccountBindingMock.mock.invocationCallOrder[0] ?? 0,
    );
    expect(isAndroidCloudAccountSwitchPending()).toBe(true);
    expect(signOutFromSsoBridgedHost).not.toHaveBeenCalled();
    expect(client.cloudDisconnect).not.toHaveBeenCalled();
    expect(result.current.elizaCloudConnected).toBe(false);
    expect(result.current.elizaCloudEnabled).toBe(false);
    expect(result.current.elizaCloudUserId).toBeNull();
    expect(result.current.elizaCloudDisconnecting).toBe(false);
    expect(loadPersistedActiveServer()).toBeNull();
    expect(loadPersistedFirstRunComplete()).toBe(false);
    expect(params.setActionNotice).toHaveBeenCalledWith(
      "Signed out of Eliza Cloud.",
      "success",
      5000,
    );

    await waitFor(() => expect(client.getCloudStatus).toHaveBeenCalled());
    expect(result.current.elizaCloudConnected).toBe(false);
  });

  it("does not erase a replacement pair token published during remote logout", async () => {
    nativePlatformState.enabled = true;
    const replacementKey = cloudPairTokenKeyForAgent("replacement-agent");
    signOutAndroidCloudMock.mockImplementationOnce(async () => {
      localStorage.setItem(replacementKey, "account-b-pair-token");
      sessionStorage.setItem(replacementKey, "account-b-pair-token");
    });
    const { result } = renderHook(() => useCloudState(makeParams()));

    await waitFor(() =>
      expect(result.current.elizaCloudUserId).toBe("user-after-poll"),
    );

    await act(async () => {
      await result.current.handleCloudSignOut();
    });

    expect(localStorage.getItem(replacementKey)).toBe("account-b-pair-token");
    expect(sessionStorage.getItem(replacementKey)).toBe("account-b-pair-token");
  });

  it("uses cross-host logout on the hosted Cloud app", async () => {
    isElizaCloudRuntimeLockedMock.mockReturnValue(false);
    isAppModeHostMock.mockReturnValue(true);
    const params = makeParams();
    const { result } = renderHook(() => useCloudState(params));

    await act(async () => {
      await result.current.pollCloudCredits();
    });

    await waitFor(() =>
      expect(result.current.elizaCloudUserId).toBe("user-after-poll"),
    );

    await act(async () => {
      await result.current.handleCloudSignOut();
    });

    expect(signOutFromSsoBridgedHost).toHaveBeenCalledWith(
      window.location.hostname,
      fetch,
      {
        expectedSessionGeneration: null,
        expectedToken: "account-a-token",
      },
    );
    expect(
      captureManagedCloudAccountBindingAuthorityMock.mock
        .invocationCallOrder[0],
    ).toBeLessThan(
      signOutFromSsoBridgedHostMock.mock.invocationCallOrder[0] ?? 0,
    );
    expect(
      signOutFromSsoBridgedHostMock.mock.invocationCallOrder[0],
    ).toBeLessThan(
      clearManagedCloudAccountBindingMock.mock.invocationCallOrder[0] ?? 0,
    );
    expect(client.cloudDisconnect).not.toHaveBeenCalled();
    expect(result.current.elizaCloudConnected).toBe(false);
    expect(result.current.elizaCloudEnabled).toBe(false);
    expect(result.current.elizaCloudUserId).toBeNull();
  });
});
