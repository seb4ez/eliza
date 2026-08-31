/** Verifies the credential precedence used by native Cloud settings. */
// @vitest-environment jsdom

import {
  STEWARD_SESSION_CHANGE_EVENT,
  STEWARD_TOKEN_KEY,
} from "@elizaos/shared/steward-session-client";
import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const credentialMock = vi.hoisted(() => ({
  bootApiToken: null as string | null,
  runtimeApiToken: null as string | null,
}));

vi.mock("@elizaos/shared", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@elizaos/shared")>()),
  getElizaApiToken: () => credentialMock.runtimeApiToken,
}));

vi.mock("../../../config/boot-config", () => ({
  BOOT_CONFIG_CHANGE_EVENT: "elizaos:boot-config-change",
  getBootConfig: () => ({ apiToken: credentialMock.bootApiToken }),
}));

import { beginStewardSessionRecovery } from "../../../cloud/lib/steward-session-recovery-marker";
import { DEFAULT_STEWARD_TENANT_ID } from "../../../cloud/shell/steward-config";

import {
  captureCloudManagementAuthority,
  currentCloudManagementToken,
  hasCloudManagementCredential,
  resolveCloudManagementToken,
  useHasCloudManagementCredential,
} from "./cloud-management-auth";

describe("resolveCloudManagementToken", () => {
  beforeEach(() => {
    localStorage.clear();
    credentialMock.bootApiToken = null;
    credentialMock.runtimeApiToken = null;
  });
  afterEach(() => cleanup());

  it("prefers the independently scoped Steward session", () => {
    expect(
      resolveCloudManagementToken({
        stewardToken: " steward-jwt ",
        bootApiToken: "eliza_boot-owner-key",
        runtimeApiToken: "eliza_runtime-owner-key",
      }),
    ).toBe("steward-jwt");
  });

  it("accepts the owner API key returned by desktop device-code login", () => {
    expect(
      resolveCloudManagementToken({
        stewardToken: null,
        bootApiToken: "eliza_boot-owner-key",
        runtimeApiToken: null,
      }),
    ).toBe("eliza_boot-owner-key");
  });

  it("rejects unrelated agent bearer strings", () => {
    expect(
      resolveCloudManagementToken({
        stewardToken: null,
        bootApiToken: "container-bearer",
        runtimeApiToken: "not-an-owner-key",
      }),
    ).toBe("");
  });

  it("reacts to same-document and cross-document Steward token removal", () => {
    const { result } = renderHook(() => useHasCloudManagementCredential());
    expect(result.current).toBe(false);

    act(() => {
      localStorage.setItem(STEWARD_TOKEN_KEY, "steward-token");
      window.dispatchEvent(new CustomEvent(STEWARD_SESSION_CHANGE_EVENT));
    });
    expect(result.current).toBe(true);

    act(() => {
      localStorage.removeItem(STEWARD_TOKEN_KEY);
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: STEWARD_TOKEN_KEY,
          oldValue: "steward-token",
          newValue: null,
        }),
      );
    });
    expect(result.current).toBe(false);
  });

  it("quarantines stored account A as soon as durable login B begins", () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a");
    expect(currentCloudManagementToken()).toBe("account-a");

    beginStewardSessionRecovery(DEFAULT_STEWARD_TENANT_ID, "provider");

    expect(currentCloudManagementToken()).toBe("");
    expect(captureCloudManagementAuthority(() => "account-a")).toBeNull();
  });

  it("fails the whole management chain closed for account A plus owner-key fallback while login B is pending", () => {
    credentialMock.bootApiToken = "eliza_owner-key";
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a");
    beginStewardSessionRecovery(DEFAULT_STEWARD_TENANT_ID, "provider");

    expect(currentCloudManagementToken()).toBe("");
    expect(hasCloudManagementCredential()).toBe(false);
    expect(captureCloudManagementAuthority()).toBeNull();

    localStorage.removeItem(STEWARD_TOKEN_KEY);
    expect(currentCloudManagementToken()).toBe("");
    expect(captureCloudManagementAuthority()).toBeNull();
  });

  it("admits an independently configured owner key only in a clean recovery generation", () => {
    credentialMock.bootApiToken = "eliza_owner-key";

    expect(currentCloudManagementToken()).toBe("eliza_owner-key");
    const authority = captureCloudManagementAuthority();
    expect(authority?.token).toBe("eliza_owner-key");
    expect(authority?.isCurrent()).toBe(true);
  });

  it("invalidates exact Steward authority when login B starts during an await", () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a");
    const authority = captureCloudManagementAuthority();
    expect(authority?.isCurrent()).toBe(true);

    beginStewardSessionRecovery(DEFAULT_STEWARD_TENANT_ID, "oauth");

    expect(authority?.isCurrent()).toBe(false);
  });

  it("reacts to the recovery event even while account A remains stored", () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a");
    const { result } = renderHook(() => useHasCloudManagementCredential());
    expect(result.current).toBe(true);

    act(() => {
      beginStewardSessionRecovery(DEFAULT_STEWARD_TENANT_ID, "provider");
    });

    expect(result.current).toBe(false);
  });
});
