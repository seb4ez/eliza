/** Verifies cloud-steward-login seam through the package's configured test harness. */
// @vitest-environment jsdom

import { registerStewardTokenRemoval } from "@elizaos/shared/steward-session-client";

/**
 * The Steward login seam (`cloud-steward-login`): stored-JWT usability checks
 * (expiry parsing), launcher registration, and `launchStewardLogin` dispatch.
 * jsdom + real `localStorage`; JWTs are synthetic (unsigned) — no real Steward
 * service.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionRecovery,
  rejectStewardSessionRecovery,
} from "../cloud/lib/steward-session-recovery-marker";
import {
  captureStoredStewardLoginAuthority,
  hasStewardLoginLauncher,
  hasUsableStoredStewardToken,
  launchStewardLogin,
  registerStewardLoginLauncher,
} from "./cloud-steward-login";

const STEWARD_TOKEN_KEY = "steward_session_token";

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

describe("cloud-steward-login seam", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("reports no launcher by default", () => {
    expect(hasStewardLoginLauncher()).toBe(false);
  });

  it("resolves immediately with an opaque stored token (device-code/Remote, no launcher call)", async () => {
    // Non-JWT opaque session tokens have no decodable `exp` → left to the legacy
    // flow (preserved), so they still short-circuit.
    localStorage.setItem(STEWARD_TOKEN_KEY, "opaque-device-code-token");
    const launcher = vi.fn(async () => ({ token: "launcher-jwt" }));
    const unregister = registerStewardLoginLauncher(launcher);
    try {
      await expect(launchStewardLogin()).resolves.toEqual({
        token: "opaque-device-code-token",
      });
      expect(launcher).not.toHaveBeenCalled();
    } finally {
      unregister();
    }
  });

  it("short-circuits on a still-valid Steward JWT (no launcher call)", async () => {
    const token = makeJwt(600);
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const launcher = vi.fn(async () => ({ token: "launcher-jwt" }));
    const unregister = registerStewardLoginLauncher(launcher);
    try {
      await expect(launchStewardLogin()).resolves.toEqual({ token });
      expect(launcher).not.toHaveBeenCalled();
    } finally {
      unregister();
    }
  });

  it("never returns local account A while login B has a durable recovery receipt", async () => {
    const accountA = makeJwt(600);
    localStorage.setItem(STEWARD_TOKEN_KEY, accountA);
    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    const accountBAuthority = { isCurrent: () => true };
    const launcher = vi.fn(async () => ({
      token: "account-b-token",
      authority: accountBAuthority,
    }));
    const unregister = registerStewardLoginLauncher(launcher);
    try {
      const result = await launchStewardLogin();
      expect(result.token).toBe("account-b-token");
      expect(result.authority).toBe(accountBAuthority);
      expect(launcher).toHaveBeenCalledTimes(1);
      // The unresolved attempt, not this seam, owns account A's rollback.
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(accountA);
    } finally {
      unregister();
      rejectStewardSessionRecovery(loginB);
    }
  });

  it("reports local account A unusable while login B has a durable recovery receipt", () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(600));
    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    try {
      expect(hasUsableStoredStewardToken()).toBe(false);
    } finally {
      rejectStewardSessionRecovery(loginB);
    }
  });

  it("invalidates account A even when login B begins and retires between caller fences", () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(600));
    const accountA = captureStoredStewardLoginAuthority();
    expect(accountA?.isCurrent()).toBe(true);

    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    rejectStewardSessionRecovery(loginB);

    expect(accountA?.isCurrent()).toBe(false);
  });

  it("reports a stored token unusable when recovery storage cannot be enumerated", () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(600));
    const keySpy = vi
      .spyOn(window.localStorage, "key")
      .mockImplementation(() => {
        throw new DOMException("Storage denied", "SecurityError");
      });
    try {
      expect(hasUsableStoredStewardToken()).toBe(false);
    } finally {
      keySpy.mockRestore();
    }
  });

  it("blocks local account A behind login B when no recovery surface is mounted", async () => {
    const accountA = makeJwt(600);
    localStorage.setItem(STEWARD_TOKEN_KEY, accountA);
    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    try {
      await expect(launchStewardLogin()).rejects.toThrow(
        /another sign-in is still being finalized/,
      );
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(accountA);
    } finally {
      rejectStewardSessionRecovery(loginB);
    }
  });

  it("forces re-auth on an expired Steward JWT (clears stale token, invokes launcher)", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(-60));
    const launcher = vi.fn(async () => ({ token: "fresh-jwt" }));
    const unregister = registerStewardLoginLauncher(launcher);
    try {
      await expect(launchStewardLogin()).resolves.toEqual({
        token: "fresh-jwt",
      });
      expect(launcher).toHaveBeenCalledTimes(1);
      // Stale token must be drained so it can't 401 later flows in a loop.
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    } finally {
      unregister();
    }
  });

  it("does not clear a newer token while retiring an expired predecessor", async () => {
    const expired = makeJwt(-60);
    const newer = makeJwt(600);
    localStorage.setItem(STEWARD_TOKEN_KEY, expired);
    const unregisterRemoval = registerStewardTokenRemoval(async (options) => {
      expect(options?.expectedToken).toBe(expired);
      localStorage.setItem(STEWARD_TOKEN_KEY, newer);
      return false;
    });
    const unregisterLauncher = registerStewardLoginLauncher(async () => ({
      token: "fresh-jwt",
    }));
    try {
      await expect(launchStewardLogin()).resolves.toEqual({
        token: "fresh-jwt",
      });
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(newer);
    } finally {
      unregisterLauncher();
      unregisterRemoval();
    }
  });

  it("forces re-auth on a JWT expiring within the safety margin", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(5));
    const launcher = vi.fn(async () => ({ token: "fresh-jwt" }));
    const unregister = registerStewardLoginLauncher(launcher);
    try {
      await expect(launchStewardLogin()).resolves.toEqual({
        token: "fresh-jwt",
      });
      expect(launcher).toHaveBeenCalledTimes(1);
    } finally {
      unregister();
    }
  });

  it("clears the stale token and throws when an expired JWT has no launcher", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(-60));
    await expect(launchStewardLogin()).rejects.toThrow(
      /Steward login surface is not mounted/,
    );
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("invokes the registered launcher when no token is stored", async () => {
    const launcher = vi.fn(async () => ({ token: "launcher-jwt" }));
    const unregister = registerStewardLoginLauncher(launcher);
    try {
      await expect(launchStewardLogin()).resolves.toEqual({
        token: "launcher-jwt",
      });
      expect(launcher).toHaveBeenCalledTimes(1);
      expect(hasStewardLoginLauncher()).toBe(true);
    } finally {
      unregister();
    }
  });

  it("throws when no launcher is registered and no token is stored", async () => {
    await expect(launchStewardLogin()).rejects.toThrow(
      /Steward login surface is not mounted/,
    );
  });

  it("hasUsableStoredStewardToken mirrors the short-circuit rules", () => {
    // No token stored.
    expect(hasUsableStoredStewardToken()).toBe(false);
    // Still-valid JWT — usable.
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(600));
    expect(hasUsableStoredStewardToken()).toBe(true);
    // Expired JWT — NOT usable (would only be drained + rethrown launcher-less).
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(-60));
    expect(hasUsableStoredStewardToken()).toBe(false);
    // Within the safety margin — NOT usable.
    localStorage.setItem(STEWARD_TOKEN_KEY, makeJwt(5));
    expect(hasUsableStoredStewardToken()).toBe(false);
    // Opaque device-code token (no decodable exp) — treated usable.
    localStorage.setItem(STEWARD_TOKEN_KEY, "opaque-device-code-token");
    expect(hasUsableStoredStewardToken()).toBe(true);
    // Checking must never drain the stored value.
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
      "opaque-device-code-token",
    );
  });

  it("unregister removes the launcher", () => {
    const unregister = registerStewardLoginLauncher(async () => ({
      token: "x",
    }));
    expect(hasStewardLoginLauncher()).toBe(true);
    unregister();
    expect(hasStewardLoginLauncher()).toBe(false);
  });
});
