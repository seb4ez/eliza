/** Proves /join admits only a live bearer from a clean recovery generation. */
// @vitest-environment jsdom

import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionRecovery,
  rejectStewardSessionRecovery,
} from "../../lib/steward-session-recovery-marker";
import {
  LocalStewardAuthContext,
  type LocalStewardAuthValue,
} from "../../shell/StewardProviderShared";
import { useJoinSessionAuth } from "./use-join-session";

function makeJwt(userId: string): string {
  const encode = (value: object) =>
    btoa(JSON.stringify(value))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${encode({ alg: "HS256", typ: "JWT" })}.${encode({
    userId,
    exp: Math.floor(Date.now() / 1000) + 600,
  })}.sig`;
}

function providerValue(): LocalStewardAuthValue {
  return {
    isAuthenticated: true,
    isLoading: false,
    user: { id: "account-a" },
    session: null,
    signOut: () => undefined,
    getToken: () => null,
    verifyEmailCallback: async () => ({ token: "" }),
  };
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
});

describe("useJoinSessionAuth recovery authority", () => {
  it("drops stored account A as soon as same-document login B begins", () => {
    const accountA = makeJwt("account-a");
    localStorage.setItem("steward_session_token", accountA);
    const { result } = renderHook(() => useJoinSessionAuth());
    expect(result.current).toMatchObject({
      authenticated: true,
      authToken: accountA,
    });

    let loginB!: ReturnType<typeof beginStewardSessionRecovery>;
    act(() => {
      loginB = beginStewardSessionRecovery("elizacloud", "provider");
    });
    try {
      expect(result.current.authenticated).toBe(false);
      expect(result.current.authToken).toBeNull();
    } finally {
      act(() => rejectStewardSessionRecovery(loginB));
    }
    expect(result.current.authenticated).toBe(true);
    expect(result.current.authToken).toBe(accountA);
  });

  it("does not trust mounted provider auth while a recovery receipt is live", () => {
    const { result } = renderHook(() => useJoinSessionAuth(), {
      wrapper: ({ children }) => (
        <LocalStewardAuthContext.Provider value={providerValue()}>
          {children}
        </LocalStewardAuthContext.Provider>
      ),
    });
    expect(result.current.authenticated).toBe(true);

    let loginB!: ReturnType<typeof beginStewardSessionRecovery>;
    act(() => {
      loginB = beginStewardSessionRecovery("elizacloud", "provider");
    });
    try {
      expect(result.current.authenticated).toBe(false);
      expect(result.current.authToken).toBeNull();
    } finally {
      act(() => rejectStewardSessionRecovery(loginB));
    }
  });

  it("fails closed when recovery storage cannot be enumerated", () => {
    localStorage.setItem("steward_session_token", makeJwt("account-a"));
    vi.spyOn(window.localStorage, "key").mockImplementation(() => {
      throw new DOMException("Storage denied", "SecurityError");
    });

    const { result } = renderHook(() => useJoinSessionAuth());

    expect(result.current.authenticated).toBe(false);
    expect(result.current.authToken).toBeNull();
  });
});
