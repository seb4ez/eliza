/** Verifies StewardLoginSection — OAuth callback completion state (#13519) through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * #13519: after a successful OAuth callback the login section must NOT re-render
 * the provider options while the token exchange is in flight — that re-render is
 * what read as the login "flashing back to the sign-in options" after success.
 *
 * This test renders the section with an OAuth callback present in the URL and a
 * never-resolving exchange, and asserts it holds a terminal "Completing
 * sign-in…" state (no email input, no passkey/OAuth buttons). A companion case
 * asserts a callback FAILURE clears that state and surfaces the error + the
 * options again, so a real failure is never hidden behind the spinner.
 */

import {
  STEWARD_SESSION_CHANGE_EVENT,
  StewardSessionError,
} from "@elizaos/shared/steward-session-client";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionRecovery,
  markStewardSessionRecoveryCookiePending,
  readStewardSessionRecovery,
} from "../../../lib/steward-session-recovery-marker";

const callbackState = vi.hoisted(() => ({
  hasCallback: true,
  returnedState: "state-1" as string | null,
  expectedState: "state-1" as string | null,
  pkceVerifier: "verifier-1" as string | undefined,
  codeAvailable: true,
  hasAuthedCookie: false,
  pendingReturnTo: null as string | null,
  exchangeCalls: 0,
  exchangeSignals: [] as AbortSignal[],
  exchange: (_signal?: AbortSignal): Promise<{ token?: string }> =>
    new Promise(() => {}),
  recover: vi.fn(),
  resolveReturnTo: vi.fn(),
  sync: vi.fn(),
}));

vi.mock("../../lib/steward-session", () => ({
  hasStewardOAuthCallbackInUrl: () => callbackState.hasCallback,
  consumeStewardCodeFromQuery: () => {
    if (!callbackState.codeAvailable) return null;
    callbackState.codeAvailable = false;
    callbackState.hasCallback = false;
    return "callback-code";
  },
  consumeStewardOAuthStateFromCallback: () => callbackState.returnedState,
  stripLegacyTokenHashFromAddressBar: () => false,
  exchangeStewardCodeViaApi: (
    _code: string,
    options?: { signal?: AbortSignal },
  ) => {
    callbackState.exchangeCalls += 1;
    if (options?.signal) callbackState.exchangeSignals.push(options.signal);
    return callbackState.exchange(options?.signal);
  },
  recoverStewardSessionViaCookie: callbackState.recover,
  refreshStewardSessionViaCookie: () => Promise.resolve({ ok: true as const }),
  syncStewardSessionCookie: callbackState.sync,
}));

vi.mock("@elizaos/shared/steward-session-client", async () => {
  const actual = await vi.importActual<
    typeof import("@elizaos/shared/steward-session-client")
  >("@elizaos/shared/steward-session-client");
  return {
    ...actual,
    hasStewardAuthedCookie: () => callbackState.hasAuthedCookie,
    peekStewardOAuthState: () => callbackState.expectedState,
  };
});

vi.mock("@stwd/sdk", () => ({
  StewardAuth: class {
    getSession() {
      return null;
    }
    getProviders() {
      return Promise.resolve({
        passkey: true,
        email: true,
        siwe: false,
        siws: false,
        google: true,
        discord: true,
        github: false,
        twitter: false,
        oauth: ["google", "discord"],
      });
    }
    refreshSession() {
      return Promise.resolve(null);
    }
  },
}));

vi.mock("../../../shell/steward-url", () => ({
  resolveBrowserStewardApiUrl: () => "https://api.example.test",
}));

vi.mock("../../../shell/steward-config", () => ({
  configuredStewardTenantId: () => "elizacloud",
  DEFAULT_STEWARD_TENANT_ID: "elizacloud",
}));

vi.mock("../../../shell/CloudI18nProvider", () => ({
  useCloudT: () => (_key: string, opts?: { defaultValue?: string }) =>
    opts?.defaultValue ?? _key,
}));

vi.mock("../../lib/steward-oauth-url", async () => {
  const actual = await vi.importActual<
    typeof import("../../lib/steward-oauth-url")
  >("../../lib/steward-oauth-url");
  return {
    ...actual,
    consumeStewardPkceVerifier: () => callbackState.pkceVerifier,
    buildStewardOAuthRedirectUri: () => "https://app.example.test/login",
  };
});

vi.mock("../../lib/login-return-to", () => ({
  resolveLoginReturnTo: callbackState.resolveReturnTo,
  consumePendingOAuthReturnTo: () => callbackState.pendingReturnTo,
  storePendingOAuthReturnTo: () => undefined,
}));

import StewardLoginSection from "./steward-login-section";

function createMemoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() {
      return values.size;
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => {
      values.delete(key);
    },
    setItem: (key, value) => {
      values.set(key, String(value));
    },
  };
}

let storage: Storage;

function renderSection(initialUrl = "/login?code=callback-code&state=state-1") {
  return render(
    <MemoryRouter initialEntries={[initialUrl]}>
      <StewardLoginSection />
    </MemoryRouter>,
  );
}

function pendingExchange(signal?: AbortSignal): Promise<{ token?: string }> {
  return new Promise((_resolve, reject) => {
    signal?.addEventListener(
      "abort",
      () => reject(new DOMException("Aborted", "AbortError")),
      { once: true },
    );
  });
}

function makeJwt(userId: string, rotation = 1): string {
  const payload = btoa(
    JSON.stringify({ sub: userId, tenantId: "elizacloud", rotation }),
  )
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `header.${payload}.signature`;
}

function armCurrentRecovery(expectedToken: string): void {
  const snapshot = readStewardSessionRecovery("elizacloud");
  const receipt = snapshot.generation;
  const kind = snapshot.currentReceiptKind;
  if (!receipt || !kind || !snapshot.receipts.includes(receipt)) {
    throw new Error("Expected a current recovery reservation");
  }
  markStewardSessionRecoveryCookiePending(
    {
      tenantId: "elizacloud",
      receipt,
      kind,
      preexistingReceipts: snapshot.receipts.filter(
        (candidate) => candidate !== receipt,
      ),
    },
    expectedToken,
  );
}

describe("StewardLoginSection — OAuth callback completion state (#13519)", () => {
  beforeEach(() => {
    storage = createMemoryStorage();
    vi.stubGlobal("localStorage", storage);
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: storage,
    });
    callbackState.hasCallback = true;
    callbackState.returnedState = "state-1";
    callbackState.expectedState = "state-1";
    callbackState.pkceVerifier = "verifier-1";
    callbackState.codeAvailable = true;
    callbackState.hasAuthedCookie = false;
    callbackState.pendingReturnTo = null;
    callbackState.exchangeCalls = 0;
    callbackState.exchangeSignals = [];
    callbackState.exchange = pendingExchange;
    callbackState.recover.mockReset().mockResolvedValue(null);
    callbackState.resolveReturnTo.mockReset().mockReturnValue("/cloud");
    callbackState.sync.mockReset().mockResolvedValue(undefined);
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  afterEach(async () => {
    cleanup();
    await Promise.resolve();
    await Promise.resolve();
    storage.clear();
    window.sessionStorage.clear();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("shows a terminal 'Completing sign-in…' state and NOT the provider options while a callback exchange is in flight", async () => {
    renderSection();

    await waitFor(() =>
      expect(screen.getByText("Completing sign-in…")).toBeTruthy(),
    );

    // The provider options must not be rendered underneath — no flash back.
    expect(screen.queryByPlaceholderText("you@example.com")).toBeNull();
    expect(screen.queryByRole("button", { name: /Passkey/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /Magic Link/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /Google/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /Discord/i })).toBeNull();
  });

  it("retires callback A before its authority event and preserves reentrant login B", async () => {
    callbackState.exchange = () =>
      Promise.resolve({ token: "oauth-callback-account-a" });
    let recoveryB: ReturnType<typeof beginStewardSessionRecovery> | undefined;
    let receiptsAtPublication: readonly string[] | undefined;
    const onAuthority = () => {
      receiptsAtPublication = readStewardSessionRecovery("elizacloud").receipts;
      recoveryB = beginStewardSessionRecovery("elizacloud", "provider");
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority, {
      once: true,
    });

    try {
      renderSection();
      await waitFor(() => expect(recoveryB).toBeDefined());
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onAuthority);
    }

    expect(receiptsAtPublication).toEqual([]);
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([
      recoveryB?.receipt,
    ]);
    expect(window.localStorage.getItem("steward_session_token")).toBe(
      "oauth-callback-account-a",
    );
    expect(callbackState.resolveReturnTo).not.toHaveBeenCalled();
  });

  it("does not redirect callback A when token-sync queues login B", async () => {
    callbackState.exchange = () =>
      Promise.resolve({ token: "oauth-callback-account-a" });
    let recoveryB: ReturnType<typeof beginStewardSessionRecovery> | undefined;
    const onSync = () => {
      queueMicrotask(() => {
        recoveryB = beginStewardSessionRecovery("elizacloud", "provider");
      });
    };
    window.addEventListener("steward-token-sync", onSync, { once: true });

    try {
      renderSection();
      await waitFor(() => expect(recoveryB).toBeDefined());
    } finally {
      window.removeEventListener("steward-token-sync", onSync);
    }

    expect(callbackState.resolveReturnTo).not.toHaveBeenCalled();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([
      recoveryB?.receipt,
    ]);
  });

  it("recovers a server-committed callback and its /chat intent after BFCache restore", async () => {
    const restoredToken = makeJwt("callback-account-b");
    callbackState.hasAuthedCookie = true;
    callbackState.pendingReturnTo = "/chat";
    callbackState.resolveReturnTo.mockReturnValue("/chat");
    callbackState.recover.mockResolvedValue({
      ok: true,
      token: restoredToken,
    });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token",
    );

    renderSection("/login?code=callback-code&state=state-1&returnTo=%2Fchat");
    await waitFor(() => expect(callbackState.exchangeCalls).toBe(1));
    expect(callbackState.exchangeSignals[0]?.aborted).toBe(false);
    // Model a freeze after nonce exchange returned B and durably bound the
    // cookie-pending receipt, but before local token publication.
    armCurrentRecovery(restoredToken);

    const historyRestore = new Event("pageshow");
    Object.defineProperty(historyRestore, "persisted", { value: true });
    act(() => window.dispatchEvent(historyRestore));

    await waitFor(() => expect(callbackState.recover).toHaveBeenCalledOnce());
    expect(callbackState.recover).toHaveBeenCalledWith(
      expect.objectContaining({ rejectedSession: "preserve" }),
    );
    expect(callbackState.sync).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(window.localStorage.getItem("steward_session_token")).toBe(
        restoredToken,
      ),
    );
    expect(callbackState.exchangeSignals[0]?.aborted).toBe(true);
    await waitFor(() =>
      expect(callbackState.resolveReturnTo).toHaveBeenCalledWith(
        expect.objectContaining({ get: expect.any(Function) }),
        "/chat",
      ),
    );
    const staleRouterSearch = callbackState.resolveReturnTo.mock.calls[0]?.[0];
    expect(staleRouterSearch?.get("code")).toBe("callback-code");
  });

  it("keeps cookie authority across an ordinary unmount and remount", async () => {
    const recoveredToken = makeJwt("new-server-account");
    callbackState.pendingReturnTo = "/chat";
    callbackState.resolveReturnTo.mockReturnValue("/chat");
    callbackState.recover.mockResolvedValue({
      ok: true,
      token: recoveredToken,
    });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token",
    );

    const firstMount = renderSection(
      "/login?code=callback-code&state=state-1&returnTo=%2Fchat",
    );
    await waitFor(() => expect(callbackState.exchangeCalls).toBe(1));
    expect(readStewardSessionRecovery("elizacloud")).toMatchObject({
      hasOAuth: true,
      receipts: [expect.any(String)],
    });
    armCurrentRecovery(recoveredToken);

    firstMount.unmount();
    // A real tab close drops sessionStorage. The v2 receipt is intentionally
    // localStorage-backed, so the next document still reconciles cookie-first.
    window.sessionStorage.clear();
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    callbackState.hasAuthedCookie = true;
    renderSection("/login?returnTo=%2Fchat");

    await waitFor(() => expect(callbackState.recover).toHaveBeenCalledOnce());
    expect(callbackState.recover).toHaveBeenCalledWith(
      expect.objectContaining({ rejectedSession: "preserve" }),
    );
    expect(callbackState.sync).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(window.localStorage.getItem("steward_session_token")).toBe(
        recoveredToken,
      ),
    );
    await waitFor(() =>
      expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(0),
    );
    await waitFor(() =>
      expect(callbackState.resolveReturnTo).toHaveBeenCalledWith(
        expect.objectContaining({ get: expect.any(Function) }),
        "/chat",
      ),
    );
  });

  it("keeps a pre-response OAuth reservation block-only after tab close instead of adopting stale cookie A", async () => {
    callbackState.hasAuthedCookie = true;
    callbackState.recover.mockResolvedValue({
      ok: true,
      token: makeJwt("stale-cookie-account-a"),
    });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token-a",
    );

    const firstMount = renderSection();
    await waitFor(() => expect(callbackState.exchangeCalls).toBe(1));
    expect(readStewardSessionRecovery("elizacloud")).toMatchObject({
      currentReceiptPhase: "cookie_pending",
      expectedIdentity: null,
    });

    firstMount.unmount();
    window.sessionStorage.clear();
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    renderSection("/login");

    await waitFor(() =>
      expect(screen.getByPlaceholderText("you@example.com")).toBeTruthy(),
    );
    expect(callbackState.recover).not.toHaveBeenCalled();
    expect(callbackState.sync).not.toHaveBeenCalled();
    expect(window.localStorage.getItem("steward_session_token")).toBe(
      "previous-account-token-a",
    );
  });

  it("publishes token sync after cookie recovery even when authority unmounts the provider", async () => {
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    callbackState.hasAuthedCookie = true;
    callbackState.recover.mockResolvedValue({
      ok: true,
      token: "cookie-recovery-account-a",
    });
    const tokenSync = vi.fn();
    window.addEventListener("steward-token-sync", tokenSync);
    let unmountCurrent = () => {};
    const unmountOnAuthority = () => unmountCurrent();
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, unmountOnAuthority, {
      once: true,
    });

    try {
      const view = renderSection("/login?returnTo=%2Fchat");
      unmountCurrent = view.unmount;

      await waitFor(() =>
        expect(window.localStorage.getItem("steward_session_token")).toBe(
          "cookie-recovery-account-a",
        ),
      );
      await waitFor(() => expect(tokenSync).toHaveBeenCalledOnce());
      expect(callbackState.resolveReturnTo).not.toHaveBeenCalled();
    } finally {
      window.removeEventListener("steward-token-sync", tokenSync);
      window.removeEventListener(
        STEWARD_SESSION_CHANGE_EVENT,
        unmountOnAuthority,
      );
    }
  });

  it("does not treat a bearer-only steward-authed cookie as mutation ambiguity", async () => {
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    callbackState.hasAuthedCookie = true;
    callbackState.recover.mockResolvedValue({
      ok: true,
      token: "new-server-account-token",
    });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token",
    );

    renderSection("/login");

    await waitFor(() =>
      expect(callbackState.sync).toHaveBeenCalledWith(
        "previous-account-token",
        null,
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      ),
    );
    expect(callbackState.recover).not.toHaveBeenCalled();
  });

  it("keeps stale cookie account A unpublished when cookie-pending recovery is bound to account B", async () => {
    const attemptedB = makeJwt("attempted-account-b");
    const staleA = makeJwt("stale-cookie-account-a");
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    callbackState.hasAuthedCookie = true;
    callbackState.recover.mockResolvedValue({ ok: true, token: staleA });
    const receipt = beginStewardSessionRecovery("elizacloud", "provider");
    markStewardSessionRecoveryCookiePending(receipt, attemptedB);

    renderSection("/login");

    expect(
      await screen.findByText(
        "The server recovered a different account than this sign-in expected. Continue with a new sign-in instead.",
      ),
    ).toBeTruthy();
    expect(callbackState.recover).toHaveBeenCalledOnce();
    expect(callbackState.sync).not.toHaveBeenCalled();
    expect(window.localStorage.getItem("steward_session_token")).toBeNull();
    expect(readStewardSessionRecovery("elizacloud")).toMatchObject({
      receipts: [receipt.receipt],
      currentReceiptPhase: "cookie_pending",
      expectedIdentity: {
        userId: "attempted-account-b",
        tenantId: "elizacloud",
      },
    });
  });

  it("keeps an ambiguity receipt and never replays the old account on a 200 response without a token", async () => {
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    callbackState.recover.mockResolvedValue({ ok: true });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token",
    );
    const receipt = beginStewardSessionRecovery("elizacloud", "provider");
    markStewardSessionRecoveryCookiePending(
      receipt,
      makeJwt("expected-account-b"),
    );

    renderSection("/login");

    await waitFor(() =>
      expect(
        screen.getByText(
          "The server session was restored, but its browser token could not be hydrated. Retry session recovery.",
        ),
      ).toBeTruthy(),
    );
    expect(callbackState.sync).not.toHaveBeenCalled();
    expect(readStewardSessionRecovery("elizacloud").receipts).toContain(
      receipt.receipt,
    );
    expect(
      screen.getByRole("button", { name: "Retry session recovery" }),
    ).toBeTruthy();
  });

  it("keeps an ambiguity receipt and never replays account A after two rejected cookie reads", async () => {
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    callbackState.recover.mockResolvedValue(null);
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token-A",
    );
    const receipt = beginStewardSessionRecovery("elizacloud", "provider");
    markStewardSessionRecoveryCookiePending(
      receipt,
      makeJwt("expected-account-b"),
    );

    renderSection("/login");

    await waitFor(() =>
      expect(
        screen.getByText(
          "The previous sign-in may have completed, but its browser session could not be recovered. Retry session recovery.",
        ),
      ).toBeTruthy(),
    );
    expect(callbackState.sync).not.toHaveBeenCalled();
    expect(readStewardSessionRecovery("elizacloud").receipts).toContain(
      receipt.receipt,
    );
  });

  it("does not dispatch an OAuth exchange when the durable receipt write fails", async () => {
    const workingSetItem = storage.setItem.bind(storage);
    storage.setItem = (key, value) => {
      if (key.startsWith("eliza.steward.server-session-recovery.v2:")) {
        throw new DOMException("Storage denied", "SecurityError");
      }
      workingSetItem(key, value);
    };

    renderSection();

    await waitFor(() =>
      expect(
        screen.getByText(
          "Sign-in cannot start because durable recovery storage is unavailable. Enable site storage and try again.",
        ),
      ).toBeTruthy(),
    );
    expect(callbackState.exchangeCalls).toBe(0);
  });

  it("retires callback recovery when the origin lock rejects before dispatch", async () => {
    const previousLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    const request = vi
      .fn()
      .mockRejectedValue(new Error("Origin session lock unavailable"));
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: { request },
    });

    try {
      renderSection();
      expect(
        await screen.findByText("Origin session lock unavailable"),
      ).toBeTruthy();
    } finally {
      if (previousLocks) {
        Object.defineProperty(navigator, "locks", previousLocks);
      } else {
        Reflect.deleteProperty(navigator, "locks");
      }
    }

    expect(request).toHaveBeenCalledOnce();
    expect(callbackState.exchangeCalls).toBe(0);
    expect(callbackState.recover).not.toHaveBeenCalled();
    expect(callbackState.sync).not.toHaveBeenCalled();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
  });

  it("blocks local replay when durable marker enumeration is unavailable", async () => {
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token-A",
    );
    const receipt = beginStewardSessionRecovery("elizacloud", "provider");
    const workingKey = storage.key.bind(storage);
    storage.key = () => {
      throw new DOMException("Storage denied", "SecurityError");
    };

    renderSection("/login");

    await waitFor(() =>
      expect(
        screen.getByText(
          "Session recovery storage cannot be read. Enable site storage and retry before continuing.",
        ),
      ).toBeTruthy(),
    );
    expect(callbackState.recover).not.toHaveBeenCalled();
    expect(callbackState.sync).not.toHaveBeenCalled();

    storage.key = workingKey;
    expect(readStewardSessionRecovery("elizacloud").receipts).toContain(
      receipt.receipt,
    );
  });

  it("keeps callback account authority across repeated BFCache restores", async () => {
    const firstRecoveredToken = makeJwt("callback-account-b", 1);
    const secondRecoveredToken = makeJwt("callback-account-b", 2);
    callbackState.hasAuthedCookie = true;
    callbackState.pendingReturnTo = "/chat";
    callbackState.resolveReturnTo.mockReturnValue("/chat");
    let resolveFirstRecovery: (
      value: { ok: true; token: string } | null,
    ) => void = () => {};
    callbackState.recover
      .mockImplementationOnce(
        (options?: { signal?: AbortSignal }) =>
          new Promise((resolve) => {
            resolveFirstRecovery = resolve;
            options?.signal?.addEventListener("abort", () => resolve(null), {
              once: true,
            });
          }),
      )
      .mockResolvedValueOnce({
        ok: true,
        token: secondRecoveredToken,
      });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token",
    );

    renderSection("/login?code=callback-code&state=state-1&returnTo=%2Fchat");
    await waitFor(() => expect(callbackState.exchangeCalls).toBe(1));
    armCurrentRecovery(firstRecoveredToken);

    const firstRestore = new Event("pageshow");
    Object.defineProperty(firstRestore, "persisted", { value: true });
    act(() => window.dispatchEvent(firstRestore));
    await waitFor(() => expect(callbackState.recover).toHaveBeenCalledOnce());
    const firstRecoverySignal = callbackState.recover.mock.calls[0]?.[0]
      ?.signal as AbortSignal;

    const secondRestore = new Event("pageshow");
    Object.defineProperty(secondRestore, "persisted", { value: true });
    act(() => window.dispatchEvent(secondRestore));

    await waitFor(() => expect(callbackState.recover).toHaveBeenCalledTimes(2));
    const secondRecoverySignal = callbackState.recover.mock.calls[1]?.[0]
      ?.signal as AbortSignal;
    expect(firstRecoverySignal.aborted).toBe(true);
    expect(secondRecoverySignal.aborted).toBe(false);
    expect(callbackState.sync).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(callbackState.resolveReturnTo).toHaveBeenCalledWith(
        expect.objectContaining({ get: expect.any(Function) }),
        "/chat",
      ),
    );

    await act(async () => {
      resolveFirstRecovery(null);
      await Promise.resolve();
    });
    expect(
      callbackState.sync.mock.calls.some(
        ([token]) => token === "previous-account-token",
      ),
    ).toBe(false);
  });

  it("clears the completing state and surfaces the error when the callback exchange fails", async () => {
    callbackState.hasAuthedCookie = true;
    callbackState.exchange = () =>
      Promise.reject(new Error("Could not complete Eliza Cloud sign-in."));

    renderSection();

    await waitFor(() =>
      expect(
        screen.getByText("Could not complete Eliza Cloud sign-in."),
      ).toBeTruthy(),
    );

    // Completing spinner is gone; the sign-in options are reachable again.
    expect(screen.queryByText("Completing sign-in…")).toBeNull();
    expect(screen.getByPlaceholderText("you@example.com")).toBeTruthy();
    expect(readStewardSessionRecovery("elizacloud")).toMatchObject({
      hasOAuth: true,
      receipts: [expect.any(String)],
    });
    expect(callbackState.recover).not.toHaveBeenCalled();
    expect(window.localStorage.getItem("steward_session_token")).toBeNull();
  });

  it("retires callback recovery when nonce exchange returns HTTP 502", async () => {
    callbackState.hasAuthedCookie = true;
    callbackState.exchange = () =>
      Promise.reject(
        new StewardSessionError(
          "Nonce exchange unavailable",
          502,
          "upstream_unavailable",
        ),
      );

    renderSection();

    expect(await screen.findByText("Nonce exchange unavailable")).toBeTruthy();
    expect(callbackState.exchangeCalls).toBe(1);
    expect(callbackState.recover).not.toHaveBeenCalled();
    expect(callbackState.sync).not.toHaveBeenCalled();
    expect(window.localStorage.getItem("steward_session_token")).toBeNull();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
  });

  it("shows a friendly 'expired / try again' message (not the raw 401) when a stale or cross-tenant one-time code is rejected", async () => {
    // A prod-issued code replayed against staging comes back 401 — benign and
    // recoverable, so the copy must invite a fresh sign-in, not read as broken.
    callbackState.exchange = () =>
      Promise.reject(
        new StewardSessionError("Unauthorized", 401, "code_tenant_mismatch"),
      );

    renderSection();

    await waitFor(() =>
      expect(
        screen.getByText(
          "That sign-in link expired or was already used. Please sign in again below.",
        ),
      ).toBeTruthy(),
    );
    // The raw upstream error is not surfaced, and the form is usable again.
    expect(screen.queryByText(/Unauthorized/)).toBeNull();
    expect(screen.queryByText("Completing sign-in…")).toBeNull();
    expect(screen.getByPlaceholderText("you@example.com")).toBeTruthy();
    expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(0);
  });

  it("refuses the exchange when the callback state does not match the stashed state", async () => {
    callbackState.expectedState = "different-state";

    renderSection("/login?code=callback-code&state=state-1");

    await waitFor(() =>
      expect(
        screen.getByText(
          "This sign-in link is invalid or has expired. Please start sign-in again.",
        ),
      ).toBeTruthy(),
    );
    expect(callbackState.exchangeCalls).toBe(0);
    expect(screen.queryByText("Completing sign-in…")).toBeNull();
  });

  it("refuses the exchange when the callback carries no state echo", async () => {
    callbackState.returnedState = null;
    renderSection("/login?code=callback-code");

    await waitFor(() =>
      expect(
        screen.getByText(
          "This sign-in link is invalid or has expired. Please start sign-in again.",
        ),
      ).toBeTruthy(),
    );
    expect(callbackState.exchangeCalls).toBe(0);
  });

  it("refuses the exchange when the stored PKCE verifier is gone", async () => {
    callbackState.pkceVerifier = undefined;

    renderSection("/login?code=callback-code&state=state-1");

    await waitFor(() =>
      expect(
        screen.getByText(
          "This sign-in was started in another tab or has expired. Please start sign-in again.",
        ),
      ).toBeTruthy(),
    );
    expect(callbackState.exchangeCalls).toBe(0);
  });
});
