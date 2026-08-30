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

import { StewardSessionError } from "@elizaos/shared/steward-session-client";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionRecovery,
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

  it("recovers a server-committed callback and its /chat intent after BFCache restore", async () => {
    callbackState.hasAuthedCookie = true;
    callbackState.pendingReturnTo = "/chat";
    callbackState.resolveReturnTo.mockReturnValue("/chat");
    callbackState.recover.mockResolvedValue({
      ok: true,
      token: "restored-callback-token",
    });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token",
    );

    renderSection("/login?code=callback-code&state=state-1&returnTo=%2Fchat");
    await waitFor(() => expect(callbackState.exchangeCalls).toBe(1));
    expect(callbackState.exchangeSignals[0]?.aborted).toBe(false);

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
        "restored-callback-token",
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
    callbackState.pendingReturnTo = "/chat";
    callbackState.resolveReturnTo.mockReturnValue("/chat");
    callbackState.recover.mockResolvedValue({
      ok: true,
      token: "new-server-account-token",
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
        "new-server-account-token",
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

  it("keeps an ambiguity receipt and never replays the old account on a 200 response without a token", async () => {
    callbackState.hasCallback = false;
    callbackState.codeAvailable = false;
    callbackState.recover.mockResolvedValue({ ok: true });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token",
    );
    const receipt = beginStewardSessionRecovery("elizacloud", "provider");

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
        token: "second-restored-callback-token",
      });
    window.localStorage.setItem(
      "steward_session_token",
      "previous-account-token",
    );

    renderSection("/login?code=callback-code&state=state-1&returnTo=%2Fchat");
    await waitFor(() => expect(callbackState.exchangeCalls).toBe(1));

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
