/** Verifies EmailCallbackPage through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * `EmailCallbackPage` mounts the magic-link callback inside `StewardAuthProvider`
 * so the verify actually runs instead of dead-ending on "unavailable". The
 * Steward provider, i18n provider, page-title hook, session helper, and
 * authorize-return module are doubled to isolate the mount.
 */

import { StewardApiError } from "@stwd/sdk";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, StrictMode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionRecovery,
  completeStewardSessionRecovery,
  readStewardSessionRecovery,
} from "../../../lib/steward-session-recovery-marker";

const callbackState = vi.hoisted(() => ({
  verifyEmailCallback:
    vi.fn<
      (
        token: string,
        email: string,
      ) => Promise<{ token: string; refreshToken?: string }>
    >(),
  resend: vi.fn(),
  publishComplete: vi.fn(),
  isAuthenticated: false,
}));

const sessionSpies = vi.hoisted(() => ({
  sync: vi.fn(),
}));

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function jwtFor(userId: string): string {
  const payload = btoa(JSON.stringify({ sub: userId, tenantId: "elizacloud" }))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `header.${payload}.signature`;
}

function setDocumentCookie(value: string): void {
  Object.getOwnPropertyDescriptor(Document.prototype, "cookie")?.set?.call(
    document,
    value,
  );
}

// Stub StewardAuthProvider with a marker that ALSO supplies the Steward context
// — what the real provider does once its runtime mounts. This lets the test
// assert both halves: (a) the callback renders INSIDE the self-mounted
// provider, and (b) the context reaches it so the magic-link verify runs rather
// than hitting the "Sign-in is unavailable" dead-end that a provider-less
// public route produces (#9881-class).
vi.mock("../../../shell/StewardProvider", async () => {
  const { createContext } = await import("react");
  const LocalStewardAuthContext = createContext<unknown>(null);
  return {
    LocalStewardAuthContext,
    StewardAuthProvider: ({ children }: { children: ReactNode }) => (
      <div data-testid="steward-auth-provider">
        <LocalStewardAuthContext.Provider
          value={{
            isAuthenticated: callbackState.isAuthenticated,
            isLoading: false,
            user: null,
            session: null,
            signOut: () => {},
            getToken: () => "",
            verifyEmailCallback: callbackState.verifyEmailCallback,
          }}
        >
          {children}
        </LocalStewardAuthContext.Provider>
      </div>
    ),
  };
});

vi.mock("../../../shell/CloudI18nProvider", () => ({
  useCloudT: () => (_key: string, opts?: { defaultValue?: string }) =>
    opts?.defaultValue ?? _key,
}));
vi.mock("../../lib/use-page-title", () => ({ usePageTitle: () => {} }));
vi.mock("../../lib/steward-session", () => ({
  syncStewardSessionCookie: sessionSpies.sync,
}));
vi.mock("../../lib/steward-email-login", () => ({
  startStewardEmailLogin: callbackState.resend,
}));
vi.mock("../../lib/steward-email-login-complete", () => ({
  publishStewardEmailLoginComplete: callbackState.publishComplete,
}));
vi.mock("../../../shell/steward-config", () => ({
  configuredStewardTenantId: () => "elizacloud",
  DEFAULT_STEWARD_TENANT_ID: "elizacloud",
}));
vi.mock("../../../shell/steward-url", () => ({
  resolveBrowserStewardApiUrl: () => "https://api.example.test/steward",
}));
vi.mock("../../../../cloud-ui/components/auth/authorize-return", () => ({
  APP_AUTHORIZE_PATH: "/app-auth/authorize",
  readStoredAppAuthorizeReturnTo: () => null,
  clearStoredAppAuthorizeReturnTo: () => {},
}));

import { storePendingOAuthReturnTo } from "../../lib/login-return-to";
import EmailCallbackPage, {
  classifyEmailCallbackDestination,
  resolveEmailCallbackDestination,
} from "./email-callback-page";

beforeEach(() => {
  callbackState.verifyEmailCallback.mockReset();
  callbackState.resend.mockReset();
  callbackState.resend.mockResolvedValue({
    expiresAt: Date.now() + 600_000,
    challengeId: "fresh-challenge",
    pollSecret: "fresh-secret",
  });
  callbackState.publishComplete.mockReset();
  callbackState.isAuthenticated = false;
  sessionSpies.sync.mockReset();
  sessionSpies.sync.mockImplementation(
    async (
      token: string,
      _refreshToken?: string,
      options?: {
        finalizeBeforePublish?: () => (durableRestored: boolean) => void;
      },
    ) => {
      window.localStorage.setItem("steward_session_token", token);
      options?.finalizeBeforePublish?.();
    },
  );
  window.sessionStorage.clear();
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  delete document.documentElement.dataset.emailCallbackDocument;
});

describe("EmailCallbackPage", () => {
  it("mounts the callback inside StewardAuthProvider so the magic-link verify runs (not the 'unavailable' dead-end)", async () => {
    callbackState.verifyEmailCallback.mockImplementation(
      () => new Promise(() => {}),
    );

    render(
      <MemoryRouter
        initialEntries={["/auth/callback/email?token=tok&email=a%40b.co"]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    // (a) the callback renders inside the self-mounted provider — drop the
    // wrapper and this marker is never rendered, so getByTestId throws.
    expect(screen.getByTestId("steward-auth-provider")).toBeTruthy();

    // (b) the Steward context reaches the page, so verify runs with the URL
    // token/email. Without the wrapper `auth` is null and this never fires —
    // the page dead-ends on "Sign-in is unavailable".
    await waitFor(() =>
      expect(callbackState.verifyEmailCallback).toHaveBeenCalledWith(
        "tok",
        "a@b.co",
      ),
    );
  });

  it("keeps one-time verification single-flight across provider remounts", async () => {
    callbackState.verifyEmailCallback.mockImplementation(
      () => new Promise(() => {}),
    );

    const firstMount = render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=strict-token&email=strict%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(callbackState.verifyEmailCallback).toHaveBeenCalledTimes(1),
    );
    firstMount.unmount();

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=strict-token&email=strict%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    expect(callbackState.verifyEmailCallback).toHaveBeenCalledTimes(1);
    expect(callbackState.verifyEmailCallback).toHaveBeenCalledWith(
      "strict-token",
      "strict@example.com",
    );
  });

  it("finishes the single-flight magic-link publication through the StrictMode effect replay", async () => {
    const verification = deferred<{
      token: string;
      refreshToken?: string;
    }>();
    callbackState.verifyEmailCallback.mockReturnValue(verification.promise);

    render(
      <StrictMode>
        <MemoryRouter
          initialEntries={[
            "/auth/callback/email?token=strict-publication&email=strict-publication%40example.com",
          ]}
        >
          <EmailCallbackPage />
        </MemoryRouter>
      </StrictMode>,
    );

    await waitFor(() =>
      expect(callbackState.verifyEmailCallback).toHaveBeenCalledTimes(1),
    );
    await act(async () => {
      verification.resolve({
        token: "strict-publication-session-token",
        refreshToken: "strict-publication-refresh-token",
      });
      await verification.promise;
    });

    expect(await screen.findByText("Signed in")).toBeTruthy();
    expect(callbackState.verifyEmailCallback).toHaveBeenCalledTimes(1);
    expect(sessionSpies.sync).toHaveBeenCalledTimes(1);
    expect(callbackState.publishComplete).toHaveBeenCalledTimes(1);
  });

  it("plants callback A before verification so a completed login B cannot be overwritten", async () => {
    const verification = deferred<{
      token: string;
      refreshToken?: string;
    }>();
    callbackState.verifyEmailCallback.mockReturnValue(verification.promise);

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=delayed-a&email=a%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(callbackState.verifyEmailCallback).toHaveBeenCalledOnce(),
    );
    const callbackA = readStewardSessionRecovery("elizacloud");
    expect(callbackA.receipts).toHaveLength(1);
    const loginB = beginStewardSessionRecovery("elizacloud", "provider");
    window.localStorage.setItem("steward_session_token", "account-b-token");
    completeStewardSessionRecovery(loginB);

    verification.resolve({ token: "account-a-token" });

    expect(
      await screen.findByText(/newer sign-in superseded this email callback/i),
    ).toBeTruthy();
    expect(sessionSpies.sync).not.toHaveBeenCalled();
    expect(callbackState.publishComplete).not.toHaveBeenCalled();
    expect(window.localStorage.getItem("steward_session_token")).toBe(
      "account-b-token",
    );
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
  });

  it("publishes callback completion once when the first mount is replaced", async () => {
    const verification = deferred<{
      token: string;
      refreshToken?: string;
    }>();
    callbackState.verifyEmailCallback.mockReturnValue(verification.promise);
    const route =
      "/auth/callback/email?token=remount-token&email=remount%40example.com";
    const firstMount = render(
      <MemoryRouter initialEntries={[route]}>
        <EmailCallbackPage />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(callbackState.verifyEmailCallback).toHaveBeenCalledTimes(1),
    );
    firstMount.unmount();

    render(
      <MemoryRouter initialEntries={[route]}>
        <EmailCallbackPage />
      </MemoryRouter>,
    );
    verification.resolve({ token: "remount-session-token" });

    await waitFor(() =>
      expect(callbackState.publishComplete).toHaveBeenCalledTimes(1),
    );
    expect(callbackState.verifyEmailCallback).toHaveBeenCalledTimes(1);
  });

  it("does not reverify or republish a completed callback after remount", async () => {
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "completed-remount-session-token",
    });
    const route =
      "/auth/callback/email?token=completed-remount&email=completed%40example.com";
    const firstMount = render(
      <MemoryRouter initialEntries={[route]}>
        <EmailCallbackPage />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(callbackState.publishComplete).toHaveBeenCalledTimes(1),
    );
    firstMount.unmount();

    render(
      <MemoryRouter initialEntries={[route]}>
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Signed in")).toBeTruthy();
    expect(callbackState.verifyEmailCallback).toHaveBeenCalledTimes(1);
    expect(callbackState.publishComplete).toHaveBeenCalledTimes(1);
  });

  it("identifies an upstream one-time-link rejection as expired or already used", async () => {
    callbackState.verifyEmailCallback.mockRejectedValue(
      new StewardApiError("Invalid or expired magic link", 410),
    );

    const firstMount = render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=used-token&email=used%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(
        screen.getByText(
          "That sign-in link expired or was already used. Please sign in again.",
        ),
      ).toBeTruthy(),
    );
    expect(screen.queryByText("Invalid or expired magic link")).toBeNull();
    expect(
      screen.getByRole("button", { name: "Resend sign-in email" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("link", { name: "Back to login" }).getAttribute("href"),
    ).toBe("/login");

    firstMount.unmount();
    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=used-token&email=used%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(callbackState.verifyEmailCallback).toHaveBeenCalledTimes(2),
    );
  });

  it("retires callback recovery when verification fails before cookie dispatch", async () => {
    callbackState.verifyEmailCallback.mockRejectedValue(
      new Error("Verification transport unavailable"),
    );

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=pre-dispatch-failure&email=pre-dispatch%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText("Verification transport unavailable"),
    ).toBeTruthy();
    expect(sessionSpies.sync).not.toHaveBeenCalled();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
  });

  it("keeps a tab-closed email verification reservation block-only before cookie dispatch", async () => {
    const verification = deferred<{
      token: string;
      refreshToken?: string;
    }>();
    callbackState.verifyEmailCallback.mockReturnValue(verification.promise);
    setDocumentCookie("steward-authed=1; path=/");

    const mounted = render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=pre-cookie-email-link&email=pre-cookie%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(callbackState.verifyEmailCallback).toHaveBeenCalledOnce(),
    );
    const beforeClose = readStewardSessionRecovery("elizacloud");
    expect(beforeClose).toMatchObject({
      receipts: [expect.any(String)],
      currentReceiptPhase: "reserved",
      expectedIdentity: null,
    });
    expect(sessionSpies.sync).not.toHaveBeenCalled();
    expect(window.localStorage.getItem("steward_session_token")).toBeNull();

    mounted.unmount();
    window.sessionStorage.clear();

    expect(readStewardSessionRecovery("elizacloud")).toEqual(beforeClose);
    expect(window.localStorage.getItem("steward_session_token")).toBeNull();
    setDocumentCookie("steward-authed=; Max-Age=0; path=/");
  });

  it("retires callback recovery when steward-session returns 500 after a stale cookie", async () => {
    setDocumentCookie("steward-authed=1; path=/");
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "fresh-callback-account-b",
    });
    sessionSpies.sync.mockRejectedValueOnce(
      Object.assign(new Error("Session service unavailable"), { status: 500 }),
    );
    const syncEvents: Event[] = [];
    const onSync = (event: Event) => syncEvents.push(event);
    window.addEventListener("steward-token-sync", onSync);

    try {
      render(
        <MemoryRouter
          initialEntries={[
            "/auth/callback/email?token=account-b-link&email=b%40example.com",
          ]}
        >
          <EmailCallbackPage />
        </MemoryRouter>,
      );

      expect(
        await screen.findByText("Session service unavailable"),
      ).toBeTruthy();
      expect(sessionSpies.sync).toHaveBeenCalledWith(
        "fresh-callback-account-b",
        undefined,
        expect.any(Object),
      );
      expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
      expect(window.localStorage.getItem("steward_session_token")).toBeNull();
      expect(syncEvents).toEqual([]);
    } finally {
      window.removeEventListener("steward-token-sync", onSync);
      setDocumentCookie("steward-authed=; Max-Age=0; path=/");
    }
  });

  it("resends an expired callback as a fresh challenge and shows the cooldown", async () => {
    const user = userEvent.setup();
    callbackState.verifyEmailCallback.mockRejectedValue(
      new StewardApiError("expired", 410),
    );

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=expired-token&email=person%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    await user.click(
      await screen.findByRole("button", { name: "Resend sign-in email" }),
    );

    await waitFor(() =>
      expect(callbackState.resend).toHaveBeenCalledWith(
        {
          baseUrl: "https://api.example.test/steward",
          tenantId: "elizacloud",
        },
        "person@example.com",
      ),
    );
    expect(
      await screen.findByText("A new sign-in email is on its way."),
    ).toBeTruthy();
    expect(
      screen
        .getByRole("button", { name: /Resend in 30s/ })
        .hasAttribute("disabled"),
    ).toBe(true);
  });

  it("publishes a token-free completion only after the shared cookie is synced", async () => {
    storePendingOAuthReturnTo(
      new URLSearchParams({ returnTo: "/get-started" }),
    );
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "private-session-token",
      refreshToken: "private-refresh-token",
    });

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=backslash-state-token&email=person%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(callbackState.publishComplete).toHaveBeenCalledWith(
        "person@example.com",
        "/get-started",
      ),
    );
    expect(sessionSpies.sync).toHaveBeenCalledWith(
      "private-session-token",
      "private-refresh-token",
      expect.objectContaining({
        finalizeBeforePublish: expect.any(Function),
        mutationLease: expect.any(Object),
        validate: expect.any(Function),
      }),
    );
    expect(sessionSpies.sync.mock.invocationCallOrder[0]).toBeLessThan(
      callbackState.publishComplete.mock.invocationCallOrder[0],
    );
    expect(
      JSON.stringify(callbackState.publishComplete.mock.calls),
    ).not.toContain("private-session-token");
  });

  it("retires callback A before publication and preserves reentrant login B", async () => {
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "callback-account-a",
    });
    let recoveryB: ReturnType<typeof beginStewardSessionRecovery> | undefined;
    let receiptsAtPublication: readonly string[] | undefined;
    sessionSpies.sync.mockImplementationOnce(
      async (
        token: string,
        _refreshToken?: string,
        options?: {
          finalizeBeforePublish?: () => (durableRestored: boolean) => void;
        },
      ) => {
        window.localStorage.setItem("steward_session_token", token);
        expect(options?.finalizeBeforePublish?.()).toEqual(
          expect.any(Function),
        );
        receiptsAtPublication =
          readStewardSessionRecovery("elizacloud").receipts;
        recoveryB = beginStewardSessionRecovery("elizacloud", "provider");
      },
    );

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=callback-a&email=a%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText(
        "A newer sign-in superseded this email callback. Restore the latest browser session before continuing.",
      ),
    ).toBeTruthy();
    expect(receiptsAtPublication).toEqual([]);
    expect(recoveryB).toBeDefined();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([
      recoveryB?.receipt,
    ]);
    expect(callbackState.publishComplete).not.toHaveBeenCalled();
  });

  it("does not finish callback A when token-sync queues login B", async () => {
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "callback-account-a",
    });
    let recoveryB: ReturnType<typeof beginStewardSessionRecovery> | undefined;
    const onSync = () => {
      queueMicrotask(() => {
        recoveryB = beginStewardSessionRecovery("elizacloud", "provider");
      });
    };
    window.addEventListener("steward-token-sync", onSync, { once: true });

    try {
      render(
        <MemoryRouter
          initialEntries={[
            "/auth/callback/email?token=callback-a&email=a%40example.com",
          ]}
        >
          <EmailCallbackPage />
        </MemoryRouter>,
      );

      expect(
        await screen.findByText(
          "A newer sign-in superseded this email callback. Restore the latest browser session before continuing.",
        ),
      ).toBeTruthy();
    } finally {
      window.removeEventListener("steward-token-sync", onSync);
    }

    expect(recoveryB?.preexistingReceipts).toEqual([]);
    expect(callbackState.publishComplete).not.toHaveBeenCalled();
  });

  it("never paints callback A success when completion queues login B", async () => {
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "completion-account-a",
    });
    callbackState.publishComplete.mockImplementationOnce(() => {
      queueMicrotask(() => {
        beginStewardSessionRecovery("elizacloud", "provider");
      });
    });

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=completion-a&email=completion%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText(
        "A newer sign-in superseded this email callback. Restore the latest browser session before continuing.",
      ),
    ).toBeTruthy();
    expect(screen.queryByText("Signed in")).toBeNull();
  });

  it("keeps a durable ambiguity receipt when the tab closes after cookie dispatch", async () => {
    const cookieCommit = deferred<void>();
    const accountBToken = jwtFor("tab-close-account-b");
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: accountBToken,
      refreshToken: "tab-close-refresh-token",
    });
    sessionSpies.sync.mockImplementationOnce(
      async (
        token: string,
        _refreshToken?: string,
        options?: {
          validate?: () => boolean;
          finalizeBeforePublish?: () => (durableRestored: boolean) => void;
        },
      ) => {
        await cookieCommit.promise;
        if (options?.validate?.() === false) return;
        window.localStorage.setItem("steward_session_token", token);
        options?.finalizeBeforePublish?.();
      },
    );

    const mounted = render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=tab-close-link&email=close%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    await waitFor(() => expect(sessionSpies.sync).toHaveBeenCalledTimes(1));
    const beforeClose = readStewardSessionRecovery("elizacloud");
    expect(beforeClose).toMatchObject({
      receipts: [expect.any(String)],
      currentReceiptPhase: "cookie_pending",
      expectedIdentity: {
        userId: "tab-close-account-b",
        tenantId: "elizacloud",
      },
    });

    mounted.unmount();
    window.sessionStorage.clear();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual(
      beforeClose.receipts,
    );

    cookieCommit.resolve();
    await waitFor(() =>
      expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(0),
    );
  });

  it("fails closed before cookie dispatch when durable receipt storage is unavailable", async () => {
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "storage-failure-session-token",
    });
    const originalStorage = window.localStorage;
    const deniedStorage: Storage = {
      get length() {
        return originalStorage.length;
      },
      clear: () => originalStorage.clear(),
      getItem: (key) => originalStorage.getItem(key),
      key: (index) => originalStorage.key(index),
      removeItem: (key) => originalStorage.removeItem(key),
      setItem: () => {
        throw new DOMException("Storage denied", "SecurityError");
      },
    };
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: deniedStorage,
    });
    try {
      render(
        <MemoryRouter
          initialEntries={[
            "/auth/callback/email?token=storage-failure-link&email=storage%40example.com",
          ]}
        >
          <EmailCallbackPage />
        </MemoryRouter>,
      );

      expect(
        await screen.findByText(
          "Sign-in cannot start because durable recovery storage is unavailable. Enable site storage and try again.",
        ),
      ).toBeTruthy();
      expect(sessionSpies.sync).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(window, "localStorage", {
        configurable: true,
        value: originalStorage,
      });
    }
  });

  it("falls back safely when callback state contains a backslash authority", async () => {
    const hostile = JSON.stringify({
      returnTo: "/\\\\evil.example",
      expiresAt: Date.now() + 60_000,
    });
    window.sessionStorage.setItem("eliza.login.oauth.returnTo", hostile);
    window.localStorage.setItem("eliza.login.oauth.returnTo", hostile);
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "private-session-token",
    });

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=one-time-token&email=person%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(callbackState.publishComplete).toHaveBeenCalledWith(
        "person@example.com",
        "/join",
      ),
    );
    expect(
      window.sessionStorage.getItem("eliza.login.oauth.returnTo"),
    ).toBeNull();
    expect(
      window.localStorage.getItem("eliza.login.oauth.returnTo"),
    ).toBeNull();
  });

  it("rejects a replayed callback without broadcasting when this tab already has a session", async () => {
    callbackState.isAuthenticated = true;
    callbackState.verifyEmailCallback.mockRejectedValue(
      new StewardApiError("already used", 410),
    );

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=replayed-token&email=person%40example.com",
        ]}
      >
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText(
        "That sign-in link expired or was already used. Please sign in again.",
      ),
    ).toBeTruthy();
    expect(callbackState.verifyEmailCallback).toHaveBeenCalledWith(
      "replayed-token",
      "person@example.com",
    );
    expect(sessionSpies.sync).not.toHaveBeenCalled();
    expect(callbackState.publishComplete).not.toHaveBeenCalled();
  });

  it("restores a pending messaging continuation after magic-link verification", async () => {
    expect(resolveEmailCallbackDestination(null, "/get-started")).toBe(
      "/get-started",
    );
    expect(
      resolveEmailCallbackDestination(
        "/app-auth/authorize?id=1",
        "/get-started",
      ),
    ).toBe("/app-auth/authorize?id=1");
  });

  it("classifies an app-authorization destination explicitly", () => {
    const { isAppAuthorization, isJoinFallback } =
      classifyEmailCallbackDestination("/app-auth/authorize?id=1");
    expect(isAppAuthorization).toBe(true);
    expect(isJoinFallback).toBe(false);
  });

  it("classifies the ordinary login fallback as /join, not authorization", () => {
    const { isAppAuthorization, isJoinFallback } =
      classifyEmailCallbackDestination("/join");
    expect(isAppAuthorization).toBe(false);
    expect(isJoinFallback).toBe(true);
  });

  it("classifies a neutral same-origin target as neither", () => {
    const { isAppAuthorization, isJoinFallback } =
      classifyEmailCallbackDestination("/get-started");
    expect(isAppAuthorization).toBe(false);
    expect(isJoinFallback).toBe(false);
  });

  it("does not treat an embedded or lookalike authorization path as app authorization", () => {
    for (const destination of [
      "/continue/app-auth/authorize",
      "/app-auth/authorize-extra",
      "/get-started?next=/app-auth/authorize",
    ]) {
      expect(classifyEmailCallbackDestination(destination)).toEqual({
        isAppAuthorization: false,
        isJoinFallback: false,
      });
    }
  });

  it("continues to a same-origin return path without replacing the document", async () => {
    const user = userEvent.setup();
    storePendingOAuthReturnTo(
      new URLSearchParams({ returnTo: "/get-started" }),
    );
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "verified-token",
    });
    document.documentElement.dataset.emailCallbackDocument = "survived";

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=navigation-token&email=navigation%40b.co",
        ]}
      >
        <Routes>
          <Route path="/auth/callback/email" element={<EmailCallbackPage />} />
          <Route path="/get-started" element={<div>continued in place</div>} />
        </Routes>
      </MemoryRouter>,
    );

    await user.click(
      await screen.findByRole("button", {
        name: "Continue",
      }),
    );

    expect(await screen.findByText("continued in place")).toBeTruthy();
    expect(document.documentElement.dataset.emailCallbackDocument).toBe(
      "survived",
    );
  });

  it("blocks the manual success continuation when login B starts after callback A", async () => {
    const user = userEvent.setup();
    storePendingOAuthReturnTo(
      new URLSearchParams({ returnTo: "/get-started" }),
    );
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "verified-account-a",
    });

    render(
      <MemoryRouter
        initialEntries={[
          "/auth/callback/email?token=manual-a&email=manual%40b.co",
        ]}
      >
        <Routes>
          <Route path="/auth/callback/email" element={<EmailCallbackPage />} />
          <Route path="/get-started" element={<div>continued in place</div>} />
        </Routes>
      </MemoryRouter>,
    );

    const continueButton = await screen.findByRole("button", {
      name: "Continue",
    });
    beginStewardSessionRecovery("elizacloud", "provider");
    await user.click(continueButton);

    expect(screen.queryByText("continued in place")).toBeNull();
    expect(
      await screen.findByText(
        "A newer sign-in superseded this email callback. Restore the latest browser session before continuing.",
      ),
    ).toBeTruthy();
  });

  it("blocks the timed success continuation when login B starts after callback A", async () => {
    vi.useFakeTimers();
    storePendingOAuthReturnTo(
      new URLSearchParams({ returnTo: "/get-started" }),
    );
    callbackState.verifyEmailCallback.mockResolvedValue({
      token: "verified-timer-account-a",
    });

    try {
      render(
        <MemoryRouter
          initialEntries={[
            "/auth/callback/email?token=timer-a&email=timer%40b.co",
          ]}
        >
          <Routes>
            <Route
              path="/auth/callback/email"
              element={<EmailCallbackPage />}
            />
            <Route
              path="/get-started"
              element={<div>continued in place</div>}
            />
          </Routes>
        </MemoryRouter>,
      );

      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(screen.getByRole("button", { name: "Continue" })).toBeTruthy();
      beginStewardSessionRecovery("elizacloud", "provider");
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_500);
      });

      expect(screen.queryByText("continued in place")).toBeNull();
      expect(
        screen.getByText(
          "A newer sign-in superseded this email callback. Restore the latest browser session before continuing.",
        ),
      ).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects an incomplete callback and offers a safe keyboard-reachable recovery action", async () => {
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={["/auth/callback/email"]}>
        <EmailCallbackPage />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText(
        "This sign-in link is missing its token or email.",
      ),
    ).toBeTruthy();
    expect(await screen.findByRole("main")).toBeTruthy();
    expect(
      screen.getByRole("heading", { level: 1, name: "Sign-in failed" }),
    ).toBeTruthy();
    const recovery = screen.getByRole("link", { name: "Sign In Again" });
    expect(recovery.getAttribute("href")).toBe("/login");
    await user.tab();
    expect(document.activeElement).toBe(recovery);
    expect(callbackState.verifyEmailCallback).not.toHaveBeenCalled();
  });
});
