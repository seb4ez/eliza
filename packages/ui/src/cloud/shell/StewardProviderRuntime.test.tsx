/** Verifies AuthTokenSync 401 handling through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * `AuthTokenSync` 401 handling in the Steward runtime: a still-valid token
 * survives a session-sync/refresh 401 (no re-login loop) and retries the cookie
 * sync on the next trigger, while a genuinely expired — or exp-less, thus
 * never-ageable — token is cleared on a refresh 401 so the session self-heals.
 */

import {
  STEWARD_SESSION_CHANGE_EVENT,
  STEWARD_TOKEN_KEY,
  type StewardSessionChangeDetail,
} from "@elizaos/shared/steward-session-client";
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { type ReactNode, StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearPendingOnboardingSession,
  peekPendingOnboardingSession,
  storePendingOnboardingSession,
  TELEGRAM_ACCOUNT_CLAIM_PURPOSE,
} from "../join/lib/onboarding-continuation";
import { consumeStewardServerCookieSynced } from "../lib/steward-session-cookie-sync-marker";
import { enqueueStewardSessionMutation } from "../lib/steward-session-mutation-queue";
import {
  beginStewardSessionRecovery,
  completeStewardSessionRecovery,
  completeStewardSessionRecoverySnapshot,
  readStewardSessionRecovery,
} from "../lib/steward-session-recovery-marker";
import { syncStewardSessionCookie } from "../public-pages/lib/steward-session";
import { clearStaleStewardSession } from "./StewardProviderShared";

// AuthTokenSync's 401 handling is the load-bearing fix for the re-login loop:
// a 401 from session-sync or refresh must NOT wipe a still-valid token (a
// misrouted/stale control plane 401s valid sessions), but MUST still clear
// once the token is expired — and an exp-less token counts as expired, or no
// 401 could ever clear it. These tests exercise the real AuthTokenSync against
// a stubbed fetch; only the @stwd SDK boundary is mocked.

const stewardAuthState = vi.hoisted(() => ({
  isAuthenticated: false,
  user: null as { id: string } | null,
}));

vi.mock("@stwd/react", () => ({
  StewardProvider: ({ children }: { children: ReactNode }) => children,
  useAuth: () => ({
    isAuthenticated: stewardAuthState.isAuthenticated,
    isLoading: false,
    user: stewardAuthState.user,
    session: null,
    signOut: () => {},
    getToken: () => "",
    verifyEmailCallback: async () => ({ token: "" }),
  }),
}));
vi.mock("@stwd/sdk", () => ({
  StewardClient: class {},
}));

import StewardAuthRuntimeProvider from "./StewardProviderRuntime";

function makeJwt(payload: Record<string, unknown>): string {
  const b64url = (value: object) =>
    btoa(JSON.stringify(value))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(payload)}.sig`;
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

type RecordedCall = { url: string; method: string };
let calls: RecordedCall[] = [];

// Node ≥22 ships a bare `localStorage` global that is non-functional without
// --localstorage-file and shadows jsdom's Storage (its methods throw), and in
// this vitest setup even window.localStorage resolves to it. The code under
// test reads via both the bare global and window.localStorage, so install one
// in-memory Storage on both access paths.
function createMemoryStorage(): Storage {
  const store = new Map<string, string>();
  return {
    get length() {
      return store.size;
    },
    clear: () => store.clear(),
    getItem: (key: string) => store.get(key) ?? null,
    key: (index: number) => [...store.keys()][index] ?? null,
    removeItem: (key: string) => {
      store.delete(key);
    },
    setItem: (key: string, value: string) => {
      store.set(key, String(value));
    },
  };
}

let storage: Storage = createMemoryStorage();

function stubFetchWith401s(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push({ url, method });
      if (method === "DELETE") return new Response(null, { status: 200 });
      return new Response(JSON.stringify({}), { status: 401 });
    }),
  );
}

function postsTo(endpoint: string): RecordedCall[] {
  return calls.filter((c) => c.method === "POST" && c.url.includes(endpoint));
}

function mount() {
  return render(
    <StewardAuthRuntimeProvider apiUrl="https://steward.test">
      <div />
    </StewardAuthRuntimeProvider>,
  );
}

function setLocation(hostname: string): void {
  Object.defineProperty(window, "location", {
    configurable: true,
    value: {
      hostname,
      origin: `https://${hostname}`,
      href: `https://${hostname}/login`,
    },
  });
}

function rerenderAuthenticated(view: ReturnType<typeof mount>): void {
  stewardAuthState.isAuthenticated = true;
  stewardAuthState.user = { id: "u1" };
  view.rerender(
    <StewardAuthRuntimeProvider apiUrl="https://steward.test">
      <div />
    </StewardAuthRuntimeProvider>,
  );
}

beforeEach(() => {
  calls = [];
  stewardAuthState.isAuthenticated = false;
  stewardAuthState.user = null;
  storage = createMemoryStorage();
  vi.stubGlobal("localStorage", storage);
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: storage,
  });
  // Neutralize any configured API base so endpoints resolve to the relative
  // paths (unknown jsdom host) — the handlers under test are endpoint-agnostic.
  vi.stubEnv("VITE_API_URL", "");
  vi.stubEnv("NEXT_PUBLIC_API_URL", "");
  setLocation("localhost");
  stubFetchWith401s();
  clearPendingOnboardingSession();
  consumeStewardServerCookieSynced("", "");
});

afterEach(() => {
  cleanup();
  completeStewardSessionRecoverySnapshot(
    readStewardSessionRecovery("elizacloud"),
  );
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  window.sessionStorage.clear();
});

describe("AuthTokenSync", () => {
  it("serializes an admitted parent A sync before child B so B is always the final cookie commit", async () => {
    const tokenA = makeJwt({
      sub: "account-a",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const tokenB = makeJwt({
      sub: "account-b",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    storage.setItem(STEWARD_TOKEN_KEY, tokenA);
    const committedTokens: string[] = [];
    let releaseParentA: ((response: Response) => void) | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        calls.push({ url, method });
        if (!url.includes("steward-session") || method !== "POST") {
          return Response.json({ ok: true });
        }
        const body = JSON.parse(String(init?.body)) as { token?: string };
        if (body.token) committedTokens.push(body.token);
        if (body.token === tokenA) {
          return await new Promise<Response>((resolve) => {
            releaseParentA = resolve;
          });
        }
        return Response.json({ ok: true });
      }),
    );

    mount();
    await waitFor(() => expect(committedTokens).toEqual([tokenA]));

    const recovery = beginStewardSessionRecovery("elizacloud", "provider");
    const childB = syncStewardSessionCookie(tokenB);
    await act(async () => Promise.resolve());
    // B is admitted only after the already-dispatched A response proves that
    // A's server-cookie mutation has settled.
    expect(committedTokens).toEqual([tokenA]);

    releaseParentA?.(Response.json({ ok: true }));
    await act(async () => {
      await childB;
    });
    completeStewardSessionRecovery(recovery);

    expect(committedTokens).toEqual([tokenA, tokenB]);
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(tokenB);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(committedTokens).toEqual([tokenA, tokenB]);
  });

  it("blocks passive sync and refresh behind a durable login receipt, including StrictMode replay", async () => {
    const token = makeJwt({
      sub: "previous-account",
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    storage.setItem(STEWARD_TOKEN_KEY, token);
    beginStewardSessionRecovery("elizacloud", "provider");

    render(
      <StrictMode>
        <StewardAuthRuntimeProvider
          apiUrl="https://steward.test"
          tenantId="elizacloud"
        >
          <div />
        </StewardAuthRuntimeProvider>
      </StrictMode>,
    );

    await act(async () => Promise.resolve());
    expect(postsTo("steward-session")).toHaveLength(0);
    expect(postsTo("steward-refresh")).toHaveLength(0);

    act(() => {
      completeStewardSessionRecoverySnapshot(
        readStewardSessionRecovery("elizacloud"),
      );
    });

    await waitFor(() => {
      expect(postsTo("steward-session").length).toBeGreaterThanOrEqual(1);
      expect(postsTo("steward-refresh").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("revalidates a recovery receipt after waiting for an already-held lease", async () => {
    const token = makeJwt({
      sub: "account-a",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    storage.setItem(STEWARD_TOKEN_KEY, token);
    const acquired = deferred<void>();
    const release = deferred<void>();
    const held = enqueueStewardSessionMutation(async () => {
      acquired.resolve();
      await release.promise;
    });
    await acquired.promise;

    mount();
    await act(async () => Promise.resolve());
    beginStewardSessionRecovery("elizacloud", "provider");
    release.resolve();
    await held;
    await act(async () => Promise.resolve());

    expect(postsTo("steward-session")).toHaveLength(0);
    expect(postsTo("steward-refresh")).toHaveLength(0);
  });

  it("never posts captured account A after account B wins while the lease is held", async () => {
    const tokenA = makeJwt({
      sub: "account-a",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const tokenB = makeJwt({
      sub: "account-b",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    storage.setItem(STEWARD_TOKEN_KEY, tokenA);
    const acquired = deferred<void>();
    const release = deferred<void>();
    const held = enqueueStewardSessionMutation(async () => {
      acquired.resolve();
      await release.promise;
    });
    await acquired.promise;

    mount();
    await act(async () => Promise.resolve());
    storage.setItem(STEWARD_TOKEN_KEY, tokenB);
    release.resolve();
    await held;
    await act(async () => Promise.resolve());

    const postedBodies = (fetch as ReturnType<typeof vi.fn>).mock.calls
      .filter(
        ([input, init]) =>
          String(input).includes("steward-session") && init?.method === "POST",
      )
      .map(([, init]) => JSON.parse(String(init?.body)) as { token?: string });
    expect(postedBodies).not.toContainEqual({ token: tokenA });
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(tokenB);
  });

  it("dedupes a direct-map explicit sync only at the identical endpoint", async () => {
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    setLocation("staging.eliza.app");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
        });
        return Response.json({ ok: true });
      }),
    );

    const view = mount();
    await act(() => syncStewardSessionCookie(token));

    // Canonical token publication changes the auth provider state in the real
    // app. Re-render that transition explicitly here so AuthTokenSync consumes
    // the same-bundle one-shot marker.
    act(() => rerenderAuthenticated(view));

    await waitFor(() => expect(postsTo("steward-session")).toHaveLength(1));
    expect(postsTo("steward-session")[0]?.url).toBe(
      "https://staging.eliza.app/api/auth/steward-session",
    );
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
  });

  it("uses the configured API fallback when the explicit endpoint differs", async () => {
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    setLocation("preview.example");
    vi.stubEnv("VITE_API_URL", "https://api-preview.example");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
        });
        return Response.json({ ok: true });
      }),
    );

    const view = mount();
    await act(() => syncStewardSessionCookie(token));
    act(() => rerenderAuthenticated(view));

    await waitFor(() => expect(postsTo("steward-session")).toHaveLength(2));
    expect(postsTo("steward-session").map(({ url }) => url)).toEqual([
      "/api/auth/steward-session",
      "https://api-preview.example/api/auth/steward-session",
    ]);
  });

  it("does not suppress passive sync after an explicit cookie sync fails", async () => {
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    let sessionPostCount = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
        });
        if (String(input).includes("steward-session")) {
          sessionPostCount += 1;
          if (sessionPostCount === 1) {
            return Response.json({ error: "sync rejected" }, { status: 500 });
          }
        }
        return Response.json({ ok: true });
      }),
    );

    mount();
    await expect(syncStewardSessionCookie(token)).rejects.toThrow(
      "sync rejected",
    );

    storage.setItem(STEWARD_TOKEN_KEY, token);
    act(() => {
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: STEWARD_TOKEN_KEY,
          newValue: token,
        }),
      );
    });

    await waitFor(() => expect(postsTo("steward-session")).toHaveLength(2));
  });

  it("re-establishes the same token once after a failing logout cookie clear", async () => {
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    let deleteAttempts = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
        });
        if (init?.method === "DELETE") {
          deleteAttempts += 1;
          throw new Error("cookie clear unavailable");
        }
        return Response.json({ ok: true });
      }),
    );

    mount();
    await act(() => syncStewardSessionCookie(token));
    expect(postsTo("steward-session")).toHaveLength(1);

    // The clear is best-effort and its DELETE fails, but it must retire the
    // unconsumed explicit-sync proof before any fallible teardown boundary.
    await act(() => clearStaleStewardSession());
    expect(deleteAttempts).toBeGreaterThan(0);
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull();

    storage.setItem(STEWARD_TOKEN_KEY, token);
    act(() => {
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: STEWARD_TOKEN_KEY,
          newValue: token,
        }),
      );
    });

    await waitFor(() => expect(postsTo("steward-session")).toHaveLength(2));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(postsTo("steward-session")).toHaveLength(2);
  });

  it("ignores a forged same-tab token event and still mirrors on a real storage trigger", async () => {
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
        });
        return Response.json({ ok: true });
      }),
    );

    mount();
    storage.setItem(STEWARD_TOKEN_KEY, token);
    act(() => {
      window.dispatchEvent(
        new CustomEvent("steward-token-sync", {
          detail: { token, serverCookieSynced: true },
        }),
      );
    });
    expect(postsTo("steward-session")).toHaveLength(0);

    act(() => {
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: STEWARD_TOKEN_KEY,
          newValue: token,
        }),
      );
    });

    await waitFor(() => expect(postsTo("steward-session")).toHaveLength(1));
  });

  it("does not loop after a successful passive session sync", async () => {
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    storage.setItem(STEWARD_TOKEN_KEY, token);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
        });
        return Response.json({ ok: true });
      }),
    );

    mount();
    await waitFor(() => expect(postsTo("steward-session")).toHaveLength(1));

    act(() => {
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: STEWARD_TOKEN_KEY,
          newValue: token,
        }),
      );
      window.dispatchEvent(new CustomEvent("steward-token-sync"));
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(postsTo("steward-session")).toHaveLength(1);
  });

  it("never carries a pending Telegram account claim through the passive token sync", async () => {
    // The passive JWT → cookie mirror runs on any authenticated page load with
    // no user gesture, so it must not execute the account-claim merge. Login
    // and SSO establish auth only; /get-started confirmation is the sole
    // consumer.
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    storage.setItem(STEWARD_TOKEN_KEY, token);
    storePendingOnboardingSession(
      "opaque-telegram-claim-token",
      TELEGRAM_ACCOUNT_CLAIM_PURPOSE,
    );
    let requestBody: unknown;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
        });
        if (String(input).includes("steward-session")) {
          requestBody = JSON.parse(String(init?.body));
        }
        return Response.json({ ok: true });
      }),
    );

    mount();

    await waitFor(() => expect(requestBody).toEqual({ token }));
    expect(peekPendingOnboardingSession(TELEGRAM_ACCOUNT_CLAIM_PURPOSE)).toBe(
      "opaque-telegram-claim-token",
    );
  });

  it("keeps a still-valid token when session-sync and refresh both 401 (no re-login loop), then retries the cookie sync on the next trigger", async () => {
    // exp 60s out: valid, but inside the 120s refresh-ahead window so the
    // mount-time checkAndRefresh actually POSTs the refresh endpoint.
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    storage.setItem(STEWARD_TOKEN_KEY, token);

    mount();

    await waitFor(() => {
      expect(postsTo("steward-session").length).toBeGreaterThanOrEqual(1);
      expect(postsTo("steward-refresh").length).toBeGreaterThanOrEqual(1);
    });

    // Both endpoints 401'd — pre-fix this wiped the token and looped /login.
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(token);

    // The keep-path resets the sync dedupe marker, so the next trigger
    // re-attempts the cookie POST for the SAME token (the endpoint may have
    // healed). Without the reset this second POST never happens.
    const before = postsTo("steward-session").length;
    document.dispatchEvent(new Event("visibilitychange"));
    await waitFor(() =>
      expect(postsTo("steward-session").length).toBeGreaterThan(before),
    );
    expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
  });

  it("clears a STILL-VALID token when session-sync 401s with session_ended — an explicit cross-host logout is a real revocation, not a stale proxy", async () => {
    // Far outside the refresh-ahead window: only the session-sync POST fires,
    // isolating the session_ended handling from the refresh path.
    const token = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    storage.setItem(STEWARD_TOKEN_KEY, token);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        calls.push({ url, method });
        if (method === "DELETE") return new Response(null, { status: 200 });
        if (url.includes("steward-session")) {
          return new Response(
            JSON.stringify({
              error: "Session was signed out",
              code: "session_ended",
            }),
            { status: 401 },
          );
        }
        return new Response(JSON.stringify({}), { status: 401 });
      }),
    );

    mount();

    // Unlike the bare-401 stale-proxy keep above, the distinct code clears the
    // stored session even though the token itself is still unexpired — this is
    // what propagates a logout performed on the PAIRED origin to this one.
    await waitFor(() => expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull());
  });

  it("parses refresh session_ended but never clears a newer account B", async () => {
    const tokenA = makeJwt({
      sub: "account-a",
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    const tokenB = makeJwt({
      sub: "account-b",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    storage.setItem(STEWARD_TOKEN_KEY, tokenA);
    const refreshResponse = deferred<Response>();
    let refreshInit: RequestInit | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push({ url, method: init?.method ?? "GET" });
        if (url.includes("steward-refresh")) {
          refreshInit = init;
          return refreshResponse.promise;
        }
        return Response.json({ ok: true });
      }),
    );

    mount();
    await waitFor(() => expect(refreshInit).toBeDefined());
    storage.setItem(STEWARD_TOKEN_KEY, tokenB);
    refreshResponse.resolve(
      Response.json(
        { error: "Session was signed out", code: "session_ended" },
        { status: 401 },
      ),
    );

    await act(async () => Promise.resolve());
    await waitFor(() =>
      expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(tokenB),
    );
    expect(refreshInit?.headers).toMatchObject({
      "Content-Type": "application/json",
      "X-Eliza-CSRF": "1",
    });
  });

  it("clears the exact still-valid token when refresh returns session_ended", async () => {
    const token = makeJwt({
      sub: "account-a",
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    storage.setItem(STEWARD_TOKEN_KEY, token);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push({ url, method: init?.method ?? "GET" });
        if (init?.method === "DELETE") return Response.json({ ok: true });
        if (url.includes("steward-refresh")) {
          return Response.json(
            { error: "Session was signed out", code: "session_ended" },
            { status: 401 },
          );
        }
        return Response.json({ ok: true });
      }),
    );

    mount();

    await waitFor(() => expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull());
  });

  it("clears an expired token on a refresh 401 (genuine end-of-session still self-heals)", async () => {
    storage.setItem(
      STEWARD_TOKEN_KEY,
      makeJwt({ sub: "u1", exp: Math.floor(Date.now() / 1000) - 60 }),
    );

    mount();

    await waitFor(() => expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull());
  });

  it("clears an exp-less token on a refresh 401 (it can never age out, so it must not be keepable)", async () => {
    storage.setItem(STEWARD_TOKEN_KEY, makeJwt({ sub: "u1" }));

    mount();

    await waitFor(() => expect(storage.getItem(STEWARD_TOKEN_KEY)).toBeNull());
  });

  it("publishes exactly one present transition when refresh stores a rotated token", async () => {
    const currentToken = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    const rotatedToken = makeJwt({
      sub: "u1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    storage.setItem(STEWARD_TOKEN_KEY, currentToken);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        calls.push({ url, method });
        if (url.includes("steward-refresh")) {
          return new Response(JSON.stringify({ token: rotatedToken }), {
            status: 200,
          });
        }
        return new Response(JSON.stringify({}), { status: 401 });
      }),
    );
    const transitions: StewardSessionChangeDetail[] = [];
    const listener = (event: Event) => {
      transitions.push(
        (event as CustomEvent<StewardSessionChangeDetail>).detail,
      );
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      mount();
      await waitFor(() =>
        expect(storage.getItem(STEWARD_TOKEN_KEY)).toBe(rotatedToken),
      );
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }

    expect(transitions.map(({ state }) => state)).toEqual(["present"]);
  });
});
