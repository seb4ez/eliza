/**
 * POST /api/auth/steward-nonce-exchange contract: PKCE verifier is required,
 * the non-simple-request marker is required alongside the exact-host origin
 * policy, the verifier is forwarded to the Steward exchange, and the
 * long-lived refresh token is never mirrored into the JSON body.
 * Route handler is real; Steward upstream, token verification, and user sync
 * are mocked.
 */
import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import {
  STEWARD_CSRF_HEADER,
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
} from "@elizaos/shared/steward-session-client";
import { Hono } from "hono";
import { STEWARD_REFRESH_AUTHORITY_TTL_SECONDS } from "@/lib/auth/steward-cookies";

const verifyCalls: string[] = [];
let upstreamBodies: string[] = [];
const isBlockedBySsoBridgeLogout = mock(
  async (_userId: string, _issuedAt: number) => false,
);
let logoutClassificationOverride:
  | { status: "allowed" | "definitely_revoked" }
  | {
      status: "ambiguous_cooldown";
      retryAfterSeconds: number;
      retryAtEpochSeconds: number;
    }
  | null = null;
const classifySsoBridgeLogout = mock(
  async (userId: string, issuedAt: number) => {
    if (logoutClassificationOverride) return logoutClassificationOverride;
    return (await isBlockedBySsoBridgeLogout(userId, issuedAt))
      ? ({ status: "definitely_revoked" } as const)
      : ({ status: "allowed" } as const);
  },
);
const syncUserFromSteward = mock(async () => ({
  id: "cloud-user-1",
  organization_id: "org-1",
  initialCreditsGranted: false,
  initialFreeCreditsUsd: 0,
  welcomeBonusWithheld: false,
}));

mock.module("@/lib/auth/steward-client", () => ({
  STEWARD_AUTH_UPSTREAM_TIMEOUT_MS: 5_000,
  STEWARD_VERIFY_CLOCK_SKEW_SECONDS: 300,
  verifyStewardTokenCached: async (_env: unknown, token: string) => {
    verifyCalls.push(token);
    if (token !== "steward-jwt") return null;
    return {
      userId: "steward-user-1",
      email: "user@example.test",
      tenantId: "elizacloud",
      expiration: Math.floor(Date.now() / 1000) + 3600,
      issuedAt: Math.floor(Date.now() / 1000),
    };
  },
}));

mock.module("@/lib/steward-sync", () => ({
  describeSyncError: (error: unknown) => String(error),
  StewardTelegramAccountClaimError: class extends Error {},
  syncUserFromSteward,
}));

mock.module("@/lib/services/sso-bridge-codes", () => ({
  classifySsoBridgeLogout,
  isBlockedBySsoBridgeLogout,
}));

mock.module("@/lib/steward/sign", () => ({
  signStewardMutatingRequest: async () => undefined,
}));

mock.module("@/lib/utils/logger", () => ({
  logger: { debug() {}, info() {}, warn() {}, error() {} },
}));

const { default: route } = await import("./route");

const ENV = {
  NODE_ENV: "test",
  STEWARD_API_URL: "https://steward.example.test",
  STEWARD_SESSION_SECRET: "test-secret",
} as never;

const originalFetch = globalThis.fetch;

function buildApp() {
  const app = new Hono();
  app.route("/api/auth/steward-nonce-exchange", route);
  return app;
}

function postExchange(
  headers: Record<string, string>,
  body?: unknown,
  url = "/api/auth/steward-nonce-exchange",
) {
  return buildApp().request(
    url,
    {
      method: "POST",
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
    ENV,
  );
}

const FIRST_PARTY = {
  origin: "https://eliza.app",
  "sec-fetch-site": "same-origin",
  "content-type": "application/json",
  [STEWARD_CSRF_HEADER]: STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
};

beforeEach(() => {
  verifyCalls.length = 0;
  upstreamBodies = [];
  logoutClassificationOverride = null;
  classifySsoBridgeLogout.mockClear();
  isBlockedBySsoBridgeLogout.mockClear();
  isBlockedBySsoBridgeLogout.mockResolvedValue(false);
  syncUserFromSteward.mockClear();
  globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
    upstreamBodies.push(String(init?.body ?? ""));
    return new Response(
      JSON.stringify({
        ok: true,
        token: "steward-jwt",
        refreshToken: "steward-refresh",
        expiresIn: 3600,
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("POST /api/auth/steward-nonce-exchange", () => {
  test("rejects requests with no Origin or Referer", async () => {
    const res = await postExchange(
      { "content-type": "application/json" },
      { code: "c", redirectUri: "https://eliza.app/login" },
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: "forbidden_origin" });
  });

  test("rejects a simple request without the non-simple marker", async () => {
    const res = await postExchange(
      {
        origin: "https://eliza.app",
        "sec-fetch-site": "same-origin",
        "content-type": "text/plain",
      },
      { code: "c", redirectUri: "https://eliza.app/login" },
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: "csrf_marker_required" });
  });

  test("legacy browser exchange writes only v1 before activation", async () => {
    const res = await postExchange(
      {
        origin: "https://eliza.app",
        "sec-fetch-site": "same-origin",
        "content-type": "application/json",
        [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
      },
      {
        code: "account-a-code",
        redirectUri: "https://eliza.app/login",
        codeVerifier: "account-a-verifier",
      },
    );

    expect(res.status).toBe(200);
    expect(upstreamBodies).toHaveLength(1);
    expect(verifyCalls).toEqual(["steward-jwt"]);
    const cookies = res.headers.getSetCookie().join("\n");
    expect(cookies).toContain("steward-token=steward-jwt");
    expect(cookies).toContain("steward-refresh-token=steward-refresh");
    expect(cookies).toContain("steward-authed=1");
    expect(cookies).not.toContain("-v2");
  });

  test("rejects a legacy browser exchange after v2 activation", async () => {
    const res = await postExchange(
      {
        origin: "https://eliza.app",
        "sec-fetch-site": "same-origin",
        "content-type": "application/json",
        cookie: "__Host-steward-authed-v2=1; __Host-steward-token-v2=current",
        [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
      },
      {
        code: "late-v1-code",
        redirectUri: "https://eliza.app/login",
        codeVerifier: "late-v1-verifier",
      },
    );

    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      code: "session_mutation_protocol_required",
    });
    expect(upstreamBodies).toHaveLength(0);
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  test("rejects a verifier-less exchange", async () => {
    const res = await postExchange(FIRST_PARTY, {
      code: "one-time-code",
      redirectUri: "https://eliza.app/login",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ code: "missing_code_verifier" });
    expect(upstreamBodies).toHaveLength(0);
  });

  test("forwards the verifier upstream and never mirrors the refresh token", async () => {
    const res = await postExchange(FIRST_PARTY, {
      code: "one-time-code",
      redirectUri: "https://eliza.app/login",
      codeVerifier: "pkce-verifier",
    });
    expect(res.status).toBe(200);

    expect(upstreamBodies).toHaveLength(1);
    const upstream = JSON.parse(upstreamBodies[0] ?? "{}") as Record<
      string,
      unknown
    >;
    expect(upstream.code_verifier).toBe("pkce-verifier");

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    // The SPA needs the short-lived access-token mirror; the long-lived
    // refresh token must stay inside the HttpOnly cookie.
    expect(body.token).toBe("steward-jwt");
    expect(body).not.toHaveProperty("refreshToken");

    const cookies = res.headers.getSetCookie().join("\n");
    expect(cookies).toContain("__Host-steward-token-v2=steward-jwt");
    expect(cookies).toContain(
      "__Host-steward-refresh-token-v2=steward-refresh",
    );
    expect(cookies).toContain("__Host-steward-authed-v2=1");
    expect(cookies).not.toContain("steward-refresh-token=steward-refresh");
    expect(
      res.headers
        .getSetCookie()
        .find((cookie) => cookie.startsWith("__Host-steward-token-v2=")),
    ).toContain(`Max-Age=${STEWARD_REFRESH_AUTHORITY_TTL_SECONDS}`);
    for (const cookie of res.headers.getSetCookie()) {
      expect(cookie).toContain("Path=/");
      expect(cookie).toContain("Secure");
      expect(cookie).not.toContain("Domain=");
    }
    expect(verifyCalls).toEqual(["steward-jwt"]);
  });

  test("does not publish cookies or bearer when logout wins during user sync", async () => {
    isBlockedBySsoBridgeLogout
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);

    const res = await postExchange(FIRST_PARTY, {
      code: "one-time-code",
      redirectUri: "https://eliza.app/login",
      codeVerifier: "pkce-verifier",
    });

    expect(res.status).toBe(401);
    expect((await res.json()) as { error: string; code: string }).toEqual({
      error: "Session was signed out",
      code: "session_ended",
    });
    expect(syncUserFromSteward).toHaveBeenCalledTimes(1);
    expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledTimes(2);
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  test("returns a distinct cooldown and publishes no authority for an ambiguous fresh token", async () => {
    logoutClassificationOverride = {
      status: "ambiguous_cooldown",
      retryAfterSeconds: 4,
      retryAtEpochSeconds: Math.floor(Date.now() / 1000) + 4,
    };

    const response = await postExchange(FIRST_PARTY, {
      code: "one-time-code",
      redirectUri: "https://eliza.app/login",
      codeVerifier: "pkce-verifier",
    });

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      code: "logout_cooldown",
      retryAfterSeconds: 4,
      error: expect.stringContaining("sign in again"),
    });
    expect(response.headers.get("retry-after")).toBe("4");
    expect(syncUserFromSteward).not.toHaveBeenCalled();
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  test("hardware checkout is bearer-only and emits zero cookies", async () => {
    const res = await postExchange(
      {
        origin: "https://elizaos.ai",
        "sec-fetch-site": "cross-site",
        "content-type": "application/json",
        [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
      },
      {
        code: "checkout-code",
        redirectUri: "https://elizaos.ai/checkout",
        codeVerifier: "checkout-verifier",
      },
      "https://api.eliza.app/api/auth/steward-nonce-exchange",
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ token: "steward-jwt" });
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  test("rejects every other direct cross-site nonce exchange", async () => {
    for (const headers of [
      {
        origin: "https://checkout.elizaos.ai",
        "sec-fetch-site": "cross-site",
      },
      { origin: "https://elizaos.ai", "sec-fetch-site": "same-site" },
      { origin: "https://api.eliza.app", "sec-fetch-site": "same-origin" },
    ]) {
      const res = await postExchange(
        {
          ...headers,
          "content-type": "application/json",
          [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
        },
        {
          code: "rejected-code",
          redirectUri: "https://elizaos.ai/checkout",
          codeVerifier: "rejected-verifier",
        },
        "https://api.eliza.app/api/auth/steward-nonce-exchange",
      );
      expect(res.status).toBe(403);
      expect(res.headers.getSetCookie()).toEqual([]);
    }
  });
});
