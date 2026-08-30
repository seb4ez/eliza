// Exercises cloud API auth steward refresh route.test behavior with deterministic Worker route fixtures.
import { beforeEach, describe, expect, mock, test } from "bun:test";
import {
  STEWARD_CSRF_HEADER,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
} from "@elizaos/shared/steward-session-client";

type VerifiedStewardClaims = {
  userId: string;
  email: string;
  tenantId: string;
  expiration: number;
  issuedAt: number;
  bridged?: boolean;
};

const verifyStewardTokenCached = mock<
  (_env: unknown, _token: string) => Promise<VerifiedStewardClaims | null>
>(async () => ({
  userId: "steward-user-1",
  email: "user@example.com",
  tenantId: "elizacloud",
  expiration: Math.floor(Date.now() / 1000) + 60,
  issuedAt: Math.floor(Date.now() / 1000) - 60,
}));

const mintStewardTokenFromClaims = mock<
  (
    _env: unknown,
    _claims: VerifiedStewardClaims,
    _ttlSeconds: number,
  ) => Promise<{ token: string; expiresAt: number; expiresIn: number } | null>
>(async () => ({
  token: "fresh-steward-jwt",
  expiresAt: 1_800_000_000,
  expiresIn: 3600,
}));

const isBlockedBySsoBridgeLogout = mock<
  (_userId: string, _issuedAt: number) => Promise<boolean>
>(async () => false);

mock.module("@/lib/auth/steward-client", () => ({
  STEWARD_AUTH_UPSTREAM_TIMEOUT_MS: 25_000,
  verifyStewardTokenCached,
  mintStewardTokenFromClaims,
}));

mock.module("@/lib/steward/sign", () => ({
  signStewardMutatingRequest: mock(async () => undefined),
}));

mock.module("@/lib/services/sso-bridge-codes", () => ({
  isBlockedBySsoBridgeLogout,
}));

mock.module("@/lib/utils/logger", () => ({
  logger: {
    error: mock(() => undefined),
    info: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const { default: app } = await import("./route");

const ENV = {
  NODE_ENV: "production",
  STEWARD_JWT_SECRET: "secret",
  STEWARD_TENANT_ID: "elizacloud",
};

const MUTATION_PROTOCOL_HEADERS = {
  [STEWARD_CSRF_HEADER]: STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
} as const;

function post(headers: HeadersInit = {}) {
  return app.fetch(
    new Request("https://api.elizacloud.ai/", {
      method: "POST",
      headers,
    }),
    ENV,
  );
}

function deletedCookieNames(res: Response): string[] {
  return res.headers
    .getSetCookie()
    .filter((cookie) => /Max-Age=0/i.test(cookie))
    .map((cookie) => cookie.split("=")[0]);
}

describe("steward-refresh bearer rotation", () => {
  beforeEach(() => {
    verifyStewardTokenCached.mockClear();
    mintStewardTokenFromClaims.mockClear();
    isBlockedBySsoBridgeLogout.mockClear();
    isBlockedBySsoBridgeLogout.mockResolvedValue(false);
    verifyStewardTokenCached.mockResolvedValue({
      userId: "steward-user-1",
      email: "user@example.com",
      tenantId: "elizacloud",
      expiration: Math.floor(Date.now() / 1000) + 60,
      issuedAt: Math.floor(Date.now() / 1000) - 60,
    });
    mintStewardTokenFromClaims.mockResolvedValue({
      token: "fresh-steward-jwt",
      expiresAt: 1_800_000_000,
      expiresIn: 3600,
    });
  });

  test("accepts native Bearer refresh without browser Origin or refresh cookie", async () => {
    const response = await post({
      Authorization: "Bearer near-expiry-steward-jwt",
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      ok: true,
      token: "fresh-steward-jwt",
      expiresAt: 1_800_000_000,
      expiresIn: 3600,
    });
    expect(verifyStewardTokenCached).toHaveBeenCalledWith(
      expect.objectContaining({ STEWARD_JWT_SECRET: "secret" }),
      "near-expiry-steward-jwt",
    );
    expect(mintStewardTokenFromClaims).toHaveBeenCalledWith(
      expect.objectContaining({ STEWARD_JWT_SECRET: "secret" }),
      expect.objectContaining({ userId: "steward-user-1" }),
      3600,
    );
  });

  test("rejects a revoked bridge-issued Bearer with authoritative session_ended", async () => {
    const issuedAt = Math.floor(Date.now() / 1000) - 60;
    verifyStewardTokenCached.mockResolvedValue({
      userId: "bridged-user",
      email: "bridged@example.com",
      tenantId: "elizacloud",
      expiration: issuedAt + 600,
      issuedAt,
      bridged: true,
    });
    isBlockedBySsoBridgeLogout.mockResolvedValue(true);

    const response = await post({
      Authorization: "Bearer revoked-bridge-jwt",
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "Session was signed out",
      code: "session_ended",
    });
    expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledWith(
      "bridged-user",
      issuedAt,
    );
    expect(mintStewardTokenFromClaims).not.toHaveBeenCalled();
  });

  test("fails a bridge-issued Bearer closed when the logout marker store is unavailable", async () => {
    verifyStewardTokenCached.mockResolvedValue({
      userId: "bridged-user",
      email: "bridged@example.com",
      tenantId: "elizacloud",
      expiration: Math.floor(Date.now() / 1000) + 600,
      issuedAt: Math.floor(Date.now() / 1000) - 60,
      bridged: true,
    });
    isBlockedBySsoBridgeLogout.mockImplementation(async () => {
      throw new Error("marker store unavailable");
    });

    const response = await post({
      Authorization: "Bearer bridge-jwt-during-outage",
    });

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "SSO bridge unavailable",
      code: "sso_unavailable",
    });
    expect(mintStewardTokenFromClaims).not.toHaveBeenCalled();
  });

  test("rejects invalid Bearer refresh before falling back to cookie refresh", async () => {
    verifyStewardTokenCached.mockResolvedValue(null);

    const response = await post({
      Authorization: "Bearer expired-steward-jwt",
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "Invalid token",
      code: "invalid_token",
    });
    expect(mintStewardTokenFromClaims).not.toHaveBeenCalled();
  });

  test("keeps the browser cookie path origin-gated when no Bearer token is supplied", async () => {
    const response = await post();

    expect(response.status).toBe(403);
    expect(verifyStewardTokenCached).not.toHaveBeenCalled();
    expect(mintStewardTokenFromClaims).not.toHaveBeenCalled();
  });
});

describe("steward-refresh browser cookie cleanup", () => {
  beforeEach(() => {
    verifyStewardTokenCached.mockClear();
    mintStewardTokenFromClaims.mockClear();
    isBlockedBySsoBridgeLogout.mockClear();
    isBlockedBySsoBridgeLogout.mockResolvedValue(false);
    verifyStewardTokenCached.mockResolvedValue({
      userId: "steward-user-1",
      email: "user@example.com",
      tenantId: "elizacloud",
      expiration: Math.floor(Date.now() / 1000) + 60,
      issuedAt: Math.floor(Date.now() / 1000) - 60,
    });
  });

  test("hydrates a valid first-party access cookie without a refresh cookie or mutation", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("access-cookie hydration must not call Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const expiration = Math.floor(Date.now() / 1000) + 300;
    verifyStewardTokenCached.mockResolvedValue({
      userId: "steward-user-1",
      email: "user@example.com",
      tenantId: "elizacloud",
      expiration,
      issuedAt: expiration - 60,
    });

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie:
              "steward-token-staging=committed-access-token; steward-authed-staging=1",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        ok: true,
        token: "committed-access-token",
        expiresAt: expiration,
        expiresIn: expect.any(Number),
      });
      expect(verifyStewardTokenCached).toHaveBeenCalledWith(
        expect.objectContaining({ ENVIRONMENT: "staging" }),
        "committed-access-token",
      );
      expect(fetchMock).not.toHaveBeenCalled();
      expect(response.headers.getSetCookie()).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("clears only current-environment access cookies for a revoked bridged access-cookie session", async () => {
    const issuedAt = Math.floor(Date.now() / 1000) - 60;
    verifyStewardTokenCached.mockResolvedValue({
      userId: "bridged-user",
      email: "bridged@example.com",
      tenantId: "elizacloud",
      expiration: issuedAt + 600,
      issuedAt,
      bridged: true,
    });
    isBlockedBySsoBridgeLogout.mockResolvedValue(true);

    const response = await app.fetch(
      new Request("https://api-staging.elizacloud.ai/", {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.elizacloud.ai",
          cookie:
            "steward-token=prod-access; steward-authed=1; steward-token-staging=revoked-bridge-access; steward-authed-staging=1",
        },
      }),
      {
        ...ENV,
        ENVIRONMENT: "staging",
        STEWARD_API_URL: "https://steward.example.test",
      },
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "Session was signed out",
      code: "session_ended",
    });
    const cleared = deletedCookieNames(response);
    expect(cleared).toContain("steward-token-staging");
    expect(cleared).toContain("steward-authed-staging");
    expect(cleared).not.toContain("steward-refresh-token-staging");
    expect(cleared).not.toContain("steward-token");
    expect(cleared).not.toContain("steward-authed");
  });

  test("legacy access-only recovery cannot delete account B cookies", async () => {
    const response = await app.fetch(
      new Request("https://api-staging.elizacloud.ai/", {
        method: "POST",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.elizacloud.ai",
          cookie:
            "steward-token-staging=account-a-access; steward-authed-staging=1",
          [STEWARD_CSRF_HEADER]: "1",
        },
      }),
      {
        ...ENV,
        ENVIRONMENT: "staging",
        STEWARD_API_URL: "https://steward.example.test",
      },
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      code: "session_mutation_protocol_required",
    });
    expect(verifyStewardTokenCached).not.toHaveBeenCalled();
    expect(isBlockedBySsoBridgeLogout).not.toHaveBeenCalled();
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  test("keeps access cookies intact when the bridged logout marker store is unavailable", async () => {
    verifyStewardTokenCached.mockResolvedValue({
      userId: "bridged-user",
      email: "bridged@example.com",
      tenantId: "elizacloud",
      expiration: Math.floor(Date.now() / 1000) + 600,
      issuedAt: Math.floor(Date.now() / 1000) - 60,
      bridged: true,
    });
    isBlockedBySsoBridgeLogout.mockImplementation(async () => {
      throw new Error("marker store unavailable");
    });

    const response = await app.fetch(
      new Request("https://api-staging.elizacloud.ai/", {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.elizacloud.ai",
          cookie:
            "steward-token-staging=bridge-access; steward-authed-staging=1",
        },
      }),
      {
        ...ENV,
        ENVIRONMENT: "staging",
        STEWARD_API_URL: "https://steward.example.test",
      },
    );

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "SSO bridge unavailable",
      code: "sso_unavailable",
    });
    expect(deletedCookieNames(response)).toEqual([]);
  });

  test("staging legacy-only refresh cookie is not read or forwarded", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("legacy refresh cookie must not reach Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie: "steward-refresh-token=prod-refresh; steward-authed=1",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toEqual({
        error: "Refresh token required",
        code: "missing_token",
      });
      expect(fetchMock).not.toHaveBeenCalled();
      expect(deletedCookieNames(response)).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("invalid refresh clears NO cookies (rotation-race safety, #13728 env-scoping holds trivially)", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () => {
      return new Response(
        JSON.stringify({ ok: false, error: "refresh rejected" }),
        { status: 401, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie:
              "steward-refresh-token=prod-refresh; steward-authed=1; steward-refresh-token-staging=staging-refresh; steward-authed-staging=1",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(401);
      // A Steward 401 also fires for the LOSER of a refresh-rotation race
      // (single-use tokens, one domain-wide cookie shared by console + app
      // tabs). Clearing cookies here nuked the whole session on every lost
      // race — the winner's fresh cookies included. The route now clears
      // NOTHING on 401: the race self-heals from the winner's Set-Cookie,
      // and a genuinely dead token keeps 401ing into the login surface.
      // The #13728 env-scoping invariant (staging must never clear prod
      // cookies) holds trivially.
      const cleared = deletedCookieNames(response);
      expect(cleared).toHaveLength(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("rejects a legacy cookie refresh before upstream work or Set-Cookie", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("legacy refresh must not reach Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie:
              "steward-token-staging=account-a-access; steward-refresh-token-staging=account-a-refresh; steward-authed-staging=1",
            // The pre-Web-Locks bundle sent the CSRF marker but could not
            // attest the serialized session-mutation protocol.
            [STEWARD_CSRF_HEADER]: "1",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(409);
      await expect(response.json()).resolves.toEqual({
        error: "Session refresh client update required",
        code: "session_mutation_protocol_required",
      });
      expect(fetchMock).not.toHaveBeenCalled();
      expect(verifyStewardTokenCached).not.toHaveBeenCalled();
      expect(response.headers.getSetCookie()).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("rejects stale refresh A before it can overwrite access-only identity B", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () =>
      Response.json({
        ok: true,
        token: "rotated-refresh-access",
        refreshToken: "rotated-refresh-cookie",
        expiresAt: 1_800_000_000,
        expiresIn: 3600,
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const cases = [
      {
        label: "different user in the same tenant",
        current: { userId: "access-user-b", tenantId: "elizacloud" },
        refreshed: { userId: "refresh-user-a", tenantId: "elizacloud" },
      },
      {
        label: "same user in a different tenant",
        current: {
          userId: "shared-user",
          tenantId: "personal-shared-user",
        },
        refreshed: { userId: "shared-user", tenantId: "elizacloud" },
      },
    ] as const;

    try {
      for (const identityCase of cases) {
        verifyStewardTokenCached.mockImplementation(async (_env, token) => {
          const identity =
            token === "current-access-b"
              ? identityCase.current
              : identityCase.refreshed;
          return {
            ...identity,
            email: "user@example.com",
            expiration: Math.floor(Date.now() / 1000) + 600,
            issuedAt: Math.floor(Date.now() / 1000) - 60,
          };
        });

        const response = await app.fetch(
          new Request("https://api-staging.elizacloud.ai/", {
            method: "POST",
            headers: {
              ...MUTATION_PROTOCOL_HEADERS,
              host: "api-staging.elizacloud.ai",
              origin: "https://staging.elizacloud.ai",
              cookie:
                "steward-token=prod-access; steward-refresh-token=prod-refresh; steward-token-staging=current-access-b; steward-refresh-token-staging=stale-refresh-a; steward-authed-staging=1",
            },
          }),
          {
            ...ENV,
            ENVIRONMENT: "staging",
            STEWARD_API_URL: "https://steward.example.test",
          },
        );

        expect(response.status).toBe(401);
        await expect(response.json()).resolves.toEqual({
          error: "Refresh token does not match current session",
          code: "invalid_token",
        });
        expect(deletedCookieNames(response)).toEqual([
          "steward-refresh-token-staging",
        ]);
        const setCookies = response.headers.getSetCookie().join("\n");
        expect(setCookies).not.toContain(
          "steward-token-staging=rotated-refresh-access",
        );
        expect(setCookies).not.toContain("steward-refresh-token=prod-refresh");
      }
      expect(fetchMock).toHaveBeenCalledTimes(cases.length);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("allows a normal same-identity refresh rotation and sets its fresh cookies", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () =>
      Response.json({
        ok: true,
        token: "same-identity-access",
        refreshToken: "same-identity-refresh",
        expiresAt: 1_800_000_000,
        expiresIn: 3600,
      }),
    ) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie:
              "steward-token-staging=old-same-identity-access; steward-refresh-token-staging=old-same-identity-refresh",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(200);
      const setCookies = response.headers.getSetCookie().join("\n");
      expect(setCookies).toContain(
        "steward-token-staging=same-identity-access",
      );
      expect(setCookies).toContain(
        "steward-refresh-token-staging=same-identity-refresh",
      );
      expect(deletedCookieNames(response)).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("forwards the trusted client identity without forwarding browser credentials", async () => {
    const originalFetch = globalThis.fetch;
    const forwarded = { headers: null as Headers | null };
    globalThis.fetch = mock(async (_input, init) => {
      forwarded.headers = new Headers(init?.headers);
      return Response.json(
        { ok: false, error: "refresh rejected" },
        { status: 401 },
      );
    }) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie: "steward-refresh-token-staging=staging-refresh",
            "cf-connecting-ip": "203.0.113.40",
            "x-forwarded-for": "198.51.100.9, 198.51.100.10",
            "user-agent": "Eliza Browser Test",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(401);
      expect(forwarded.headers?.get("x-forwarded-for")).toBe("203.0.113.40");
      expect(forwarded.headers?.get("origin")).toBe(
        "https://staging.elizacloud.ai",
      );
      expect(forwarded.headers?.get("user-agent")).toBe("Eliza Browser Test");
      expect(forwarded.headers?.has("cookie")).toBe(false);
      expect(forwarded.headers?.has("authorization")).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("ignores caller-controlled forwarding identity away from loopback", async () => {
    const originalFetch = globalThis.fetch;
    const forwarded = { headers: null as Headers | null };
    globalThis.fetch = mock(async (_input, init) => {
      forwarded.headers = new Headers(init?.headers);
      return Response.json(
        { ok: false, error: "refresh rejected" },
        { status: 401 },
      );
    }) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie: "steward-refresh-token-staging=staging-refresh",
            "x-real-ip": "198.51.100.8",
            "x-forwarded-for": "198.51.100.9, 198.51.100.10",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(401);
      expect(forwarded.headers?.has("x-forwarded-for")).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("allows the forwarding fallback only on a direct loopback request", async () => {
    const originalFetch = globalThis.fetch;
    const forwarded = { headers: null as Headers | null };
    globalThis.fetch = mock(async (_input, init) => {
      forwarded.headers = new Headers(init?.headers);
      return Response.json(
        { ok: false, error: "refresh rejected" },
        { status: 401 },
      );
    }) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("http://127.0.0.1:8787/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "127.0.0.1:8787",
            origin: "http://127.0.0.1:5173",
            cookie: "steward-refresh-token-staging=staging-refresh",
            "x-forwarded-for": "198.51.100.9, 198.51.100.10",
          },
        }),
        {
          ...ENV,
          NODE_ENV: "development",
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(401);
      expect(forwarded.headers?.get("x-forwarded-for")).toBe("198.51.100.9");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("fails closed on forwarding identity for a production loopback URL", async () => {
    const originalFetch = globalThis.fetch;
    const forwarded = { headers: null as Headers | null };
    globalThis.fetch = mock(async (_input, init) => {
      forwarded.headers = new Headers(init?.headers);
      return Response.json(
        { ok: false, error: "refresh rejected" },
        { status: 401 },
      );
    }) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("http://127.0.0.1:8787/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "127.0.0.1:8787",
            origin: "https://cloud.eliza.app",
            cookie: "steward-refresh-token-staging=staging-refresh",
            "x-forwarded-for": "198.51.100.9",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(401);
      expect(forwarded.headers?.has("x-forwarded-for")).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("preserves Steward throttling as a retryable 429 instead of an opaque 502", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () =>
      Response.json(
        { ok: false, error: "Too many requests. Please try again later." },
        { status: 429, headers: { "Retry-After": "60" } },
      ),
    ) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie: "steward-refresh-token-staging=staging-refresh",
            "cf-connecting-ip": "203.0.113.40",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toBe("60");
      await expect(response.json()).resolves.toEqual({
        error: "Too many refresh attempts. Wait a moment and try again.",
        code: "internal_error",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("does not reflect a non-JSON upstream error page into the browser", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(
      async () =>
        new Response("<html>upstream private diagnostic</html>", {
          status: 502,
          headers: { "content-type": "text/html" },
        }),
    ) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.elizacloud.ai",
            cookie: "steward-refresh-token-staging=staging-refresh",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(502);
      await expect(response.json()).resolves.toEqual({
        error: "Steward refresh failed",
        code: "internal_error",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
