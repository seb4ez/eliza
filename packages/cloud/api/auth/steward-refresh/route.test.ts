// Exercises cloud API auth steward refresh route.test behavior with deterministic Worker route fixtures.
import { beforeEach, describe, expect, mock, test } from "bun:test";
import {
  STEWARD_CSRF_HEADER,
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
} from "@elizaos/shared/steward-session-client";
import { STEWARD_REFRESH_AUTHORITY_TTL_SECONDS } from "@/lib/auth/steward-cookies";

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

const verifyStewardRefreshLineageToken = mock<
  (_env: unknown, _token: string) => Promise<VerifiedStewardClaims | null>
>(async () => null);

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
  STEWARD_VERIFY_CLOCK_SKEW_SECONDS: 300,
  verifyStewardRefreshLineageToken,
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
  "sec-fetch-site": "same-origin",
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
    verifyStewardRefreshLineageToken.mockClear();
    verifyStewardRefreshLineageToken.mockResolvedValue(null);
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
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  test("does not return a re-mint when logout commits during the mint await", async () => {
    const issuedAt = Math.floor(Date.now() / 1000) - 60;
    verifyStewardTokenCached.mockResolvedValue({
      userId: "ordinary-user",
      email: "ordinary@example.com",
      tenantId: "elizacloud",
      expiration: issuedAt + 600,
      issuedAt,
    });
    isBlockedBySsoBridgeLogout
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);

    const response = await post({
      Authorization: "Bearer ordinary-jwt",
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "Session was signed out",
      code: "session_ended",
    });
    expect(mintStewardTokenFromClaims).toHaveBeenCalledTimes(1);
    expect(isBlockedBySsoBridgeLogout).toHaveBeenNthCalledWith(
      1,
      "ordinary-user",
      issuedAt,
    );
    expect(isBlockedBySsoBridgeLogout).toHaveBeenNthCalledWith(
      2,
      "ordinary-user",
      issuedAt,
    );
  });

  test("rejects every revoked Bearer with authoritative session_ended", async () => {
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

  test("fails every Bearer closed when the logout marker store is unavailable", async () => {
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

  test("rejects direct same-site and API-origin cookie refreshes", async () => {
    const headerCases: Array<Record<string, string>> = [
      {
        origin: "https://staging.eliza.app",
        "sec-fetch-site": "same-site",
      },
      {
        origin: "https://api-staging.eliza.app",
        "sec-fetch-site": "same-origin",
      },
      { origin: "https://staging.eliza.app" },
    ];
    for (const headers of headerCases) {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...headers,
            [STEWARD_CSRF_HEADER]: STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
            cookie: "steward-refresh-token-staging=staging-refresh",
          },
        }),
        { ...ENV, ENVIRONMENT: "staging" },
      );
      expect(response.status).toBe(403);
      expect(response.headers.getSetCookie()).toEqual([]);
    }
  });
});

describe("steward-refresh browser cookie cleanup", () => {
  beforeEach(() => {
    verifyStewardTokenCached.mockClear();
    verifyStewardRefreshLineageToken.mockClear();
    verifyStewardRefreshLineageToken.mockResolvedValue(null);
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

  test("rejects a lone v1 access cookie before verification, upstream, or mutation", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("access-cookie hydration must not call Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.eliza.app",
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

      expect(response.status).toBe(409);
      await expect(response.json()).resolves.toEqual({
        error: "Session upgrade requires a verified login token",
        code: "session_mutation_protocol_required",
      });
      expect(verifyStewardTokenCached).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(response.headers.getSetCookie()).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("tombstones v2 and clears current-environment credentials for a revoked session", async () => {
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
          origin: "https://staging.eliza.app",
          cookie:
            "steward-token=prod-access; steward-authed=1; __Host-steward-token-v2-staging=revoked-bridge-access; __Host-steward-authed-v2-staging=1",
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
    expect(cleared).toContain("__Host-steward-token-v2-staging");
    expect(cleared).toContain("__Host-steward-refresh-token-v2-staging");
    expect(cleared).toContain("steward-token-staging");
    expect(cleared).toContain("steward-authed-staging");
    expect(cleared).toContain("steward-refresh-token-staging");
    expect(cleared).not.toContain("steward-token");
    expect(cleared).not.toContain("steward-authed");
    expect(response.headers.getSetCookie()).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2-staging=0"),
      ]),
    );
  });

  test("legacy access-only recovery cannot delete account B cookies", async () => {
    const response = await app.fetch(
      new Request("https://api-staging.elizacloud.ai/", {
        method: "POST",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "__Host-steward-authed-v2-staging=1; __Host-steward-token-v2-staging=account-b-access; steward-token-staging=account-a-access; steward-authed-staging=1",
          [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
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

  test("rejects duplicate exact v2 cookie names before upstream or mutation", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("ambiguous cookie header must not reach Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.elizacloud.ai/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=first; __Host-steward-refresh-token-v2-staging=second; __Host-steward-authed-v2-staging=1",
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
      expect(fetchMock).not.toHaveBeenCalled();
      expect(response.headers.getSetCookie()).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("duplicate v1 cookie scopes are tombstoned without selecting or forwarding a credential", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("ambiguous legacy credential must not reach Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.request(
        "/",
        {
          method: "POST",
          headers: {
            host: "api-staging.elizacloud.ai",
            origin: "https://staging.eliza.app",
            "sec-fetch-site": "same-origin",
            [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
            cookie:
              "steward-token-staging=host; steward-token-staging=domain; steward-refresh-token-staging=host-refresh; steward-refresh-token-staging=domain-refresh; steward-authed-staging=1",
          },
        },
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(409);
      expect(fetchMock).not.toHaveBeenCalled();
      expect(verifyStewardTokenCached).not.toHaveBeenCalled();
      for (const name of [
        "steward-token-staging",
        "steward-refresh-token-staging",
        "steward-authed-staging",
      ]) {
        const clears = response.headers
          .getSetCookie()
          .filter((cookie) => cookie.startsWith(`${name}=`));
        expect(clears).toHaveLength(2);
        expect(
          clears.some((cookie) => cookie.includes("Domain=elizacloud.ai")),
        ).toBe(true);
        expect(clears.some((cookie) => !cookie.includes("Domain="))).toBe(true);
      }
      expect(response.headers.getSetCookie()).toEqual(
        expect.arrayContaining([
          expect.stringContaining("__Host-steward-authed-v2-staging=0"),
        ]),
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("keeps access cookies intact when the logout marker store is unavailable", async () => {
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
          origin: "https://staging.eliza.app",
          cookie:
            "__Host-steward-token-v2-staging=bridge-access; __Host-steward-authed-v2-staging=1",
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
            origin: "https://staging.eliza.app",
            "sec-fetch-site": "same-origin",
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

  test("retires an active v2 marker when both authoritative credentials are absent", async () => {
    const response = await app.fetch(
      new Request("https://api-staging.eliza.app/", {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          origin: "https://staging.eliza.app",
          cookie: "__Host-steward-authed-v2-staging=1",
        },
      }),
      { ...ENV, ENVIRONMENT: "staging" },
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      code: "missing_token",
    });
    expect(response.headers.getSetCookie()).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2-staging=0"),
      ]),
    );
  });

  test.each([
    ["legacy", STEWARD_CSRF_HEADER_VALUE],
    ["current", STEWARD_SESSION_MUTATION_PROTOCOL_VALUE],
  ])(
    "clears a stale v1 marker for the %s client without activating v2",
    async (_client, protocol) => {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            origin: "https://staging.eliza.app",
            "sec-fetch-site": "same-origin",
            [STEWARD_CSRF_HEADER]: protocol,
            cookie: "steward-authed-staging=1",
          },
        }),
        { ...ENV, ENVIRONMENT: "staging" },
      );

      expect(response.status).toBe(401);
      expect(deletedCookieNames(response)).toEqual(
        expect.arrayContaining([
          "steward-token-staging",
          "steward-authed-staging",
        ]),
      );
      expect(
        response.headers
          .getSetCookie()
          .some((cookie) => cookie.includes("-v2")),
      ).toBe(false);
    },
  );

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
            origin: "https://staging.eliza.app",
            cookie:
              "steward-refresh-token=prod-refresh; steward-authed=1; __Host-steward-refresh-token-v2-staging=staging-refresh; __Host-steward-authed-v2-staging=1",
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
      expect(response.headers.getSetCookie().join("\n")).not.toContain(
        "__Host-steward-authed-v2-staging",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("rejects a legacy cookie refresh after v2 activation", async () => {
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
            origin: "https://staging.eliza.app",
            "sec-fetch-site": "same-origin",
            cookie:
              "__Host-steward-authed-v2-staging=1; __Host-steward-token-v2-staging=account-b; steward-token-staging=account-a-access; steward-refresh-token-staging=account-a-refresh; steward-authed-staging=1",
            // The pre-Web-Locks bundle sent the CSRF marker but could not
            // attest the serialized session-mutation protocol.
            [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
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

  test("rejects cookie-only legacy refresh before activation", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("ambient legacy refresh must not reach Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            origin: "https://staging.eliza.app",
            "sec-fetch-site": "same-origin",
            [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
            cookie:
              "steward-token-staging=legacy-access; steward-refresh-token-staging=legacy-refresh; steward-authed-staging=1",
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
        error: "Session upgrade requires a verified login token",
        code: "session_mutation_protocol_required",
      });
      expect(verifyStewardTokenCached).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(response.headers.getSetCookie()).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("current refresh cannot promote ambient v1 credentials into v2", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("ambient legacy refresh must not reach Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            origin: "https://staging.eliza.app",
            cookie:
              "steward-token-staging=legacy-access; steward-refresh-token-staging=legacy-refresh; steward-authed-staging=1",
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
        error: "Session upgrade requires a verified login token",
        code: "session_mutation_protocol_required",
      });
      expect(verifyStewardTokenCached).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(response.headers.getSetCookie()).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("rejects a v1-to-v2 migration with no legacy access identity before upstream rotation", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("unbound legacy refresh must not reach Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            origin: "https://staging.eliza.app",
            cookie:
              "steward-refresh-token-staging=unbound-legacy-refresh; steward-authed-staging=1",
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
        error: "Session upgrade requires a verified login token",
        code: "session_mutation_protocol_required",
      });
      expect(verifyStewardTokenCached).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(response.headers.getSetCookie()).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("rejects an unverifiable v1 access identity before consuming its refresh", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("unverifiable legacy session must not reach Steward");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    verifyStewardTokenCached.mockResolvedValue(null);

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            origin: "https://staging.eliza.app",
            cookie:
              "steward-token-staging=expired-or-malformed-access; steward-refresh-token-staging=single-use-refresh; steward-authed-staging=1",
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
        error: "Session upgrade requires a verified login token",
        code: "session_mutation_protocol_required",
      });
      expect(verifyStewardTokenCached).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(response.headers.getSetCookie()).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("rotates an ordinary v2 refresh without requiring an access cookie", async () => {
    const originalFetch = globalThis.fetch;
    const nowSeconds = Math.floor(Date.now() / 1000);
    verifyStewardTokenCached.mockResolvedValue({
      userId: "steward-user-1",
      email: "user@example.com",
      tenantId: "elizacloud",
      expiration: nowSeconds + 3600,
      issuedAt: nowSeconds,
    });
    const fetchMock = mock(async () =>
      Response.json({
        ok: true,
        token: "fresh-v2-access",
        refreshToken: "fresh-v2-refresh",
        expiresAt: 1_800_000_000,
        expiresIn: 3600,
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=current-refresh; __Host-steward-authed-v2-staging=1",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(verifyStewardTokenCached).toHaveBeenCalledTimes(1);
      const setCookies = response.headers.getSetCookie().join("\n");
      expect(setCookies).toContain(
        "__Host-steward-token-v2-staging=fresh-v2-access",
      );
      expect(setCookies).toContain(
        "__Host-steward-refresh-token-v2-staging=fresh-v2-refresh",
      );
      expect(setCookies).toContain("__Host-steward-authed-v2-staging=1");
      const accessCookie = response.headers
        .getSetCookie()
        .find((cookie) =>
          cookie.startsWith("__Host-steward-token-v2-staging="),
        );
      expect(accessCookie).toContain(
        `Max-Age=${STEWARD_REFRESH_AUTHORITY_TTL_SECONDS}`,
      );
      for (const cookie of response.headers.getSetCookie()) {
        expect(cookie).toContain("Path=/");
        expect(cookie).toContain("Secure");
        expect(cookie).not.toContain("Domain=");
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("blocks a cryptographically expired pre-logout lineage before consuming its refresh", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () => {
      throw new Error("revoked lineage must not consume opaque refresh");
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const lineageIssuedAt = Math.floor(Date.now() / 1000) - 2 * 60 * 60;
    verifyStewardTokenCached.mockResolvedValue(null);
    verifyStewardRefreshLineageToken.mockResolvedValue({
      userId: "steward-user-1",
      email: "user@example.com",
      tenantId: "elizacloud",
      expiration: lineageIssuedAt + 60 * 60,
      issuedAt: lineageIssuedAt,
    });
    isBlockedBySsoBridgeLogout.mockResolvedValue(true);

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-token-v2-staging=expired-prelogout-lineage; __Host-steward-refresh-token-v2-staging=opaque-refresh; __Host-steward-authed-v2-staging=1",
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
      expect(verifyStewardRefreshLineageToken).toHaveBeenCalledWith(
        expect.anything(),
        "expired-prelogout-lineage",
      );
      expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledWith(
        "steward-user-1",
        lineageIssuedAt,
      );
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("allows a cryptographically expired post-logout lineage to rotate the same identity", async () => {
    const originalFetch = globalThis.fetch;
    const markerIssuedAt = Math.floor(Date.now() / 1000) - 3 * 60 * 60;
    const lineageIssuedAt = markerIssuedAt + 6;
    verifyStewardTokenCached.mockImplementation(async (_env, token) =>
      token === "fresh-postlogout-access"
        ? {
            userId: "steward-user-1",
            email: "user@example.com",
            tenantId: "elizacloud",
            expiration: Math.floor(Date.now() / 1000) + 60 * 60,
            issuedAt: Math.floor(Date.now() / 1000),
          }
        : null,
    );
    verifyStewardRefreshLineageToken.mockResolvedValue({
      userId: "steward-user-1",
      email: "user@example.com",
      tenantId: "elizacloud",
      expiration: lineageIssuedAt + 60 * 60,
      issuedAt: lineageIssuedAt,
    });
    isBlockedBySsoBridgeLogout.mockImplementation(
      async (_userId, issuedAt) => issuedAt <= markerIssuedAt + 5,
    );
    globalThis.fetch = mock(async () =>
      Response.json({
        ok: true,
        token: "fresh-postlogout-access",
        refreshToken: "fresh-postlogout-refresh",
        expiresAt: 1_800_000_000,
        expiresIn: 3600,
      }),
    ) as unknown as typeof fetch;

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-token-v2-staging=expired-postlogout-lineage; __Host-steward-refresh-token-v2-staging=postlogout-refresh; __Host-steward-authed-v2-staging=1",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(200);
      expect(verifyStewardRefreshLineageToken).toHaveBeenCalledWith(
        expect.anything(),
        "expired-postlogout-lineage",
      );
      expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledTimes(2);
      expect(response.headers.getSetCookie().join("\n")).toContain(
        `__Host-steward-token-v2-staging=fresh-postlogout-access; Max-Age=${STEWARD_REFRESH_AUTHORITY_TTL_SECONDS}`,
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("fails an opaque no-access refresh closed against any live logout marker", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () =>
      Response.json({
        ok: true,
        token: "fresh-v2-access",
        refreshToken: "fresh-v2-refresh",
        expiresAt: 1_800_000_000,
        expiresIn: 3600,
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    isBlockedBySsoBridgeLogout.mockResolvedValue(true);

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=opaque-refresh; __Host-steward-authed-v2-staging=1",
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
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledWith(
        "steward-user-1",
        0,
      );
      const cookies = response.headers.getSetCookie().join("\n");
      expect(cookies).not.toContain("=fresh-v2-access");
      expect(cookies).not.toContain("=fresh-v2-refresh");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("does not publish an opaque refresh when logout wins its final marker read", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = mock(async () =>
      Response.json({
        ok: true,
        token: "fresh-v2-access",
        refreshToken: "fresh-v2-refresh",
        expiresAt: 1_800_000_000,
        expiresIn: 3600,
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    isBlockedBySsoBridgeLogout
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);

    try {
      const response = await app.fetch(
        new Request("https://api-staging.eliza.app/", {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=opaque-refresh; __Host-steward-authed-v2-staging=1",
          },
        }),
        {
          ...ENV,
          ENVIRONMENT: "staging",
          STEWARD_API_URL: "https://steward.example.test",
        },
      );

      expect(response.status).toBe(401);
      expect(isBlockedBySsoBridgeLogout).toHaveBeenNthCalledWith(
        1,
        "steward-user-1",
        0,
      );
      expect(isBlockedBySsoBridgeLogout).toHaveBeenNthCalledWith(
        2,
        "steward-user-1",
        0,
      );
      const cookies = response.headers.getSetCookie().join("\n");
      expect(cookies).not.toContain("=fresh-v2-access");
      expect(cookies).not.toContain("=fresh-v2-refresh");
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
              origin: "https://staging.eliza.app",
              cookie:
                "steward-token=prod-access; steward-refresh-token=prod-refresh; __Host-steward-token-v2-staging=current-access-b; __Host-steward-refresh-token-v2-staging=stale-refresh-a; __Host-steward-authed-v2-staging=1",
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
          "__Host-steward-refresh-token-v2-staging",
        ]);
        expect(response.headers.getSetCookie()[0]).toContain("Secure");
        expect(response.headers.getSetCookie()[0]).toContain("Path=/");
        expect(response.headers.getSetCookie()[0]).not.toContain("Domain=");
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
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-token-v2-staging=old-same-identity-access; __Host-steward-refresh-token-v2-staging=old-same-identity-refresh; __Host-steward-authed-v2-staging=1",
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
        "__Host-steward-token-v2-staging=same-identity-access",
      );
      expect(setCookies).toContain(
        "__Host-steward-refresh-token-v2-staging=same-identity-refresh",
      );
      expect(setCookies).toContain("__Host-steward-authed-v2-staging=1");
      expect(setCookies).not.toContain(
        "steward-token-staging=same-identity-access",
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
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=staging-refresh; __Host-steward-authed-v2-staging=1",
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
        "https://staging.eliza.app",
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
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=staging-refresh; __Host-steward-authed-v2-staging=1",
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
            origin: "http://127.0.0.1:8787",
            cookie:
              "steward-refresh-token-v2-local=local-refresh; steward-authed-v2-local=1",
            "x-forwarded-for": "198.51.100.9, 198.51.100.10",
          },
        }),
        {
          ...ENV,
          NODE_ENV: "development",
          ENVIRONMENT: "local",
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
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=staging-refresh; __Host-steward-authed-v2-staging=1",
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
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=staging-refresh; __Host-steward-authed-v2-staging=1",
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
            origin: "https://staging.eliza.app",
            cookie:
              "__Host-steward-refresh-token-v2-staging=staging-refresh; __Host-steward-authed-v2-staging=1",
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
