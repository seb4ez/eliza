/**
 * Logout enforces the Steward mutation origin policy while keeping production
 * and staging cookie names isolated. The harness mocks teardown collaborators
 * but exercises the real route and cookie headers.
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  mock,
  setSystemTime,
  test,
} from "bun:test";
import {
  STEWARD_CSRF_HEADER,
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
} from "@elizaos/shared/steward-session-client";
import { STEWARD_REFRESH_AUTHORITY_TTL_SECONDS } from "@/lib/auth/steward-cookies";

const MUTATION_PROTOCOL_HEADERS = {
  [STEWARD_CSRF_HEADER]: STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  "sec-fetch-site": "same-origin",
};

const getCurrentUserMock = mock(
  async (): Promise<{ id: string; organization_id: string } | null> => null,
);
const readStewardSessionTokenMock = mock((): string | null => null);
type TestStewardClaims = { userId: string; issuedAt: number };
type TestCloudUser = { id: string; organization_id: string };
const getExistingUserForVerifiedStewardClaimsMock = mock<
  (
    _context: unknown,
    _claims: TestStewardClaims,
  ) => Promise<TestCloudUser | null>
>(async () => null);
const endAllUserSessionsMock = mock<(_userId: string) => Promise<void>>(
  async () => undefined,
);
const verifyStewardTokenMock = mock<
  (_env: unknown, _token: string) => Promise<TestStewardClaims | null>
>(async () => ({
  userId: "steward-1",
  issuedAt: 100,
}));
const verifyStewardRefreshLineageTokenMock = mock<
  (_env: unknown, _token: string) => Promise<TestStewardClaims | null>
>(async () => null);
const revokeInferenceSessionsThroughMock = mock<
  (_organizationId: string, _userId: string, _issuedAt: number) => Promise<void>
>(async () => undefined);
const markSsoBridgeLogoutMock = mock<(_stewardUserId: string) => Promise<void>>(
  async () => undefined,
);
const invalidateSessionCachesMock = mock<(_token: string) => Promise<void>>(
  async () => undefined,
);

mock.module("@/lib/auth", () => ({
  invalidateSessionCaches: invalidateSessionCachesMock,
}));

mock.module("@/lib/auth/workers-hono-auth", () => ({
  getCurrentUser: getCurrentUserMock,
  getExistingUserForVerifiedStewardClaims:
    getExistingUserForVerifiedStewardClaimsMock,
  readStewardSessionToken: readStewardSessionTokenMock,
}));
mock.module("@/lib/auth/steward-client", () => ({
  verifyStewardRefreshLineageToken: verifyStewardRefreshLineageTokenMock,
  verifyStewardTokenCached: verifyStewardTokenMock,
}));

mock.module("@/lib/middleware/rate-limit-hono-cloudflare", () => ({
  getRequestIp: () => undefined,
  RateLimitPresets: { STANDARD: {} },
  rateLimit: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));

mock.module("@/lib/services/user-sessions", () => ({
  userSessionsService: {
    endAllUserSessions: endAllUserSessionsMock,
  },
}));
mock.module("@/lib/services/inference-credential-revocation", () => ({
  isInferenceStrongRevocationEnabled: (env: Record<string, unknown>) =>
    env.INFERENCE_STRONG_REVOCATION_ENABLED === "true",
  revokeInferenceSessionsThrough: revokeInferenceSessionsThroughMock,
}));
mock.module("@/lib/services/sso-bridge-codes", () => ({
  markSsoBridgeLogout: markSsoBridgeLogoutMock,
}));

mock.module("@/api-app/services/audit-dispatcher-singleton", () => ({
  getAuditDispatcher: () => ({
    emit: mock(async () => undefined),
  }),
}));

mock.module("@/lib/utils/logger", () => ({
  logger: {
    debug: mock(() => undefined),
    error: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const { default: app } = await import("./route");

const ACCOUNT_A_TOKEN = "account-a.jwt.signature";
const ACCOUNT_B_TOKEN = "account-b.jwt.signature";

function requestDistinctV2Logout() {
  return app.request(
    "/",
    {
      method: "POST",
      headers: {
        ...MUTATION_PROTOCOL_HEADERS,
        host: "api.elizacloud.ai",
        origin: "https://eliza.app",
        authorization: `Bearer ${ACCOUNT_A_TOKEN}`,
        cookie: `__Host-steward-authed-v2=1; __Host-steward-token-v2=${ACCOUNT_B_TOKEN}`,
      },
    },
    {
      ENVIRONMENT: "production",
      NODE_ENV: "production",
      INFERENCE_STRONG_REVOCATION_ENABLED: "true",
    },
  );
}

function requestProductionV2LogoutWithCookie(cookie: string) {
  return app.request(
    "/",
    {
      method: "POST",
      headers: {
        ...MUTATION_PROTOCOL_HEADERS,
        host: "api.elizacloud.ai",
        origin: "https://eliza.app",
        authorization: `Bearer ${ACCOUNT_A_TOKEN}`,
        cookie,
      },
    },
    { ENVIRONMENT: "production", NODE_ENV: "production" },
  );
}

function arrangeDistinctVerifiedIdentities(): void {
  readStewardSessionTokenMock.mockReturnValue(ACCOUNT_A_TOKEN);
  verifyStewardTokenMock.mockImplementation(async (_env, token) => {
    if (token === ACCOUNT_A_TOKEN) {
      return { userId: "steward-a", issuedAt: 101 };
    }
    if (token === ACCOUNT_B_TOKEN) {
      return { userId: "steward-b", issuedAt: 202 };
    }
    return null;
  });
  getExistingUserForVerifiedStewardClaimsMock.mockImplementation(
    async (_context, claims) => ({
      id: claims.userId === "steward-a" ? "cloud-a" : "cloud-b",
      organization_id: claims.userId === "steward-a" ? "org-a" : "org-b",
    }),
  );
}

function deletedCookieNames(res: Response): string[] {
  return res.headers
    .getSetCookie()
    .filter((cookie) => /Max-Age=0/i.test(cookie))
    .map((cookie) => cookie.split("=")[0]);
}

function setCookieHeaders(res: Response): string[] {
  return res.headers.getSetCookie();
}

beforeEach(() => {
  getCurrentUserMock.mockClear();
  getCurrentUserMock.mockResolvedValue(null);
  readStewardSessionTokenMock.mockClear();
  readStewardSessionTokenMock.mockReturnValue(null);
  verifyStewardTokenMock.mockClear();
  verifyStewardTokenMock.mockResolvedValue({
    userId: "steward-1",
    issuedAt: 100,
  });
  verifyStewardRefreshLineageTokenMock.mockClear();
  verifyStewardRefreshLineageTokenMock.mockResolvedValue(null);
  revokeInferenceSessionsThroughMock.mockClear();
  revokeInferenceSessionsThroughMock.mockResolvedValue(undefined);
  markSsoBridgeLogoutMock.mockClear();
  markSsoBridgeLogoutMock.mockResolvedValue(undefined);
  getExistingUserForVerifiedStewardClaimsMock.mockResolvedValue(null);
  getExistingUserForVerifiedStewardClaimsMock.mockClear();
  invalidateSessionCachesMock.mockClear();
  endAllUserSessionsMock.mockClear();
});

afterEach(() => {
  setSystemTime();
});

describe("POST /api/auth/logout cookie clearing", () => {
  test("stamps logout authority for a bearer-authenticated hosted session", async () => {
    readStewardSessionTokenMock.mockReturnValue("header.payload.signature");

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api-staging.elizacloud.ai",
          origin: "https://cloud-staging.eliza.app",
          authorization: "Bearer header.payload.signature",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    expect(setCookieHeaders(res)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2-staging=0"),
      ]),
    );
    expect(verifyStewardTokenMock).toHaveBeenCalledWith(
      expect.anything(),
      "header.payload.signature",
    );
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledWith("steward-1");
  });

  test("revokes bearer A and committed HttpOnly cookie B before clearing either session", async () => {
    arrangeDistinctVerifiedIdentities();

    const res = await requestDistinctV2Logout();

    expect(res.status).toBe(200);
    expect(verifyStewardTokenMock.mock.calls.map((call) => call[1])).toEqual([
      ACCOUNT_A_TOKEN,
      ACCOUNT_B_TOKEN,
    ]);
    expect(revokeInferenceSessionsThroughMock.mock.calls).toEqual([
      ["org-a", "cloud-a", 101],
      ["org-b", "cloud-b", 202],
    ]);
    expect(markSsoBridgeLogoutMock.mock.calls).toEqual([
      ["steward-a"],
      ["steward-b"],
    ]);
    expect(invalidateSessionCachesMock.mock.calls).toEqual([
      [ACCOUNT_A_TOKEN],
      [ACCOUNT_B_TOKEN],
    ]);
    expect(endAllUserSessionsMock.mock.calls).toEqual([
      ["cloud-a"],
      ["cloud-b"],
    ]);
    expect(deletedCookieNames(res)).toContain("__Host-steward-token-v2");
    expect(setCookieHeaders(res)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2=0"),
      ]),
    );
  });

  test("deduplicates one identity while keeping the newest strong-revocation boundary", async () => {
    readStewardSessionTokenMock.mockReturnValue(ACCOUNT_A_TOKEN);
    verifyStewardTokenMock.mockImplementation(async (_env, token) => ({
      userId: "steward-shared",
      issuedAt: token === ACCOUNT_A_TOKEN ? 101 : 202,
    }));
    getExistingUserForVerifiedStewardClaimsMock.mockResolvedValue({
      id: "cloud-shared",
      organization_id: "org-shared",
    });

    const res = await requestDistinctV2Logout();

    expect(res.status).toBe(200);
    expect(revokeInferenceSessionsThroughMock.mock.calls).toEqual([
      ["org-shared", "cloud-shared", 202],
    ]);
    expect(markSsoBridgeLogoutMock.mock.calls).toEqual([["steward-shared"]]);
    expect(endAllUserSessionsMock.mock.calls).toEqual([["cloud-shared"]]);
    expect(invalidateSessionCachesMock.mock.calls).toEqual([
      [ACCOUNT_A_TOKEN],
      [ACCOUNT_B_TOKEN],
    ]);
  });

  test("keeps both verified marker identities when one strong user lookup fails", async () => {
    arrangeDistinctVerifiedIdentities();
    getExistingUserForVerifiedStewardClaimsMock.mockImplementation(
      async (_context, claims) => {
        if (claims.userId === "steward-b") {
          throw new Error("user lookup unavailable");
        }
        return { id: "cloud-a", organization_id: "org-a" };
      },
    );

    const res = await requestDistinctV2Logout();

    expect(res.status).toBe(503);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(revokeInferenceSessionsThroughMock.mock.calls).toEqual([
      ["org-a", "cloud-a", 101],
    ]);
    expect(markSsoBridgeLogoutMock.mock.calls).toEqual([
      ["steward-a"],
      ["steward-b"],
    ]);
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
  });

  test("preserves cookie B on a partial marker failure, then clears it only after a successful A+B retry", async () => {
    arrangeDistinctVerifiedIdentities();
    let failCookieIdentity = true;
    markSsoBridgeLogoutMock.mockImplementation(async (stewardUserId) => {
      if (stewardUserId === "steward-b" && failCookieIdentity) {
        throw new Error("cookie identity marker unavailable");
      }
    });

    const failedResponse = await requestDistinctV2Logout();

    expect(failedResponse.status).toBe(503);
    expect(failedResponse.headers.getSetCookie()).toEqual([]);
    expect(markSsoBridgeLogoutMock.mock.calls).toEqual([
      ["steward-a"],
      ["steward-b"],
      ["steward-b"],
    ]);
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();

    failCookieIdentity = false;
    const retryResponse = await requestDistinctV2Logout();

    expect(retryResponse.status).toBe(200);
    expect(markSsoBridgeLogoutMock.mock.calls.slice(3)).toEqual([
      ["steward-a"],
      ["steward-b"],
    ]);
    expect(deletedCookieNames(retryResponse)).toContain(
      "__Host-steward-token-v2",
    );
    expect(setCookieHeaders(retryResponse)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2=0"),
      ]),
    );
  });

  test("ignores invalid bearer A as non-authority while revoking valid cookie B", async () => {
    arrangeDistinctVerifiedIdentities();
    verifyStewardTokenMock.mockImplementation(async (_env, token) => {
      if (token === ACCOUNT_B_TOKEN) {
        return { userId: "steward-b", issuedAt: 202 };
      }
      return null;
    });

    const res = await requestDistinctV2Logout();

    expect(res.status).toBe(200);
    expect(verifyStewardRefreshLineageTokenMock).toHaveBeenCalledWith(
      expect.anything(),
      ACCOUNT_A_TOKEN,
    );
    expect(revokeInferenceSessionsThroughMock.mock.calls).toEqual([
      ["org-b", "cloud-b", 202],
    ]);
    expect(markSsoBridgeLogoutMock.mock.calls).toEqual([["steward-b"]]);
    expect(invalidateSessionCachesMock.mock.calls).toEqual([[ACCOUNT_B_TOKEN]]);
    expect(deletedCookieNames(res)).toContain("__Host-steward-token-v2");
  });

  test("refuses ambiguous v2 cookie authority without destroying it, even after stamping bearer A", async () => {
    readStewardSessionTokenMock.mockReturnValue(ACCOUNT_A_TOKEN);

    const res = await requestProductionV2LogoutWithCookie(
      "__Host-steward-authed-v2=1; __Host-steward-token-v2=first.jwt.signature; __Host-steward-token-v2=second.jwt.signature",
    );

    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(markSsoBridgeLogoutMock.mock.calls).toEqual([["steward-1"]]);
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
  });

  test("refuses refresh-only v2 cookie authority without destroying it", async () => {
    readStewardSessionTokenMock.mockReturnValue(ACCOUNT_A_TOKEN);

    const res = await requestProductionV2LogoutWithCookie(
      "__Host-steward-authed-v2=1; __Host-steward-refresh-token-v2=opaque-refresh-authority",
    );

    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(markSsoBridgeLogoutMock.mock.calls).toEqual([["steward-1"]]);
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
  });

  test("resolves an expired v2 access cookie through signed lineage before clearing it", async () => {
    const expiredCookieToken = "expired.cookie.lineage";
    const lineageClaims = { userId: "steward-cookie", issuedAt: 303 };
    verifyStewardTokenMock.mockResolvedValueOnce(null);
    verifyStewardRefreshLineageTokenMock.mockResolvedValueOnce(lineageClaims);

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: `__Host-steward-authed-v2=1; __Host-steward-token-v2=${expiredCookieToken}`,
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    expect(verifyStewardRefreshLineageTokenMock).toHaveBeenCalledWith(
      expect.anything(),
      expiredCookieToken,
    );
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledWith("steward-cookie");
    expect(deletedCookieNames(res)).toContain("__Host-steward-token-v2");
  });

  test("rejects a hosted bearer when neither access auth nor signed lineage verifies", async () => {
    const bearer = "unverifiable.hosted.bearer";
    readStewardSessionTokenMock.mockReturnValue(bearer);
    verifyStewardTokenMock.mockResolvedValueOnce(null);

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api-staging.elizacloud.ai",
          origin: "https://cloud-staging.eliza.app",
          authorization: `Bearer ${bearer}`,
          cookie: `__Host-steward-authed-v2-staging=1; __Host-steward-token-v2-staging=${bearer}`,
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(401);
    expect(verifyStewardRefreshLineageTokenMock).toHaveBeenCalledWith(
      expect.anything(),
      bearer,
    );
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(res.headers.getSetCookie()).toEqual([]);
    expect((await res.json()) as unknown).toEqual({
      error: "Logout identity could not be verified",
      code: "invalid_token",
    });
  });

  test("keeps logout retryable when the cross-host revocation stamp cannot commit", async () => {
    readStewardSessionTokenMock.mockReturnValue("header.payload.signature");
    markSsoBridgeLogoutMock.mockRejectedValue(
      new Error("logout marker store unavailable"),
    );

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api-staging.elizacloud.ai",
          origin: "https://cloud-staging.eliza.app",
          authorization: "Bearer header.payload.signature",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledTimes(2);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect((await res.json()) as unknown).toEqual({
      error: "Logout revocation is temporarily unavailable",
      code: "logout_revocation_unavailable",
    });
  });

  test("retries a near-expiry-installed bearer in the final hour of its signed lineage", async () => {
    const issuedAt = 2_000_000_000;
    const expiration = issuedAt + 60 * 60;
    const latestInstallAt = expiration + 299;
    const exactBearer = "retryable.expired.lineage";
    const claims = { userId: "steward-retry", issuedAt };
    const markerError = new Error("logout marker store unavailable");

    // The ordinary verifier can still admit the access token here, and the
    // route starts both 30-day cookie lifetimes from this late install.
    setSystemTime(new Date(latestInstallAt * 1_000));
    readStewardSessionTokenMock.mockReturnValue(exactBearer);
    verifyStewardTokenMock
      .mockResolvedValueOnce(claims)
      .mockResolvedValueOnce(null);
    verifyStewardRefreshLineageTokenMock.mockResolvedValueOnce(claims);
    markSsoBridgeLogoutMock
      .mockRejectedValueOnce(markerError)
      .mockRejectedValueOnce(markerError)
      .mockResolvedValueOnce(undefined);

    const request = () =>
      app.request(
        "/",
        {
          method: "POST",
          headers: {
            ...MUTATION_PROTOCOL_HEADERS,
            host: "api-staging.elizacloud.ai",
            origin: "https://cloud-staging.eliza.app",
            authorization: `Bearer ${exactBearer}`,
          },
        },
        { ENVIRONMENT: "staging", NODE_ENV: "production" },
      );

    const firstResponse = await request();
    expect(firstResponse.status).toBe(503);
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledTimes(2);

    // Retry one minute before that late-installed cookie expires. Ordinary
    // access auth is long dead, but signed lineage must still identify the
    // exact user so the previously failed logout marker can become durable.
    setSystemTime(
      new Date(
        (latestInstallAt + STEWARD_REFRESH_AUTHORITY_TTL_SECONDS - 60) * 1_000,
      ),
    );
    const retryResponse = await request();

    expect(retryResponse.status).toBe(200);
    expect(verifyStewardRefreshLineageTokenMock).toHaveBeenCalledWith(
      expect.anything(),
      exactBearer,
    );
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledTimes(3);
    expect(markSsoBridgeLogoutMock).toHaveBeenLastCalledWith("steward-retry");
  });

  test("strong rollout commits the session cutoff before reporting logout success", async () => {
    readStewardSessionTokenMock.mockReturnValue("prod-token");
    getExistingUserForVerifiedStewardClaimsMock.mockResolvedValue({
      id: "user-1",
      organization_id: "org-1",
    });
    revokeInferenceSessionsThroughMock.mockResolvedValue(undefined);
    revokeInferenceSessionsThroughMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: "steward-token=prod-token",
        },
      },
      {
        ENVIRONMENT: "production",
        NODE_ENV: "production",
        INFERENCE_STRONG_REVOCATION_ENABLED: "true",
      },
    );

    expect(res.status).toBe(200);
    expect(revokeInferenceSessionsThroughMock).toHaveBeenCalledWith(
      "org-1",
      "user-1",
      100,
    );
  });

  test("strong rollout preserves retry credentials when the cutoff is unconfirmed", async () => {
    readStewardSessionTokenMock.mockReturnValue("prod-token");
    getExistingUserForVerifiedStewardClaimsMock.mockResolvedValue({
      id: "user-1",
      organization_id: "org-1",
    });
    revokeInferenceSessionsThroughMock.mockRejectedValueOnce(
      new Error("boundary unavailable"),
    );

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: "steward-token=prod-token",
        },
      },
      {
        ENVIRONMENT: "production",
        NODE_ENV: "production",
        INFERENCE_STRONG_REVOCATION_ENABLED: "true",
      },
    );

    expect(res.status).toBe(503);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect((await res.json()) as unknown).toEqual({
      error: "Logout revocation is temporarily unavailable",
      code: "logout_revocation_unavailable",
    });
  });

  test("staging legacy-only logout does not end production user sessions", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    const cleared = deletedCookieNames(res);
    expect(cleared).toContain("__Host-steward-token-v2-staging");
    expect(cleared).toContain("__Host-steward-refresh-token-v2-staging");
    expect(cleared).toContain("steward-token-staging");
    expect(cleared).toContain("steward-refresh-token-staging");
    expect(cleared).toContain("steward-authed-staging");
    expect(cleared).not.toContain("steward-token");
    expect(cleared).not.toContain("steward-refresh-token");
    expect(cleared).not.toContain("steward-authed");
    expect(setCookieHeaders(res)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2-staging=0"),
      ]),
    );
    expect(getCurrentUserMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
  });

  test("staging logout does not delete production's unsuffixed steward cookies", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh; steward-token-staging=staging-token; steward-refresh-token-staging=staging-refresh",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    const cleared = deletedCookieNames(res);
    expect(cleared).toContain("__Host-steward-token-v2-staging");
    expect(cleared).toContain("__Host-steward-refresh-token-v2-staging");
    expect(cleared).toContain("steward-token-staging");
    expect(cleared).toContain("steward-refresh-token-staging");
    expect(cleared).toContain("steward-authed-staging");
    expect(cleared).not.toContain("steward-token");
    expect(cleared).not.toContain("steward-refresh-token");
    expect(cleared).not.toContain("steward-authed");
    expect(setCookieHeaders(res)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2-staging=0"),
      ]),
    );
  });

  test("production logout still clears the historical steward cookies", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    const cleared = deletedCookieNames(res);
    expect(cleared).toContain("__Host-steward-token-v2");
    expect(cleared).toContain("__Host-steward-refresh-token-v2");
    expect(cleared).toContain("steward-token");
    expect(cleared).toContain("steward-refresh-token");
    expect(cleared).toContain("steward-authed");
    expect(setCookieHeaders(res)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2=0"),
      ]),
    );
  });

  test("same-site user-content origin cannot force a production logout", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api.eliza.app",
          origin: "https://attacker.cloud.eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(403);
    expect((await res.json()) as unknown).toEqual({
      error: "Forbidden",
      code: "forbidden_origin",
    });
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(getCurrentUserMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
  });

  test("missing browser origin cannot mutate the session", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          ...MUTATION_PROTOCOL_HEADERS,
          host: "api.eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(403);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(getCurrentUserMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
  });

  test("legacy logout clears v1 and closes the v2 authority boundary", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.eliza.app",
          origin: "https://eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "steward-token=account-a; steward-refresh-token=account-a-refresh; steward-authed=1",
          [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    expect(deletedCookieNames(res)).toEqual(
      expect.arrayContaining([
        "steward-token",
        "steward-refresh-token",
        "steward-authed",
      ]),
    );
    expect(setCookieHeaders(res)).toEqual(
      expect.arrayContaining([
        expect.stringMatching(
          /^__Host-steward-authed-v2=0;.*Max-Age=.*; Path=\/; Secure; SameSite=Lax$/,
        ),
      ]),
    );
    expect(setCookieHeaders(res).join("\n")).not.toContain("Domain=");
  });

  test("elizacloud legacy logout clears both host-only and historical Domain cookies", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "steward-token-staging=account-a; steward-refresh-token-staging=account-a-refresh; steward-authed-staging=1",
          [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    for (const name of [
      "steward-token-staging",
      "steward-refresh-token-staging",
      "steward-authed-staging",
    ]) {
      const clears = setCookieHeaders(res).filter((cookie) =>
        cookie.startsWith(`${name}=`),
      );
      expect(clears).toHaveLength(2);
      expect(
        clears.some((cookie) => cookie.includes("Domain=elizacloud.ai")),
      ).toBe(true);
      expect(clears.some((cookie) => !cookie.includes("Domain="))).toBe(true);
    }
    expect(setCookieHeaders(res).join("\n")).not.toContain("steward-token=;");
    expect(setCookieHeaders(res).join("\n")).not.toContain(
      "__Host-steward-authed-v2-staging=0; Domain=",
    );
  });

  test("uses one exact valid legacy cookie JWT for server-side logout teardown", async () => {
    getExistingUserForVerifiedStewardClaimsMock.mockResolvedValue({
      id: "cloud-user-a",
      organization_id: "org-a",
    });

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "steward-token=legacy.jwt.signature; steward-refresh-token=legacy-refresh; steward-authed=1",
          [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
        },
      },
      {
        ENVIRONMENT: "production",
        NODE_ENV: "production",
        INFERENCE_STRONG_REVOCATION_ENABLED: "true",
      },
    );

    expect(res.status).toBe(200);
    expect(readStewardSessionTokenMock).not.toHaveBeenCalled();
    expect(verifyStewardTokenMock).toHaveBeenCalledWith(
      expect.anything(),
      "legacy.jwt.signature",
    );
    expect(getExistingUserForVerifiedStewardClaimsMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ userId: "steward-1" }),
    );
    expect(invalidateSessionCachesMock).toHaveBeenCalledWith(
      "legacy.jwt.signature",
    );
    expect(revokeInferenceSessionsThroughMock).toHaveBeenCalledWith(
      "org-a",
      "cloud-user-a",
      100,
    );
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledWith("steward-1");
    expect(endAllUserSessionsMock).toHaveBeenCalledWith("cloud-user-a");
  });

  test("an invalid legacy JWT reports 401 without destroying retry evidence", async () => {
    verifyStewardTokenMock.mockResolvedValueOnce(null);

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "steward-token=invalid.jwt.signature; steward-refresh-token=legacy-refresh; steward-authed=1",
          [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
        },
      },
      {
        ENVIRONMENT: "production",
        NODE_ENV: "production",
        INFERENCE_STRONG_REVOCATION_ENABLED: "true",
      },
    );

    expect(res.status).toBe(401);
    expect(verifyStewardTokenMock).toHaveBeenCalledWith(
      expect.anything(),
      "invalid.jwt.signature",
    );
    expect(verifyStewardRefreshLineageTokenMock).toHaveBeenCalledWith(
      expect.anything(),
      "invalid.jwt.signature",
    );
    expect((await res.json()) as unknown).toEqual({
      error: "Logout identity could not be verified",
      code: "invalid_token",
    });
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(getExistingUserForVerifiedStewardClaimsMock).not.toHaveBeenCalled();
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
    expect(revokeInferenceSessionsThroughMock).not.toHaveBeenCalled();
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
  });

  test("duplicate legacy cookies are cleaned in both scopes without selecting an identity", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "steward-token=host.jwt.value; steward-token=domain.jwt.value; steward-refresh-token=host-refresh; steward-refresh-token=domain-refresh; steward-authed=1",
          [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    for (const name of [
      "steward-token",
      "steward-refresh-token",
      "steward-authed",
    ]) {
      expect(
        setCookieHeaders(res).filter((cookie) => cookie.startsWith(`${name}=`)),
      ).toHaveLength(2);
    }
    expect(verifyStewardTokenMock).not.toHaveBeenCalled();
    expect(getExistingUserForVerifiedStewardClaimsMock).not.toHaveBeenCalled();
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
  });

  test("legacy logout cannot clear a v2 browser session", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();
    readStewardSessionTokenMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.eliza.app",
          origin: "https://eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "__Host-steward-authed-v2=1; __Host-steward-token-v2=account-b; steward-token=account-a; steward-refresh-token=account-a-refresh",
          [STEWARD_CSRF_HEADER]: STEWARD_CSRF_HEADER_VALUE,
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      code: "session_mutation_protocol_required",
    });
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(readStewardSessionTokenMock).not.toHaveBeenCalled();
    expect(getCurrentUserMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
  });

  test("rejects a valid hosted Origin when Sec-Fetch-Site is missing", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          [STEWARD_CSRF_HEADER]: STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
          origin: "https://eliza.app",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(403);
    expect(res.headers.getSetCookie()).toEqual([]);
  });
});
