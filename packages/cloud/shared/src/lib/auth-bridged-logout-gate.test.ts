import { beforeEach, describe, expect, mock, test } from "bun:test";

const user = {
  id: "user-1",
  steward_user_id: "steward-1",
  email: "user@example.test",
  name: "User",
  role: "owner",
  is_active: true,
  organization_id: "org-1",
  organization: { id: "org-1", name: "Org", is_active: true },
};

let cachedSessionUser: typeof user | null = null;
const cacheGet = mock(async () => cachedSessionUser);
const cacheSet = mock(async () => undefined);
mock.module("./cache/client", () => ({
  cache: {
    get: cacheGet,
    set: cacheSet,
    del: mock(async () => undefined),
  },
}));

let tokenClaimsBehavior: () => Promise<unknown> = async () => null;
const verifyStewardTokenCached = mock(() => tokenClaimsBehavior());
mock.module("./auth/steward-client", () => ({
  invalidateStewardTokenCache: mock(async () => undefined),
  isStagingSessionTokenCandidate: () => false,
  verifyStewardTokenCached,
}));

let logoutMarkerBehavior: () => Promise<boolean> = async () => false;
const isBlockedBySsoBridgeLogout = mock(() => logoutMarkerBehavior());
mock.module("./services/sso-bridge-codes", () => ({ isBlockedBySsoBridgeLogout }));

const getByStewardId = mock(async () => user);
mock.module("./services/users", () => ({
  usersService: {
    getByStewardId,
    getWithOrganization: mock(async () => user),
  },
}));

mock.module("./auth/playwright-test-session", () => ({
  isPlaywrightTestAuthEnabled: () => false,
  PLAYWRIGHT_TEST_SESSION_COOKIE_NAME: "pw-test-session",
  verifyPlaywrightTestSessionToken: () => null,
}));
mock.module("./auth/staging-session-binding", () => ({
  loadVerifiedStagingSessionUser: mock(async () => null),
}));
mock.module("./auth/wallet-auth", () => ({
  verifyWalletSignature: mock(async () => null),
}));
mock.module("./runtime/cloud-bindings", () => ({
  getCloudAwareEnv: () => ({ ENVIRONMENT: "production", NODE_ENV: "production" }),
}));
mock.module("./services/admin", () => ({ adminService: {} }));
mock.module("./services/api-keys", () => ({
  apiKeysService: {
    ensureUserHasApiKey: mock(async () => undefined),
    incrementUsageDebounced: mock(() => undefined),
    validateApiKey: mock(async () => null),
  },
}));
mock.module("./services/user-sessions", () => ({
  userSessionsService: { getOrCreateSession: mock(async () => ({ id: "session-1" })) },
}));
mock.module("./steward-sync", () => ({
  ensureDefaultCharacter: mock(async () => undefined),
  syncUserFromSteward: mock(async () => user),
}));
mock.module("./utils/logger", () => ({
  logger: {
    debug: mock(() => undefined),
    error: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const { getCurrentUserFromRequest, getUserFromRequest, requireAuthOrApiKeyWithOrg } = await import(
  "./auth"
);

const bridgedClaims = {
  userId: "steward-1",
  issuedAt: 1_700_000_000,
  expiration: 1_700_003_600,
  bridged: true,
};

function cookieRequest(): Request {
  return new Request("https://api.eliza.app/v1/anything", {
    headers: { cookie: "__Host-steward-token-v2=header.payload.signature" },
  });
}

function bearerRequest(): Request {
  return new Request("https://api.eliza.app/v1/anything", {
    headers: { authorization: "Bearer header.payload.signature" },
  });
}

beforeEach(() => {
  cachedSessionUser = null;
  tokenClaimsBehavior = async () => null;
  logoutMarkerBehavior = async () => false;
  cacheGet.mockClear();
  cacheSet.mockClear();
  verifyStewardTokenCached.mockClear();
  isBlockedBySsoBridgeLogout.mockClear();
  getByStewardId.mockClear();
});

describe("legacy auth bridge logout marker", () => {
  test("a cached user projection cannot resurrect a logged-out bridged cookie", async () => {
    cachedSessionUser = user;
    tokenClaimsBehavior = async () => bridgedClaims;
    logoutMarkerBehavior = async () => true;

    await expect(requireAuthOrApiKeyWithOrg(cookieRequest())).rejects.toMatchObject({
      status: 401,
      code: "authentication_required",
    });
    expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledWith("steward-1", 1_700_000_000);
    expect(verifyStewardTokenCached).toHaveBeenCalledTimes(1);
    expect(getByStewardId).not.toHaveBeenCalled();
  });

  test("an uncached logged-out bridged cookie is rejected before user hydration", async () => {
    tokenClaimsBehavior = async () => bridgedClaims;
    logoutMarkerBehavior = async () => true;

    await expect(getCurrentUserFromRequest(cookieRequest())).resolves.toBeNull();
    expect(cacheGet).not.toHaveBeenCalled();
    expect(getByStewardId).not.toHaveBeenCalled();
  });

  test("an active uncached bridged cookie still resolves normally", async () => {
    tokenClaimsBehavior = async () => bridgedClaims;

    await expect(requireAuthOrApiKeyWithOrg(cookieRequest())).resolves.toMatchObject({
      user: { id: "user-1", organization_id: "org-1" },
      authMethod: "session",
    });
    expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledWith("steward-1", 1_700_000_000);
    expect(getByStewardId).toHaveBeenCalledWith("steward-1");
  });

  test("marker-store failure for an ordinary token surfaces as 503 even with a cached user", async () => {
    cachedSessionUser = user;
    tokenClaimsBehavior = async () => ({ ...bridgedClaims, bridged: false });
    logoutMarkerBehavior = async () => {
      throw new Error("primary unavailable");
    };

    await expect(requireAuthOrApiKeyWithOrg(cookieRequest())).rejects.toMatchObject({
      status: 503,
      code: "service_unavailable",
    });
    expect(cacheGet).not.toHaveBeenCalled();
  });

  test("an ordinary Steward cookie passes when no logout marker blocks it", async () => {
    cachedSessionUser = user;
    tokenClaimsBehavior = async () => ({ ...bridgedClaims, bridged: false });

    await expect(getCurrentUserFromRequest(cookieRequest())).resolves.toMatchObject({
      id: "user-1",
    });
    expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledWith("steward-1", 1_700_000_000);
  });

  test("a paired-origin logout also blocks an ordinary host-only Steward cookie", async () => {
    cachedSessionUser = user;
    tokenClaimsBehavior = async () => ({ ...bridgedClaims, bridged: false });
    logoutMarkerBehavior = async () => true;

    await expect(requireAuthOrApiKeyWithOrg(cookieRequest())).rejects.toMatchObject({
      status: 401,
      code: "authentication_required",
    });
    expect(cacheGet).not.toHaveBeenCalled();
  });

  test("the direct bearer org guard rejects a logged-out bridged token", async () => {
    tokenClaimsBehavior = async () => bridgedClaims;
    logoutMarkerBehavior = async () => true;

    await expect(requireAuthOrApiKeyWithOrg(bearerRequest())).rejects.toMatchObject({
      status: 401,
      code: "authentication_required",
    });
    expect(getByStewardId).not.toHaveBeenCalled();
  });

  test("the nullable bearer helper returns no user for a logged-out bridged token", async () => {
    tokenClaimsBehavior = async () => bridgedClaims;
    logoutMarkerBehavior = async () => true;

    await expect(getUserFromRequest(bearerRequest())).resolves.toBeNull();
    expect(getByStewardId).not.toHaveBeenCalled();
  });
});
