/**
 * Steward-session Redis-outage rate-limit behavior.
 *
 * The route must not repeat the staging outage from #13890: a Redis limiter
 * failure cannot block legitimate session minting before auth validation. It
 * also cannot become naked fail-open, so this drives the real route with a
 * throwing Redis client and proves the route-owned fallback bucket still bounds
 * invalid-token spray.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import { STEWARD_SESSION_MUTATION_PROTOCOL_VALUE } from "@elizaos/shared/steward-session-client";
import { Hono } from "hono";
import { STEWARD_REFRESH_AUTHORITY_TTL_SECONDS } from "@/lib/auth/steward-cookies";

const emitAudit = mock(async () => undefined);
const verifyStewardTokenCached = mock(async (_env: unknown, token: string) =>
  token === "valid-steward-token"
    ? {
        userId: "steward-user-1",
        email: "person@example.test",
        expiration: Math.floor(Date.now() / 1000) + 900,
        issuedAt: Math.floor(Date.now() / 1000) - 10,
      }
    : null,
);
const syncUserFromSteward = mock(async () => ({
  id: "cloud-user-1",
  organization_id: "org-1",
  initialCreditsGranted: false,
  initialFreeCreditsUsd: "0.00",
  welcomeBonusWithheld: false,
  welcomeBonusWithheldReason: undefined,
  welcomeBonusWithheldMessage: undefined,
}));
class MockStewardPhoneAccountConflictError extends Error {}
class MockStewardTelegramAccountClaimError extends Error {}

const throwingRedis = {
  incr: async () => {
    throw new Error("ECONNREFUSED: redis down");
  },
  pttl: async () => {
    throw new Error("ECONNREFUSED: redis down");
  },
  pexpire: async () => {
    throw new Error("ECONNREFUSED: redis down");
  },
};

mock.module("@/lib/cache/redis-factory", () => ({
  buildRedisClient: () => throwingRedis,
  hasRedisConfig: () => true,
  isCloudflareWorkerRuntime: () => false,
}));

mock.module("@/api-app/services/audit-dispatcher-singleton", () => ({
  getAuditDispatcher: () => ({ emit: emitAudit }),
}));

mock.module("@/lib/auth/steward-client", () => ({
  STEWARD_VERIFY_CLOCK_SKEW_SECONDS: 300,
  verifyStewardTokenCached,
}));

mock.module("@/lib/services/sso-bridge-codes", () => ({
  classifySsoBridgeLogout: mock(async () => ({ status: "allowed" as const })),
  isBlockedBySsoBridgeLogout: mock(async () => false),
}));

mock.module("@/lib/steward-sync", () => ({
  describeSyncError: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
  StewardPhoneAccountConflictError: MockStewardPhoneAccountConflictError,
  StewardTelegramAccountClaimError: MockStewardTelegramAccountClaimError,
  syncUserFromSteward,
}));

mock.module("@/lib/utils/logger", () => ({
  logger: {
    debug: mock(() => undefined),
    error: mock(() => undefined),
    info: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const { default: stewardSessionRoute } = await import("./route");
const { _resetRedisUnavailableFallbackBuckets } = await import(
  "@/lib/middleware/rate-limit-hono-cloudflare"
);

const ENV = {
  ENVIRONMENT: "staging",
  NODE_ENV: "production",
  REDIS_URL: "redis://mock:6379",
  STEWARD_SESSION_SECRET: "test-secret",
};

function postStewardSession(body: unknown, ip = "203.0.113.10") {
  const app = new Hono();
  app.route("/api/auth/steward-session", stewardSessionRoute);
  return app.fetch(
    new Request("https://api-staging.elizacloud.ai/api/auth/steward-session", {
      method: "POST",
      headers: {
        "cf-connecting-ip": ip,
        "content-type": "application/json",
        origin: "https://staging.eliza.app",
        "sec-fetch-site": "same-origin",
        "x-eliza-csrf": STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
      },
      body: JSON.stringify(body),
    }),
    ENV,
  );
}

beforeEach(() => {
  emitAudit.mockClear();
  verifyStewardTokenCached.mockClear();
  syncUserFromSteward.mockClear();
  _resetRedisUnavailableFallbackBuckets();
});

describe("POST /api/auth/steward-session — Redis outage fallback limiter", () => {
  test("a missing token reaches normal auth validation instead of rate_limit_unavailable", async () => {
    const res = await postStewardSession({});
    expect(res.status).toBe(400);
    expect(res.headers.get("X-RateLimit-Policy")).toBe(
      "redis-unavailable-local",
    );
    await expect(res.json()).resolves.toMatchObject({
      code: "missing_token",
    });
    expect(verifyStewardTokenCached).not.toHaveBeenCalled();
  });

  test("a valid Steward token can mint staging-scoped cookies while Redis is down", async () => {
    const res = await postStewardSession({
      token: "valid-steward-token",
      refreshToken: "valid-refresh-token",
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("X-RateLimit-Policy")).toBe(
      "redis-unavailable-local",
    );
    await expect(res.json()).resolves.toMatchObject({
      ok: true,
      userId: "cloud-user-1",
      stewardUserId: "steward-user-1",
    });
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain(
      "__Host-steward-token-v2-staging=valid-steward-token",
    );
    expect(setCookie).toContain(
      "__Host-steward-refresh-token-v2-staging=valid-refresh-token",
    );
    for (const cookieName of [
      "__Host-steward-token-v2-staging",
      "__Host-steward-refresh-token-v2-staging",
    ]) {
      expect(
        res.headers
          .getSetCookie()
          .find((cookie) => cookie.startsWith(`${cookieName}=`)),
      ).toContain(`Max-Age=${STEWARD_REFRESH_AUTHORITY_TTL_SECONDS}`);
    }
    expect(verifyStewardTokenCached).toHaveBeenCalledTimes(1);
    expect(syncUserFromSteward).toHaveBeenCalledTimes(1);
  });

  test("a token admitted near exp plus verifier skew still installs a full 30-day refresh lineage", async () => {
    const now = Math.floor(Date.now() / 1000);
    verifyStewardTokenCached.mockResolvedValueOnce({
      userId: "steward-user-near-expiry",
      email: "near-expiry@example.test",
      // The normal verifier admits through exp + 299 seconds. Cookie lifetime
      // begins here, so lineage must cover this late installation window.
      expiration: now - 299,
      issuedAt: now - 60 * 60 - 299,
    });

    const res = await postStewardSession({
      token: "near-expiry-steward-token",
      refreshToken: "near-expiry-refresh-token",
    });

    expect(res.status).toBe(200);
    for (const cookieName of [
      "__Host-steward-token-v2-staging",
      "__Host-steward-refresh-token-v2-staging",
    ]) {
      expect(
        res.headers
          .getSetCookie()
          .find((cookie) => cookie.startsWith(`${cookieName}=`)),
      ).toContain(`Max-Age=${STEWARD_REFRESH_AUTHORITY_TTL_SECONDS}`);
    }
  });

  test("invalid-token spray is still bounded by the local fallback bucket", async () => {
    for (let i = 0; i < 10; i += 1) {
      const res = await postStewardSession({ token: `invalid-${i}` });
      expect(res.status).toBe(401);
    }

    const blocked = await postStewardSession({ token: "invalid-10" });
    expect(blocked.status).toBe(429);
    await expect(blocked.json()).resolves.toMatchObject({
      success: false,
      code: "rate_limit_exceeded",
    });
    expect(blocked.headers.get("X-RateLimit-Policy")).toBe(
      "redis-unavailable-local",
    );
    expect(verifyStewardTokenCached).toHaveBeenCalledTimes(10);
  });
});
