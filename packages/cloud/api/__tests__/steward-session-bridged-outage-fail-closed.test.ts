/**
 * POST /api/auth/steward-session availability scoping during an SSO
 * logout-marker STORE outage, through the real route module with the marker
 * service mocked to throw (what the repository read does when Postgres is
 * unreachable). Bridge-issued tokens (`bridged` claim, stamped by the
 * sso-bridge exchange re-mint) must fail CLOSED with the bridge legs' 503
 * `sso_unavailable` and plant no cookies; ordinary tokens must never touch
 * the marker store at all and keep minting — the pre-bridge no-datastore
 * availability posture the Redis-outage suite pins.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import { STEWARD_SESSION_MUTATION_PROTOCOL_VALUE } from "@elizaos/shared/steward-session-client";
import { Hono } from "hono";

const emitAudit = mock(async () => undefined);
const verifyStewardTokenCached = mock(async (_env: unknown, token: string) => {
  const base = {
    userId: "steward-user-1",
    email: "person@example.test",
    tenantId: "elizacloud",
    expiration: Math.floor(Date.now() / 1000) + 900,
    issuedAt: Math.floor(Date.now() / 1000) - 60,
  };
  if (token === "bridged-token") return { ...base, bridged: true };
  if (token === "plain-token") return base;
  if (token === "different-user-token") {
    return { ...base, userId: "steward-user-2" };
  }
  return null;
});
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
const isBlockedBySsoBridgeLogout = mock<
  (_userId: string, _issuedAt: number) => Promise<boolean>
>(async () => {
  throw new Error("connect ECONNREFUSED: postgres down");
});

mock.module("@/api-app/services/audit-dispatcher-singleton", () => ({
  getAuditDispatcher: () => ({ emit: emitAudit }),
}));

mock.module("@/lib/auth/steward-client", () => ({
  verifyStewardTokenCached,
}));

mock.module("@/lib/steward-sync", () => ({
  describeSyncError: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
  StewardPhoneAccountConflictError: MockStewardPhoneAccountConflictError,
  StewardTelegramAccountClaimError: MockStewardTelegramAccountClaimError,
  syncUserFromSteward,
}));

mock.module("@/lib/services/sso-bridge-codes", () => ({
  isBlockedBySsoBridgeLogout,
}));

mock.module("@/lib/utils/logger", () => ({
  logger: {
    debug: mock(() => undefined),
    error: mock(() => undefined),
    info: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const { default: stewardSessionRoute } = await import(
  "../auth/steward-session/route"
);

const ENV = {
  ENVIRONMENT: "staging",
  NODE_ENV: "production",
  STEWARD_SESSION_SECRET: "test-secret",
};

let ipCounter = 0;

function postStewardSession(body: unknown, cookie?: string) {
  ipCounter += 1;
  const app = new Hono();
  app.route("/api/auth/steward-session", stewardSessionRoute);
  return app.fetch(
    new Request("https://api-staging.elizacloud.ai/api/auth/steward-session", {
      method: "POST",
      headers: {
        "cf-connecting-ip": `203.0.113.${ipCounter}`,
        "content-type": "application/json",
        origin: "https://staging.elizacloud.ai",
        "x-eliza-csrf": STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
        ...(cookie ? { cookie } : {}),
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
  isBlockedBySsoBridgeLogout.mockClear();
});

describe("POST /api/auth/steward-session — logout-marker store outage", () => {
  test("a BRIDGE-issued token fails closed: 503 sso_unavailable, no cookies", async () => {
    const res = await postStewardSession({ token: "bridged-token" });
    expect(res.status).toBe(503);
    await expect(res.json()).resolves.toMatchObject({
      code: "sso_unavailable",
    });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledTimes(1);
    expect(syncUserFromSteward).not.toHaveBeenCalled();
  });

  test("an ORDINARY token never touches the marker store and still mints", async () => {
    const res = await postStewardSession({ token: "plain-token" });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      ok: true,
      userId: "cloud-user-1",
      stewardUserId: "steward-user-1",
    });
    expect(res.headers.get("set-cookie") ?? "").toContain(
      "steward-token-staging=plain-token",
    );
    expect(isBlockedBySsoBridgeLogout).not.toHaveBeenCalled();
  });

  test("an access-only bridge login removes an older refresh cookie", async () => {
    isBlockedBySsoBridgeLogout.mockResolvedValueOnce(false);

    const res = await postStewardSession(
      { token: "bridged-token" },
      "steward-token=prod-token; steward-refresh-token=prod-refresh; steward-token-staging=plain-token; steward-refresh-token-staging=stale-refresh",
    );

    expect(res.status).toBe(200);
    const cookies = res.headers.getSetCookie();
    const deleted = cookies
      .filter((cookie) => /Max-Age=0/i.test(cookie))
      .map((cookie) => cookie.split("=")[0]);
    expect(deleted).toContain("steward-refresh-token-staging");
    expect(deleted).not.toContain("steward-refresh-token");
    expect(cookies.join("\n")).toContain("steward-token-staging=bridged-token");
  });

  test("an access-only account switch removes the prior identity's refresh cookie", async () => {
    const res = await postStewardSession(
      { token: "different-user-token" },
      "steward-token-staging=plain-token; steward-refresh-token-staging=stale-refresh",
    );

    expect(res.status).toBe(200);
    const deleted = res.headers
      .getSetCookie()
      .filter((cookie) => /Max-Age=0/i.test(cookie))
      .map((cookie) => cookie.split("=")[0]);
    expect(deleted).toEqual(["steward-refresh-token-staging"]);
    expect(isBlockedBySsoBridgeLogout).not.toHaveBeenCalled();
  });

  test.each([
    ["expired", "expired-access-token"],
    ["malformed", "malformed-access-token"],
    ["missing", null],
  ])(
    "an access-only login removes a stale refresh when the prior access is %s",
    async (_label, priorAccessToken) => {
      const priorCookies = [
        priorAccessToken ? `steward-token-staging=${priorAccessToken}` : null,
        "steward-refresh-token-staging=stale-refresh-a",
      ]
        .filter((cookie): cookie is string => cookie !== null)
        .join("; ");

      const res = await postStewardSession(
        { token: "different-user-token" },
        priorCookies,
      );

      expect(res.status).toBe(200);
      const deleted = res.headers
        .getSetCookie()
        .filter((cookie) => /Max-Age=0/i.test(cookie))
        .map((cookie) => cookie.split("=")[0]);
      expect(deleted).toEqual(["steward-refresh-token-staging"]);
      expect(res.headers.getSetCookie().join("\n")).toContain(
        "steward-token-staging=different-user-token",
      );
      expect(isBlockedBySsoBridgeLogout).not.toHaveBeenCalled();
    },
  );

  test("an ordinary same-identity passive sync preserves its refresh cookie", async () => {
    const res = await postStewardSession(
      { token: "plain-token" },
      "steward-token-staging=plain-token; steward-refresh-token-staging=live-refresh",
    );

    expect(res.status).toBe(200);
    expect(
      res.headers
        .getSetCookie()
        .map((cookie) => cookie.split("=")[0])
        .filter((name) => name === "steward-refresh-token-staging"),
    ).toEqual([]);
  });
});
