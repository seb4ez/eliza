/**
 * POST /api/auth/steward-session × the cross-host SSO logout marker, through
 * the REAL route module with real HS256 Steward JWTs and the real
 * Postgres-backed marker store on PGlite. After an explicit logout, the
 * paired origin's surviving token can re-POST here on its sync cadence —
 * regardless of whether it originally crossed the bridge. Without this gate,
 * that sync re-plants the cookies the logout just deleted. The gate must 401 with
 * the DISTINCT `session_ended` code (the client treats it as a real revocation
 * and clears its stored session), set no cookies, and allow only tokens whose
 * signed issuance is strictly newer than the logout ordering tolerance.
 */

import {
  afterAll,
  beforeAll,
  describe,
  expect,
  setDefaultTimeout,
  setSystemTime,
  test,
} from "bun:test";
import { STEWARD_SESSION_MUTATION_PROTOCOL_VALUE } from "@elizaos/shared/steward-session-client";

const AMBIENT_DATABASE_URL = process.env.DATABASE_URL ?? "";
const CAN_USE_ISOLATED_PGLITE =
  AMBIENT_DATABASE_URL === "" || AMBIENT_DATABASE_URL.startsWith("pglite");
process.env.DATABASE_URL ||= "pglite://memory";
process.env.NODE_ENV ||= "test";
process.env.MOCK_REDIS = "1";

setDefaultTimeout(90_000);

const SECRET = "steward-session-gate-test-secret-01";

type RouteApp = typeof import("../auth/steward-session/route").default;
type StewardClientModule = typeof import("@/lib/auth/steward-client");
let app: RouteApp;
let markSsoBridgeLogout: (stewardUserId: string) => Promise<void>;
let mintStewardTokenFromClaims: StewardClientModule["mintStewardTokenFromClaims"];

const ENV = {
  NODE_ENV: "test",
  ENVIRONMENT: "test",
  STEWARD_SESSION_SECRET: SECRET,
  RATE_LIMIT_MULTIPLIER: "100",
};

let ipCounter = 0;

async function mintToken(
  userId: string,
  iatOffsetSec: number,
  restoreClock = true,
): Promise<string> {
  const realNow = Date.now();
  try {
    if (iatOffsetSec !== 0) {
      setSystemTime(new Date(realNow + iatOffsetSec * 1000));
    }
    const minted = await mintStewardTokenFromClaims(
      ENV,
      { userId, expiration: 0, issuedAt: 0 },
      // Keep the signed issued lifetime at the production one-hour contract.
      // The clock shift exists only to order the token around the logout mark.
      3600,
    );
    if (!minted) throw new Error("test token mint failed");
    return minted.token;
  } finally {
    if (restoreClock) setSystemTime();
  }
}

async function postSession(token: string): Promise<Response> {
  ipCounter += 1;
  return app.request(
    "/",
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://eliza.app",
        "sec-fetch-site": "same-origin",
        "x-eliza-csrf": STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
        "x-forwarded-for": `10.9.0.${ipCounter}`,
      },
      body: JSON.stringify({ token }),
    },
    ENV,
  );
}

beforeAll(async () => {
  expect(CAN_USE_ISOLATED_PGLITE).toBe(true);

  const { pushSchema } = await import("@/db/push-schema-for-tests");
  const { dbWrite } = await import("@/db/client");
  const { ssoBridgeCodes, ssoBridgeLogoutMarkers } = await import(
    "@/db/schemas/sso-bridge"
  );
  const { apply } = await pushSchema(
    { ssoBridgeCodes, ssoBridgeLogoutMarkers } as never,
    dbWrite as never,
  );
  await apply();

  app = (await import("../auth/steward-session/route")).default;
  ({ markSsoBridgeLogout } = await import("@/lib/services/sso-bridge-codes"));
  ({ mintStewardTokenFromClaims } = await import("@/lib/auth/steward-client"));
});

afterAll(async () => {
  setSystemTime();
  const { closeDatabaseConnectionsForTests } = await import("@/db/client");
  await closeDatabaseConnectionsForTests();
});

describe("logout marker gates the cookie-planting session sync", () => {
  test("a pre-logout token gets 401 session_ended and NO cookies", async () => {
    const userId = "gate-user-blocked";
    const preLogoutToken = await mintToken(userId, -10);

    await markSsoBridgeLogout(userId);

    const res = await postSession(preLogoutToken);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { code: string }).code).toBe("session_ended");
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("a genuinely new token inside the clock-skew window gets a truthful cooldown and NO cookies", async () => {
    const userId = "gate-user-cooldown";
    await markSsoBridgeLogout(userId);

    const postLogoutNow = Date.now();
    try {
      // Keep issuer and verifier clocks together. The token is genuinely new,
      // but its +1s iat is indistinguishable from a pre-logout fast-clock JWT.
      setSystemTime(new Date(postLogoutNow + 1_000));
      const response = await postSession(await mintToken(userId, 0, false));
      expect(response.status).toBe(409);
      const body = (await response.json()) as {
        code: string;
        error: string;
        retryAfterSeconds: number;
        retryAtEpochSeconds: number;
      };
      expect(body.code).toBe("logout_cooldown");
      expect(body.error).toContain("sign in again");
      expect(body.retryAfterSeconds).toBeGreaterThanOrEqual(4);
      expect(body.retryAfterSeconds).toBeLessThanOrEqual(6);
      expect(response.headers.get("retry-after")).toBe(
        String(body.retryAfterSeconds),
      );
      expect(body.retryAtEpochSeconds).toBeGreaterThan(
        Math.floor(Date.now() / 1000),
      );
      expect(response.headers.get("set-cookie")).toBeNull();
    } finally {
      setSystemTime();
    }
  });

  test("a same-second post-logout login is ambiguous rather than falsely called revoked", async () => {
    const userId = "gate-user-same-second";
    try {
      setSystemTime(new Date("2026-08-30T12:00:00.250Z"));
      await markSsoBridgeLogout(userId);
      const response = await postSession(await mintToken(userId, 0, false));

      expect(response.status).toBe(409);
      await expect(response.json()).resolves.toMatchObject({
        code: "logout_cooldown",
        error: expect.stringContaining("sign in again"),
      });
      expect(response.headers.get("set-cookie")).toBeNull();
    } finally {
      setSystemTime();
    }
  });

  test("a token issued beyond the post-logout tolerance passes the gate", async () => {
    const userId = "gate-user-fresh";
    const preLogoutToken = await mintToken(userId, -10);
    await markSsoBridgeLogout(userId);

    const blocked = await postSession(preLogoutToken);
    expect(((await blocked.json()) as { code: string }).code).toBe(
      "session_ended",
    );

    // The fresh token must NOT be refused as session_ended. (Later stages of
    // the login pipeline — user sync — have their own dependencies and their
    // own suites; this contract is only that the gate discriminates on iat.)
    try {
      // Keep the test clock six seconds ahead through verification: this
      // models real elapsed time, rather than presenting a future token to an
      // otherwise unadvanced verifier clock.
      const fresh = await postSession(await mintToken(userId, 6, false));
      const freshBody = (await fresh.json()) as { code?: string };
      expect(freshBody.code).not.toBe("session_ended");
      expect(freshBody.code).not.toBe("invalid_token");
    } finally {
      setSystemTime();
    }
  });

  test("a token with no marker is never blocked by the gate", async () => {
    const res = await postSession(await mintToken("gate-user-unmarked", -10));
    const body = (await res.json()) as { code?: string };
    expect(body.code).not.toBe("session_ended");
  });

  test("an ordinary token is also blocked by a stamped logout marker", async () => {
    const userId = "gate-user-ordinary";
    const preLogoutToken = await mintToken(userId, -10);
    await markSsoBridgeLogout(userId);

    const res = await postSession(preLogoutToken);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { code?: string }).code).toBe(
      "session_ended",
    );
    expect(res.headers.get("set-cookie")).toBeNull();
  });
});
