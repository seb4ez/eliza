import { afterEach, beforeEach, describe, expect, mock, setSystemTime, test } from "bun:test";

const fixedNow = new Date("2026-08-30T12:00:00.000Z");
const logoutMarkers = new Map<string, Date>();

const insertCode = mock(async () => ({}));
const claimCode = mock(async () => undefined);
const purgeExpiredCodes = mock(async () => 0);
let stampLogoutDelay: Promise<void> | undefined;
const stampLogout = mock(async (stewardUserId: string) => {
  await stampLogoutDelay;
  const databaseNow = new Date();
  const current = logoutMarkers.get(stewardUserId);
  const loggedOutAt = current && current.getTime() > databaseNow.getTime() ? current : databaseNow;
  logoutMarkers.set(stewardUserId, loggedOutAt);
  return { loggedOutAt, databaseNow };
});
const purgeLogoutMarkersOlderThan = mock(async (olderThan: Date) => {
  let purged = 0;
  for (const [stewardUserId, loggedOutAt] of logoutMarkers) {
    if (loggedOutAt.getTime() <= olderThan.getTime()) {
      logoutMarkers.delete(stewardUserId);
      purged += 1;
    }
  }
  return purged;
});
const getLogoutMarker = mock(async () => undefined);
const getLogoutMarkerForWrite = mock(async (stewardUserId: string) => {
  const loggedOutAt = logoutMarkers.get(stewardUserId);
  return loggedOutAt ? { steward_user_id: stewardUserId, logged_out_at: loggedOutAt } : undefined;
});

mock.module("../../db/repositories/sso-bridge", () => ({
  ssoBridgeRepository: {
    insertCode,
    claimCode,
    purgeExpiredCodes,
    stampLogout,
    purgeLogoutMarkersOlderThan,
    getLogoutMarker,
    getLogoutMarkerForWrite,
  },
}));

const {
  classifySsoBridgeLogout,
  isBlockedBySsoBridgeLogout,
  markSsoBridgeLogout,
  SSO_BRIDGE_LOGOUT_MARKER_TTL_SECONDS,
} = await import("./sso-bridge-codes");
const { STEWARD_FUTURE_ISSUED_AT_TOLERANCE_SECONDS, STEWARD_VERIFY_CLOCK_SKEW_SECONDS } =
  await import("../auth/steward-client");
const { STEWARD_REFRESH_AUTHORITY_TTL_SECONDS } = await import("../auth/steward-cookies");

describe("SSO bridge logout-marker retention", () => {
  beforeEach(() => {
    setSystemTime(fixedNow);
    logoutMarkers.clear();
    stampLogoutDelay = undefined;
    insertCode.mockClear();
    claimCode.mockClear();
    purgeExpiredCodes.mockClear();
    stampLogout.mockClear();
    purgeLogoutMarkersOlderThan.mockClear();
    getLogoutMarker.mockClear();
    getLogoutMarkerForWrite.mockClear();
  });

  afterEach(() => {
    setSystemTime();
  });

  test("retains markers through the refresh-authority horizon and purges only after it", async () => {
    const refreshAuthorityHorizonSeconds =
      STEWARD_REFRESH_AUTHORITY_TTL_SECONDS +
      STEWARD_VERIFY_CLOCK_SKEW_SECONDS +
      STEWARD_FUTURE_ISSUED_AT_TOLERANCE_SECONDS;

    logoutMarkers.set("older-than-one-hour", new Date(fixedNow.getTime() - 2 * 60 * 60 * 1000));
    logoutMarkers.set(
      "at-refresh-boundary",
      new Date(fixedNow.getTime() - refreshAuthorityHorizonSeconds * 1000),
    );
    logoutMarkers.set(
      "past-refresh-boundary",
      new Date(fixedNow.getTime() - (refreshAuthorityHorizonSeconds + 1) * 1000),
    );

    await markSsoBridgeLogout("current-user");

    expect(SSO_BRIDGE_LOGOUT_MARKER_TTL_SECONDS).toBe(refreshAuthorityHorizonSeconds + 1);
    expect(purgeLogoutMarkersOlderThan).toHaveBeenCalledWith(
      new Date(fixedNow.getTime() - SSO_BRIDGE_LOGOUT_MARKER_TTL_SECONDS * 1000),
    );
    expect(logoutMarkers.has("older-than-one-hour")).toBe(true);
    expect(logoutMarkers.has("at-refresh-boundary")).toBe(true);
    expect(logoutMarkers.has("past-refresh-boundary")).toBe(false);
    expect(logoutMarkers.get("current-user")).toEqual(fixedNow);
  });

  test("uses the effective write time so a token minted during a delayed logout stays revoked", async () => {
    let releaseStamp: (() => void) | undefined;
    stampLogoutDelay = new Promise<void>((resolve) => {
      releaseStamp = resolve;
    });

    const logout = markSsoBridgeLogout("delayed-user");

    // The DB write is still pending. This token is issued more than five
    // seconds after logout began, so a stale pre-await process timestamp would
    // incorrectly allow it once the logout eventually succeeded.
    setSystemTime(new Date(fixedNow.getTime() + 6_000));
    const issuedWhileLogoutWasPending = Math.floor(Date.now() / 1000);

    // Simulate the primary accepting the write only after a longer delay.
    setSystemTime(new Date(fixedNow.getTime() + 10_000));
    releaseStamp?.();
    await logout;

    expect(stampLogout.mock.calls).toEqual([["delayed-user"]]);
    expect(logoutMarkers.get("delayed-user")).toEqual(new Date(fixedNow.getTime() + 10_000));
    expect(purgeLogoutMarkersOlderThan).toHaveBeenCalledWith(
      new Date(fixedNow.getTime() + 10_000 - SSO_BRIDGE_LOGOUT_MARKER_TTL_SECONDS * 1000),
    );
    expect(await classifySsoBridgeLogout("delayed-user", issuedWhileLogoutWasPending)).toEqual({
      status: "definitely_revoked",
    });
  });

  test("does not let a legacy future marker advance the global purge cutoff", async () => {
    const anomalousFutureMarker = new Date(fixedNow.getTime() + 24 * 60 * 60 * 1000);
    const otherMarkerInsideRetention = new Date(
      fixedNow.getTime() - SSO_BRIDGE_LOGOUT_MARKER_TTL_SECONDS * 1000 + 1_000,
    );
    logoutMarkers.set("future-marker-user", anomalousFutureMarker);
    logoutMarkers.set("other-user", otherMarkerInsideRetention);

    await markSsoBridgeLogout("future-marker-user");

    expect(logoutMarkers.get("future-marker-user")).toEqual(anomalousFutureMarker);
    expect(logoutMarkers.get("other-user")).toEqual(otherMarkerInsideRetention);
    expect(purgeLogoutMarkersOlderThan).toHaveBeenCalledWith(
      new Date(fixedNow.getTime() - SSO_BRIDGE_LOGOUT_MARKER_TTL_SECONDS * 1000),
    );
  });

  test("classifies revoked, ambiguous, and unambiguously fresh token times on the primary", async () => {
    logoutMarkers.set("steward-1", fixedNow);
    const markerSeconds = Math.floor(fixedNow.getTime() / 1000);
    expect(STEWARD_FUTURE_ISSUED_AT_TOLERANCE_SECONDS).toBe(5);

    expect(await classifySsoBridgeLogout("steward-1", markerSeconds - 1)).toEqual({
      status: "definitely_revoked",
    });
    expect(await classifySsoBridgeLogout("steward-1", markerSeconds)).toEqual({
      status: "ambiguous_cooldown",
      retryAtEpochSeconds: markerSeconds + 6,
      retryAfterSeconds: 6,
    });
    expect(await classifySsoBridgeLogout("steward-1", markerSeconds + 1)).toEqual({
      status: "ambiguous_cooldown",
      retryAtEpochSeconds: markerSeconds + 6,
      retryAfterSeconds: 6,
    });
    expect(await classifySsoBridgeLogout("steward-1", markerSeconds + 5)).toEqual({
      status: "ambiguous_cooldown",
      retryAtEpochSeconds: markerSeconds + 6,
      retryAfterSeconds: 6,
    });
    expect(await classifySsoBridgeLogout("steward-1", markerSeconds + 6)).toEqual({
      status: "allowed",
    });

    // Waiting does not make the SAME ambiguous token valid. Once the boundary
    // is already past, Retry-After reaches zero but the caller must re-auth to
    // obtain a new iat; the compatibility predicate still blocks the old JWT.
    setSystemTime(new Date(fixedNow.getTime() + 10_000));
    expect(await classifySsoBridgeLogout("steward-1", markerSeconds + 1)).toEqual({
      status: "ambiguous_cooldown",
      retryAtEpochSeconds: markerSeconds + 6,
      retryAfterSeconds: 0,
    });
    expect(await isBlockedBySsoBridgeLogout("steward-1", markerSeconds + 1)).toBe(true);

    // Ordinary authorization remains fail-closed for the ambiguous interval.
    expect(await isBlockedBySsoBridgeLogout("steward-1", markerSeconds + 5)).toBe(true);
    expect(await isBlockedBySsoBridgeLogout("steward-1", markerSeconds + 6)).toBe(false);
    expect(getLogoutMarkerForWrite).toHaveBeenCalledWith("steward-1");
    expect(getLogoutMarker).not.toHaveBeenCalled();
  });
});
