/**
 * Single-use code + logout-marker service for the cross-host SSO bridge
 * (`/api/auth/sso-bridge` — dashboard origin ↔ Eliza app origin).
 *
 * BACKED BY POSTGRES, DELIBERATELY NOT THE CACHE: the deployed Worker's cache
 * is Cloudflare KV (`CacheClient.initialize()` prefers the `CACHE_KV` binding
 * in a Worker), which is eventually consistent and has no atomic operations —
 * its `getdel`/`set NX` emulations are racy by their own documentation, and
 * `CacheClient.supportsAtomicOperations()` returns false for it. A cache-based
 * code store therefore CANNOT deliver "consumed exactly once", and a
 * cache-based logout marker can stay invisible (or vanish) for ~60s — long
 * enough to cover the whole code TTL. Postgres — already the Worker's
 * strongly-consistent store for sessions and idempotency fences — gives both
 * guarantees: `DELETE … RETURNING` claims a code atomically, and marker
 * reads are read-your-writes.
 *
 * Codes are opaque 256-bit values with a ≤60s TTL, stored ONLY as their
 * sha256, bound to a PKCE-style challenge (sha256 of a verifier that never
 * appears in any URL), and carrying the VERIFIED claims of the minting
 * session — never the session token itself (a DB dump yields no usable code,
 * verifier, or token). The exchange leg re-mints a fresh token from those
 * claims, capped to the original token's expiry.
 *
 * Failure semantics are fail-closed: every store error THROWS to the route
 * boundary (503 → the client falls back to the normal per-origin login).
 * Because codes and markers share the one store, an outage that could hide a
 * logout marker also disables minting and exchanging entirely.
 */

import { ssoBridgeRepository } from "../../db/repositories/sso-bridge";
import {
  STEWARD_FUTURE_ISSUED_AT_TOLERANCE_SECONDS,
  STEWARD_VERIFY_CLOCK_SKEW_SECONDS,
  type StewardTokenClaims,
} from "../auth/steward-client";
import { STEWARD_REFRESH_AUTHORITY_TTL_SECONDS } from "../auth/steward-cookies";

export const SSO_BRIDGE_CODE_TTL_SECONDS = 60;
const SSO_BRIDGE_CODE_PREFIX = "esso_";

/**
 * Keep a logout marker beyond the full opaque-refresh lifetime. The verifier
 * skew and bounded future-iat allowance are retained as a conservative clock
 * boundary between cookie issuance and marker storage; the final extra second
 * keeps the repository's inclusive purge cutoff strictly outside that horizon.
 */
export const SSO_BRIDGE_LOGOUT_MARKER_TTL_SECONDS =
  STEWARD_REFRESH_AUTHORITY_TTL_SECONDS +
  STEWARD_VERIFY_CLOCK_SKEW_SECONDS +
  STEWARD_FUTURE_ISSUED_AT_TOLERANCE_SECONDS +
  1;

const HEX_64_RE = /^[0-9a-f]{64}$/;

export interface SsoBridgeCodeRecord {
  stewardUserId: string;
  /** Verified claims of the ORIGINAL session; the exchange re-mints from these. */
  claims: StewardTokenClaims;
  /** iat (unix seconds) of the original token — logout-marker ordering input. */
  tokenIssuedAt: number;
  /** exp (unix seconds) of the original token — re-mint cap. */
  tokenExpiresAt: number;
}

function createOpaqueHex(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function looksLikeSsoBridgeCode(value: string | null | undefined): value is string {
  return (
    typeof value === "string" &&
    value.startsWith(SSO_BRIDGE_CODE_PREFIX) &&
    HEX_64_RE.test(value.slice(SSO_BRIDGE_CODE_PREFIX.length))
  );
}

/** Challenge and verifier are both 64 lowercase hex chars (sha256 / 32 bytes). */
export function looksLikeSsoBridgeChallenge(value: string | null | undefined): value is string {
  return typeof value === "string" && HEX_64_RE.test(value);
}

export async function issueSsoBridgeCode(input: {
  claims: StewardTokenClaims;
  codeChallenge: string;
}): Promise<{ code: string; expiresIn: number }> {
  if (!looksLikeSsoBridgeChallenge(input.codeChallenge)) {
    throw new Error("SSO bridge mint requires a well-formed code challenge");
  }

  const now = new Date();
  // Opportunistic hygiene on the hot row set; both tables stay tiny.
  await ssoBridgeRepository.purgeExpiredCodes(now);

  const code = `${SSO_BRIDGE_CODE_PREFIX}${createOpaqueHex()}`;
  await ssoBridgeRepository.insertCode({
    code_hash: await sha256Hex(code),
    steward_user_id: input.claims.userId,
    code_challenge: input.codeChallenge,
    claims: input.claims as unknown as Record<string, unknown>,
    token_issued_at: new Date(input.claims.issuedAt * 1000),
    token_expires_at: new Date(input.claims.expiration * 1000),
    expires_at: new Date(now.getTime() + SSO_BRIDGE_CODE_TTL_SECONDS * 1000),
  });

  return { code, expiresIn: SSO_BRIDGE_CODE_TTL_SECONDS };
}

/**
 * Claim-then-verify, in that order: the atomic `DELETE … RETURNING` burns the
 * code FIRST (exactly one presenter of any concurrent set receives the row —
 * replays and race losers get null), and only then is the PKCE verifier
 * checked against the stored challenge. A presentation with a wrong or
 * missing verifier therefore still destroys the code — which is exactly what
 * the client's abandoned-handshake path relies on to burn a live code it
 * refuses to exchange.
 */
export async function consumeSsoBridgeCode(
  code: string,
  codeVerifier: string | null,
): Promise<SsoBridgeCodeRecord | null> {
  if (!looksLikeSsoBridgeCode(code)) return null;

  const row = await ssoBridgeRepository.claimCode(await sha256Hex(code));
  if (!row) return null;

  if (!looksLikeSsoBridgeChallenge(codeVerifier)) return null;
  if ((await sha256Hex(codeVerifier)) !== row.code_challenge) return null;

  const claims = row.claims as unknown as StewardTokenClaims;
  const tokenIssuedAt = Math.floor(row.token_issued_at.getTime() / 1000);
  const tokenExpiresAt = Math.floor(row.token_expires_at.getTime() / 1000);
  if (tokenExpiresAt * 1000 <= Date.now()) return null;

  return { stewardUserId: row.steward_user_id, claims, tokenIssuedAt, tokenExpiresAt };
}

/** Stamp "this user explicitly logged out now" for the bridge to honor. */
export async function markSsoBridgeLogout(stewardUserId: string): Promise<void> {
  const { databaseNow } = await ssoBridgeRepository.stampLogout(stewardUserId);
  await ssoBridgeRepository.purgeLogoutMarkersOlderThan(
    new Date(databaseNow.getTime() - SSO_BRIDGE_LOGOUT_MARKER_TTL_SECONDS * 1000),
  );
}

export type SsoBridgeLogoutClassification =
  | { status: "allowed" }
  | { status: "definitely_revoked" }
  | {
      /**
       * The signed second-resolution `iat` is newer than the marker but still
       * inside the verifier's bounded future-clock allowance. It may be either
       * a genuinely fresh login or a pre-logout token from a fast issuer. The
       * token therefore stays blocked, but session-establishment routes must
       * report a retryable reauthentication cooldown instead of claiming that
       * the new login was itself revoked.
       */
      status: "ambiguous_cooldown";
      /** First unix second whose newly minted token is unambiguously newer. */
      retryAtEpochSeconds: number;
      /** Whole seconds remaining before `retryAtEpochSeconds` (may be zero). */
      retryAfterSeconds: number;
    };

/**
 * Order a verified token against the last explicit logout without weakening
 * the bounded future-iat defense.
 *
 * A token whose signed second is earlier than the marker's signed second is
 * definitely revoked. The marker's own second and the accepted issuer-clock
 * tolerance ahead are ambiguous: the token remains unusable, because
 * accepting it could resurrect a pre-logout token from a fast issuer.
 * Establishment routes may surface that ambiguity as a truthful cooldown and
 * require a newly minted token after the boundary. Store failures THROW —
 * callers translate that into an unavailable response, never into "allowed".
 */
export async function classifySsoBridgeLogout(
  stewardUserId: string,
  tokenIssuedAtSeconds: number,
): Promise<SsoBridgeLogoutClassification> {
  // Authentication/re-publication is a security decision and must observe the
  // primary connection. A replica read could briefly resurrect a bridged token
  // immediately after an acknowledged logout stamp.
  const marker = await ssoBridgeRepository.getLogoutMarkerForWrite(stewardUserId);
  if (!marker) return { status: "allowed" };

  const markerMs = marker.logged_out_at.getTime();
  const markerEpochSeconds = Math.floor(markerMs / 1000);
  // Steward `iat` has only whole-second precision. A token carrying the same
  // second as the marker may have been minted just before OR just after the
  // sub-second logout commit, so it is not definitely revoked. It remains
  // blocked below as ambiguous. Only an earlier signed second is provably old.
  if (tokenIssuedAtSeconds < markerEpochSeconds) {
    return { status: "definitely_revoked" };
  }

  const tokenIssuedAtMs = tokenIssuedAtSeconds * 1000;
  const ambiguousThroughMs = markerMs + STEWARD_FUTURE_ISSUED_AT_TOLERANCE_SECONDS * 1000;
  if (tokenIssuedAtMs <= ambiguousThroughMs) {
    // `iat` has whole-second precision and `allowed` requires a strict `>`.
    // Advance to the first whole second strictly beyond the ambiguity window.
    const retryAtEpochSeconds = Math.floor(ambiguousThroughMs / 1000) + 1;
    const retryAfterSeconds = Math.max(
      0,
      Math.ceil((retryAtEpochSeconds * 1000 - Date.now()) / 1000),
    );
    return {
      status: "ambiguous_cooldown",
      retryAtEpochSeconds,
      retryAfterSeconds,
    };
  }

  return { status: "allowed" };
}

/**
 * Fail-closed compatibility predicate for ordinary authorization and refresh
 * paths. Both definitely-revoked and time-ambiguous tokens remain blocked.
 */
export async function isBlockedBySsoBridgeLogout(
  stewardUserId: string,
  tokenIssuedAtSeconds: number,
): Promise<boolean> {
  return (await classifySsoBridgeLogout(stewardUserId, tokenIssuedAtSeconds)).status !== "allowed";
}
