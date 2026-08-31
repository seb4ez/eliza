/**
 * Validates the bounded lifetime shared by Cloud's symmetric bearer-token verifiers.
 * Clock tolerances apply to verifier/issuer disagreement, never to the minted lifetime.
 * Future `iat` tolerance may be kept tighter than expiry/not-before tolerance.
 */

import type { JWTPayload } from "jose";

export interface JwtLifetimePolicy {
  maxTtlSeconds: number;
  clockToleranceSeconds: number;
  /**
   * Maximum issuer-ahead allowance for `iat`. Defaults to the general clock
   * tolerance for existing callers; security-sensitive ordering policies
   * should provide a tighter value explicitly.
   */
  futureIssuedAtToleranceSeconds?: number;
  nowSeconds?: number;
}

export type JwtLifetimeResult = { valid: true } | { valid: false; reason: string };

function isNumericDate(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** Validate required issued-at/expiry claims and their relationship. */
export function validateJwtLifetime(
  payload: Pick<JWTPayload, "exp" | "iat" | "nbf">,
  policy: JwtLifetimePolicy,
): JwtLifetimeResult {
  const now = policy.nowSeconds ?? Math.floor(Date.now() / 1000);
  const futureIssuedAtToleranceSeconds =
    policy.futureIssuedAtToleranceSeconds ?? policy.clockToleranceSeconds;

  if (!isNumericDate(payload.iat)) {
    return { valid: false, reason: "iat must be a non-negative safe-integer NumericDate" };
  }
  if (!isNumericDate(payload.exp)) {
    return { valid: false, reason: "exp must be a non-negative safe-integer NumericDate" };
  }
  if (payload.nbf !== undefined && !isNumericDate(payload.nbf)) {
    return { valid: false, reason: "nbf must be a non-negative safe-integer NumericDate" };
  }
  if (payload.exp <= payload.iat) {
    return { valid: false, reason: "exp must be later than iat" };
  }
  if (payload.exp - payload.iat > policy.maxTtlSeconds) {
    return { valid: false, reason: "issued lifetime exceeds the configured maximum" };
  }
  if (payload.iat > now + futureIssuedAtToleranceSeconds) {
    return { valid: false, reason: "iat is beyond the allowed future clock tolerance" };
  }
  if (payload.exp <= now - policy.clockToleranceSeconds) {
    return { valid: false, reason: "exp is outside the allowed clock tolerance" };
  }
  if (payload.nbf !== undefined && payload.nbf > payload.exp) {
    return { valid: false, reason: "nbf must not be later than exp" };
  }

  return { valid: true };
}
