/**
 * Coverage for JWT lifetime validation.
 */
import { describe, expect, it } from "vitest";

import { validateJwtLifetime } from "./jwt-lifetime.js";

const POLICY = {
  maxTtlSeconds: 3600,
  clockToleranceSeconds: 60,
  futureIssuedAtToleranceSeconds: 5,
  nowSeconds: 1000,
};

describe("validateJwtLifetime", () => {
  it("validates good payload", () => {
    expect(validateJwtLifetime({ iat: 900, exp: 1500 }, POLICY)).toEqual({
      valid: true,
    });
  });

  it("rejects missing iat", () => {
    expect(validateJwtLifetime({ exp: 1500 } as never, POLICY).valid).toBe(false);
  });

  it("rejects exp <= iat", () => {
    expect(validateJwtLifetime({ iat: 1000, exp: 1000 }, POLICY).valid).toBe(false);
    expect(validateJwtLifetime({ iat: 1000, exp: 900 }, POLICY).valid).toBe(false);
  });

  it("rejects ttl too long", () => {
    expect(validateJwtLifetime({ iat: 0, exp: 4000 }, POLICY).valid).toBe(false);
  });

  it("accepts iat at the future-issued boundary and rejects one second beyond it", () => {
    expect(validateJwtLifetime({ iat: 1005, exp: 1500 }, POLICY).valid).toBe(true);
    expect(validateJwtLifetime({ iat: 1006, exp: 1500 }, POLICY).valid).toBe(false);
  });

  it("rejects exp in past beyond tolerance", () => {
    expect(validateJwtLifetime({ iat: 100, exp: 200 }, POLICY).valid).toBe(false);
  });

  it("validates nbf", () => {
    expect(validateJwtLifetime({ iat: 900, exp: 1500, nbf: 1000 }, POLICY).valid).toBe(true);
    expect(validateJwtLifetime({ iat: 900, exp: 1500, nbf: 1600 }, POLICY).valid).toBe(false);
  });

  it("rejects non-integer nbf", () => {
    expect(validateJwtLifetime({ iat: 900, exp: 1500, nbf: 1.5 } as never, POLICY).valid).toBe(
      false,
    );
  });
});
