/**
 * Hosted v2 names are browser-enforced host cookies. The generic auth reader is
 * v2-only; historical v1 state is exposed only by the explicit migration reader
 * used by independently authorized cookie writers.
 */

import { describe, expect, it } from "vitest";
import {
  canMutateLegacyStewardCookies,
  LEGACY_STEWARD_COOKIES,
  LOCAL_STEWARD_V2_COOKIES,
  legacyStewardCookieNames,
  readStewardAccessCookieFromHeader,
  readStewardSessionCookieStateFromHeader,
  readStewardSessionMigrationCookieStateFromHeader,
  STEWARD_V2_COOKIES,
  stewardCookieNames,
  stewardV2CookiesAreHostBound,
} from "./steward-cookies";

describe("stewardCookieNames", () => {
  it("production and unset use rollout-isolated v2 names", () => {
    expect(stewardCookieNames("production")).toEqual(STEWARD_V2_COOKIES);
    expect(stewardCookieNames(undefined)).toEqual(STEWARD_V2_COOKIES);
  });

  it("staging v2 names are suffixed and disjoint from every v1 name", () => {
    const staging = stewardCookieNames("staging");
    expect(staging).toEqual({
      token: "__Host-steward-token-v2-staging",
      refreshToken: "__Host-steward-refresh-token-v2-staging",
      authed: "__Host-steward-authed-v2-staging",
    });
    expect(staging.token).not.toBe(LEGACY_STEWARD_COOKIES.token);
    expect(staging.refreshToken).not.toBe(LEGACY_STEWARD_COOKIES.refreshToken);
    expect(staging.authed).not.toBe(LEGACY_STEWARD_COOKIES.authed);
  });

  it("uses non-prefixed names only for the explicit local HTTP environment", () => {
    expect(stewardCookieNames("local")).toEqual({
      token: "steward-token-v2-local",
      refreshToken: "steward-refresh-token-v2-local",
      authed: "steward-authed-v2-local",
    });
    expect(LOCAL_STEWARD_V2_COOKIES.token).not.toMatch(/^__Host-/);
    expect(stewardV2CookiesAreHostBound("local")).toBe(false);
    expect(stewardV2CookiesAreHostBound("staging")).toBe(true);
    expect(stewardV2CookiesAreHostBound("production")).toBe(true);
    expect(stewardV2CookiesAreHostBound(undefined)).toBe(true);
  });

  it("keeps explicit v1 names available only for migration and cleanup", () => {
    expect(legacyStewardCookieNames("production")).toEqual(LEGACY_STEWARD_COOKIES);
    expect(legacyStewardCookieNames("staging")).toEqual({
      token: "steward-token-staging",
      refreshToken: "steward-refresh-token-staging",
      authed: "steward-authed-staging",
    });
  });
});

describe("canMutateLegacyStewardCookies", () => {
  it("limits legacy mutations to production and unset local environments", () => {
    expect(canMutateLegacyStewardCookies("production")).toBe(true);
    expect(canMutateLegacyStewardCookies(undefined)).toBe(true);
    expect(canMutateLegacyStewardCookies("staging")).toBe(false);
    expect(canMutateLegacyStewardCookies("preview")).toBe(false);
  });
});

describe("readStewardAccessCookieFromHeader v2 rollout isolation", () => {
  it("prefers the v2 access cookie and never mixes namespaces", () => {
    expect(
      readStewardAccessCookieFromHeader(
        "steward-token-staging=v1; __Host-steward-token-v2-staging=v2; steward-refresh-token-staging=v1-refresh",
        "staging",
      ),
    ).toBe("v2");
    expect(
      readStewardSessionCookieStateFromHeader(
        "__Host-steward-token-v2-staging=v2; steward-refresh-token-staging=v1-refresh",
        "staging",
      ),
    ).toEqual({
      ambiguous: false,
      v2Authority: "absent",
      source: "v2",
      token: "v2",
      refreshToken: undefined,
    });
  });

  it("never authenticates from an ambient v1 cookie when v2 is absent", () => {
    expect(
      readStewardAccessCookieFromHeader(
        "steward-token=prod; steward-token-staging=stage",
        "staging",
      ),
    ).toBeUndefined();
    expect(readStewardAccessCookieFromHeader("steward-token=prod", "staging")).toBeUndefined();
    expect(readStewardAccessCookieFromHeader("steward-token=prod", "production")).toBeUndefined();
    expect(readStewardAccessCookieFromHeader("steward-token=local", undefined)).toBeUndefined();
  });

  it("exposes exact v1 credentials only through the explicit migration reader", () => {
    expect(
      readStewardSessionMigrationCookieStateFromHeader(
        "steward-token=prod; steward-refresh-token=refresh",
        "production",
      ),
    ).toEqual({
      ambiguous: false,
      v2Authority: "absent",
      source: "v1",
      token: "prod",
      refreshToken: "refresh",
    });
    expect(
      readStewardSessionCookieStateFromHeader(
        "steward-token=prod; steward-refresh-token=refresh",
        "production",
      ),
    ).toEqual({
      ambiguous: false,
      v2Authority: "absent",
      source: null,
      token: undefined,
      refreshToken: undefined,
    });
  });

  it("a v2 active marker makes a late v1 logout unable to erase v2", () => {
    expect(
      readStewardSessionCookieStateFromHeader(
        "__Host-steward-token-v2=account-b; __Host-steward-refresh-token-v2=refresh-b; __Host-steward-authed-v2=1",
        "production",
      ),
    ).toEqual({
      ambiguous: false,
      v2Authority: "active",
      source: "v2",
      token: "account-b",
      refreshToken: "refresh-b",
    });
  });

  it("a v2 tombstone makes a late v1 login unable to revive authentication", () => {
    const cookies =
      "__Host-steward-authed-v2=0; steward-token=late-account-a; steward-refresh-token=late-refresh-a; steward-authed=1";
    expect(readStewardSessionCookieStateFromHeader(cookies, "production")).toEqual({
      ambiguous: false,
      v2Authority: "tombstone",
      source: "v2",
      token: undefined,
      refreshToken: undefined,
    });
    expect(readStewardAccessCookieFromHeader(cookies, "production")).toBeUndefined();
  });

  it("fails closed on a malformed present v2 marker", () => {
    expect(
      readStewardAccessCookieFromHeader(
        "__Host-steward-authed-v2=wat; steward-token=late-v1",
        "production",
      ),
    ).toBeUndefined();
  });

  it("ignores a domain-cookie lookalike and reads only the host-bound name", () => {
    expect(
      readStewardSessionCookieStateFromHeader(
        "steward-token-v2=domain-attacker; steward-authed-v2=1; __Host-steward-token-v2=host-session; __Host-steward-authed-v2=1",
        "production",
      ),
    ).toEqual({
      ambiguous: false,
      v2Authority: "active",
      source: "v2",
      token: "host-session",
      refreshToken: undefined,
    });
  });

  it("fails closed on duplicate exact host-bound cookie names", () => {
    expect(
      readStewardSessionCookieStateFromHeader(
        "__Host-steward-token-v2=domain-order-a; __Host-steward-token-v2=host-order-b; __Host-steward-authed-v2=1",
        "production",
      ),
    ).toEqual({
      ambiguous: true,
      v2Authority: "tombstone",
      source: "v2",
      token: undefined,
      refreshToken: undefined,
    });
  });

  it("returns undefined when no cookie is present", () => {
    expect(readStewardAccessCookieFromHeader(null, "staging")).toBeUndefined();
    expect(readStewardAccessCookieFromHeader("", "production")).toBeUndefined();
  });
});
