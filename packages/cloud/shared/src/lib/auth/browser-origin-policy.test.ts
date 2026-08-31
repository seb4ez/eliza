/**
 * Deterministic coverage for the exact-host Steward mutation policy, including
 * canonical, transition, same-origin, development, and hostile suffix cases.
 */

import { describe, expect, it } from "bun:test";
import {
  browserOriginHost,
  checkElizaMutatingRequestOrigin,
  checkStewardCookieWriterRequest,
  checkStewardNonceExchangeRequest,
  hasElizaNonSimpleRequestMarker,
  isPermittedElizaBrowserOrigin,
  serializedBrowserOrigin,
} from "./browser-origin-policy";

function headers(values: Record<string, string | undefined>) {
  return {
    header(name: string): string | undefined {
      return values[name];
    },
  };
}

function request(url: string, values: Record<string, string | undefined>) {
  const normalized = Object.fromEntries(
    Object.entries(values).map(([name, value]) => [name.toLowerCase(), value]),
  );
  return {
    url,
    header(name: string): string | undefined {
      return normalized[name.toLowerCase()];
    },
  };
}

describe("Steward browser origin policy", () => {
  it("accepts exact canonical and redirect-era first-party UI hosts", () => {
    for (const host of [
      "eliza.app",
      "www.eliza.app",
      "cloud.eliza.app",
      "staging.eliza.app",
      "cloud-staging.eliza.app",
      "elizacloud.ai",
      "app.elizacloud.ai",
    ]) {
      expect(isPermittedElizaBrowserOrigin(host, "api.eliza.app", true)).toBe(true);
    }
  });

  it("rejects unlisted subdomains and suffix-confusion hosts", () => {
    for (const host of [
      "evil.eliza.app",
      "agent.cloud.eliza.app",
      "blob.elizacloud.ai",
      "apps.elizacloud.ai",
      "eliza.app.evil.test",
    ]) {
      expect(isPermittedElizaBrowserOrigin(host, "api.eliza.app", true)).toBe(false);
    }
  });

  it("accepts an exact same-origin host without opening sibling hosts", () => {
    expect(
      isPermittedElizaBrowserOrigin("agent.cloud.eliza.app", "agent.cloud.eliza.app", true),
    ).toBe(true);
    expect(
      isPermittedElizaBrowserOrigin("evil.cloud.eliza.app", "agent.cloud.eliza.app", true),
    ).toBe(false);
  });

  it("allows localhost only outside production", () => {
    expect(isPermittedElizaBrowserOrigin("localhost", null, false)).toBe(true);
    expect(isPermittedElizaBrowserOrigin("localhost", null, true)).toBe(false);
  });

  it("requires a valid Origin or Referer and reports invalid input", () => {
    expect(browserOriginHost("not a url")).toBeNull();
    expect(checkElizaMutatingRequestOrigin(headers({}), true)).toEqual({
      ok: false,
      reason: "missing_origin_and_referer",
    });
    expect(
      checkElizaMutatingRequestOrigin(
        headers({
          host: "api.eliza.app",
          referer: "https://cloud.eliza.app/settings",
        }),
        true,
      ),
    ).toEqual({ ok: true });
  });

  it("accepts the custom CSRF header or a JSON content type as the non-simple marker", () => {
    expect(hasElizaNonSimpleRequestMarker(headers({ "x-eliza-csrf": "1" }))).toBe(true);
    expect(
      hasElizaNonSimpleRequestMarker(
        headers({ "content-type": "application/json; charset=utf-8" }),
      ),
    ).toBe(true);
    expect(hasElizaNonSimpleRequestMarker(headers({ "content-type": "Application/JSON" }))).toBe(
      true,
    );
  });

  it("rejects simple-request shapes that a cross-origin form/fetch can produce", () => {
    // No headers at all (curl-style or header-less simple request).
    expect(hasElizaNonSimpleRequestMarker(headers({}))).toBe(false);
    // CORS-safelisted content types never force a preflight.
    expect(hasElizaNonSimpleRequestMarker(headers({ "content-type": "text/plain" }))).toBe(false);
    expect(
      hasElizaNonSimpleRequestMarker(
        headers({ "content-type": "application/x-www-form-urlencoded" }),
      ),
    ).toBe(false);
    expect(
      hasElizaNonSimpleRequestMarker(
        headers({ "content-type": "multipart/form-data; boundary=x" }),
      ),
    ).toBe(false);
    // An empty marker value is not a marker.
    expect(hasElizaNonSimpleRequestMarker(headers({ "x-eliza-csrf": "  " }))).toBe(false);
  });
});

describe("strict Steward cookie-writer Fetch Metadata policy", () => {
  it("accepts only canonical same-environment Pages origins with same-origin metadata", () => {
    for (const origin of ["https://eliza.app", "https://cloud.eliza.app"]) {
      expect(
        checkStewardCookieWriterRequest(
          request("https://api.eliza.app/api/auth/logout", {
            origin,
            "sec-fetch-site": "same-origin",
          }),
          "production",
          true,
        ),
      ).toEqual({ ok: true });
    }
    for (const origin of ["https://staging.eliza.app", "https://cloud-staging.eliza.app"]) {
      expect(
        checkStewardCookieWriterRequest(
          request("https://api-staging.eliza.app/api/auth/logout", {
            origin,
            "sec-fetch-site": "same-origin",
          }),
          "staging",
          true,
        ),
      ).toEqual({ ok: true });
    }
  });

  it("rejects API, www, legacy, sibling-environment, and user-content origins", () => {
    for (const origin of [
      "https://api.eliza.app",
      "https://www.eliza.app",
      "https://elizacloud.ai",
      "https://app.elizacloud.ai",
      "https://staging.eliza.app",
      "https://evil.sites.eliza.app",
    ]) {
      expect(
        checkStewardCookieWriterRequest(
          request("https://api.eliza.app/api/auth/logout", {
            origin,
            "sec-fetch-site": "same-origin",
          }),
          "production",
          true,
        ).ok,
      ).toBe(false);
    }
  });

  it("requires a complete serialized Origin and same-origin Fetch Metadata", () => {
    expect(serializedBrowserOrigin("https://eliza.app")).toBe("https://eliza.app");
    for (const values of [
      { "sec-fetch-site": "same-origin" },
      { origin: "https://eliza.app" },
      { origin: "https://eliza.app/", "sec-fetch-site": "same-origin" },
      { origin: "http://eliza.app", "sec-fetch-site": "same-origin" },
      { origin: "https://eliza.app:444", "sec-fetch-site": "same-origin" },
      { origin: "https://eliza.app", "sec-fetch-site": "same-site" },
      { origin: "https://eliza.app", "sec-fetch-site": "cross-site" },
    ]) {
      expect(
        checkStewardCookieWriterRequest(
          request("https://api.eliza.app/api/auth/logout", values),
          "production",
          true,
        ).ok,
      ).toBe(false);
    }
  });

  it("bounds the session-POST OIDC exception to canonical marketing-to-API pairs", () => {
    expect(
      checkStewardCookieWriterRequest(
        request("https://api.eliza.app/api/auth/steward-session", {
          origin: "https://eliza.app",
          "sec-fetch-site": "same-site",
        }),
        "production",
        true,
        { allowCanonicalOidcSameSite: true },
      ),
    ).toEqual({ ok: true });
    expect(
      checkStewardCookieWriterRequest(
        request("https://api-staging.eliza.app/api/auth/steward-session", {
          origin: "https://staging.eliza.app",
          "sec-fetch-site": "same-site",
        }),
        "staging",
        true,
        { allowCanonicalOidcSameSite: true },
      ),
    ).toEqual({ ok: true });

    for (const candidate of [
      request("https://api.eliza.app/api/auth/logout", {
        origin: "https://eliza.app",
        "sec-fetch-site": "same-site",
      }),
      request("https://api.eliza.app/api/auth/steward-session", {
        origin: "https://cloud.eliza.app",
        "sec-fetch-site": "same-site",
      }),
      request("https://api-staging.eliza.app/api/auth/steward-session", {
        origin: "https://eliza.app",
        "sec-fetch-site": "same-site",
      }),
    ]) {
      expect(
        checkStewardCookieWriterRequest(
          candidate,
          candidate.url.includes("staging") ? "staging" : "production",
          true,
          { allowCanonicalOidcSameSite: candidate.url.includes("steward-session") },
        ).ok,
      ).toBe(false);
    }
  });

  it("allows exact production A/B and loopback documents only on their same-origin lane", () => {
    for (const origin of ["https://b.eliza.app", "https://eliza-app-b.pages.dev"]) {
      expect(
        checkStewardCookieWriterRequest(
          request("https://api.eliza.app/api/auth/steward-session", {
            origin,
            "sec-fetch-site": "same-origin",
          }),
          "production",
          true,
        ),
      ).toEqual({ ok: true });
    }
    expect(
      checkStewardCookieWriterRequest(
        request("http://127.0.0.1:8787/api/auth/logout", {
          origin: "http://127.0.0.1:8787",
          "sec-fetch-site": "same-origin",
        }),
        "development",
        false,
      ),
    ).toEqual({ ok: true });
    expect(
      checkStewardCookieWriterRequest(
        request("http://127.0.0.1:8787/api/auth/logout", {
          origin: "http://localhost:8787",
          "sec-fetch-site": "same-origin",
        }),
        "development",
        false,
      ).ok,
    ).toBe(false);
  });

  it("allows the exact develop Pages host only on the staging same-origin lane", () => {
    const stagingPagesRequest = request("https://api-staging.eliza.app/api/auth/steward-session", {
      origin: "https://develop.eliza-app.pages.dev",
      "sec-fetch-site": "same-origin",
    });
    expect(checkStewardCookieWriterRequest(stagingPagesRequest, "staging", true)).toEqual({
      ok: true,
    });
    expect(checkStewardCookieWriterRequest(stagingPagesRequest, "production", true).ok).toBe(false);

    for (const origin of [
      "https://preview.eliza-app.pages.dev",
      "https://develop.eliza-app.pages.dev.evil.test",
    ]) {
      expect(
        checkStewardCookieWriterRequest(
          request("https://api-staging.eliza.app/api/auth/steward-session", {
            origin,
            "sec-fetch-site": "same-origin",
          }),
          "staging",
          true,
        ).ok,
      ).toBe(false);
    }
    expect(
      checkStewardCookieWriterRequest(
        request("https://api-staging.eliza.app/api/auth/steward-session", {
          origin: "https://develop.eliza-app.pages.dev",
          "sec-fetch-site": "same-site",
        }),
        "staging",
        true,
      ).ok,
    ).toBe(false);
  });
});

describe("Steward nonce-exchange response mode", () => {
  it("uses cookie mode for canonical same-origin Pages requests", () => {
    expect(
      checkStewardNonceExchangeRequest(
        request("https://api.eliza.app/api/auth/steward-nonce-exchange", {
          origin: "https://eliza.app",
          "sec-fetch-site": "same-origin",
        }),
        "production",
        true,
      ),
    ).toEqual({ ok: true, responseMode: "cookie" });
  });

  it("permits only exact checkout origins on a bearer-only cross-site lane", () => {
    for (const origin of ["https://elizaos.ai", "https://www.elizaos.ai"]) {
      expect(
        checkStewardNonceExchangeRequest(
          request("https://api.eliza.app/api/auth/steward-nonce-exchange", {
            origin,
            "sec-fetch-site": "cross-site",
          }),
          "production",
          true,
        ),
      ).toEqual({ ok: true, responseMode: "bearer-only" });
    }
    for (const candidate of [
      request("https://api.eliza.app/api/auth/steward-nonce-exchange", {
        origin: "https://checkout.elizaos.ai",
        "sec-fetch-site": "cross-site",
      }),
      request("https://api.eliza.app/api/auth/steward-nonce-exchange", {
        origin: "https://elizaos.ai",
        "sec-fetch-site": "same-site",
      }),
      request("https://api-staging.eliza.app/api/auth/steward-nonce-exchange", {
        origin: "https://elizaos.ai",
        "sec-fetch-site": "cross-site",
      }),
    ]) {
      expect(checkStewardNonceExchangeRequest(candidate, "production", true).ok).toBe(false);
    }
  });
});
