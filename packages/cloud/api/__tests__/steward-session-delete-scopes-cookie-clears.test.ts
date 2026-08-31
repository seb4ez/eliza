/**
 * Steward session cookie clears must respect environment ownership. Production
 * owns the historical unsuffixed names on the shared parent domain; staging/dev
 * own only their suffixed names and must never delete production's live legacy
 * cookies. Cleanup on an elizacloud.ai host emits both host-only and historical
 * parent-Domain tombstones, while every v2 cookie stays host-bound.
 */

import {
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
} from "@elizaos/shared/steward-session-client";
import { describe, expect, it } from "vitest";
import app from "../auth/steward-session/route";

function deletedCookieNames(res: Response): string[] {
  return res.headers
    .getSetCookie()
    .filter((c) => /Max-Age=0/i.test(c))
    .map((c) => c.split("=")[0]);
}

function clearsFor(res: Response, name: string): string[] {
  return res.headers
    .getSetCookie()
    .filter((cookie) => cookie.startsWith(`${name}=`));
}

describe("DELETE /api/auth/steward-session cookie clearing", () => {
  it("rejects a simple request without the non-simple marker", async () => {
    const res = await app.request(
      "/",
      {
        method: "DELETE",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          "sec-fetch-site": "same-origin",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "test" },
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: "csrf_marker_required" });
    expect(res.headers.getSetCookie()).toHaveLength(0);
  });

  it("legacy clear removes v1 and closes the v2 authority boundary", async () => {
    const res = await app.request(
      "/",
      {
        method: "DELETE",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "steward-token-staging=legacy; steward-refresh-token-staging=legacy-refresh; steward-authed-staging=1",
          "x-eliza-csrf": STEWARD_CSRF_HEADER_VALUE,
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "test" },
    );
    expect(res.status).toBe(200);
    expect(deletedCookieNames(res)).toEqual(
      expect.arrayContaining([
        "steward-token-staging",
        "steward-refresh-token-staging",
        "steward-authed-staging",
      ]),
    );
    expect(res.headers.getSetCookie()).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2-staging=0"),
      ]),
    );
    const tombstone = res.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith("__Host-steward-authed-v2-staging="));
    expect(tombstone).toContain("Path=/");
    expect(tombstone).toContain("Secure");
    expect(tombstone).not.toContain("Domain=");
    for (const name of [
      "steward-token-staging",
      "steward-refresh-token-staging",
      "steward-authed-staging",
    ]) {
      expect(clearsFor(res, name)).toHaveLength(2);
      expect(
        clearsFor(res, name).some((cookie) =>
          cookie.includes("Domain=elizacloud.ai"),
        ),
      ).toBe(true);
      expect(
        clearsFor(res, name).some((cookie) => !cookie.includes("Domain=")),
      ).toBe(true);
    }
  });

  it("duplicate host-only and Domain v1 cookies are still cleaned without touching production", async () => {
    const res = await app.request(
      "/",
      {
        method: "DELETE",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "steward-token-staging=host; steward-token-staging=domain; steward-refresh-token-staging=host-refresh; steward-refresh-token-staging=domain-refresh; steward-authed-staging=1",
          "x-eliza-csrf": STEWARD_CSRF_HEADER_VALUE,
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "test" },
    );

    expect(res.status).toBe(200);
    for (const name of [
      "steward-token-staging",
      "steward-refresh-token-staging",
      "steward-authed-staging",
    ]) {
      expect(clearsFor(res, name)).toHaveLength(2);
    }
    expect(clearsFor(res, "steward-token")).toHaveLength(0);
    expect(clearsFor(res, "steward-refresh-token")).toHaveLength(0);
    expect(clearsFor(res, "steward-authed")).toHaveLength(0);
    expect(
      res.headers
        .getSetCookie()
        .find((cookie) =>
          cookie.startsWith("__Host-steward-authed-v2-staging="),
        ),
    ).not.toContain("Domain=");
  });

  it("rejects a legacy clear after v2 activation", async () => {
    const res = await app.request(
      "/",
      {
        method: "DELETE",
        headers: {
          origin: "https://staging.eliza.app",
          "sec-fetch-site": "same-origin",
          cookie:
            "__Host-steward-authed-v2-staging=1; __Host-steward-token-v2-staging=current; steward-token-staging=late-legacy",
          "x-eliza-csrf": STEWARD_CSRF_HEADER_VALUE,
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "test" },
    );

    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      code: "session_mutation_protocol_required",
    });
    expect(res.headers.getSetCookie()).toHaveLength(0);
  });

  it("staging v2 clear tombstones authority and clears only staging names", async () => {
    const res = await app.request(
      "/",
      {
        method: "DELETE",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          "sec-fetch-site": "same-origin",
          "x-eliza-csrf": STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "test" },
    );
    expect(res.status).toBe(200);
    const cleared = deletedCookieNames(res);
    expect(cleared).toContain("__Host-steward-token-v2-staging");
    expect(cleared).toContain("__Host-steward-refresh-token-v2-staging");
    expect(cleared).toContain("steward-token-staging");
    expect(cleared).toContain("steward-refresh-token-staging");
    expect(cleared).toContain("steward-authed-staging");
    expect(cleared).not.toContain("steward-token");
    expect(cleared).not.toContain("steward-refresh-token");
    expect(cleared).not.toContain("steward-authed");
    expect(res.headers.getSetCookie()).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2-staging=0"),
      ]),
    );
  });

  it("production clears the historical pair (both eras resolve to the same names)", async () => {
    const res = await app.request(
      "/",
      {
        method: "DELETE",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          "sec-fetch-site": "same-origin",
          "x-eliza-csrf": STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "test" },
    );
    expect(res.status).toBe(200);
    const cleared = deletedCookieNames(res);
    expect(cleared).toContain("__Host-steward-token-v2");
    expect(cleared).toContain("__Host-steward-refresh-token-v2");
    expect(cleared).toContain("steward-token");
    expect(cleared).toContain("steward-refresh-token");
    expect(cleared).toContain("steward-authed");
    expect(res.headers.getSetCookie()).toEqual(
      expect.arrayContaining([
        expect.stringContaining("__Host-steward-authed-v2=0"),
      ]),
    );
    for (const cookie of res.headers
      .getSetCookie()
      .filter((value) => value.startsWith("__Host-"))) {
      expect(cookie).toContain("Path=/");
      expect(cookie).toContain("Secure");
      expect(cookie).not.toContain("Domain=");
    }
  });
});
