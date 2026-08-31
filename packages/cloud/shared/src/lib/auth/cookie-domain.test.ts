import { describe, expect, it } from "bun:test";
import { legacyCookieCleanupDomainForHost } from "./cookie-domain";

describe("legacyCookieCleanupDomainForHost", () => {
  it("recognizes only the elizacloud.ai parent zone", () => {
    expect(legacyCookieCleanupDomainForHost("elizacloud.ai")).toBe("elizacloud.ai");
    expect(legacyCookieCleanupDomainForHost("API-Staging.ElizaCloud.AI:443")).toBe("elizacloud.ai");
    expect(legacyCookieCleanupDomainForHost("worker.elizacloud.ai.")).toBe("elizacloud.ai");
  });

  it.each([
    undefined,
    "",
    "eliza.app",
    "api.eliza.app",
    "elizacloud.ai.evil.example",
    "notelizacloud.ai",
    ".elizacloud.ai",
    "bad..elizacloud.ai",
    "-bad.elizacloud.ai",
    "bad-.elizacloud.ai",
    "api.elizacloud.ai:65536",
    "localhost:8787",
    "[::1]:8787",
  ])("rejects a non-elizacloud host: %s", (host) => {
    expect(legacyCookieCleanupDomainForHost(host)).toBeUndefined();
  });
});
