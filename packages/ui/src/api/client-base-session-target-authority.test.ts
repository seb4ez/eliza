/** Exact, non-mutating authority for a staged client target. */
// @vitest-environment jsdom

import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_BOOT_CONFIG,
  setBootConfig,
} from "../config/boot-config-store";
import { ElizaClient } from "./client-base";

afterEach(() => {
  setBootConfig(DEFAULT_BOOT_CONFIG);
});

describe("SessionTargetAuthority.isCurrent", () => {
  it("checks the exact revision/base/token pair without mutating it", () => {
    const client = new ElizaClient("https://api.eliza.app", "old-token");
    const targetA = {
      baseUrl: "https://00000000-0000-4000-8000-000000000020.cloud.eliza.app",
      token: "token-a",
    };
    const authority = client.installSessionTarget(targetA, { persist: false });
    const revision = client.getAuthorityRevision();

    expect(authority?.isCurrent()).toBe(true);
    expect(authority?.isCurrent()).toBe(true);
    expect(client.getAuthorityRevision()).toBe(revision);
    expect(client.getBaseUrl()).toBe(targetA.baseUrl);
    expect(client.getRestAuthToken()).toBe(targetA.token);

    client.installSessionTarget(
      {
        baseUrl: "https://00000000-0000-4000-8000-000000000021.cloud.eliza.app",
        token: "token-b",
      },
      { persist: false },
    );
    client.installSessionTarget(targetA, { persist: false });

    expect(authority?.isCurrent()).toBe(false);
    expect(client.getBaseUrl()).toBe(targetA.baseUrl);
    expect(client.getRestAuthToken()).toBe(targetA.token);
  });
});
