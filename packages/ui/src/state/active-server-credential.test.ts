/** Verifies persistActiveServerCredential through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * Shared active-server credential persistence over real jsdom localStorage,
 * covering the durable server and profile records without network mocks.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import * as storageBridge from "../bridge/storage-bridge";
import {
  persistActiveServerCredential,
  scrubRejectedActiveServerCredential,
  scrubRejectedActiveServerCredentialDurably,
} from "./active-server-credential";
import { getActiveProfile, loadAgentProfileRegistry } from "./agent-profiles";
import {
  createPersistedActiveServer,
  loadPersistedActiveServer,
  savePersistedActiveServer,
} from "./persistence";

describe("persistActiveServerCredential", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("updates the active remote server and its active profile", async () => {
    savePersistedActiveServer(
      createPersistedActiveServer({
        kind: "cloud",
        id: "cloud:test",
        label: "Cloud Test",
        apiBase: "https://runtime.example.test",
      }),
    );

    await persistActiveServerCredential("session-token");

    expect(loadPersistedActiveServer()?.accessToken).toBe("session-token");
    expect(getActiveProfile()?.accessToken).toBe("session-token");
  });

  it("persists a directly booted remote target before pairing reloads", async () => {
    await persistActiveServerCredential(
      "paired-token",
      "https://runtime.example.test/",
    );

    expect(loadPersistedActiveServer()).toEqual({
      id: "remote:https://runtime.example.test",
      kind: "remote",
      label: "runtime.example.test",
      apiBase: "https://runtime.example.test",
      accessToken: "paired-token",
    });
  });

  it("does not copy a remote pairing bearer into a stale Cloud profile", async () => {
    savePersistedActiveServer(
      createPersistedActiveServer({
        kind: "cloud",
        id: "cloud:personal:test",
        label: "Eliza",
        apiBase: "https://api.eliza.app/api/v1/eliza/agents/personal:test",
      }),
    );
    expect(getActiveProfile()?.kind).toBe("cloud");

    await persistActiveServerCredential(
      "vps-session",
      "https://runtime.example.test",
    );

    expect(loadPersistedActiveServer()).toMatchObject({
      kind: "remote",
      apiBase: "https://runtime.example.test",
      accessToken: "vps-session",
    });
    expect(getActiveProfile()).toMatchObject({
      kind: "remote",
      apiBase: "https://runtime.example.test",
      accessToken: "vps-session",
    });
    expect(
      loadAgentProfileRegistry().profiles.find(
        (profile) => profile.kind === "cloud",
      )?.accessToken,
    ).toBeUndefined();
  });

  it("scrubs a rejected active credential without dropping the target", async () => {
    savePersistedActiveServer(
      createPersistedActiveServer({
        kind: "remote",
        apiBase: "https://runtime.example.test",
        accessToken: "stale-token",
      }),
    );
    await persistActiveServerCredential("stale-token");

    scrubRejectedActiveServerCredential("stale-token");

    expect(loadPersistedActiveServer()).toMatchObject({
      kind: "remote",
      apiBase: "https://runtime.example.test",
    });
    expect(loadPersistedActiveServer()?.accessToken).toBeUndefined();
    expect(getActiveProfile()?.accessToken).toBeUndefined();
  });

  it("durably scrubs the rejected bearer from both active mirrors", async () => {
    savePersistedActiveServer(
      createPersistedActiveServer({
        kind: "remote",
        apiBase: "https://runtime.example.test",
        accessToken: "stale-token",
      }),
    );
    await persistActiveServerCredential("stale-token");

    await expect(
      scrubRejectedActiveServerCredentialDurably("stale-token"),
    ).resolves.toBe(true);

    expect(loadPersistedActiveServer()?.accessToken).toBeUndefined();
    expect(getActiveProfile()?.accessToken).toBeUndefined();
  });

  it("preserves a newer runtime B when rejected-A scrubs lose their exact compares", async () => {
    savePersistedActiveServer(
      createPersistedActiveServer({
        kind: "remote",
        apiBase: "https://runtime-a.example.test",
        accessToken: "account-a",
      }),
    );
    await persistActiveServerCredential("account-a");
    const registryA = loadAgentProfileRegistry();
    const profileA = getActiveProfile();
    if (!profileA) throw new Error("expected account-A profile");
    let plantedB = false;
    vi.spyOn(storageBridge, "setStorageValueIfCurrent").mockImplementation(
      async () => {
        if (!plantedB) {
          plantedB = true;
          const profileB = {
            ...profileA,
            id: "runtime-b",
            apiBase: "https://runtime-b.example.test",
            accessToken: "account-b",
          };
          localStorage.setItem(
            "elizaos:agent-profiles",
            JSON.stringify({
              ...registryA,
              activeProfileId: profileB.id,
              profiles: [profileB],
            }),
          );
          localStorage.setItem(
            "elizaos:active-server",
            JSON.stringify({
              id: "remote:https://runtime-b.example.test",
              kind: "remote",
              label: "runtime-b.example.test",
              apiBase: "https://runtime-b.example.test",
              accessToken: "account-b",
            }),
          );
        }
        return false;
      },
    );

    await expect(
      scrubRejectedActiveServerCredentialDurably("account-a"),
    ).resolves.toBe(true);
    expect(loadPersistedActiveServer()?.accessToken).toBe("account-b");
    expect(getActiveProfile()?.accessToken).toBe("account-b");
  });
});
