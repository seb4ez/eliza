/** Verifies complete browser teardown of an account-scoped shared Cloud binding under jsdom. */
// @vitest-environment jsdom

import { cloudPairTokenKeyForAgent } from "@elizaos/shared/contracts";
import { STEWARD_TOKEN_KEY } from "@elizaos/shared/steward-session-client";
import { beforeEach, describe, expect, it } from "vitest";
import {
  beginStewardSessionRecovery,
  completeStewardSessionRecovery,
} from "../cloud/lib/steward-session-recovery-marker";
import { clearStaleStewardSession } from "../cloud/shell/StewardProviderShared";
import { persistCloudPairApiToken } from "../components/auth/CloudPairRelay";
import { getBootConfig, setBootConfig } from "../config/boot-config";
import {
  clearManagedSharedCloudProfilesAndTokensDurably,
  loadAgentProfileRegistry,
  saveAgentProfileRegistry,
} from "./agent-profiles";
import {
  captureFirstRunAccountResetAuthority,
  loadPersistedActiveServer,
  loadPersistedFirstRunComplete,
  markFirstRunIncompleteForAccountIfCurrent,
  savePersistedActiveServer,
  savePersistedFirstRunComplete,
} from "./persistence";
import {
  captureManagedCloudAccountBindingAuthority,
  clearManagedCloudAccountBinding,
  clearSharedCloudAccountBinding,
  clearSharedCloudAccountBindingDurably,
  sharedCloudAccountBindingInternals,
} from "./shared-cloud-account-binding";

const SHARED_BASE =
  "https://api.eliza.app/api/v1/eliza/agents/previous-account-agent";

describe("clearSharedCloudAccountBinding", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    setBootConfig({
      branding: {},
      apiBase: SHARED_BASE,
      apiToken: "previous-account-token",
    });
  });

  it("clears active-server, profile, boot, and legacy base mirrors", () => {
    savePersistedActiveServer({
      id: "cloud:previous-account-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: SHARED_BASE,
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "old-profile",
      profiles: [
        {
          id: "old-profile",
          kind: "cloud",
          label: "Eliza Cloud",
          apiBase: SHARED_BASE,
          createdAt: new Date().toISOString(),
        },
        {
          id: "inactive-old-profile",
          kind: "cloud",
          label: "Other old shared agent",
          apiBase: "https://api.eliza.app/api/v1/eliza/agents/other-old-agent",
          createdAt: new Date().toISOString(),
        },
        {
          id: "legacy-shared-profile",
          kind: "cloud",
          label: "Legacy shared agent",
          apiBase:
            "https://api.eliza.app/api/v1/eliza/agents/legacy-agent/bridge",
          createdAt: new Date().toISOString(),
        },
        {
          id: "self-hosted-profile",
          kind: "remote",
          label: "Self hosted",
          apiBase: "https://box.example/api/v1/eliza/agents/local-agent",
          createdAt: new Date().toISOString(),
        },
      ],
    });
    localStorage.setItem("elizaos_api_base", SHARED_BASE);
    sessionStorage.setItem("elizaos_api_base", SHARED_BASE);

    expect(clearSharedCloudAccountBinding()).toBe(true);

    expect(loadPersistedActiveServer()).toBeNull();
    expect(loadAgentProfileRegistry()).toEqual({
      version: 1,
      activeProfileId: null,
      profiles: [
        expect.objectContaining({
          id: "self-hosted-profile",
          apiBase: "https://box.example/api/v1/eliza/agents/local-agent",
        }),
      ],
    });
    expect(getBootConfig().apiBase).toBeUndefined();
    expect(getBootConfig().apiToken).toBeUndefined();
    expect(localStorage.getItem("elizaos_api_base")).toBeNull();
    expect(sessionStorage.getItem("elizaos_api_base")).toBeNull();
  });

  it("clears dedicated Cloud selection while preserving self-hosted profiles", async () => {
    const dedicatedBase =
      "https://dedicated-agent.cloud.eliza.app/api/v1/eliza/agents/dedicated-agent";
    savePersistedActiveServer({
      id: "cloud:dedicated-agent",
      kind: "cloud",
      label: "Dedicated agent",
      apiBase: dedicatedBase,
      accessToken: "dedicated-pair-token",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "dedicated-profile",
      profiles: [
        {
          id: "dedicated-profile",
          kind: "cloud",
          label: "Dedicated agent",
          apiBase: dedicatedBase,
          accessToken: "dedicated-pair-token",
          createdAt: new Date().toISOString(),
        },
        {
          id: "self-hosted-profile",
          kind: "remote",
          label: "Self hosted",
          apiBase: "https://box.example/api",
          accessToken: "self-hosted-token",
          createdAt: new Date().toISOString(),
        },
      ],
    });

    const authority = await captureManagedCloudAccountBindingAuthority();
    await clearManagedCloudAccountBinding(authority);

    expect(loadPersistedActiveServer()).toBeNull();
    expect(loadAgentProfileRegistry()).toEqual({
      version: 1,
      activeProfileId: null,
      profiles: [
        expect.objectContaining({
          id: "self-hosted-profile",
          accessToken: "self-hosted-token",
        }),
      ],
    });
  });

  it("accepts the exact post-SSO scrub of account A and finishes managed cleanup", async () => {
    const pairKey = cloudPairTokenKeyForAgent("previous-account-agent");
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-token");
    localStorage.setItem(pairKey, "account-a-token");
    sessionStorage.setItem(pairKey, "account-a-token");
    savePersistedFirstRunComplete(true);
    savePersistedActiveServer({
      id: "cloud:previous-account-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: SHARED_BASE,
      accessToken: "account-a-token",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "shared-profile",
      profiles: [
        {
          id: "shared-profile",
          kind: "cloud",
          cloudAgentId: "previous-account-agent",
          label: "Eliza Cloud",
          apiBase: SHARED_BASE,
          accessToken: "account-a-token",
          createdAt: new Date().toISOString(),
        },
      ],
    });
    const authority = await captureManagedCloudAccountBindingAuthority();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    try {
      await clearStaleStewardSession();
      await expect(
        clearManagedCloudAccountBinding(authority),
      ).resolves.toBeUndefined();
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(loadPersistedActiveServer()).toBeNull();
    expect(loadAgentProfileRegistry().profiles).toEqual([]);
    expect(localStorage.getItem(pairKey)).toBeNull();
    expect(sessionStorage.getItem(pairKey)).toBeNull();
    expect(loadPersistedFirstRunComplete()).toBe(false);
  });

  it("makes a logout reset visible to cloud-only first-run readers", () => {
    setBootConfig({
      branding: { cloudOnly: true },
      apiBase: SHARED_BASE,
      apiToken: "account-a-token",
    });
    savePersistedFirstRunComplete(true);
    const authority = captureFirstRunAccountResetAuthority();

    expect(
      markFirstRunIncompleteForAccountIfCurrent(
        authority,
        "account-a-logout",
        () => true,
      ),
    ).toBe(true);
    expect(loadPersistedFirstRunComplete(true)).toBe(false);
  });

  it("does not reset account B onboarding after B changes the session generation", async () => {
    setBootConfig({
      branding: { cloudOnly: true },
      apiBase: SHARED_BASE,
      apiToken: "account-a-token",
    });
    savePersistedFirstRunComplete(true);
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-token");
    savePersistedActiveServer({
      id: "cloud:account-a-agent",
      kind: "cloud",
      label: "Account A",
      apiBase: "https://account-a-agent.cloud.eliza.app",
      accessToken: "account-a-token",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "account-a-profile",
      profiles: [
        {
          id: "account-a-profile",
          kind: "cloud",
          label: "Account A",
          apiBase: "https://account-a-agent.cloud.eliza.app",
          accessToken: "account-a-token",
          createdAt: new Date().toISOString(),
        },
      ],
    });
    const recoveryA = beginStewardSessionRecovery("elizacloud", "provider");
    completeStewardSessionRecovery(recoveryA);
    const authority = await captureManagedCloudAccountBindingAuthority({
      stewardToken: "account-a-token",
      sessionGeneration: recoveryA.receipt,
    });

    beginStewardSessionRecovery("elizacloud", "provider");
    savePersistedFirstRunComplete(true);

    await expect(
      clearManagedCloudAccountBinding(authority, {
        sessionGeneration: recoveryA.receipt,
      }),
    ).rejects.toThrow("could not prove authority");
    expect(loadPersistedFirstRunComplete(true)).toBe(true);
  });

  it("does not adopt a pair token B queued while account A is captured", async () => {
    const agentId = "account-a-agent";
    const pairKey = cloudPairTokenKeyForAgent(agentId);
    setBootConfig({
      branding: {},
      apiBase: SHARED_BASE,
      apiToken: "account-a-token",
    });
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-token");
    localStorage.setItem(pairKey, "account-a-pair-token");
    sessionStorage.setItem(pairKey, "account-a-pair-token");
    savePersistedActiveServer({
      id: `cloud:${agentId}`,
      kind: "cloud",
      label: "Account A",
      apiBase: `https://${agentId}.cloud.eliza.app`,
      accessToken: "account-a-token",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "account-a-profile",
      profiles: [
        {
          id: "account-a-profile",
          kind: "cloud",
          cloudAgentId: agentId,
          label: "Account A",
          apiBase: `https://${agentId}.cloud.eliza.app`,
          accessToken: "account-a-token",
          createdAt: new Date().toISOString(),
        },
      ],
    });
    const recoveryA = beginStewardSessionRecovery("elizacloud", "provider");
    completeStewardSessionRecovery(recoveryA);

    const capture = captureManagedCloudAccountBindingAuthority({
      stewardToken: "account-a-token",
      sessionGeneration: recoveryA.receipt,
    });
    const publishB = persistCloudPairApiToken("account-b-pair-token", agentId);
    const authority = await capture;
    await publishB;

    await expect(
      clearManagedCloudAccountBinding(authority, {
        sessionGeneration: recoveryA.receipt,
      }),
    ).rejects.toThrow("could not prove authority");
    expect(localStorage.getItem(pairKey)).toBe("account-b-pair-token");
    expect(sessionStorage.getItem(pairKey)).toBe("account-b-pair-token");
  });

  it("rejects B's partial registry-active-token publication during capture", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-token");
    const recoveryA = beginStewardSessionRecovery("elizacloud", "provider");
    completeStewardSessionRecovery(recoveryA);
    const capture = captureManagedCloudAccountBindingAuthority({
      stewardToken: "account-a-token",
      sessionGeneration: recoveryA.receipt,
    });
    await Promise.resolve();

    beginStewardSessionRecovery("elizacloud", "provider");
    savePersistedActiveServer({
      id: "cloud:account-b-agent",
      kind: "cloud",
      label: "Account B",
      apiBase: "https://account-b-agent.cloud.eliza.app",
      accessToken: "account-b-token",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "account-b-profile",
      profiles: [
        {
          id: "account-b-profile",
          kind: "cloud",
          label: "Account B",
          apiBase: "https://account-b-agent.cloud.eliza.app",
          accessToken: "account-b-token",
          createdAt: new Date().toISOString(),
        },
      ],
    });

    await expect(capture).rejects.toThrow("generation changed");
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-a-token");
    expect(loadPersistedActiveServer()?.label).toBe("Account B");
  });

  it("does not resurrect terminal profile A or clear live mirrors after authority B appears", async () => {
    savePersistedActiveServer({
      id: "cloud:previous-account-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: SHARED_BASE,
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "old-profile",
      profiles: [
        {
          id: "old-profile",
          kind: "cloud",
          label: "Eliza Cloud",
          apiBase: SHARED_BASE,
          accessToken: "revoked-a",
          createdAt: new Date().toISOString(),
        },
      ],
    });
    localStorage.setItem("elizaos_api_base", SHARED_BASE);
    await expect(
      clearSharedCloudAccountBindingDurably({
        // The exact terminal profile transform is authority A's last allowed
        // write; its resulting empty registry deterministically represents B.
        validate: () => loadAgentProfileRegistry().profiles.length > 0,
      }),
    ).resolves.toBe(false);

    expect(loadAgentProfileRegistry().profiles).toEqual([]);
    expect(loadPersistedActiveServer()?.apiBase).toBe(SHARED_BASE);
    expect(localStorage.getItem("elizaos_api_base")).toBe(SHARED_BASE);
    expect(getBootConfig().apiToken).toBe("previous-account-token");
  });

  it("keeps terminal profiles scrubbed on active-server failure without publishing logout", async () => {
    savePersistedActiveServer({
      id: "cloud:previous-account-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: SHARED_BASE,
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "old-profile",
      profiles: [
        {
          id: "old-profile",
          kind: "cloud",
          label: "Eliza Cloud",
          apiBase: SHARED_BASE,
          accessToken: "revoked-a",
          createdAt: new Date().toISOString(),
        },
      ],
    });
    localStorage.setItem("elizaos_api_base", SHARED_BASE);
    await expect(
      sharedCloudAccountBindingInternals.clearSharedCloudAccountBindingDurablyWithDependencies(
        { validate: () => true },
        async (options) => {
          await clearManagedSharedCloudProfilesAndTokensDurably(options);
          throw new DOMException("blocked", "SecurityError");
        },
      ),
    ).rejects.toThrow("blocked");

    expect(loadAgentProfileRegistry().profiles).toEqual([]);
    expect(loadPersistedActiveServer()?.apiBase).toBe(SHARED_BASE);
    expect(localStorage.getItem("elizaos_api_base")).toBe(SHARED_BASE);
    expect(getBootConfig().apiToken).toBe("previous-account-token");
  });
});
