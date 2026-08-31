/**
 * Exercises Cloud-pair credential deletion against real jsdom storage. Scoped
 * clears must preserve unrelated agents, while global clears remove every
 * scoped/legacy credential and loopback owner hint.
 */
// @vitest-environment jsdom

import {
  CLOUD_PAIR_LOCAL_OWNER_HINT_KEY,
  cloudPairTokenKeyForAgent,
} from "@elizaos/shared/contracts";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { persistCloudPairApiToken } from "../components/auth/CloudPairRelay";
import { shellLocalStorage } from "../surface-realm-channel";
import { withRuntimeConnectionPersistenceLock } from "./agent-profiles";
import {
  captureCloudPairApiTokenClearAuthority,
  clearCloudPairApiToken,
  clearCloudPairApiTokenIfCurrent,
  clearStalePairCredentialsForAgent,
  clearStalePairCredentialsForAgentDurably,
} from "./cloud-pair-token";

const LEGACY_KEY = "eliza:cloud-pair:api-token";
const ACTIVE_SERVER_KEY = "elizaos:active-server";
const PROFILES_KEY = "elizaos:agent-profiles";

function seedActiveServer(agentId: string): void {
  localStorage.setItem(
    ACTIVE_SERVER_KEY,
    JSON.stringify({
      id: `cloud:${agentId}`,
      kind: "cloud",
      label: "Dedicated agent",
      apiBase: `https://${agentId}.elizacloud.ai`,
      accessToken: `bearer-${agentId}`,
    }),
  );
}

function seedProfiles(): void {
  localStorage.setItem(
    PROFILES_KEY,
    JSON.stringify({
      version: 1,
      activeProfileId: "p1",
      profiles: [
        {
          id: "p1",
          label: "Agent A",
          kind: "cloud",
          apiBase: "https://agent-a.elizacloud.ai",
          accessToken: "token-a",
          createdAt: "2026-01-01T00:00:00.000Z",
        },
        {
          id: "p2",
          label: "Agent B",
          kind: "cloud",
          cloudAgentId: "agent-b",
          apiBase: "https://elizacloud.ai/api/v1/eliza/agents/agent-b",
          accessToken: "token-b",
          createdAt: "2026-01-01T00:00:00.000Z",
        },
        {
          id: "p3",
          label: "Self-hosted",
          kind: "remote",
          apiBase: "https://my-box.example.com",
          accessToken: "token-remote",
          createdAt: "2026-01-01T00:00:00.000Z",
        },
      ],
    }),
  );
}

function profileTokens(): Record<string, string | undefined> {
  const registry = JSON.parse(localStorage.getItem(PROFILES_KEY) ?? "{}") as {
    profiles: Array<{ id: string; accessToken?: string }>;
  };
  return Object.fromEntries(
    registry.profiles.map((p) => [p.id, p.accessToken]),
  );
}

function seedRejectedCredentialMirrors(
  agentId: string,
  rejectedToken: string,
): void {
  const pairKey = cloudPairTokenKeyForAgent(agentId);
  localStorage.setItem(pairKey, rejectedToken);
  sessionStorage.setItem(pairKey, rejectedToken);
  localStorage.setItem(LEGACY_KEY, rejectedToken);
  sessionStorage.setItem(LEGACY_KEY, rejectedToken);
  localStorage.setItem(
    ACTIVE_SERVER_KEY,
    JSON.stringify({
      id: `cloud:${agentId}`,
      kind: "cloud",
      label: "Rejected agent",
      apiBase: `https://${agentId}.elizacloud.ai`,
      accessToken: rejectedToken,
    }),
  );
  localStorage.setItem(
    PROFILES_KEY,
    JSON.stringify({
      version: 1,
      activeProfileId: "profile-a",
      profiles: [
        {
          id: "profile-a",
          createdAt: "2026-08-31T00:00:00.000Z",
          kind: "cloud",
          label: "Rejected agent",
          cloudAgentId: agentId,
          apiBase: `https://${agentId}.elizacloud.ai`,
          accessToken: rejectedToken,
        },
        {
          id: "profile-other",
          createdAt: "2026-08-31T00:00:00.000Z",
          kind: "cloud",
          label: "Other agent",
          cloudAgentId: "agent-other",
          apiBase: "https://agent-other.elizacloud.ai",
          accessToken: "keep-other-bearer",
        },
      ],
    }),
  );
}

describe("clearCloudPairApiToken", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("removes ONLY the target agent's per-agent key from BOTH storages", () => {
    const agentKey = cloudPairTokenKeyForAgent("agent-a");
    localStorage.setItem(agentKey, "stale-key");
    sessionStorage.setItem(agentKey, "stale-key");
    // The legacy key predates owner binding — on a pre-migration install it
    // may hold a DIFFERENT agent's only bearer, so a scoped clear for agent-a
    // must leave it alone.
    localStorage.setItem(LEGACY_KEY, "legacy-key");
    sessionStorage.setItem(LEGACY_KEY, "legacy-key");
    // Another agent's scoped key must survive an explicit sign-out for agent-a.
    const otherAgentKey = cloudPairTokenKeyForAgent("agent-b");
    localStorage.setItem(otherAgentKey, "keep-agent-b");
    localStorage.setItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY, "agent-b");
    sessionStorage.setItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY, "agent-b");
    localStorage.setItem("eliza:unrelated", "keep-me");

    clearCloudPairApiToken("agent-a");

    expect(localStorage.getItem(agentKey)).toBeNull();
    expect(sessionStorage.getItem(agentKey)).toBeNull();
    expect(localStorage.getItem(LEGACY_KEY)).toBe("legacy-key");
    expect(sessionStorage.getItem(LEGACY_KEY)).toBe("legacy-key");
    expect(localStorage.getItem(otherAgentKey)).toBe("keep-agent-b");
    expect(localStorage.getItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY)).toBe(
      "agent-b",
    );
    expect(sessionStorage.getItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY)).toBe(
      "agent-b",
    );
    expect(localStorage.getItem("eliza:unrelated")).toBe("keep-me");
  });

  it("clears every scoped key AND the legacy global key on a global clear", () => {
    localStorage.setItem(LEGACY_KEY, "legacy-key");
    sessionStorage.setItem(LEGACY_KEY, "legacy-key");
    const agentAKey = cloudPairTokenKeyForAgent("agent-a");
    const agentBKey = cloudPairTokenKeyForAgent("agent-b");
    localStorage.setItem(agentAKey, "key-a");
    sessionStorage.setItem(agentBKey, "key-b");
    localStorage.setItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY, "agent-a");
    sessionStorage.setItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY, "agent-a");

    clearCloudPairApiToken();

    expect(localStorage.getItem(LEGACY_KEY)).toBeNull();
    expect(sessionStorage.getItem(LEGACY_KEY)).toBeNull();
    expect(localStorage.getItem(agentAKey)).toBeNull();
    expect(sessionStorage.getItem(agentBKey)).toBeNull();
    expect(localStorage.getItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY)).toBeNull();
    expect(sessionStorage.getItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY)).toBeNull();
  });

  it("clears a scoped loopback owner hint only for the matching agent", () => {
    localStorage.setItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY, "agent-a");
    sessionStorage.setItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY, "agent-a");

    clearCloudPairApiToken("agent-a");

    expect(localStorage.getItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY)).toBeNull();
    expect(sessionStorage.getItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY)).toBeNull();
  });

  it("is a safe no-op when the key is absent", () => {
    expect(() => clearCloudPairApiToken("agent-a")).not.toThrow();
    expect(localStorage.getItem(LEGACY_KEY)).toBeNull();
  });

  it("targets the exact keys the write channel uses", async () => {
    // Guards against a silent rename drift between the write channel
    // (CloudPairRelay) and this delete channel: both must share the literal.
    const relay = await import("../components/auth/CloudPairRelay");
    expect(relay.CLOUD_PAIR_SESSION_STORAGE_KEY).toBe(LEGACY_KEY);
    expect(relay.CLOUD_PAIR_LOCAL_STORAGE_KEY).toBe(LEGACY_KEY);
    expect(relay.cloudPairTokenKeyForAgent("agent-a")).toBe(
      "eliza:cloud-pair:api-token:agent-a",
    );
  });

  it.each([
    [
      "account-a-pair-token",
      "account-b-pair-token",
      null,
      "account-b-pair-token",
    ],
    [
      "account-b-pair-token",
      "account-a-pair-token",
      "account-b-pair-token",
      null,
    ],
  ])(
    "clears only A's legacy channel when local/session owners differ",
    async (localValue, sessionValue, expectedLocal, expectedSession) => {
      localStorage.setItem(LEGACY_KEY, localValue);
      sessionStorage.setItem(LEGACY_KEY, sessionValue);
      const authority = captureCloudPairApiTokenClearAuthority(
        [],
        ["account-a-pair-token"],
      );

      await withRuntimeConnectionPersistenceLock(async (lease) => {
        clearCloudPairApiTokenIfCurrent(authority, lease);
      });

      expect(localStorage.getItem(LEGACY_KEY)).toBe(expectedLocal);
      expect(sessionStorage.getItem(LEGACY_KEY)).toBe(expectedSession);
    },
  );

  it("keeps B when its writer starts between A's comparison and removal", async () => {
    const agentKey = cloudPairTokenKeyForAgent("agent-a");
    localStorage.setItem(agentKey, "account-a-pair-token");
    sessionStorage.setItem(agentKey, "account-a-pair-token");
    const authority = captureCloudPairApiTokenClearAuthority(
      ["agent-a"],
      ["account-a-pair-token"],
    );
    const realRemove = shellLocalStorage.removeItem.bind(shellLocalStorage);
    let writeB: Promise<void> | null = null;
    const removeSpy = vi
      .spyOn(shellLocalStorage, "removeItem")
      .mockImplementation((key) => {
        if (key === agentKey && writeB === null) {
          // The writer is invoked after clear observed A but before its local
          // remove. Its shared lock queues B until A's exact clear completes.
          writeB = persistCloudPairApiToken("account-b-pair-token", "agent-a");
        }
        realRemove(key);
      });

    try {
      await withRuntimeConnectionPersistenceLock(async (lease) => {
        clearCloudPairApiTokenIfCurrent(authority, lease);
      });
      await writeB;
    } finally {
      removeSpy.mockRestore();
    }

    expect(localStorage.getItem(agentKey)).toBe("account-b-pair-token");
    expect(sessionStorage.getItem(agentKey)).toBe("account-b-pair-token");
  });
});

describe("clearStalePairCredentialsForAgent", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("purges the per-agent key, active-server token, and ONLY the target agent's profile token", () => {
    const agentKey = cloudPairTokenKeyForAgent("agent-a");
    localStorage.setItem(agentKey, "stale-bearer");
    sessionStorage.setItem(agentKey, "stale-bearer");
    localStorage.setItem(LEGACY_KEY, "legacy-bearer");
    seedActiveServer("agent-a");
    seedProfiles();

    clearStalePairCredentialsForAgent("agent-a");

    expect(localStorage.getItem(agentKey)).toBeNull();
    expect(sessionStorage.getItem(agentKey)).toBeNull();
    // The legacy key has no owner binding, so an agent-scoped purge leaves it
    // for the global disconnect/sign-out path to clear.
    expect(localStorage.getItem(LEGACY_KEY)).toBe("legacy-bearer");
    const active = JSON.parse(
      localStorage.getItem(ACTIVE_SERVER_KEY) ?? "{}",
    ) as { accessToken?: string; apiBase?: string };
    // Server selection survives; only the credential is scrubbed.
    expect(active.accessToken).toBeUndefined();
    expect(active.apiBase).toBe("https://agent-a.elizacloud.ai");
    // Unrelated valid credentials survive the target-agent purge.
    expect(profileTokens()).toEqual({
      p1: undefined,
      p2: "token-b",
      p3: "token-remote",
    });
  });

  it("leaves ANOTHER agent's per-agent key untouched", () => {
    const agentAKey = cloudPairTokenKeyForAgent("agent-a");
    const agentBKey = cloudPairTokenKeyForAgent("agent-b");
    localStorage.setItem(agentAKey, "stale-a");
    localStorage.setItem(agentBKey, "valid-b");
    seedActiveServer("agent-b");
    seedProfiles();

    clearStalePairCredentialsForAgent("agent-b");

    expect(localStorage.getItem(agentBKey)).toBeNull();
    expect(localStorage.getItem(agentAKey)).toBe("stale-a");
    expect(profileTokens()).toEqual({
      p1: "token-a",
      p2: undefined,
      p3: "token-remote",
    });
  });

  it("matches a profile by explicit cloudAgentId / REST-adapter base too", () => {
    seedActiveServer("agent-b");
    seedProfiles();

    clearStalePairCredentialsForAgent("agent-b");

    expect(profileTokens()).toEqual({
      p1: "token-a",
      p2: undefined,
      p3: "token-remote",
    });
  });

  it("purges the deleted agent's per-agent key even when the active server is a DIFFERENT agent", () => {
    // The durable key is per-agent, so the deleted agent's scoped key is
    // always purged regardless of which agent is the active server (a key
    // that provably belongs to the target is never left re-adoptable). The
    // active-server bearer is left alone because it belongs to another agent.
    const agentAKey = cloudPairTokenKeyForAgent("agent-a");
    localStorage.setItem(agentAKey, "other-agents-bearer");
    seedActiveServer("agent-b");
    seedProfiles();

    clearStalePairCredentialsForAgent("agent-a");

    expect(localStorage.getItem(agentAKey)).toBeNull();
    const active = JSON.parse(
      localStorage.getItem(ACTIVE_SERVER_KEY) ?? "{}",
    ) as { accessToken?: string };
    expect(active.accessToken).toBe("bearer-agent-b");
    // The proven agent's profile credential is still scrubbed.
    expect(profileTokens()).toEqual({
      p1: undefined,
      p2: "token-b",
      p3: "token-remote",
    });
  });

  it("is a safe no-op for a blank agent id and when nothing is persisted", () => {
    const agentAKey = cloudPairTokenKeyForAgent("agent-a");
    localStorage.setItem(agentAKey, "keep-me");
    clearStalePairCredentialsForAgent("  ");
    expect(localStorage.getItem(agentAKey)).toBe("keep-me");

    localStorage.clear();
    expect(() => clearStalePairCredentialsForAgent("agent-a")).not.toThrow();
  });
});

describe("clearStalePairCredentialsForAgentDurably", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("terminally clears the exact rejected bearer from pair, active, and profile mirrors", async () => {
    const rejectedToken = "rejected-account-a-bearer";
    seedRejectedCredentialMirrors("agent-a", rejectedToken);

    await expect(
      clearStalePairCredentialsForAgentDurably({
        agentId: "agent-a",
        rejectedToken,
        validate: () => true,
      }),
    ).resolves.toBe(true);

    const pairKey = cloudPairTokenKeyForAgent("agent-a");
    expect(localStorage.getItem(pairKey)).toBeNull();
    expect(sessionStorage.getItem(pairKey)).toBeNull();
    expect(localStorage.getItem(LEGACY_KEY)).toBeNull();
    expect(sessionStorage.getItem(LEGACY_KEY)).toBeNull();
    expect(localStorage.getItem(ACTIVE_SERVER_KEY)).not.toContain(
      rejectedToken,
    );
    expect(localStorage.getItem(PROFILES_KEY)).not.toContain(rejectedToken);
    expect(localStorage.getItem(PROFILES_KEY)).toContain("keep-other-bearer");
  });

  it("keeps every B byte when B wins generation while purge is suspended on the runtime lock", async () => {
    seedRejectedCredentialMirrors("agent-a", "rejected-account-a-bearer");
    const originalLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    let releaseLock!: () => void;
    let reportLockRequested!: () => void;
    const lockRequested = new Promise<void>((resolve) => {
      reportLockRequested = resolve;
    });
    const lockBarrier = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });
    const request = vi.fn(
      async (
        _name: string,
        _options: LockOptions,
        callback: () => Promise<boolean>,
      ) => {
        reportLockRequested();
        await lockBarrier;
        return callback();
      },
    );
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: { request },
    });
    let accountAGenerationIsCurrent = true;

    try {
      const purge = clearStalePairCredentialsForAgentDurably({
        agentId: "agent-a",
        rejectedToken: "rejected-account-a-bearer",
        validate: () => accountAGenerationIsCurrent,
      });
      await lockRequested;

      // Login B publishes its generation/token/runtime mirrors before A ever
      // acquires the lock. A must fail closed instead of targeting these bytes.
      accountAGenerationIsCurrent = false;
      const pairKey = cloudPairTokenKeyForAgent("agent-a");
      localStorage.setItem(pairKey, "account-b-bearer");
      sessionStorage.setItem(pairKey, "account-b-bearer");
      localStorage.setItem(LEGACY_KEY, "account-b-bearer");
      sessionStorage.setItem(LEGACY_KEY, "account-b-bearer");
      localStorage.setItem(
        ACTIVE_SERVER_KEY,
        JSON.stringify({
          id: "cloud:agent-a",
          kind: "cloud",
          label: "Account B agent",
          apiBase: "https://agent-a.elizacloud.ai",
          accessToken: "account-b-bearer",
        }),
      );
      localStorage.setItem(
        PROFILES_KEY,
        JSON.stringify({
          version: 1,
          activeProfileId: "profile-b",
          profiles: [
            {
              id: "profile-b",
              createdAt: "2026-08-31T00:00:00.000Z",
              kind: "cloud",
              label: "Account B agent",
              cloudAgentId: "agent-a",
              apiBase: "https://agent-a.elizacloud.ai",
              accessToken: "account-b-bearer",
            },
          ],
        }),
      );
      releaseLock();

      await expect(purge).resolves.toBe(false);
      expect(localStorage.getItem(pairKey)).toBe("account-b-bearer");
      expect(sessionStorage.getItem(pairKey)).toBe("account-b-bearer");
      expect(localStorage.getItem(LEGACY_KEY)).toBe("account-b-bearer");
      expect(sessionStorage.getItem(LEGACY_KEY)).toBe("account-b-bearer");
      expect(localStorage.getItem(ACTIVE_SERVER_KEY)).toContain(
        "account-b-bearer",
      );
      expect(localStorage.getItem(PROFILES_KEY)).toContain("account-b-bearer");
    } finally {
      if (originalLocks) {
        Object.defineProperty(navigator, "locks", originalLocks);
      } else {
        Reflect.deleteProperty(navigator, "locks");
      }
    }
  });

  it("returns false and preserves A when the runtime lock host rejects", async () => {
    const rejectedToken = "rejected-account-a-bearer";
    seedRejectedCredentialMirrors("agent-a", rejectedToken);
    const originalLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: vi.fn(async () => {
          throw new Error("runtime lock host unavailable");
        }),
      },
    });

    try {
      await expect(
        clearStalePairCredentialsForAgentDurably({
          agentId: "agent-a",
          rejectedToken,
          validate: () => true,
        }),
      ).resolves.toBe(false);
      expect(localStorage.getItem(cloudPairTokenKeyForAgent("agent-a"))).toBe(
        rejectedToken,
      );
      expect(localStorage.getItem(ACTIVE_SERVER_KEY)).toContain(rejectedToken);
      expect(localStorage.getItem(PROFILES_KEY)).toContain(rejectedToken);
    } finally {
      if (originalLocks) {
        Object.defineProperty(navigator, "locks", originalLocks);
      } else {
        Reflect.deleteProperty(navigator, "locks");
      }
    }
  });
});
