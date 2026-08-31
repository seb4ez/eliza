// @vitest-environment jsdom

import { STEWARD_TOKEN_KEY } from "@elizaos/shared/steward-session-client";
/** Deterministic failure coverage for multi-record protected transactions. */
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  abortTransaction: vi.fn(),
  beginTransaction: vi.fn(),
  decideTransaction: vi.fn(),
  finishTransaction: vi.fn(),
  pinnedRemoteApiBase: null as string | null,
  getStorageValue: vi.fn(),
  removeStorageValueIfCurrent: vi.fn(),
  setWithCompensation: vi.fn(),
  setStorageValue: vi.fn(),
  setStorageValueIfCurrent: vi.fn(),
}));

vi.mock("../bridge/storage-bridge", () => ({
  abortRuntimeConnectionStorageTransaction: mocks.abortTransaction,
  beginRuntimeConnectionStorageTransaction: mocks.beginTransaction,
  decideRuntimeConnectionStorageTransaction: mocks.decideTransaction,
  finishRuntimeConnectionStorageTransaction: mocks.finishTransaction,
  getStorageValue: mocks.getStorageValue,
  removeStorageValueIfCurrent: mocks.removeStorageValueIfCurrent,
  setStorageValue: mocks.setStorageValue,
  setStorageValueIfCurrent: mocks.setStorageValueIfCurrent,
  setStorageValueWithCompensation: mocks.setWithCompensation,
}));

vi.mock("./runtime-url-trust", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./runtime-url-trust")>()),
  getBuildConfiguredRemoteApiBaseUrl: () => mocks.pinnedRemoteApiBase,
}));

vi.mock("@elizaos/logger", () => ({
  createLogger: () => ({
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
  }),
  logger: { error: vi.fn(), warn: vi.fn() },
}));

import {
  captureCloudRuntimeAuthorityLeaseDurably,
  clearCloudRuntimeAuthorityDurably,
  persistAgentProfileConnectionDurably,
  persistAgentProfileSelectionDurably,
  removeAgentProfileWithFallbackDurably,
} from "./agent-profiles";
import { createPersistedActiveServer } from "./persistence";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((release) => {
    resolve = release;
  });
  return { promise, resolve };
}

function installBrowserStorageWriter(
  options: {
    blockActiveServerId?: string;
    blocked?: ReturnType<typeof deferred>;
    release?: ReturnType<typeof deferred>;
  } = {},
): void {
  mocks.setWithCompensation.mockImplementation(
    async (
      key: string,
      value: string,
      validation?: { validate?: () => boolean },
    ) => {
      if (validation?.validate?.() === false) return null;
      const predecessor = localStorage.getItem(key);
      localStorage.setItem(key, value);
      if (
        key === "elizaos:active-server" &&
        JSON.parse(value).id === options.blockActiveServerId
      ) {
        options.blocked?.resolve();
        await options.release?.promise;
      }
      return {
        compensate: async () => {
          if (localStorage.getItem(key) !== value) return false;
          if (predecessor === null) localStorage.removeItem(key);
          else localStorage.setItem(key, predecessor);
          return true;
        },
      };
    },
  );
}

describe("durable agent-profile compensation", () => {
  beforeEach(() => {
    localStorage.clear();
    mocks.pinnedRemoteApiBase = null;
    mocks.abortTransaction.mockReset();
    mocks.abortTransaction.mockResolvedValue(true);
    mocks.beginTransaction.mockReset();
    mocks.beginTransaction.mockResolvedValue(null);
    mocks.decideTransaction.mockReset();
    mocks.decideTransaction.mockResolvedValue(undefined);
    mocks.finishTransaction.mockReset();
    mocks.finishTransaction.mockResolvedValue(undefined);
    mocks.getStorageValue.mockReset();
    mocks.getStorageValue.mockImplementation(async (key: string) =>
      localStorage.getItem(key),
    );
    mocks.removeStorageValueIfCurrent.mockReset();
    mocks.removeStorageValueIfCurrent.mockImplementation(
      async (key: string, expectedValue: string | null) => {
        if (localStorage.getItem(key) !== expectedValue) return false;
        if (expectedValue !== null) localStorage.removeItem(key);
        return true;
      },
    );
    mocks.setWithCompensation.mockReset();
    mocks.setStorageValue.mockReset();
    mocks.setStorageValueIfCurrent.mockReset();
    mocks.setStorageValueIfCurrent.mockImplementation(
      async (
        key: string,
        expectedValue: string,
        value: string,
        options?: { validate?: () => boolean },
      ) => {
        if (options?.validate?.() === false) return false;
        if (localStorage.getItem(key) !== expectedValue) return false;
        localStorage.setItem(key, value);
        return options?.validate?.() !== false;
      },
    );
  });

  it("attempts every rollback even when the first compensation rejects", async () => {
    let authorityLive = true;
    const registryCompensate = vi.fn(async () => {
      throw new Error("registry rollback rejected");
    });
    const serverCompensate = vi.fn(async () => {
      throw new Error("server rollback rejected");
    });
    mocks.setWithCompensation
      .mockResolvedValueOnce({ compensate: registryCompensate })
      .mockImplementationOnce(async () => {
        authorityLive = false;
        return { compensate: serverCompensate };
      });
    const server = createPersistedActiveServer({
      kind: "cloud",
      id: "cloud:transaction-a",
      label: "Transaction A",
      apiBase: "https://transaction-a.example.test",
      accessToken: "token-a",
    });

    await expect(
      persistAgentProfileConnectionDurably(
        {
          kind: "cloud",
          label: server.label,
          apiBase: server.apiBase,
          accessToken: "token-a",
        },
        server,
        { validate: () => authorityLive },
      ),
    ).rejects.toThrow("could not be compensated");

    expect(serverCompensate).toHaveBeenCalledOnce();
    expect(registryCompensate).toHaveBeenCalledOnce();
  });

  it("hard-fails when an exact rollback is superseded", async () => {
    let authorityLive = true;
    const registryCompensate = vi.fn(async () => false);
    const serverCompensate = vi.fn(async () => true);
    mocks.setWithCompensation
      .mockResolvedValueOnce({ compensate: registryCompensate })
      .mockImplementationOnce(async () => {
        authorityLive = false;
        return { compensate: serverCompensate };
      });
    const server = createPersistedActiveServer({
      kind: "remote",
      label: "Runtime A",
      apiBase: "http://100.64.0.1:3000",
    });

    await expect(
      persistAgentProfileConnectionDurably(
        {
          kind: "remote",
          label: server.label,
          apiBase: server.apiBase,
        },
        server,
        { validate: () => authorityLive },
      ),
    ).rejects.toThrow("could not be compensated");

    expect(serverCompensate).toHaveBeenCalledOnce();
    expect(registryCompensate).toHaveBeenCalledOnce();
  });

  it("refuses a build-pinned target before either protected record is written", async () => {
    mocks.pinnedRemoteApiBase = "https://pinned.example.test";
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: "pinned",
        profiles: [
          {
            id: "pinned",
            kind: "remote",
            label: "Pinned",
            apiBase: mocks.pinnedRemoteApiBase,
            createdAt: "2026-08-30T00:00:00.000Z",
          },
        ],
      }),
    );
    const originalRegistry = localStorage.getItem("elizaos:agent-profiles");
    const cloudServer = createPersistedActiveServer({
      kind: "cloud",
      id: "cloud:forbidden",
      label: "Forbidden Cloud",
      apiBase: "https://forbidden.example.test",
    });

    await expect(
      persistAgentProfileConnectionDurably(
        {
          kind: "cloud",
          label: cloudServer.label,
          apiBase: cloudServer.apiBase,
        },
        cloudServer,
      ),
    ).resolves.toBeNull();

    expect(mocks.setWithCompensation).not.toHaveBeenCalled();
    expect(localStorage.getItem("elizaos:agent-profiles")).toBe(
      originalRegistry,
    );
    expect(localStorage.getItem("elizaos:active-server")).toBeNull();
  });

  it("keeps legacy migration pure before a build-pinned refusal", async () => {
    mocks.pinnedRemoteApiBase = "https://pinned.example.test";
    localStorage.setItem(
      "elizaos:active-server",
      JSON.stringify({
        id: "remote:https://pinned.example.test",
        kind: "remote",
        label: "Pinned",
        apiBase: mocks.pinnedRemoteApiBase,
      }),
    );
    const forbidden = createPersistedActiveServer({
      kind: "cloud",
      id: "cloud:forbidden",
      label: "Forbidden Cloud",
      apiBase: "https://forbidden.example.test",
    });

    await expect(
      persistAgentProfileConnectionDurably(
        {
          kind: "cloud",
          label: forbidden.label,
          apiBase: forbidden.apiBase,
        },
        forbidden,
      ),
    ).resolves.toBeNull();

    expect(mocks.setWithCompensation).not.toHaveBeenCalled();
    expect(localStorage.getItem("elizaos:agent-profiles")).toBeNull();
  });

  it("fails closed when the origin-wide lock cannot be acquired", async () => {
    installBrowserStorageWriter();
    const originalLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: vi.fn(async () => {
          throw new Error("origin lock unavailable");
        }),
      },
    });
    const server = createPersistedActiveServer({
      kind: "remote",
      label: "Runtime A",
      apiBase: "http://100.64.0.1:3000",
    });

    try {
      await expect(
        persistAgentProfileConnectionDurably(
          {
            kind: "remote",
            label: server.label,
            apiBase: server.apiBase,
          },
          server,
        ),
      ).resolves.toBeNull();
      expect(mocks.setWithCompensation).not.toHaveBeenCalled();
      expect(localStorage.getItem("elizaos:agent-profiles")).toBeNull();
      expect(localStorage.getItem("elizaos:active-server")).toBeNull();
    } finally {
      if (originalLocks) {
        Object.defineProperty(navigator, "locks", originalLocks);
      } else {
        Reflect.deleteProperty(navigator, "locks");
      }
    }
  });

  it("prepares before either record and finishes only after finalization and the global decision", async () => {
    const events: string[] = [];
    const transaction = { transactionId: "transaction-a" };
    mocks.beginTransaction.mockImplementation(async () => {
      events.push("begin");
      return transaction;
    });
    mocks.setWithCompensation.mockImplementation(
      async (key: string, value: string) => {
        events.push(`set:${key}`);
        const predecessor = localStorage.getItem(key);
        localStorage.setItem(key, value);
        return {
          compensate: async () => {
            if (predecessor === null) localStorage.removeItem(key);
            else localStorage.setItem(key, predecessor);
            return true;
          },
        };
      },
    );
    mocks.decideTransaction.mockImplementation(async () => {
      events.push("decide");
    });
    mocks.finishTransaction.mockImplementation(async () => {
      events.push("finish");
    });
    const server = createPersistedActiveServer({
      kind: "remote",
      label: "Runtime WAL",
      apiBase: "http://100.64.0.10:3000",
    });

    await expect(
      persistAgentProfileConnectionDurably(
        {
          kind: "remote",
          label: server.label,
          apiBase: server.apiBase,
        },
        server,
        {
          finalize: async () => {
            events.push("finalize");
            return true;
          },
        },
      ),
    ).resolves.toMatchObject({ label: server.label });

    expect(events).toEqual([
      "begin",
      "set:elizaos:agent-profiles",
      "set:elizaos:active-server",
      "finalize",
      "decide",
      "finish",
    ]);
    expect(mocks.beginTransaction).toHaveBeenCalledWith([
      expect.objectContaining({ key: "elizaos:agent-profiles" }),
      expect.objectContaining({ key: "elizaos:active-server" }),
    ]);
  });

  it("aborts the whole transaction before participant compensation when a post-decision finalizer fails", async () => {
    const events: string[] = [];
    const transaction = { transactionId: "transaction-token-finalizer" };
    mocks.beginTransaction.mockResolvedValue(transaction);
    mocks.setWithCompensation.mockImplementation(async (key: string) => ({
      compensate: async () => {
        events.push(`compensate:${key}`);
        return true;
      },
    }));
    mocks.decideTransaction.mockImplementation(async () => {
      events.push("decide");
    });
    mocks.abortTransaction.mockImplementation(async () => {
      events.push("abort");
      return true;
    });
    const compensateFinalization = vi.fn(async () => {
      events.push("compensate-finalizer");
    });
    const server = createPersistedActiveServer({
      kind: "cloud",
      id: "cloud:transaction-finalizer",
      label: "Cloud WAL",
      apiBase: "https://transaction-finalizer.example.test",
      accessToken: "token-b",
    });

    await expect(
      persistAgentProfileConnectionDurably(
        {
          kind: "cloud",
          label: server.label,
          apiBase: server.apiBase,
          accessToken: server.accessToken,
        },
        server,
        {
          compensateFinalization,
          finalize: async () => {
            // Models the Steward adapter's pre-publication durable decision.
            await mocks.decideTransaction(transaction);
            events.push("finalizer");
            throw new Error("post-decision finalizer failed");
          },
        },
      ),
    ).rejects.toThrow("post-decision finalizer failed");

    expect(events).toEqual([
      "decide",
      "finalizer",
      "compensate-finalizer",
      "abort",
      "compensate:elizaos:active-server",
      "compensate:elizaos:agent-profiles",
    ]);
    expect(mocks.finishTransaction).not.toHaveBeenCalled();
  });

  it("serializes A/B selection through live publication", async () => {
    const blocked = deferred();
    const release = deferred();
    installBrowserStorageWriter({
      blockActiveServerId: "remote:http://100.64.0.1:3000",
      blocked,
      release,
    });
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: null,
        profiles: [
          {
            id: "profile-a",
            kind: "remote",
            label: "Runtime A",
            apiBase: "http://100.64.0.1:3000",
            createdAt: "2026-08-30T00:00:00.000Z",
          },
          {
            id: "profile-b",
            kind: "remote",
            label: "Runtime B",
            apiBase: "http://100.64.0.2:3000",
            createdAt: "2026-08-30T00:00:00.000Z",
          },
        ],
      }),
    );
    const live: string[] = [];
    const serverA = createPersistedActiveServer({
      kind: "remote",
      id: "runtime-a",
      label: "Runtime A",
      apiBase: "http://100.64.0.1:3000",
    });
    const serverB = createPersistedActiveServer({
      kind: "remote",
      id: "runtime-b",
      label: "Runtime B",
      apiBase: "http://100.64.0.2:3000",
    });

    const selectionA = persistAgentProfileSelectionDurably("profile-a", {
      createServer: () => serverA,
      finalize: async (_profile, server) => {
        live.push(server.id);
        return true;
      },
    });
    await blocked.promise;
    const selectionB = persistAgentProfileSelectionDurably("profile-b", {
      createServer: () => serverB,
      finalize: async (_profile, server) => {
        live.push(server.id);
        return true;
      },
    });
    release.resolve();

    await expect(Promise.all([selectionA, selectionB])).resolves.toEqual([
      expect.objectContaining({ ok: true }),
      expect.objectContaining({ ok: true }),
    ]);
    expect(
      JSON.parse(localStorage.getItem("elizaos:agent-profiles") ?? "{}")
        .activeProfileId,
    ).toBe("profile-b");
    expect(
      JSON.parse(localStorage.getItem("elizaos:active-server") ?? "{}").id,
    ).toBe(serverB.id);
    expect(live).toEqual([serverA.id, serverB.id]);
  });

  it("recomputes queued connection B from registry A instead of overwriting it", async () => {
    const blocked = deferred();
    const release = deferred();
    installBrowserStorageWriter({
      blockActiveServerId: "remote:http://100.64.0.1:3000",
      blocked,
      release,
    });
    const serverA = createPersistedActiveServer({
      kind: "remote",
      id: "runtime-a",
      label: "Runtime A",
      apiBase: "http://100.64.0.1:3000",
    });
    const serverB = createPersistedActiveServer({
      kind: "remote",
      id: "runtime-b",
      label: "Runtime B",
      apiBase: "http://100.64.0.2:3000",
    });

    const connectionA = persistAgentProfileConnectionDurably(
      {
        kind: "remote",
        label: serverA.label,
        apiBase: serverA.apiBase,
      },
      serverA,
    );
    await blocked.promise;
    const connectionB = persistAgentProfileConnectionDurably(
      {
        kind: "remote",
        label: serverB.label,
        apiBase: serverB.apiBase,
      },
      serverB,
    );
    release.resolve();
    await expect(Promise.all([connectionA, connectionB])).resolves.toEqual([
      expect.objectContaining({ apiBase: serverA.apiBase }),
      expect.objectContaining({ apiBase: serverB.apiBase }),
    ]);

    const registry = JSON.parse(
      localStorage.getItem("elizaos:agent-profiles") ?? "{}",
    ) as { activeProfileId: string; profiles: Array<{ apiBase?: string }> };
    expect(registry.profiles.map((profile) => profile.apiBase)).toEqual([
      serverA.apiBase,
      serverB.apiBase,
    ]);
    expect(registry.activeProfileId).toBeTruthy();
    expect(
      JSON.parse(localStorage.getItem("elizaos:active-server") ?? "{}").id,
    ).toBe(serverB.id);
  });

  it("selects the host-authoritative same-id profile instead of a stale renderer snapshot", async () => {
    installBrowserStorageWriter();
    const staleProfile = {
      id: "same-id",
      kind: "remote" as const,
      label: "Runtime A",
      apiBase: "http://100.64.0.1:3000",
      accessToken: "token-a",
      createdAt: "2026-08-30T00:00:00.000Z",
    };
    const currentProfile = {
      ...staleProfile,
      label: "Runtime B",
      apiBase: "http://100.64.0.2:3000",
      accessToken: "token-b",
    };
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: staleProfile.id,
        profiles: [staleProfile],
      }),
    );
    const authoritativeRegistry = JSON.stringify({
      version: 1,
      activeProfileId: currentProfile.id,
      profiles: [currentProfile],
    });
    mocks.getStorageValue.mockImplementation(async (key: string) =>
      key === "elizaos:agent-profiles"
        ? authoritativeRegistry
        : localStorage.getItem(key),
    );
    const published: Array<{ apiBase?: string; accessToken?: string }> = [];

    await expect(
      persistAgentProfileSelectionDurably(currentProfile.id, {
        createServer: (profile) =>
          createPersistedActiveServer({
            kind: profile.kind,
            label: profile.label,
            apiBase: profile.apiBase,
            accessToken: profile.accessToken,
          }),
        finalize: async (profile) => {
          published.push(profile);
          return true;
        },
      }),
    ).resolves.toEqual({ ok: true, profile: currentProfile });

    expect(published).toEqual([
      expect.objectContaining({
        apiBase: currentProfile.apiBase,
        accessToken: "token-b",
      }),
    ]);
    expect(
      JSON.parse(localStorage.getItem("elizaos:active-server") ?? "{}"),
    ).toMatchObject({
      apiBase: currentProfile.apiBase,
      accessToken: "token-b",
    });
  });

  it("recomputes a queued same-id selection after a credential/base update", async () => {
    const blocked = deferred();
    const release = deferred();
    const ownerId = "11111111-1111-4111-8111-111111111111";
    const profileId = "same-cloud-profile";
    const serverB = createPersistedActiveServer({
      kind: "cloud",
      id: `cloud:${ownerId}`,
      label: "Runtime B",
      apiBase: "https://runtime-b.example.test",
      accessToken: "token-b",
    });
    installBrowserStorageWriter({
      blockActiveServerId: serverB.id,
      blocked,
      release,
    });
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: profileId,
        profiles: [
          {
            id: profileId,
            kind: "cloud",
            cloudAgentId: ownerId,
            label: "Runtime A",
            apiBase: "https://runtime-a.example.test",
            accessToken: "token-a",
            createdAt: "2026-08-30T00:00:00.000Z",
          },
        ],
      }),
    );

    const update = persistAgentProfileConnectionDurably(
      {
        kind: "cloud",
        cloudAgentId: ownerId,
        label: serverB.label,
        apiBase: serverB.apiBase,
        accessToken: serverB.accessToken,
      },
      serverB,
    );
    await blocked.promise;
    const published: string[] = [];
    const selection = persistAgentProfileSelectionDurably(profileId, {
      createServer: (profile) =>
        createPersistedActiveServer({
          kind: profile.kind,
          id: `cloud:${profile.cloudAgentId}`,
          label: profile.label,
          apiBase: profile.apiBase,
          accessToken: profile.accessToken,
        }),
      finalize: async (profile) => {
        published.push(`${profile.apiBase}|${profile.accessToken}`);
        return true;
      },
    });
    release.resolve();

    await expect(update).resolves.toMatchObject({ id: profileId });
    await expect(selection).resolves.toMatchObject({
      ok: true,
      profile: { id: profileId, accessToken: "token-b" },
    });
    expect(published).toEqual(["https://runtime-b.example.test|token-b"]);
    expect(
      JSON.parse(localStorage.getItem("elizaos:active-server") ?? "{}"),
    ).toMatchObject({
      apiBase: "https://runtime-b.example.test",
      accessToken: "token-b",
    });
  });

  it("keeps removal and fallback publication atomic against a queued switch to the target", async () => {
    const blocked = deferred();
    const release = deferred();
    installBrowserStorageWriter({
      blockActiveServerId: "local:embedded",
      blocked,
      release,
    });
    const runtimeA = {
      id: "runtime-a",
      kind: "remote" as const,
      label: "Runtime A",
      apiBase: "http://100.64.0.1:3000",
      createdAt: "2026-08-30T00:00:00.000Z",
    };
    const runtimeB = {
      id: "runtime-b",
      kind: "local" as const,
      label: "Runtime B",
      createdAt: "2026-08-30T00:00:00.000Z",
    };
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: runtimeA.id,
        profiles: [runtimeA, runtimeB],
      }),
    );
    localStorage.setItem(
      "elizaos:active-server",
      JSON.stringify(
        createPersistedActiveServer({
          kind: runtimeA.kind,
          label: runtimeA.label,
          apiBase: runtimeA.apiBase,
        }),
      ),
    );
    const published: string[] = [];
    const remove = removeAgentProfileWithFallbackDurably(runtimeA.id, {
      createServer: (profile) =>
        createPersistedActiveServer({
          kind: profile.kind,
          label: profile.label,
          apiBase: profile.apiBase,
        }),
      finalize: async (profile) => {
        published.push(profile?.id ?? "cleared");
        return true;
      },
    });
    await blocked.promise;
    const switchBack = persistAgentProfileSelectionDurably(runtimeA.id, {
      createServer: (profile) =>
        createPersistedActiveServer({
          kind: profile.kind,
          label: profile.label,
          apiBase: profile.apiBase,
        }),
    });
    release.resolve();

    await expect(remove).resolves.toEqual({
      ok: true,
      activeProfile: runtimeB,
    });
    await expect(switchBack).resolves.toEqual({
      ok: false,
      reason: "not-found",
    });
    expect(published).toEqual([runtimeB.id]);
    expect(
      JSON.parse(localStorage.getItem("elizaos:agent-profiles") ?? "{}"),
    ).toMatchObject({ activeProfileId: runtimeB.id, profiles: [runtimeB] });
    expect(
      JSON.parse(localStorage.getItem("elizaos:active-server") ?? "{}").id,
    ).toBe("local:embedded");
  });

  it("refuses to remove the last profile from a build-pinned runtime", async () => {
    mocks.pinnedRemoteApiBase = "https://pinned.example.test";
    installBrowserStorageWriter();
    const pinnedProfile = {
      id: "pinned-profile",
      kind: "remote" as const,
      label: "Pinned",
      apiBase: mocks.pinnedRemoteApiBase,
      createdAt: "2026-08-30T00:00:00.000Z",
    };
    const registryRaw = JSON.stringify({
      version: 1,
      activeProfileId: pinnedProfile.id,
      profiles: [pinnedProfile],
    });
    const serverRaw = JSON.stringify(
      createPersistedActiveServer({
        kind: pinnedProfile.kind,
        label: pinnedProfile.label,
        apiBase: pinnedProfile.apiBase,
      }),
    );
    localStorage.setItem("elizaos:agent-profiles", registryRaw);
    localStorage.setItem("elizaos:active-server", serverRaw);
    const finalize = vi.fn(async () => true);

    await expect(
      removeAgentProfileWithFallbackDurably(pinnedProfile.id, {
        createServer: (profile) =>
          createPersistedActiveServer({
            kind: profile.kind,
            label: profile.label,
            apiBase: profile.apiBase,
          }),
        finalize,
      }),
    ).resolves.toEqual({ ok: false, reason: "build-pinned" });

    expect(mocks.setWithCompensation).not.toHaveBeenCalled();
    expect(mocks.removeStorageValueIfCurrent).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
    expect(localStorage.getItem("elizaos:agent-profiles")).toBe(registryRaw);
    expect(localStorage.getItem("elizaos:active-server")).toBe(serverRaw);
  });

  it("restores the registry when clearing the last active server rejects", async () => {
    installBrowserStorageWriter();
    const profile = {
      id: "runtime-a",
      kind: "remote" as const,
      label: "Runtime A",
      apiBase: "http://100.64.0.1:3000",
      createdAt: "2026-08-30T00:00:00.000Z",
    };
    const registryRaw = JSON.stringify({
      version: 1,
      activeProfileId: profile.id,
      profiles: [profile],
    });
    const serverRaw = JSON.stringify(
      createPersistedActiveServer({
        kind: profile.kind,
        label: profile.label,
        apiBase: profile.apiBase,
      }),
    );
    localStorage.setItem("elizaos:agent-profiles", registryRaw);
    localStorage.setItem("elizaos:active-server", serverRaw);
    mocks.removeStorageValueIfCurrent.mockRejectedValueOnce(
      new Error("protected delete rejected"),
    );
    const finalize = vi.fn(async () => true);

    await expect(
      removeAgentProfileWithFallbackDurably(profile.id, {
        createServer: (current) =>
          createPersistedActiveServer({
            kind: current.kind,
            label: current.label,
            apiBase: current.apiBase,
          }),
        finalize,
      }),
    ).rejects.toThrow("protected delete rejected");

    expect(finalize).not.toHaveBeenCalled();
    expect(localStorage.getItem("elizaos:agent-profiles")).toBe(registryRaw);
    expect(localStorage.getItem("elizaos:active-server")).toBe(serverRaw);
  });

  it("keeps the exact terminal profile scrub when shared active-server deletion rejects", async () => {
    const sharedBase =
      "https://api.eliza.app/api/v1/eliza/agents/account-a-agent";
    const serverRaw = JSON.stringify(
      createPersistedActiveServer({
        kind: "cloud",
        id: "cloud:account-a-agent",
        label: "Account A",
        apiBase: sharedBase,
      }),
    );
    localStorage.setItem("elizaos:active-server", serverRaw);
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: "shared-a",
        profiles: [
          {
            id: "shared-a",
            kind: "cloud",
            label: "Account A",
            apiBase: sharedBase,
            accessToken: "revoked-a",
            createdAt: "2026-08-30T00:00:00.000Z",
          },
          {
            id: "self-hosted",
            kind: "remote",
            label: "Self hosted",
            apiBase: "https://box.example.test",
            accessToken: "also-revoked-a",
            createdAt: "2026-08-30T00:00:00.000Z",
          },
        ],
      }),
    );
    mocks.removeStorageValueIfCurrent.mockRejectedValueOnce(
      new Error("protected delete rejected"),
    );
    const finalize = vi.fn();

    await expect(
      clearCloudRuntimeAuthorityDurably({
        scope: "shared",
        finalize,
      }),
    ).rejects.toThrow("protected delete rejected");

    const retainedRegistry = JSON.parse(
      localStorage.getItem("elizaos:agent-profiles") ?? "{}",
    );
    expect(retainedRegistry).toEqual({
      version: 1,
      activeProfileId: null,
      profiles: [
        expect.objectContaining({
          id: "self-hosted",
        }),
      ],
    });
    expect(retainedRegistry.profiles[0]).not.toHaveProperty("accessToken");
    expect(localStorage.getItem("elizaos:active-server")).toBe(serverRaw);
    expect(finalize).not.toHaveBeenCalled();
  });

  it("does not delete the active server or publish logout after a profile CAS conflict", async () => {
    const sharedBase =
      "https://api.eliza.app/api/v1/eliza/agents/account-a-agent";
    const serverRaw = JSON.stringify(
      createPersistedActiveServer({
        kind: "cloud",
        id: "cloud:account-a-agent",
        label: "Account A",
        apiBase: sharedBase,
      }),
    );
    localStorage.setItem("elizaos:active-server", serverRaw);
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: "shared-a",
        profiles: [
          {
            id: "shared-a",
            kind: "cloud",
            label: "Account A",
            apiBase: sharedBase,
            createdAt: "2026-08-30T00:00:00.000Z",
          },
        ],
      }),
    );
    mocks.setStorageValueIfCurrent.mockResolvedValueOnce(false);
    const finalize = vi.fn();

    await expect(
      clearCloudRuntimeAuthorityDurably({
        scope: "shared",
        finalize,
      }),
    ).resolves.toEqual({ ok: false, reason: "conflict" });

    expect(mocks.removeStorageValueIfCurrent).not.toHaveBeenCalled();
    expect(localStorage.getItem("elizaos:active-server")).toBe(serverRaw);
    expect(finalize).not.toHaveBeenCalled();
  });

  it("preserves account B when it committed before account A acquires the clear lock", async () => {
    const sharedBaseA =
      "https://api.eliza.app/api/v1/eliza/agents/account-a-agent";
    const sharedBaseB =
      "https://api.eliza.app/api/v1/eliza/agents/account-b-agent";
    const activeServerRawA = JSON.stringify(
      createPersistedActiveServer({
        kind: "cloud",
        id: "cloud:account-a-agent",
        label: "Account A",
        apiBase: sharedBaseA,
        accessToken: "token-a",
      }),
    );
    const registryRawA = JSON.stringify({
      version: 1,
      activeProfileId: "shared-a",
      profiles: [
        {
          id: "shared-a",
          kind: "cloud",
          label: "Account A",
          apiBase: sharedBaseA,
          accessToken: "token-a",
          createdAt: "2026-08-30T00:00:00.000Z",
        },
      ],
    });
    const activeServerRawB = JSON.stringify(
      createPersistedActiveServer({
        kind: "cloud",
        id: "cloud:account-b-agent",
        label: "Account B",
        apiBase: sharedBaseB,
        accessToken: "token-b",
      }),
    );
    const registryRawB = JSON.stringify({
      version: 1,
      activeProfileId: "shared-b",
      profiles: [
        {
          id: "shared-b",
          kind: "cloud",
          label: "Account B",
          apiBase: sharedBaseB,
          accessToken: "token-b",
          createdAt: "2026-08-30T00:01:00.000Z",
        },
      ],
    });
    localStorage.setItem("elizaos:active-server", activeServerRawB);
    localStorage.setItem("elizaos:agent-profiles", registryRawB);
    // The renderer-local protected cache was invalidated, so it sees no token;
    // the host-authoritative read still returns account B's bearer.
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    mocks.getStorageValue.mockImplementation(async (key: string) =>
      key === STEWARD_TOKEN_KEY ? "token-b" : localStorage.getItem(key),
    );
    const finalize = vi.fn();

    await expect(
      clearCloudRuntimeAuthorityDurably({
        expectedAuthority: {
          activeServerRaw: activeServerRawA,
          registryRaw: registryRawA,
          stewardToken: "token-a",
        },
        scope: "managed",
        finalize,
      }),
    ).resolves.toEqual({ ok: false, reason: "conflict" });

    expect(localStorage.getItem("elizaos:active-server")).toBe(
      activeServerRawB,
    );
    expect(localStorage.getItem("elizaos:agent-profiles")).toBe(registryRawB);
    expect(mocks.setStorageValueIfCurrent).not.toHaveBeenCalled();
    expect(mocks.removeStorageValueIfCurrent).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
  });

  it("refuses passive shared cleanup when another renderer has a host token", async () => {
    mocks.getStorageValue.mockImplementation(async (key: string) =>
      key === STEWARD_TOKEN_KEY ? "token-b" : localStorage.getItem(key),
    );

    await expect(
      clearCloudRuntimeAuthorityDurably({
        requireStewardTokenAbsent: true,
        scope: "shared",
      }),
    ).resolves.toEqual({ ok: false, reason: "authority-lost" });

    expect(mocks.setStorageValueIfCurrent).not.toHaveBeenCalled();
    expect(mocks.removeStorageValueIfCurrent).not.toHaveBeenCalled();
  });

  it("rejects a mixed host lease when the Steward token changes mid-capture", async () => {
    mocks.getStorageValue
      .mockResolvedValueOnce("token-a")
      .mockResolvedValueOnce("active-a")
      .mockResolvedValueOnce("registry-a")
      .mockResolvedValueOnce("token-b");

    await expect(captureCloudRuntimeAuthorityLeaseDurably()).rejects.toThrow(
      "Cloud account authority changed while it was captured",
    );
  });

  it("refuses account A before capture when the host already owns account B", async () => {
    mocks.getStorageValue.mockImplementation(async (key: string) =>
      key === STEWARD_TOKEN_KEY ? "token-b" : localStorage.getItem(key),
    );

    await expect(
      captureCloudRuntimeAuthorityLeaseDurably("token-a"),
    ).rejects.toThrow("Cloud account authority changed before it was captured");

    expect(mocks.setStorageValueIfCurrent).not.toHaveBeenCalled();
    expect(mocks.removeStorageValueIfCurrent).not.toHaveBeenCalled();
  });

  it("finishes account A teardown before a queued account B connection publishes", async () => {
    installBrowserStorageWriter();
    const sharedBaseA =
      "https://api.eliza.app/api/v1/eliza/agents/account-a-agent";
    const sharedBaseB =
      "https://api.eliza.app/api/v1/eliza/agents/account-b-agent";
    localStorage.setItem(
      "elizaos:active-server",
      JSON.stringify(
        createPersistedActiveServer({
          kind: "cloud",
          id: "cloud:account-a-agent",
          label: "Account A",
          apiBase: sharedBaseA,
        }),
      ),
    );
    localStorage.setItem(
      "elizaos:agent-profiles",
      JSON.stringify({
        version: 1,
        activeProfileId: "shared-a",
        profiles: [
          {
            id: "shared-a",
            kind: "cloud",
            cloudAgentId: "account-a-agent",
            label: "Account A",
            apiBase: sharedBaseA,
            createdAt: "2026-08-30T00:00:00.000Z",
          },
        ],
      }),
    );
    const profileWriteBlocked = deferred();
    const releaseProfileWrite = deferred();
    mocks.setStorageValueIfCurrent.mockImplementationOnce(
      async (key: string, expectedValue: string, value: string) => {
        if (localStorage.getItem(key) !== expectedValue) return false;
        localStorage.setItem(key, value);
        profileWriteBlocked.resolve();
        await releaseProfileWrite.promise;
        return true;
      },
    );
    const publication: string[] = [];

    const clearA = clearCloudRuntimeAuthorityDurably({
      scope: "shared",
      finalize: () => {
        publication.push("clear-a");
      },
    });
    await profileWriteBlocked.promise;
    const serverB = createPersistedActiveServer({
      kind: "cloud",
      id: "cloud:account-b-agent",
      label: "Account B",
      apiBase: sharedBaseB,
      accessToken: "token-b",
    });
    const connectB = persistAgentProfileConnectionDurably(
      {
        kind: "cloud",
        cloudAgentId: "account-b-agent",
        label: "Account B",
        apiBase: sharedBaseB,
        accessToken: "token-b",
      },
      serverB,
      {
        finalize: async () => {
          publication.push("publish-b");
          return true;
        },
      },
    );
    releaseProfileWrite.resolve();

    await expect(clearA).resolves.toMatchObject({
      ok: true,
      clearedActiveServer: true,
    });
    await expect(connectB).resolves.toMatchObject({
      cloudAgentId: "account-b-agent",
      accessToken: "token-b",
    });
    expect(publication).toEqual(["clear-a", "publish-b"]);
    expect(
      JSON.parse(localStorage.getItem("elizaos:agent-profiles") ?? "{}"),
    ).toMatchObject({
      profiles: [
        expect.objectContaining({
          cloudAgentId: "account-b-agent",
          accessToken: "token-b",
        }),
      ],
    });
    expect(
      JSON.parse(localStorage.getItem("elizaos:active-server") ?? "{}"),
    ).toMatchObject({
      id: "cloud:account-b-agent",
      accessToken: "token-b",
    });
  });
});
