// @vitest-environment jsdom

/** Deterministic failure coverage for multi-record protected transactions. */
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  pinnedRemoteApiBase: null as string | null,
  setWithCompensation: vi.fn(),
  setStorageValue: vi.fn(),
  setStorageValueIfCurrent: vi.fn(),
}));

vi.mock("../bridge/storage-bridge", () => ({
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
  persistAgentProfileConnectionDurably,
  persistAgentProfileSelectionDurably,
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
    mocks.setWithCompensation.mockReset();
    mocks.setStorageValue.mockReset();
    mocks.setStorageValueIfCurrent.mockReset();
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

    const selectionA = persistAgentProfileSelectionDurably(
      "profile-a",
      serverA,
      {
        finalize: async () => {
          live.push(serverA.id);
          return true;
        },
      },
    );
    await blocked.promise;
    const selectionB = persistAgentProfileSelectionDurably(
      "profile-b",
      serverB,
      {
        finalize: async () => {
          live.push(serverB.id);
          return true;
        },
      },
    );
    release.resolve();

    await expect(Promise.all([selectionA, selectionB])).resolves.toEqual([
      true,
      true,
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
});
