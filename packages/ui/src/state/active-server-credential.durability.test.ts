/** Verifies that paired credentials reach durable native storage before callers continue. */

import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getActiveProfile: vi.fn(),
  loadPersistedActiveServer: vi.fn(),
  persistAgentProfileConnectionDurably: vi.fn(),
}));

vi.mock("./agent-profiles", () => ({
  getActiveProfile: mocks.getActiveProfile,
  loadAgentProfileRegistry: vi.fn(() => ({
    version: 1,
    activeProfileId: null,
    profiles: [],
  })),
  persistAgentProfileConnectionDurably:
    mocks.persistAgentProfileConnectionDurably,
  updateAgentProfile: vi.fn(),
}));

vi.mock("./persistence", () => ({
  createPersistedActiveServer: vi.fn((args) => ({
    id: `remote:${args.apiBase}`,
    kind: "remote",
    label: "Test runtime",
    apiBase: args.apiBase,
    accessToken: args.accessToken,
  })),
  loadPersistedActiveServer: mocks.loadPersistedActiveServer,
  savePersistedActiveServer: vi.fn(),
  savePersistedActiveServerDurably: vi.fn(async () => true),
}));

import { persistActiveServerCredential } from "./active-server-credential";

describe("persistActiveServerCredential native durability", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.loadPersistedActiveServer.mockReturnValue({
      id: "remote:test",
      kind: "remote",
      label: "Test runtime",
      apiBase: "https://runtime.example.test",
    });
    mocks.getActiveProfile.mockReturnValue(null);
  });

  it("does not resolve until the active-server mirror is durable", async () => {
    let releaseWrite!: () => void;
    mocks.persistAgentProfileConnectionDurably.mockReturnValue(
      new Promise((resolve) => {
        releaseWrite = () =>
          resolve({
            id: "remote:test",
            createdAt: "2026-08-30T00:00:00.000Z",
            kind: "remote",
            label: "Test runtime",
            apiBase: "https://runtime.example.test",
            accessToken: "paired-token",
          });
      }),
    );

    let completed = false;
    const persistence = persistActiveServerCredential("paired-token").then(
      () => {
        completed = true;
      },
    );
    await Promise.resolve();

    const authenticatedServer = {
      id: "remote:test",
      kind: "remote",
      label: "Test runtime",
      apiBase: "https://runtime.example.test",
      accessToken: "paired-token",
    };
    expect(mocks.persistAgentProfileConnectionDurably).toHaveBeenCalledWith(
      {
        kind: "remote",
        label: "Test runtime",
        apiBase: "https://runtime.example.test",
        accessToken: "paired-token",
      },
      authenticatedServer,
      {},
    );
    expect(completed).toBe(false);

    releaseWrite();
    await persistence;
    expect(completed).toBe(true);
  });
});
