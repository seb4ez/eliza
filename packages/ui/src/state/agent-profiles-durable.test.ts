// @vitest-environment jsdom

/** Deterministic failure coverage for multi-record protected transactions. */
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  setWithCompensation: vi.fn(),
  setStorageValue: vi.fn(),
  setStorageValueIfCurrent: vi.fn(),
}));

vi.mock("../bridge/storage-bridge", () => ({
  setStorageValue: mocks.setStorageValue,
  setStorageValueIfCurrent: mocks.setStorageValueIfCurrent,
  setStorageValueWithCompensation: mocks.setWithCompensation,
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

import { persistAgentProfileConnectionDurably } from "./agent-profiles";
import { createPersistedActiveServer } from "./persistence";

describe("durable agent-profile compensation", () => {
  beforeEach(() => {
    localStorage.clear();
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
});
