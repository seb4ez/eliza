/** Verifies awaited, fail-closed runtime-management profile persistence. */
// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  addAgentProfileDurably: vi.fn(),
  loadAgentProfileRegistry: vi.fn(() => ({
    version: 1 as const,
    activeProfileId: null,
    profiles: [],
  })),
  removeAgentProfileDurably: vi.fn(async () => true),
  removeRuntimeProfileNonDestructive: vi.fn(async () => ({ ok: true })),
  isTrustedRestoreApiBaseUrl: vi.fn(() => true),
}));

vi.mock("../state", () => ({
  addAgentProfileDurably: mocks.addAgentProfileDurably,
  loadAgentProfileRegistry: mocks.loadAgentProfileRegistry,
  removeAgentProfileDurably: mocks.removeAgentProfileDurably,
}));

vi.mock("../state/runtime-url-trust", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../state/runtime-url-trust")>()),
  isTrustedRestoreApiBaseUrl: mocks.isTrustedRestoreApiBaseUrl,
}));

vi.mock("../state/switch-runtime", () => ({
  removeRuntimeProfileNonDestructive: mocks.removeRuntimeProfileNonDestructive,
}));

import { executeRuntimeManagementCommand } from "./runtime-management";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((release) => {
    resolve = release;
  });
  return { promise, resolve };
}

describe("runtime-management durable profile writes", () => {
  beforeEach(() => {
    mocks.addAgentProfileDurably.mockReset();
    mocks.isTrustedRestoreApiBaseUrl.mockReturnValue(true);
  });

  it("does not report add_direct success before the protected write settles", async () => {
    const write = deferred<{
      id: string;
      label: string;
      kind: "remote";
      apiBase: string;
      createdAt: string;
    } | null>();
    mocks.addAgentProfileDurably.mockReturnValue(write.promise);

    const result = executeRuntimeManagementCommand({
      op: "add_direct",
      label: "Private VPS",
      apiBase: "http://100.72.1.9:3000",
      accessToken: "runtime-token",
    });
    let settled = false;
    void result.then(() => {
      settled = true;
    });
    await Promise.resolve();

    expect(mocks.addAgentProfileDurably).toHaveBeenCalledWith(
      {
        kind: "remote",
        label: "Private VPS",
        apiBase: "http://100.72.1.9:3000",
        accessToken: "runtime-token",
      },
      { activate: false },
    );
    expect(settled).toBe(false);

    write.resolve({
      id: "runtime-1",
      label: "Private VPS",
      kind: "remote",
      apiBase: "http://100.72.1.9:3000",
      createdAt: "2026-08-30T00:00:00.000Z",
    });
    await expect(result).resolves.toEqual({
      ok: true,
      op: "add_direct",
      data: { runtimeId: "runtime-1", label: "Private VPS" },
    });
  });

  it("returns an explicit failure when protected add_direct persistence refuses", async () => {
    mocks.addAgentProfileDurably.mockResolvedValue(null);

    await expect(
      executeRuntimeManagementCommand({
        op: "add_direct",
        label: "Private VPS",
        apiBase: "http://100.72.1.9:3000",
      }),
    ).resolves.toMatchObject({
      ok: false,
      op: "add_direct",
      error: expect.stringContaining("protected storage"),
    });
  });
});
