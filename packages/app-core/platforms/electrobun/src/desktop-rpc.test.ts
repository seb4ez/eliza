/**
 * Exercises the real desktop RPC factory with deterministic Electrobun
 * transport and owner-cleanup adapters, including missed invalidations and a
 * shutdown wait that cannot finish before credential rollback cleanup.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  awaitDesktopRpcSecureStoreCleanup,
  createDesktopRpc,
  quitAfterDesktopCleanup,
} from "./desktop-rpc";
import { rendererSecureStoreRevisions } from "./renderer-secure-store-revisions";

const mocks = vi.hoisted(() => ({
  releaseOwner: vi.fn<() => Promise<void>>(() => Promise.resolve()),
  rpcSend: vi.fn<(message: string, payload: unknown) => void>(),
  shellRelease: vi.fn(),
}));

vi.mock("electrobun/bun", () => ({
  BrowserView: {
    defineRPC: vi.fn(() => ({
      request: {},
      send: mocks.rpcSend,
    })),
  },
}));

vi.mock("./rpc-handlers", () => ({
  buildBunRpcHandlers: vi.fn(() => ({})),
  releaseRendererSecureStoreOwner: mocks.releaseOwner,
}));

vi.mock("./shell-sync-relay", () => ({
  registerShellSyncEndpoint: vi.fn(() => ({
    id: Symbol("shell-endpoint"),
    release: mocks.shellRelease,
  })),
}));

vi.mock("./logger", () => ({
  logger: { warn: vi.fn() },
}));

afterEach(async () => {
  mocks.releaseOwner.mockImplementation(() => Promise.resolve());
  mocks.rpcSend.mockReset();
  mocks.shellRelease.mockReset();
  await awaitDesktopRpcSecureStoreCleanup();
  mocks.releaseOwner.mockClear();
});

describe("createDesktopRpc secure-store lifecycle", () => {
  it("lets the revision authority quarantine a throwing real RPC send wrapper without leaking a secret", async () => {
    mocks.rpcSend.mockImplementation(() => {
      throw new Error("closed renderer transport");
    });
    const endpoint = createDesktopRpc("throwing-renderer");
    const vaultId = `desktop-rpc-test-${crypto.randomUUID()}`;

    await expect(
      rendererSecureStoreRevisions.run(
        vaultId,
        "session.steward_token",
        async () => ({ ok: true as const, rollbackReceipt: "secret-receipt" }),
        { invalidates: (result) => result.ok },
      ),
    ).resolves.toMatchObject({ ok: true, revision: 1 });
    await rendererSecureStoreRevisions.run(
      vaultId,
      "session.steward_token",
      async () => ({ ok: true as const }),
      { invalidates: (result) => result.ok },
    );

    expect(mocks.rpcSend).toHaveBeenCalledTimes(1);
    expect(mocks.rpcSend).toHaveBeenCalledWith("secureStoreChanged", {
      kind: "session.steward_token",
      revision: 1,
    });
    expect(JSON.stringify(mocks.rpcSend.mock.calls)).not.toContain(
      "secret-receipt",
    );

    endpoint.releaseShellSync();
    await awaitDesktopRpcSecureStoreCleanup();
  });

  it("does not invoke the real quit gate until a deferred owner release completes", async () => {
    let finishRelease: () => void = () => {};
    mocks.releaseOwner.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finishRelease = resolve;
        }),
    );
    const endpoint = createDesktopRpc("deferred-cleanup-renderer");
    endpoint.releaseShellSync();

    const quit = vi.fn();
    const shutdown = quitAfterDesktopCleanup(
      awaitDesktopRpcSecureStoreCleanup,
      quit,
    );
    await Promise.resolve();
    expect(quit).not.toHaveBeenCalled();

    finishRelease();
    await shutdown;
    expect(quit).toHaveBeenCalledOnce();
  });

  it("retains a failed owner cleanup so the next shutdown attempt retries it", async () => {
    mocks.releaseOwner.mockRejectedValueOnce(new Error("keychain unavailable"));
    const endpoint = createDesktopRpc("retry-cleanup-renderer");
    endpoint.releaseShellSync();

    await expect(awaitDesktopRpcSecureStoreCleanup()).rejects.toThrow(
      "still pending",
    );
    mocks.releaseOwner.mockResolvedValue(undefined);
    await expect(awaitDesktopRpcSecureStoreCleanup()).resolves.toBeUndefined();
    expect(mocks.releaseOwner).toHaveBeenCalledTimes(2);
  });
});
