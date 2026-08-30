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
  buildHandlers: vi.fn(),
  releaseOwner: vi.fn<() => Promise<void>>(() => Promise.resolve()),
  resolveSecureStoreOwner: null as null | (() => Promise<symbol>),
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
  buildBunRpcHandlers: mocks.buildHandlers.mockImplementation(
    (options: { secureStoreOwner: () => Promise<symbol> }) => {
      mocks.resolveSecureStoreOwner = options.secureStoreOwner;
      return {};
    },
  ),
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
  mocks.buildHandlers.mockClear();
  mocks.resolveSecureStoreOwner = null;
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

  it("rolls the prior document back before a reload can hydrate under a new owner", async () => {
    let finishRelease: () => void = () => {};
    mocks.releaseOwner.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finishRelease = resolve;
        }),
    );
    const endpoint = createDesktopRpc("reload-renderer");
    const lifecycleHandlers = new Map<string, () => void>();
    endpoint.bindRendererLifecycle({
      on: (name, handler) => lifecycleHandlers.set(name, handler),
    });
    const resolveOwner = mocks.resolveSecureStoreOwner;
    if (!resolveOwner) throw new Error("secure-store owner resolver missing");
    const priorOwner = await resolveOwner();

    lifecycleHandlers.get("did-commit-navigation")?.();
    const hydrationOwner = resolveOwner();
    let hydrationSettled = false;
    void hydrationOwner.then(() => {
      hydrationSettled = true;
    });
    await vi.waitFor(() => {
      expect(mocks.releaseOwner).toHaveBeenCalledWith(priorOwner);
    });
    expect(hydrationSettled).toBe(false);

    finishRelease();
    const nextOwner = await hydrationOwner;
    expect(nextOwner).not.toBe(priorOwner);
    expect(hydrationSettled).toBe(true);

    endpoint.releaseShellSync();
    mocks.releaseOwner.mockResolvedValue(undefined);
    await awaitDesktopRpcSecureStoreCleanup();
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
