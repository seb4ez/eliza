/**
 * Exercises the real desktop RPC factory with deterministic Electrobun
 * transport and owner-cleanup adapters, including authenticated document
 * rollover and a shutdown wait that cannot preempt credential rollback.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  awaitDesktopRpcSecureStoreCleanup,
  createDesktopRpc,
  quitAfterDesktopCleanup,
} from "./desktop-rpc";
import type { RendererSecureStoreOwner } from "./renderer-secure-store-authority";
import { rendererSecureStoreRevisions } from "./renderer-secure-store-revisions";

interface TestDocumentAuthority {
  run<T>(
    documentCapability: string,
    operation: (owner: RendererSecureStoreOwner) => Promise<T>,
  ): Promise<T>;
}

function resolveDocumentOwner(
  documents: TestDocumentAuthority,
  documentCapability: string,
): Promise<RendererSecureStoreOwner> {
  return documents.run(documentCapability, async (owner) => owner);
}

const mocks = vi.hoisted(() => ({
  buildHandlers: vi.fn(),
  releaseOwner: vi.fn<() => Promise<void>>(() => Promise.resolve()),
  secureStoreDocuments: null as TestDocumentAuthority | null,
  rpcMessages: {} as Record<string, () => void>,
  rpcSend: vi.fn<(message: string, payload: unknown) => void>(),
  shellRelease: vi.fn(),
}));

vi.mock("electrobun/bun", () => ({
  BrowserView: {
    defineRPC: vi.fn(
      (config: { handlers?: { messages?: Record<string, () => void> } }) => {
        mocks.rpcMessages = config.handlers?.messages ?? {};
        return {
          request: {},
          send: mocks.rpcSend,
        };
      },
    ),
  },
}));

vi.mock("./rpc-handlers", () => ({
  buildBunRpcHandlers: mocks.buildHandlers.mockImplementation(
    (options: { secureStoreDocuments: TestDocumentAuthority }) => {
      mocks.secureStoreDocuments = options.secureStoreDocuments;
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

function createLifecycleHarness(): {
  executeJavascript: ReturnType<typeof vi.fn<(script: string) => void>>;
  handlers: Map<string, () => void>;
  lifecycle: {
    executeJavascript: (script: string) => void;
    on: (name: string, handler: () => void) => void;
  };
} {
  const handlers = new Map<string, () => void>();
  const executeJavascript = vi.fn<(script: string) => void>();
  return {
    executeJavascript,
    handlers,
    lifecycle: {
      executeJavascript,
      on: (name, handler) => handlers.set(name, handler),
    },
  };
}

function readPublishedCapability(script: string): {
  documentCapability: string;
  generation: number;
} {
  const match = script.match(/\?\.\((\{.*\})\);$/);
  if (!match?.[1]) throw new Error(`capability payload missing: ${script}`);
  return JSON.parse(match[1]) as {
    documentCapability: string;
    generation: number;
  };
}

afterEach(async () => {
  mocks.releaseOwner.mockImplementation(() => Promise.resolve());
  mocks.buildHandlers.mockClear();
  mocks.secureStoreDocuments = null;
  mocks.rpcMessages = {};
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

  it("rolls A back after native commit before publishing B and rejects delayed A", async () => {
    let finishRelease: () => void = () => {};
    mocks.releaseOwner.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finishRelease = resolve;
        }),
    );
    const endpoint = createDesktopRpc("reload-renderer");
    const lifecycle = createLifecycleHarness();
    endpoint.bindRendererLifecycle(lifecycle.lifecycle);
    const documents = mocks.secureStoreDocuments;
    if (!documents) throw new Error("secure-store document authority missing");

    lifecycle.handlers.get("dom-ready")?.();
    await vi.waitFor(() => {
      expect(lifecycle.executeJavascript).toHaveBeenCalledOnce();
    });
    const publicationA = readPublishedCapability(
      lifecycle.executeJavascript.mock.calls[0]?.[0] ?? "",
    );
    expect(publicationA.generation).toBe(0);
    const ownerA = await resolveDocumentOwner(
      documents,
      publicationA.documentCapability,
    );

    lifecycle.handlers.get("will-navigate")?.();
    expect(mocks.releaseOwner).not.toHaveBeenCalled();
    lifecycle.handlers.get("did-commit-navigation")?.();
    const delayedA = resolveDocumentOwner(
      documents,
      publicationA.documentCapability,
    );
    let delayedASettled = false;
    void delayedA.then(
      () => {
        delayedASettled = true;
      },
      () => {
        delayedASettled = true;
      },
    );
    lifecycle.handlers.get("dom-ready")?.();

    await vi.waitFor(() => {
      expect(mocks.releaseOwner).toHaveBeenCalledWith(ownerA);
    });
    expect(delayedASettled).toBe(false);
    expect(lifecycle.executeJavascript).toHaveBeenCalledTimes(1);

    finishRelease();
    await expect(delayedA).rejects.toThrow("document is not active");
    await vi.waitFor(() => {
      expect(lifecycle.executeJavascript).toHaveBeenCalledTimes(2);
    });
    const publicationB = readPublishedCapability(
      lifecycle.executeJavascript.mock.calls[1]?.[0] ?? "",
    );
    expect(publicationB.generation).toBe(1);
    expect(publicationB.documentCapability).not.toBe(
      publicationA.documentCapability,
    );
    await expect(
      resolveDocumentOwner(documents, publicationB.documentCapability),
    ).resolves.toBeDefined();
    await expect(
      resolveDocumentOwner(documents, publicationA.documentCapability),
    ).rejects.toThrow("document is not active");

    mocks.rpcMessages.secureStoreDocumentReady?.();
    await vi.waitFor(() => {
      expect(lifecycle.executeJavascript).toHaveBeenCalledTimes(3);
    });
    expect(
      readPublishedCapability(
        lifecycle.executeJavascript.mock.calls[2]?.[0] ?? "",
      ),
    ).toEqual(publicationB);

    mocks.releaseOwner.mockResolvedValue(undefined);
    endpoint.releaseShellSync();
    await awaitDesktopRpcSecureStoreCleanup();
  });

  it("keeps A active when will-navigate is cancelled and a raw ready hint cannot rotate authority", async () => {
    const endpoint = createDesktopRpc("cancelled-navigation-renderer");
    const lifecycle = createLifecycleHarness();
    endpoint.bindRendererLifecycle(lifecycle.lifecycle);
    const documents = mocks.secureStoreDocuments;
    if (!documents) throw new Error("secure-store document authority missing");

    lifecycle.handlers.get("dom-ready")?.();
    await vi.waitFor(() => {
      expect(lifecycle.executeJavascript).toHaveBeenCalledOnce();
    });
    const publicationA = readPublishedCapability(
      lifecycle.executeJavascript.mock.calls[0]?.[0] ?? "",
    );
    const ownerA = await resolveDocumentOwner(
      documents,
      publicationA.documentCapability,
    );

    lifecycle.handlers.get("will-navigate")?.();
    lifecycle.handlers.get("dom-ready")?.();
    mocks.rpcMessages.secureStoreDocumentReady?.();
    await Promise.resolve();

    expect(mocks.releaseOwner).not.toHaveBeenCalled();
    expect(lifecycle.executeJavascript).toHaveBeenCalledOnce();
    await expect(
      resolveDocumentOwner(documents, publicationA.documentCapability),
    ).resolves.toBe(ownerA);

    endpoint.releaseShellSync();
    await awaitDesktopRpcSecureStoreCleanup();
  });

  it("retries the same host capability when its first native-document injection is lost", async () => {
    const endpoint = createDesktopRpc("lost-capability-publication-renderer");
    const lifecycle = createLifecycleHarness();
    lifecycle.executeJavascript.mockImplementationOnce(() => {
      throw new Error("preload callback is not installed yet");
    });
    endpoint.bindRendererLifecycle(lifecycle.lifecycle);
    const documents = mocks.secureStoreDocuments;
    if (!documents) throw new Error("secure-store document authority missing");

    lifecycle.handlers.get("dom-ready")?.();
    await vi.waitFor(() => {
      expect(lifecycle.executeJavascript).toHaveBeenCalledOnce();
    });
    const lostPublication = readPublishedCapability(
      lifecycle.executeJavascript.mock.calls[0]?.[0] ?? "",
    );

    mocks.rpcMessages.secureStoreDocumentReady?.();
    await vi.waitFor(() => {
      expect(lifecycle.executeJavascript).toHaveBeenCalledTimes(2);
    });
    const retriedPublication = readPublishedCapability(
      lifecycle.executeJavascript.mock.calls[1]?.[0] ?? "",
    );
    expect(retriedPublication).toEqual(lostPublication);
    await expect(
      resolveDocumentOwner(documents, retriedPublication.documentCapability),
    ).resolves.toBeDefined();

    endpoint.releaseShellSync();
    await awaitDesktopRpcSecureStoreCleanup();
  });

  it("drains A's complete secure RPC response turn before publishing B", async () => {
    let finishGet: (value: string) => void = () => {};
    let responseAWasDelivered = false;
    mocks.releaseOwner.mockImplementation(async () => {
      expect(responseAWasDelivered).toBe(true);
    });

    const endpoint = createDesktopRpc("in-flight-response-renderer");
    const lifecycle = createLifecycleHarness();
    endpoint.bindRendererLifecycle(lifecycle.lifecycle);
    const documents = mocks.secureStoreDocuments;
    if (!documents) throw new Error("secure-store document authority missing");

    lifecycle.handlers.get("dom-ready")?.();
    await vi.waitFor(() => {
      expect(lifecycle.executeJavascript).toHaveBeenCalledOnce();
    });
    const publicationA = readPublishedCapability(
      lifecycle.executeJavascript.mock.calls[0]?.[0] ?? "",
    );

    const responseA = documents
      .run(
        publicationA.documentCapability,
        async () =>
          await new Promise<string>((resolve) => {
            finishGet = resolve;
          }),
      )
      .then((value) => {
        // This continuation stands in for Electrobun serializing and sending
        // the response packet for A's request id on the shared webview RPC.
        responseAWasDelivered = true;
        return value;
      });

    lifecycle.handlers.get("did-commit-navigation")?.();
    await Promise.resolve();
    expect(mocks.releaseOwner).not.toHaveBeenCalled();
    expect(lifecycle.executeJavascript).toHaveBeenCalledOnce();

    finishGet("token-a");
    await expect(responseA).resolves.toBe("token-a");
    expect(mocks.releaseOwner).not.toHaveBeenCalled();
    expect(lifecycle.executeJavascript).toHaveBeenCalledOnce();

    await vi.waitFor(() => {
      expect(mocks.releaseOwner).toHaveBeenCalledOnce();
      expect(lifecycle.executeJavascript).toHaveBeenCalledTimes(2);
    });

    endpoint.releaseShellSync();
    await awaitDesktopRpcSecureStoreCleanup();
  });

  it("mints only the latest host epoch across overlapping committed navigations", async () => {
    let finishRelease: () => void = () => {};
    mocks.releaseOwner.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finishRelease = resolve;
        }),
    );
    const endpoint = createDesktopRpc("overlapping-navigation-renderer");
    const lifecycle = createLifecycleHarness();
    endpoint.bindRendererLifecycle(lifecycle.lifecycle);

    lifecycle.handlers.get("did-commit-navigation")?.();
    lifecycle.handlers.get("did-commit-navigation")?.();
    lifecycle.handlers.get("dom-ready")?.();
    await vi.waitFor(() => expect(mocks.releaseOwner).toHaveBeenCalledOnce());
    finishRelease();

    await vi.waitFor(() => {
      expect(lifecycle.executeJavascript).toHaveBeenCalledOnce();
    });
    expect(
      readPublishedCapability(
        lifecycle.executeJavascript.mock.calls[0]?.[0] ?? "",
      ).generation,
    ).toBe(2);
    expect(mocks.releaseOwner).toHaveBeenCalledOnce();

    mocks.releaseOwner.mockResolvedValue(undefined);
    endpoint.releaseShellSync();
    await awaitDesktopRpcSecureStoreCleanup();
  });

  it("creates a fresh host capability when the same surface closes and reopens", async () => {
    const firstEndpoint = createDesktopRpc("tray-popover");
    const firstLifecycle = createLifecycleHarness();
    firstEndpoint.bindRendererLifecycle(firstLifecycle.lifecycle);
    firstLifecycle.handlers.get("dom-ready")?.();
    await vi.waitFor(() => {
      expect(firstLifecycle.executeJavascript).toHaveBeenCalledOnce();
    });
    const firstPublication = readPublishedCapability(
      firstLifecycle.executeJavascript.mock.calls[0]?.[0] ?? "",
    );
    firstEndpoint.releaseShellSync();
    await awaitDesktopRpcSecureStoreCleanup();

    const reopenedEndpoint = createDesktopRpc("tray-popover");
    const reopenedLifecycle = createLifecycleHarness();
    reopenedEndpoint.bindRendererLifecycle(reopenedLifecycle.lifecycle);
    reopenedLifecycle.handlers.get("dom-ready")?.();
    await vi.waitFor(() => {
      expect(reopenedLifecycle.executeJavascript).toHaveBeenCalledOnce();
    });
    const reopenedPublication = readPublishedCapability(
      reopenedLifecycle.executeJavascript.mock.calls[0]?.[0] ?? "",
    );
    expect(reopenedPublication.documentCapability).not.toBe(
      firstPublication.documentCapability,
    );

    reopenedEndpoint.releaseShellSync();
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
