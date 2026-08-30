/**
 * Constructs renderer RPC endpoints and owns their secure-store cleanup until
 * shutdown has observed every release. Failed cleanup remains registered so a
 * later shutdown attempt can retry instead of forgetting rollback authority.
 */

import { BrowserView } from "electrobun/bun";
import { logger } from "./logger";
import { rendererSecureStoreRevisions } from "./renderer-secure-store-revisions";
import {
  buildBunRpcHandlers,
  releaseRendererSecureStoreOwner,
} from "./rpc-handlers";
import type { ElizaDesktopRPCSchema } from "./rpc-schema";
import { registerShellSyncEndpoint } from "./shell-sync-relay";
import type { SendToWebview } from "./types";

export type ElizaDesktopRpc = ReturnType<
  typeof BrowserView.defineRPC<ElizaDesktopRPCSchema>
>;

interface PendingOwnerRelease {
  label: string;
  owner: symbol;
  promise: Promise<void> | null;
}

interface RendererDocumentLifecycle {
  on(name: "did-commit-navigation", handler: () => void): void;
}

const pendingOwnerReleases = new Map<symbol, PendingOwnerRelease>();
const MAX_RPC_REQUEST_TIME_MS = 600_000;

function asRpcSend(
  send: unknown,
): (message: string, payload?: unknown) => void {
  return send as (message: string, payload?: unknown) => void;
}

function startOwnerRelease(entry: PendingOwnerRelease): Promise<void> {
  if (entry.promise) return entry.promise;
  const promise = releaseRendererSecureStoreOwner(entry.owner).then(
    () => {
      if (pendingOwnerReleases.get(entry.owner) === entry) {
        pendingOwnerReleases.delete(entry.owner);
      }
    },
    (error: unknown) => {
      // Keep the owner registered and clear only the attempt. Shutdown can
      // retry the still-live rollback receipts after a transient store error.
      if (pendingOwnerReleases.get(entry.owner) === entry) {
        entry.promise = null;
      }
      throw error;
    },
  );
  entry.promise = promise;
  // error-policy:J5 the same rejection remains observable through the tracker
  // and awaitDesktopRpcSecureStoreCleanup; this branch prevents an unhandled
  // rejection when a window closes before shutdown begins.
  void promise.catch((error) => {
    logger.warn(
      `[secure-store:${entry.label}] endpoint cleanup failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  });
  return promise;
}

/** Wait for every released renderer owner, retrying a prior failed attempt. */
export async function awaitDesktopRpcSecureStoreCleanup(): Promise<void> {
  while (pendingOwnerReleases.size > 0) {
    const entries = Array.from(pendingOwnerReleases.values());
    const results = await Promise.allSettled(
      entries.map((entry) => startOwnerRelease(entry)),
    );
    const failures = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (failures.length > 0) {
      throw new AggregateError(
        failures,
        "One or more renderer secure-store releases are still pending.",
      );
    }
  }
}

/** Invoke the process quit primitive only after the complete cleanup settles. */
export async function quitAfterDesktopCleanup(
  cleanup: () => Promise<void>,
  quit: () => void,
): Promise<void> {
  await cleanup();
  quit();
}

/** Build one fully wired renderer RPC endpoint. */
export function createDesktopRpc(label: string): {
  rpc: ElizaDesktopRpc;
  sendToWebview: SendToWebview;
  bindRendererLifecycle: (lifecycle: RendererDocumentLifecycle) => void;
  releaseShellSync: () => void;
} {
  let rpc: ElizaDesktopRpc | undefined;
  let released = false;
  let lifecycleBound = false;
  let ownerGeneration = 0;

  const createOwnerRelease = (): PendingOwnerRelease => {
    ownerGeneration += 1;
    const entry: PendingOwnerRelease = {
      label: `${label}:document-${ownerGeneration}`,
      owner: Symbol(
        `renderer-secure-store-owner:${label}:document-${ownerGeneration}`,
      ),
      promise: null,
    };
    pendingOwnerReleases.set(entry.owner, entry);
    return entry;
  };

  let currentOwnerRelease = createOwnerRelease();
  let ownerReady: Promise<void> = Promise.resolve();

  const prepareForRendererDocument = (): Promise<void> => {
    if (released) return ownerReady;
    ownerReady = ownerReady
      .catch(() => undefined)
      .then(async () => {
        await startOwnerRelease(currentOwnerRelease);
        if (!released) currentOwnerRelease = createOwnerRelease();
      });
    // error-policy:J5 resolver RPC calls and shutdown both observe this same
    // rejection; this branch only prevents an unhandled navigation callback.
    void ownerReady.catch((error) => {
      logger.warn(
        `[secure-store:${label}] document rollover failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
    return ownerReady;
  };

  const resolveSecureStoreOwner = async (): Promise<symbol> => {
    while (true) {
      const observedReady = ownerReady;
      await observedReady;
      if (observedReady === ownerReady) return currentOwnerRelease.owner;
    }
  };

  const sendToWebview: SendToWebview = (message, payload) => {
    if (!rpc) {
      logger.warn(
        `[sendToWebview:${label}] RPC not yet initialised; dropping message: ${message}`,
      );
      return;
    }
    try {
      asRpcSend(rpc.send)(message, payload ?? null);
    } catch (error) {
      logger.warn(
        `[sendToWebview:${label}] send(${message}) failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      // The revision authority must observe delivery failure so it can
      // quarantine this endpoint. Renderer caches independently expire via a
      // secret-free revision lease, bounding any missed event.
      throw error;
    }
  };

  type BunRpcRequestsHandlers = NonNullable<
    Parameters<
      typeof BrowserView.defineRPC<ElizaDesktopRPCSchema>
    >[0]["handlers"]
  >["requests"];

  const shellSyncEndpoint = registerShellSyncEndpoint(label, sendToWebview);
  const releaseSecureStoreRevisions =
    rendererSecureStoreRevisions.registerEndpoint(sendToWebview);

  rpc = BrowserView.defineRPC<ElizaDesktopRPCSchema>({
    maxRequestTime: MAX_RPC_REQUEST_TIME_MS,
    handlers: {
      requests: buildBunRpcHandlers({
        sendToWebview,
        secureStoreOwner: resolveSecureStoreOwner,
        shellControllerEndpoint: shellSyncEndpoint,
      }) as BunRpcRequestsHandlers,
    },
  });

  return {
    rpc,
    sendToWebview,
    bindRendererLifecycle: (lifecycle) => {
      if (lifecycleBound) return;
      lifecycleBound = true;
      // A committed top-level document boundary covers reload, allowed
      // navigation, and renderer crash recovery. Rotate before its preload can
      // hydrate: every secure-store RPC awaits ownerReady, so the old
      // document's pending receipts are reconciled before the new owner exists.
      lifecycle.on("did-commit-navigation", () => {
        void prepareForRendererDocument();
      });
    },
    releaseShellSync: () => {
      if (released) return;
      released = true;
      releaseSecureStoreRevisions();
      shellSyncEndpoint.release();
      ownerReady = ownerReady
        .catch(() => undefined)
        .then(() => startOwnerRelease(currentOwnerRelease));
      void ownerReady.catch((error) => {
        logger.warn(
          `[secure-store:${label}] endpoint cleanup failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      });
    },
  };
}
