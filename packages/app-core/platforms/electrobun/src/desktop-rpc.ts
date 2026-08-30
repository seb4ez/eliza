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
  releaseShellSync: () => void;
} {
  let rpc: ElizaDesktopRpc | undefined;
  let released = false;
  const secureStoreOwner = Symbol(`renderer-secure-store-owner:${label}`);

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
        secureStoreOwner,
        shellControllerEndpoint: shellSyncEndpoint,
      }) as BunRpcRequestsHandlers,
    },
  });
  const ownerRelease: PendingOwnerRelease = {
    label,
    owner: secureStoreOwner,
    promise: null,
  };
  pendingOwnerReleases.set(secureStoreOwner, ownerRelease);

  return {
    rpc,
    sendToWebview,
    releaseShellSync: () => {
      if (released) return;
      released = true;
      releaseSecureStoreRevisions();
      shellSyncEndpoint.release();
      void startOwnerRelease(ownerRelease);
    },
  };
}
