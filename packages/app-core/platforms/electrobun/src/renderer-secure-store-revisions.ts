/**
 * Host-global revision and invalidation authority for renderer-visible secure
 * store slots. It wraps the credential authority's complete RPC operations so
 * a returned snapshot and its revision are atomic with respect to later
 * renderer mutations. Broadcasts contain only kind + revision, never secrets.
 */

import type {
  RendererSecureStoreChangedEvent,
  RendererSecureStoreKind,
} from "./rpc-schema";
import type { SendToWebview } from "./types";

interface RevisionedOperationOptions<T> {
  invalidates: (result: T) => boolean;
  invalidatesOnError?: boolean;
}

export class RendererSecureStoreRevisions {
  private readonly endpoints = new Map<symbol, SendToWebview>();
  private readonly revisions = new Map<string, number>();
  private readonly slotTails = new Map<string, Promise<void>>();

  private slotKey(vaultId: string, kind: RendererSecureStoreKind): string {
    return `${vaultId}\u0000${kind}`;
  }

  registerEndpoint(sendToWebview: SendToWebview): () => void {
    const endpointId = Symbol("renderer-secure-store-endpoint");
    this.endpoints.set(endpointId, sendToWebview);
    return () => {
      this.endpoints.delete(endpointId);
    };
  }

  private invalidate(slot: string, kind: RendererSecureStoreKind): number {
    const revision = (this.revisions.get(slot) ?? 0) + 1;
    this.revisions.set(slot, revision);
    const event: RendererSecureStoreChangedEvent = { kind, revision };
    for (const [endpointId, sendToWebview] of this.endpoints) {
      try {
        sendToWebview("secureStoreChanged", event);
      } catch {
        // A renderer may close between registration and broadcast. The host
        // mutation has already completed, so a stale endpoint must not turn a
        // successful receipt-bearing response into an ambiguous failure.
        this.endpoints.delete(endpointId);
      }
    }
    return revision;
  }

  run<T extends object>(
    vaultId: string,
    kind: RendererSecureStoreKind,
    operation: () => Promise<T>,
    options: RevisionedOperationOptions<T>,
  ): Promise<T & { revision: number }> {
    return this.runWithRevision(vaultId, kind, () => operation(), options);
  }

  /** Execute while holding the slot revision lock and expose its exact epoch. */
  runWithRevision<T extends object>(
    vaultId: string,
    kind: RendererSecureStoreKind,
    operation: (revision: number) => Promise<T>,
    options: RevisionedOperationOptions<T>,
  ): Promise<T & { revision: number }> {
    const slot = this.slotKey(vaultId, kind);
    const predecessor = this.slotTails.get(slot) ?? Promise.resolve();
    const result = predecessor
      .catch(() => undefined)
      .then(async () => {
        let operationResult: T;
        try {
          operationResult = await operation(this.revisions.get(slot) ?? 0);
        } catch (error) {
          if (options.invalidatesOnError) this.invalidate(slot, kind);
          throw error;
        }
        let revision = this.revisions.get(slot) ?? 0;
        if (options.invalidates(operationResult)) {
          revision = this.invalidate(slot, kind);
        }
        return { ...operationResult, revision };
      });
    const tail = result.then(
      () => undefined,
      () => undefined,
    );
    this.slotTails.set(slot, tail);
    void tail.then(() => {
      if (this.slotTails.get(slot) === tail) {
        this.slotTails.delete(slot);
      }
    });
    return result;
  }
}

export const rendererSecureStoreRevisions = new RendererSecureStoreRevisions();
