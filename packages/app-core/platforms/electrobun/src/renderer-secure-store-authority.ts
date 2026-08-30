/**
 * Serializes renderer access to each host secure-store slot. All Electrobun
 * renderer windows share one authority. Every successful set captures its
 * host-observed predecessor behind an opaque, revision-bound receipt so stale
 * or same-value ABA rollbacks cannot overwrite another renderer's mutation.
 */

import { randomUUID } from "node:crypto";
import type {
  PlatformSecureStore,
  SecureStoreDeleteResult,
  SecureStoreGetResult,
  SecureStoreSecretKind,
} from "../../../src/security/platform-secure-store";
import type {
  RendererSecureStoreCompareAndRestoreResult,
  RendererSecureStoreSetResult,
} from "./rpc-schema";

type SecureStoreOperationResult =
  | SecureStoreGetResult
  | SecureStoreDeleteResult
  | RendererSecureStoreSetResult
  | RendererSecureStoreCompareAndRestoreResult;

interface SlotRollbackAuthority {
  predecessor: string | null;
  receipt: string;
  revision: number;
}

interface SlotAuthorityState {
  revision: number;
  rollback: SlotRollbackAuthority | null;
}

const rollbackVerificationFailure = {
  ok: false,
  reason: "error",
  message: "Secure credential rollback could not be verified.",
} as const;

/**
 * Owns the host-global mutation order for renderer-visible credential slots.
 * Different vault/kind slots remain independent while every operation on one
 * slot observes a single total order.
 */
export class RendererSecureStoreAuthority {
  private readonly slotStates = new Map<string, SlotAuthorityState>();
  private readonly slotTails = new Map<string, Promise<void>>();

  constructor(
    private readonly store: PlatformSecureStore,
    private readonly createRollbackReceipt: () => string = randomUUID,
  ) {}

  private slotKey(vaultId: string, kind: SecureStoreSecretKind): string {
    return `${vaultId}\u0000${kind}`;
  }

  private stateFor(slot: string): SlotAuthorityState {
    const existing = this.slotStates.get(slot);
    if (existing) return existing;
    const created: SlotAuthorityState = { revision: 0, rollback: null };
    this.slotStates.set(slot, created);
    return created;
  }

  private serialize<T extends SecureStoreOperationResult>(
    vaultId: string,
    kind: SecureStoreSecretKind,
    operation: () => Promise<T>,
  ): Promise<T> {
    const slot = this.slotKey(vaultId, kind);
    const predecessor = this.slotTails.get(slot) ?? Promise.resolve();
    const result = predecessor.catch(() => undefined).then(operation);
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

  get(
    vaultId: string,
    kind: SecureStoreSecretKind,
  ): Promise<SecureStoreGetResult> {
    return this.serialize(vaultId, kind, () => this.store.get(vaultId, kind));
  }

  set(
    vaultId: string,
    kind: SecureStoreSecretKind,
    value: string,
  ): Promise<RendererSecureStoreSetResult> {
    return this.serialize(vaultId, kind, async () => {
      const predecessorResult = await this.store.get(vaultId, kind);
      let predecessor: string | null;
      if (predecessorResult.ok) {
        predecessor = predecessorResult.value;
      } else if (predecessorResult.reason === "not_found") {
        predecessor = null;
      } else {
        return predecessorResult;
      }

      const result = await this.store.set(vaultId, kind, value);
      if (!result.ok) return result;

      const state = this.stateFor(this.slotKey(vaultId, kind));
      state.revision += 1;
      const rollbackReceipt = this.createRollbackReceipt();
      state.rollback = {
        predecessor,
        receipt: rollbackReceipt,
        revision: state.revision,
      };
      return { ok: true, rollbackReceipt };
    });
  }

  delete(
    vaultId: string,
    kind: SecureStoreSecretKind,
  ): Promise<SecureStoreDeleteResult> {
    return this.serialize(vaultId, kind, async () => {
      const result = await this.store.delete(vaultId, kind);
      if (result.ok) {
        const state = this.stateFor(this.slotKey(vaultId, kind));
        state.revision += 1;
        state.rollback = null;
      }
      return result;
    });
  }

  compareAndRestore(
    vaultId: string,
    kind: SecureStoreSecretKind,
    rollbackReceipt: string,
  ): Promise<RendererSecureStoreCompareAndRestoreResult> {
    return this.serialize(vaultId, kind, async () => {
      const state = this.stateFor(this.slotKey(vaultId, kind));
      const rollback = state.rollback;
      if (
        !rollback ||
        rollback.receipt !== rollbackReceipt ||
        rollback.revision !== state.revision
      ) {
        const current = await this.store.get(vaultId, kind);
        if (!current.ok && current.reason === "not_found") {
          return { ok: true, restored: false, value: null };
        }
        return current.ok
          ? { ok: true, restored: false, value: current.value }
          : current;
      }

      if (rollback.predecessor === null) {
        const deletion = await this.store.delete(vaultId, kind);
        if (!deletion.ok) return deletion;
        const verified = await this.store.get(vaultId, kind);
        if (!verified.ok && verified.reason === "not_found") {
          state.revision += 1;
          state.rollback = null;
          return { ok: true, restored: true, value: null };
        }
        return verified.ok ? rollbackVerificationFailure : verified;
      }

      const restoration = await this.store.set(
        vaultId,
        kind,
        rollback.predecessor,
      );
      if (!restoration.ok) return restoration;
      const verified = await this.store.get(vaultId, kind);
      if (!verified.ok) return verified;
      if (verified.value !== rollback.predecessor) {
        return rollbackVerificationFailure;
      }
      state.revision += 1;
      state.rollback = null;
      return { ok: true, restored: true, value: rollback.predecessor };
    });
  }
}
