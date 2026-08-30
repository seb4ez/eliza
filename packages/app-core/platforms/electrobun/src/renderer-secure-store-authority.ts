/**
 * Host-global authority for renderer-visible secure-store mutations.
 *
 * Each endpoint owns its receipts. Logical SETs carry a renderer-generated
 * mutation id so a lost RPC response can be retried without writing the OS
 * credential store twice. Pending receipts are rolled back when their owner
 * endpoint closes.
 *
 * This authority is process-memory scoped. It closes renderer crashes,
 * transport loss, endpoint release, and orderly application shutdown, but an
 * uncatchable process/OS termination after the OS SET and before receipt commit
 * can still leave that SET durable. Making that window crash-atomic requires an
 * encrypted, fsync-backed intent/predecessor journal beside the platform store;
 * plaintext persistence of either value would be a worse security boundary.
 */

import { createHash, randomUUID } from "node:crypto";
import type {
  PlatformSecureStore,
  SecureStoreDeleteResult,
  SecureStoreGetResult,
  SecureStoreSecretKind,
  SecureStoreSetResult,
} from "../../../src/security/platform-secure-store";
import type {
  RendererSecureStoreCommitReceiptResult,
  RendererSecureStoreCompareAndDeleteResult,
  RendererSecureStoreCompareAndRestoreResult,
  RendererSecureStoreCompareAndSetResult,
  RendererSecureStoreCompensateCommittedReceiptResult,
  RendererSecureStoreSetResult,
} from "./rpc-schema";

export type RendererSecureStoreOwner = symbol;

interface SlotRollbackAuthority {
  cancelled: boolean;
  owner: RendererSecureStoreOwner;
  parentReceipt: string | null;
  predecessor: string | null;
  receipt: string;
  value: string;
}

interface SlotAuthorityState {
  currentReceipt: string | null;
  kind: SecureStoreSecretKind;
  rollbacks: Map<string, SlotRollbackAuthority>;
  vaultId: string;
}

interface SetJournalEntry {
  expiresAt: number;
  owner: RendererSecureStoreOwner;
  result: RendererSecureStoreSetResult;
  slot: string;
  valueFingerprint: string;
}

interface CommitJournalEntry {
  compensation: { predecessor: string | null; value: string } | null;
  compensationResult?: RendererSecureStoreCompensateCommittedReceiptResult;
  compensationRevision?: number;
  expiresAt: number;
  owner: RendererSecureStoreOwner;
  receipt: string;
  result: RendererSecureStoreCommitReceiptResult;
  slot: string;
}

interface DeleteJournalEntry {
  expectedRevision: number;
  expiresAt: number;
  owner: RendererSecureStoreOwner;
  result: RendererSecureStoreCompareAndDeleteResult;
  slot: string;
  valueFingerprint: string;
}

interface CompareSetJournalEntry {
  expectedRevision: number;
  expectedValueFingerprint: string;
  expiresAt: number;
  owner: RendererSecureStoreOwner;
  result: RendererSecureStoreCompareAndSetResult;
  slot: string;
  valueFingerprint: string;
}

export interface RendererSecureStoreAuthorityOptions {
  journalCapacity?: number;
  journalTtlMs?: number;
  maxPendingReceiptsPerSlot?: number;
  now?: () => number;
}

const DEFAULT_JOURNAL_CAPACITY = 512;
// A renderer may spend the full ten-minute Electrobun request budget on each
// of three commit retries. Keep the host answer for the entire retry sequence,
// plus one minute for WebView suspension and scheduling delay.
const DEFAULT_JOURNAL_TTL_MS = 31 * 60_000;
const DEFAULT_MAX_PENDING_RECEIPTS_PER_SLOT = 256;
const LIVE_SET_JOURNAL_WEIGHT = 2;
const defaultOwner = Symbol("renderer-secure-store-default-owner");

const rollbackVerificationFailure = {
  ok: false,
  reason: "error",
  message: "Secure credential rollback could not be verified.",
} as const;

const writeVerificationFailure = {
  ok: false,
  reason: "error",
  message: "Secure credential write could not be verified.",
} as const;

const releasedOwnerFailure = {
  ok: false,
  reason: "denied",
  message: "Secure credential endpoint is closed.",
} as const;

/** Owns the total order for every renderer-visible credential slot. */
export class RendererSecureStoreAuthority {
  private readonly activeOwnerOperations = new Map<
    RendererSecureStoreOwner,
    number
  >();
  private readonly commitJournal = new Map<string, CommitJournalEntry>();
  private readonly compareSetJournal = new Map<
    string,
    CompareSetJournalEntry
  >();
  private readonly deleteJournal = new Map<string, DeleteJournalEntry>();
  private readonly journalCapacity: number;
  private readonly journalTtlMs: number;
  private journalReservations = 0;
  private readonly maxPendingReceiptsPerSlot: number;
  private readonly mutationJournal = new Map<string, SetJournalEntry>();
  private readonly now: () => number;
  private nextOwnerId = 0;
  private readonly ownerIds = new Map<RendererSecureStoreOwner, number>();
  private readonly releasedOwners = new Set<RendererSecureStoreOwner>();
  private readonly slotStates = new Map<string, SlotAuthorityState>();
  private readonly slotTails = new Map<string, Promise<void>>();

  constructor(
    private readonly store: PlatformSecureStore,
    private readonly createRollbackReceipt: () => string = randomUUID,
    options: RendererSecureStoreAuthorityOptions = {},
  ) {
    this.journalCapacity = Math.max(
      1,
      options.journalCapacity ?? DEFAULT_JOURNAL_CAPACITY,
    );
    this.journalTtlMs = Math.max(
      1,
      options.journalTtlMs ?? DEFAULT_JOURNAL_TTL_MS,
    );
    this.maxPendingReceiptsPerSlot = Math.max(
      1,
      options.maxPendingReceiptsPerSlot ??
        DEFAULT_MAX_PENDING_RECEIPTS_PER_SLOT,
    );
    this.now = options.now ?? Date.now;
  }

  private slotKey(vaultId: string, kind: SecureStoreSecretKind): string {
    return `${vaultId}\u0000${kind}`;
  }

  private stateFor(
    slot: string,
    vaultId: string,
    kind: SecureStoreSecretKind,
  ): SlotAuthorityState {
    const existing = this.slotStates.get(slot);
    if (existing) return existing;
    const created: SlotAuthorityState = {
      currentReceipt: null,
      kind,
      rollbacks: new Map(),
      vaultId,
    };
    this.slotStates.set(slot, created);
    return created;
  }

  private serializeSlot<T>(
    slot: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    const predecessor = this.slotTails.get(slot) ?? Promise.resolve();
    const result = predecessor.catch(() => undefined).then(operation);
    const tail = result.then(
      () => undefined,
      () => undefined,
    );
    this.slotTails.set(slot, tail);
    void tail.then(() => {
      if (this.slotTails.get(slot) === tail) this.slotTails.delete(slot);
      this.pruneReleasedOwnerIdentities();
    });
    return result;
  }

  private serialize<T>(
    vaultId: string,
    kind: SecureStoreSecretKind,
    operation: () => Promise<T>,
  ): Promise<T> {
    return this.serializeSlot(this.slotKey(vaultId, kind), operation);
  }

  private ownerId(owner: RendererSecureStoreOwner): number {
    const existing = this.ownerIds.get(owner);
    if (existing !== undefined) return existing;
    this.nextOwnerId += 1;
    this.ownerIds.set(owner, this.nextOwnerId);
    return this.nextOwnerId;
  }

  private journalKey(
    operation: "set" | "commit" | "delete" | "compare-set",
    owner: RendererSecureStoreOwner,
    id: string,
  ): string {
    return `${operation}:${this.ownerId(owner)}:${id}`;
  }

  private pruneJournal(now = this.now()): void {
    for (const [key, entry] of this.mutationJournal) {
      if (entry.expiresAt <= now && !this.setJournalEntryIsLive(entry)) {
        this.mutationJournal.delete(key);
      }
    }
    for (const [key, entry] of this.commitJournal) {
      if (entry.expiresAt <= now) this.commitJournal.delete(key);
    }
    for (const [key, entry] of this.deleteJournal) {
      if (entry.expiresAt <= now) this.deleteJournal.delete(key);
    }
    for (const [key, entry] of this.compareSetJournal) {
      if (entry.expiresAt <= now) this.compareSetJournal.delete(key);
    }
  }

  private journalSize(): number {
    let size =
      this.commitJournal.size +
      this.deleteJournal.size +
      this.compareSetJournal.size;
    for (const entry of this.mutationJournal.values()) {
      size +=
        this.setJournalEntryIsLive(entry) &&
        !this.setJournalEntryHasCommitTombstone(entry)
          ? LIVE_SET_JOURNAL_WEIGHT
          : 1;
    }
    return size;
  }

  private setJournalEntryIsLive(entry: SetJournalEntry): boolean {
    const receipt = entry.result.rollbackReceipt;
    return Boolean(
      receipt && this.slotStates.get(entry.slot)?.rollbacks.has(receipt),
    );
  }

  private setJournalEntryHasCommitTombstone(entry: SetJournalEntry): boolean {
    const receipt = entry.result.rollbackReceipt;
    if (!receipt) return false;
    for (const commit of this.commitJournal.values()) {
      if (
        commit.owner === entry.owner &&
        commit.receipt === receipt &&
        commit.slot === entry.slot
      ) {
        return true;
      }
    }
    return false;
  }

  private reserveJournalEntry(weight = 1): boolean {
    this.pruneJournal();
    if (
      this.journalSize() + this.journalReservations + weight >
      this.journalCapacity
    ) {
      return false;
    }
    this.journalReservations += weight;
    return true;
  }

  private rememberSet(
    key: string,
    entry: Omit<SetJournalEntry, "expiresAt">,
  ): void {
    this.journalReservations = Math.max(
      0,
      this.journalReservations - LIVE_SET_JOURNAL_WEIGHT,
    );
    this.mutationJournal.set(key, {
      ...entry,
      expiresAt: this.now() + this.journalTtlMs,
    });
    this.pruneJournal();
  }

  private rememberCommit(
    key: string,
    entry: Omit<CommitJournalEntry, "expiresAt">,
  ): void {
    this.commitJournal.set(key, {
      ...entry,
      expiresAt: this.now() + this.journalTtlMs,
    });
    this.pruneJournal();
  }

  private rememberDelete(
    key: string,
    entry: Omit<DeleteJournalEntry, "expiresAt">,
  ): void {
    this.journalReservations = Math.max(0, this.journalReservations - 1);
    this.deleteJournal.set(key, {
      ...entry,
      expiresAt: this.now() + this.journalTtlMs,
    });
    this.pruneJournal();
  }

  private rememberCompareSet(
    key: string,
    entry: Omit<CompareSetJournalEntry, "expiresAt">,
  ): void {
    this.journalReservations = Math.max(0, this.journalReservations - 1);
    this.compareSetJournal.set(key, {
      ...entry,
      expiresAt: this.now() + this.journalTtlMs,
    });
    this.pruneJournal();
  }

  private valueFingerprint(value: string): string {
    return createHash("sha256").update(value).digest("hex");
  }

  private beginOwnerOperation(owner: RendererSecureStoreOwner): void {
    this.activeOwnerOperations.set(
      owner,
      (this.activeOwnerOperations.get(owner) ?? 0) + 1,
    );
  }

  private endOwnerOperation(owner: RendererSecureStoreOwner): void {
    const remaining = (this.activeOwnerOperations.get(owner) ?? 1) - 1;
    if (remaining > 0) {
      this.activeOwnerOperations.set(owner, remaining);
      return;
    }
    this.activeOwnerOperations.delete(owner);
    if (this.releasedOwners.has(owner)) this.forgetOwnerJournal(owner);
  }

  private ownerHasReceipts(owner: RendererSecureStoreOwner): boolean {
    for (const state of this.slotStates.values()) {
      for (const rollback of state.rollbacks.values()) {
        if (rollback.owner === owner) return true;
      }
    }
    return false;
  }

  private pruneReleasedOwnerIdentities(): void {
    for (const owner of this.releasedOwners) {
      if (
        !this.activeOwnerOperations.has(owner) &&
        !this.ownerHasReceipts(owner)
      ) {
        this.forgetOwnerJournal(owner);
      }
    }
  }

  private discardCurrentRollback(
    state: SlotAuthorityState,
    rollback: SlotRollbackAuthority,
  ): void {
    state.rollbacks.delete(rollback.receipt);
    if (state.currentReceipt === rollback.receipt) {
      state.currentReceipt = rollback.parentReceipt;
    }
  }

  /** Resolve past ancestors that have already lost publication authority. */
  private effectivePredecessor(
    state: SlotAuthorityState,
    rollback: SlotRollbackAuthority,
  ): {
    cancelledAncestors: string[];
    predecessor: string | null;
    parentReceipt: string | null;
  } {
    let predecessor = rollback.predecessor;
    let parentReceipt = rollback.parentReceipt;
    const cancelledAncestors: string[] = [];
    while (parentReceipt) {
      const parent = state.rollbacks.get(parentReceipt);
      if (!parent?.cancelled) break;
      cancelledAncestors.push(parent.receipt);
      predecessor = parent.predecessor;
      parentReceipt = parent.parentReceipt;
    }
    return { cancelledAncestors, predecessor, parentReceipt };
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
    owner: RendererSecureStoreOwner = defaultOwner,
    mutationId: string = randomUUID(),
  ): Promise<RendererSecureStoreSetResult> {
    const slot = this.slotKey(vaultId, kind);
    this.beginOwnerOperation(owner);
    return this.serializeSlot(
      slot,
      async (): Promise<RendererSecureStoreSetResult> => {
        this.pruneJournal();
        if (this.releasedOwners.has(owner)) {
          return { ...releasedOwnerFailure, changed: false };
        }
        const journalKey = this.journalKey("set", owner, mutationId);
        const valueFingerprint = this.valueFingerprint(value);
        const replay = this.mutationJournal.get(journalKey);
        if (replay) {
          if (
            replay.slot !== slot ||
            replay.valueFingerprint !== valueFingerprint
          ) {
            return {
              ok: false,
              reason: "error",
              message: "Secure credential mutation id was reused.",
            };
          }
          return { ...replay.result, changed: false };
        }
        if (!this.reserveJournalEntry(LIVE_SET_JOURNAL_WEIGHT)) {
          return {
            ok: false,
            reason: "unavailable",
            message: "Secure credential retry journal is full.",
            changed: false,
          };
        }
        const finish = (
          result: RendererSecureStoreSetResult,
        ): RendererSecureStoreSetResult => {
          const changedResult = { ...result, changed: true };
          this.rememberSet(journalKey, {
            owner,
            result: changedResult,
            slot,
            valueFingerprint,
          });
          return changedResult;
        };

        let predecessorResult: SecureStoreGetResult;
        try {
          predecessorResult = await this.store.get(vaultId, kind);
        } catch {
          return finish({
            ok: false,
            reason: "error",
            message: "Secure credential predecessor could not be read.",
          });
        }
        let predecessor: string | null;
        if (predecessorResult.ok) {
          predecessor = predecessorResult.value;
        } else if (predecessorResult.reason === "not_found") {
          predecessor = null;
        } else {
          return finish(predecessorResult);
        }
        if (this.releasedOwners.has(owner)) return finish(releasedOwnerFailure);

        const state = this.stateFor(slot, vaultId, kind);
        const currentRollback = state.currentReceipt
          ? state.rollbacks.get(state.currentReceipt)
          : null;
        if (currentRollback && currentRollback.value !== predecessor) {
          state.currentReceipt = null;
          state.rollbacks.clear();
        }
        if (state.rollbacks.size >= this.maxPendingReceiptsPerSlot) {
          const result = {
            ok: false,
            reason: "unavailable",
            message: "Too many pending secure credential mutations.",
          } as const;
          return finish(result);
        }

        // Register before awaiting the backend: it may mutate and then throw.
        const rollbackReceipt = this.createRollbackReceipt();
        const rollback: SlotRollbackAuthority = {
          cancelled: false,
          owner,
          parentReceipt: state.currentReceipt,
          predecessor,
          receipt: rollbackReceipt,
          value,
        };
        state.rollbacks.set(rollbackReceipt, rollback);
        state.currentReceipt = rollbackReceipt;

        let writeResult: SecureStoreSetResult;
        try {
          writeResult = await this.store.set(vaultId, kind, value);
        } catch {
          writeResult = {
            ok: false,
            reason: "error",
            message: "Secure credential backend write failed.",
          };
        }

        let verified: SecureStoreGetResult;
        try {
          verified = await this.store.get(vaultId, kind);
        } catch {
          verified = {
            ok: false,
            reason: "error",
            message: "Secure credential readback failed.",
          };
        }
        let result: RendererSecureStoreSetResult;
        if (verified.ok && verified.value === value) {
          // Readback is authoritative: mutate-then-error is a successful write.
          result = { ok: true, rollbackReceipt };
        } else if (verified.ok || verified.reason === "not_found") {
          const verifiedValue = verified.ok ? verified.value : null;
          if (verifiedValue === predecessor) {
            this.discardCurrentRollback(state, rollback);
          } else {
            // Never overwrite a value placed by an authority outside this chain.
            state.currentReceipt = null;
            state.rollbacks.clear();
          }
          result = writeResult.ok ? writeVerificationFailure : writeResult;
        } else {
          result = {
            ok: false,
            reason: verified.reason,
            message: verified.message,
            rollbackReceipt,
          };
        }

        return finish(result);
      },
    ).finally(() => this.endOwnerOperation(owner));
  }

  commitReceipt(
    vaultId: string,
    kind: SecureStoreSecretKind,
    rollbackReceipt: string,
    owner: RendererSecureStoreOwner = defaultOwner,
  ): Promise<RendererSecureStoreCommitReceiptResult> {
    const slot = this.slotKey(vaultId, kind);
    return this.serializeSlot(slot, async () => {
      this.pruneJournal();
      if (this.releasedOwners.has(owner)) return releasedOwnerFailure;
      const journalKey = this.journalKey("commit", owner, rollbackReceipt);
      const replay = this.commitJournal.get(journalKey);
      if (replay) {
        return replay.slot === slot
          ? replay.result
          : { ok: true, committed: false };
      }

      let result: RendererSecureStoreCommitReceiptResult;
      const state = this.stateFor(slot, vaultId, kind);
      const committed = state.rollbacks.get(rollbackReceipt);
      if (!committed || committed.owner !== owner || committed.cancelled) {
        // A receipt that belongs to another slot must not poison the correct
        // slot with a false replay tombstone. Unknown/released receipts do not
        // mutate authority and therefore need no response-loss journal entry.
        return { ok: true, committed: false };
      } else if (state.currentReceipt === rollbackReceipt) {
        const effective = this.effectivePredecessor(state, committed);
        state.currentReceipt = null;
        state.rollbacks.clear();
        result = { ok: true, committed: true };
        this.rememberCommit(journalKey, {
          compensation: {
            predecessor: effective.predecessor,
            value: committed.value,
          },
          owner,
          receipt: rollbackReceipt,
          result,
          slot,
        });
        return result;
      } else {
        // A newer renderer owns the slot. Cancel this ancestor so the current
        // child rolls back past it to the real predecessor.
        committed.cancelled = true;
        result = { ok: true, committed: false };
      }

      this.rememberCommit(journalKey, {
        compensation: null,
        owner,
        receipt: rollbackReceipt,
        result,
        slot,
      });
      return result;
    });
  }

  /**
   * Compensate a receipt that already committed only at the exact SET revision.
   * The revision lock is owned by RendererSecureStoreRevisions; accepting both
   * values here keeps response-loss replay inside the same receipt journal while
   * making A -> B -> A distinguishable from the original A write.
   */
  compensateCommittedReceipt(
    vaultId: string,
    kind: SecureStoreSecretKind,
    rollbackReceipt: string,
    expectedRevision: number,
    currentRevision: number,
    owner: RendererSecureStoreOwner = defaultOwner,
  ): Promise<RendererSecureStoreCompensateCommittedReceiptResult> {
    const slot = this.slotKey(vaultId, kind);
    return this.serializeSlot(
      slot,
      async (): Promise<RendererSecureStoreCompensateCommittedReceiptResult> => {
        this.pruneJournal();
        if (this.releasedOwners.has(owner)) return releasedOwnerFailure;
        const journalKey = this.journalKey("commit", owner, rollbackReceipt);
        const commit = this.commitJournal.get(journalKey);
        if (!commit || commit.slot !== slot || commit.owner !== owner) {
          const current = await this.store.get(vaultId, kind);
          if (!current.ok && current.reason === "not_found") {
            return { ok: true, restored: false, changed: false, value: null };
          }
          return current.ok
            ? {
                ok: true,
                restored: false,
                changed: false,
                value: current.value,
              }
            : current;
        }
        if (commit.compensationResult) {
          if (commit.compensationRevision === expectedRevision) {
            return commit.compensationResult.ok
              ? { ...commit.compensationResult, changed: false }
              : commit.compensationResult;
          }
          const current = await this.store.get(vaultId, kind);
          if (!current.ok && current.reason === "not_found") {
            return { ok: true, restored: false, changed: false, value: null };
          }
          return current.ok
            ? {
                ok: true,
                restored: false,
                changed: false,
                value: current.value,
              }
            : current;
        }
        if (
          !commit.result.ok ||
          !commit.result.committed ||
          !commit.compensation ||
          currentRevision !== expectedRevision
        ) {
          const current = await this.store.get(vaultId, kind);
          if (!current.ok && current.reason === "not_found") {
            return { ok: true, restored: false, changed: false, value: null };
          }
          return current.ok
            ? {
                ok: true,
                restored: false,
                changed: false,
                value: current.value,
              }
            : current;
        }

        const current = await this.store.get(vaultId, kind);
        if (!current.ok && current.reason === "not_found") {
          return { ok: true, restored: false, changed: false, value: null };
        }
        if (!current.ok) return current;
        if (current.value !== commit.compensation.value) {
          return {
            ok: true,
            restored: false,
            changed: false,
            value: current.value,
          };
        }
        if (this.releasedOwners.has(owner)) return releasedOwnerFailure;

        let result: RendererSecureStoreCompensateCommittedReceiptResult;
        if (commit.compensation.predecessor === null) {
          const deletion = await this.store.delete(vaultId, kind);
          const verified = await this.store.get(vaultId, kind);
          if (!verified.ok && verified.reason === "not_found") {
            result = { ok: true, restored: true, changed: true, value: null };
          } else if (!deletion.ok) {
            return deletion;
          } else {
            return verified.ok ? rollbackVerificationFailure : verified;
          }
        } else {
          const restoration = await this.store.set(
            vaultId,
            kind,
            commit.compensation.predecessor,
          );
          const verified = await this.store.get(vaultId, kind);
          if (
            verified.ok &&
            verified.value === commit.compensation.predecessor
          ) {
            result = {
              ok: true,
              restored: true,
              changed: true,
              value: commit.compensation.predecessor,
            };
          } else if (!restoration.ok) {
            return restoration;
          } else if (!verified.ok) {
            return verified;
          } else {
            return rollbackVerificationFailure;
          }
        }
        commit.compensationResult = result;
        commit.compensationRevision = expectedRevision;
        return result;
      },
    );
  }

  delete(
    vaultId: string,
    kind: SecureStoreSecretKind,
    owner: RendererSecureStoreOwner = defaultOwner,
  ): Promise<SecureStoreDeleteResult> {
    this.beginOwnerOperation(owner);
    return this.serialize(vaultId, kind, async () => {
      if (this.releasedOwners.has(owner)) return releasedOwnerFailure;
      const result = await this.store.delete(vaultId, kind);
      if (result.ok || result.reason === "not_found") {
        const state = this.stateFor(this.slotKey(vaultId, kind), vaultId, kind);
        state.currentReceipt = null;
        state.rollbacks.clear();
      }
      return result;
    }).finally(() => this.endOwnerOperation(owner));
  }

  /** Delete only the exact value + host revision observed by the renderer. */
  compareAndDelete(
    vaultId: string,
    kind: SecureStoreSecretKind,
    expectedValue: string | null,
    expectedRevision: number,
    currentRevision: number,
    owner: RendererSecureStoreOwner = defaultOwner,
    mutationId: string = randomUUID(),
  ): Promise<RendererSecureStoreCompareAndDeleteResult> {
    const slot = this.slotKey(vaultId, kind);
    this.beginOwnerOperation(owner);
    return this.serializeSlot(
      slot,
      async (): Promise<RendererSecureStoreCompareAndDeleteResult> => {
        this.pruneJournal();
        if (this.releasedOwners.has(owner)) return releasedOwnerFailure;
        const journalKey = this.journalKey("delete", owner, mutationId);
        const valueFingerprint = this.valueFingerprint(
          expectedValue === null ? "\u0000absent" : `\u0001${expectedValue}`,
        );
        const replay = this.deleteJournal.get(journalKey);
        if (replay) {
          if (
            replay.slot !== slot ||
            replay.expectedRevision !== expectedRevision ||
            replay.valueFingerprint !== valueFingerprint
          ) {
            return {
              ok: false,
              reason: "error",
              message: "Secure credential mutation id was reused.",
            };
          }
          return { ...replay.result, changed: false };
        }
        if (!this.reserveJournalEntry()) {
          return {
            ok: false,
            reason: "unavailable",
            message: "Secure credential retry journal is full.",
          };
        }
        const finish = (
          result: RendererSecureStoreCompareAndDeleteResult,
        ): RendererSecureStoreCompareAndDeleteResult => {
          const changedResult = result.ok
            ? result
            : { ...result, changed: true };
          this.rememberDelete(journalKey, {
            expectedRevision,
            owner,
            result: changedResult,
            slot,
            valueFingerprint,
          });
          return changedResult;
        };

        const current = await this.store.get(vaultId, kind);
        if (!current.ok && current.reason === "not_found") {
          return finish({
            ok: true,
            deleted:
              expectedValue === null && currentRevision === expectedRevision,
            changed: false,
            value: null,
          });
        }
        if (!current.ok) return finish(current);
        if (
          currentRevision !== expectedRevision ||
          current.value !== expectedValue
        ) {
          return finish({
            ok: true,
            deleted: false,
            changed: false,
            value: current.value,
          });
        }
        if (this.releasedOwners.has(owner)) {
          return finish(releasedOwnerFailure);
        }

        const deletion = await this.store.delete(vaultId, kind);
        const verified = await this.store.get(vaultId, kind);
        if (!verified.ok && verified.reason === "not_found") {
          const state = this.stateFor(
            this.slotKey(vaultId, kind),
            vaultId,
            kind,
          );
          state.currentReceipt = null;
          state.rollbacks.clear();
          return finish({
            ok: true,
            deleted: true,
            changed: true,
            value: null,
          });
        }
        if (!deletion.ok) return finish(deletion);
        return finish(verified.ok ? writeVerificationFailure : verified);
      },
    ).finally(() => this.endOwnerOperation(owner));
  }

  /** Atomically transform one exact revision without creating a rollback. */
  compareAndSet(
    vaultId: string,
    kind: SecureStoreSecretKind,
    expectedValue: string,
    value: string,
    expectedRevision: number,
    currentRevision: number,
    owner: RendererSecureStoreOwner = defaultOwner,
    mutationId: string = randomUUID(),
  ): Promise<RendererSecureStoreCompareAndSetResult> {
    const slot = this.slotKey(vaultId, kind);
    this.beginOwnerOperation(owner);
    return this.serializeSlot(
      slot,
      async (): Promise<RendererSecureStoreCompareAndSetResult> => {
        this.pruneJournal();
        if (this.releasedOwners.has(owner)) return releasedOwnerFailure;
        const journalKey = this.journalKey("compare-set", owner, mutationId);
        const expectedValueFingerprint = this.valueFingerprint(expectedValue);
        const valueFingerprint = this.valueFingerprint(value);
        const replay = this.compareSetJournal.get(journalKey);
        if (replay) {
          if (
            replay.slot !== slot ||
            replay.expectedRevision !== expectedRevision ||
            replay.expectedValueFingerprint !== expectedValueFingerprint ||
            replay.valueFingerprint !== valueFingerprint
          ) {
            return {
              ok: false,
              reason: "error",
              message: "Secure credential mutation id was reused.",
            };
          }
          return { ...replay.result, changed: false };
        }
        if (!this.reserveJournalEntry()) {
          return {
            ok: false,
            reason: "unavailable",
            message: "Secure credential retry journal is full.",
          };
        }
        const finish = (
          result: RendererSecureStoreCompareAndSetResult,
        ): RendererSecureStoreCompareAndSetResult => {
          const changedResult = result.ok
            ? result
            : { ...result, changed: true };
          this.rememberCompareSet(journalKey, {
            expectedRevision,
            expectedValueFingerprint,
            owner,
            result: changedResult,
            slot,
            valueFingerprint,
          });
          return changedResult;
        };

        let current: SecureStoreGetResult;
        try {
          current = await this.store.get(vaultId, kind);
        } catch {
          return finish({
            ok: false,
            reason: "error",
            message: "Secure credential snapshot could not be read.",
          });
        }
        if (!current.ok && current.reason === "not_found") {
          return finish({
            ok: true,
            applied: false,
            changed: false,
            value: null,
          });
        }
        if (!current.ok) return finish(current);
        if (
          currentRevision !== expectedRevision ||
          current.value !== expectedValue
        ) {
          return finish({
            ok: true,
            applied: false,
            changed: false,
            value: current.value,
          });
        }
        if (value === expectedValue) {
          return finish({
            ok: true,
            applied: true,
            changed: false,
            value,
          });
        }
        if (this.releasedOwners.has(owner)) {
          return finish(releasedOwnerFailure);
        }

        let write: SecureStoreSetResult;
        try {
          write = await this.store.set(vaultId, kind, value);
        } catch {
          write = {
            ok: false,
            reason: "error",
            message: "Secure credential backend write failed.",
          };
        }
        let verified: SecureStoreGetResult;
        try {
          verified = await this.store.get(vaultId, kind);
        } catch {
          verified = {
            ok: false,
            reason: "error",
            message: "Secure credential readback failed.",
          };
        }
        if (verified.ok && verified.value === value) {
          // This is a terminal transform: only a verified mutation acquires A.
          // A failed backend call that left A unchanged must retain its live
          // predecessor chain so endpoint cleanup can still roll A back.
          const state = this.stateFor(slot, vaultId, kind);
          state.currentReceipt = null;
          state.rollbacks.clear();
          return finish({
            ok: true,
            applied: true,
            changed: true,
            value,
          });
        }
        if (!write.ok) return finish(write);
        return finish(verified.ok ? writeVerificationFailure : verified);
      },
    ).finally(() => this.endOwnerOperation(owner));
  }

  private async compareAndRestoreUnlocked(
    state: SlotAuthorityState,
    rollbackReceipt: string,
    owner: RendererSecureStoreOwner,
  ): Promise<RendererSecureStoreCompareAndRestoreResult> {
    const { kind, vaultId } = state;
    const rollback = state.rollbacks.get(rollbackReceipt);
    if (!rollback || rollback.owner !== owner) {
      const current = await this.store.get(vaultId, kind);
      if (!current.ok && current.reason === "not_found") {
        return { ok: true, restored: false, value: null };
      }
      return current.ok
        ? { ok: true, restored: false, value: current.value }
        : current;
    }

    if (state.currentReceipt !== rollbackReceipt) {
      rollback.cancelled = true;
      const current = await this.store.get(vaultId, kind);
      if (!current.ok && current.reason === "not_found") {
        state.currentReceipt = null;
        state.rollbacks.clear();
        return { ok: true, restored: false, value: null };
      }
      return current.ok
        ? { ok: true, restored: false, value: current.value }
        : current;
    }

    const current = await this.store.get(vaultId, kind);
    if (!current.ok && current.reason === "not_found") {
      state.currentReceipt = null;
      state.rollbacks.clear();
      return { ok: true, restored: false, value: null };
    }
    if (!current.ok) return current;
    if (current.value !== rollback.value) {
      state.currentReceipt = null;
      state.rollbacks.clear();
      return { ok: true, restored: false, value: current.value };
    }

    const effective = this.effectivePredecessor(state, rollback);
    const predecessor = effective.predecessor;
    const parentReceipt = effective.parentReceipt;
    const consumedReceipts = [
      rollback.receipt,
      ...effective.cancelledAncestors,
    ];

    if (predecessor === null) {
      const deletion = await this.store.delete(vaultId, kind);
      const verified = await this.store.get(vaultId, kind);
      if (!verified.ok && verified.reason === "not_found") {
        for (const receipt of consumedReceipts) state.rollbacks.delete(receipt);
        state.currentReceipt = parentReceipt;
        return { ok: true, restored: true, value: null };
      }
      if (!deletion.ok) return deletion;
      return verified.ok ? rollbackVerificationFailure : verified;
    }

    const restoration = await this.store.set(vaultId, kind, predecessor);
    const verified = await this.store.get(vaultId, kind);
    if (verified.ok && verified.value === predecessor) {
      for (const receipt of consumedReceipts) state.rollbacks.delete(receipt);
      state.currentReceipt = parentReceipt;
      return { ok: true, restored: true, value: predecessor };
    }
    if (!restoration.ok) return restoration;
    if (!verified.ok) return verified;
    return rollbackVerificationFailure;
  }

  compareAndRestore(
    vaultId: string,
    kind: SecureStoreSecretKind,
    rollbackReceipt: string,
    owner: RendererSecureStoreOwner = defaultOwner,
  ): Promise<RendererSecureStoreCompareAndRestoreResult> {
    const slot = this.slotKey(vaultId, kind);
    return this.serializeSlot(slot, async () => {
      if (this.releasedOwners.has(owner)) return releasedOwnerFailure;
      return this.compareAndRestoreUnlocked(
        this.stateFor(slot, vaultId, kind),
        rollbackReceipt,
        owner,
      );
    });
  }

  /** Prevents a closing endpoint from starting or finalizing new mutations. */
  markOwnerReleased(owner: RendererSecureStoreOwner): void {
    this.releasedOwners.add(owner);
  }

  ownerSlots(
    owner: RendererSecureStoreOwner,
  ): Array<{ kind: SecureStoreSecretKind; vaultId: string }> {
    const slots: Array<{ kind: SecureStoreSecretKind; vaultId: string }> = [];
    for (const state of this.slotStates.values()) {
      if (
        Array.from(state.rollbacks.values()).some(
          (rollback) => rollback.owner === owner,
        )
      ) {
        slots.push({ kind: state.kind, vaultId: state.vaultId });
      }
    }
    return slots;
  }

  async releaseOwnerSlot(
    owner: RendererSecureStoreOwner,
    vaultId: string,
    kind: SecureStoreSecretKind,
  ): Promise<{ released: boolean }> {
    const slot = this.slotKey(vaultId, kind);
    return this.serializeSlot(slot, async () => {
      const state = this.stateFor(slot, vaultId, kind);
      let released = false;
      for (const rollback of state.rollbacks.values()) {
        if (
          rollback.owner === owner &&
          rollback.receipt !== state.currentReceipt
        ) {
          rollback.cancelled = true;
          released = true;
        }
      }

      while (state.currentReceipt) {
        const current = state.rollbacks.get(state.currentReceipt);
        if (!current || current.owner !== owner) break;
        released = true;
        let result = await this.compareAndRestoreUnlocked(
          state,
          current.receipt,
          owner,
        );
        if (!result.ok) {
          result = await this.compareAndRestoreUnlocked(
            state,
            current.receipt,
            owner,
          );
        }
        if (!result.ok) {
          throw new Error("Secure credential endpoint cleanup failed.");
        }
      }
      return { released };
    });
  }

  forgetOwnerJournal(owner: RendererSecureStoreOwner): void {
    for (const [key, entry] of this.mutationJournal) {
      if (entry.owner === owner) this.mutationJournal.delete(key);
    }
    for (const [key, entry] of this.commitJournal) {
      if (entry.owner === owner) this.commitJournal.delete(key);
    }
    for (const [key, entry] of this.deleteJournal) {
      if (entry.owner === owner) this.deleteJournal.delete(key);
    }
    for (const [key, entry] of this.compareSetJournal) {
      if (entry.owner === owner) this.compareSetJournal.delete(key);
    }
    if (
      !this.activeOwnerOperations.has(owner) &&
      !this.ownerHasReceipts(owner)
    ) {
      this.ownerIds.delete(owner);
      // Keep releasedOwners as a permanent process-lifetime deny tombstone.
      // Late closures still hold the symbol after every receipt and retry
      // journal entry drains; deleting it would silently re-authorize them.
    }
  }

  async releaseOwner(owner: RendererSecureStoreOwner): Promise<void> {
    this.markOwnerReleased(owner);
    const failures: unknown[] = [];
    for (const { kind, vaultId } of this.ownerSlots(owner)) {
      try {
        await this.releaseOwnerSlot(owner, vaultId, kind);
      } catch (error) {
        failures.push(error);
      }
    }
    this.forgetOwnerJournal(owner);
    if (failures.length > 0) {
      throw new AggregateError(
        failures,
        "One or more secure credential endpoint cleanups failed.",
      );
    }
  }
}
