/**
 * Crash-atomic host authority for the runtime connection's protected records.
 *
 * The renderer still owns validation and live-client publication, but it may
 * not acknowledge the individual secure-store receipts until this authority
 * has written the global commit decision. The write-ahead log is itself one
 * OS-protected secure-store value: registry, server, token, and every captured
 * predecessor therefore remain encrypted at rest.
 */

import { createHash, randomUUID } from "node:crypto";
import type {
  PlatformSecureStore,
  SecureStoreSecretKind,
} from "../../../src/security/platform-secure-store";
import type { RendererSecureStoreOwner } from "./renderer-secure-store-authority";

export type RendererConnectionTransactionKind =
  | "runtime.agent_profiles"
  | "runtime.active_server"
  | "session.steward_token";

export interface RendererConnectionTransactionParticipantInput {
  kind: RendererConnectionTransactionKind;
  value: string;
}

export interface RendererConnectionTransactionReceipt {
  kind: RendererConnectionTransactionKind;
  rollbackReceipt: string;
}

export interface RendererConnectionTransactionCompensationReceipt
  extends RendererConnectionTransactionReceipt {
  expectedRevision: number;
}

export type RendererConnectionTransactionAccess =
  | {
      kind: RendererConnectionTransactionKind;
      operation: "read" | "receipt" | "mutation";
    }
  | {
      kind: RendererConnectionTransactionKind;
      operation: "set";
      value: string;
    };

interface ConnectionTransactionParticipant {
  after: string | null;
  before: string | null;
  kind: RendererConnectionTransactionKind;
}

interface ConnectionTransactionWal {
  epoch: string;
  participants: ConnectionTransactionParticipant[];
  phase: "prepared" | "committed" | "aborting";
  transactionId: string;
  version: 1;
}

interface ConnectionTransactionWalEnvelope {
  digest: string;
  wal: ConnectionTransactionWal;
}

interface ActiveConnectionTransaction {
  mode: "forward" | "reverse";
  owner: RendererSecureStoreOwner;
  receipts: RendererConnectionTransactionReceipt[];
  revisions?: Array<{
    kind: RendererConnectionTransactionKind;
    revision: number;
  }>;
  sourceTransactionId?: string;
  wal: ConnectionTransactionWal;
}

interface CompletedConnectionTransaction {
  epoch: string;
  outcome: "aborted" | "committed" | "compensated";
  owner?: RendererSecureStoreOwner;
  receipts?: RendererConnectionTransactionReceipt[];
  revisions?: Array<{
    kind: RendererConnectionTransactionKind;
    revision: number;
  }>;
  wal?: ConnectionTransactionWal;
}

export type RendererConnectionTransactionStatus =
  | "prepared"
  | "committed"
  | "finished"
  | "aborted"
  | "compensating"
  | "compensated";

export interface RendererSecureStoreTransactionOptions {
  createEpoch?: () => string;
  completedCapacity?: number;
}

const WAL_KIND = "runtime.connection_txn" as const;
const TRANSACTION_KINDS = new Set<RendererConnectionTransactionKind>([
  "runtime.agent_profiles",
  "runtime.active_server",
  "session.steward_token",
]);
const DEFAULT_COMPLETED_CAPACITY = 128;

function canonicalWal(wal: ConnectionTransactionWal): string {
  return JSON.stringify(wal);
}

function walDigest(wal: ConnectionTransactionWal): string {
  return createHash("sha256").update(canonicalWal(wal)).digest("hex");
}

function encodeWal(wal: ConnectionTransactionWal): string {
  return JSON.stringify({ digest: walDigest(wal), wal });
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function parseWal(value: string): ConnectionTransactionWal {
  let envelope: ConnectionTransactionWalEnvelope;
  try {
    envelope = JSON.parse(value) as ConnectionTransactionWalEnvelope;
  } catch {
    throw new Error("Runtime connection transaction WAL is malformed.");
  }
  const wal = envelope?.wal;
  if (
    wal?.version !== 1 ||
    typeof wal.epoch !== "string" ||
    wal.epoch.length === 0 ||
    typeof wal.transactionId !== "string" ||
    wal.transactionId.length === 0 ||
    (wal.phase !== "prepared" &&
      wal.phase !== "committed" &&
      wal.phase !== "aborting") ||
    !Array.isArray(wal.participants) ||
    wal.participants.length === 0 ||
    wal.participants.length > TRANSACTION_KINDS.size ||
    envelope?.digest !== walDigest(wal)
  ) {
    throw new Error("Runtime connection transaction WAL failed validation.");
  }
  const kinds = new Set<RendererConnectionTransactionKind>();
  for (const participant of wal.participants) {
    if (
      !participant ||
      !TRANSACTION_KINDS.has(participant.kind) ||
      kinds.has(participant.kind) ||
      !isNullableString(participant.before) ||
      !isNullableString(participant.after)
    ) {
      throw new Error("Runtime connection transaction WAL failed validation.");
    }
    kinds.add(participant.kind);
  }
  return wal;
}

/** One host-global transaction is sufficient: every participant is host-global. */
export class RendererSecureStoreTransactionAuthority {
  private active: ActiveConnectionTransaction | null = null;
  private readonly completed = new Map<
    string,
    CompletedConnectionTransaction
  >();
  private readonly completedCapacity: number;
  private readonly createEpoch: () => string;
  /**
   * Transaction ids are capabilities scoped to one renderer owner. Keep their
   * tombstones for that owner's entire lifetime so eviction from the bounded
   * response-replay journal can never turn a delayed BEGIN into a new epoch.
   */
  private readonly completedIdsByOwner = new Map<
    RendererSecureStoreOwner,
    Set<string>
  >();
  private tail: Promise<void> = Promise.resolve();

  constructor(
    private readonly store: PlatformSecureStore,
    options: RendererSecureStoreTransactionOptions = {},
  ) {
    this.createEpoch =
      options.createEpoch ?? (() => `${Date.now()}:${randomUUID()}`);
    this.completedCapacity = Math.max(
      1,
      options.completedCapacity ?? DEFAULT_COMPLETED_CAPACITY,
    );
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.catch(() => undefined).then(operation);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private rememberCompleted(
    transactionId: string,
    completed: CompletedConnectionTransaction,
  ): void {
    if (completed.owner) {
      let ids = this.completedIdsByOwner.get(completed.owner);
      if (!ids) {
        ids = new Set();
        this.completedIdsByOwner.set(completed.owner, ids);
      }
      ids.add(transactionId);
    }
    this.completed.delete(transactionId);
    this.completed.set(transactionId, completed);
    while (this.completed.size > this.completedCapacity) {
      const oldest = this.completed.keys().next().value;
      if (typeof oldest !== "string") break;
      this.completed.delete(oldest);
    }
  }

  private ownerCompleted(
    owner: RendererSecureStoreOwner,
    transactionId: string,
  ): boolean {
    return this.completedIdsByOwner.get(owner)?.has(transactionId) === true;
  }

  private revokeFinishedCompensationForKind(
    kind: RendererConnectionTransactionKind,
  ): void {
    for (const completed of this.completed.values()) {
      if (
        completed.outcome !== "committed" ||
        !completed.wal?.participants.some(
          (participant) => participant.kind === kind,
        )
      ) {
        continue;
      }
      completed.wal = undefined;
      completed.receipts = undefined;
    }
  }

  private async readValue(
    vaultId: string,
    kind: SecureStoreSecretKind,
  ): Promise<string | null> {
    const result = await this.store.get(vaultId, kind);
    if (result.ok) return result.value;
    if (result.reason === "not_found") return null;
    throw new Error("Runtime connection secure-store read failed.");
  }

  private async writeValue(
    vaultId: string,
    kind: SecureStoreSecretKind,
    value: string | null,
  ): Promise<void> {
    try {
      if (value === null) await this.store.delete(vaultId, kind);
      else await this.store.set(vaultId, kind, value);
    } catch {
      // Native stores may mutate before reporting an error. Exact readback below
      // is the authority, not the acknowledgement.
    }
    if ((await this.readValue(vaultId, kind)) !== value) {
      throw new Error("Runtime connection secure-store write did not verify.");
    }
  }

  private async readWal(
    vaultId: string,
  ): Promise<ConnectionTransactionWal | null> {
    const value = await this.readValue(vaultId, WAL_KIND);
    return value === null ? null : parseWal(value);
  }

  private async writeWal(
    vaultId: string,
    wal: ConnectionTransactionWal,
  ): Promise<void> {
    const encoded = encodeWal(wal);
    await this.writeValue(vaultId, WAL_KIND, encoded);
    if ((await this.readValue(vaultId, WAL_KIND)) !== encoded) {
      throw new Error("Runtime connection transaction WAL did not verify.");
    }
  }

  private async clearWal(vaultId: string): Promise<void> {
    await this.writeValue(vaultId, WAL_KIND, null);
  }

  private async assertActiveWal(
    vaultId: string,
    active: ActiveConnectionTransaction,
  ): Promise<void> {
    const encoded = await this.readValue(vaultId, WAL_KIND);
    if (encoded !== encodeWal(active.wal)) {
      throw new Error("Runtime connection transaction WAL authority was lost.");
    }
  }

  /**
   * Reconcile only values that are still one of this WAL's exact endpoints.
   * An unexpected third value is a superseding authority and is never clobbered.
   */
  private async reconcileWal(
    vaultId: string,
    wal: ConnectionTransactionWal,
  ): Promise<RendererConnectionTransactionKind[]> {
    const targetField = wal.phase === "committed" ? "after" : "before";
    const snapshots = new Map<
      RendererConnectionTransactionKind,
      string | null
    >();
    for (const participant of wal.participants) {
      const current = await this.readValue(vaultId, participant.kind);
      if (current !== participant.before && current !== participant.after) {
        throw new Error(
          "Runtime connection transaction was superseded by an unknown value.",
        );
      }
      snapshots.set(participant.kind, current);
    }

    const changed: RendererConnectionTransactionKind[] = [];
    for (const participant of wal.participants) {
      const target = participant[targetField];
      if (snapshots.get(participant.kind) === target) continue;
      await this.writeValue(vaultId, participant.kind, target);
      changed.push(participant.kind);
    }
    await this.clearWal(vaultId);
    return changed;
  }

  private async reconcileOrphanedWal(
    vaultId: string,
  ): Promise<RendererConnectionTransactionKind[]> {
    const wal = await this.readWal(vaultId);
    if (!wal) return [];
    const changed = await this.reconcileWal(vaultId, wal);
    this.rememberCompleted(wal.transactionId, {
      epoch: wal.epoch,
      outcome: wal.phase === "committed" ? "committed" : "aborted",
    });
    // A committed WAL may contain bytes that were already written before the
    // process died, while their collective visibility revision was never
    // published. Invalidate every participant after recovery, not only bytes
    // that reconciliation happened to rewrite.
    // Visibility history is process-local and cannot be inferred from bytes:
    // an aborting WAL can already have published B before restoring A, and a
    // prepared WAL can have suppressed every SET revision. Conservatively
    // invalidate the complete participant set for every orphan recovery.
    void changed;
    return wal.participants.map((participant) => participant.kind);
  }

  /**
   * Gate every renderer secure-store operation. A transaction id is an exact
   * owner capability; a stale renderer cannot continue after B aborts A.
   * Even its owner may use it only for a declared participant and only for the
   * prepared SET value. This prevents unrelated credential writers from being
   * silently enlisted merely because they share the renderer document.
   */
  runAccess<T>(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    transactionId?: string,
    access?: RendererConnectionTransactionAccess,
    operation?: () => Promise<T>,
    allowCommittedReceiptReplay?: () => boolean,
    transactionEpoch?: string,
    publishRevisions?: (
      kinds: readonly RendererConnectionTransactionKind[],
    ) => Promise<unknown>,
  ): Promise<{
    changedKinds: RendererConnectionTransactionKind[];
    result: T | undefined;
  }> {
    return this.serialize(async () => {
      const active = this.active;
      if (active) {
        if (
          active.owner === owner &&
          active.mode === "forward" &&
          transactionId === active.wal.transactionId &&
          (transactionEpoch === undefined ||
            transactionEpoch === active.wal.epoch)
        ) {
          if (!access) {
            throw new Error(
              "Runtime connection transaction access is missing its participant.",
            );
          }
          const participant = active.wal.participants.find(
            (candidate) => candidate.kind === access.kind,
          );
          if (!participant) {
            throw new Error(
              "Runtime connection transaction access is not a participant.",
            );
          }
          if (
            access.operation === "receipt" ||
            access.operation === "mutation"
          ) {
            throw new Error(
              "Runtime connection transaction mutations are settled only by the coordinator.",
            );
          }
          if (access.operation === "set" && active.wal.phase !== "prepared") {
            throw new Error(
              "Runtime connection transaction no longer accepts participant SETs.",
            );
          }
          if (
            access.operation === "read" &&
            active.wal.phase !== "prepared" &&
            active.wal.phase !== "committed"
          ) {
            throw new Error(
              "Runtime connection transaction no longer permits participant reads.",
            );
          }
          if (
            access.operation === "set" &&
            access.value !== participant.after
          ) {
            throw new Error(
              "Runtime connection transaction SET does not match its prepared value.",
            );
          }
          await this.assertActiveWal(vaultId, active);
          return { changedKinds: [], result: await operation?.() };
        }
        // A response-lost generic COMMIT is an immutable read-like replay of
        // the predecessor that was already durable before this WAL began. It
        // remains retrievable without admitting a live receipt mutation or
        // exposing participant bytes staged by the active transaction.
        if (!transactionId && allowCommittedReceiptReplay?.() === true) {
          return { changedKinds: [], result: await operation?.() };
        }
        // Never let an unrelated renderer turn a transient invalidation into a
        // transaction abort. Participants stay invisible/fail-closed until the
        // owning document commits, aborts, or is released.
        throw new Error("Runtime connection transaction is in progress.");
      }

      const changed = await this.reconcileOrphanedWal(vaultId);
      if (changed.length > 0) await publishRevisions?.(changed);
      if (transactionId) {
        throw new Error("Runtime connection transaction is no longer active.");
      }
      if (
        access &&
        (access.operation === "set" ||
          access.operation === "receipt" ||
          access.operation === "mutation")
      ) {
        this.revokeFinishedCompensationForKind(access.kind);
      }
      return { changedKinds: changed, result: await operation?.() };
    });
  }

  beforeAccess(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    transactionId?: string,
    transactionEpoch?: string,
    publishRevisions?: (
      kinds: readonly RendererConnectionTransactionKind[],
    ) => Promise<unknown>,
  ): Promise<RendererConnectionTransactionKind[]> {
    return this.runAccess(
      vaultId,
      owner,
      transactionId,
      undefined,
      undefined,
      undefined,
      transactionEpoch,
      publishRevisions,
    ).then(({ changedKinds }) => changedKinds);
  }

  begin(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    transactionId: string,
    participants: readonly RendererConnectionTransactionParticipantInput[],
    assertCanBegin?: () => void,
  ): Promise<{ epoch: string }> {
    return this.serialize(async () => {
      if (
        this.completed.has(transactionId) ||
        this.ownerCompleted(owner, transactionId)
      ) {
        throw new Error(
          "Runtime connection transaction id was already completed.",
        );
      }
      if (this.active) {
        if (
          this.active.owner === owner &&
          this.active.mode === "forward" &&
          this.active.wal.transactionId === transactionId &&
          this.active.wal.phase === "prepared"
        ) {
          await this.assertActiveWal(vaultId, this.active);
          return { epoch: this.active.wal.epoch };
        }
        throw new Error("Runtime connection transaction is in progress.");
      } else {
        await this.reconcileOrphanedWal(vaultId);
      }

      // This callback deliberately runs under the same host-global tail used
      // by every renderer secure-store RPC. A check in the RPC handler would
      // leave a SET -> BEGIN TOCTOU window before the WAL captures `before`.
      assertCanBegin?.();

      if (
        participants.length === 0 ||
        participants.length > TRANSACTION_KINDS.size
      ) {
        throw new Error(
          "Runtime connection transaction participants are invalid.",
        );
      }
      const kinds = new Set<RendererConnectionTransactionKind>();
      const captured: ConnectionTransactionParticipant[] = [];
      for (const participant of participants) {
        if (
          !TRANSACTION_KINDS.has(participant.kind) ||
          kinds.has(participant.kind) ||
          typeof participant.value !== "string"
        ) {
          throw new Error(
            "Runtime connection transaction participants are invalid.",
          );
        }
        kinds.add(participant.kind);
        captured.push({
          after: participant.value,
          before: await this.readValue(vaultId, participant.kind),
          kind: participant.kind,
        });
      }

      // A finished transaction's reverse authority is valid only while every
      // participant remains untouched. BEGIN itself is a new mutation epoch:
      // even an eventually-aborted same-value transaction advances collective
      // revisions, so revoke overlapping reverse snapshots under this same
      // host-global tail before the new WAL can be installed.
      for (const kind of kinds) {
        this.revokeFinishedCompensationForKind(kind);
      }

      const wal: ConnectionTransactionWal = {
        epoch: this.createEpoch(),
        participants: captured,
        phase: "prepared",
        transactionId,
        version: 1,
      };
      await this.writeWal(vaultId, wal);
      this.active = { mode: "forward", owner, receipts: [], wal };
      return { epoch: wal.epoch };
    });
  }

  /** Add the token participant to the durable intent before its SET can run. */
  stage(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    transactionId: string,
    participant: RendererConnectionTransactionParticipantInput,
    epoch?: string,
  ): Promise<void> {
    return this.serialize(async () => {
      const active = this.active;
      if (
        active?.mode !== "forward" ||
        active.owner !== owner ||
        active.wal.transactionId !== transactionId ||
        (epoch !== undefined && active.wal.epoch !== epoch) ||
        active.wal.phase !== "prepared"
      ) {
        throw new Error("Runtime connection transaction is no longer active.");
      }
      if (!TRANSACTION_KINDS.has(participant.kind)) {
        throw new Error(
          "Runtime connection transaction participant is invalid.",
        );
      }
      await this.assertActiveWal(vaultId, active);
      const existing = active.wal.participants.find(
        (candidate) => candidate.kind === participant.kind,
      );
      if (existing) {
        if (existing.after !== participant.value) {
          throw new Error(
            "Runtime connection transaction participant changed after prepare.",
          );
        }
        return;
      }
      const next: ConnectionTransactionWal = {
        ...active.wal,
        participants: [
          ...active.wal.participants,
          {
            after: participant.value,
            before: await this.readValue(vaultId, participant.kind),
            kind: participant.kind,
          },
        ],
      };
      await this.writeWal(vaultId, next);
      active.wal = next;
    });
  }

  /**
   * The committed WAL write is the sole durable decision point. Receipt
   * acknowledgement and WAL deletion happen inside the same host serialization
   * window; a process death on either side is recovered from the WAL phase.
   */
  decideCommit(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    transactionId: string,
    receipts: readonly RendererConnectionTransactionReceipt[],
    commitReceipts: (
      receipts: readonly RendererConnectionTransactionReceipt[],
    ) => Promise<void>,
    epoch?: string,
    publishRevisions?: (
      kinds: readonly RendererConnectionTransactionKind[],
    ) => Promise<
      Array<{ kind: RendererConnectionTransactionKind; revision: number }>
    >,
  ): Promise<{
    committed: true;
    epoch: string;
    revisions: Array<{
      kind: RendererConnectionTransactionKind;
      revision: number;
    }>;
  }> {
    return this.serialize(async () => {
      const completed = this.completed.get(transactionId);
      if (
        completed?.owner === owner &&
        (epoch === undefined || completed.epoch === epoch) &&
        completed.outcome === "committed"
      ) {
        return {
          committed: true,
          epoch: completed.epoch,
          revisions: completed.revisions ?? [],
        };
      }
      if (completed) {
        throw new Error("Runtime connection transaction was already aborted.");
      }
      const active = this.active;
      if (
        active?.mode !== "forward" ||
        active.owner !== owner ||
        active.wal.transactionId !== transactionId ||
        (epoch !== undefined && active.wal.epoch !== epoch)
      ) {
        throw new Error("Runtime connection transaction is no longer active.");
      }
      await this.assertActiveWal(vaultId, active);
      if (active.wal.phase === "aborting") {
        // ABORT is a durable monotone decision. A delayed DECIDE carrying the
        // same owner/id/epoch must never turn an interrupted rollback back into
        // a committed successor.
        throw new Error("Runtime connection transaction is already aborting.");
      }

      const participantKinds = new Set(
        active.wal.participants.map((participant) => participant.kind),
      );
      const receiptKinds = new Set<RendererConnectionTransactionKind>();
      for (const receipt of receipts) {
        if (
          !participantKinds.has(receipt.kind) ||
          receiptKinds.has(receipt.kind) ||
          typeof receipt.rollbackReceipt !== "string" ||
          receipt.rollbackReceipt.length === 0
        ) {
          throw new Error(
            "Runtime connection transaction receipts are invalid.",
          );
        }
        receiptKinds.add(receipt.kind);
      }
      if (receiptKinds.size !== participantKinds.size) {
        throw new Error(
          "Runtime connection transaction receipts are incomplete.",
        );
      }
      for (const participant of active.wal.participants) {
        if (
          (await this.readValue(vaultId, participant.kind)) !==
          participant.after
        ) {
          throw new Error(
            "Runtime connection transaction participant did not verify.",
          );
        }
      }

      active.receipts = receipts.map((receipt) => ({ ...receipt }));
      if (active.wal.phase !== "committed") {
        const committedWal: ConnectionTransactionWal = {
          ...active.wal,
          phase: "committed",
        };
        await this.writeWal(vaultId, committedWal);
        active.wal = committedWal;
      }
      await commitReceipts(active.receipts);
      active.revisions ??=
        (await publishRevisions?.(
          active.wal.participants.map((participant) => participant.kind),
        )) ?? [];
      return {
        committed: true,
        epoch: active.wal.epoch,
        revisions: active.revisions.map((revision) => ({ ...revision })),
      };
    });
  }

  /** Clear the committed WAL only after every renderer finalizer has settled. */
  finishCommit(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    transactionId: string,
    epoch?: string,
  ): Promise<{ committed: true; epoch: string }> {
    return this.serialize(async () => {
      const completed = this.completed.get(transactionId);
      if (
        completed?.owner === owner &&
        (epoch === undefined || completed.epoch === epoch) &&
        completed.outcome === "committed"
      ) {
        return { committed: true, epoch: completed.epoch };
      }
      if (completed) {
        throw new Error("Runtime connection transaction was already aborted.");
      }
      const active = this.active;
      if (
        active?.mode !== "forward" ||
        active.owner !== owner ||
        active.wal.transactionId !== transactionId ||
        (epoch !== undefined && active.wal.epoch !== epoch) ||
        active.wal.phase !== "committed"
      ) {
        throw new Error("Runtime connection transaction is not committed.");
      }
      await this.assertActiveWal(vaultId, active);
      await this.clearWal(vaultId);
      this.rememberCompleted(transactionId, {
        epoch: active.wal.epoch,
        outcome: "committed",
        owner,
        receipts: active.receipts.map((receipt) => ({ ...receipt })),
        revisions: active.revisions?.map((revision) => ({ ...revision })),
        wal: {
          ...active.wal,
          participants: active.wal.participants.map((participant) => ({
            ...participant,
          })),
        },
      });
      this.active = null;
      return { committed: true, epoch: active.wal.epoch };
    });
  }

  abort(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    transactionId: string,
    receipts: readonly RendererConnectionTransactionReceipt[] = [],
    settleReceipts?: (
      receipts: readonly RendererConnectionTransactionReceipt[],
      participantKinds: readonly RendererConnectionTransactionKind[],
    ) => Promise<void>,
    epoch?: string,
    publishRevisions?: (
      kinds: readonly RendererConnectionTransactionKind[],
    ) => Promise<unknown>,
  ): Promise<{
    aborted: boolean;
    changedKinds: RendererConnectionTransactionKind[];
    committed: boolean;
  }> {
    return this.serialize(async () => {
      const completed = this.completed.get(transactionId);
      if (completed) {
        if (
          completed.owner !== owner ||
          (epoch !== undefined && completed.epoch !== epoch)
        ) {
          throw new Error("Runtime connection transaction epoch is stale.");
        }
        return {
          aborted: completed.outcome === "aborted",
          changedKinds: [],
          committed: completed.outcome === "committed",
        };
      }
      const active = this.active;
      if (
        active?.mode !== "forward" ||
        active.owner !== owner ||
        active.wal.transactionId !== transactionId ||
        (epoch !== undefined && active.wal.epoch !== epoch)
      ) {
        return { aborted: false, changedKinds: [], committed: false };
      }
      await this.assertActiveWal(vaultId, active);
      const participantKinds = new Set(
        active.wal.participants.map((participant) => participant.kind),
      );
      const receiptKinds = new Set<RendererConnectionTransactionKind>();
      for (const receipt of receipts) {
        if (
          !participantKinds.has(receipt.kind) ||
          receiptKinds.has(receipt.kind) ||
          typeof receipt.rollbackReceipt !== "string" ||
          receipt.rollbackReceipt.length === 0
        ) {
          throw new Error(
            "Runtime connection transaction abort receipts are invalid.",
          );
        }
        receiptKinds.add(receipt.kind);
      }
      if (active.receipts.length > 0) {
        const expected = new Map(
          active.receipts.map((receipt) => [
            receipt.kind,
            receipt.rollbackReceipt,
          ]),
        );
        if (
          receipts.length !== active.receipts.length ||
          receipts.some(
            (receipt) => expected.get(receipt.kind) !== receipt.rollbackReceipt,
          )
        ) {
          throw new Error(
            "Runtime connection transaction abort receipts changed.",
          );
        }
      } else {
        active.receipts = receipts.map((receipt) => ({ ...receipt }));
      }
      const abortingWal: ConnectionTransactionWal = {
        ...active.wal,
        phase: "aborting",
      };
      await this.writeWal(vaultId, abortingWal);
      active.wal = abortingWal;
      const changedKinds = await this.reconcileWalWithoutClear(
        vaultId,
        abortingWal,
      );
      await settleReceipts?.(
        active.receipts,
        active.wal.participants.map((participant) => participant.kind),
      );
      await publishRevisions?.(
        active.wal.participants.map((participant) => participant.kind),
      );
      await this.clearWal(vaultId);
      this.rememberCompleted(transactionId, {
        epoch: active.wal.epoch,
        outcome: "aborted",
        owner,
      });
      this.active = null;
      return {
        aborted: true,
        changedKinds,
        committed: false,
      };
    });
  }

  status(
    owner: RendererSecureStoreOwner,
    transactionId: string,
    epoch?: string,
  ): Promise<{
    epoch: string;
    revisions?: Array<{
      kind: RendererConnectionTransactionKind;
      revision: number;
    }>;
    status: RendererConnectionTransactionStatus;
  }> {
    return this.serialize(async () => {
      const active = this.active;
      if (
        active?.owner === owner &&
        (active.wal.transactionId === transactionId ||
          active.sourceTransactionId === transactionId) &&
        (epoch === undefined || active.wal.epoch === epoch)
      ) {
        return {
          epoch: active.wal.epoch,
          ...(active.revisions
            ? {
                revisions: active.revisions.map((revision) => ({
                  ...revision,
                })),
              }
            : {}),
          status:
            active.mode === "reverse"
              ? "compensating"
              : active.wal.phase === "committed"
                ? "committed"
                : "prepared",
        };
      }
      const completed = this.completed.get(transactionId);
      if (
        !completed ||
        completed.owner !== owner ||
        (epoch !== undefined && completed.epoch !== epoch)
      ) {
        throw new Error(
          "Runtime connection transaction status is unavailable.",
        );
      }
      return {
        epoch: completed.epoch,
        ...(completed.revisions
          ? {
              revisions: completed.revisions.map((revision) => ({
                ...revision,
              })),
            }
          : {}),
        status:
          completed.outcome === "committed" ? "finished" : completed.outcome,
      };
    });
  }

  /**
   * Reverse a globally finished connection through a second encrypted WAL.
   * All receipt compensations run while that WAL is prepared and revisions are
   * withheld. The reverse commit decision precedes one collective visibility
   * publication, so crashes recover either the entire successor or predecessor.
   */
  compensateFinishedCommit(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    transactionId: string,
    epoch: string,
    receipts: readonly RendererConnectionTransactionCompensationReceipt[],
    compensateReceipts: (
      receipts: readonly RendererConnectionTransactionCompensationReceipt[],
    ) => Promise<void>,
    publishRevisions: (
      kinds: readonly RendererConnectionTransactionKind[],
    ) => Promise<
      Array<{ kind: RendererConnectionTransactionKind; revision: number }>
    >,
  ): Promise<{
    compensated: true;
    revisions: Array<{
      kind: RendererConnectionTransactionKind;
      revision: number;
    }>;
  }> {
    return this.serialize(async () => {
      let completed = this.completed.get(transactionId);
      if (
        completed?.owner !== owner ||
        completed.epoch !== epoch ||
        (completed.outcome !== "committed" &&
          completed.outcome !== "compensated")
      ) {
        throw new Error(
          "Runtime connection transaction cannot be compensated.",
        );
      }
      if (completed.outcome === "compensated") {
        return {
          compensated: true,
          revisions:
            completed.revisions?.map((revision) => ({ ...revision })) ?? [],
        };
      }
      if (!completed.wal || !completed.receipts) {
        throw new Error("Runtime connection transaction compensation expired.");
      }
      const expected = new Map(
        completed.receipts.map((receipt) => [
          receipt.kind,
          receipt.rollbackReceipt,
        ]),
      );
      if (
        receipts.length !== expected.size ||
        receipts.some(
          (receipt) =>
            expected.get(receipt.kind) !== receipt.rollbackReceipt ||
            !Number.isSafeInteger(receipt.expectedRevision) ||
            receipt.expectedRevision < 0,
        )
      ) {
        throw new Error(
          "Runtime connection transaction compensation receipts are invalid.",
        );
      }

      let reverse = this.active;
      if (reverse) {
        if (
          reverse.mode !== "reverse" ||
          reverse.owner !== owner ||
          reverse.sourceTransactionId !== transactionId ||
          reverse.wal.epoch !== epoch
        ) {
          throw new Error("Runtime connection transaction is in progress.");
        }
        await this.assertActiveWal(vaultId, reverse);
      } else {
        const existingWal = await this.readWal(vaultId);
        if (existingWal) {
          throw new Error("Runtime connection transaction WAL is occupied.");
        }
        const reverseWal: ConnectionTransactionWal = {
          epoch,
          participants: completed.wal.participants.map((participant) => ({
            after: participant.before,
            before: participant.after,
            kind: participant.kind,
          })),
          phase: "prepared",
          transactionId: `${transactionId}:reverse`,
          version: 1,
        };
        // Validate every endpoint before creating the durable reverse intent.
        for (const participant of reverseWal.participants) {
          if (
            (await this.readValue(vaultId, participant.kind)) !==
            participant.before
          ) {
            throw new Error(
              "Runtime connection transaction successor was superseded.",
            );
          }
        }
        await this.writeWal(vaultId, reverseWal);
        reverse = {
          mode: "reverse",
          owner,
          receipts: completed.receipts.map((receipt) => ({ ...receipt })),
          sourceTransactionId: transactionId,
          wal: reverseWal,
        };
        this.active = reverse;
      }

      await compensateReceipts(receipts);
      for (const participant of reverse.wal.participants) {
        if (
          (await this.readValue(vaultId, participant.kind)) !==
          participant.after
        ) {
          throw new Error(
            "Runtime connection transaction compensation did not verify.",
          );
        }
      }
      const committedWal: ConnectionTransactionWal = {
        ...reverse.wal,
        phase: "committed",
      };
      await this.writeWal(vaultId, committedWal);
      reverse.wal = committedWal;
      const revisions = await publishRevisions(
        committedWal.participants.map((participant) => participant.kind),
      );
      await this.clearWal(vaultId);
      completed = {
        epoch,
        outcome: "compensated",
        owner,
        revisions: revisions.map((revision) => ({ ...revision })),
      };
      this.rememberCompleted(transactionId, completed);
      this.active = null;
      return { compensated: true, revisions };
    });
  }

  /** Settle an owner's durable transaction before normal receipt cleanup. */
  releaseOwner(
    vaultId: string,
    owner: RendererSecureStoreOwner,
    commitReceipts: (
      receipts: readonly RendererConnectionTransactionReceipt[],
    ) => Promise<void>,
    publishRevisions?: (
      kinds: readonly RendererConnectionTransactionKind[],
    ) => Promise<unknown>,
  ): Promise<RendererConnectionTransactionKind[]> {
    return this.serialize(async () => {
      const active = this.active;
      if (!active || active.owner !== owner) return [];
      await this.assertActiveWal(vaultId, active);
      if (active.mode === "reverse") {
        const originalTransactionId = active.sourceTransactionId;
        if (!originalTransactionId) {
          throw new Error("Runtime connection reverse transaction is invalid.");
        }
        if (active.wal.phase === "committed") {
          await this.reconcileWalWithoutClear(vaultId, active.wal);
          await publishRevisions?.(
            active.wal.participants.map((participant) => participant.kind),
          );
          await this.clearWal(vaultId);
          this.rememberCompleted(originalTransactionId, {
            epoch: active.wal.epoch,
            outcome: "compensated",
            owner,
          });
          this.active = null;
          return active.wal.participants.map((participant) => participant.kind);
        }
        const changed = await this.reconcileWal(vaultId, active.wal);
        if (changed.length > 0) await publishRevisions?.(changed);
        const prior = this.completed.get(originalTransactionId);
        this.rememberCompleted(originalTransactionId, {
          ...(prior ?? { epoch: active.wal.epoch }),
          outcome: "committed",
          owner,
        });
        this.active = null;
        return changed;
      }
      if (active.wal.phase === "committed") {
        await this.reconcileWalWithoutClear(vaultId, active.wal);
        await commitReceipts(active.receipts);
        await publishRevisions?.(
          active.wal.participants.map((participant) => participant.kind),
        );
        await this.clearWal(vaultId);
        this.rememberCompleted(active.wal.transactionId, {
          epoch: active.wal.epoch,
          outcome: "committed",
          owner,
        });
        this.active = null;
        // Participant SET revisions were intentionally withheld while the WAL
        // was prepared. Even when every byte is already `after`, owner release
        // is the first visibility boundary after a failed receipt/finalizer
        // path, so all participant leases must be invalidated together.
        return active.wal.participants.map((participant) => participant.kind);
      }
      const changed = await this.reconcileWal(vaultId, active.wal);
      if (changed.length > 0) await publishRevisions?.(changed);
      this.rememberCompleted(active.wal.transactionId, {
        epoch: active.wal.epoch,
        outcome: "aborted",
        owner,
      });
      this.active = null;
      return changed;
    });
  }

  forgetOwner(owner: RendererSecureStoreOwner): void {
    this.completedIdsByOwner.delete(owner);
  }

  private async reconcileWalWithoutClear(
    vaultId: string,
    wal: ConnectionTransactionWal,
  ): Promise<RendererConnectionTransactionKind[]> {
    const encoded = await this.readValue(vaultId, WAL_KIND);
    if (encoded === null || encoded !== encodeWal(wal)) {
      throw new Error("Runtime connection transaction WAL authority was lost.");
    }
    const snapshots = new Map<
      RendererConnectionTransactionKind,
      string | null
    >();
    const targetField = wal.phase === "committed" ? "after" : "before";
    for (const participant of wal.participants) {
      const current = await this.readValue(vaultId, participant.kind);
      if (current !== participant.before && current !== participant.after) {
        throw new Error(
          "Runtime connection transaction was superseded by an unknown value.",
        );
      }
      snapshots.set(participant.kind, current);
    }
    const changed: RendererConnectionTransactionKind[] = [];
    for (const participant of wal.participants) {
      const target = participant[targetField];
      if (snapshots.get(participant.kind) === target) continue;
      await this.writeValue(vaultId, participant.kind, target);
      changed.push(participant.kind);
    }
    return changed;
  }
}
