// @vitest-environment jsdom

/**
 * Covers the storage bridge's platform routing for non-credential keys:
 * web passthrough, electrobun desktop secure-store reads/writes/removals,
 * native synced-key mirroring between localStorage and Capacitor
 * Preferences, registerSyncedKey, and sessionStorage isolation.
 * Harness is deterministic: the real bridge module runs against in-memory
 * stand-ins for the native-only Capacitor/desktop boundaries.
 */
import {
  configureStoredStewardTokenScope,
  STEWARD_SESSION_CHANGE_EVENT,
  STEWARD_TOKEN_KEY,
  STEWARD_TOKEN_SCOPE_KEY,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Captured before any test can install the storage-bridge proxy so
// assertions can observe the raw underlying store, bypassing interception.
const rawStorage = window.localStorage;
const rawGetItem = rawStorage.getItem.bind(rawStorage) as (
  key: string,
) => string | null;
const rawSetItem = rawStorage.setItem.bind(rawStorage) as (
  key: string,
  value: string,
) => void;

// Mutable knobs read inside hoisted vi.mock factories; the `mock` prefix is
// vitest's sanctioned way for factories to close over module-level state.
const mockRuntime = { native: false, electrobun: false };
const mockPreferences = new Map<string, string>();
const mockDesktopStore = new Map<string, string>();
const mockDesktopSecure = {
  available: true,
  abortOnSet: null as AbortController | null,
  connectionTransaction: null as null | {
    before: Map<string, string | null>;
    epoch: string;
    id: string;
    participants: Map<string, string>;
    phase: "prepared" | "committed";
    receipts?: Array<{ kind: string; rollbackReceipt: string }>;
  },
  completedConnectionTransaction: null as null | {
    before: Map<string, string | null>;
    epoch: string;
    id: string;
    participants: Map<string, string>;
    receipts: Array<{ kind: string; rollbackReceipt: string }>;
    status: "finished" | "aborted" | "compensated";
  },
  connectionTransactionCalls: [] as string[],
  connectionBeginResponseLossesRemaining: 0,
  connectionFinishResponseLossesRemaining: 0,
  connectionAbortResponseLossesRemaining: 0,
  connectionCompensateResponseLossesRemaining: 0,
  compareAndRestoreCalls: [] as Array<{
    kind: string;
    rollbackReceipt: string;
  }>,
  compareAndDeleteCalls: [] as Array<{
    expectedRevision: number;
    expectedValue: string | null;
    kind: string;
    mutationId: string;
  }>,
  compareAndDeleteHook: null as null | (() => Promise<void>),
  compareAndDeleteJournal: new Map<
    string,
    {
      ok: true;
      deleted: boolean;
      changed: boolean;
      value: string | null;
      revision: number;
    }
  >(),
  compareAndDeleteResponseLossesRemaining: 0,
  compareAndSetCalls: [] as Array<{
    expectedRevision: number;
    expectedValue: string;
    kind: string;
    mutationId: string;
    value: string;
  }>,
  compareAndSetHook: null as null | (() => Promise<void>),
  compareAndSetJournal: new Map<
    string,
    {
      ok: true;
      applied: boolean;
      changed: boolean;
      value: string | null;
      revision: number;
    }
  >(),
  compareAndSetResponseLossesRemaining: 0,
  compensateCommittedCalls: [] as Array<{
    expectedRevision: number;
    kind: string;
    rollbackReceipt: string;
  }>,
  committedCompensations: new Map<
    string,
    {
      predecessor: string | null;
      result?: {
        ok: true;
        restored: true;
        changed: boolean;
        value: string | null;
        revision: number;
      };
      revision: number;
      value: string;
    }
  >(),
  commitReceiptCalls: [] as Array<{
    kind: string;
    rollbackReceipt: string;
  }>,
  commitJournal: new Map<
    string,
    {
      ok: true;
      committed: boolean;
      revision: number;
      value?: string;
    }
  >(),
  commitResponseLossesRemaining: 0,
  changedListeners: new Set<(payload: unknown) => void>(),
  commitReceiptHook: null as null | ((kind: string) => Promise<void>),
  commitReceiptSettledHook: null as null | ((kind: string) => Promise<void>),
  failNextSetAfterMutation: false,
  loseNextCommitResponse: false,
  loseNextSetResponse: false,
  mutationJournal: new Map<
    string,
    | { ok: true; rollbackReceipt: string; revision: number }
    | {
        ok: false;
        reason: "unavailable";
        rollbackReceipt: string;
        revision: number;
      }
  >(),
  setBackendWrites: 0,
  setRequestCalls: [] as Array<{
    kind: string;
    mutationId: string;
    value: string;
  }>,
  receiptSequence: 0,
  revisionRequestCalls: [] as string[],
  rejectSets: false,
  failRemovals: false,
  getSnapshotStarted: null as null | (() => void),
  getSnapshotWait: null as Promise<void> | null,
  nextGetFailure: null as null | "not_found" | "throw" | "unavailable",
  revisions: new Map<string, number>(),
  rollbacks: new Map<
    string,
    {
      predecessor: string | null;
      receipt: string;
      revision: number;
    }
  >(),
};

function mockDesktopStewardToken(): string | null {
  const value = mockDesktopStore.get("session.steward_token");
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as { marker?: string; token?: string };
    if (
      parsed.marker === "eliza.steward-token.v1" &&
      typeof parsed.token === "string"
    ) {
      return parsed.token;
    }
  } catch {
    // Legacy fixtures intentionally remain plain strings.
  }
  return value;
}

vi.mock("@capacitor/core", () => ({
  Capacitor: {
    getPlatform: () => (mockRuntime.native ? "android" : "web"),
    isNativePlatform: () => mockRuntime.native,
  },
}));

vi.mock("@capacitor/preferences", () => ({
  Preferences: {
    get: async ({ key }: { key: string }) => ({
      value: mockPreferences.get(key) ?? null,
    }),
    set: async ({ key, value }: { key: string; value: string }) => {
      mockPreferences.set(key, value);
    },
    remove: async ({ key }: { key: string }) => {
      mockPreferences.delete(key);
    },
  },
}));

vi.mock("@elizaos/logger", () => ({
  logger: { error: () => undefined },
}));

vi.mock("../first-run/mobile-runtime-mode", () => ({
  MOBILE_RUNTIME_MODE_STORAGE_KEY: "eliza:mobile-runtime-mode",
}));

vi.mock("./electrobun-runtime", () => ({
  isElectrobunRuntime: () => mockRuntime.electrobun,
}));

vi.mock("./electrobun-rpc", () => ({
  desktopSecureStoreGet: async (
    kind: string,
    transactionId?: string,
    transactionEpoch?: string,
  ) => {
    const activeTransaction = mockDesktopSecure.connectionTransaction;
    if (
      activeTransaction &&
      (transactionId !== activeTransaction.id ||
        transactionEpoch !== activeTransaction.epoch)
    ) {
      throw new Error("mock runtime connection transaction is in progress");
    }
    const failure = mockDesktopSecure.nextGetFailure;
    mockDesktopSecure.nextGetFailure = null;
    if (failure === "throw") {
      throw new Error("deterministic secure-store readback transport failure");
    }
    if (failure === "unavailable") {
      return {
        ok: false as const,
        reason: "unavailable" as const,
        revision: mockDesktopSecure.revisions.get(kind) ?? 0,
      };
    }
    if (failure === "not_found") {
      return {
        ok: false as const,
        reason: "not_found" as const,
        revision: mockDesktopSecure.revisions.get(kind) ?? 0,
      };
    }
    if (!mockDesktopSecure.available) {
      return {
        ok: false as const,
        reason: "unavailable" as const,
        revision: mockDesktopSecure.revisions.get(kind) ?? 0,
      };
    }
    const snapshot = mockDesktopStore.has(kind)
      ? {
          ok: true as const,
          value: mockDesktopStore.get(kind),
          revision: mockDesktopSecure.revisions.get(kind) ?? 0,
        }
      : {
          ok: false as const,
          reason: "not_found" as const,
          revision: mockDesktopSecure.revisions.get(kind) ?? 0,
        };
    mockDesktopSecure.getSnapshotStarted?.();
    await mockDesktopSecure.getSnapshotWait;
    return snapshot;
  },
  desktopSecureStoreRevision: async (kind: string) => {
    mockDesktopSecure.revisionRequestCalls.push(kind);
    if (!mockDesktopSecure.available) return null;
    return {
      ok: true as const,
      revision: mockDesktopSecure.revisions.get(kind) ?? 0,
    };
  },
  desktopSecureStoreSet: async (
    kind: string,
    value: string,
    mutationId: string,
    transactionId?: string,
    transactionEpoch?: string,
  ) => {
    mockDesktopSecure.setRequestCalls.push({ kind, mutationId, value });
    const activeTransaction = mockDesktopSecure.connectionTransaction;
    if (activeTransaction) {
      if (
        transactionId !== activeTransaction.id ||
        transactionEpoch !== activeTransaction.epoch
      ) {
        throw new Error("mock runtime connection transaction is in progress");
      }
      if (activeTransaction.participants.get(kind) !== value) {
        throw new Error("mock secure-store SET is not a prepared participant");
      }
    } else if (transactionId) {
      throw new Error("mock runtime connection transaction is not active");
    }
    const journalKey = `${kind}:${mutationId}`;
    const replay = mockDesktopSecure.mutationJournal.get(journalKey);
    if (replay) return replay;
    if (mockDesktopSecure.rejectSets) {
      return { ok: false as const, reason: "denied" as const };
    }
    const predecessor = mockDesktopStore.get(kind) ?? null;
    mockDesktopSecure.setBackendWrites += 1;
    mockDesktopStore.set(kind, value);
    const revision =
      (mockDesktopSecure.revisions.get(kind) ?? 0) + (transactionId ? 0 : 1);
    mockDesktopSecure.revisions.set(kind, revision);
    if (!transactionId) {
      for (const listener of mockDesktopSecure.changedListeners) {
        listener({ kind, revision });
      }
    }
    mockDesktopSecure.receiptSequence += 1;
    const rollbackReceipt = `mock-receipt-${mockDesktopSecure.receiptSequence}`;
    mockDesktopSecure.rollbacks.set(kind, {
      predecessor,
      receipt: rollbackReceipt,
      revision,
    });
    mockDesktopSecure.abortOnSet?.abort();
    const response = mockDesktopSecure.failNextSetAfterMutation
      ? {
          ok: false as const,
          reason: "unavailable" as const,
          rollbackReceipt,
          revision,
        }
      : { ok: true as const, rollbackReceipt, revision };
    mockDesktopSecure.failNextSetAfterMutation = false;
    mockDesktopSecure.mutationJournal.set(journalKey, response);
    if (mockDesktopSecure.loseNextSetResponse) {
      mockDesktopSecure.loseNextSetResponse = false;
      throw new Error("deterministic lost SET response");
    }
    return response;
  },
  desktopSecureStoreDelete: async (kind: string) => {
    if (mockDesktopSecure.failRemovals) {
      return { ok: false as const, reason: "denied" as const };
    }
    mockDesktopStore.delete(kind);
    const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
    mockDesktopSecure.revisions.set(kind, revision);
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind, revision });
    }
    mockDesktopSecure.rollbacks.delete(kind);
    return { ok: true as const, revision };
  },
  desktopSecureStoreCompareAndDelete: async (
    kind: string,
    expectedValue: string | null,
    expectedRevision: number,
    mutationId: string,
  ) => {
    mockDesktopSecure.compareAndDeleteCalls.push({
      expectedRevision,
      expectedValue,
      kind,
      mutationId,
    });
    const journalKey = `${kind}:${mutationId}`;
    const replay = mockDesktopSecure.compareAndDeleteJournal.get(journalKey);
    if (replay) {
      if (mockDesktopSecure.compareAndDeleteResponseLossesRemaining > 0) {
        mockDesktopSecure.compareAndDeleteResponseLossesRemaining -= 1;
        throw new Error("deterministic lost CAS DELETE response");
      }
      const currentRevision = mockDesktopSecure.revisions.get(kind) ?? 0;
      const currentValue = mockDesktopStore.get(kind) ?? null;
      return replay.revision === currentRevision &&
        replay.value === currentValue
        ? { ...replay, changed: false }
        : {
            ok: true as const,
            deleted: false,
            changed: false,
            value: currentValue,
            revision: currentRevision,
          };
    }
    await mockDesktopSecure.compareAndDeleteHook?.();
    const currentValue = mockDesktopStore.get(kind) ?? null;
    const currentRevision = mockDesktopSecure.revisions.get(kind) ?? 0;
    if (currentValue === null) {
      const response = {
        ok: true as const,
        deleted: expectedValue === null && currentRevision === expectedRevision,
        changed: false,
        value: null,
        revision: currentRevision,
      };
      mockDesktopSecure.compareAndDeleteJournal.set(journalKey, response);
      return response;
    }
    if (
      currentRevision !== expectedRevision ||
      currentValue !== expectedValue
    ) {
      const response = {
        ok: true as const,
        deleted: false,
        changed: false,
        value: currentValue,
        revision: currentRevision,
      };
      mockDesktopSecure.compareAndDeleteJournal.set(journalKey, response);
      return response;
    }
    mockDesktopStore.delete(kind);
    const revision = currentRevision + 1;
    mockDesktopSecure.revisions.set(kind, revision);
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind, revision });
    }
    const response = {
      ok: true as const,
      deleted: true,
      changed: true,
      value: null,
      revision,
    };
    mockDesktopSecure.compareAndDeleteJournal.set(journalKey, response);
    if (mockDesktopSecure.compareAndDeleteResponseLossesRemaining > 0) {
      mockDesktopSecure.compareAndDeleteResponseLossesRemaining -= 1;
      throw new Error("deterministic lost CAS DELETE response");
    }
    return response;
  },
  desktopSecureStoreCompareAndSet: async (
    kind: string,
    expectedValue: string,
    value: string,
    expectedRevision: number,
    mutationId: string,
  ) => {
    mockDesktopSecure.compareAndSetCalls.push({
      expectedRevision,
      expectedValue,
      kind,
      mutationId,
      value,
    });
    const replay = mockDesktopSecure.compareAndSetJournal.get(mutationId);
    if (replay) {
      if (mockDesktopSecure.compareAndSetResponseLossesRemaining > 0) {
        mockDesktopSecure.compareAndSetResponseLossesRemaining -= 1;
        throw new Error("lost compare-and-set replay response");
      }
      const currentRevision = mockDesktopSecure.revisions.get(kind) ?? 0;
      const currentValue = mockDesktopStore.get(kind) ?? null;
      return replay.revision === currentRevision &&
        replay.value === currentValue
        ? { ...replay, changed: false }
        : {
            ok: true as const,
            applied: false,
            changed: false,
            value: currentValue,
            revision: currentRevision,
          };
    }
    await mockDesktopSecure.compareAndSetHook?.();
    const currentRevision = mockDesktopSecure.revisions.get(kind) ?? 0;
    const currentValue = mockDesktopStore.get(kind) ?? null;
    if (
      currentRevision !== expectedRevision ||
      currentValue !== expectedValue
    ) {
      const result = {
        ok: true as const,
        applied: false,
        changed: false,
        value: currentValue,
        revision: currentRevision,
      };
      mockDesktopSecure.compareAndSetJournal.set(mutationId, result);
      return result;
    }
    mockDesktopStore.set(kind, value);
    const revision = currentRevision + 1;
    mockDesktopSecure.revisions.set(kind, revision);
    mockDesktopSecure.rollbacks.delete(kind);
    const result = {
      ok: true as const,
      applied: true,
      changed: true,
      value,
      revision,
    };
    mockDesktopSecure.compareAndSetJournal.set(mutationId, result);
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind, revision });
    }
    if (mockDesktopSecure.compareAndSetResponseLossesRemaining > 0) {
      mockDesktopSecure.compareAndSetResponseLossesRemaining -= 1;
      throw new Error("lost compare-and-set response");
    }
    return result;
  },
  desktopSecureStoreCommitReceipt: async (
    kind: string,
    rollbackReceipt: string,
    expectedRevision: number,
  ) => {
    mockDesktopSecure.commitReceiptCalls.push({ kind, rollbackReceipt });
    const journalKey = `${kind}:${rollbackReceipt}`;
    const replay = mockDesktopSecure.commitJournal.get(journalKey);
    if (replay) {
      if (mockDesktopSecure.commitResponseLossesRemaining > 0) {
        mockDesktopSecure.commitResponseLossesRemaining -= 1;
        throw new Error("deterministic lost COMMIT response");
      }
      return replay.committed
        ? {
            ...replay,
            publishable:
              (mockDesktopSecure.revisions.get(kind) ?? 0) === expectedRevision,
            revision:
              (mockDesktopSecure.revisions.get(kind) ?? 0) === expectedRevision
                ? expectedRevision
                : replay.revision,
          }
        : replay;
    }
    await mockDesktopSecure.commitReceiptHook?.(kind);
    const rollback = mockDesktopSecure.rollbacks.get(kind);
    let response: {
      ok: true;
      committed: boolean;
      revision: number;
      value?: string;
    };
    if (
      !rollback ||
      rollback.receipt !== rollbackReceipt ||
      (mockDesktopSecure.revisions.get(kind) ?? 0) !== expectedRevision
    ) {
      response = {
        ok: true as const,
        committed: false,
        revision: mockDesktopSecure.revisions.get(kind) ?? 0,
      };
    } else {
      mockDesktopSecure.committedCompensations.set(journalKey, {
        predecessor: rollback.predecessor,
        revision: rollback.revision,
        value: mockDesktopStore.get(kind) ?? "",
      });
      mockDesktopSecure.rollbacks.delete(kind);
      response = {
        ok: true as const,
        committed: true,
        revision: mockDesktopSecure.revisions.get(kind) ?? 0,
        value: mockDesktopStore.get(kind) ?? "",
      };
    }
    mockDesktopSecure.commitJournal.set(journalKey, response);
    await mockDesktopSecure.commitReceiptSettledHook?.(kind);
    if (mockDesktopSecure.commitResponseLossesRemaining > 0) {
      mockDesktopSecure.commitResponseLossesRemaining -= 1;
      throw new Error("deterministic lost COMMIT response");
    }
    if (mockDesktopSecure.loseNextCommitResponse) {
      mockDesktopSecure.loseNextCommitResponse = false;
      throw new Error("deterministic lost COMMIT response");
    }
    return response;
  },
  desktopSecureStoreCompensateCommittedReceipt: async (
    kind: string,
    rollbackReceipt: string,
    expectedRevision: number,
  ) => {
    mockDesktopSecure.compensateCommittedCalls.push({
      expectedRevision,
      kind,
      rollbackReceipt,
    });
    const journalKey = `${kind}:${rollbackReceipt}`;
    const compensation =
      mockDesktopSecure.committedCompensations.get(journalKey);
    if (compensation?.result) {
      const currentRevision = mockDesktopSecure.revisions.get(kind) ?? 0;
      const currentValue = mockDesktopStore.get(kind) ?? null;
      return compensation.result.revision === currentRevision &&
        compensation.result.value === currentValue
        ? { ...compensation.result, changed: false }
        : {
            ok: true as const,
            restored: false,
            changed: false,
            value: currentValue,
            revision: currentRevision,
          };
    }
    const currentValue = mockDesktopStore.get(kind) ?? null;
    if (
      !compensation ||
      compensation.revision !== expectedRevision ||
      mockDesktopSecure.revisions.get(kind) !== expectedRevision ||
      currentValue !== compensation.value
    ) {
      return {
        ok: true as const,
        restored: false,
        changed: false,
        value: currentValue,
        revision: mockDesktopSecure.revisions.get(kind) ?? 0,
      };
    }
    if (compensation.predecessor === null) {
      mockDesktopStore.delete(kind);
    } else {
      mockDesktopStore.set(kind, compensation.predecessor);
    }
    const revision = expectedRevision + 1;
    mockDesktopSecure.revisions.set(kind, revision);
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind, revision });
    }
    const result = {
      ok: true as const,
      restored: true as const,
      changed: true,
      value: compensation.predecessor,
      revision,
    };
    compensation.result = result;
    return result;
  },
  desktopSecureStoreCompareAndRestore: async (
    kind: string,
    rollbackReceipt: string,
  ) => {
    mockDesktopSecure.compareAndRestoreCalls.push({
      kind,
      rollbackReceipt,
    });
    const rollback = mockDesktopSecure.rollbacks.get(kind);
    const currentValue = mockDesktopStore.get(kind) ?? null;
    if (
      !rollback ||
      rollback.receipt !== rollbackReceipt ||
      rollback.revision !== mockDesktopSecure.revisions.get(kind)
    ) {
      const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
      mockDesktopSecure.revisions.set(kind, revision);
      for (const listener of mockDesktopSecure.changedListeners) {
        listener({ kind, revision });
      }
      return {
        ok: true as const,
        restored: false,
        value: currentValue,
        revision,
      };
    }
    if (rollback.predecessor === null) {
      mockDesktopStore.delete(kind);
    } else {
      mockDesktopStore.set(kind, rollback.predecessor);
    }
    mockDesktopSecure.revisions.set(kind, rollback.revision + 1);
    const revision = rollback.revision + 1;
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind, revision });
    }
    mockDesktopSecure.rollbacks.delete(kind);
    return {
      ok: true as const,
      restored: true,
      value: rollback.predecessor,
      revision,
    };
  },
  desktopConnectionTransactionBegin: async (
    transactionId: string,
    participants: Array<{ kind: string; value: string }>,
  ) => {
    mockDesktopSecure.connectionTransactionCalls.push("begin");
    const existing = mockDesktopSecure.connectionTransaction;
    if (existing && existing.id !== transactionId) {
      throw new Error("mock transaction is already active");
    }
    mockDesktopSecure.connectionTransaction ??= {
      before: new Map(
        participants.map(({ kind }) => [
          kind,
          mockDesktopStore.get(kind) ?? null,
        ]),
      ),
      epoch: "mock-epoch",
      id: transactionId,
      participants: new Map(
        participants.map(({ kind, value }) => [kind, value]),
      ),
      phase: "prepared",
    };
    if (mockDesktopSecure.connectionBeginResponseLossesRemaining > 0) {
      mockDesktopSecure.connectionBeginResponseLossesRemaining -= 1;
      throw new Error("deterministic lost BEGIN response");
    }
    return { ok: true as const, epoch: "mock-epoch" };
  },
  desktopConnectionTransactionStage: async (
    transactionId: string,
    epoch: string,
    participant: { kind: string; value: string },
  ) => {
    const transaction = mockDesktopSecure.connectionTransaction;
    if (
      !transaction ||
      transaction.id !== transactionId ||
      transaction.epoch !== epoch
    ) {
      throw new Error("mock transaction is not active");
    }
    mockDesktopSecure.connectionTransactionCalls.push(
      `stage:${participant.kind}`,
    );
    transaction.before.set(
      participant.kind,
      mockDesktopStore.get(participant.kind) ?? null,
    );
    transaction.participants.set(participant.kind, participant.value);
    return { ok: true as const };
  },
  desktopConnectionTransactionDecide: async (
    transactionId: string,
    epoch: string,
    receipts: Array<{ kind: string; rollbackReceipt: string }>,
  ) => {
    const transaction = mockDesktopSecure.connectionTransaction;
    if (
      !transaction ||
      transaction.id !== transactionId ||
      transaction.epoch !== epoch
    ) {
      throw new Error("mock transaction is not active");
    }
    mockDesktopSecure.connectionTransactionCalls.push("decide");
    const revisions: Array<{ kind: string; revision: number }> = [];
    for (const { kind, rollbackReceipt } of receipts) {
      const rollback = mockDesktopSecure.rollbacks.get(kind);
      if (!rollback || rollback.receipt !== rollbackReceipt) {
        throw new Error("mock transaction receipt is invalid");
      }
      const journalKey = `${kind}:${rollbackReceipt}`;
      const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
      mockDesktopSecure.revisions.set(kind, revision);
      mockDesktopSecure.committedCompensations.set(journalKey, {
        predecessor: rollback.predecessor,
        revision,
        value: mockDesktopStore.get(kind) ?? "",
      });
      mockDesktopSecure.commitJournal.set(journalKey, {
        ok: true,
        committed: true,
        revision,
        value: mockDesktopStore.get(kind) ?? "",
      });
      mockDesktopSecure.rollbacks.delete(kind);
      revisions.push({ kind, revision });
      for (const listener of mockDesktopSecure.changedListeners) {
        listener({ kind, revision });
      }
    }
    transaction.phase = "committed";
    transaction.receipts = receipts.map((receipt) => ({ ...receipt }));
    return {
      ok: true as const,
      committed: true as const,
      epoch: "mock-epoch",
      revisions,
    };
  },
  desktopConnectionTransactionFinish: async (
    transactionId: string,
    epoch: string,
  ) => {
    const transaction = mockDesktopSecure.connectionTransaction;
    const completed = mockDesktopSecure.completedConnectionTransaction;
    if (
      !transaction &&
      completed?.id === transactionId &&
      completed.epoch === epoch &&
      completed.status === "finished"
    ) {
      if (mockDesktopSecure.connectionFinishResponseLossesRemaining > 0) {
        mockDesktopSecure.connectionFinishResponseLossesRemaining -= 1;
        throw new Error("deterministic lost FINISH response");
      }
      return {
        ok: true as const,
        committed: true as const,
        epoch: completed.epoch,
      };
    }
    if (
      !transaction ||
      transaction.id !== transactionId ||
      transaction.epoch !== epoch ||
      transaction.phase !== "committed"
    ) {
      throw new Error("mock transaction is not committed");
    }
    mockDesktopSecure.connectionTransactionCalls.push("finish");
    mockDesktopSecure.completedConnectionTransaction = {
      before: new Map(transaction.before),
      epoch: transaction.epoch,
      id: transaction.id,
      participants: new Map(transaction.participants),
      receipts: transaction.receipts?.map((receipt) => ({ ...receipt })) ?? [],
      status: "finished",
    };
    mockDesktopSecure.connectionTransaction = null;
    if (mockDesktopSecure.connectionFinishResponseLossesRemaining > 0) {
      mockDesktopSecure.connectionFinishResponseLossesRemaining -= 1;
      throw new Error("deterministic lost FINISH response");
    }
    return { ok: true as const, committed: true as const, epoch: "mock-epoch" };
  },
  desktopConnectionTransactionAbort: async (
    transactionId: string,
    epoch: string,
    receipts: Array<{ kind: string; rollbackReceipt: string }>,
  ) => {
    const transaction = mockDesktopSecure.connectionTransaction;
    const completed = mockDesktopSecure.completedConnectionTransaction;
    if (
      !transaction &&
      completed?.id === transactionId &&
      completed.epoch === epoch &&
      completed.status === "aborted"
    ) {
      if (mockDesktopSecure.connectionAbortResponseLossesRemaining > 0) {
        mockDesktopSecure.connectionAbortResponseLossesRemaining -= 1;
        throw new Error("deterministic lost ABORT response");
      }
      return { ok: true as const, aborted: true, committed: false };
    }
    if (
      !transaction ||
      transaction.id !== transactionId ||
      transaction.epoch !== epoch
    ) {
      throw new Error("mock transaction is not active");
    }
    mockDesktopSecure.connectionTransactionCalls.push("abort");
    for (const [kind, before] of transaction.before) {
      const current = mockDesktopStore.get(kind) ?? null;
      if (before === null) mockDesktopStore.delete(kind);
      else mockDesktopStore.set(kind, before);
      const receipt = receipts.find((candidate) => candidate.kind === kind);
      const rollback = mockDesktopSecure.rollbacks.get(kind);
      if (receipt && rollback?.receipt === receipt.rollbackReceipt) {
        mockDesktopSecure.rollbacks.delete(kind);
      }
      if (current !== before) {
        const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
        mockDesktopSecure.revisions.set(kind, revision);
        for (const listener of mockDesktopSecure.changedListeners) {
          listener({ kind, revision });
        }
      }
    }
    mockDesktopSecure.completedConnectionTransaction = {
      before: new Map(transaction.before),
      epoch: transaction.epoch,
      id: transaction.id,
      participants: new Map(transaction.participants),
      receipts: receipts.map((receipt) => ({ ...receipt })),
      status: "aborted",
    };
    mockDesktopSecure.connectionTransaction = null;
    if (mockDesktopSecure.connectionAbortResponseLossesRemaining > 0) {
      mockDesktopSecure.connectionAbortResponseLossesRemaining -= 1;
      throw new Error("deterministic lost ABORT response");
    }
    return { ok: true as const, aborted: true, committed: false };
  },
  desktopConnectionTransactionStatus: async (
    transactionId: string,
    epoch?: string,
  ) => {
    const active = mockDesktopSecure.connectionTransaction;
    if (
      active?.id === transactionId &&
      (epoch === undefined || active.epoch === epoch)
    ) {
      return {
        ok: true as const,
        epoch: active.epoch,
        status: active.phase,
      };
    }
    const completed = mockDesktopSecure.completedConnectionTransaction;
    if (
      completed?.id === transactionId &&
      (epoch === undefined || completed.epoch === epoch)
    ) {
      return {
        ok: true as const,
        epoch: completed.epoch,
        revisions: Array.from(completed.participants.keys(), (kind) => ({
          kind,
          revision: mockDesktopSecure.revisions.get(kind) ?? 0,
        })),
        status: completed.status,
      };
    }
    throw new Error("mock transaction status is unavailable");
  },
  desktopConnectionTransactionCompensate: async (
    transactionId: string,
    epoch: string,
    receipts: Array<{
      expectedRevision: number;
      kind: string;
      rollbackReceipt: string;
    }>,
  ) => {
    const completed = mockDesktopSecure.completedConnectionTransaction;
    if (
      !completed ||
      completed.id !== transactionId ||
      completed.epoch !== epoch ||
      (completed.status !== "finished" && completed.status !== "compensated")
    ) {
      throw new Error("mock transaction cannot be compensated");
    }
    if (completed.status === "compensated") {
      const replay = {
        ok: true as const,
        compensated: true as const,
        revisions: receipts.map(({ kind }) => ({
          kind,
          revision: mockDesktopSecure.revisions.get(kind) ?? 0,
        })),
      };
      if (mockDesktopSecure.connectionCompensateResponseLossesRemaining > 0) {
        mockDesktopSecure.connectionCompensateResponseLossesRemaining -= 1;
        throw new Error("deterministic lost COMPENSATE response");
      }
      return replay;
    }
    mockDesktopSecure.connectionTransactionCalls.push("compensate");
    const revisions: Array<{ kind: string; revision: number }> = [];
    for (const receipt of receipts) {
      const expectedReceipt = completed.receipts.find(
        (candidate) => candidate.kind === receipt.kind,
      );
      if (
        expectedReceipt?.rollbackReceipt !== receipt.rollbackReceipt ||
        mockDesktopSecure.revisions.get(receipt.kind) !==
          receipt.expectedRevision
      ) {
        throw new Error("mock compensation receipt is stale");
      }
    }
    for (const [kind, before] of completed.before) {
      if (before === null) mockDesktopStore.delete(kind);
      else mockDesktopStore.set(kind, before);
      const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
      mockDesktopSecure.revisions.set(kind, revision);
      revisions.push({ kind, revision });
      for (const listener of mockDesktopSecure.changedListeners) {
        listener({ kind, revision });
      }
    }
    completed.status = "compensated";
    const result = {
      ok: true as const,
      compensated: true as const,
      revisions,
    };
    if (mockDesktopSecure.connectionCompensateResponseLossesRemaining > 0) {
      mockDesktopSecure.connectionCompensateResponseLossesRemaining -= 1;
      throw new Error("deterministic lost COMPENSATE response");
    }
    return result;
  },
  subscribeDesktopBridgeEvent: (options: {
    rpcMessage: string;
    listener: (payload: unknown) => void;
  }) => {
    if (options.rpcMessage !== "secureStoreChanged") return () => {};
    mockDesktopSecure.changedListeners.add(options.listener);
    return () => {
      mockDesktopSecure.changedListeners.delete(options.listener);
    };
  },
}));

vi.mock("../surface-realm-channel", () => ({
  runAsPrivilegedShell: (operation: () => unknown) => operation(),
}));

// The bridge keeps module-singleton state (proxy install flag, caches), so
// the module is imported exactly once and sections below progress the
// runtime knobs monotonically: web -> electrobun -> native.
let bridge: typeof import("./storage-bridge");

// Deferred native writes are scheduled with setTimeout(0); give them a macrotask.
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

beforeAll(async () => {
  bridge = await import("./storage-bridge");
});

beforeEach(() => {
  mockPreferences.clear();
  mockDesktopStore.clear();
  mockDesktopSecure.available = true;
  mockDesktopSecure.abortOnSet = null;
  mockDesktopSecure.connectionTransaction = null;
  mockDesktopSecure.completedConnectionTransaction = null;
  mockDesktopSecure.connectionTransactionCalls.length = 0;
  mockDesktopSecure.connectionBeginResponseLossesRemaining = 0;
  mockDesktopSecure.connectionFinishResponseLossesRemaining = 0;
  mockDesktopSecure.connectionAbortResponseLossesRemaining = 0;
  mockDesktopSecure.connectionCompensateResponseLossesRemaining = 0;
  mockDesktopSecure.compareAndRestoreCalls.length = 0;
  mockDesktopSecure.compareAndDeleteCalls.length = 0;
  mockDesktopSecure.compareAndDeleteHook = null;
  mockDesktopSecure.compareAndDeleteJournal.clear();
  mockDesktopSecure.compareAndDeleteResponseLossesRemaining = 0;
  mockDesktopSecure.compareAndSetCalls.length = 0;
  mockDesktopSecure.compareAndSetHook = null;
  mockDesktopSecure.compareAndSetJournal.clear();
  mockDesktopSecure.compareAndSetResponseLossesRemaining = 0;
  mockDesktopSecure.compensateCommittedCalls.length = 0;
  mockDesktopSecure.committedCompensations.clear();
  mockDesktopSecure.commitReceiptCalls.length = 0;
  mockDesktopSecure.commitJournal.clear();
  mockDesktopSecure.commitResponseLossesRemaining = 0;
  mockDesktopSecure.commitReceiptHook = null;
  mockDesktopSecure.commitReceiptSettledHook = null;
  mockDesktopSecure.failNextSetAfterMutation = false;
  mockDesktopSecure.loseNextCommitResponse = false;
  mockDesktopSecure.loseNextSetResponse = false;
  mockDesktopSecure.mutationJournal.clear();
  mockDesktopSecure.receiptSequence = 0;
  mockDesktopSecure.revisionRequestCalls.length = 0;
  mockDesktopSecure.rejectSets = false;
  mockDesktopSecure.failRemovals = false;
  mockDesktopSecure.getSnapshotStarted = null;
  mockDesktopSecure.getSnapshotWait = null;
  mockDesktopSecure.nextGetFailure = null;
  mockDesktopSecure.rollbacks.clear();
  mockDesktopSecure.setBackendWrites = 0;
  mockDesktopSecure.setRequestCalls.length = 0;
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe("storage bridge on the web runtime", () => {
  it("skips initialization entirely", async () => {
    rawSetItem("eliza.web.sentinel", "untouched");
    await bridge.initializeStorageBridge();
    expect(bridge.isStorageBridgeInitialized()).toBe(false);
    expect(rawGetItem("eliza.web.sentinel")).toBe("untouched");
  });

  it("round-trips values through localStorage alone", async () => {
    await bridge.setStorageValue("eliza.web.plain", "value-one");
    expect(rawGetItem("eliza.web.plain")).toBe("value-one");
    expect(await bridge.getStorageValue("eliza.web.plain")).toBe("value-one");

    await bridge.removeStorageValue("eliza.web.plain");
    expect(rawGetItem("eliza.web.plain")).toBeNull();
    expect(await bridge.getStorageValue("eliza.web.plain")).toBeNull();
  });

  it("removes a missing key without throwing", async () => {
    await expect(
      bridge.removeStorageValue("eliza.web.never-written"),
    ).resolves.toBeUndefined();
  });

  it("keeps an acquired web terminal removal successful after authority changes", async () => {
    const key = "eliza.web.terminal-token";
    rawSetItem(key, "expired-a");
    let checks = 0;

    await expect(
      bridge.removeStorageValueIfCurrent(key, "expired-a", {
        validate: () => {
          checks += 1;
          return checks < 3;
        },
      }),
    ).resolves.toBe(true);

    expect(rawGetItem(key)).toBeNull();
  });

  it("keeps registered keys local even after registerSyncedKey", async () => {
    bridge.registerSyncedKey("eliza.test.web-registered");
    await bridge.setStorageValue("eliza.test.web-registered", "local-only");
    expect(window.localStorage.getItem("eliza.test.web-registered")).toBe(
      "local-only",
    );
    await settle();
    expect(mockPreferences.size).toBe(0);
  });
});

describe("storage bridge on the electrobun desktop runtime", () => {
  beforeAll(() => {
    mockRuntime.electrobun = true;
  });

  it("initializes immediately because no cold native plugin must warm up", async () => {
    await bridge.initializeStorageBridge();
    expect(bridge.isStorageBridgeInitialized()).toBe(true);
  });

  it("makes the global WAL decision before Steward finalization and publishes the three caches together", async () => {
    await bridge.setStorageValue("elizaos:agent-profiles", "registry-a");
    await bridge.setStorageValue("elizaos:active-server", "server-a");
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "token-a");
    mockDesktopSecure.commitReceiptCalls.length = 0;
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key: "elizaos:agent-profiles", value: "registry-b" },
      { key: "elizaos:active-server", value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");

    await bridge.setStorageValueWithCompensation(
      "elizaos:agent-profiles",
      "registry-b",
      { runtimeConnectionTransaction: transaction },
    );
    await bridge.setStorageValueWithCompensation(
      "elizaos:active-server",
      "server-b",
      { runtimeConnectionTransaction: transaction },
    );
    // Participant SETs are host-private until the collective decision.
    expect(window.localStorage.getItem("elizaos:agent-profiles")).toBe(
      "registry-a",
    );
    expect(window.localStorage.getItem("elizaos:active-server")).toBe(
      "server-a",
    );

    await writeStoredStewardToken("token-b", {
      hostPersistenceContext: transaction,
      finalizeBeforePublish: () => {
        expect(mockDesktopSecure.connectionTransactionCalls).toEqual([
          "begin",
          "stage:session.steward_token",
          "decide",
        ]);
        expect(window.localStorage.getItem("elizaos:agent-profiles")).toBe(
          "registry-b",
        );
        expect(window.localStorage.getItem("elizaos:active-server")).toBe(
          "server-b",
        );
        expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-b");
      },
    });
    await bridge.finishRuntimeConnectionStorageTransaction(transaction);

    expect(mockDesktopSecure.connectionTransactionCalls).toEqual([
      "begin",
      "stage:session.steward_token",
      "decide",
      "finish",
    ]);
    expect(mockDesktopSecure.commitReceiptCalls).toEqual([]);
  });

  it("recovers the prepared epoch when every BEGIN response is lost", async () => {
    mockDesktopSecure.connectionBeginResponseLossesRemaining = 3;
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key: "elizaos:active-server", value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not recovered");
    expect(mockDesktopSecure.connectionTransaction?.phase).toBe("prepared");
    await expect(
      bridge.abortRuntimeConnectionStorageTransaction(transaction),
    ).resolves.toBe(true);
    expect(mockDesktopSecure.connectionTransaction).toBeNull();
  });

  it("uses status to settle an ABORT whose every response was lost", async () => {
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key: "elizaos:active-server", value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");
    mockDesktopSecure.connectionAbortResponseLossesRemaining = 3;
    await expect(
      bridge.abortRuntimeConnectionStorageTransaction(transaction),
    ).resolves.toBe(true);

    const next = await bridge.beginRuntimeConnectionStorageTransaction([
      { key: "elizaos:active-server", value: "server-c" },
    ]);
    if (!next) throw new Error("next transaction was blocked");
    await bridge.abortRuntimeConnectionStorageTransaction(next);
  });

  it("treats a status-confirmed lost FINISH as globally sealed", async () => {
    const key = "elizaos:active-server";
    await bridge.setStorageValue(key, "server-a");
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key, value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");
    const compensation = await bridge.setStorageValueWithCompensation(
      key,
      "server-b",
      { runtimeConnectionTransaction: transaction },
    );
    if (!compensation) throw new Error("compensation was not captured");
    await bridge.decideRuntimeConnectionStorageTransaction(transaction);
    mockDesktopSecure.connectionFinishResponseLossesRemaining = 3;
    await expect(
      bridge.finishRuntimeConnectionStorageTransaction(transaction),
    ).resolves.toBeUndefined();

    await expect(compensation.compensate()).resolves.toBe(true);
    expect(mockDesktopSecure.connectionTransactionCalls).toContain(
      "compensate",
    );
    expect(mockDesktopStore.get("runtime.active_server")).toBe("server-a");
  });

  it("uses status to publish the predecessor after every COMPENSATE response is lost", async () => {
    const key = "elizaos:active-server";
    await bridge.setStorageValue(key, "server-a");
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key, value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");
    const compensation = await bridge.setStorageValueWithCompensation(
      key,
      "server-b",
      { runtimeConnectionTransaction: transaction },
    );
    if (!compensation) throw new Error("compensation was not captured");
    await bridge.decideRuntimeConnectionStorageTransaction(transaction);
    await bridge.finishRuntimeConnectionStorageTransaction(transaction);

    mockDesktopSecure.connectionCompensateResponseLossesRemaining = 3;
    await expect(compensation.compensate()).resolves.toBe(true);

    expect(mockDesktopStore.get("runtime.active_server")).toBe("server-a");
    await expect(bridge.getStorageValue(key)).resolves.toBe("server-a");
    expect(window.localStorage.getItem(key)).toBe("server-a");
  });

  it("revokes reverse authority when a participant mutation starts after finish", async () => {
    const key = "elizaos:active-server";
    await bridge.setStorageValue(key, "server-a");
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key, value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");
    const compensation = await bridge.setStorageValueWithCompensation(
      key,
      "server-b",
      { runtimeConnectionTransaction: transaction },
    );
    if (!compensation) throw new Error("compensation was not captured");
    await bridge.decideRuntimeConnectionStorageTransaction(transaction);
    await bridge.finishRuntimeConnectionStorageTransaction(transaction);

    await bridge.setStorageValue(key, "server-c");
    await expect(compensation.compensate()).resolves.toBe(false);
    expect(mockDesktopStore.get("runtime.active_server")).toBe("server-c");
  });

  it("records aborting and restores every participant when Steward finalization throws", async () => {
    await bridge.setStorageValue("elizaos:agent-profiles", "registry-a");
    await bridge.setStorageValue("elizaos:active-server", "server-a");
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "token-a");
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key: "elizaos:agent-profiles", value: "registry-b" },
      { key: "elizaos:active-server", value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");
    await bridge.setStorageValueWithCompensation(
      "elizaos:agent-profiles",
      "registry-b",
      { runtimeConnectionTransaction: transaction },
    );
    await bridge.setStorageValueWithCompensation(
      "elizaos:active-server",
      "server-b",
      { runtimeConnectionTransaction: transaction },
    );

    await expect(
      writeStoredStewardToken("token-b", {
        hostPersistenceContext: transaction,
        finalizeBeforePublish: () => {
          expect(mockDesktopSecure.connectionTransactionCalls.at(-1)).toBe(
            "decide",
          );
          throw new Error("injected finalizer failure");
        },
      }),
    ).rejects.toThrow("injected finalizer failure");

    expect(mockDesktopSecure.connectionTransactionCalls).toEqual([
      "begin",
      "stage:session.steward_token",
      "decide",
      "abort",
    ]);
    expect(mockDesktopSecure.compareAndRestoreCalls).toEqual([]);
    expect(mockDesktopStore.get("runtime.agent_profiles")).toBe("registry-a");
    expect(mockDesktopStore.get("runtime.active_server")).toBe("server-a");
    expect(mockDesktopStewardToken()).toBe("token-a");
    expect(window.localStorage.getItem("elizaos:agent-profiles")).toBe(
      "registry-a",
    );
    expect(window.localStorage.getItem("elizaos:active-server")).toBe(
      "server-a",
    );
    expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-a");
  });

  it("pairs a legacy predecessor scope before committed abort can expose it", async () => {
    configureStoredStewardTokenScope("https://api.eliza.app");
    mockDesktopStore.set("session.steward_token", "legacy-token-a");
    rawSetItem(STEWARD_TOKEN_SCOPE_KEY, "eliza-cloud:production");
    await expect(bridge.getStorageValue(STEWARD_TOKEN_KEY)).resolves.toBe(
      "legacy-token-a",
    );
    configureStoredStewardTokenScope("https://api-staging.eliza.app");

    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key: "elizaos:agent-profiles", value: "registry-b" },
      { key: "elizaos:active-server", value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");
    await bridge.setStorageValueWithCompensation(
      "elizaos:agent-profiles",
      "registry-b",
      { runtimeConnectionTransaction: transaction },
    );
    await bridge.setStorageValueWithCompensation(
      "elizaos:active-server",
      "server-b",
      { runtimeConnectionTransaction: transaction },
    );
    await expect(
      writeStoredStewardToken("staging-token-b", {
        hostPersistenceContext: transaction,
        finalizeBeforePublish: () => {
          throw new Error("injected finalizer failure after decision");
        },
      }),
    ).rejects.toThrow("injected finalizer failure after decision");

    // Simulate a cold renderer cache: host restored raw legacy A, while the
    // only scope available at restart is the value published before ABORT.
    const revision =
      (mockDesktopSecure.revisions.get("session.steward_token") ?? 0) + 1;
    mockDesktopSecure.revisions.set("session.steward_token", revision);
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind: "session.steward_token", revision });
    }
    await expect(bridge.getStorageValue(STEWARD_TOKEN_KEY)).resolves.toBe(
      "legacy-token-a",
    );
    expect(mockDesktopStore.get("session.steward_token")).toBe(
      "legacy-token-a",
    );
    expect(window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:production",
    );
  });

  it("does not let an unrelated Steward writer enlist in or decide the ambient WAL", async () => {
    await bridge.setStorageValue("elizaos:agent-profiles", "registry-a");
    await bridge.setStorageValue("elizaos:active-server", "server-a");
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "token-a");
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key: "elizaos:agent-profiles", value: "registry-b" },
      { key: "elizaos:active-server", value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");
    await bridge.setStorageValueWithCompensation(
      "elizaos:agent-profiles",
      "registry-b",
      { runtimeConnectionTransaction: transaction },
    );
    await bridge.setStorageValueWithCompensation(
      "elizaos:active-server",
      "server-b",
      { runtimeConnectionTransaction: transaction },
    );
    const transitions: string[] = [];
    const listener = (event: Event) => {
      transitions.push((event as CustomEvent<{ state: string }>).detail.state);
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      await expect(writeStoredStewardToken("token-c")).rejects.toMatchObject({
        name: "StewardTokenPersistenceError",
      });
      expect(mockDesktopSecure.connectionTransactionCalls).toEqual(["begin"]);
      expect(transitions).toEqual([]);
      expect(mockDesktopStewardToken()).toBe("token-a");
      await expect(
        bridge.abortRuntimeConnectionStorageTransaction(transaction),
      ).resolves.toBe(true);
      expect(mockDesktopSecure.connectionTransactionCalls).toEqual([
        "begin",
        "abort",
      ]);
      expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-a");
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("rejects a non-participant device credential without hiding a revision or cache change", async () => {
    await bridge.setStorageValue("eliza.device.auth", "device-a");
    const revision = mockDesktopSecure.revisions.get("session.device_auth");
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key: "elizaos:agent-profiles", value: "registry-b" },
      { key: "elizaos:active-server", value: "server-b" },
    ]);
    if (!transaction) throw new Error("transaction was not prepared");

    await expect(
      bridge.setStorageValue("eliza.device.auth", "device-b"),
    ).rejects.toThrow("runtime connection transaction is in progress");
    expect(mockDesktopStore.get("session.device_auth")).toBe("device-a");
    expect(mockDesktopSecure.revisions.get("session.device_auth")).toBe(
      revision,
    );
    expect(window.localStorage.getItem("eliza.device.auth")).toBe("device-a");
    await bridge.abortRuntimeConnectionStorageTransaction(transaction);
  });

  it("hydrates the token/scope bundle coherently after prepared rollback and committed roll-forward", async () => {
    configureStoredStewardTokenScope("https://api.eliza.app");
    await writeStoredStewardToken("token-a");
    expect(window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:production",
    );

    const publishHostSnapshot = (value: string, staleScope: string) => {
      mockDesktopStore.set("session.steward_token", value);
      rawSetItem(STEWARD_TOKEN_SCOPE_KEY, staleScope);
      const revision =
        (mockDesktopSecure.revisions.get("session.steward_token") ?? 0) + 1;
      mockDesktopSecure.revisions.set("session.steward_token", revision);
      for (const listener of mockDesktopSecure.changedListeners) {
        listener({ kind: "session.steward_token", revision });
      }
    };

    // Recovery of a prepared WAL has restored the predecessor bundle. Even if
    // the renderer-local scope survived as B, hydration publishes token A
    // first and then repairs its paired production scope.
    publishHostSnapshot(
      JSON.stringify({
        marker: "eliza.steward-token.v1",
        scope: "eliza-cloud:production",
        token: "token-a",
      }),
      "eliza-cloud:staging",
    );
    await expect(bridge.getStorageValue(STEWARD_TOKEN_KEY)).resolves.toBe(
      "token-a",
    );
    expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-a");
    expect(window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:production",
    );

    // Recovery of a committed WAL rolls the same participant forward as one
    // bundle, so a stale A scope is repaired to B after token B is cached.
    publishHostSnapshot(
      JSON.stringify({
        marker: "eliza.steward-token.v1",
        scope: "eliza-cloud:staging",
        token: "token-b",
      }),
      "eliza-cloud:production",
    );
    await expect(bridge.getStorageValue(STEWARD_TOKEN_KEY)).resolves.toBe(
      "token-b",
    );
    expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("token-b");
    expect(window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)).toBe(
      "eliza-cloud:staging",
    );
  });

  it("persists session credentials only in the desktop secure store", async () => {
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "desktop-secret");
    expect(mockDesktopStewardToken()).toBe("desktop-secret");
    expect(rawGetItem(STEWARD_TOKEN_KEY)).toBeNull();
    // The installed proxy serves the live credential from its in-memory
    // cache; plaintext must only be absent from the RAW store above.
    expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
      "desktop-secret",
    );
    expect(await bridge.getStorageValue(STEWARD_TOKEN_KEY)).toBe(
      "desktop-secret",
    );
  });

  it("repopulates the sync facade after its own host invalidation event", async () => {
    const key = "eliza.device.auth";
    window.localStorage.setItem(key, "legacy-sync-writer-token");

    await vi.waitFor(() => {
      expect(mockDesktopStore.get("session.device_auth")).toBe(
        "legacy-sync-writer-token",
      );
      expect(window.localStorage.getItem(key)).toBe("legacy-sync-writer-token");
    });
  });

  it("rejects an awaited write the desktop store refused", async () => {
    mockDesktopSecure.rejectSets = true;
    await expect(
      bridge.setStorageValue(STEWARD_TOKEN_KEY, "refused-write"),
    ).rejects.toThrow("Protected storage rejected write");
    expect(mockDesktopStore.has("session.steward_token")).toBe(false);
    expect(rawGetItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("reads a never-stored credential as null", async () => {
    expect(await bridge.getStorageValue("eliza.device.auth")).toBeNull();
  });

  it("retries a lost SET response with the same mutation id and one backend write", async () => {
    mockDesktopSecure.loseNextSetResponse = true;

    await bridge.setStorageValue("eliza.device.auth", "retry-safe-token");

    expect(mockDesktopSecure.setRequestCalls).toHaveLength(2);
    expect(mockDesktopSecure.setRequestCalls[0]?.mutationId).toBe(
      mockDesktopSecure.setRequestCalls[1]?.mutationId,
    );
    expect(mockDesktopSecure.setBackendWrites).toBe(1);
    expect(mockDesktopStore.get("session.device_auth")).toBe(
      "retry-safe-token",
    );
  });

  it("reconciles an exact receipt when the host cannot confirm a maybe-written SET", async () => {
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "prior-token");
    mockDesktopSecure.compareAndRestoreCalls.length = 0;
    mockDesktopSecure.failNextSetAfterMutation = true;

    await expect(
      bridge.setStorageValue(STEWARD_TOKEN_KEY, "ambiguous-latent-token"),
    ).rejects.toThrow();

    expect(mockDesktopSecure.compareAndRestoreCalls).toEqual([
      {
        kind: "session.steward_token",
        rollbackReceipt: "mock-receipt-2",
      },
    ]);
    expect(mockDesktopStewardToken()).toBe("prior-token");
  });

  it("retries a lost COMMIT response with the same receipt and authoritative readback", async () => {
    mockDesktopSecure.loseNextCommitResponse = true;

    await bridge.setStorageValue("eliza.device.auth", "commit-retry-token");

    expect(mockDesktopSecure.commitReceiptCalls).toHaveLength(2);
    expect(mockDesktopSecure.commitReceiptCalls[0]).toEqual(
      mockDesktopSecure.commitReceiptCalls[1],
    );
    expect(mockDesktopSecure.setBackendWrites).toBe(1);
    expect(await bridge.getStorageValue("eliza.device.auth")).toBe(
      "commit-retry-token",
    );
  });

  it("replays an atomic COMMIT snapshot when a prepared WAL starts after the lost response", async () => {
    await bridge.setStorageValue("elizaos:active-server", "server-a");
    let concurrentTransaction: Awaited<
      ReturnType<typeof bridge.beginRuntimeConnectionStorageTransaction>
    > = null;
    mockDesktopSecure.loseNextCommitResponse = true;
    mockDesktopSecure.commitReceiptSettledHook = async (kind) => {
      if (kind !== "session.device_auth") return;
      mockDesktopSecure.commitReceiptSettledHook = null;
      concurrentTransaction =
        await bridge.beginRuntimeConnectionStorageTransaction([
          { key: "elizaos:active-server", value: "server-b" },
        ]);
    };

    await expect(
      bridge.setStorageValue("eliza.device.auth", "committed-before-wal"),
    ).resolves.toBeUndefined();
    expect(mockDesktopSecure.commitReceiptCalls.slice(-2)).toEqual([
      mockDesktopSecure.commitReceiptCalls.at(-1),
      mockDesktopSecure.commitReceiptCalls.at(-1),
    ]);
    expect(window.localStorage.getItem("eliza.device.auth")).toBe(
      "committed-before-wal",
    );
    if (!concurrentTransaction) throw new Error("WAL did not start");
    await bridge.abortRuntimeConnectionStorageTransaction(
      concurrentTransaction,
    );
  });

  it("does not publish an old COMMIT snapshot after a WAL commits a successor", async () => {
    const key = "elizaos:active-server";
    const kind = "runtime.active_server";
    await bridge.setStorageValue(key, "server-a");
    let concurrentTransaction: Awaited<
      ReturnType<typeof bridge.beginRuntimeConnectionStorageTransaction>
    > = null;
    mockDesktopSecure.loseNextCommitResponse = true;
    mockDesktopSecure.commitReceiptSettledHook = async (settledKind) => {
      if (settledKind !== kind) return;
      mockDesktopSecure.commitReceiptSettledHook = null;
      concurrentTransaction =
        await bridge.beginRuntimeConnectionStorageTransaction([
          { key, value: "server-c" },
        ]);
      if (!concurrentTransaction) throw new Error("WAL did not start");
      await bridge.setStorageValueWithCompensation(key, "server-c", {
        runtimeConnectionTransaction: concurrentTransaction,
      });
      await bridge.decideRuntimeConnectionStorageTransaction(
        concurrentTransaction,
      );
    };

    await expect(bridge.setStorageValue(key, "server-b")).rejects.toThrow(
      "superseded",
    );
    if (!concurrentTransaction) throw new Error("WAL did not commit");
    await bridge.finishRuntimeConnectionStorageTransaction(
      concurrentTransaction,
    );
    expect(mockDesktopStore.get(kind)).toBe("server-c");
    expect(window.localStorage.getItem(key)).toBe("server-c");
  });

  it("keeps a transaction compensation valid at the final decision revision", async () => {
    const key = "elizaos:active-server";
    const kind = "runtime.active_server";
    await bridge.setStorageValue(key, "server-a");
    const transaction = await bridge.beginRuntimeConnectionStorageTransaction([
      { key, value: "server-b" },
    ]);
    if (!transaction) throw new Error("WAL did not start");
    const compensation = await bridge.setStorageValueWithCompensation(
      key,
      "server-b",
      { runtimeConnectionTransaction: transaction },
    );
    if (!compensation) throw new Error("compensation was not captured");
    await bridge.decideRuntimeConnectionStorageTransaction(transaction);
    await bridge.finishRuntimeConnectionStorageTransaction(transaction);

    await expect(compensation.compensate()).resolves.toBe(true);
    expect(mockDesktopStore.get(kind)).toBe("server-a");
    expect(window.localStorage.getItem(key)).toBe("server-a");
  });

  it("restores an active-server predecessor when every COMMIT response is lost", async () => {
    const key = "elizaos:active-server";
    const kind = "runtime.active_server";
    await bridge.setStorageValue(key, "prior-active-server");
    mockDesktopSecure.commitReceiptCalls.length = 0;
    mockDesktopSecure.commitResponseLossesRemaining = 3;

    await expect(
      bridge.setStorageValue(key, "ambiguous-active-server"),
    ).rejects.toThrow("deterministic lost COMMIT response");

    expect(mockDesktopSecure.commitReceiptCalls).toHaveLength(3);
    expect(mockDesktopSecure.commitReceiptCalls.slice(1)).toEqual([
      mockDesktopSecure.commitReceiptCalls[0],
      mockDesktopSecure.commitReceiptCalls[0],
    ]);
    expect(mockDesktopSecure.compensateCommittedCalls).toHaveLength(1);
    expect(mockDesktopStore.get(kind)).toBe("prior-active-server");
    expect(window.localStorage.getItem(key)).toBe("prior-active-server");
  });

  it("restores the prior Steward token without publishing when every COMMIT response is lost", async () => {
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "prior-token");
    mockDesktopSecure.commitReceiptCalls.length = 0;
    mockDesktopSecure.commitResponseLossesRemaining = 3;
    const transitions: string[] = [];
    const listener = (event: Event) => {
      transitions.push((event as CustomEvent<{ state: string }>).detail.state);
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      await expect(
        writeStoredStewardToken("ambiguous-steward-token"),
      ).rejects.toMatchObject({ name: "StewardTokenPersistenceError" });

      expect(mockDesktopSecure.commitReceiptCalls).toHaveLength(3);
      // Reconcile once after the lost COMMIT replies, then replay the durable
      // compensation tombstone from Shared's outer restoration closure.
      expect(mockDesktopSecure.compensateCommittedCalls).toHaveLength(2);
      expect(mockDesktopStewardToken()).toBe("prior-token");
      expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
        "prior-token",
      );
      expect(transitions).toEqual([]);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("invalidates renderer A immediately when renderer B removes the host credential", async () => {
    await bridge.setStorageValue("eliza.device.auth", "renderer-a-token");
    expect(window.localStorage.getItem("eliza.device.auth")).toBe(
      "renderer-a-token",
    );

    // Model renderer B logging out through the shared host authority. The
    // current renderer has not observed that mutation yet and still holds A.
    const kind = "session.device_auth";
    mockDesktopStore.delete(kind);
    const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
    mockDesktopSecure.revisions.set(kind, revision);
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind, revision });
    }

    expect(window.localStorage.getItem("eliza.device.auth")).toBeNull();
    await expect(
      bridge.getStorageValue("eliza.device.auth"),
    ).resolves.toBeNull();
    expect(window.localStorage.getItem("eliza.device.auth")).toBeNull();
  });

  it("quarantines a stale cache through a secret-free revision lease when an invalidation event is missed", async () => {
    const now = Date.now();
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const key = "eliza.device.auth";
      const kind = "session.device_auth";
      await bridge.setStorageValue(key, "renderer-a-token");
      expect(window.localStorage.getItem(key)).toBe("renderer-a-token");

      // Model a host mutation whose push could not reach this renderer. The
      // next active cache read after half the lease asks only for a revision.
      mockDesktopStore.delete(kind);
      mockDesktopSecure.revisions.set(
        kind,
        (mockDesktopSecure.revisions.get(kind) ?? 0) + 1,
      );
      nowSpy.mockReturnValue(now + 16_000);
      expect(window.localStorage.getItem(key)).toBe("renderer-a-token");
      await vi.waitFor(() => {
        expect(mockDesktopSecure.revisionRequestCalls).toEqual([kind]);
        expect(window.localStorage.getItem(key)).toBeNull();
      });
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("renews a healthy credential lease proactively before a delayed sync read", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-30T00:00:00.000Z"));
    try {
      const key = "eliza.device.auth";
      const kind = "session.device_auth";
      await bridge.setStorageValue(key, "proactively-renewed-token");
      expect(mockDesktopSecure.revisionRequestCalls).toEqual([]);

      // There are no renderer reads before the original 30-second lease would
      // expire. The timer renews with a revision-only RPC, so a 60-second UI
      // polling cadence cannot mistake a healthy credential for an absence.
      await vi.advanceTimersByTimeAsync(31_000);

      expect(mockDesktopSecure.revisionRequestCalls).toContain(kind);
      expect(window.localStorage.getItem(key)).toBe(
        "proactively-renewed-token",
      );
    } finally {
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });

  it("expires proactively at the original bound when lease renewal is unavailable", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-30T00:00:00.000Z"));
    try {
      const key = "eliza.device.auth";
      const kind = "session.device_auth";
      await bridge.setStorageValue(key, "unrenewed-token");
      mockDesktopSecure.available = false;

      await vi.advanceTimersByTimeAsync(30_001);

      expect(mockDesktopSecure.revisionRequestCalls).toEqual([kind]);
      expect(window.localStorage.getItem(key)).toBeNull();
    } finally {
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });

  it("fails the synchronous credential cache closed at the fixed lease bound when revision polling is unavailable", async () => {
    const now = Date.now();
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const key = "eliza.device.auth";
      await bridge.setStorageValue(key, "lease-bounded-token");
      nowSpy.mockReturnValue(now + 30_001);

      expect(window.localStorage.getItem(key)).toBeNull();
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("does not let an older in-flight read refill cache after renderer B advances the revision", async () => {
    const key = "eliza.device.auth";
    const kind = "session.device_auth";
    await bridge.setStorageValue(key, "renderer-a-token");
    let markReadStarted: () => void = () => {};
    const readStarted = new Promise<void>((resolve) => {
      markReadStarted = resolve;
    });
    let releaseOldSnapshot: () => void = () => {};
    mockDesktopSecure.getSnapshotWait = new Promise<void>((resolve) => {
      releaseOldSnapshot = resolve;
    });
    mockDesktopSecure.getSnapshotStarted = markReadStarted;

    const staleRead = bridge.getStorageValue(key);
    await readStarted;

    mockDesktopStore.set(kind, "renderer-b-token");
    const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
    mockDesktopSecure.revisions.set(kind, revision);
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind, revision });
    }
    // Only the already-captured first response is held. The retry must read B.
    mockDesktopSecure.getSnapshotWait = null;
    mockDesktopSecure.getSnapshotStarted = null;
    releaseOldSnapshot();

    await expect(staleRead).resolves.toBe("renderer-b-token");
    expect(window.localStorage.getItem(key)).toBe("renderer-b-token");
  });

  it.each(["throw", "unavailable", "not_found"] as const)(
    "rolls the exact desktop write back when its readback reports %s",
    async (failure) => {
      await bridge.setStorageValue(STEWARD_TOKEN_KEY, "prior-token");
      mockDesktopSecure.compareAndRestoreCalls.length = 0;
      mockDesktopSecure.nextGetFailure = failure;

      await expect(
        bridge.setStorageValue(STEWARD_TOKEN_KEY, "latent-rejected-token"),
      ).rejects.toThrow();

      expect(mockDesktopSecure.compareAndRestoreCalls).toEqual([
        {
          kind: "session.steward_token",
          rollbackReceipt: "mock-receipt-2",
        },
      ]);
      expect(mockDesktopStewardToken()).toBe("prior-token");
      expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
        "prior-token",
      );
    },
  );

  it("removes a credential and tolerates removing it again", async () => {
    await bridge.setStorageValue("eliza.device.auth", "doomed-secret");
    await bridge.removeStorageValue("eliza.device.auth");
    expect(mockDesktopStore.has("session.device_auth")).toBe(false);
    expect(await bridge.getStorageValue("eliza.device.auth")).toBeNull();

    await expect(
      bridge.removeStorageValue("eliza.device.auth"),
    ).resolves.toBeUndefined();
  });

  it("does not let renderer A's terminal CAS delete renderer B's newer token", async () => {
    const key = STEWARD_TOKEN_KEY;
    const kind = "session.steward_token";
    await bridge.setStorageValue(key, "renderer-a-token");
    mockDesktopSecure.compareAndDeleteHook = async () => {
      mockDesktopStore.set(kind, "renderer-b-token");
      const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
      mockDesktopSecure.revisions.set(kind, revision);
      for (const listener of mockDesktopSecure.changedListeners) {
        listener({ kind, revision });
      }
    };

    await expect(
      bridge.removeStorageValueIfCurrent(key, "renderer-a-token", {
        validate: () => true,
      }),
    ).resolves.toBe(false);

    expect(mockDesktopSecure.compareAndDeleteCalls).toHaveLength(1);
    expect(mockDesktopStore.get(kind)).toBe("renderer-b-token");
    expect(window.localStorage.getItem(key)).toBe("renderer-b-token");
  });

  it("does not confirm expected absence from a snapshot overtaken by renderer B", async () => {
    const key = STEWARD_TOKEN_KEY;
    const kind = "session.steward_token";
    let markSnapshotStarted: () => void = () => {};
    const snapshotStarted = new Promise<void>((resolve) => {
      markSnapshotStarted = resolve;
    });
    let releaseSnapshot: () => void = () => {};
    mockDesktopSecure.getSnapshotStarted = markSnapshotStarted;
    mockDesktopSecure.getSnapshotWait = new Promise<void>((resolve) => {
      releaseSnapshot = resolve;
    });

    const terminalClear = bridge.removeStorageValueIfCurrent(key, null, {
      validate: () => true,
    });
    await snapshotStarted;
    mockDesktopStore.set(kind, "renderer-b-token");
    const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
    mockDesktopSecure.revisions.set(kind, revision);
    for (const listener of mockDesktopSecure.changedListeners) {
      listener({ kind, revision });
    }
    mockDesktopSecure.getSnapshotStarted = null;
    mockDesktopSecure.getSnapshotWait = null;
    releaseSnapshot();

    await expect(terminalClear).resolves.toBe(false);
    expect(mockDesktopStore.get(kind)).toBe("renderer-b-token");
    expect(window.localStorage.getItem(key)).toBe("renderer-b-token");
  });

  it("keeps terminal renderer A absent and completes after its exact CAS deletion", async () => {
    const key = STEWARD_TOKEN_KEY;
    await bridge.setStorageValue(key, "renderer-a-token");
    let checks = 0;

    await expect(
      bridge.removeStorageValueIfCurrent(key, "renderer-a-token", {
        validate: () => {
          checks += 1;
          return checks < 3;
        },
      }),
    ).resolves.toBe(true);

    expect(mockDesktopStore.has("session.steward_token")).toBe(false);
    expect(window.localStorage.getItem(key)).toBeNull();
  });

  it("replays one delete mutation id after all retry responses are lost", async () => {
    const key = STEWARD_TOKEN_KEY;
    await bridge.setStorageValue(key, "renderer-a-token");
    mockDesktopSecure.compareAndDeleteResponseLossesRemaining = 3;
    let checks = 0;

    await expect(
      bridge.removeStorageValueIfCurrent(key, "renderer-a-token", {
        validate: () => {
          checks += 1;
          return checks < 3;
        },
      }),
    ).resolves.toBe(true);

    expect(mockDesktopSecure.compareAndDeleteCalls).toHaveLength(4);
    expect(
      new Set(
        mockDesktopSecure.compareAndDeleteCalls.map(
          ({ mutationId }) => mutationId,
        ),
      ),
    ).toHaveLength(1);
    expect(mockDesktopStore.has("session.steward_token")).toBe(false);
  });

  it("does not resurrect renderer A when renderer B owns the observed deletion", async () => {
    const key = STEWARD_TOKEN_KEY;
    const kind = "session.steward_token";
    await bridge.setStorageValue(key, "shared-token");
    mockDesktopSecure.compareAndDeleteHook = async () => {
      mockDesktopStore.delete(kind);
      const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
      mockDesktopSecure.revisions.set(kind, revision);
      for (const listener of mockDesktopSecure.changedListeners) {
        listener({ kind, revision });
      }
    };

    await expect(
      bridge.removeStorageValueIfCurrent(key, "shared-token", {
        validate: () => true,
      }),
    ).resolves.toBe(false);

    // A's owner-bound journal has no success entry, so B remains absent and A
    // cannot attribute or compensate B's deletion.
    expect(mockDesktopStore.has(kind)).toBe(false);
  });

  it("terminally transforms only the exact protected record snapshot", async () => {
    const key = "elizaos:agent-profiles";
    await bridge.setStorageValue(key, "profile-a-with-token");

    await expect(
      bridge.setStorageValueIfCurrent(
        key,
        "profile-a-with-token",
        "profile-a-scrubbed",
        { validate: () => true },
      ),
    ).resolves.toBe(true);

    expect(mockDesktopStore.get("runtime.agent_profiles")).toBe(
      "profile-a-scrubbed",
    );
    expect(mockDesktopSecure.compareAndSetCalls).toHaveLength(1);
  });

  it("does not transform renderer B after A's profile snapshot goes stale", async () => {
    const key = "elizaos:agent-profiles";
    const kind = "runtime.agent_profiles";
    await bridge.setStorageValue(key, "profile-a-with-token");
    mockDesktopSecure.compareAndSetHook = async () => {
      mockDesktopStore.set(kind, "profile-b-with-token");
      mockDesktopSecure.revisions.set(
        kind,
        (mockDesktopSecure.revisions.get(kind) ?? 0) + 1,
      );
    };

    await expect(
      bridge.setStorageValueIfCurrent(
        key,
        "profile-a-with-token",
        "profile-a-scrubbed",
        { validate: () => true },
      ),
    ).resolves.toBe(false);
    expect(mockDesktopStore.get(kind)).toBe("profile-b-with-token");
  });

  it("replays one terminal transform id after every normal response is lost", async () => {
    const key = "elizaos:active-server";
    await bridge.setStorageValue(key, "active-a-with-token");
    mockDesktopSecure.compareAndSetResponseLossesRemaining = 3;

    await expect(
      bridge.setStorageValueIfCurrent(
        key,
        "active-a-with-token",
        "active-a-scrubbed",
      ),
    ).resolves.toBe(true);

    expect(mockDesktopSecure.compareAndSetCalls).toHaveLength(4);
    expect(
      new Set(
        mockDesktopSecure.compareAndSetCalls.map(
          ({ mutationId }) => mutationId,
        ),
      ),
    ).toHaveLength(1);
    expect(mockDesktopStore.get("runtime.active_server")).toBe(
      "active-a-scrubbed",
    );
  });

  it("never restores terminal A when validation changes after its exact transform", async () => {
    const key = "elizaos:active-server";
    await bridge.setStorageValue(key, "active-a-with-token");
    let checks = 0;

    await expect(
      bridge.setStorageValueIfCurrent(
        key,
        "active-a-with-token",
        "active-a-scrubbed",
        {
          validate: () => {
            checks += 1;
            return checks < 3;
          },
        },
      ),
    ).resolves.toBe(false);
    expect(mockDesktopStore.get("runtime.active_server")).toBe(
      "active-a-scrubbed",
    );
  });

  it("rolls an aborted Steward write back through one host CAS request", async () => {
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "prior-token");
    const controller = new AbortController();
    mockDesktopSecure.abortOnSet = controller;

    await expect(
      writeStoredStewardToken("aborted-token", { signal: controller.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });

    expect(mockDesktopSecure.compareAndRestoreCalls).toEqual([
      {
        kind: "session.steward_token",
        rollbackReceipt: "mock-receipt-2",
      },
    ]);
    expect(mockDesktopStewardToken()).toBe("prior-token");
    expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("prior-token");
  });

  it("compensates a committed Steward receipt when its validator changes during the commit RPC", async () => {
    await bridge.setStorageValue(STEWARD_TOKEN_KEY, "prior-token");
    let authorityLive = true;
    let committedSetRevision = -1;
    mockDesktopSecure.commitReceiptHook = async (kind) => {
      committedSetRevision = mockDesktopSecure.revisions.get(kind) ?? -1;
      authorityLive = false;
    };
    const transitions: string[] = [];
    const listener = (event: Event) => {
      transitions.push((event as CustomEvent<{ state: string }>).detail.state);
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);

    try {
      await writeStoredStewardToken("superseded-token", {
        validate: () => authorityLive,
      });

      expect(mockDesktopSecure.compensateCommittedCalls).toEqual([
        {
          expectedRevision: committedSetRevision,
          kind: "session.steward_token",
          rollbackReceipt: "mock-receipt-2",
        },
      ]);
      expect(mockDesktopStewardToken()).toBe("prior-token");
      expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(
        "prior-token",
      );
      expect(transitions).toEqual([]);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("does not publish a Steward login when another renderer deletes before receipt commit", async () => {
    const transitions: string[] = [];
    const listener = (event: Event) => {
      transitions.push((event as CustomEvent<{ state: string }>).detail.state);
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    mockDesktopSecure.commitReceiptHook = async (kind) => {
      mockDesktopStore.delete(kind);
      mockDesktopSecure.rollbacks.delete(kind);
      const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
      mockDesktopSecure.revisions.set(kind, revision);
      for (const changedListener of mockDesktopSecure.changedListeners) {
        changedListener({ kind, revision });
      }
    };

    try {
      await expect(
        writeStoredStewardToken("superseded-renderer-token"),
      ).rejects.toMatchObject({ name: "StewardTokenPersistenceError" });
      expect(transitions).toEqual([]);
      expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(mockDesktopStore.has("session.steward_token")).toBe(false);
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("does not publish an ancestor receipt even when the newer renderer wrote the same token", async () => {
    const transitions: string[] = [];
    const listener = (event: Event) => {
      transitions.push((event as CustomEvent<{ state: string }>).detail.state);
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    mockDesktopSecure.commitReceiptHook = async (kind) => {
      // Model B superseding A with the same credential bytes. The host value
      // alone cannot prove A is still current; only its receipt ancestry can.
      mockDesktopSecure.rollbacks.delete(kind);
      const revision = (mockDesktopSecure.revisions.get(kind) ?? 0) + 1;
      mockDesktopSecure.revisions.set(kind, revision);
      for (const changedListener of mockDesktopSecure.changedListeners) {
        changedListener({ kind, revision });
      }
    };

    try {
      await expect(
        writeStoredStewardToken("same-bytes-superseded-token"),
      ).rejects.toMatchObject({ name: "StewardTokenPersistenceError" });
      expect(transitions).toEqual([]);
      expect(mockDesktopStewardToken()).toBe("same-bytes-superseded-token");
      expect(window.localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, listener);
    }
  });

  it("fails closed when the desktop secure store is unavailable", async () => {
    mockDesktopSecure.available = false;
    await expect(bridge.getStorageValue(STEWARD_TOKEN_KEY)).rejects.toThrow(
      "Desktop protected storage is unavailable",
    );
  });

  it("leaves ordinary keys in localStorage untouched by the secure store", async () => {
    await bridge.setStorageValue("eliza.desktop.plain", "ordinary");
    expect(window.localStorage.getItem("eliza.desktop.plain")).toBe("ordinary");
    expect(mockDesktopStore.size).toBe(0);
  });
});

describe("storage bridge on the native android runtime", () => {
  beforeAll(() => {
    mockRuntime.electrobun = false;
    mockRuntime.native = true;
  });

  it("mirrors synced localStorage writes into Capacitor Preferences and back out on removal", async () => {
    window.localStorage.setItem("eliza:first-run-complete", "resume-flag");
    expect(rawGetItem("eliza:first-run-complete")).toBe("resume-flag");
    await vi.waitFor(() => {
      expect(mockPreferences.get("eliza:first-run-complete")).toBe(
        "resume-flag",
      );
    });

    window.localStorage.removeItem("eliza:first-run-complete");
    expect(window.localStorage.getItem("eliza:first-run-complete")).toBeNull();
    await vi.waitFor(() => {
      expect(mockPreferences.has("eliza:first-run-complete")).toBe(false);
    });
  });

  it("never syncs unregistered keys to Preferences", async () => {
    window.localStorage.setItem("eliza.test.unregistered", "stays-local");
    await settle();
    expect(mockPreferences.size).toBe(0);
    expect(window.localStorage.getItem("eliza.test.unregistered")).toBe(
      "stays-local",
    );

    window.localStorage.removeItem("eliza.test.unregistered");
    await settle();
    expect(mockPreferences.size).toBe(0);
  });

  it("serves synced keys from Preferences even when localStorage is empty", async () => {
    mockPreferences.set("eliza.device.identity", "from-preferences");
    expect(await bridge.getStorageValue("eliza.device.identity")).toBe(
      "from-preferences",
    );
    expect(
      await bridge.getStorageValue("eliza.device.missing-synced"),
    ).toBeNull();
  });

  it("extends the synced set at runtime via registerSyncedKey", async () => {
    bridge.registerSyncedKey("eliza.test.native-registered");
    window.localStorage.setItem(
      "eliza.test.native-registered",
      "late-addition",
    );
    await vi.waitFor(() => {
      expect(mockPreferences.get("eliza.test.native-registered")).toBe(
        "late-addition",
      );
    });

    window.localStorage.removeItem("eliza.test.native-registered");
    await vi.waitFor(() => {
      expect(mockPreferences.has("eliza.test.native-registered")).toBe(false);
    });
  });

  it("keeps sessionStorage writes out of the native sync path", async () => {
    window.localStorage.setItem("eliza:first-run-complete", "disk-value");
    window.sessionStorage.setItem("eliza:first-run-complete", "session-value");
    await settle();

    expect(window.sessionStorage.getItem("eliza:first-run-complete")).toBe(
      "session-value",
    );
    expect(window.localStorage.getItem("eliza:first-run-complete")).toBe(
      "disk-value",
    );
    expect(mockPreferences.get("eliza:first-run-complete")).toBe("disk-value");
  });
});
