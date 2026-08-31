/**
 * Storage Bridge
 *
 * This module provides a bridge between the web UI's localStorage usage
 * and Capacitor's Preferences plugin for native platforms. On web, it
 * passes through to localStorage. On native, it uses Preferences for
 * more reliable persistence.
 *
 * The bridge works by intercepting localStorage calls via a proxy and
 * syncing with Capacitor Preferences on native platforms.
 */

import { Capacitor } from "@capacitor/core";
import { logger } from "@elizaos/logger";
import {
  registerStewardTokenCompareAndRestore,
  registerStewardTokenPersistence,
  registerStewardTokenRemoval,
  STEWARD_TOKEN_KEY,
  STEWARD_TOKEN_SCOPE_KEY,
  type StewardTokenHostPersistenceContext,
} from "@elizaos/shared/steward-session-client";
import { MOBILE_RUNTIME_MODE_STORAGE_KEY } from "../first-run/mobile-runtime-mode";
import { runAsPrivilegedShell } from "../surface-realm-channel";
import {
  type DesktopConnectionTransactionKind,
  type DesktopSecureStoreChangedEvent,
  type DesktopSecureStoreKind,
  desktopConnectionTransactionAbort,
  desktopConnectionTransactionBegin,
  desktopConnectionTransactionCompensate,
  desktopConnectionTransactionDecide,
  desktopConnectionTransactionFinish,
  desktopConnectionTransactionStage,
  desktopConnectionTransactionStatus,
  desktopSecureStoreCommitReceipt,
  desktopSecureStoreCompareAndDelete,
  desktopSecureStoreCompareAndRestore,
  desktopSecureStoreCompareAndSet,
  desktopSecureStoreCompensateCommittedReceipt,
  desktopSecureStoreDelete,
  desktopSecureStoreGet,
  desktopSecureStoreRevision,
  desktopSecureStoreSet,
  subscribeDesktopBridgeEvent,
} from "./electrobun-rpc";
import { isElectrobunRuntime } from "./electrobun-runtime";

/**
 * Lazy-load the @capacitor/preferences module on demand. Keeping it out of the
 * static module graph means server consumers that pull in the @elizaos/ui barrel
 * (e.g. plugin-inbox in the Node agent image) don't crash resolving a
 * native-only, mobile-only devDependency. Only ever invoked behind an
 * `isNativePlatform()` guard.
 *
 * Returns the module namespace, NOT the bare `Preferences` plugin. The plugin is
 * a Capacitor proxy whose `.then` resolves to a function, which makes it
 * *thenable*: resolving any promise (an async return or a `.then` callback)
 * with the bare proxy triggers the Promise resolution procedure, which calls
 * `proxy.then(resolve, reject)`. On Android that throws
 * `"Preferences.then()" is not implemented` AND the proxy's `.then` ignores the
 * resolve/reject it was handed, so the adopting promise never settles —
 * `await loadPreferences()` would hang forever and block boot. The module
 * namespace has no `then` export, so it is safe to await; callers destructure
 * `{ Preferences }` and only ever resolve promises with method-call results.
 */
function loadPreferences() {
  return import("@capacitor/preferences");
}

function loadNativeSecureStore() {
  return import("@elizaos/capacitor-secure-store");
}

function isNativePlatform(): boolean {
  try {
    const platform = Capacitor.getPlatform();
    return (
      Capacitor.isNativePlatform() ||
      platform === "ios" ||
      platform === "android"
    );
  } catch {
    // error-policy:J4 no Capacitor bridge → web runtime; treat as non-native.
    return false;
  }
}

// Keys that should be synced to Capacitor Preferences.
// On iOS, WKWebView localStorage can be purged under memory pressure.
// These keys are critical for session restoration on mobile.
const SYNCED_KEYS = new Set([
  "eliza.control.settings.v1",
  "eliza.device.identity",
  // Native hosts intercept these through PROTECTED_STORAGE_KIND before this
  // set is consulted, so credentials never land in Preferences.
  "eliza.device.auth",
  STEWARD_TOKEN_KEY,
  "elizaos:active-server",
  "eliza:first-run-complete",
  "eliza:setup:step",
  MOBILE_RUNTIME_MODE_STORAGE_KEY,
  // `useAppLifecycleEvents` writes this on APP_PAUSE so the next
  // foreground can rehydrate the same conversation even after the
  // WKWebView localStorage was purged under memory pressure.
  "eliza:chat:activeConversationId",
  "eliza:ios-local-agent:conversations:v1",
  "eliza:ios-local-agent:active-model:v1",
  "eliza:ios-local-agent:assignments:v1",
  "eliza:ios-local-agent:browser-workspace:v1",
  "eliza:ios-local-agent:wallet-market-overview:v1",
  "eliza:ios-local-agent:eliza-1-bundles:v1",
  "eliza:ios-full-bun-smoke:request",
  "eliza:ios-full-bun-smoke:result",
  "eliza:ios-onboarding-smoke:request",
  "eliza:ios-onboarding-smoke:result",
  "eliza:ios-onboarding-relaunch-smoke:request",
  "eliza:ios-onboarding-relaunch-smoke:result",
  "eliza:ios-mixed-content-smoke:request",
  "eliza:ios-mixed-content-smoke:result",
  "eliza:ios-attachment-smoke:request",
  "eliza:ios-attachment-smoke:result",
  "eliza:ios-voice-selftest:request",
  "eliza:ios-voice-selftest:result",
  // Harness wallet for zero-interaction SIWE e2e (#13377): device harnesses
  // seed these via native Preferences before first launch; the install itself
  // is gated off store builds (platform/e2e-wallet.ts).
  "eliza:e2e-wallet:pk",
  "eliza:e2e-wallet:autologin",
]);

const PROTECTED_STORAGE_KIND = new Map<string, DesktopSecureStoreKind>([
  ["eliza.device.auth", "session.device_auth"],
  [STEWARD_TOKEN_KEY, "session.steward_token"],
  ["elizaos:active-server", "runtime.active_server"],
  ["elizaos:agent-profiles", "runtime.agent_profiles"],
]);
const PROTECTED_STORAGE_KEY = new Map<DesktopSecureStoreKind, string>(
  Array.from(PROTECTED_STORAGE_KIND, ([key, kind]) => [kind, key]),
);

const STEWARD_TOKEN_RECORD_MARKER = "eliza.steward-token.v1";

interface StewardTokenRecord {
  marker: typeof STEWARD_TOKEN_RECORD_MARKER;
  scope: string | null;
  token: string;
}

function encodeProtectedStorageValue(
  key: string,
  value: string,
  stewardScope?: string | null,
): string {
  if (
    key !== STEWARD_TOKEN_KEY ||
    isNativePlatform() ||
    !isElectrobunRuntime()
  ) {
    return value;
  }
  const record: StewardTokenRecord = {
    marker: STEWARD_TOKEN_RECORD_MARKER,
    scope:
      stewardScope === undefined
        ? window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY)
        : stewardScope,
    token: value,
  };
  return JSON.stringify(record);
}

function decodeStewardTokenRecord(value: string): {
  scope?: string | null;
  token: string;
} {
  try {
    const parsed = JSON.parse(value) as Partial<StewardTokenRecord>;
    if (
      parsed?.marker === STEWARD_TOKEN_RECORD_MARKER &&
      typeof parsed.token === "string" &&
      (parsed.scope === null || typeof parsed.scope === "string")
    ) {
      return { scope: parsed.scope, token: parsed.token };
    }
  } catch {
    // Existing installations store a plain token. Preserve it and its legacy
    // local scope until the next successful write upgrades the secure record.
  }
  return { token: value };
}

function synchronizeStewardTokenScope(scope: string | null): void {
  runAsPrivilegedShell(() => {
    if (scope === null) window.localStorage.removeItem(STEWARD_TOKEN_SCOPE_KEY);
    else window.localStorage.setItem(STEWARD_TOKEN_SCOPE_KEY, scope);
  });
}

function decodeProtectedStorageValue(
  key: string,
  value: string,
): { scope?: string | null; value: string } {
  if (key !== STEWARD_TOKEN_KEY) return { value };
  const decoded = decodeStewardTokenRecord(value);
  return {
    ...(Object.hasOwn(decoded, "scope")
      ? { scope: decoded.scope ?? null }
      : {}),
    value: decoded.token,
  };
}

const protectedStorageCache = new Map<string, string>();
const protectedStorageCacheValidatedAt = new Map<string, number>();
const protectedStorageHostRevision = new Map<string, number>();
const protectedStorageLeaseRefreshes = new Map<string, Promise<void>>();
const protectedStorageLeaseTimers = new Map<
  string,
  ReturnType<typeof setTimeout>
>();
const protectedStorageMutationVersion = new Map<string, number>();
const protectedStorageMutationTail = new Map<string, Promise<void>>();

interface ProtectedStoreSetResult {
  predecessor?: string | null;
  rollbackReceipt: string | null;
  setRevision?: number;
  storedValue?: string;
  stored: boolean;
}

interface ProtectedStoreRollbackAuthority {
  receipt: string;
  setRevision: number;
  transactionReceipt?: RuntimeConnectionTransactionReceiptState;
}

interface ProtectedStoreCompensationSnapshot {
  restored: boolean;
  revision?: number;
  value: string | null;
}

interface PersistedStorageValue {
  mutationVersion: number;
  previousValue?: string | null;
  rollbackAuthority: ProtectedStoreRollbackAuthority | null;
  storedValue: string;
}

interface PersistStorageValueContext {
  stewardScope?: string | null;
  transaction?: RuntimeConnectionStorageTransaction;
}

export interface StorageWriteCompensation {
  compensate(): Promise<boolean>;
}

export interface StorageWriteValidationOptions {
  /**
   * Defaults to true for transactional writes. Terminal credential scrubs set
   * this false: once A is removed, a newer marker must never resurrect A.
   */
  compensateOnValidationFailure?: boolean;
  /** Opaque, identity-branded capability for the owning connection WAL. */
  runtimeConnectionTransaction?: RuntimeConnectionStorageTransaction;
  validate?: () => boolean;
}

export interface StorageRemovalValidationOptions {
  validate?: () => boolean;
}

const RUNTIME_CONNECTION_STORAGE_TRANSACTION = Symbol(
  "runtime-connection-storage-transaction",
);

export interface RuntimeConnectionStorageParticipant {
  key: string;
  value: string;
}

export interface RuntimeConnectionStorageTransaction {
  readonly [RUNTIME_CONNECTION_STORAGE_TRANSACTION]: true;
  readonly transactionId: string;
}

type RuntimeConnectionTransactionPhase =
  | "prepared"
  | "committed"
  | "aborted"
  | "finished";

interface RuntimeConnectionTransactionReceiptState {
  phase: RuntimeConnectionTransactionPhase;
  transaction: RuntimeConnectionStorageTransactionState;
}

interface RuntimeConnectionTransactionReceiptEntry {
  authority: ProtectedStoreRollbackAuthority;
  kind: DesktopConnectionTransactionKind;
  state: RuntimeConnectionTransactionReceiptState;
}

interface RuntimeConnectionStorageTransactionState
  extends RuntimeConnectionStorageTransaction {
  abortPromise: Promise<boolean> | null;
  compensationPromise: Promise<boolean> | null;
  epoch: string;
  participants: Map<string, string>;
  phase: RuntimeConnectionTransactionPhase;
  receipts: Map<string, RuntimeConnectionTransactionReceiptEntry>;
  sealedMutationVersions: Map<string, number | undefined> | null;
  stewardPredecessorScope: { value: string | null } | null;
}

interface PendingRuntimeConnectionTransactionPrepare {
  epoch: string | null;
  inFlight: boolean;
  participants: Array<{
    kind: DesktopConnectionTransactionKind;
    value: string;
  }>;
  transactionId: string;
}

let activeRuntimeConnectionTransaction: RuntimeConnectionStorageTransactionState | null =
  null;
let pendingRuntimeConnectionTransactionPrepare: PendingRuntimeConnectionTransactionPrepare | null =
  null;

const DESKTOP_SECURE_STORE_RPC_ATTEMPTS = 3;
const DESKTOP_SECURE_STORE_MAX_VALUE_BYTES = 256 * 1024;
export const PROTECTED_STORAGE_CACHE_LEASE_MS = 30_000;
const PROTECTED_STORAGE_CACHE_RENEW_AFTER_MS =
  PROTECTED_STORAGE_CACHE_LEASE_MS / 2;
let protectedStorageMutationIdSequence = 0;

class ProtectedStorageWriteSupersededError extends Error {
  constructor(key: string) {
    super(`Desktop protected storage write was superseded for ${key}`);
    this.name = "ProtectedStorageWriteSupersededError";
  }
}

function runtimeConnectionTransactionCapability(
  transaction: RuntimeConnectionStorageTransactionState | null | undefined,
  key: string,
): { epoch: string; transactionId: string } | null {
  if (!transaction) return null;
  const active = requireActiveRuntimeConnectionTransaction(transaction);
  if (active.phase !== "prepared" && active.phase !== "committed") {
    throw new Error("Runtime connection storage transaction is not usable");
  }
  if (!active.participants.has(key)) {
    throw new Error(
      `Protected storage key is not a runtime connection participant: ${key}`,
    );
  }
  return { epoch: active.epoch, transactionId: active.transactionId };
}

function runtimeConnectionKindForKey(
  key: string,
): DesktopConnectionTransactionKind | null {
  const kind = PROTECTED_STORAGE_KIND.get(key);
  return kind === "runtime.agent_profiles" ||
    kind === "runtime.active_server" ||
    kind === "session.steward_token"
    ? kind
    : null;
}

async function retryDesktopConnectionTransactionRequest<T>(
  operation: () => Promise<T | null>,
  unavailableMessage: string,
): Promise<T> {
  let lastError: unknown = new Error(unavailableMessage);
  for (
    let attempt = 0;
    attempt < DESKTOP_SECURE_STORE_RPC_ATTEMPTS;
    attempt += 1
  ) {
    try {
      const result = await operation();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

async function prepareRuntimeConnectionTransaction(
  pending: PendingRuntimeConnectionTransactionPrepare,
): Promise<{ ok: true; epoch: string }> {
  try {
    return await retryDesktopConnectionTransactionRequest(
      () =>
        desktopConnectionTransactionBegin(
          pending.transactionId,
          pending.participants,
        ),
      "Desktop runtime connection transaction prepare is unavailable",
    );
  } catch (beginError) {
    // error-policy:J2 BEGIN may have durably prepared the WAL even when every
    // response was lost, so recover its owner-scoped epoch before rethrowing.
    let status: NonNullable<
      Awaited<ReturnType<typeof desktopConnectionTransactionStatus>>
    >;
    try {
      status = await retryDesktopConnectionTransactionRequest(
        () => desktopConnectionTransactionStatus(pending.transactionId),
        "Desktop runtime connection transaction status is unavailable",
      );
    } catch (statusError) {
      // error-policy:J2 preserve both transport failures while the caller
      // retains the transaction identity for a later recovery attempt.
      throw new AggregateError(
        [beginError, statusError],
        "Desktop runtime connection transaction prepare outcome is ambiguous",
      );
    }
    if (status.status !== "prepared") throw beginError;
    return { ok: true, epoch: status.epoch };
  }
}

async function retirePendingRuntimeConnectionTransaction(): Promise<void> {
  const pending = pendingRuntimeConnectionTransactionPrepare;
  if (!pending) return;
  if (pending.inFlight) {
    throw new Error(
      "A runtime connection storage transaction prepare is already in progress",
    );
  }
  pending.inFlight = true;
  try {
    let epoch = pending.epoch;
    if (!epoch) {
      try {
        const status = await retryDesktopConnectionTransactionRequest(
          () => desktopConnectionTransactionStatus(pending.transactionId),
          "Desktop runtime connection transaction status is unavailable",
        );
        if (status.status === "aborted") {
          if (pendingRuntimeConnectionTransactionPrepare === pending) {
            pendingRuntimeConnectionTransactionPrepare = null;
          }
          return;
        }
        if (status.status !== "prepared") {
          throw new Error(
            `Ambiguous runtime connection transaction cannot be retired from ${status.status}`,
          );
        }
        epoch = status.epoch;
      } catch (statusError) {
        // error-policy:J2 STATUS is attempted before replaying BEGIN because the
        // production handler fences BEGIN while this owner's WAL is active. If
        // no WAL was written, replaying the exact validated intent can create a
        // transaction that is immediately retired instead.
        try {
          epoch = (await prepareRuntimeConnectionTransaction(pending)).epoch;
        } catch (prepareError) {
          throw new AggregateError(
            [statusError, prepareError],
            "Desktop runtime connection transaction retirement outcome is ambiguous",
          );
        }
      }
    }
    pending.epoch = epoch;
    try {
      const result = await retryDesktopConnectionTransactionRequest(
        () =>
          desktopConnectionTransactionAbort(pending.transactionId, epoch, []),
        "Desktop runtime connection transaction abort is unavailable",
      );
      if (!result.aborted || result.committed) {
        throw new Error(
          "Ambiguous runtime connection transaction could not be aborted",
        );
      }
    } catch (abortError) {
      // error-policy:J2 ABORT may have released the WAL after every response
      // was lost; confirm the owner/epoch-bound terminal state before clearing.
      let status: NonNullable<
        Awaited<ReturnType<typeof desktopConnectionTransactionStatus>>
      >;
      try {
        status = await retryDesktopConnectionTransactionRequest(
          () =>
            desktopConnectionTransactionStatus(pending.transactionId, epoch),
          "Desktop runtime connection transaction status is unavailable",
        );
      } catch (statusError) {
        // error-policy:J2 keep the pending identity and epoch retryable while
        // reporting both failures to the caller.
        throw new AggregateError(
          [abortError, statusError],
          "Desktop runtime connection transaction retirement outcome is ambiguous",
        );
      }
      if (status.status !== "aborted") throw abortError;
    }
    if (pendingRuntimeConnectionTransactionPrepare === pending) {
      pendingRuntimeConnectionTransactionPrepare = null;
    }
  } finally {
    if (pendingRuntimeConnectionTransactionPrepare === pending) {
      pending.inFlight = false;
    }
  }
}

function requireActiveRuntimeConnectionTransaction(
  transaction: RuntimeConnectionStorageTransaction,
): RuntimeConnectionStorageTransactionState {
  const active = activeRuntimeConnectionTransaction;
  if (
    !active ||
    active !== transaction ||
    transaction[RUNTIME_CONNECTION_STORAGE_TRANSACTION] !== true
  ) {
    throw new Error(
      "Runtime connection storage transaction is no longer active",
    );
  }
  return active;
}

export async function beginRuntimeConnectionStorageTransaction(
  participants: readonly RuntimeConnectionStorageParticipant[],
): Promise<RuntimeConnectionStorageTransaction | null> {
  if (isNativePlatform() || !isElectrobunRuntime()) return null;
  if (pendingRuntimeConnectionTransactionPrepare) {
    await retirePendingRuntimeConnectionTransaction();
  }
  if (activeRuntimeConnectionTransaction) {
    throw new Error(
      "A runtime connection storage transaction is already active",
    );
  }
  const mapped = participants.map((participant) => {
    const kind = runtimeConnectionKindForKey(participant.key);
    if (!kind) {
      throw new Error(
        `Protected storage key cannot join a runtime connection transaction: ${participant.key}`,
      );
    }
    if (
      typeof participant.value !== "string" ||
      participant.value.length === 0 ||
      new TextEncoder().encode(participant.value).byteLength >
        DESKTOP_SECURE_STORE_MAX_VALUE_BYTES
    ) {
      throw new Error(
        "Runtime connection transaction participant value is missing or too large",
      );
    }
    return { key: participant.key, kind, value: participant.value };
  });
  if (mapped.length === 0) {
    throw new Error("Runtime connection transaction participants are missing");
  }
  if (
    new Set(mapped.map((participant) => participant.kind)).size !==
    mapped.length
  ) {
    throw new Error(
      "Runtime connection transaction contains duplicate participants",
    );
  }
  const pending: PendingRuntimeConnectionTransactionPrepare = {
    epoch: null,
    inFlight: true,
    participants: mapped.map(({ kind, value }) => ({ kind, value })),
    transactionId: crypto.randomUUID(),
  };
  pendingRuntimeConnectionTransactionPrepare = pending;
  let result: { ok: true; epoch: string };
  try {
    result = await prepareRuntimeConnectionTransaction(pending);
    pending.epoch = result.epoch;
  } finally {
    pending.inFlight = false;
  }
  pendingRuntimeConnectionTransactionPrepare = null;
  const transaction: RuntimeConnectionStorageTransactionState = {
    [RUNTIME_CONNECTION_STORAGE_TRANSACTION]: true,
    abortPromise: null,
    compensationPromise: null,
    epoch: result.epoch,
    participants: new Map(
      mapped.map((participant) => [participant.key, participant.value]),
    ),
    phase: "prepared",
    receipts: new Map(),
    sealedMutationVersions: null,
    stewardPredecessorScope: null,
    transactionId: pending.transactionId,
  };
  activeRuntimeConnectionTransaction = transaction;
  return transaction;
}

async function stageActiveRuntimeConnectionParticipant(
  transaction: RuntimeConnectionStorageTransactionState | null | undefined,
  key: string,
  value: string,
): Promise<void> {
  if (!transaction) return;
  requireActiveRuntimeConnectionTransaction(transaction);
  if (transaction.phase !== "prepared") {
    throw new Error(
      "Runtime connection transaction is no longer accepting participants",
    );
  }
  const kind = runtimeConnectionKindForKey(key);
  if (!kind) return;
  const existing = transaction.participants.get(key);
  if (existing !== undefined) {
    if (existing !== value) {
      throw new Error("Runtime connection transaction participant changed");
    }
    return;
  }
  await retryDesktopConnectionTransactionRequest(
    () =>
      desktopConnectionTransactionStage(
        transaction.transactionId,
        transaction.epoch,
        {
          kind,
          value,
        },
      ),
    "Desktop runtime connection transaction staging is unavailable",
  );
  transaction.participants.set(key, value);
}

function registerRuntimeConnectionTransactionReceipt(
  transaction: RuntimeConnectionStorageTransactionState | null | undefined,
  key: string,
  value: string,
  authority: ProtectedStoreRollbackAuthority,
): boolean {
  if (transaction?.phase !== "prepared") return false;
  requireActiveRuntimeConnectionTransaction(transaction);
  const expected = transaction.participants.get(key);
  const kind = runtimeConnectionKindForKey(key);
  if (expected !== value || !kind) return false;
  const existing = transaction.receipts.get(key);
  if (existing) {
    if (existing.authority.receipt !== authority.receipt) {
      throw new Error("Runtime connection participant received two receipts");
    }
    authority.transactionReceipt = existing.state;
    return true;
  }
  const state: RuntimeConnectionTransactionReceiptState = {
    phase: "prepared",
    transaction,
  };
  authority.transactionReceipt = state;
  transaction.receipts.set(key, { authority, kind, state });
  return true;
}

async function refreshRuntimeConnectionTransactionCache(
  transaction: RuntimeConnectionStorageTransactionState,
  useTransactionCapability = true,
): Promise<void> {
  const snapshots = await Promise.all(
    Array.from(transaction.participants.keys(), async (key) => {
      let scope: string | null | undefined;
      const value = await protectedStoreGet(
        key,
        useTransactionCapability ? transaction : null,
        (nextScope) => {
          scope = nextScope;
        },
      );
      return [key, value, scope] as const;
    }),
  );
  for (const [key, value] of snapshots) {
    if (value === null) invalidateProtectedStorageCache(key);
    else cacheProtectedStorageValue(key, value);
  }
  const tokenSnapshot = snapshots.find(([key]) => key === STEWARD_TOKEN_KEY);
  if (tokenSnapshot?.[2] !== undefined) {
    // Token first, scope second: an intercalated synchronous read is at worst
    // quarantined (B token + A scope), never old token A authorized by scope B.
    synchronizeStewardTokenScope(tokenSnapshot[2]);
  }
}

export async function decideRuntimeConnectionStorageTransaction(
  transaction: RuntimeConnectionStorageTransaction,
): Promise<void> {
  const active = requireActiveRuntimeConnectionTransaction(transaction);
  if (active.phase === "committed") return;
  if (active.phase !== "prepared") {
    throw new Error("Runtime connection storage transaction cannot commit");
  }
  const receipts = Array.from(active.participants.keys(), (key) => {
    const receipt = active.receipts.get(key);
    if (!receipt) {
      throw new Error(
        `Runtime connection transaction receipt is missing for ${key}`,
      );
    }
    return {
      kind: receipt.kind,
      rollbackReceipt: receipt.authority.receipt,
    };
  });
  const decision = await retryDesktopConnectionTransactionRequest(
    () =>
      desktopConnectionTransactionDecide(
        active.transactionId,
        active.epoch,
        receipts,
      ),
    "Desktop runtime connection transaction decision is unavailable",
  );
  if (decision.epoch !== active.epoch) {
    throw new Error("Desktop runtime connection transaction epoch changed");
  }
  const revisionByKind = new Map<DesktopConnectionTransactionKind, number>();
  for (const entry of decision.revisions) {
    if (
      revisionByKind.has(entry.kind) ||
      !Number.isSafeInteger(entry.revision) ||
      entry.revision < 0
    ) {
      throw new Error(
        "Desktop runtime connection transaction revisions are invalid",
      );
    }
    revisionByKind.set(entry.kind, entry.revision);
  }
  if (revisionByKind.size !== active.receipts.size) {
    throw new Error(
      "Desktop runtime connection transaction revisions are incomplete",
    );
  }
  active.phase = "committed";
  for (const [key, receipt] of active.receipts) {
    const revision = revisionByKind.get(receipt.kind);
    if (revision === undefined) {
      throw new Error(
        "Desktop runtime connection transaction revision is missing",
      );
    }
    receipt.authority.setRevision = revision;
    receipt.state.phase = "committed";
    acceptProtectedStorageHostRevision(key, revision);
  }
  // Read every participant first, then publish the cache as one synchronous
  // batch. No participant cache becomes authoritative before the WAL decision.
  await refreshRuntimeConnectionTransactionCache(active);
}

export async function finishRuntimeConnectionStorageTransaction(
  transaction: RuntimeConnectionStorageTransaction,
): Promise<void> {
  const settled = transaction as RuntimeConnectionStorageTransactionState;
  if (settled.phase === "finished") return;
  if (settled.phase === "aborted") {
    throw new Error("Runtime connection storage transaction was aborted");
  }
  const active = requireActiveRuntimeConnectionTransaction(transaction);
  if (active.phase === "prepared") {
    await decideRuntimeConnectionStorageTransaction(active);
  }
  if (active.phase !== "committed") {
    throw new Error("Runtime connection storage transaction cannot finish");
  }
  try {
    await retryDesktopConnectionTransactionRequest(
      () =>
        desktopConnectionTransactionFinish(active.transactionId, active.epoch),
      "Desktop runtime connection transaction finalization is unavailable",
    );
  } catch (finishError) {
    const status = await retryDesktopConnectionTransactionRequest(
      () =>
        desktopConnectionTransactionStatus(active.transactionId, active.epoch),
      "Desktop runtime connection transaction status is unavailable",
    );
    if (status.status !== "finished") throw finishError;
  }
  active.phase = "finished";
  for (const receipt of active.receipts.values()) {
    receipt.state.phase = "finished";
  }
  active.sealedMutationVersions = new Map(
    Array.from(active.participants.keys(), (key) => [
      key,
      protectedStorageMutationVersion.get(key),
    ]),
  );
  activeRuntimeConnectionTransaction = null;
}

export async function abortRuntimeConnectionStorageTransaction(
  transaction: RuntimeConnectionStorageTransaction,
): Promise<boolean> {
  const settled = transaction as RuntimeConnectionStorageTransactionState;
  if (settled.phase === "aborted") return true;
  if (settled.phase === "finished") return false;
  if (settled.abortPromise) return settled.abortPromise;
  const active = requireActiveRuntimeConnectionTransaction(transaction);
  const operation = (async () => {
    if (active.stewardPredecessorScope) {
      // Publish/quarantine the legacy token's predecessor scope before the
      // host can restore raw token A and clear its aborting WAL. A crash before
      // this RPC still recovers committed bundle B/scope B; a crash after it
      // observes only A/scope A (or fail-closed null), never A/scope B.
      synchronizeStewardTokenScope(active.stewardPredecessorScope.value);
    }
    const receipts = Array.from(active.receipts.values(), (receipt) => ({
      kind: receipt.kind,
      rollbackReceipt: receipt.authority.receipt,
    }));
    const result = await retryDesktopConnectionTransactionRequest(
      () =>
        desktopConnectionTransactionAbort(
          active.transactionId,
          active.epoch,
          receipts,
        ),
      "Desktop runtime connection transaction abort is unavailable",
    ).catch(async (abortError) => {
      const status = await retryDesktopConnectionTransactionRequest(
        () =>
          desktopConnectionTransactionStatus(
            active.transactionId,
            active.epoch,
          ),
        "Desktop runtime connection transaction status is unavailable",
      );
      if (status.status === "aborted") {
        return { ok: true as const, aborted: true, committed: false };
      }
      if (status.status === "finished") {
        return { ok: true as const, aborted: false, committed: true };
      }
      throw abortError;
    });
    if (!result.aborted) {
      if (result.committed) {
        active.phase = "finished";
        for (const receipt of active.receipts.values()) {
          receipt.state.phase = "finished";
        }
        active.sealedMutationVersions = new Map(
          Array.from(active.participants.keys(), (key) => [
            key,
            protectedStorageMutationVersion.get(key),
          ]),
        );
        activeRuntimeConnectionTransaction = null;
      }
      return false;
    }
    active.phase = "aborted";
    for (const receipt of active.receipts.values()) {
      receipt.state.phase = "aborted";
    }
    activeRuntimeConnectionTransaction = null;
    await refreshRuntimeConnectionTransactionCache(active, false);
    return true;
  })();
  settled.abortPromise = operation;
  void operation.catch(() => {
    if (settled.abortPromise === operation) settled.abortPromise = null;
  });
  return operation;
}

async function compensateFinishedRuntimeConnectionStorageTransaction(
  transaction: RuntimeConnectionStorageTransactionState,
): Promise<boolean> {
  if (transaction.phase === "aborted") return true;
  if (transaction.phase !== "finished") {
    return abortRuntimeConnectionStorageTransaction(transaction);
  }
  if (transaction.compensationPromise) return transaction.compensationPromise;

  // Snapshot all renderer mutation authorities synchronously before the first
  // await. If C has even started locally after B was sealed, B's reverse
  // authority is obsolete; the host independently revokes it for every later
  // participant mutation, including same-byte ABA writes from other renderers.
  const sealed = transaction.sealedMutationVersions;
  if (
    !sealed ||
    Array.from(sealed).some(
      ([key, version]) => protectedStorageMutationVersion.get(key) !== version,
    )
  ) {
    return false;
  }

  const receipts = Array.from(transaction.receipts.values(), (receipt) => ({
    expectedRevision: receipt.authority.setRevision,
    kind: receipt.kind,
    rollbackReceipt: receipt.authority.receipt,
  }));
  if (receipts.length !== transaction.participants.size) return false;

  if (transaction.stewardPredecessorScope) {
    // Same crash-safe ordering as forward abort: publish/quarantine legacy A's
    // scope before the host can atomically reverse the secure token bundle.
    synchronizeStewardTokenScope(transaction.stewardPredecessorScope.value);
  }
  const operation = (async () => {
    let result: NonNullable<
      Awaited<ReturnType<typeof desktopConnectionTransactionCompensate>>
    >;
    try {
      result = await retryDesktopConnectionTransactionRequest(
        () =>
          desktopConnectionTransactionCompensate(
            transaction.transactionId,
            transaction.epoch,
            receipts,
          ),
        "Desktop runtime connection transaction compensation is unavailable",
      );
    } catch (compensationError) {
      // The reverse WAL may have committed and published all host revisions
      // even if every COMPENSATE response was lost. Resolve that ambiguity
      // from the owner/epoch-bound tombstone, then still publish A into the
      // renderer caches and live client before resolving the compensation.
      let status: NonNullable<
        Awaited<ReturnType<typeof desktopConnectionTransactionStatus>>
      >;
      try {
        status = await retryDesktopConnectionTransactionRequest(
          () =>
            desktopConnectionTransactionStatus(
              transaction.transactionId,
              transaction.epoch,
            ),
          "Desktop runtime connection transaction status is unavailable",
        );
      } catch (statusError) {
        throw new AggregateError(
          [compensationError, statusError],
          "Desktop runtime connection compensation outcome is ambiguous",
        );
      }
      if (status.status !== "compensated" || !status.revisions) {
        throw compensationError;
      }
      result = {
        ok: true,
        compensated: true,
        revisions: status.revisions,
      };
    }
    const revisionByKind = new Map(
      result.revisions.map((entry) => [entry.kind, entry.revision]),
    );
    if (revisionByKind.size !== receipts.length) {
      throw new Error(
        "Desktop runtime connection compensation revisions are incomplete",
      );
    }
    transaction.phase = "aborted";
    for (const [key, receipt] of transaction.receipts) {
      const revision = revisionByKind.get(receipt.kind);
      if (!Number.isSafeInteger(revision)) {
        throw new Error(
          "Desktop runtime connection compensation revision is invalid",
        );
      }
      receipt.authority.setRevision = revision as number;
      receipt.state.phase = "aborted";
      acceptProtectedStorageHostRevision(key, revision);
    }
    await refreshRuntimeConnectionTransactionCache(transaction, false);
    return true;
  })();
  transaction.compensationPromise = operation;
  void operation.catch(() => {
    if (transaction.compensationPromise === operation) {
      transaction.compensationPromise = null;
    }
  });
  return operation;
}

function invalidateProtectedStorageCache(key: string): void {
  protectedStorageCache.delete(key);
  protectedStorageCacheValidatedAt.delete(key);
  const timer = protectedStorageLeaseTimers.get(key);
  if (timer !== undefined) {
    clearTimeout(timer);
    protectedStorageLeaseTimers.delete(key);
  }
}

function cacheProtectedStorageValue(key: string, value: string): void {
  protectedStorageCache.set(key, value);
  if (isElectrobunRuntime() && !isNativePlatform()) {
    protectedStorageCacheValidatedAt.set(key, Date.now());
    scheduleProtectedStorageLeaseRenewal(key);
  }
}

type ProtectedStorageLeaseRefreshResult =
  | "renewed"
  | "invalidated"
  | "unavailable";

function scheduleProtectedStorageLeaseExpiry(
  key: string,
  validatedAt: number,
): void {
  const currentTimer = protectedStorageLeaseTimers.get(key);
  if (currentTimer !== undefined) clearTimeout(currentTimer);
  const remaining = Math.max(
    0,
    validatedAt + PROTECTED_STORAGE_CACHE_LEASE_MS - Date.now(),
  );
  const timer = setTimeout(() => {
    if (protectedStorageLeaseTimers.get(key) !== timer) return;
    protectedStorageLeaseTimers.delete(key);
    if (protectedStorageCacheValidatedAt.get(key) !== validatedAt) return;
    if (Date.now() - validatedAt >= PROTECTED_STORAGE_CACHE_LEASE_MS) {
      invalidateProtectedStorageCache(key);
      return;
    }
    // A clock adjustment can make a timer run before the absolute lease bound.
    // Re-arm only for the remaining part of the original lease; a failed poll
    // never extends credential authority.
    scheduleProtectedStorageLeaseExpiry(key, validatedAt);
  }, remaining);
  protectedStorageLeaseTimers.set(key, timer);
}

function scheduleProtectedStorageLeaseRenewal(key: string): void {
  const validatedAt = protectedStorageCacheValidatedAt.get(key);
  if (
    validatedAt === undefined ||
    !isElectrobunRuntime() ||
    isNativePlatform()
  ) {
    return;
  }
  const currentTimer = protectedStorageLeaseTimers.get(key);
  if (currentTimer !== undefined) clearTimeout(currentTimer);
  const remaining = Math.max(
    0,
    validatedAt + PROTECTED_STORAGE_CACHE_RENEW_AFTER_MS - Date.now(),
  );
  const timer = setTimeout(() => {
    if (protectedStorageLeaseTimers.get(key) !== timer) return;
    protectedStorageLeaseTimers.delete(key);
    startProtectedStorageLeaseRefresh(key);
  }, remaining);
  protectedStorageLeaseTimers.set(key, timer);
}

async function refreshProtectedStorageCacheLease(
  key: string,
): Promise<ProtectedStorageLeaseRefreshResult> {
  const kind = PROTECTED_STORAGE_KIND.get(key);
  const expectedValue = protectedStorageCache.get(key);
  const expectedRevision = protectedStorageHostRevision.get(key) ?? 0;
  const expectedValidatedAt = protectedStorageCacheValidatedAt.get(key);
  if (
    !kind ||
    expectedValue === undefined ||
    expectedValidatedAt === undefined
  ) {
    return "invalidated";
  }
  // Background timer throttling must not turn an already-expired cache entry
  // back into an authorised credential when the renderer wakes up.
  if (Date.now() - expectedValidatedAt >= PROTECTED_STORAGE_CACHE_LEASE_MS) {
    invalidateProtectedStorageCache(key);
    return "invalidated";
  }
  try {
    const result = await desktopSecureStoreRevision(kind, undefined);
    if (
      !result?.ok ||
      !Number.isSafeInteger(result.revision) ||
      result.revision < 0
    ) {
      return "unavailable";
    }
    if (result.revision !== expectedRevision) {
      if (result.revision > expectedRevision) {
        protectedStorageHostRevision.set(key, result.revision);
      }
      invalidateProtectedStorageCache(key);
      return "invalidated";
    }
    if (Date.now() - expectedValidatedAt >= PROTECTED_STORAGE_CACHE_LEASE_MS) {
      invalidateProtectedStorageCache(key);
      return "invalidated";
    }
    if (
      protectedStorageCache.get(key) === expectedValue &&
      (protectedStorageHostRevision.get(key) ?? 0) === expectedRevision &&
      protectedStorageCacheValidatedAt.get(key) === expectedValidatedAt
    ) {
      protectedStorageCacheValidatedAt.set(key, Date.now());
      return "renewed";
    }
    return "invalidated";
  } catch {
    // error-policy:J4 a failed secret-free lease check leaves the old
    // validation timestamp untouched; the synchronous facade then expires to
    // null at the fixed bound instead of serving stale credentials forever.
    return "unavailable";
  }
}

function startProtectedStorageLeaseRefresh(key: string): void {
  if (protectedStorageLeaseRefreshes.has(key)) return;
  const refresh = refreshProtectedStorageCacheLease(key)
    .then((result) => {
      if (result === "renewed") {
        scheduleProtectedStorageLeaseRenewal(key);
        return;
      }
      if (result === "unavailable") {
        const validatedAt = protectedStorageCacheValidatedAt.get(key);
        if (validatedAt !== undefined) {
          scheduleProtectedStorageLeaseExpiry(key, validatedAt);
        }
      }
    })
    .finally(() => {
      if (protectedStorageLeaseRefreshes.get(key) === refresh) {
        protectedStorageLeaseRefreshes.delete(key);
      }
    });
  protectedStorageLeaseRefreshes.set(key, refresh);
}

function readProtectedStorageCache(key: string): string | null {
  const value = protectedStorageCache.get(key);
  if (value === undefined) return null;
  if (!isElectrobunRuntime() || isNativePlatform()) return value;

  const validatedAt = protectedStorageCacheValidatedAt.get(key) ?? 0;
  const age = Date.now() - validatedAt;
  if (age >= PROTECTED_STORAGE_CACHE_LEASE_MS) {
    invalidateProtectedStorageCache(key);
    return null;
  }
  if (
    age >= PROTECTED_STORAGE_CACHE_RENEW_AFTER_MS &&
    !protectedStorageLeaseRefreshes.has(key)
  ) {
    startProtectedStorageLeaseRefresh(key);
  }
  return value;
}

function acceptProtectedStorageHostRevision(
  key: string,
  revision: number | undefined,
): boolean {
  // Backward-compatible while a renderer and host from adjacent desktop
  // builds briefly overlap during an update. Current hosts always provide it.
  if (revision === undefined) {
    return (protectedStorageHostRevision.get(key) ?? 0) === 0;
  }
  if (!Number.isSafeInteger(revision) || revision < 0) return false;
  const knownRevision = protectedStorageHostRevision.get(key) ?? 0;
  if (revision < knownRevision) return false;
  protectedStorageHostRevision.set(key, revision);
  return true;
}

function handleProtectedStorageHostInvalidation(payload: unknown): void {
  if (!payload || typeof payload !== "object") return;
  const { kind, revision } = payload as Partial<DesktopSecureStoreChangedEvent>;
  if (
    typeof kind !== "string" ||
    !Number.isSafeInteger(revision) ||
    (revision ?? -1) < 0
  ) {
    return;
  }
  const key = PROTECTED_STORAGE_KEY.get(kind as DesktopSecureStoreKind);
  if (!key) return;
  const knownRevision = protectedStorageHostRevision.get(key) ?? 0;
  if ((revision as number) <= knownRevision) return;
  protectedStorageHostRevision.set(key, revision as number);
  // Never broadcast credential values. A revision advance makes the sync
  // localStorage facade fail closed until this renderer performs an awaited
  // secureStoreGet and repopulates from the host-authoritative snapshot.
  invalidateProtectedStorageCache(key);
}

function markProtectedStorageMutation(key: string): number {
  const version = (protectedStorageMutationVersion.get(key) ?? 0) + 1;
  protectedStorageMutationVersion.set(key, version);
  return version;
}

function createProtectedStorageMutationId(): string {
  const cryptoApi = globalThis.crypto;
  if (typeof cryptoApi?.randomUUID === "function") {
    return cryptoApi.randomUUID();
  }
  if (typeof cryptoApi?.getRandomValues === "function") {
    const entropy = new Uint32Array(4);
    cryptoApi.getRandomValues(entropy);
    return Array.from(entropy, (part) =>
      part.toString(16).padStart(8, "0"),
    ).join("");
  }
  // Mutation ids are scoped to one host-owned renderer endpoint. A monotonic
  // per-renderer fallback remains collision-free inside that authority even on
  // older WebViews without randomUUID/getRandomValues.
  protectedStorageMutationIdSequence += 1;
  return `renderer-mutation-${protectedStorageMutationIdSequence}`;
}

/** Orders native mutations for one logical credential without coupling keys. */
function serializeProtectedStorageMutation<T>(
  key: string,
  operation: () => Promise<T>,
): Promise<T> {
  const predecessor =
    protectedStorageMutationTail.get(key) ?? Promise.resolve();
  const result = predecessor.catch(() => undefined).then(operation);
  const tail = result.then(
    () => undefined,
    () => undefined,
  );
  protectedStorageMutationTail.set(key, tail);
  void tail.then(() => {
    if (protectedStorageMutationTail.get(key) === tail) {
      protectedStorageMutationTail.delete(key);
    }
  });
  return result;
}

function serializedProtectedStoreSet(
  key: string,
  value: string,
  transaction?: RuntimeConnectionStorageTransactionState | null,
  stewardScope?: string | null,
): Promise<ProtectedStoreSetResult> {
  return serializeProtectedStorageMutation(key, async () => {
    const storedValue = encodeProtectedStorageValue(key, value, stewardScope);
    if (isNativePlatform()) {
      return {
        ...(await nativeProtectedStoreSetWithCompensation(key, value)),
        storedValue,
      };
    }
    const result = await protectedStoreSet(key, storedValue, transaction);
    if (!result.stored) {
      if (result.rollbackReceipt) {
        await rollbackFailedDesktopProtectedStoreSet(key, result, transaction);
      }
      return { stored: false, rollbackReceipt: null };
    }
    try {
      if ((await protectedStoreGet(key, transaction)) === value) {
        return { ...result, storedValue };
      }
    } catch (readbackError) {
      // Electrobun's set and get are separate renderer→host RPCs. A set may
      // therefore commit successfully before the readback transport fails.
      // Keep the opaque set receipt live long enough to undo that exact host
      // mutation; otherwise the caller sees a rejected login while the token
      // silently survives in the OS credential store and returns on restart.
      await rollbackFailedDesktopProtectedStoreSet(key, result, transaction);
      throw readbackError;
    }

    // A readable but mismatched value is also a failed publication. Roll the
    // exact write back when it still owns the slot; the host CAS preserves a
    // newer renderer mutation when this receipt has already gone stale.
    await rollbackFailedDesktopProtectedStoreSet(key, result, transaction);
    return { stored: false, rollbackReceipt: null };
  });
}

function serializedProtectedStoreDelete(key: string): Promise<void> {
  return serializeProtectedStorageMutation(key, () =>
    protectedStoreDelete(key),
  );
}

function compareAndRestoreProtectedStorageCache(
  key: string,
  expectedValue: string,
  restoreValue: string | null,
): void {
  if (protectedStorageCache.get(key) !== expectedValue) return;
  if (restoreValue === null) {
    invalidateProtectedStorageCache(key);
  } else {
    cacheProtectedStorageValue(key, restoreValue);
  }
}

function applyProtectedStorageHostSnapshot(
  key: string,
  value: string | null,
  revision: number | undefined,
): void {
  if (!acceptProtectedStorageHostRevision(key, revision)) return;
  if (value === null) {
    invalidateProtectedStorageCache(key);
  } else {
    const decoded = decodeProtectedStorageValue(key, value);
    cacheProtectedStorageValue(key, decoded.value);
    if (decoded.scope !== undefined) {
      synchronizeStewardTokenScope(decoded.scope);
    }
  }
}

function compareAndRestoreStorageValue(
  key: string,
  expectedValue: string,
  restoreValue: string | null,
  rollbackReceipt: string | null = null,
): Promise<boolean> {
  if (!isProtectedStorageHost() || !PROTECTED_STORAGE_KIND.has(key)) {
    if (window.localStorage.getItem(key) !== expectedValue) {
      return Promise.resolve(false);
    }
    runAsPrivilegedShell(() => {
      if (restoreValue === null) {
        window.localStorage.removeItem(key);
      } else {
        window.localStorage.setItem(key, restoreValue);
      }
    });
    return Promise.resolve(true);
  }

  markProtectedStorageMutation(key);
  return serializeProtectedStorageMutation(key, async () => {
    if (!isNativePlatform() && isElectrobunRuntime()) {
      const kind = PROTECTED_STORAGE_KIND.get(key);
      if (!kind) {
        throw new Error("Protected storage kind is not registered");
      }
      if (!rollbackReceipt) {
        throw new Error(
          "Desktop protected storage rollback receipt is missing",
        );
      }
      const result = await desktopSecureStoreCompareAndRestore(
        kind,
        rollbackReceipt,
        undefined,
      );
      if (!result?.ok) {
        throw new Error("Desktop protected storage rejected rollback");
      }
      if (result.restored) {
        applyProtectedStorageHostSnapshot(key, result.value, result.revision);
      } else {
        acceptProtectedStorageHostRevision(key, result.revision);
        invalidateProtectedStorageCache(key);
      }
      return result.restored;
    }

    const currentValue = await protectedStoreGet(key);
    if (currentValue !== expectedValue) {
      compareAndRestoreProtectedStorageCache(key, expectedValue, currentValue);
      return false;
    }

    if (restoreValue === null) {
      await protectedStoreDelete(key);
      if ((await protectedStoreGet(key)) !== null) {
        throw new Error(`Protected storage rejected rollback for ${key}`);
      }
    } else {
      const restored = await protectedStoreSet(key, restoreValue);
      if (!restored.stored || (await protectedStoreGet(key)) !== restoreValue) {
        throw new Error(`Protected storage rejected rollback for ${key}`);
      }
    }

    compareAndRestoreProtectedStorageCache(key, expectedValue, restoreValue);
    return true;
  });
}

function isProtectedStorageHost(): boolean {
  return isNativePlatform() || isElectrobunRuntime();
}

/** Whether protected runtime/session records require an awaited host write. */
export function isProtectedStorageHostRuntime(): boolean {
  return isProtectedStorageHost();
}

async function protectedStoreGet(
  key: string,
  transaction?: RuntimeConnectionStorageTransactionState | null,
  receiveStewardScope?: (scope: string | null) => void,
): Promise<string | null> {
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) return null;
  if (isNativePlatform()) {
    const { ElizaSecureStore } = await loadNativeSecureStore();
    const result = await ElizaSecureStore.get({ key: kind });
    if (result.ok) {
      if (typeof result.value !== "string") return null;
      const decoded = decodeProtectedStorageValue(key, result.value);
      if (decoded.scope !== undefined) receiveStewardScope?.(decoded.scope);
      return decoded.value;
    }
    if (result.error === "not_found") return null;
    throw new Error("Native protected storage is unavailable");
  }
  if (isElectrobunRuntime()) {
    // A mutation event can overtake an older in-flight get response on another
    // renderer transport. Retry any snapshot whose host revision is older than
    // the invalidation already observed here, so it can never refill the cache
    // with the previous account's credential.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const capability = runtimeConnectionTransactionCapability(
        transaction,
        key,
      );
      const result = await desktopSecureStoreGet(
        kind,
        capability?.transactionId,
        capability?.epoch,
      );
      if (result && !acceptProtectedStorageHostRevision(key, result.revision)) {
        if (attempt < 2) continue;
        throw new Error("Desktop protected storage returned a stale snapshot");
      }
      if (result?.ok) {
        if (typeof result.value !== "string") return null;
        const decoded = decodeProtectedStorageValue(key, result.value);
        if (decoded.scope !== undefined) receiveStewardScope?.(decoded.scope);
        return decoded.value;
      }
      if (result?.reason === "not_found") return null;
      throw new Error("Desktop protected storage is unavailable");
    }
  }
  return null;
}

async function protectedStoreSet(
  key: string,
  value: string,
  transaction?: RuntimeConnectionStorageTransactionState | null,
): Promise<ProtectedStoreSetResult> {
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) return { stored: false, rollbackReceipt: null };
  if (isNativePlatform()) {
    const { ElizaSecureStore } = await loadNativeSecureStore();
    return {
      stored: (await ElizaSecureStore.set({ key: kind, value })).ok,
      rollbackReceipt: null,
    };
  }
  if (isElectrobunRuntime()) {
    const mutationId = createProtectedStorageMutationId();
    let result: Awaited<ReturnType<typeof desktopSecureStoreSet>> = null;
    let lastError: unknown = new Error(
      "Desktop protected storage request is unavailable",
    );
    for (
      let attempt = 0;
      attempt < DESKTOP_SECURE_STORE_RPC_ATTEMPTS;
      attempt += 1
    ) {
      try {
        const capability = runtimeConnectionTransactionCapability(
          transaction,
          key,
        );
        result = await desktopSecureStoreSet(
          kind,
          value,
          mutationId,
          capability?.transactionId,
          capability?.epoch,
        );
        if (result) break;
      } catch (error) {
        lastError = error;
      }
    }
    if (!result) throw lastError;
    if (result) {
      acceptProtectedStorageHostRevision(key, result.revision);
    }
    return result?.ok
      ? {
          stored: true,
          rollbackReceipt: result.rollbackReceipt,
          ...(Number.isSafeInteger(result.revision)
            ? { setRevision: result.revision }
            : {}),
        }
      : {
          stored: false,
          rollbackReceipt: result?.rollbackReceipt ?? null,
          ...(Number.isSafeInteger(result?.revision)
            ? { setRevision: result?.revision }
            : {}),
        };
  }
  return { stored: false, rollbackReceipt: null };
}

/**
 * Capacitor currently exposes no compare-and-swap primitive. Mobile uses one
 * renderer, and this bridge serializes the predecessor read, write, readback,
 * and compensation for each key. That makes exact restoration safe inside the
 * supported single-renderer boundary; a future multi-WebView host must add CAS
 * at the native plugin before sharing this path.
 */
async function nativeProtectedStoreSetWithCompensation(
  key: string,
  value: string,
): Promise<ProtectedStoreSetResult> {
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) return { stored: false, rollbackReceipt: null };
  const predecessor = await protectedStoreGet(key);
  // The native host snapshot is authoritative even before the successor SET
  // can run. Reconcile a stale renderer cache here so a blocked write never
  // exposes credentials that the OS store no longer contains.
  if (predecessor === null) invalidateProtectedStorageCache(key);
  else cacheProtectedStorageValue(key, predecessor);
  const { ElizaSecureStore } = await loadNativeSecureStore();
  let writeError: unknown = null;
  try {
    await ElizaSecureStore.set({ key: kind, value });
  } catch (error) {
    writeError = error;
  }

  let readback: string | null;
  try {
    readback = await protectedStoreGet(key);
    if (readback === value) {
      return { stored: true, rollbackReceipt: null, predecessor };
    }
  } catch (readbackError) {
    await restoreNativeProtectedStorePredecessor(key, predecessor);
    throw readbackError;
  }

  // A readable mismatch is just as authoritative as a failed GET: the write
  // did not publish the requested value. Restore and verify the exact
  // predecessor before exposing failure to the caller.
  await restoreNativeProtectedStorePredecessor(key, predecessor);
  if (writeError) throw writeError;
  return { stored: false, rollbackReceipt: null, predecessor };
}

async function restoreNativeProtectedStorePredecessor(
  key: string,
  predecessor: string | null,
): Promise<void> {
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) throw new Error("Protected storage kind is not registered");
  const { ElizaSecureStore } = await loadNativeSecureStore();
  try {
    if (predecessor === null) {
      await ElizaSecureStore.remove({ key: kind });
    } else {
      await ElizaSecureStore.set({ key: kind, value: predecessor });
    }
  } catch {
    // A native adapter may mutate before throwing. Verification below, rather
    // than the acknowledgement alone, decides whether compensation succeeded.
  }
  if ((await protectedStoreGet(key)) !== predecessor) {
    throw new Error(
      `Native protected storage could not restore predecessor for ${key}`,
    );
  }
}

async function rollbackFailedDesktopProtectedStoreSet(
  key: string,
  result: ProtectedStoreSetResult,
  transaction?: RuntimeConnectionStorageTransactionState | null,
): Promise<void> {
  if (isNativePlatform() || !isElectrobunRuntime() || !result.rollbackReceipt) {
    return;
  }
  if (transaction) {
    await abortRuntimeConnectionStorageTransaction(transaction);
    return;
  }
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) {
    throw new Error("Protected storage kind is not registered");
  }
  const rollback = await desktopSecureStoreCompareAndRestore(
    kind,
    result.rollbackReceipt,
    undefined,
  );
  if (!rollback?.ok) {
    throw new Error(
      `Desktop protected storage could not reconcile failed write for ${key}`,
    );
  }
  applyProtectedStorageHostSnapshot(key, rollback.value, rollback.revision);
}

async function commitDesktopProtectedStoreReceipt(
  key: string,
  authority: ProtectedStoreRollbackAuthority,
  expectedValue: string,
  transaction?: RuntimeConnectionStorageTransactionState | null,
  expectedStoredValue = expectedValue,
): Promise<void> {
  if (isNativePlatform() || !isElectrobunRuntime()) return;
  if (
    registerRuntimeConnectionTransactionReceipt(
      transaction,
      key,
      expectedStoredValue,
      authority,
    )
  ) {
    return;
  }
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) {
    throw new Error("Protected storage kind is not registered");
  }
  let committed: Awaited<ReturnType<typeof desktopSecureStoreCommitReceipt>> =
    null;
  let lastError: unknown = new Error(
    "Desktop protected storage commit request is unavailable",
  );
  for (
    let attempt = 0;
    attempt < DESKTOP_SECURE_STORE_RPC_ATTEMPTS;
    attempt += 1
  ) {
    try {
      committed = await desktopSecureStoreCommitReceipt(
        kind,
        authority.receipt,
        authority.setRevision,
        undefined,
      );
      if (committed) break;
    } catch (error) {
      lastError = error;
    }
  }
  const throwAfterReconciliation = async (commitFailure: unknown) => {
    try {
      await reconcileAmbiguousDesktopProtectedStoreCommit(
        key,
        authority,
        expectedValue,
      );
    } catch (reconciliationError) {
      throw new AggregateError(
        [commitFailure, reconciliationError],
        `Desktop protected storage could not safely reconcile commit for ${key}`,
      );
    }
    throw commitFailure;
  };
  if (!committed) {
    return throwAfterReconciliation(lastError);
  }
  if (!committed.ok) {
    return throwAfterReconciliation(
      new Error(
        `Desktop protected storage could not commit write receipt for ${key}`,
      ),
    );
  }
  acceptProtectedStorageHostRevision(key, committed.revision);
  if (!committed.committed) {
    throw new ProtectedStorageWriteSupersededError(key);
  }
  if (committed.publishable === false) {
    throw new ProtectedStorageWriteSupersededError(key);
  }
  const authoritativeValue = decodeProtectedStorageValue(
    key,
    committed.value,
  ).value;
  if (authoritativeValue !== expectedValue) {
    throw new ProtectedStorageWriteSupersededError(key);
  }
}

async function compensateCommittedDesktopProtectedStoreReceipt(
  key: string,
  authority: ProtectedStoreRollbackAuthority & { expectedToken: string },
  publishSnapshot = true,
): Promise<ProtectedStoreCompensationSnapshot> {
  if (isNativePlatform() || !isElectrobunRuntime()) {
    return { restored: false, value: null };
  }
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) {
    throw new Error("Protected storage kind is not registered");
  }
  let compensation: Awaited<
    ReturnType<typeof desktopSecureStoreCompensateCommittedReceipt>
  > = null;
  let lastError: unknown = new Error(
    "Desktop protected storage compensation request is unavailable",
  );
  for (
    let attempt = 0;
    attempt < DESKTOP_SECURE_STORE_RPC_ATTEMPTS;
    attempt += 1
  ) {
    try {
      compensation = await desktopSecureStoreCompensateCommittedReceipt(
        kind,
        authority.receipt,
        authority.setRevision,
        undefined,
      );
      if (compensation) break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!compensation) throw lastError;
  if (!compensation.ok) {
    throw new Error(
      `Desktop protected storage could not compensate committed receipt for ${key}`,
    );
  }
  if (publishSnapshot || compensation.restored) {
    applyProtectedStorageHostSnapshot(
      key,
      compensation.value,
      compensation.revision,
    );
  }
  // restored:false means a newer revision already owns the slot. That is the
  // correct CAS outcome and must never be overwritten by this older writer.
  return {
    restored: compensation.restored,
    revision: compensation.revision,
    value:
      compensation.value === null
        ? null
        : decodeProtectedStorageValue(key, compensation.value).value,
  };
}

/**
 * Resolve an RPC outcome that cannot distinguish an uncommitted SET from a
 * committed SET whose response was lost. First replay the committed tombstone;
 * if no tombstone owns the exact SET revision, consume the still-live receipt.
 * A newer host revision/value is authoritative and must never be overwritten.
 */
async function reconcileAmbiguousDesktopProtectedStoreCommit(
  key: string,
  authority: { receipt: string; setRevision: number | undefined },
  expectedValue: string,
): Promise<void> {
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) {
    throw new Error("Protected storage kind is not registered");
  }

  let compensationError: unknown = null;
  if (Number.isSafeInteger(authority.setRevision)) {
    try {
      const compensation =
        await compensateCommittedDesktopProtectedStoreReceipt(
          key,
          {
            expectedToken: expectedValue,
            receipt: authority.receipt,
            setRevision: authority.setRevision as number,
          },
          false,
        );
      if (
        compensation.restored ||
        compensation.value !== expectedValue ||
        (Number.isSafeInteger(compensation.revision) &&
          compensation.revision !== authority.setRevision)
      ) {
        return;
      }
    } catch (error) {
      compensationError = error;
    }
  }

  let rollback: Awaited<
    ReturnType<typeof desktopSecureStoreCompareAndRestore>
  > = null;
  let rollbackError: unknown = new Error(
    "Desktop protected storage rollback request is unavailable",
  );
  for (
    let attempt = 0;
    attempt < DESKTOP_SECURE_STORE_RPC_ATTEMPTS;
    attempt += 1
  ) {
    try {
      rollback = await desktopSecureStoreCompareAndRestore(
        kind,
        authority.receipt,
        undefined,
      );
      if (rollback) break;
    } catch (error) {
      rollbackError = error;
    }
  }
  if (rollback?.ok) {
    const rollbackValue =
      rollback.value === null
        ? null
        : decodeProtectedStorageValue(key, rollback.value).value;
    if (rollback.restored) {
      applyProtectedStorageHostSnapshot(key, rollback.value, rollback.revision);
      return;
    }
    if (rollbackValue !== expectedValue) return;
    rollbackError = new Error(
      `Desktop protected storage still contains the ambiguous value for ${key}`,
    );
  } else if (rollback) {
    rollbackError = new Error(
      `Desktop protected storage rejected ambiguous rollback for ${key}`,
    );
  }

  throw compensationError
    ? new AggregateError(
        [compensationError, rollbackError],
        `Desktop protected storage ambiguity could not be reconciled for ${key}`,
      )
    : rollbackError;
}

async function protectedStoreDelete(key: string): Promise<void> {
  const kind = PROTECTED_STORAGE_KIND.get(key);
  if (!kind) {
    throw new Error("Protected storage kind is not registered");
  }
  if (isNativePlatform()) {
    const { ElizaSecureStore } = await loadNativeSecureStore();
    let removalError: unknown = null;
    try {
      await ElizaSecureStore.remove({ key: kind });
    } catch (error) {
      removalError = error;
    }
    // Native acknowledgements are not authoritative: adapters can return
    // ok:true without deleting, or delete and then report an error. The host
    // snapshot alone decides whether the requested absence is durable.
    if ((await protectedStoreGet(key)) === null) return;
    if (removalError) throw removalError;
    throw new Error("Native protected storage rejected deletion");
  }
  if (isElectrobunRuntime()) {
    const result = await desktopSecureStoreDelete(kind, undefined);
    if (result?.ok || result?.reason === "not_found") return;
    throw new Error("Desktop protected storage rejected deletion");
  }
  throw new Error("Protected storage is unavailable");
}

// In-memory cache of values from Preferences (for native)
const preferencesCache = new Map<string, string>();

// Flag to track if initial sync has completed
let initialized = false;
let storageProxyInstalled = false;

interface NativeStorageMethods {
  storage: Storage;
  setItem: (key: string, value: string) => void;
  getItem: (key: string) => string | null;
  removeItem: (key: string) => void;
  prototypeSetItem: Storage["setItem"];
  prototypeGetItem: Storage["getItem"];
  prototypeRemoveItem: Storage["removeItem"];
}

let nativeLocalStorageMethods: NativeStorageMethods | null = null;

function getNativeLocalStorageMethods(): NativeStorageMethods {
  if (nativeLocalStorageMethods) return nativeLocalStorageMethods;
  const storage = window.localStorage;
  const prototype = Object.getPrototypeOf(storage) as Storage;
  const prototypeSetItem = prototype.setItem;
  const prototypeGetItem = prototype.getItem;
  const prototypeRemoveItem = prototype.removeItem;
  nativeLocalStorageMethods = {
    storage,
    // Bind the functions the instance itself resolves rather than the
    // prototype slots. Hosts that hand out `localStorage` through a proxy
    // (jsdom does) reject a prototype method invoked with the proxy as `this`
    // on their branded internal-slot check; the instance-resolved function
    // works on both a proxied and a plain Storage object.
    setItem: storage.setItem.bind(storage),
    getItem: storage.getItem.bind(storage),
    removeItem: storage.removeItem.bind(storage),
    prototypeSetItem,
    prototypeGetItem,
    prototypeRemoveItem,
  };
  return nativeLocalStorageMethods;
}

const PREFERENCE_READ_TIMEOUT_MS = 1_500;
// Warm-up probe before hydration: retry a few times so a cold native bridge
// doesn't drop critical synced keys (first-run-complete, active-server, …).
const PREFERENCE_HYDRATION_ATTEMPTS = 6;
const PREFERENCE_HYDRATION_RETRY_MS = 350;

/**
 * Resolve `true` as soon as the native Preferences plugin answers a call (even
 * with a null value), `false` if it times out (still cold). Used to warm up the
 * bridge before hydration so a cold plugin doesn't silently drop synced keys.
 */
async function preferencesResponded(): Promise<boolean> {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  try {
    const timeout = new Promise<false>((resolve) => {
      timeoutId = setTimeout(() => resolve(false), PREFERENCE_READ_TIMEOUT_MS);
    });
    const { Preferences } = await loadPreferences();
    const probe = Preferences.get({ key: "eliza:first-run-complete" }).then(
      () => true as const,
    );
    return await Promise.race([probe, timeout]);
  } catch {
    // error-policy:J4 probe contract is "did the plugin answer?"; a thrown
    // read means it did not (still cold) — the caller retries.
    return false;
  } finally {
    if (timeoutId !== null) clearTimeout(timeoutId);
  }
}

async function readPreferenceWithTimeout(key: string): Promise<string | null> {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  try {
    const timeout = new Promise<null>((resolve) => {
      timeoutId = setTimeout(() => resolve(null), PREFERENCE_READ_TIMEOUT_MS);
    });
    const { Preferences } = await loadPreferences();
    const result = await Promise.race([Preferences.get({ key }), timeout]);
    return result?.value ?? null;
  } catch {
    // error-policy:J4 hydration read is best-effort; a failed/timed-out read
    // skips this key for the pass. The warm-up probe gates `initialized`, so a
    // cold bridge re-hydrates rather than permanently dropping the key.
    return null;
  } finally {
    if (timeoutId !== null) clearTimeout(timeoutId);
  }
}

/**
 * Initialize the storage bridge
 *
 * On native platforms, this loads values from Capacitor Preferences
 * into the in-memory cache and optionally syncs them to localStorage.
 */
export async function initializeStorageBridge(): Promise<void> {
  if (initialized) {
    return;
  }

  if (!isNativePlatform() && !isElectrobunRuntime()) {
    return;
  }

  const { getItem: originalGetItem, removeItem: originalRemoveItem } =
    getNativeLocalStorageMethods();

  // Install the proxy FIRST, before any of the awaited native round trips
  // below. Hydration and protected-credential migration each await the real
  // Preferences/secure-store bridge, which can take several retries to warm
  // up; every await below is a window where a concurrent `localStorage` call
  // on a protected key (e.g. a login flow racing this init) would otherwise
  // hit the raw, unpatched Storage prototype — reading a still-present legacy
  // plaintext value straight off disk, or writing a fresh credential in
  // plaintext instead of into the secure store. Installing the proxy up front
  // means every protected-key access, including ones that race this
  // function, is intercepted from the first possible moment: reads are
  // gated on `protectedStorageCache` (empty until migration populates it,
  // so they return null rather than leaking the legacy plaintext) and writes
  // go straight to the secure store instead of `originalSetItem`. The
  // migration loop below reads/removes the legacy value through the
  // `originalGetItem`/`originalRemoveItem` closures captured above, which
  // stay bound to the raw prototype regardless of when the proxy patches it,
  // so migration itself is unaffected by moving this earlier.
  setupStorageProxy();

  // The Capacitor Preferences plugin is frequently not yet responsive on the
  // first read during very early WebView startup (the bridge is still wiring
  // up), so a single best-effort pass loses critical session/first-run state —
  // e.g. `eliza:first-run-complete` fails to hydrate and the user is bounced
  // back into onboarding even though native Preferences has it. Probe one key
  // with a few short retries until the plugin answers, then hydrate. The probe
  // can't distinguish "plugin cold" from "key genuinely unset", so it is capped
  // and never blocks first paint for more than a moment.
  let pluginResponded = isElectrobunRuntime();
  if (isNativePlatform()) {
    for (
      let attempt = 0;
      attempt < PREFERENCE_HYDRATION_ATTEMPTS;
      attempt += 1
    ) {
      if (await preferencesResponded()) {
        pluginResponded = true;
        break;
      }
      if (attempt < PREFERENCE_HYDRATION_ATTEMPTS - 1) {
        await new Promise((resolve) =>
          setTimeout(resolve, PREFERENCE_HYDRATION_RETRY_MS),
        );
      }
    }
  }

  // Load synced keys from Preferences into cache. Hydration stays best-effort so
  // a single stale preference read cannot block first paint.
  const entries = isNativePlatform()
    ? await Promise.all(
        Array.from(
          isProtectedStorageHost()
            ? [...SYNCED_KEYS].filter((key) => !PROTECTED_STORAGE_KIND.has(key))
            : SYNCED_KEYS,
          async (key) => [key, await readPreferenceWithTimeout(key)] as const,
        ),
      )
    : [];
  for (const [key, value] of entries) {
    if (value === null) continue;
    preferencesCache.set(key, value);
    // Also set in localStorage for immediate availability. Privileged: the
    // synced keys are shell-reserved and re-hydration can run after mount
    // (cold-plugin retry), i.e. while a surface scope has the raw guard armed.
    try {
      runAsPrivilegedShell(() => window.localStorage.setItem(key, value));
    } catch {
      // error-policy:J4 localStorage mirror is best-effort; the authoritative
      // copy lives in `preferencesCache` (set above). A quota/private-mode
      // write failure must not abort hydration of the remaining keys.
    }
  }

  // Migrate legacy plaintext credentials only after a write + read-back match.
  // On a failed store call the old value stays in place for recovery, while all
  // new writes below remain memory-only instead of silently reintroducing
  // plaintext persistence.
  let protectedStoreResponded = true;
  if (isProtectedStorageHost()) {
    for (const key of PROTECTED_STORAGE_KIND.keys()) {
      try {
        let stewardScope: string | null | undefined;
        const protectedValue = await protectedStoreGet(key, null, (scope) => {
          stewardScope = scope;
        });
        if (protectedValue !== null) {
          cacheProtectedStorageValue(key, protectedValue);
          if (key === STEWARD_TOKEN_KEY && stewardScope !== undefined) {
            synchronizeStewardTokenScope(stewardScope);
          }
          originalRemoveItem(key);
          if (isNativePlatform()) {
            const { Preferences } = await loadPreferences();
            await Preferences.remove({ key });
          }
          continue;
        }

        const preferenceValue = isNativePlatform()
          ? await readPreferenceWithTimeout(key)
          : null;
        const legacyValue = preferenceValue ?? originalGetItem(key);
        if (legacyValue === null) continue;

        const migrationVersion = markProtectedStorageMutation(key);
        cacheProtectedStorageValue(key, legacyValue);
        const stored = await serializedProtectedStoreSet(key, legacyValue);
        if (!stored.stored) {
          protectedStoreResponded = false;
          logger.error(
            { key },
            "[StorageBridge] protected-storage migration did not verify",
          );
          continue;
        }
        if (stored.rollbackReceipt) {
          await commitDesktopProtectedStoreReceipt(
            key,
            {
              receipt: stored.rollbackReceipt,
              setRevision: stored.setRevision as number,
            },
            legacyValue,
            null,
            stored.storedValue ?? legacyValue,
          );
        }
        if (protectedStorageMutationVersion.get(key) === migrationVersion) {
          cacheProtectedStorageValue(key, legacyValue);
        }
        originalRemoveItem(key);
        if (isNativePlatform()) {
          const { Preferences } = await loadPreferences();
          await Preferences.remove({ key });
        }
      } catch (err) {
        protectedStoreResponded = false;
        logger.error(
          { err, key },
          "[StorageBridge] protected-storage hydration failed",
        );
      }
    }
  }

  // Only consider the bridge initialized once the native plugin has actually
  // answered. If it never warmed up, leave `initialized` false so a later call
  // (e.g. from initializePlatform after more of the bridge has wired up)
  // re-hydrates instead of permanently dropping critical synced keys —
  // first-run-complete, active-server, the smoke request — which otherwise
  // strands the user in onboarding or silently skips the QA smoke.
  if (pluginResponded && protectedStoreResponded) {
    initialized = true;
  }
}

/**
 * Set up a proxy to intercept localStorage operations
 */
function setupStorageProxy(): void {
  if (storageProxyInstalled) {
    return;
  }

  if (!isNativePlatform() && !isElectrobunRuntime()) {
    return;
  }

  if (isElectrobunRuntime()) {
    subscribeDesktopBridgeEvent({
      rpcMessage: "secureStoreChanged",
      ipcChannel: "secureStore:changed",
      listener: handleProtectedStorageHostInvalidation,
    });
  }

  const nativeStorage = getNativeLocalStorageMethods();
  const {
    setItem: originalSetItem,
    getItem: originalGetItem,
    removeItem: originalRemoveItem,
  } = nativeStorage;

  // Patch the shared Storage prototype with a localStorage-only branch instead
  // of assigning named properties on the Storage instance. Web Storage objects
  // have exotic named-property behavior, so a plain `localStorage.setItem =
  // fn` (and, in WebKit-style implementations, even an own descriptor) can
  // become a persisted key or be ignored. sessionStorage and any other Storage
  // object continue through the captured native prototype methods unchanged.
  const localStorageInstance = nativeStorage.storage;
  const storagePrototype = Object.getPrototypeOf(
    localStorageInstance,
  ) as Storage;
  const { prototypeSetItem, prototypeGetItem, prototypeRemoveItem } =
    nativeStorage;
  const secureSetItem = (key: string, value: string): void => {
    if (isProtectedStorageHost() && PROTECTED_STORAGE_KIND.has(key)) {
      // Web Storage is synchronous, so this legacy-compatible surface remains
      // explicitly optimistic. Security-critical producers use the awaited
      // setStorageValue registration below and are published only after
      // protected-store write plus exact readback succeeds.
      const writeVersion = markProtectedStorageMutation(key);
      cacheProtectedStorageValue(key, value);
      originalRemoveItem(key);
      setTimeout(() => {
        serializedProtectedStoreSet(key, value)
          .then(async (stored) => {
            if (!stored.stored) {
              logger.error(
                { key },
                "[StorageBridge] secure-store rejected protected write",
              );
              return;
            }
            if (stored.rollbackReceipt) {
              await commitDesktopProtectedStoreReceipt(
                key,
                {
                  receipt: stored.rollbackReceipt,
                  setRevision: stored.setRevision as number,
                },
                value,
                null,
                stored.storedValue ?? value,
              );
            }
            if (protectedStorageMutationVersion.get(key) === writeVersion) {
              cacheProtectedStorageValue(key, value);
            }
          })
          .catch((err) => {
            logger.error(
              { err, key },
              "[StorageBridge] failed to persist protected key",
            );
          });
      }, 0);
      return;
    }
    // Always set in localStorage first
    originalSetItem(key, value);

    // If it's a synced key, also persist to Preferences
    if (SYNCED_KEYS.has(key)) {
      preferencesCache.set(key, value);
      // Fire and forget on a later task. Some native bridge calls can stall
      // during early WebView startup; localStorage writes must stay sync-fast.
      setTimeout(() => {
        loadPreferences()
          .then(({ Preferences }) => Preferences.set({ key, value }))
          .catch((err) => {
            // A dropped synced write silently diverges a critical key
            // (session/auth/first-run) across restarts — surface it instead
            // of swallowing. Fire-and-forget scheduling stays; the value is
            // already in `preferencesCache` for this session.
            logger.error(
              { err, key },
              "[StorageBridge] failed to sync key to Preferences",
            );
          });
      }, 0);
    }
  };

  // Override getItem
  const secureGetItem = (key: string): string | null => {
    if (isProtectedStorageHost() && PROTECTED_STORAGE_KIND.has(key)) {
      return readProtectedStorageCache(key);
    }
    // For synced keys, prefer the cache (which was loaded from Preferences)
    if (SYNCED_KEYS.has(key) && preferencesCache.has(key)) {
      return preferencesCache.get(key) ?? null;
    }
    return originalGetItem(key);
  };

  // Override removeItem
  const secureRemoveItem = (key: string): void => {
    if (isProtectedStorageHost() && PROTECTED_STORAGE_KIND.has(key)) {
      const removalVersion = markProtectedStorageMutation(key);
      setTimeout(() => {
        serializedProtectedStoreDelete(key)
          .then(() => {
            if (protectedStorageMutationVersion.get(key) === removalVersion) {
              invalidateProtectedStorageCache(key);
              originalRemoveItem(key);
            }
          })
          .catch((err) => {
            // error-policy:J4 a synchronous Web Storage call cannot surface an
            // asynchronous native rejection. Retain the cached credential so
            // the current session does not claim a deletion that did not occur.
            logger.error(
              { err, key },
              "[StorageBridge] failed to remove protected key",
            );
          });
      }, 0);
      return;
    }
    originalRemoveItem(key);

    if (SYNCED_KEYS.has(key)) {
      preferencesCache.delete(key);
      setTimeout(() => {
        loadPreferences()
          .then(({ Preferences }) => Preferences.remove({ key }))
          .catch((err) => {
            // A dropped synced removal leaves a stale key in Preferences that
            // out-of-sync-hydrates on the next restart — surface it instead of
            // swallowing. The in-session cache was already cleared above.
            logger.error(
              { err, key },
              "[StorageBridge] failed to remove key from Preferences",
            );
          });
      }, 0);
    }
  };

  function storageBridgeSetItem(this: Storage, key: string, value: string) {
    if (this === localStorageInstance) return secureSetItem(key, value);
    return prototypeSetItem.call(this, key, value);
  }
  function storageBridgeGetItem(this: Storage, key: string) {
    if (this === localStorageInstance) return secureGetItem(key);
    return prototypeGetItem.call(this, key);
  }
  function storageBridgeRemoveItem(this: Storage, key: string) {
    if (this === localStorageInstance) return secureRemoveItem(key);
    return prototypeRemoveItem.call(this, key);
  }

  Object.defineProperties(storagePrototype, {
    setItem: {
      configurable: true,
      writable: true,
      value: storageBridgeSetItem,
    },
    getItem: {
      configurable: true,
      writable: true,
      value: storageBridgeGetItem,
    },
    removeItem: {
      configurable: true,
      writable: true,
      value: storageBridgeRemoveItem,
    },
  });

  // A host may hand out `localStorage` through a wrapper that does not resolve
  // method lookups through the prototype patched above (jsdom's proxy does
  // not). Interception is a security boundary, so verify it rather than assume
  // it, and install the same branch directly on the instance when the
  // prototype patch is not observable there. `defineProperty` is used instead
  // of plain assignment because a Web Storage `[[Set]]` on an unknown name is
  // a named-property write that would persist a bogus "setItem" entry.
  if (localStorageInstance.getItem !== storageBridgeGetItem) {
    Object.defineProperties(localStorageInstance, {
      setItem: {
        configurable: true,
        writable: true,
        value: secureSetItem,
      },
      getItem: {
        configurable: true,
        writable: true,
        value: secureGetItem,
      },
      removeItem: {
        configurable: true,
        writable: true,
        value: secureRemoveItem,
      },
    });
  }
  storageProxyInstalled = true;
}

/**
 * Get a value from storage (works on both native and web)
 */
export async function getStorageValue(key: string): Promise<string | null> {
  if (isProtectedStorageHost() && PROTECTED_STORAGE_KIND.has(key)) {
    let stewardScope: string | null | undefined;
    const value = await protectedStoreGet(key, null, (scope) => {
      stewardScope = scope;
    });
    if (value === null) {
      // The secure host is authoritative. Falling back to a renderer-local
      // cache after `not_found` resurrects credentials removed by another
      // window (logout/account switch) and can replay the previous JWT.
      invalidateProtectedStorageCache(key);
      return null;
    }
    cacheProtectedStorageValue(key, value);
    if (key === STEWARD_TOKEN_KEY && stewardScope !== undefined) {
      synchronizeStewardTokenScope(stewardScope);
    }
    return value;
  }
  if (isNativePlatform() && SYNCED_KEYS.has(key)) {
    const { Preferences } = await loadPreferences();
    const result = await Preferences.get({ key });
    return result.value;
  }
  return window.localStorage.getItem(key);
}

/** Persists a value and returns an Electrobun rollback receipt when present. */
async function persistStorageValue(
  key: string,
  value: string,
  context: PersistStorageValueContext = {},
): Promise<PersistedStorageValue> {
  if (isProtectedStorageHost() && PROTECTED_STORAGE_KIND.has(key)) {
    const transaction = context.transaction
      ? requireActiveRuntimeConnectionTransaction(context.transaction)
      : null;
    const preparedValue = encodeProtectedStorageValue(
      key,
      value,
      context.stewardScope,
    );
    await stageActiveRuntimeConnectionParticipant(
      transaction,
      key,
      preparedValue,
    );
    const mutationVersion = markProtectedStorageMutation(key);
    const result = await serializedProtectedStoreSet(
      key,
      value,
      transaction,
      context.stewardScope,
    );
    if (!result.stored) {
      throw new Error(`Protected storage rejected write for ${key}`);
    }
    if (
      !transaction &&
      protectedStorageMutationVersion.get(key) === mutationVersion
    ) {
      cacheProtectedStorageValue(key, value);
    }
    if (!result.rollbackReceipt) {
      return {
        mutationVersion,
        rollbackAuthority: null,
        storedValue: result.storedValue ?? preparedValue,
        ...(Object.hasOwn(result, "predecessor")
          ? { previousValue: result.predecessor }
          : {}),
      };
    }
    if (!Number.isSafeInteger(result.setRevision)) {
      await rollbackFailedDesktopProtectedStoreSet(key, result, transaction);
      throw new Error(`Protected storage did not return a revision for ${key}`);
    }
    return {
      mutationVersion,
      rollbackAuthority: {
        receipt: result.rollbackReceipt,
        setRevision: result.setRevision as number,
      },
      storedValue: result.storedValue ?? preparedValue,
    };
  }
  // Privileged: this is the shell-side persistence helper (session/auth/
  // first-run keys); the view-facing path is the scoped override in
  // DynamicViewLoader's bridge compat, not this function.
  const previousValue = window.localStorage.getItem(key);
  const mutationVersion = markProtectedStorageMutation(key);
  runAsPrivilegedShell(() => window.localStorage.setItem(key, value));

  if (isNativePlatform() && SYNCED_KEYS.has(key)) {
    const { Preferences } = await loadPreferences();
    await Preferences.set({ key, value });
  }
  return {
    mutationVersion,
    previousValue,
    rollbackAuthority: null,
    storedValue: value,
  };
}

/**
 * Set a value in storage (works on both native and web)
 */
export async function setStorageValue(
  key: string,
  value: string,
): Promise<void> {
  const { rollbackAuthority, storedValue } = await persistStorageValue(
    key,
    value,
  );
  if (rollbackAuthority) {
    await commitDesktopProtectedStoreReceipt(
      key,
      rollbackAuthority,
      value,
      null,
      storedValue,
    );
  }
}

/**
 * Persist a protected value and retain an exact compensation handle until the
 * caller has durably committed all related records. Electrobun compensation is
 * receipt + SET-revision fenced; native remains within the documented
 * single-renderer serialized boundary.
 */
export async function setStorageValueWithCompensation(
  key: string,
  value: string,
  options: StorageWriteValidationOptions = {},
): Promise<StorageWriteCompensation | null> {
  if (options.validate?.() === false) return null;
  const compensateOnValidationFailure =
    options.compensateOnValidationFailure !== false;
  const transaction = options.runtimeConnectionTransaction
    ? requireActiveRuntimeConnectionTransaction(
        options.runtimeConnectionTransaction,
      )
    : null;
  const persisted = await persistStorageValue(key, value, {
    ...(transaction ? { transaction } : {}),
  });
  const compensate = async (): Promise<boolean> => {
    if (
      protectedStorageMutationVersion.get(key) !== persisted.mutationVersion
    ) {
      return false;
    }
    if (persisted.rollbackAuthority) {
      const transactionReceipt = persisted.rollbackAuthority.transactionReceipt;
      if (transactionReceipt?.phase === "aborted") return true;
      if (
        transactionReceipt?.phase === "prepared" ||
        transactionReceipt?.phase === "committed"
      ) {
        return abortRuntimeConnectionStorageTransaction(
          transactionReceipt.transaction,
        );
      }
      if (transactionReceipt?.phase === "finished") {
        return compensateFinishedRuntimeConnectionStorageTransaction(
          transactionReceipt.transaction,
        );
      }
      const compensation =
        await compensateCommittedDesktopProtectedStoreReceipt(key, {
          ...persisted.rollbackAuthority,
          expectedToken: value,
        });
      return compensation.restored;
    }
    return compareAndRestoreStorageValue(
      key,
      value,
      persisted.previousValue ?? null,
    );
  };

  if (persisted.rollbackAuthority) {
    if (options.validate?.() === false && compensateOnValidationFailure) {
      if (transaction) {
        await abortRuntimeConnectionStorageTransaction(transaction);
      } else {
        await compareAndRestoreStorageValue(
          key,
          value,
          null,
          persisted.rollbackAuthority.receipt,
        );
      }
      return null;
    }
    try {
      await commitDesktopProtectedStoreReceipt(
        key,
        persisted.rollbackAuthority,
        value,
        transaction,
        persisted.storedValue,
      );
    } catch (error) {
      if (error instanceof ProtectedStorageWriteSupersededError) return null;
      throw error;
    }
  }
  if (options.validate?.() === false) {
    if (compensateOnValidationFailure) await compensate();
    return null;
  }
  return { compensate };
}

/**
 * Apply a terminal credential transform only to the exact raw record observed
 * by the caller. Electrobun binds bytes + host revision + owner mutation id;
 * native relies on the documented single-renderer per-key serialization.
 * Once applied, validator loss suppresses publication but never restores A.
 */
export async function setStorageValueIfCurrent(
  key: string,
  expectedValue: string,
  value: string,
  options: StorageWriteValidationOptions = {},
): Promise<boolean> {
  if (options.validate?.() === false) return false;
  if (!isProtectedStorageHost() || !PROTECTED_STORAGE_KIND.has(key)) {
    if (window.localStorage.getItem(key) !== expectedValue) return false;
    if (options.validate?.() === false) return false;
    await setStorageValue(key, value);
    return options.validate?.() !== false;
  }

  const mutationVersion = markProtectedStorageMutation(key);
  return serializeProtectedStorageMutation(key, async () => {
    if (!isNativePlatform() && isElectrobunRuntime()) {
      const kind = PROTECTED_STORAGE_KIND.get(key);
      if (!kind) throw new Error("Protected storage kind is not registered");
      const snapshot = await desktopSecureStoreGet(kind, undefined);
      if (!snapshot) {
        throw new Error("Desktop protected storage is unavailable");
      }
      const snapshotStoredValue = snapshot.ok
        ? typeof snapshot.value === "string"
          ? snapshot.value
          : null
        : snapshot.reason === "not_found"
          ? null
          : undefined;
      if (snapshotStoredValue === undefined) {
        throw new Error("Desktop protected storage is unavailable");
      }
      applyProtectedStorageHostSnapshot(
        key,
        snapshotStoredValue,
        snapshot.revision,
      );
      const snapshotValue =
        snapshotStoredValue === null
          ? null
          : decodeProtectedStorageValue(key, snapshotStoredValue).value;
      if (
        snapshotValue !== expectedValue ||
        options.validate?.() === false ||
        !Number.isSafeInteger(snapshot.revision)
      ) {
        return false;
      }

      const mutationId = createProtectedStorageMutationId();
      const storedValue = encodeProtectedStorageValue(key, value);
      let transformed: Awaited<
        ReturnType<typeof desktopSecureStoreCompareAndSet>
      > = null;
      let transformError: unknown = new Error(
        "Desktop protected storage CAS transform is unavailable",
      );
      for (
        let attempt = 0;
        attempt < DESKTOP_SECURE_STORE_RPC_ATTEMPTS;
        attempt += 1
      ) {
        try {
          transformed = await desktopSecureStoreCompareAndSet(
            kind,
            snapshotStoredValue as string,
            storedValue,
            snapshot.revision as number,
            mutationId,
            undefined,
          );
          if (transformed) break;
        } catch (error) {
          transformError = error;
        }
      }
      if (!transformed) {
        try {
          transformed = await desktopSecureStoreCompareAndSet(
            kind,
            snapshotStoredValue as string,
            storedValue,
            snapshot.revision as number,
            mutationId,
            undefined,
          );
        } catch (error) {
          transformError = error;
        }
      }
      if (!transformed) throw transformError;
      if (!transformed.ok) {
        throw new Error("Desktop protected storage rejected CAS transform");
      }
      applyProtectedStorageHostSnapshot(
        key,
        transformed.value,
        transformed.revision,
      );
      if (!transformed.applied) return false;
      if (options.validate?.() === false) return false;
      if (protectedStorageMutationVersion.get(key) === mutationVersion) {
        cacheProtectedStorageValue(key, value);
      }
      return true;
    }

    const currentValue = await protectedStoreGet(key);
    if (currentValue !== expectedValue || options.validate?.() === false) {
      if (currentValue === null) invalidateProtectedStorageCache(key);
      else cacheProtectedStorageValue(key, currentValue);
      return false;
    }
    let writeError: unknown = null;
    try {
      await protectedStoreSet(key, value);
    } catch (error) {
      writeError = error;
    }
    let readback: string | null;
    try {
      readback = await protectedStoreGet(key);
    } catch (error) {
      throw writeError
        ? new AggregateError(
            [writeError, error],
            `Native protected storage could not verify terminal transform for ${key}`,
          )
        : error;
    }
    if (readback !== value) {
      if (readback === null) invalidateProtectedStorageCache(key);
      else cacheProtectedStorageValue(key, readback);
      if (writeError) throw writeError;
      return false;
    }
    if (protectedStorageMutationVersion.get(key) === mutationVersion) {
      cacheProtectedStorageValue(key, value);
    }
    return options.validate?.() !== false;
  });
}

/**
 * Remove a value from storage (works on both native and web)
 */
export async function removeStorageValue(key: string): Promise<void> {
  if (isProtectedStorageHost() && PROTECTED_STORAGE_KIND.has(key)) {
    const removalVersion = markProtectedStorageMutation(key);
    await serializedProtectedStoreDelete(key);
    if (protectedStorageMutationVersion.get(key) === removalVersion) {
      invalidateProtectedStorageCache(key);
    }
    return;
  }
  runAsPrivilegedShell(() => window.localStorage.removeItem(key));

  if (isNativePlatform() && SYNCED_KEYS.has(key)) {
    const { Preferences } = await loadPreferences();
    await Preferences.remove({ key });
  }
}

/**
 * Remove only the protected value observed by a terminal-session authority.
 * Electrobun fences both bytes and host revision, so renderer A cannot delete
 * renderer B's later login even when their local Web Locks are unrelated.
 */
export async function removeStorageValueIfCurrent(
  key: string,
  expectedValue: string | null,
  options: StorageRemovalValidationOptions = {},
): Promise<boolean> {
  if (options.validate?.() === false) return false;
  if (!isProtectedStorageHost() || !PROTECTED_STORAGE_KIND.has(key)) {
    if (window.localStorage.getItem(key) !== expectedValue) return false;
    if (options.validate?.() === false) return false;
    if (expectedValue === null) return true;
    await removeStorageValue(key);
    // Once the exact terminal delete is acquired, the caller must finish its
    // remaining teardown. It independently rechecks the validator to suppress
    // only the observable event; terminal credentials are never resurrected.
    return true;
  }

  const removalVersion = markProtectedStorageMutation(key);
  return serializeProtectedStorageMutation(key, async () => {
    if (isElectrobunRuntime() && !isNativePlatform()) {
      const kind = PROTECTED_STORAGE_KIND.get(key);
      if (!kind) throw new Error("Protected storage kind is not registered");
      const snapshot = await desktopSecureStoreGet(kind, undefined);
      if (!snapshot) {
        throw new Error("Desktop protected storage is unavailable");
      }
      const snapshotStoredValue = snapshot.ok
        ? typeof snapshot.value === "string"
          ? snapshot.value
          : null
        : snapshot.reason === "not_found"
          ? null
          : undefined;
      if (snapshotStoredValue === undefined) {
        throw new Error("Desktop protected storage is unavailable");
      }
      applyProtectedStorageHostSnapshot(
        key,
        snapshotStoredValue,
        snapshot.revision,
      );
      const snapshotValue =
        snapshotStoredValue === null
          ? null
          : decodeProtectedStorageValue(key, snapshotStoredValue).value;
      if (
        snapshotValue !== expectedValue ||
        options.validate?.() === false ||
        !Number.isSafeInteger(snapshot.revision)
      ) {
        return false;
      }

      let deletion: Awaited<
        ReturnType<typeof desktopSecureStoreCompareAndDelete>
      > = null;
      let deletionError: unknown = new Error(
        "Desktop protected storage CAS deletion is unavailable",
      );
      const deletionMutationId = createProtectedStorageMutationId();
      for (
        let attempt = 0;
        attempt < DESKTOP_SECURE_STORE_RPC_ATTEMPTS;
        attempt += 1
      ) {
        try {
          deletion = await desktopSecureStoreCompareAndDelete(
            kind,
            snapshotStoredValue,
            snapshot.revision as number,
            deletionMutationId,
            undefined,
          );
          if (deletion) break;
        } catch (error) {
          deletionError = error;
        }
      }
      if (!deletion) {
        try {
          // The request journal is owner + mutation-id bound. Query it once
          // after the transport retry budget so three post-host response
          // losses still resolve to A's exact deletion rather than attributing
          // an unrelated renderer B deletion by revision arithmetic.
          deletion = await desktopSecureStoreCompareAndDelete(
            kind,
            snapshotStoredValue,
            snapshot.revision as number,
            deletionMutationId,
            undefined,
          );
        } catch (error) {
          deletionError = error;
        }
      }
      if (!deletion) throw deletionError;
      if (!deletion.ok) {
        throw new Error("Desktop protected storage rejected CAS deletion");
      }
      applyProtectedStorageHostSnapshot(key, deletion.value, deletion.revision);
      if (!deletion.deleted) return false;

      if (protectedStorageMutationVersion.get(key) === removalVersion) {
        invalidateProtectedStorageCache(key);
      }
      return true;
    }

    const currentValue = await protectedStoreGet(key);
    if (currentValue !== expectedValue || options.validate?.() === false) {
      if (expectedValue === null) {
        if (currentValue === null) invalidateProtectedStorageCache(key);
        else cacheProtectedStorageValue(key, currentValue);
      } else {
        compareAndRestoreProtectedStorageCache(
          key,
          expectedValue,
          currentValue,
        );
      }
      return false;
    }
    if (expectedValue === null) return true;
    await protectedStoreDelete(key);
    if (protectedStorageMutationVersion.get(key) === removalVersion) {
      invalidateProtectedStorageCache(key);
    }
    return true;
  });
}

/**
 * Register additional keys to be synced to Preferences
 */
export function registerSyncedKey(key: string): void {
  SYNCED_KEYS.add(key);
}

/**
 * Check if storage bridge is initialized
 */
export function isStorageBridgeInitialized(): boolean {
  return initialized;
}

registerStewardTokenRemoval(async (options) => {
  if (options) {
    return removeStorageValueIfCurrent(
      STEWARD_TOKEN_KEY,
      options.expectedToken,
      { validate: options.validate },
    );
  }
  await removeStorageValue(STEWARD_TOKEN_KEY);
  return true;
});
registerStewardTokenPersistence(
  async (token, context: StewardTokenHostPersistenceContext) => {
    // The Shared writer validates its canonical localStorage facade after the
    // awaited host commit. Install that facade synchronously even if an early
    // native login races full bridge hydration; plaintext storage is never used.
    setupStorageProxy();
    const transaction = context.hostContext
      ? requireActiveRuntimeConnectionTransaction(
          context.hostContext as RuntimeConnectionStorageTransaction,
        )
      : null;
    if (transaction) {
      const captured = transaction.stewardPredecessorScope;
      if (captured && captured.value !== context.previousScope) {
        throw new Error(
          "Runtime connection transaction Steward predecessor scope changed",
        );
      }
      transaction.stewardPredecessorScope = {
        value: context.previousScope,
      };
    }
    const persisted = await persistStorageValue(STEWARD_TOKEN_KEY, token, {
      stewardScope: context.requiredScope,
      ...(transaction ? { transaction } : {}),
    });
    let committed = false;
    let commitAttempted = false;
    let restoration: Promise<boolean> | null = null;

    const restorePredecessor = (
      _validate?: () => boolean,
    ): Promise<boolean> => {
      if (restoration) return restoration;
      const operation = (async () => {
        // Same-renderer native/browser ABA is fenced by the per-key generation.
        // Electrobun additionally binds every rollback to its opaque host receipt
        // and exact SET revision, so another renderer's same bytes cannot match.
        // Once that exact CAS is acquired, the boolean remains true even if the
        // caller's validator changes while the RPC is in flight; Shared uses it
        // to restore subordinate state without guessing from same-value bytes.
        if (
          protectedStorageMutationVersion.get(STEWARD_TOKEN_KEY) !==
          persisted.mutationVersion
        ) {
          return false;
        }
        if (persisted.rollbackAuthority) {
          const transactionReceipt =
            persisted.rollbackAuthority.transactionReceipt;
          if (
            transactionReceipt &&
            (transactionReceipt.phase === "prepared" ||
              transactionReceipt.phase === "committed")
          ) {
            return abortRuntimeConnectionStorageTransaction(
              transactionReceipt.transaction,
            );
          }
          if (transactionReceipt?.phase === "aborted") return true;
          if (transactionReceipt?.phase === "finished") {
            return compensateFinishedRuntimeConnectionStorageTransaction(
              transactionReceipt.transaction,
            );
          }
          if (committed || commitAttempted) {
            const compensation =
              await compensateCommittedDesktopProtectedStoreReceipt(
                STEWARD_TOKEN_KEY,
                {
                  ...persisted.rollbackAuthority,
                  expectedToken: token,
                },
                false,
              );
            if (compensation.restored) return true;
            if (compensation.value !== token) return false;
          }
          return compareAndRestoreStorageValue(
            STEWARD_TOKEN_KEY,
            token,
            null,
            persisted.rollbackAuthority.receipt,
          );
        }
        return compareAndRestoreStorageValue(
          STEWARD_TOKEN_KEY,
          token,
          persisted.previousValue ?? null,
        );
      })();
      restoration = operation;
      void operation.catch(() => {
        if (restoration === operation) restoration = null;
      });
      return operation;
    };

    return {
      async commit(validate) {
        if (validate?.() === false) return;
        if (!persisted.rollbackAuthority) {
          committed = true;
          return;
        }
        commitAttempted = true;
        await commitDesktopProtectedStoreReceipt(
          STEWARD_TOKEN_KEY,
          persisted.rollbackAuthority,
          token,
          transaction,
          persisted.storedValue,
        );
        const transactionReceipt =
          persisted.rollbackAuthority.transactionReceipt;
        if (transactionReceipt?.phase === "prepared") {
          // This durable WAL decision deliberately precedes Shared's
          // finalizeBeforePublish hook. A process death after this line is
          // recovered by rolling all three protected records forward; an
          // in-process finalizer failure invokes restorePredecessor above, which
          // first records phase=aborting and restores the three predecessors.
          await decideRuntimeConnectionStorageTransaction(
            transactionReceipt.transaction,
          );
        }
        committed = true;
        // A newer renderer can plant its marker while the commit RPC awaits.
        // Restore through this exact tombstone before shared code can publish.
        if (validate?.() === false) await restorePredecessor();
      },
      restorePredecessor,
    };
  },
);
registerStewardTokenCompareAndRestore(async (expectedToken, restoreToken) => {
  if (
    isElectrobunRuntime() &&
    !isNativePlatform() &&
    PROTECTED_STORAGE_KIND.has(STEWARD_TOKEN_KEY)
  ) {
    // Bytes alone cannot identify a write across same-value ABA. Every modern
    // protected write receives the opaque transaction above; a legacy fallback
    // without that receipt must lose authority instead of guessing or throwing.
    return false;
  }
  return compareAndRestoreStorageValue(
    STEWARD_TOKEN_KEY,
    expectedToken,
    restoreToken,
  );
});
