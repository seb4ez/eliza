/**
 * Durable proof that a browser -> server Steward session mutation may have
 * committed while its renderer continuation was interrupted.
 *
 * Each intent owns a distinct localStorage key.  That deliberately avoids a
 * read/modify/write marker array: two tabs can create or retire receipts
 * without one tab erasing the other's newer ambiguity proof.
 */

import { readStoredStewardToken } from "@elizaos/shared/steward-session-client";
import { decodeJwtPayload } from "./jwt";

export const STEWARD_SESSION_RECOVERY_CHANGE_EVENT =
  "eliza-steward-session-recovery-change";

const RECOVERY_KEY_PREFIX = "eliza.steward.server-session-recovery.v2";
const LOGOUT_KEY_PREFIX = "eliza.steward.server-session-logout.v1";
const GENERATION_KEY_PREFIX = "eliza.steward.server-session-generation.v1";

export type StewardSessionRecoveryKind = "oauth" | "provider" | "telegram";
export type StewardSessionRecoveryPhase = "reserved" | "cookie_pending";
export type StewardSessionLogoutKind = "logout" | "account-switch";

export interface StewardSessionRecoveryIdentity {
  userId: string;
  tenantId: string;
}

export interface StewardSessionRecoverySnapshot {
  tenantId: string;
  receipts: readonly string[];
  /**
   * Last origin-wide mutation nonce. It is never rewound when receipts retire,
   * so an empty A snapshot cannot become live again after B begins and finishes.
   */
  generation: string | null;
  hasOAuth: boolean;
  /** Durable phase of the generation receipt, or null after it retired. */
  currentReceiptPhase?: StewardSessionRecoveryPhase | null;
  /** Kind of the generation receipt; Telegram uses distinct reconciliation. */
  currentReceiptKind?: StewardSessionRecoveryKind | null;
  /** Stable account binding required before cookie recovery may publish. */
  expectedIdentity?: StewardSessionRecoveryIdentity | null;
  /** False means absence cannot be proven and every passive writer must stop. */
  storageAvailable: boolean;
}

export interface StewardSessionRecoveryReceipt {
  tenantId: string;
  receipt: string;
  kind: StewardSessionRecoveryKind;
  /** Receipts which existed before this mutation was dispatched. */
  preexistingReceipts: readonly string[];
}

export interface StewardSessionLogoutIntent {
  tenantId: string;
  receipt: string;
  kind: StewardSessionLogoutKind;
  targetHostname: string;
  /** Login ambiguities which this logout supersedes once server ack succeeds. */
  preexistingRecoveryReceipts: readonly string[];
  /** Older logout attempts this retry supersedes after an acknowledged logout. */
  preexistingLogoutReceipts: readonly string[];
}

export interface StewardSessionLogoutSnapshot {
  tenantId: string;
  intents: readonly StewardSessionLogoutIntent[];
  storageAvailable: boolean;
}

export type StewardSessionRecoveryPublicationRollback = ((
  durableRestored: boolean,
) => void) & {
  beforeDurableRestore?: () => void;
};

export interface StewardSessionRecoveryPublicationFence {
  /** Revalidate the exact receipt/snapshot on both sides of durable awaits. */
  validate(): boolean;
  /** True only after the owned markers were transactionally retired. */
  isFinalized(): boolean;
  /**
   * Retire owned markers without emitting a same-document recovery event.
   * The returned rollback restores their exact raw values if token publication
   * is compensated.
   */
  finalizeBeforePublish(): StewardSessionRecoveryPublicationRollback;
  /** Wake same-document recovery consumers only after token authority exists. */
  publishChange(): boolean;
}

export interface StewardSessionRecoveryCommittedAuthority {
  /** Revalidate immediately before each external success side effect. */
  isCurrent(): boolean;
}

export class StewardSessionRecoveryStorageError extends Error {
  constructor(message = "Secure sign-in recovery storage is unavailable.") {
    super(message);
    this.name = "StewardSessionRecoveryStorageError";
  }
}

function tenantKeyPrefix(tenantId: string): string {
  return `${RECOVERY_KEY_PREFIX}:${encodeURIComponent(tenantId)}:`;
}

function markerKey(tenantId: string, receipt: string): string {
  return `${tenantKeyPrefix(tenantId)}${receipt}`;
}

function logoutKeyPrefix(tenantId: string): string {
  return `${LOGOUT_KEY_PREFIX}:${encodeURIComponent(tenantId)}:`;
}

function logoutMarkerKey(tenantId: string, receipt: string): string {
  return `${logoutKeyPrefix(tenantId)}${receipt}`;
}

function generationKey(tenantId: string): string {
  return `${GENERATION_KEY_PREFIX}:${encodeURIComponent(tenantId)}`;
}

function readGeneration(tenantId: string): {
  generation: string | null;
  storageAvailable: boolean;
} {
  if (typeof window === "undefined") {
    return { generation: null, storageAvailable: false };
  }
  try {
    return {
      generation: window.localStorage.getItem(generationKey(tenantId)),
      storageAvailable: true,
    };
  } catch (error) {
    void error;
    return { generation: null, storageAvailable: false };
  }
}

/** Read the monotonic session generation without treating a logout as unavailable. */
export function readStewardSessionGeneration(tenantId: string): {
  generation: string | null;
  storageAvailable: boolean;
} {
  return readGeneration(tenantId);
}

function persistGeneration(
  tenantId: string,
  generation: string,
  unavailableMessage: string,
): void {
  if (typeof window === "undefined") {
    throw new StewardSessionRecoveryStorageError();
  }
  try {
    window.localStorage.setItem(generationKey(tenantId), generation);
  } catch (error) {
    void error;
    throw new StewardSessionRecoveryStorageError(unavailableMessage);
  }
}

interface StewardSessionRecoveryMarker {
  kind: StewardSessionRecoveryKind;
  phase: StewardSessionRecoveryPhase;
  expectedIdentity: StewardSessionRecoveryIdentity | null;
}

function isRecoveryKind(value: unknown): value is StewardSessionRecoveryKind {
  return value === "oauth" || value === "provider" || value === "telegram";
}

function parseExpectedIdentity(
  value: unknown,
): StewardSessionRecoveryIdentity | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const userId = (value as { userId?: unknown }).userId;
  const tenantId = (value as { tenantId?: unknown }).tenantId;
  if (
    typeof userId !== "string" ||
    userId.trim().length === 0 ||
    typeof tenantId !== "string" ||
    tenantId.trim().length === 0
  ) {
    return null;
  }
  return { userId: userId.trim(), tenantId: tenantId.trim() };
}

function parseMarker(value: string | null): StewardSessionRecoveryMarker {
  if (value === "oauth" || value === "provider" || value === "telegram") {
    // A legacy marker cannot prove either dispatch or account binding. Keep it
    // as a durable block-only reservation; it may never authorize recovered
    // token publication after upgrade.
    return { kind: value, phase: "reserved", expectedIdentity: null };
  }
  try {
    const parsed: unknown = value === null ? null : JSON.parse(value);
    if (
      parsed !== null &&
      typeof parsed === "object" &&
      !Array.isArray(parsed)
    ) {
      const record = parsed as Record<string, unknown>;
      if (isRecoveryKind(record.kind)) {
        return {
          kind: record.kind,
          // A pre-phase/partial JSON marker cannot prove dispatch. Keep it as a
          // durable block-only reservation rather than probing a stale cookie.
          phase:
            record.phase === "cookie_pending" ? "cookie_pending" : "reserved",
          expectedIdentity: parseExpectedIdentity(record.expectedIdentity),
        };
      }
    }
  } catch (error) {
    // error-policy:J6 Corrupt marker contents still prove an ambiguous server
    // mutation. Conservatively recover it as a non-OAuth provider intent.
    void error;
  }
  return {
    kind: "provider",
    phase: "reserved",
    expectedIdentity: null,
  };
}

function readMarkers(tenantId: string): {
  markers: Map<string, StewardSessionRecoveryMarker>;
  storageAvailable: boolean;
} {
  const prefix = tenantKeyPrefix(tenantId);
  const markers = new Map<string, StewardSessionRecoveryMarker>();
  if (typeof window === "undefined") {
    return { markers, storageAvailable: false };
  }
  try {
    for (let index = 0; index < window.localStorage.length; index += 1) {
      const key = window.localStorage.key(index);
      if (!key?.startsWith(prefix)) continue;
      const receipt = key.slice(prefix.length);
      if (!receipt) continue;
      markers.set(receipt, parseMarker(window.localStorage.getItem(key)));
    }
  } catch (error) {
    // error-policy:J6 Absence cannot be established when enumeration fails.
    // Callers receive storageAvailable=false and fail closed.
    void error;
    return { markers, storageAvailable: false };
  }
  return { markers, storageAvailable: true };
}

function randomReceiptCandidate(): string | null {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi) return null;
  try {
    const uuid = cryptoApi.randomUUID?.();
    if (uuid) return uuid;
  } catch (error) {
    // Fall through to getRandomValues, which is equally origin-independent.
    void error;
  }
  if (typeof cryptoApi.getRandomValues !== "function") return null;
  try {
    const entropy = new Uint32Array(4);
    cryptoApi.getRandomValues(entropy);
    return `r-${Array.from(entropy, (part) =>
      part.toString(16).padStart(8, "0"),
    ).join("")}`;
  } catch (error) {
    void error;
    return null;
  }
}

function createReceipt(markers: ReadonlySet<string>): string {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const receipt = randomReceiptCandidate();
    if (!receipt) {
      throw new StewardSessionRecoveryStorageError(
        "Sign-in cannot start because secure random receipt generation is unavailable.",
      );
    }
    if (!markers.has(receipt)) return receipt;
  }
  throw new StewardSessionRecoveryStorageError(
    "Sign-in cannot start because a unique recovery receipt could not be created.",
  );
}

function readLogoutMarkers(tenantId: string): {
  intents: StewardSessionLogoutIntent[];
  storageAvailable: boolean;
} {
  const prefix = logoutKeyPrefix(tenantId);
  const intents: StewardSessionLogoutIntent[] = [];
  if (typeof window === "undefined") {
    return { intents, storageAvailable: false };
  }
  try {
    for (let index = 0; index < window.localStorage.length; index += 1) {
      const key = window.localStorage.key(index);
      if (!key?.startsWith(prefix)) continue;
      const receipt = key.slice(prefix.length);
      const raw = window.localStorage.getItem(key);
      const parsed: unknown = raw === null ? null : JSON.parse(raw);
      if (!receipt || !parsed || typeof parsed !== "object") {
        return { intents: [], storageAvailable: false };
      }
      const record = parsed as Record<string, unknown>;
      const kind = record.kind;
      const targetHostname = record.targetHostname;
      const preexistingRecoveryReceipts = record.preexistingRecoveryReceipts;
      const preexistingLogoutReceipts = record.preexistingLogoutReceipts;
      if (
        (kind !== "logout" && kind !== "account-switch") ||
        typeof targetHostname !== "string" ||
        targetHostname.length === 0 ||
        !Array.isArray(preexistingRecoveryReceipts) ||
        !preexistingRecoveryReceipts.every(
          (candidate) => typeof candidate === "string",
        ) ||
        !Array.isArray(preexistingLogoutReceipts) ||
        !preexistingLogoutReceipts.every(
          (candidate) => typeof candidate === "string",
        )
      ) {
        return { intents: [], storageAvailable: false };
      }
      intents.push({
        tenantId,
        receipt,
        kind,
        targetHostname,
        preexistingRecoveryReceipts,
        preexistingLogoutReceipts,
      });
    }
  } catch (error) {
    void error;
    return { intents: [], storageAvailable: false };
  }
  intents.sort((left, right) => left.receipt.localeCompare(right.receipt));
  return { intents, storageAvailable: true };
}

function notifyRecoveryChange(): void {
  if (typeof window === "undefined") return;
  try {
    window.dispatchEvent(new Event(STEWARD_SESSION_RECOVERY_CHANGE_EVENT));
  } catch (error) {
    // error-policy:J7 localStorage remains authoritative when an optional
    // same-document wake-up event cannot be dispatched.
    void error;
  }
}

function persistMarker(
  tenantId: string,
  receipt: string,
  kind: StewardSessionRecoveryKind,
): void {
  const key = markerKey(tenantId, receipt);
  if (typeof window === "undefined") {
    throw new StewardSessionRecoveryStorageError();
  }
  try {
    window.localStorage.setItem(
      key,
      JSON.stringify({
        kind,
        phase: "reserved",
        expectedIdentity: null,
        createdAt: Date.now(),
      }),
    );
  } catch (error) {
    void error;
    throw new StewardSessionRecoveryStorageError(
      "Sign-in cannot start because durable recovery storage is unavailable. Enable site storage and try again.",
    );
  }
}

function removeReceipts(tenantId: string, receipts: readonly string[]): void {
  if (receipts.length === 0) return;
  for (const receipt of new Set(receipts)) {
    const key = markerKey(tenantId, receipt);
    if (typeof window === "undefined") continue;
    try {
      window.localStorage.removeItem(key);
    } catch (error) {
      // error-policy:J6 A leftover durable receipt causes another conservative
      // cookie-first recovery; it cannot authorize or publish a credential.
      void error;
    }
  }
  notifyRecoveryChange();
}

interface RawRecoveryMarker {
  key: string;
  raw: string;
}

function restoreRawRecoveryMarkers(
  markers: readonly RawRecoveryMarker[],
): void {
  if (typeof window === "undefined") {
    throw new StewardSessionRecoveryStorageError();
  }
  const failures: unknown[] = [];
  for (const marker of markers) {
    try {
      const current = window.localStorage.getItem(marker.key);
      if (current === null) {
        window.localStorage.setItem(marker.key, marker.raw);
        if (window.localStorage.getItem(marker.key) !== marker.raw) {
          failures.push(
            new Error(`Recovery marker ${marker.key} was not restored.`),
          );
        }
      } else if (current !== marker.raw) {
        failures.push(
          new Error(`Recovery marker ${marker.key} changed before rollback.`),
        );
      }
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    throw new StewardSessionRecoveryStorageError(
      "Secure sign-in recovery markers could not be restored after token publication failed.",
    );
  }
}

/**
 * Remove marker values as a rollbackable part of token publication. Unlike
 * ordinary completion, this deliberately does not emit the recovery event:
 * that event would let a same-document listener reenter before the token's
 * own authority event has linearized.
 */
function removeReceiptsForPublication(
  tenantId: string,
  receipts: readonly string[],
  generation: string | null,
): StewardSessionRecoveryPublicationRollback {
  if (typeof window === "undefined") {
    throw new StewardSessionRecoveryStorageError();
  }
  const markers: RawRecoveryMarker[] = [];
  const ownedReceipts = new Set(receipts);
  const restoreIfStillOwned = () => {
    const currentGeneration = readGeneration(tenantId);
    if (
      currentGeneration.storageAvailable &&
      currentGeneration.generation !== generation
    ) {
      // A successor which started while these markers were silently absent
      // does not own them in its ancestry. Reintroducing them would poison B's
      // otherwise-live publication fence, so superseding state wins.
      return;
    }
    const currentMarkers = readMarkers(tenantId);
    if (
      currentMarkers.storageAvailable &&
      [...currentMarkers.markers.keys()].some(
        (receipt) => !ownedReceipts.has(receipt),
      )
    ) {
      return;
    }
    // An unreadable generation/marker enumeration is not proof of a successor.
    // Restore A fail-closed; if storage is still unavailable the write throws
    // into shared compensation rather than silently losing ambiguity proof.
    restoreRawRecoveryMarkers(markers);
  };
  try {
    for (const receipt of new Set(receipts)) {
      const key = markerKey(tenantId, receipt);
      const raw = window.localStorage.getItem(key);
      if (raw !== null) markers.push({ key, raw });
    }
    for (const marker of markers) {
      window.localStorage.removeItem(marker.key);
      if (window.localStorage.getItem(marker.key) !== null) {
        throw new Error(`Recovery marker ${marker.key} was not removed.`);
      }
    }
  } catch (error) {
    try {
      restoreIfStillOwned();
    } catch {
      throw new StewardSessionRecoveryStorageError(
        "Secure sign-in recovery removal and rollback both failed.",
      );
    }
    void error;
    throw new StewardSessionRecoveryStorageError(
      "Secure sign-in recovery markers could not be retired before token publication.",
    );
  }

  return restoreIfStillOwned;
}

export function readStewardSessionRecovery(
  tenantId: string,
): StewardSessionRecoverySnapshot {
  const { markers, storageAvailable } = readMarkers(tenantId);
  const logout = readLogoutMarkers(tenantId);
  const generation = readGeneration(tenantId);
  const currentMarker = generation.generation
    ? markers.get(generation.generation)
    : undefined;
  return {
    tenantId,
    receipts: [...markers.keys()].sort(),
    generation: generation.generation,
    hasOAuth: [...markers.values()].some(({ kind }) => kind === "oauth"),
    currentReceiptPhase: currentMarker?.phase ?? null,
    currentReceiptKind: currentMarker?.kind ?? null,
    expectedIdentity: currentMarker?.expectedIdentity ?? null,
    // A logout intent is intentionally not a login-recovery receipt. Reporting
    // the snapshot unavailable makes legacy cookie-first recovery stop before
    // it can replay a bearer while the logout is awaiting/replaying its lock.
    storageAvailable:
      storageAvailable &&
      generation.storageAvailable &&
      logout.storageAvailable &&
      logout.intents.length === 0,
  };
}

export function readStewardSessionLogoutIntents(
  tenantId: string,
): StewardSessionLogoutSnapshot {
  const { intents, storageAvailable } = readLogoutMarkers(tenantId);
  return { tenantId, intents, storageAvailable };
}

export function hasStewardSessionRecovery(tenantId: string): boolean {
  const snapshot = readStewardSessionRecovery(tenantId);
  return !snapshot.storageAvailable || snapshot.receipts.length > 0;
}

export function isStewardSessionRecoveryReceiptLive(
  recovery: Pick<
    StewardSessionRecoveryReceipt,
    "tenantId" | "receipt" | "preexistingReceipts"
  >,
): boolean {
  const snapshot = readStewardSessionRecovery(recovery.tenantId);
  const receiptsOwnedWhenStarted = new Set([
    recovery.receipt,
    ...recovery.preexistingReceipts,
  ]);
  return (
    snapshot.storageAvailable &&
    // A later begin permanently supersedes this continuation even if that
    // newer receipt finishes before this tab is scheduled again. Receipt-list
    // ancestry alone would otherwise permit A -> B -> [A] ABA revival.
    snapshot.generation === recovery.receipt &&
    snapshot.receipts.includes(recovery.receipt) &&
    // Older receipts may disappear while this transaction waits: a newer
    // successful transaction can legitimately reconcile them. Any receipt
    // outside this transaction's initial ancestry is newer, however, and
    // synchronously supersedes this continuation before local publication.
    snapshot.receipts.every((receipt) => receiptsOwnedWhenStarted.has(receipt))
  );
}

/**
 * Revalidate a fully published receipt after an await/microtask boundary.
 * Synchronous recovery listeners may queue login B after A's final in-callback
 * check; no caller may trust a boolean success across that boundary without
 * proving A's generation, empty receipt set, and exact canonical token again.
 */
export function isStewardSessionRecoveryPublicationAuthorityCurrent(
  recovery: Pick<StewardSessionRecoveryReceipt, "tenantId" | "receipt">,
  expectedToken: string,
  readToken: () => string | null = readStoredStewardToken,
): boolean {
  const current = readStewardSessionRecovery(recovery.tenantId);
  try {
    return (
      current.storageAvailable &&
      current.generation === recovery.receipt &&
      current.receipts.length === 0 &&
      readToken() === expectedToken
    );
  } catch (error) {
    void error;
    return false;
  }
}

export function createStewardSessionRecoveryCommittedAuthority(
  recovery: Pick<StewardSessionRecoveryReceipt, "tenantId" | "receipt">,
  expectedToken: string,
  readToken?: () => string | null,
): StewardSessionRecoveryCommittedAuthority {
  return {
    isCurrent: () =>
      isStewardSessionRecoveryPublicationAuthorityCurrent(
        recovery,
        expectedToken,
        readToken,
      ),
  };
}

export function isStewardSessionRecoverySnapshotLive(
  expected: StewardSessionRecoverySnapshot,
): boolean {
  const current = readStewardSessionRecovery(expected.tenantId);
  return (
    expected.storageAvailable &&
    current.storageAvailable &&
    current.generation === expected.generation &&
    (current.currentReceiptPhase ?? null) ===
      (expected.currentReceiptPhase ?? null) &&
    (current.currentReceiptKind ?? null) ===
      (expected.currentReceiptKind ?? null) &&
    recoveryIdentitiesEqual(
      current.expectedIdentity ?? null,
      expected.expectedIdentity ?? null,
    ) &&
    current.receipts.length === expected.receipts.length &&
    expected.receipts.every(
      (receipt, index) => current.receipts[index] === receipt,
    )
  );
}

function recoveryIdentityFromToken(
  token: string,
  tenantId: string,
): StewardSessionRecoveryIdentity | null {
  const claims = decodeJwtPayload(token) as
    | (ReturnType<typeof decodeJwtPayload> & {
        tenantId?: unknown;
        tenant_id?: unknown;
      })
    | null;
  const rawUserId = claims?.userId ?? claims?.sub;
  if (typeof rawUserId !== "string" || rawUserId.trim().length === 0) {
    return null;
  }
  const rawTenantId =
    typeof claims?.tenantId === "string"
      ? claims.tenantId
      : typeof claims?.tenant_id === "string"
        ? claims.tenant_id
        : tenantId;
  if (rawTenantId.trim().length === 0) return null;
  return { userId: rawUserId.trim(), tenantId: rawTenantId.trim() };
}

function recoveryIdentitiesEqual(
  left: StewardSessionRecoveryIdentity | null,
  right: StewardSessionRecoveryIdentity | null,
): boolean {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.userId === right.userId &&
      left.tenantId === right.tenantId)
  );
}

/** Whether a refresh result is the exact account armed for cookie recovery. */
export function doesStewardSessionRecoverySnapshotMatchToken(
  snapshot: StewardSessionRecoverySnapshot,
  token: string,
): boolean {
  return (
    snapshot.currentReceiptPhase === "cookie_pending" &&
    snapshot.currentReceiptKind !== "telegram" &&
    snapshot.expectedIdentity != null &&
    recoveryIdentitiesEqual(
      snapshot.expectedIdentity,
      recoveryIdentityFromToken(token, snapshot.tenantId),
    )
  );
}

/** Reserve authority before any provider prompt or one-time credential consume. */
export function beginStewardSessionRecovery(
  tenantId: string,
  kind: StewardSessionRecoveryKind,
): StewardSessionRecoveryReceipt {
  const before = readStewardSessionRecovery(tenantId);
  if (!before.storageAvailable) {
    throw new StewardSessionRecoveryStorageError(
      "Sign-in cannot start because durable recovery storage cannot be read. Enable site storage and try again.",
    );
  }
  const receipt = createReceipt(
    new Set([
      ...before.receipts,
      ...(before.generation ? [before.generation] : []),
    ]),
  );
  persistMarker(tenantId, receipt, kind);
  // Receipt deletion is not a generation rollback. Keeping this nonce after
  // success/rejection makes snapshot authority monotonic across tab scheduling
  // and storage-event delivery order without a racy cross-tab counter.
  persistGeneration(
    tenantId,
    receipt,
    "Sign-in cannot start because durable recovery generation storage is unavailable. Enable site storage and try again.",
  );
  notifyRecoveryChange();
  return {
    tenantId,
    receipt,
    kind,
    preexistingReceipts: before.receipts,
  };
}

/**
 * Durably arm cookie-first recovery immediately before the actual cookie POST.
 * The stable user+tenant binding survives access-token rotation while ensuring
 * a stale preexisting cookie can never be published as the attempted account.
 */
export function markStewardSessionRecoveryCookiePending(
  recovery: StewardSessionRecoveryReceipt,
  expectedToken?: string | null,
): void {
  if (!isStewardSessionRecoveryReceiptLive(recovery)) {
    throw new StewardSessionRecoveryStorageError(
      "Sign-in recovery was superseded before cookie mutation dispatch.",
    );
  }
  if (typeof window === "undefined") {
    throw new StewardSessionRecoveryStorageError();
  }
  const key = markerKey(recovery.tenantId, recovery.receipt);
  let previousRaw: string | null = null;
  let pendingRaw: string | null = null;
  const restoreReservation = (): boolean => {
    if (previousRaw === null || pendingRaw === null) return false;
    try {
      // Never overwrite a concurrent change to this exact marker. A later
      // generation uses a distinct key, while an exact-marker change owns the
      // right to remain fail-closed.
      if (window.localStorage.getItem(key) !== pendingRaw) return false;
      window.localStorage.setItem(key, previousRaw);
      return window.localStorage.getItem(key) === previousRaw;
    } catch (rollbackError) {
      void rollbackError;
      return false;
    }
  };
  try {
    previousRaw = window.localStorage.getItem(key);
    if (previousRaw === null) {
      throw new Error("Recovery reservation is missing.");
    }
    const current = parseMarker(previousRaw);
    const requestedIdentity = expectedToken
      ? recoveryIdentityFromToken(expectedToken, recovery.tenantId)
      : null;
    if (
      current.expectedIdentity !== null &&
      requestedIdentity !== null &&
      !recoveryIdentitiesEqual(current.expectedIdentity, requestedIdentity)
    ) {
      throw new Error("Recovery identity binding cannot be replaced.");
    }
    pendingRaw = JSON.stringify({
      kind: current.kind,
      phase: "cookie_pending",
      // OAuth must arm before its nonce response reveals B, then strengthens
      // the same exact marker after the response. Never weaken an existing
      // binding on an idempotent/unbound repeat.
      expectedIdentity: requestedIdentity ?? current.expectedIdentity,
      createdAt: Date.now(),
    });
    window.localStorage.setItem(key, pendingRaw);
    if (window.localStorage.getItem(key) !== pendingRaw) {
      throw new Error("Recovery dispatch phase was not persisted.");
    }
  } catch (error) {
    restoreReservation();
    void error;
    throw new StewardSessionRecoveryStorageError(
      "Sign-in cannot continue because cookie recovery authority could not be persisted.",
    );
  }
  if (!isStewardSessionRecoveryReceiptLive(recovery)) {
    restoreReservation();
    throw new StewardSessionRecoveryStorageError(
      "Sign-in recovery was superseded during cookie mutation dispatch.",
    );
  }
}

/**
 * Persist an explicit logout before waiting for the origin mutation lock. The
 * marker contains routing metadata only, never a bearer token; the protected
 * token remains quarantined until the idempotent server logout is acknowledged.
 */
export function beginStewardSessionLogout(
  tenantId: string,
  kind: StewardSessionLogoutKind,
  targetHostname: string,
): StewardSessionLogoutIntent {
  const recovery = readMarkers(tenantId);
  const logout = readLogoutMarkers(tenantId);
  const generation = readGeneration(tenantId);
  if (
    !recovery.storageAvailable ||
    !logout.storageAvailable ||
    !generation.storageAvailable
  ) {
    throw new StewardSessionRecoveryStorageError(
      "Sign-out cannot start because durable recovery storage cannot be read. Enable site storage and try again.",
    );
  }
  const normalizedHostname = targetHostname.trim().toLowerCase();
  if (
    normalizedHostname.length === 0 ||
    normalizedHostname.length > 253 ||
    !/^[a-z0-9.-]+$/.test(normalizedHostname)
  ) {
    throw new StewardSessionRecoveryStorageError(
      "Sign-out cannot start because its target host is invalid.",
    );
  }
  const existingReceipts = new Set([
    ...recovery.markers.keys(),
    ...logout.intents.map((intent) => intent.receipt),
    ...(generation.generation ? [generation.generation] : []),
  ]);
  const receipt = createReceipt(existingReceipts);
  const intent: StewardSessionLogoutIntent = {
    tenantId,
    receipt,
    kind,
    targetHostname: normalizedHostname,
    preexistingRecoveryReceipts: [...recovery.markers.keys()].sort(),
    preexistingLogoutReceipts: logout.intents.map(({ receipt }) => receipt),
  };
  if (typeof window === "undefined") {
    throw new StewardSessionRecoveryStorageError();
  }
  try {
    window.localStorage.setItem(
      logoutMarkerKey(tenantId, receipt),
      JSON.stringify({
        kind,
        targetHostname: normalizedHostname,
        preexistingRecoveryReceipts: intent.preexistingRecoveryReceipts,
        preexistingLogoutReceipts: intent.preexistingLogoutReceipts,
        createdAt: Date.now(),
      }),
    );
  } catch (error) {
    void error;
    throw new StewardSessionRecoveryStorageError(
      "Sign-out cannot start because durable recovery storage is unavailable. Enable site storage and try again.",
    );
  }
  persistGeneration(
    tenantId,
    receipt,
    "Sign-out cannot start because durable recovery generation storage is unavailable. Enable site storage and try again.",
  );
  notifyRecoveryChange();
  return intent;
}

export function isStewardSessionLogoutIntentLive(
  intent: Pick<StewardSessionLogoutIntent, "tenantId" | "receipt">,
): boolean {
  const current = readLogoutMarkers(intent.tenantId);
  const generation = readGeneration(intent.tenantId);
  return (
    current.storageAvailable &&
    generation.storageAvailable &&
    generation.generation === intent.receipt &&
    current.intents.some(({ receipt }) => receipt === intent.receipt)
  );
}

/** Retire only a superseded logout marker without touching newer login proof. */
export function rejectStewardSessionLogout(
  intent: Pick<StewardSessionLogoutIntent, "tenantId" | "receipt">,
): void {
  if (typeof window !== "undefined") {
    try {
      window.localStorage.removeItem(
        logoutMarkerKey(intent.tenantId, intent.receipt),
      );
    } catch (error) {
      // A retained marker fails passive recovery closed and can be retried.
      void error;
    }
  }
  notifyRecoveryChange();
}

/** Complete only the logout snapshot owned when this attempt began. */
export function completeStewardSessionLogout(
  intent: StewardSessionLogoutIntent,
): void {
  removeReceipts(intent.tenantId, intent.preexistingRecoveryReceipts);
  if (typeof window !== "undefined") {
    for (const receipt of new Set([
      intent.receipt,
      ...intent.preexistingLogoutReceipts,
    ])) {
      try {
        window.localStorage.removeItem(
          logoutMarkerKey(intent.tenantId, receipt),
        );
      } catch (error) {
        // A retained logout proof keeps every passive writer blocked and is
        // retried on reload; never claim completion after an unproven removal.
        void error;
      }
    }
  }
  notifyRecoveryChange();
}

/** Retire exactly one owned receipt without superseding older ambiguity. */
export function completeStewardSessionRecoveryReceipt(
  recovery: StewardSessionRecoveryReceipt,
): void {
  removeReceipts(recovery.tenantId, [recovery.receipt]);
}

/** A definitive initial-mutation rejection retires only its own receipt. */
export function rejectStewardSessionRecovery(
  recovery: StewardSessionRecoveryReceipt,
): void {
  completeStewardSessionRecoveryReceipt(recovery);
}

/**
 * A successful mutation supersedes itself and only the ambiguity that was
 * already visible when it began. A receipt created concurrently afterwards
 * intentionally remains.
 */
export function completeStewardSessionRecovery(
  recovery: StewardSessionRecoveryReceipt,
): void {
  removeReceipts(recovery.tenantId, [
    recovery.receipt,
    ...recovery.preexistingReceipts,
  ]);
}

function createRecoveryPublicationFence(options: {
  tenantId: string;
  receipts: readonly string[];
  generation: string | null;
  isLive(): boolean;
}): StewardSessionRecoveryPublicationFence {
  let finalized = false;
  let rollbackMarkers: StewardSessionRecoveryPublicationRollback | null = null;
  const finalizedStateIsLive = () => {
    const current = readStewardSessionRecovery(options.tenantId);
    return (
      current.storageAvailable &&
      current.generation === options.generation &&
      // A successor can persist its marker before its generation write becomes
      // observable in this tab. Requiring an actually empty marker set closes
      // that cross-document gap instead of accepting the still-old generation.
      current.receipts.length === 0
    );
  };
  const validate = () =>
    finalized ? finalizedStateIsLive() : options.isLive();

  return {
    validate,
    isFinalized: () => finalized && finalizedStateIsLive(),
    finalizeBeforePublish: () => {
      if (finalized || !options.isLive()) {
        throw new StewardSessionRecoveryStorageError(
          "Sign-in recovery was superseded before token publication.",
        );
      }
      const rollback = removeReceiptsForPublication(
        options.tenantId,
        options.receipts,
        options.generation,
      );
      if (!finalizedStateIsLive()) {
        try {
          rollback(false);
        } catch (error) {
          void error;
          throw new StewardSessionRecoveryStorageError(
            "Sign-in recovery changed and its removed markers could not be restored.",
          );
        }
        throw new StewardSessionRecoveryStorageError(
          "Sign-in recovery was superseded during token publication.",
        );
      }
      finalized = true;
      rollbackMarkers = rollback;
      const restoreMarkers = () => {
        const activeRollback = rollbackMarkers;
        if (!activeRollback) return;
        activeRollback(false);
        rollbackMarkers = null;
        finalized = false;
      };
      const rollbackPublication = ((_durableRestored: boolean) => {
        restoreMarkers();
      }) as StewardSessionRecoveryPublicationRollback;
      rollbackPublication.beforeDurableRestore = restoreMarkers;
      return rollbackPublication;
    },
    publishChange: () => {
      if (!finalized || !finalizedStateIsLive()) return false;
      notifyRecoveryChange();
      return finalizedStateIsLive();
    },
  };
}

/**
 * Build a rollbackable fence for one live login receipt. The finalizer removes
 * the receipt silently inside `writeStoredStewardToken`; `publishChange` is
 * intentionally separate so callers can first verify the returned token-write
 * authority and exact canonical token.
 */
export function createStewardSessionRecoveryPublicationFence(
  recovery: StewardSessionRecoveryReceipt,
): StewardSessionRecoveryPublicationFence {
  return createRecoveryPublicationFence({
    tenantId: recovery.tenantId,
    receipts: [recovery.receipt, ...recovery.preexistingReceipts],
    generation: recovery.receipt,
    isLive: () => isStewardSessionRecoveryReceiptLive(recovery),
  });
}

/** Build the same rollbackable publication fence for an exact cookie snapshot. */
export function createStewardSessionRecoverySnapshotPublicationFence(
  snapshot: StewardSessionRecoverySnapshot,
): StewardSessionRecoveryPublicationFence {
  return createRecoveryPublicationFence({
    tenantId: snapshot.tenantId,
    receipts: snapshot.receipts,
    generation: snapshot.generation,
    isLive: () => isStewardSessionRecoverySnapshotLive(snapshot),
  });
}

/** Retire exactly the receipts reconciled by one cookie-first read. */
export function completeStewardSessionRecoverySnapshot(
  snapshot: StewardSessionRecoverySnapshot,
): void {
  removeReceipts(snapshot.tenantId, snapshot.receipts);
}
