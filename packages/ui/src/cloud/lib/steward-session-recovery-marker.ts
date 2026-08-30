/**
 * Durable proof that a browser -> server Steward session mutation may have
 * committed while its renderer continuation was interrupted.
 *
 * Each intent owns a distinct localStorage key.  That deliberately avoids a
 * read/modify/write marker array: two tabs can create or retire receipts
 * without one tab erasing the other's newer ambiguity proof.
 */

export const STEWARD_SESSION_RECOVERY_CHANGE_EVENT =
  "eliza-steward-session-recovery-change";

const RECOVERY_KEY_PREFIX = "eliza.steward.server-session-recovery.v2";
const LOGOUT_KEY_PREFIX = "eliza.steward.server-session-logout.v1";
const GENERATION_KEY_PREFIX = "eliza.steward.server-session-generation.v1";

export type StewardSessionRecoveryKind = "oauth" | "provider" | "telegram";
export type StewardSessionLogoutKind = "logout" | "account-switch";

export interface StewardSessionRecoverySnapshot {
  tenantId: string;
  receipts: readonly string[];
  /**
   * Last origin-wide mutation nonce. It is never rewound when receipts retire,
   * so an empty A snapshot cannot become live again after B begins and finishes.
   */
  generation: string | null;
  hasOAuth: boolean;
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

function parseMarkerKind(value: string | null): StewardSessionRecoveryKind {
  if (value === "oauth" || value === "provider" || value === "telegram") {
    return value;
  }
  try {
    const parsed: unknown = value === null ? null : JSON.parse(value);
    if (
      parsed !== null &&
      typeof parsed === "object" &&
      !Array.isArray(parsed)
    ) {
      const parsedKind = (parsed as { kind?: unknown }).kind;
      if (
        parsedKind === "oauth" ||
        parsedKind === "provider" ||
        parsedKind === "telegram"
      ) {
        return parsedKind;
      }
    }
  } catch (error) {
    // error-policy:J6 Corrupt marker contents still prove an ambiguous server
    // mutation. Conservatively recover it as a non-OAuth provider intent.
    void error;
  }
  return "provider";
}

function readMarkers(tenantId: string): {
  markers: Map<string, StewardSessionRecoveryKind>;
  storageAvailable: boolean;
} {
  const prefix = tenantKeyPrefix(tenantId);
  const markers = new Map<string, StewardSessionRecoveryKind>();
  if (typeof window === "undefined") {
    return { markers, storageAvailable: false };
  }
  try {
    for (let index = 0; index < window.localStorage.length; index += 1) {
      const key = window.localStorage.key(index);
      if (!key?.startsWith(prefix)) continue;
      const receipt = key.slice(prefix.length);
      if (!receipt) continue;
      markers.set(receipt, parseMarkerKind(window.localStorage.getItem(key)));
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
      JSON.stringify({ kind, createdAt: Date.now() }),
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

export function readStewardSessionRecovery(
  tenantId: string,
): StewardSessionRecoverySnapshot {
  const { markers, storageAvailable } = readMarkers(tenantId);
  const logout = readLogoutMarkers(tenantId);
  const generation = readGeneration(tenantId);
  return {
    tenantId,
    receipts: [...markers.keys()].sort(),
    generation: generation.generation,
    hasOAuth: [...markers.values()].includes("oauth"),
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

export function isStewardSessionRecoverySnapshotLive(
  expected: StewardSessionRecoverySnapshot,
): boolean {
  const current = readStewardSessionRecovery(expected.tenantId);
  return (
    expected.storageAvailable &&
    current.storageAvailable &&
    current.generation === expected.generation &&
    current.receipts.length === expected.receipts.length &&
    expected.receipts.every(
      (receipt, index) => current.receipts[index] === receipt,
    )
  );
}

/** Persist synchronously and call this immediately before network dispatch. */
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
  return (
    current.storageAvailable &&
    current.intents.some(({ receipt }) => receipt === intent.receipt)
  );
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

/**
 * Commit one live receipt immediately before publishing authenticated state.
 * The boolean is the publication fence: it proves every owned marker is gone
 * and no newer generation began before the post-removal read. A failed
 * localStorage removal or concurrent successor therefore keeps publication
 * fail-closed instead of being hidden behind the best-effort cleanup API.
 */
export function commitStewardSessionRecoveryForPublication(
  recovery: StewardSessionRecoveryReceipt,
): boolean {
  if (!isStewardSessionRecoveryReceiptLive(recovery)) return false;
  const ownedReceipts = [recovery.receipt, ...recovery.preexistingReceipts];
  removeReceipts(recovery.tenantId, ownedReceipts);
  const current = readStewardSessionRecovery(recovery.tenantId);
  return (
    current.storageAvailable &&
    current.generation === recovery.receipt &&
    ownedReceipts.every((receipt) => !current.receipts.includes(receipt))
  );
}

/** Retire exactly the receipts reconciled by one cookie-first read. */
export function completeStewardSessionRecoverySnapshot(
  snapshot: StewardSessionRecoverySnapshot,
): void {
  removeReceipts(snapshot.tenantId, snapshot.receipts);
}
