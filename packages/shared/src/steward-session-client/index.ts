/**
 * Shared Steward session client.
 *
 * Single source of truth for:
 *  - the storage / cookie / endpoint key names used across the unified
 *    frontend (`eliza.app`) and the cloud-api
 *    `/api/auth/steward-session` route handler;
 *  - the request / response / error shapes the route exchanges with the
 *    browser;
 *  - the small set of helpers each consumer needs (sync, clear, read).
 *
 * Browser-only helpers return cleanly under SSR (`typeof window === "undefined"`).
 */

import { classifyElizaHostname } from "../elizacloud/domain-contract.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** localStorage key for the Steward access token (JWT). */
export const STEWARD_TOKEN_KEY = "steward_session_token";

/**
 * Deployment scope paired with the Steward access token on a loopback-rendered
 * app. Hosted Cloud origins already isolate localStorage by origin; localhost
 * does not, so this companion key prevents a token minted for one configured
 * control plane from crossing into another after a local target switch.
 */
export const STEWARD_TOKEN_SCOPE_KEY = "steward_session_token_scope";

/** Current loopback app target, stored separately from the token's mint scope. */
export const STEWARD_ACTIVE_SCOPE_KEY = "steward_session_active_scope";

/** Typed browser event emitted after a canonical Steward token mutation. */
export const STEWARD_SESSION_CHANGE_EVENT = "steward-session-change";

export interface StewardSessionChangeDetail {
  state: "present" | "cleared";
  sessionEpoch: number;
}

let sessionEpoch = 0;
let stewardTokenMutationTail: Promise<void> = Promise.resolve();
let stewardTokenMutationAuthority = Symbol("initial-steward-token-authority");

export type StewardTokenWriteValidator = () => boolean;
export interface StewardTokenRemovalOptions {
  /**
   * Exact canonical value owned by the caller. `null` means the caller
   * observed no token; it is distinct from omitting the options, which keeps
   * the explicit-log-out API's unconditional removal semantics.
   */
  expectedToken: string | null;
  validate?: StewardTokenWriteValidator;
}
type StewardTokenRemoval = (options?: StewardTokenRemovalOptions) => Promise<
  | boolean
  // biome-ignore lint/suspicious/noConfusingVoidType: legacy host adapters returned void before exact CAS outcomes were introduced.
  | void
>;
type StewardTokenPersistenceCommit = (
  validate?: StewardTokenWriteValidator,
) => Promise<void>;
export interface StewardTokenPersistenceTransaction {
  commit(validate?: StewardTokenWriteValidator): Promise<void>;
  /** Restore only the predecessor captured by this exact host write receipt. */
  restorePredecessor(validate?: StewardTokenWriteValidator): Promise<boolean>;
}
type StewardTokenPersistenceResult =
  // biome-ignore lint/suspicious/noConfusingVoidType: void preserves compatibility with adapters that need no host receipt.
  void | StewardTokenPersistenceCommit | StewardTokenPersistenceTransaction;
export interface StewardTokenHostPersistenceContext {
  /** Opaque capability supplied by the caller and interpreted by the host. */
  hostContext?: unknown;
  previousScope: string | null;
  requiredScope: string | null;
}
type StewardTokenPersistence = (
  token: string,
  context: StewardTokenHostPersistenceContext,
) => Promise<StewardTokenPersistenceResult>;
interface PersistedStewardTokenTransaction {
  commit: StewardTokenPersistenceCommit;
  restorePredecessor:
    | ((validate?: StewardTokenWriteValidator) => Promise<boolean>)
    | null;
}
type StewardTokenCompareAndRestore = (
  expectedToken: string,
  restoreToken: string | null,
  options?: Pick<StewardTokenRemovalOptions, "validate">,
) => Promise<boolean>;

let stewardTokenRemoval: StewardTokenRemoval | null = null;
let stewardTokenPersistence: StewardTokenPersistence | null = null;
let stewardTokenCompareAndRestore: StewardTokenCompareAndRestore | null = null;

/**
 * Orders canonical token writes and removals through their authority event.
 * The host secure-store adapter also serializes native I/O, but queueing only
 * at that lower layer lets a later writer update its in-memory cache before an
 * earlier writer publishes `present`. Consumers handling the earlier event can
 * then observe a newer token that has not reached durable storage yet. Keeping
 * the producer and its event in one queue closes that authority race.
 */
function serializeStewardTokenMutation<T>(
  operation: () => Promise<T>,
): Promise<T> {
  const result = stewardTokenMutationTail
    .catch(() => undefined)
    .then(operation);
  stewardTokenMutationTail = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

function advanceStewardTokenMutationAuthority(): symbol {
  const authority = Symbol("steward-token-write");
  stewardTokenMutationAuthority = authority;
  return authority;
}

function exactStoredStewardTokenIsCurrent(
  token: string,
  requiredScope: string | null,
): boolean {
  return (
    window.localStorage.getItem(STEWARD_TOKEN_KEY) === token &&
    (!requiredScope ||
      window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) === requiredScope)
  );
}

/** Distinguishes a failed durable token write from an ordinary auth failure. */
export class StewardTokenPersistenceError extends Error {
  constructor(cause: unknown) {
    super(
      cause instanceof Error
        ? cause.message
        : "Could not persist the protected Steward token",
      { cause },
    );
    this.name = "StewardTokenPersistenceError";
  }
}

/** Distinguishes a failed canonical token removal from legacy-key cleanup. */
export class StewardTokenRemovalError extends Error {
  constructor(cause: unknown) {
    super(
      cause instanceof Error
        ? cause.message
        : "Could not remove the protected Steward token",
      { cause },
    );
    this.name = "StewardTokenRemovalError";
  }
}

/** Publish a credential-domain-specific transition without exposing the token. */
export function dispatchStewardSessionChange(
  state: StewardSessionChangeDetail["state"],
): void {
  if (typeof window === "undefined") return;
  sessionEpoch += 1;
  window.dispatchEvent(
    new CustomEvent<StewardSessionChangeDetail>(STEWARD_SESSION_CHANGE_EVENT, {
      detail: { state, sessionEpoch },
    }),
  );
}

/**
 * Installs the host-owned durable removal boundary for the Steward token.
 * Browser-only consumers fall back to localStorage; native shells register
 * their awaited secure-store implementation while the storage bridge is live.
 */
export function registerStewardTokenRemoval(
  removal: StewardTokenRemoval,
): () => void {
  stewardTokenRemoval = removal;
  return () => {
    if (stewardTokenRemoval === removal) stewardTokenRemoval = null;
  };
}

/**
 * Installs the host-owned durable persistence boundary for the Steward token.
 * Native shells register an awaited secure-store write plus exact readback;
 * browser-only consumers retain the localStorage fallback.
 */
export function registerStewardTokenPersistence(
  persistence: StewardTokenPersistence,
): () => void {
  stewardTokenPersistence = persistence;
  return () => {
    if (stewardTokenPersistence === persistence) {
      stewardTokenPersistence = null;
    }
  };
}

/**
 * Installs the host-owned exact-value rollback boundary for an interrupted
 * Steward token write. The callback restores `restoreToken` only while the
 * durable current value still equals `expectedToken`; a newer value wins.
 */
export function registerStewardTokenCompareAndRestore(
  compareAndRestore: StewardTokenCompareAndRestore,
): () => void {
  stewardTokenCompareAndRestore = compareAndRestore;
  return () => {
    if (stewardTokenCompareAndRestore === compareAndRestore) {
      stewardTokenCompareAndRestore = null;
    }
  };
}

/**
 * localStorage key for the Steward refresh token.
 *
 * Refresh tokens are persisted only as the rollout-isolated HttpOnly
 * `__Host-steward-refresh-token-v2`
 * cookie (set by `/api/auth/steward-session` and
 * `/api/auth/steward-nonce-exchange`). This key is retained solely so
 * `clearStoredStewardToken()` can drain the stale localStorage value left in
 * tabs opened before the cookie-only rollout. Do NOT read or write it.
 */
export const STEWARD_REFRESH_TOKEN_KEY = "steward_refresh_token";

/**
 * Non-HttpOnly v2 authority marker. `1` means the v2 server session is live;
 * `0` is a persistent logout tombstone that prevents fallback to v1 cookies.
 */
export const STEWARD_AUTHED_COOKIE = "__Host-steward-authed-v2";
const LOCAL_STEWARD_AUTHED_COOKIE = "steward-authed-v2";

/** Steward multi-tenant identifier for Eliza Cloud. */
export const STEWARD_TENANT_ID = "elizacloud";

/** Same-origin endpoint that exchanges the JWT for HttpOnly cookies. */
export const STEWARD_SESSION_ENDPOINT = "/api/auth/steward-session";

/**
 * Same-origin endpoint that swaps a one-time OAuth `code` (the nonce-exchange
 * flow's `?code=` query param) for HttpOnly cookies. The endpoint calls
 * Steward's `POST /auth/oauth/exchange` server-side so the access and refresh
 * tokens never touch the browser URL.
 */
export const STEWARD_NONCE_EXCHANGE_ENDPOINT =
  "/api/auth/steward-nonce-exchange";

/**
 * Same-origin endpoint that rotates the Steward access + refresh tokens
 * using the HttpOnly `steward-refresh-token` cookie. The browser POSTs
 * with `credentials: "include"`; the cookie travels automatically. Trusted
 * Cloud browser origins receive the short-lived access token so the SPA can
 * refresh its localStorage mirror while route auth remains synchronous.
 */
export const STEWARD_REFRESH_ENDPOINT = "/api/auth/steward-refresh";

/**
 * Custom CSRF marker header required by the cloud-api cookie-authenticated
 * auth mutations. Presence alone is the contract: a cross-origin "simple
 * request" cannot set custom headers, so any request carrying it either
 * survived a preflight or never needed one (same-origin / non-browser).
 */
export const STEWARD_CSRF_HEADER = "x-eliza-csrf";
export const STEWARD_CSRF_HEADER_VALUE = "1";

/**
 * Exact CSRF-header value sent by browser cookie writers only after entering
 * the origin-wide Steward session mutation queue, or by an isolated non-browser
 * client whose singleton control flow supplies the same no-concurrent-writer
 * guarantee. This value explicitly activates the v2 cookie namespace. The
 * legacy `1` marker remains on v1 only before activation; after any v2
 * authority exists, an older tab is rejected before it consumes upstream
 * authority or emits a Set-Cookie header.
 *
 * This is a first-party protocol/version marker, not an authentication
 * credential. Origin/CSRF validation and the HttpOnly refresh cookie remain
 * the request authorities.
 */
export const STEWARD_SESSION_MUTATION_PROTOCOL_VALUE =
  "steward-session-web-lock.v1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StewardSessionRequest {
  token: string;
  refreshToken?: string | null;
  /** Phone independently re-verified by the Cloud API against this bearer. */
  verifiedPhone?: string;
}

export interface StewardTelegramClaimConfirmationRequest
  extends StewardSessionRequest {
  /** Opaque Telegram DM continuation that names an existing rowless account. */
  telegramContinuation: string;
  /** Explicit confirmation ceremony marker; ordinary login sync never sends it. */
  telegramClaimConfirmation: "explicit";
}

const TELEGRAM_ACCOUNT_CLAIM_PATTERN = /^[a-zA-Z0-9:+_-]{8,180}$/;

/**
 * Accepts only opaque browser credentials. Platform-scoped ids are derived
 * from guessable messaging ids and must remain inside trusted gateways.
 */
export function sanitizeTelegramAccountClaimContinuation(
  value: unknown,
): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (
    !TELEGRAM_ACCOUNT_CLAIM_PATTERN.test(trimmed) ||
    trimmed.startsWith("platform:")
  ) {
    return null;
  }
  return trimmed;
}

export interface StewardSessionResponse {
  ok: true;
  userId: string;
  stewardUserId: string;
  initialCreditsGranted?: boolean;
  initialFreeCreditsUsd?: number;
  welcomeBonusWithheld?: boolean;
  // Mirrors `SignupGrantWithheldReason` in
  // packages/cloud/shared/src/lib/services/signup-grant-guard.ts (the source of
  // truth). Kept as an inline literal union because `packages/shared` cannot
  // depend on `packages/cloud/shared`; keep in sync when reasons are added.
  welcomeBonusWithheldReason?: "ip_daily_cap" | "count_unavailable";
  welcomeBonusWithheldMessage?: string;
}

/**
 * Distinct outcomes the cloud-api route returns. The client uses these to
 * decide whether to wipe localStorage (`invalid_token`) or hold steady
 * (`server_secret_missing`).
 */
export type StewardSessionErrorCode =
  | "missing_token"
  | "invalid_token"
  /** The user explicitly logged out AFTER this token was issued (cross-host
   * SSO logout marker). A real revocation: clients clear the stored session
   * instead of retrying the sync. */
  | "session_ended"
  /** A newly issued token landed inside the logout marker's bounded issuer
   * clock-skew window. It remains blocked, but is not claimed to be revoked:
   * wait for `retryAfterSeconds`, then authenticate again for a new token. */
  | "logout_cooldown"
  /** The SSO logout-marker store is unreachable and the token is
   * bridge-issued, so the sync fails closed (503). Transient: clients hold
   * the stored session and retry, as with `server_secret_missing`. */
  | "sso_unavailable"
  | "server_secret_missing"
  | "steward_user_sync_failed"
  | "verified_phone_invalid"
  | "verified_phone_mismatch"
  | "verified_phone_conflict"
  | "telegram_claim_conflict"
  | "internal_error"
  // Nonce-exchange (response_type=code) outcomes. Surfaced both by the
  // cloud-api route and proxied through from Steward's /oauth/exchange.
  | "missing_code"
  | "code_invalid"
  | "code_expired"
  | "code_redirect_mismatch"
  | "code_tenant_mismatch"
  /** The exchange was attempted without the PKCE verifier. The hosted login
   * always starts the flow with a S256 challenge, so this is a planted or
   * pre-PKCE callback — the client must restart sign-in. */
  | "missing_code_verifier"
  | "steward_upstream_unavailable"
  /** The request carried no non-simple-request marker (custom X-Eliza-CSRF
   * header or JSON content type), so it could have been a cross-origin
   * simple request. Rejected before any cookie was read. */
  | "csrf_marker_required"
  /** The browser cookie writer predates the origin-wide session-mutation
   * protocol. It must reload/update before it can safely mutate cookies. */
  | "session_mutation_protocol_required"
  | "forbidden_origin";

export class StewardSessionError extends Error {
  readonly status: number;
  readonly code: StewardSessionErrorCode | string | null;
  readonly retryAfterSeconds: number | null;
  readonly retryAtEpochSeconds: number | null;

  constructor(
    message: string,
    status: number,
    code: StewardSessionErrorCode | string | null,
    options?: {
      retryAfterSeconds?: number | null;
      retryAtEpochSeconds?: number | null;
    },
  ) {
    super(message);
    this.name = "StewardSessionError";
    this.status = status;
    this.code = code;
    this.retryAfterSeconds =
      typeof options?.retryAfterSeconds === "number" &&
      Number.isFinite(options.retryAfterSeconds) &&
      options.retryAfterSeconds >= 0
        ? Math.ceil(options.retryAfterSeconds)
        : null;
    this.retryAtEpochSeconds =
      typeof options?.retryAtEpochSeconds === "number" &&
      Number.isFinite(options.retryAtEpochSeconds) &&
      options.retryAtEpochSeconds >= 0
        ? Math.floor(options.retryAtEpochSeconds)
        : null;
  }
}

export interface SyncOpts {
  /**
   * Absolute or relative URL to POST to. Defaults to STEWARD_SESSION_ENDPOINT
   * (same-origin). Pass an absolute URL when crossing origins
   * (e.g. elizaos.ai -> api.eliza.app).
   */
  endpoint?: string;
  /**
   * Override the global fetch (mainly for tests and SSR shims).
   */
  fetchImpl?: typeof fetch;
  /**
   * Present only when the caller owns the origin-wide Steward mutation lease.
   * Omitting it deliberately emits the legacy marker. That marker may mutate
   * only v1 while v2 is wholly absent and is rejected after v2 activation.
   */
  sessionMutationProtocol?: typeof STEWARD_SESSION_MUTATION_PROTOCOL_VALUE;
}

export interface ClearOpts {
  /** Endpoints to DELETE. Defaults to [STEWARD_SESSION_ENDPOINT]. */
  endpoints?: string[];
  fetchImpl?: typeof fetch;
  /** See {@link SyncOpts.sessionMutationProtocol}. */
  sessionMutationProtocol?: typeof STEWARD_SESSION_MUTATION_PROTOCOL_VALUE;
}

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

function isLoopbackRenderedApp(): boolean {
  if (typeof window === "undefined") return false;
  const protocol = window.location?.protocol?.toLowerCase() ?? "";
  if (protocol !== "http:" && protocol !== "https:") return false;
  const hostname = window.location?.hostname?.toLowerCase() ?? "";
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]" ||
    hostname.startsWith("127.")
  );
}

function stewardScopeForBase(configuredBase: string): string | null {
  try {
    const parsed = new URL(configuredBase);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    const classified = classifyElizaHostname(parsed.hostname);
    if (classified.environment) {
      return `eliza-cloud:${classified.environment}`;
    }
    return `origin:${parsed.origin}`;
  } catch {
    return null;
  }
}

/**
 * Bind this loopback page to its launcher-selected Cloud control plane before
 * any auth reads. Hosted pages need no marker because browser origins already
 * isolate their storage. Invalid local targets publish a fail-closed sentinel.
 */
export function configureStoredStewardTokenScope(
  configuredBase: string | null | undefined,
): void {
  if (!isLoopbackRenderedApp()) return;
  const scope = configuredBase?.trim()
    ? stewardScopeForBase(configuredBase.trim())
    : null;
  window.localStorage.setItem(
    STEWARD_ACTIVE_SCOPE_KEY,
    scope ?? "invalid:unconfigured-cloud-target",
  );
}

function configuredLoopbackStewardScope(): string | null {
  if (!isLoopbackRenderedApp()) return null;
  return window.localStorage.getItem(STEWARD_ACTIVE_SCOPE_KEY);
}

/**
 * Reads the canonical access token. Returns `null` for SSR or a missing token;
 * storage access failures propagate so callers cannot mistake them for logout.
 */
export function readStoredStewardToken(): string | null {
  if (typeof window === "undefined") return null;
  const token = window.localStorage.getItem(STEWARD_TOKEN_KEY);
  if (!token) return null;
  const requiredScope = configuredLoopbackStewardScope();
  if (!requiredScope) return token;
  return window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) === requiredScope
    ? token
    : null;
}

async function persistStoredStewardToken(
  token: string,
  requiredScope: string | null,
  previousToken: string | null,
  previousScope: string | null,
  hostContext?: unknown,
): Promise<PersistedStewardTokenTransaction | null> {
  let tokenPersisted = false;
  let transaction: PersistedStewardTokenTransaction | null = null;
  try {
    if (stewardTokenPersistence) {
      const result = await stewardTokenPersistence(token, {
        ...(hostContext === undefined ? {} : { hostContext }),
        previousScope,
        requiredScope,
      });
      if (typeof result === "function") {
        transaction = {
          commit: result,
          restorePredecessor: null,
        };
      } else if (result) {
        transaction = {
          commit: result.commit.bind(result),
          restorePredecessor: result.restorePredecessor.bind(result),
        };
      }
    } else {
      window.localStorage.setItem(STEWARD_TOKEN_KEY, token);
    }
    tokenPersisted = true;
    // Scope is deliberately published only after transaction.commit below.
    // A process death while a host WAL is still prepared therefore leaves the
    // predecessor scope beside the predecessor token instead of making an old
    // production credential readable under a staging scope (or vice versa).
    return transaction;
  } catch (error) {
    if (tokenPersisted) {
      const rollbackFailures: unknown[] = [];
      let tokenRestored = false;
      try {
        tokenRestored = transaction?.restorePredecessor
          ? await transaction.restorePredecessor()
          : await compareAndRestoreStoredStewardToken(token, previousToken);
        if (tokenRestored) advanceStewardTokenMutationAuthority();
        if (!tokenRestored) {
          rollbackFailures.push(
            new Error("Protected Steward token rollback lost authority."),
          );
        }
      } catch (rollbackError) {
        rollbackFailures.push(rollbackError);
      }
      // Scope is subordinate to the exact token CAS above. If another
      // renderer replaced A with account B while A's scope publication was
      // failing, A must not roll B's scope back to its own predecessor. Even
      // after a successful host CAS, re-check both browser mirrors so a newer
      // writer that published between the awaited CAS and this continuation
      // keeps authority.
      if (
        tokenRestored &&
        window.localStorage.getItem(STEWARD_TOKEN_KEY) === previousToken &&
        window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) === requiredScope
      ) {
        try {
          if (previousScope === null) {
            window.localStorage.removeItem(STEWARD_TOKEN_SCOPE_KEY);
          } else {
            window.localStorage.setItem(STEWARD_TOKEN_SCOPE_KEY, previousScope);
          }
        } catch (scopeRollbackError) {
          rollbackFailures.push(scopeRollbackError);
        }
      }
      if (rollbackFailures.length > 0) {
        throw new StewardTokenPersistenceError(
          new AggregateError(
            [error, ...rollbackFailures],
            "Could not restore the previous Steward token transaction.",
          ),
        );
      }
    }
    // error-policy:J2 callers must not publish authenticated state after a
    // failed durable write on a protected host.
    throw new StewardTokenPersistenceError(error);
  }
}

async function compareAndRestoreStoredStewardToken(
  expectedToken: string,
  restoreToken: string | null,
  options?: Pick<StewardTokenRemovalOptions, "validate">,
): Promise<boolean> {
  if (stewardTokenCompareAndRestore) {
    return stewardTokenCompareAndRestore(expectedToken, restoreToken, options);
  }
  if (options?.validate?.() === false) return false;
  if (window.localStorage.getItem(STEWARD_TOKEN_KEY) !== expectedToken) {
    return false;
  }
  if (options?.validate?.() === false) return false;
  if (restoreToken === null) {
    window.localStorage.removeItem(STEWARD_TOKEN_KEY);
  } else {
    window.localStorage.setItem(STEWARD_TOKEN_KEY, restoreToken);
  }
  return true;
}

/** Exact, opaque rollback authority for one successfully published write. */
export interface StewardTokenWriteAuthority {
  /**
   * Restore only this write's host-recorded predecessor. A stale receipt or
   * revision returns false, so same-value ABA from a newer account wins.
   */
  restorePredecessor(options?: {
    validate?: StewardTokenWriteValidator;
    /** Delay the restored-state event until the caller invokes `publish()`. */
    deferPublication?: boolean;
  }): Promise<boolean>;
  /**
   * Publish a restored predecessor whose event was explicitly deferred.
   * Optional for structural compatibility with authorities returned by older
   * platform adapters; this module's authorities always provide it.
   */
  publish?(): boolean;
}

/**
 * Revert the subordinate live/client state installed by a protected write.
 * `durableRestored` is true only when the exact durable predecessor and scope
 * are already canonical. A false value must clear the staged successor
 * fail-closed instead of installing a predecessor beside a still-current token.
 */
export type StewardTokenPublicationRollback = ((
  durableRestored: boolean,
) => void) & {
  /** Restore durable ambiguity proof before any awaited token compensation. */
  beforeDurableRestore?: () => void;
};

interface PreparedStewardTokenPublicationRollback {
  afterDurableRestore(durableRestored: boolean): void;
  beforeDurableRestore(): void;
}

export interface StewardTokenWriteOptions {
  signal?: AbortSignal;
  /**
   * Opaque capability interpreted only by the installed host persistence
   * adapter. The Electrobun adapter uses an identity-branded transaction
   * handle so an unrelated writer cannot join an ambient connection WAL.
   */
  hostPersistenceContext?: unknown;
  /**
   * Revalidates the caller's external authority after every awaited durable
   * boundary and immediately before publishing `present`. Returning false
   * compensates this exact write back to its predecessor without an event.
   */
  validate?: StewardTokenWriteValidator;
  /**
   * Synchronously install subordinate live/boot state after the durable token
   * commits but before any authority event or promise resolution. Returning a
   * rollback lets shared compensation restore that state without publishing an
   * intermediate mixed account. A throwing callback must undo any partial work
   * before it throws because no rollback value was returned.
   */
  finalizeBeforePublish?: () => StewardTokenPublicationRollback | undefined;
  /**
   * Synchronously retire the caller's durable recovery receipt after final
   * validation and subordinate-state installation. False suppresses the event
   * and compensates both token and finalizer state.
   */
  commitBeforePublish?: () => boolean;
}

function oneShotPublicationRollback(
  rollback: StewardTokenPublicationRollback | undefined,
): PreparedStewardTokenPublicationRollback | null {
  if (!rollback) return null;
  let beforeCompleted = false;
  let afterCompleted = false;
  return {
    beforeDurableRestore() {
      if (beforeCompleted) return;
      rollback.beforeDurableRestore?.();
      beforeCompleted = true;
    },
    afterDurableRestore(durableRestored) {
      if (afterCompleted) return;
      rollback(durableRestored);
      afterCompleted = true;
    },
  };
}

function synchronousPublicationRollback(
  value: unknown,
): PreparedStewardTokenPublicationRollback | null {
  if (
    value !== null &&
    typeof value === "object" &&
    "then" in value &&
    typeof (value as { then?: unknown }).then === "function"
  ) {
    throw new TypeError("Steward token finalization must be synchronous.");
  }
  if (value !== undefined && typeof value !== "function") {
    throw new TypeError(
      "Steward token finalization must return a synchronous rollback function.",
    );
  }
  return oneShotPublicationRollback(
    value as StewardTokenPublicationRollback | undefined,
  );
}

async function compensateUnpublishedStewardTokenWrite(
  token: string,
  previousToken: string | null,
  requiredScope: string | null,
  previousScope: string | null,
  restorePredecessor?:
    | ((validate?: StewardTokenWriteValidator) => Promise<boolean>)
    | null,
  rollbackPublication?: PreparedStewardTokenPublicationRollback | null,
): Promise<void> {
  const failures: unknown[] = [];
  let canonicalPredecessorRestored = false;
  let durableRestoreAllowed = true;
  try {
    rollbackPublication?.beforeDurableRestore();
  } catch (error) {
    failures.push(error);
    durableRestoreAllowed = false;
  }
  if (durableRestoreAllowed) {
    try {
      const restored = restorePredecessor
        ? await restorePredecessor()
        : await compareAndRestoreStoredStewardToken(token, previousToken);
      const currentToken = window.localStorage.getItem(STEWARD_TOKEN_KEY);
      if (!restored && currentToken === token) {
        throw new Error("Protected Steward token rollback lost authority.");
      }
      if (
        restored &&
        currentToken === previousToken &&
        requiredScope &&
        window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) === requiredScope
      ) {
        if (previousScope === null) {
          window.localStorage.removeItem(STEWARD_TOKEN_SCOPE_KEY);
        } else {
          window.localStorage.setItem(STEWARD_TOKEN_SCOPE_KEY, previousScope);
        }
      }
      canonicalPredecessorRestored =
        restored &&
        window.localStorage.getItem(STEWARD_TOKEN_KEY) === previousToken &&
        (!requiredScope ||
          window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) ===
            previousScope);
      if (canonicalPredecessorRestored) {
        advanceStewardTokenMutationAuthority();
      }
    } catch (error) {
      failures.push(error);
    }
  }
  if (durableRestoreAllowed) {
    // Durable ambiguity markers have already been restored above. Revert the
    // staged live/client pair only after canonical token compensation so no
    // listener can observe a predecessor client beside successor bytes.
    try {
      rollbackPublication?.afterDurableRestore(canonicalPredecessorRestored);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length === 1) {
    throw new StewardTokenPersistenceError(failures[0]);
  }
  if (failures.length > 1) {
    throw new StewardTokenPersistenceError(
      new AggregateError(
        failures,
        "Could not compensate the unpublished Steward token transaction.",
      ),
    );
  }
}

function publishedWriteAuthority(
  token: string,
  previousToken: string | null,
  requiredScope: string | null,
  previousScope: string | null,
  restorePredecessor:
    | ((validate?: StewardTokenWriteValidator) => Promise<boolean>)
    | null,
  writeAuthority: symbol,
  rollbackPublication: PreparedStewardTokenPublicationRollback | null,
): StewardTokenWriteAuthority {
  let restoration: Promise<boolean> | null = null;
  let pendingRestoredState: StewardSessionChangeDetail["state"] | null = null;
  let coherentRestorationCompleted = false;
  let restoredStatePublished = false;
  const exactRestore =
    restorePredecessor ??
    ((validate?: StewardTokenWriteValidator) => {
      if (stewardTokenMutationAuthority !== writeAuthority) {
        return Promise.resolve(false);
      }
      return compareAndRestoreStoredStewardToken(token, previousToken, {
        validate,
      });
    });
  return {
    restorePredecessor(options) {
      if (restoration) return restoration;
      const operation = serializeStewardTokenMutation(async () => {
        if (
          options?.validate?.() === false ||
          stewardTokenMutationAuthority !== writeAuthority
        ) {
          return false;
        }
        const failures: unknown[] = [];
        let restored = false;
        let durableRestoreAllowed = true;
        try {
          rollbackPublication?.beforeDurableRestore();
        } catch (error) {
          failures.push(error);
          durableRestoreAllowed = false;
        }
        if (durableRestoreAllowed) {
          try {
            restored = await exactRestore(options?.validate);
          } catch (error) {
            failures.push(error);
          }
        }
        if (restored) {
          advanceStewardTokenMutationAuthority();
        }
        if (
          restored &&
          window.localStorage.getItem(STEWARD_TOKEN_KEY) === previousToken &&
          requiredScope &&
          window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) === requiredScope
        ) {
          try {
            if (previousScope === null) {
              window.localStorage.removeItem(STEWARD_TOKEN_SCOPE_KEY);
            } else {
              window.localStorage.setItem(
                STEWARD_TOKEN_SCOPE_KEY,
                previousScope,
              );
            }
          } catch (error) {
            failures.push(error);
          }
        }
        let coherentPredecessor =
          restored &&
          failures.length === 0 &&
          window.localStorage.getItem(STEWARD_TOKEN_KEY) === previousToken &&
          (!requiredScope ||
            window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) ===
              previousScope);
        if (durableRestoreAllowed) {
          try {
            rollbackPublication?.afterDurableRestore(coherentPredecessor);
          } catch (error) {
            failures.push(error);
            coherentPredecessor = false;
          }
        }
        coherentPredecessor =
          coherentPredecessor &&
          window.localStorage.getItem(STEWARD_TOKEN_KEY) === previousToken &&
          (!requiredScope ||
            window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) ===
              previousScope);
        if (failures.length > 0) {
          throw new StewardTokenPersistenceError(
            new AggregateError(
              failures,
              "Could not publish the restored Steward token predecessor.",
            ),
          );
        }
        if (!coherentPredecessor) return false;
        coherentRestorationCompleted = true;
        if (previousToken !== token && options?.validate?.() !== false) {
          const restoredState = previousToken === null ? "cleared" : "present";
          if (options?.deferPublication) {
            pendingRestoredState = restoredState;
          } else {
            dispatchStewardSessionChange(restoredState);
            restoredStatePublished = true;
          }
        }
        return true;
      });
      restoration = operation;
      void operation.catch(() => {
        if (restoration === operation) restoration = null;
      });
      return operation;
    },
    publish() {
      if (!pendingRestoredState) {
        return (
          restoredStatePublished ||
          (coherentRestorationCompleted &&
            previousToken === token &&
            window.localStorage.getItem(STEWARD_TOKEN_KEY) === previousToken &&
            (!requiredScope ||
              window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) ===
                previousScope))
        );
      }
      if (
        window.localStorage.getItem(STEWARD_TOKEN_KEY) !== previousToken ||
        (requiredScope &&
          window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) !==
            previousScope)
      ) {
        return false;
      }
      const state = pendingRestoredState;
      pendingRestoredState = null;
      dispatchStewardSessionChange(state);
      restoredStatePublished = true;
      return true;
    },
  };
}

/**
 * Persists the canonical token and publishes authority only after the durable
 * host boundary succeeds. A protected-store rejection never becomes a
 * healthy-looking in-memory login that disappears on relaunch.
 */
export async function writeStoredStewardToken(
  token: string,
  options?: StewardTokenWriteOptions,
): Promise<StewardTokenWriteAuthority | null> {
  if (typeof window === "undefined") return null;
  return serializeStewardTokenMutation(async () => {
    options?.signal?.throwIfAborted();
    if (options?.validate?.() === false) return null;
    const requiredScope = configuredLoopbackStewardScope();
    const previousToken = window.localStorage.getItem(STEWARD_TOKEN_KEY);
    const previousScope = window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY);
    const wasCurrent =
      previousToken === token &&
      (!requiredScope || previousScope === requiredScope);
    if (
      !stewardTokenPersistence &&
      wasCurrent &&
      !options?.finalizeBeforePublish &&
      !options?.commitBeforePublish
    ) {
      return null;
    }
    const transaction = await persistStoredStewardToken(
      token,
      requiredScope,
      previousToken,
      previousScope,
      options?.hostPersistenceContext,
    );
    const abortedAfterPersistence = options?.signal?.aborted === true;
    const validAfterPersistence = options?.validate?.() !== false;
    if (abortedAfterPersistence || !validAfterPersistence) {
      await compensateUnpublishedStewardTokenWrite(
        token,
        previousToken,
        requiredScope,
        previousScope,
        transaction?.restorePredecessor,
      );
      if (!validAfterPersistence) return null;
      options?.signal?.throwIfAborted();
    }
    try {
      // The host receipt remains rollbackable until this validation has run
      // immediately before its acknowledgement. The caller still revalidates
      // below because another tab can synchronously plant a durable intent
      // while the host RPC itself is awaiting its response.
      await transaction?.commit(options?.validate);
      if (
        requiredScope &&
        window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) !== requiredScope
      ) {
        window.localStorage.setItem(STEWARD_TOKEN_SCOPE_KEY, requiredScope);
      }
    } catch (error) {
      try {
        await compensateUnpublishedStewardTokenWrite(
          token,
          previousToken,
          requiredScope,
          previousScope,
          transaction?.restorePredecessor,
        );
      } catch (compensationError) {
        throw new StewardTokenPersistenceError(
          new AggregateError(
            [error, compensationError],
            "Steward token commit and compensation both failed.",
          ),
        );
      }
      throw new StewardTokenPersistenceError(error);
    }
    // Receipt acknowledgement can itself await a renderer/host RPC. A newer
    // login may plant its recovery marker during that wait, after the earlier
    // pre-commit validation. Compensate the exact token before any observable
    // authority event in that case too.
    const abortedAfterCommit = options?.signal?.aborted === true;
    const validAfterCommit = options?.validate?.() !== false;
    if (abortedAfterCommit || !validAfterCommit) {
      await compensateUnpublishedStewardTokenWrite(
        token,
        previousToken,
        requiredScope,
        previousScope,
        transaction?.restorePredecessor,
      );
      if (!validAfterCommit) return null;
      options?.signal?.throwIfAborted();
    }
    const writeAuthority = advanceStewardTokenMutationAuthority();
    let rollbackPublication: PreparedStewardTokenPublicationRollback | null =
      null;
    try {
      rollbackPublication = synchronousPublicationRollback(
        options?.finalizeBeforePublish?.(),
      );
    } catch (error) {
      try {
        await compensateUnpublishedStewardTokenWrite(
          token,
          previousToken,
          requiredScope,
          previousScope,
          transaction?.restorePredecessor,
        );
      } catch (compensationError) {
        throw new StewardTokenPersistenceError(
          new AggregateError(
            [error, compensationError],
            "Steward token finalization and compensation both failed.",
          ),
        );
      }
      throw error;
    }
    const abortedAfterFinalization = options?.signal?.aborted === true;
    const validAfterFinalization =
      options?.validate?.() !== false &&
      exactStoredStewardTokenIsCurrent(token, requiredScope);
    if (abortedAfterFinalization || !validAfterFinalization) {
      await compensateUnpublishedStewardTokenWrite(
        token,
        previousToken,
        requiredScope,
        previousScope,
        transaction?.restorePredecessor,
        rollbackPublication,
      );
      if (!validAfterFinalization) return null;
      options?.signal?.throwIfAborted();
    }
    if (options?.commitBeforePublish) {
      let committed = false;
      try {
        committed = options.commitBeforePublish();
      } catch (error) {
        try {
          await compensateUnpublishedStewardTokenWrite(
            token,
            previousToken,
            requiredScope,
            previousScope,
            transaction?.restorePredecessor,
            rollbackPublication,
          );
        } catch (compensationError) {
          throw new StewardTokenPersistenceError(
            new AggregateError(
              [error, compensationError],
              "Steward receipt commit and token compensation both failed.",
            ),
          );
        }
        throw error;
      }
      if (
        !committed ||
        !exactStoredStewardTokenIsCurrent(token, requiredScope)
      ) {
        await compensateUnpublishedStewardTokenWrite(
          token,
          previousToken,
          requiredScope,
          previousScope,
          transaction?.restorePredecessor,
          rollbackPublication,
        );
        return null;
      }
    }
    if (!wasCurrent) dispatchStewardSessionChange("present");
    return publishedWriteAuthority(
      token,
      previousToken,
      requiredScope,
      previousScope,
      transaction?.restorePredecessor ?? null,
      writeAuthority,
      rollbackPublication,
    );
  });
}

/**
 * Replaces a token only while `expectedToken` still owns session authority.
 * The comparison, durable write, and event share the canonical mutation queue,
 * so a refresh response that arrives after logout cannot resurrect the session.
 */
export async function replaceStoredStewardTokenIfCurrent(
  expectedToken: string,
  token: string,
  options?: Pick<StewardTokenWriteOptions, "validate">,
): Promise<boolean> {
  if (typeof window === "undefined") return false;
  return serializeStewardTokenMutation(async () => {
    if (options?.validate?.() === false) return false;
    const current = readStoredStewardToken();
    if (current !== expectedToken) return false;
    const previousToken = window.localStorage.getItem(STEWARD_TOKEN_KEY);
    const previousScope = window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY);
    const requiredScope = configuredLoopbackStewardScope();
    const transaction = await persistStoredStewardToken(
      token,
      requiredScope,
      previousToken,
      previousScope,
    );
    if (options?.validate?.() === false) {
      await compensateUnpublishedStewardTokenWrite(
        token,
        previousToken,
        requiredScope,
        previousScope,
        transaction?.restorePredecessor,
      );
      return false;
    }
    try {
      await transaction?.commit(options?.validate);
      if (
        requiredScope &&
        window.localStorage.getItem(STEWARD_TOKEN_SCOPE_KEY) !== requiredScope
      ) {
        window.localStorage.setItem(STEWARD_TOKEN_SCOPE_KEY, requiredScope);
      }
    } catch (error) {
      try {
        await compensateUnpublishedStewardTokenWrite(
          token,
          previousToken,
          requiredScope,
          previousScope,
          transaction?.restorePredecessor,
        );
      } catch (compensationError) {
        throw new StewardTokenPersistenceError(
          new AggregateError(
            [error, compensationError],
            "Steward token replacement and compensation both failed.",
          ),
        );
      }
      throw new StewardTokenPersistenceError(error);
    }
    if (options?.validate?.() === false) {
      await compensateUnpublishedStewardTokenWrite(
        token,
        previousToken,
        requiredScope,
        previousScope,
        transaction?.restorePredecessor,
      );
      return false;
    }
    advanceStewardTokenMutationAuthority();
    if (current !== token) dispatchStewardSessionChange("present");
    return true;
  });
}

/**
 * Clears canonical authority before draining the obsolete refresh-token key.
 * Once the canonical removal succeeds, invalidation is published even if the
 * legacy cleanup fails; either storage failure remains observable to callers.
 */
export async function clearStoredStewardToken(
  options?: StewardTokenRemovalOptions,
): Promise<boolean> {
  if (typeof window === "undefined") return false;
  return serializeStewardTokenMutation(async () => {
    if (options?.validate?.() === false) return false;
    if (
      options &&
      window.localStorage.getItem(STEWARD_TOKEN_KEY) !== options.expectedToken
    ) {
      return false;
    }
    try {
      if (stewardTokenRemoval) {
        const removed = await stewardTokenRemoval(options);
        if (removed === false) return false;
      } else {
        if (options?.validate?.() === false) return false;
        if (
          options &&
          window.localStorage.getItem(STEWARD_TOKEN_KEY) !==
            options.expectedToken
        ) {
          return false;
        }
        window.localStorage.removeItem(STEWARD_TOKEN_KEY);
      }
    } catch (error) {
      // error-policy:J2 callers must distinguish canonical removal failure from
      // obsolete refresh-key cleanup so they never publish a false logout.
      throw new StewardTokenRemovalError(error);
    }
    // Once exact terminal removal is acquired, A stays deleted even if B plants
    // a marker while the host CAS awaits. The true result means teardown may
    // continue under its mutation lease; only the observable transition is
    // suppressed. Unlike canceled writes, terminal removals never restore A.
    const publishAllowed = options?.validate?.() !== false;
    advanceStewardTokenMutationAuthority();
    if (publishAllowed) dispatchStewardSessionChange("cleared");
    window.localStorage.removeItem(STEWARD_TOKEN_SCOPE_KEY);
    window.localStorage.removeItem(STEWARD_REFRESH_TOKEN_KEY);
    return true;
  });
}

/**
 * Returns true only when the exact non-HttpOnly v2 authority marker is `1`.
 * Legacy v1 markers never authorize automatic refresh, and duplicate exact
 * marker names fail closed instead of inheriting cookie-header ordering.
 */
export function stewardAuthedCookieName(environment?: string | null): string {
  const env = environment?.trim();
  if (env === "local") return `${LOCAL_STEWARD_AUTHED_COOKIE}-local`;
  if (!env || env === "production") return STEWARD_AUTHED_COOKIE;
  return `${STEWARD_AUTHED_COOKIE}-${env}`;
}

function inferStewardCookieEnvironment(): string | null {
  if (typeof window === "undefined") return null;
  const hostname = window.location.hostname.toLowerCase();
  if (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]"
  ) {
    return "local";
  }
  if (
    hostname === "staging.eliza.app" ||
    hostname === "cloud-staging.eliza.app" ||
    hostname === "api-staging.eliza.app" ||
    hostname === "develop.eliza-app.pages.dev" ||
    hostname === "staging.elizacloud.ai" ||
    hostname === "app-staging.elizacloud.ai" ||
    hostname === "api-staging.elizacloud.ai"
  ) {
    return "staging";
  }
  if (
    hostname === "dev.elizacloud.ai" ||
    hostname === "app-dev.elizacloud.ai" ||
    hostname === "api-dev.elizacloud.ai"
  ) {
    return "dev";
  }
  return null;
}

export function hasStewardAuthedCookie(environment?: string | null): boolean {
  if (typeof document === "undefined") return false;
  const resolvedEnvironment = environment ?? inferStewardCookieEnvironment();
  const expectedName = stewardAuthedCookieName(resolvedEnvironment);
  let value: string | undefined;
  let matches = 0;
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    const separator = trimmed.indexOf("=");
    if (separator < 0) continue;
    if (trimmed.slice(0, separator) !== expectedName) continue;
    matches += 1;
    value = trimmed.slice(separator + 1);
  }
  return matches === 1 && value === "1";
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

async function readErrorBody(response: Response): Promise<{
  error?: string;
  code?: string;
  retryAfterSeconds?: number;
  retryAtEpochSeconds?: number;
} | null> {
  try {
    return (await response.json()) as {
      error?: string;
      code?: string;
      retryAfterSeconds?: number;
      retryAtEpochSeconds?: number;
    };
  } catch {
    return null;
  }
}

/**
 * POSTs the Steward JWT (+ optional refresh token) to the session endpoint
 * so the server can set HttpOnly cookies. Throws `StewardSessionError` on
 * non-2xx; caller decides whether to wipe localStorage based on `error.code`.
 */
export async function syncStewardSession(
  token: string,
  refreshToken?: string | null,
  opts: SyncOpts = {},
): Promise<StewardSessionResponse> {
  const endpoint = opts.endpoint ?? STEWARD_SESSION_ENDPOINT;
  const f = opts.fetchImpl ?? fetch;
  // Refresh tokens now live exclusively in the HttpOnly
  // host-bound `__Host-steward-refresh-token-v2` cookie. We forward whatever
  // the caller passes
  // (e.g. the value still arriving in a legacy URL fragment during the
  // rollout window) so the server can set the cookie on first login, but we
  // do NOT read it back from localStorage — that path is being removed.
  const body: StewardSessionRequest = {
    token,
    ...(refreshToken ? { refreshToken } : {}),
  };
  const response = await f(endpoint, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      [STEWARD_CSRF_HEADER]:
        opts.sessionMutationProtocol ?? STEWARD_CSRF_HEADER_VALUE,
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const errBody = await readErrorBody(response);
    throw new StewardSessionError(
      errBody?.error || "Could not establish an Eliza Cloud session.",
      response.status,
      errBody?.code ?? null,
      {
        retryAfterSeconds: errBody?.retryAfterSeconds,
        retryAtEpochSeconds: errBody?.retryAtEpochSeconds,
      },
    );
  }
  return (await response.json()) as StewardSessionResponse;
}

// ---------------------------------------------------------------------------
// Nonce-exchange (response_type=code) flow
// ---------------------------------------------------------------------------

export interface StewardNonceExchangeRequest {
  /** One-time code from the Steward redirect (`?code=`). */
  code: string;
  /**
   * The `redirect_uri` that was sent to Steward `/authorize`. Steward verifies
   * this matches what was issued. If omitted, the cloud-api route falls back
   * to the value provided server-side via env / convention; in practice the
   * caller should send the same redirect_uri it used originally.
   */
  redirectUri?: string;
  /** Steward tenant ID (e.g. "elizacloud"). */
  tenantId?: string;
  /** PKCE verifier paired with the `code_challenge` sent to Steward. */
  codeVerifier?: string;
}

export interface StewardNonceExchangeResponse extends StewardSessionResponse {
  expiresIn?: number;
  expiresAt?: number;
  /**
   * Steward JWT. Mirrored from the upstream Steward exchange so the SPA can
   * write it to localStorage (required by `@stwd/react`'s `useAuth()` to
   * report `isAuthenticated=true`). HttpOnly cookies are still the canonical
   * session — this is the JS-readable copy that keeps the wallet and OAuth
   * paths symmetric. The long-lived refresh token is deliberately NOT
   * mirrored; it stays in the HttpOnly cookie.
   */
  token?: string;
}

export interface ExchangeStewardCodeOpts extends SyncOpts {
  /** redirect_uri that was sent to /authorize (must match exactly). */
  redirectUri?: string;
  /** Steward tenant id. */
  tenantId?: string;
  /** PKCE verifier paired with the `code_challenge` sent to Steward. */
  codeVerifier?: string;
}

/**
 * POSTs the one-time OAuth code to the cloud-api nonce-exchange endpoint.
 * The route calls Steward `POST /auth/oauth/exchange` server-side, sets the
 * HttpOnly steward-token + steward-refresh-token cookies, and returns the
 * Eliza Cloud user id. Some cross-origin checkout callers may also receive a
 * browser bearer token. Throws `StewardSessionError` on non-2xx.
 */
export async function exchangeStewardCode(
  code: string,
  opts: ExchangeStewardCodeOpts = {},
): Promise<StewardNonceExchangeResponse> {
  const endpoint = opts.endpoint ?? STEWARD_NONCE_EXCHANGE_ENDPOINT;
  const f = opts.fetchImpl ?? fetch;
  const body: StewardNonceExchangeRequest = {
    code,
    ...(opts.redirectUri ? { redirectUri: opts.redirectUri } : {}),
    ...(opts.tenantId ? { tenantId: opts.tenantId } : {}),
    ...(opts.codeVerifier ? { codeVerifier: opts.codeVerifier } : {}),
  };
  const response = await f(endpoint, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      [STEWARD_CSRF_HEADER]:
        opts.sessionMutationProtocol ?? STEWARD_CSRF_HEADER_VALUE,
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const errBody = await readErrorBody(response);
    throw new StewardSessionError(
      errBody?.error || "Could not complete Eliza Cloud sign-in.",
      response.status,
      errBody?.code ?? null,
      {
        retryAfterSeconds: errBody?.retryAfterSeconds,
        retryAtEpochSeconds: errBody?.retryAtEpochSeconds,
      },
    );
  }
  return (await response.json()) as StewardNonceExchangeResponse;
}

/**
 * Best-effort DELETE of every configured session endpoint. Failures are
 * swallowed — the caller has already wiped localStorage and there's nothing
 * useful to do about a cookie that won't clear.
 */
export {
  buildStewardOAuthAuthorizeUrl,
  consumeStewardPkceVerifier,
  createStewardPkceChallenge,
  createStewardPkcePair,
  generateStewardOAuthState,
  generateStewardPkceVerifier,
  peekStewardOAuthState,
  type StewardOAuthProvider,
  type StewardPkcePair,
  storeStewardPkceVerifier,
} from "./steward-oauth-pkce.js";

export function clearStewardSession(opts: ClearOpts = {}): void {
  const endpoints = opts.endpoints ?? [STEWARD_SESSION_ENDPOINT];
  const f = opts.fetchImpl ?? (typeof fetch !== "undefined" ? fetch : null);
  if (!f) return;
  for (const url of endpoints) {
    f(url, {
      method: "DELETE",
      credentials: "include",
      headers: {
        [STEWARD_CSRF_HEADER]:
          opts.sessionMutationProtocol ?? STEWARD_CSRF_HEADER_VALUE,
      },
    }).catch(() => {
      // ignore — see jsdoc
    });
  }
}
