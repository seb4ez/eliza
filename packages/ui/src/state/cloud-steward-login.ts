/**
 * Cloud = Steward login seam (DECISIONS.md D3).
 *
 * The Cloud connection authenticates via Steward on every target — hosted web
 * (same-origin cookie + localStorage JWT) and native (Bearer-from-localStorage).
 * The actual Steward sign-in UI (passkey / email / OAuth / wallet via
 * `@stwd/react`) lives in the shell-router layer, which lazily mounts the
 * Steward provider only when the user chooses Cloud. This module is the thin,
 * dependency-free contract between the two:
 *
 *   - The shell-router registers a launcher with {@link registerStewardLoginLauncher}.
 *   - The cloud-state login flow (the interactive Cloud branch) calls
 *     {@link launchStewardLogin}, which resolves once a Steward session token is
 *     present (or rejects on cancel / failure).
 *
 * Keeping this a plain module (no React, no `@stwd/*`) means `useCloudState`
 * never pulls the Steward SDK into the non-cloud bundle — the SDK ships only in
 * the shell-router's lazy cloud path.
 */

import {
  clearStoredStewardToken,
  readStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { decodeJwtPayload } from "../cloud/lib/jwt";
import { readStewardSessionRecovery } from "../cloud/lib/steward-session-recovery-marker";
import {
  configuredStewardTenantId,
  DEFAULT_STEWARD_TENANT_ID,
} from "../cloud/shell/steward-config";

export interface StewardLoginAuthority {
  isCurrent(): boolean;
}

export interface StoredStewardLoginAuthority extends StewardLoginAuthority {
  /** Exact bearer owned by the clean recovery generation. */
  token: string;
  /** Monotonic origin-wide recovery generation captured with the bearer. */
  recoveryGeneration: string | null;
}

export interface StewardLoginResult {
  /** The Steward session JWT now present in localStorage. */
  token: string;
  /** Exact token + recovery generation carried across caller awaits. */
  authority?: StewardLoginAuthority;
}

/**
 * Minimum lifetime (seconds) a stored Steward JWT must still have for the
 * short-circuit to trust it. A token at or under this margin is treated as
 * already dead: rather than hand the caller an expired session (which would
 * 401 the agent picker / subsequent calls in a loop) we clear it and force a
 * real re-auth.
 */
const STEWARD_TOKEN_MIN_VALID_SECS = 10;

/**
 * Whether a stored Steward token can be trusted to short-circuit sign-in.
 * Opaque (non-JWT) device-code / Remote session tokens have no decodable `exp`
 * (decoded expiry → null) and are left to the legacy flow, matching
 * the cloud token-lifecycle refresh which also no-ops on a null result. A JWT
 * is usable only while it has more than a small safety margin of life left.
 */
export function isStoredStewardTokenUsable(token: string): boolean {
  const exp = decodeJwtPayload(token)?.exp;
  const secs = typeof exp === "number" ? exp - Date.now() / 1000 : null;
  if (secs === null) return true; // opaque/device-code token — not our concern
  return secs > STEWARD_TOKEN_MIN_VALID_SECS;
}

/**
 * A launcher opens the Steward sign-in surface and resolves once the user has
 * authenticated (a Steward token is in localStorage). It rejects if the user
 * cancels or sign-in fails. Implemented by the shell-router.
 */
export type StewardLoginLauncher = () => Promise<StewardLoginResult>;

let registeredLauncher: StewardLoginLauncher | null = null;

/**
 * Register the Steward sign-in launcher. Called once by the shell-router when
 * it mounts the lazy Cloud provider tree. Returns an unregister function.
 */
export function registerStewardLoginLauncher(
  launcher: StewardLoginLauncher,
): () => void {
  registeredLauncher = launcher;
  return () => {
    if (registeredLauncher === launcher) {
      registeredLauncher = null;
    }
  };
}

/** Whether a shell-router Steward launcher is currently registered. */
export function hasStewardLoginLauncher(): boolean {
  return registeredLauncher !== null;
}

/**
 * Whether a stored Steward token exists AND owns a clean recovery generation
 * which can short-circuit sign-in (see {@link launchStewardLogin}). A usable
 * account-A JWT is still quarantined while a durable account-B receipt exists,
 * or while recovery storage cannot prove that no such receipt exists.
 */
export function hasUsableStoredStewardToken(): boolean {
  const authority = captureStoredStewardLoginAuthority();
  return Boolean(authority && isStoredStewardTokenUsable(authority.token));
}

/**
 * Capture the exact stored bearer only when recovery storage proves that it
 * belongs to a receipt-free generation. The returned fence also detects a
 * login which begins and retires entirely while a caller is suspended.
 */
export function captureStoredStewardLoginAuthority(): StoredStewardLoginAuthority | null {
  const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
  const snapshot = readStewardSessionRecovery(tenantId);
  if (!snapshot.storageAvailable || snapshot.receipts.length > 0) return null;
  let token: string;
  try {
    token = readStoredStewardToken()?.trim() ?? "";
  } catch {
    return null;
  }
  if (!token) return null;
  const authority: StoredStewardLoginAuthority = {
    token,
    recoveryGeneration: snapshot.generation,
    isCurrent: () => {
      const current = readStewardSessionRecovery(tenantId);
      let currentToken: string | null;
      try {
        currentToken = readStoredStewardToken()?.trim() || null;
      } catch {
        return false;
      }
      return (
        current.storageAvailable &&
        current.generation === snapshot.generation &&
        current.receipts.length === 0 &&
        currentToken === token
      );
    },
  };
  return authority.isCurrent() ? authority : null;
}

/**
 * Drive the Cloud=Steward sign-in. If a *still-valid* session token is already
 * stored we resolve immediately; otherwise we invoke the registered launcher.
 * A stored-but-expired Steward JWT must NOT short-circuit — doing so produces a
 * false "connected" state whose subsequent authed calls 401 in a loop — so we
 * drain the stale value and fall through to a real re-auth. Throws when no
 * launcher is registered (the shell-router has not mounted the Cloud provider)
 * so the caller can fall back to a legacy path during migration.
 */
export async function launchStewardLogin(): Promise<
  StewardLoginResult & { authority: StewardLoginAuthority }
> {
  const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
  const recoveryAtAdmission = readStewardSessionRecovery(tenantId);
  const recoveryBlockedAtAdmission =
    !recoveryAtAdmission.storageAvailable ||
    recoveryAtAdmission.receipts.length > 0;
  const existing = readStoredStewardToken()?.trim();
  const existingIsUsable = Boolean(
    existing && isStoredStewardTokenUsable(existing),
  );
  if (existing && existingIsUsable && !recoveryBlockedAtAdmission) {
    const reused = withStewardLoginAuthority({ token: existing });
    if (reused.authority.isCurrent()) return reused;
  }
  // A usable local token can belong to account A while a durable receipt proves
  // that login B is still unresolved. Keep A quarantined for rollback/recovery,
  // but never return it as the result of this login call. Only genuinely stale
  // credentials are safe to drain before the mounted surface performs re-auth.
  if (existing && !existingIsUsable) {
    await clearStoredStewardToken({ expectedToken: existing });
  }

  if (!registeredLauncher) {
    if (recoveryBlockedAtAdmission) {
      throw new Error(
        "Eliza Cloud sign-in is blocked while another sign-in is still being finalized. Open the sign-in screen to recover or restart it.",
      );
    }
    throw new Error(
      "Eliza Cloud sign-in is unavailable: the Steward login surface is not mounted.",
    );
  }
  const launched = withStewardLoginAuthority(await registeredLauncher());
  if (recoveryBlockedAtAdmission && !launched.authority.isCurrent()) {
    throw new Error(
      "Eliza Cloud sign-in was superseded by another session change. Please sign in again.",
    );
  }
  return launched;
}

function withStewardLoginAuthority(
  result: StewardLoginResult,
): StewardLoginResult & { authority: StewardLoginAuthority } {
  let authority = result.authority;
  const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
  const snapshot = readStewardSessionRecovery(tenantId);
  authority ??= {
    isCurrent: () => {
      const current = readStewardSessionRecovery(tenantId);
      return (
        snapshot.storageAvailable &&
        snapshot.receipts.length === 0 &&
        current.storageAvailable &&
        current.generation === snapshot.generation &&
        current.receipts.length === 0 &&
        readStoredStewardToken()?.trim() === result.token
      );
    },
  };
  // Keep the historical `{ token }` value shape for consumers which serialize
  // or compare it, while making the mandatory authority available to callers.
  return Object.defineProperty({ token: result.token }, "authority", {
    configurable: false,
    enumerable: false,
    value: authority,
    writable: false,
  }) as StewardLoginResult & { authority: StewardLoginAuthority };
}
