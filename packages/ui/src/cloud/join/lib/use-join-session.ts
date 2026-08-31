/**
 * Minimal Steward session-auth read for the join page.
 *
 * Reads the cloud shell's {@link LocalStewardAuthContext} (provided by
 * `StewardAuthProvider` for authenticated cloud routes) with a localStorage
 * fallback so the page resolves auth even before the heavy `@stwd/*` runtime
 * mounts. Mirrors the per-domain `useSessionAuth` pattern (account-security /
 * instances / public-pages) without cross-domain coupling — the join domain owns
 * only what it needs: `{ ready, authenticated }`.
 */

import {
  readStoredStewardToken,
  STEWARD_SESSION_CHANGE_EVENT,
} from "@elizaos/shared/steward-session-client";
import { useContext, useEffect, useState } from "react";
import { decodeJwtPayload } from "../../lib/jwt";
import {
  readStewardSessionRecovery,
  STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
} from "../../lib/steward-session-recovery-marker";
import { LocalStewardAuthContext } from "../../shell/StewardProvider";
import {
  configuredStewardTenantId,
  DEFAULT_STEWARD_TENANT_ID,
} from "../../shell/steward-config";

function isPlaywrightTestAuthEnabled(): boolean {
  if (import.meta.env?.VITE_PLAYWRIGHT_TEST_AUTH === "true") return true;
  if (
    typeof process !== "undefined" &&
    process.env?.NEXT_PUBLIC_PLAYWRIGHT_TEST_AUTH === "true"
  ) {
    return true;
  }
  return false;
}

function tokenIsLive(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload) return false;
  if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) {
    return false;
  }
  return true;
}

function readStoredAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    if (!readStewardRecoveryClean()) return null;
    const token = readStoredStewardToken()?.trim();
    if (!token || !tokenIsLive(token)) return null;
    return readStewardRecoveryClean() ? token : null;
  } catch {
    // error-policy:J3 storage unavailable reads as unauthenticated
    // (fail-closed) — the join flow prompts for login.
    return null;
  }
}

function readStewardRecoveryClean(): boolean {
  const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
  const recovery = readStewardSessionRecovery(tenantId);
  return recovery.storageAvailable && recovery.receipts.length === 0;
}

export interface JoinSessionAuthState {
  /** True once the auth state is settled (provider not loading). */
  ready: boolean;
  /** True when a live Steward session exists. */
  authenticated: boolean;
  /** Exact live Steward bearer that owns any join work started by this render. */
  authToken: string | null;
}

export function useJoinSessionAuth(): JoinSessionAuthState {
  const providerAuth = useContext(LocalStewardAuthContext);
  const [authToken, setAuthToken] = useState(readStoredAuthToken);
  const [stewardRecoveryClean, setStewardRecoveryClean] = useState(
    readStewardRecoveryClean,
  );

  useEffect(() => {
    const handler = () => {
      setStewardRecoveryClean(readStewardRecoveryClean());
      setAuthToken(readStoredAuthToken());
    };
    handler();
    window.addEventListener("storage", handler);
    window.addEventListener("steward-token-sync", handler);
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, handler);
    window.addEventListener(STEWARD_SESSION_RECOVERY_CHANGE_EVENT, handler);
    const timer = setTimeout(handler, 250);
    return () => {
      window.removeEventListener("storage", handler);
      window.removeEventListener("steward-token-sync", handler);
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, handler);
      window.removeEventListener(
        STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
        handler,
      );
      clearTimeout(timer);
    };
  }, []);

  const usableAuthToken = stewardRecoveryClean ? authToken : null;
  const authenticated =
    (stewardRecoveryClean && (providerAuth?.isAuthenticated ?? false)) ||
    usableAuthToken !== null;
  const ready =
    !(providerAuth?.isLoading ?? false) || isPlaywrightTestAuthEnabled();

  return { ready, authenticated, authToken: usableAuthToken };
}
