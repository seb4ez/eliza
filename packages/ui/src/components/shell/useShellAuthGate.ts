/**
 * React binding for {@link deriveShellAuthGate}: branding `cloudOnly`, the
 * canonical Steward session, and the shared auth snapshot, with no extra
 * network traffic.
 *
 * Subscribe-only (`observeOnly`) so the pill can read the app-level
 * `/api/auth/me` probe. The first-run conductor still owns the first sign-in
 * card; this hook is the resting / recovery gate after that card is closed.
 */

import { STEWARD_SESSION_CHANGE_EVENT } from "@elizaos/shared/steward-session-client";
import { useSyncExternalStore } from "react";
import { STEWARD_SESSION_RECOVERY_CHANGE_EVENT } from "../../cloud/lib/steward-session-recovery-marker";
import { useBranding } from "../../config/branding";
import { useAuthStatus } from "../../hooks/useAuthStatus";
import { hasUsableStoredStewardToken } from "../../state/cloud-steward-login";
import { deriveShellAuthGate, type ShellAuthGate } from "./shell-auth-gate";

function subscribeToStoredCloudSession(onStoreChange: () => void): () => void {
  if (typeof window === "undefined") return () => undefined;

  const onSessionChange = () => onStoreChange();
  const onStorage = (_event: StorageEvent) => {
    // Recovery marker prefixes are deliberately private to their authority
    // module. Re-read on any cross-tab storage mutation so planting login B
    // immediately quarantines a still-readable token A in this shell.
    onStoreChange();
  };
  window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onSessionChange);
  window.addEventListener(
    STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
    onSessionChange,
  );
  window.addEventListener("storage", onStorage);
  return () => {
    window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onSessionChange);
    window.removeEventListener(
      STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
      onSessionChange,
    );
    window.removeEventListener("storage", onStorage);
  };
}

function noStoredCloudSession(): boolean {
  return false;
}

export function useShellAuthGate(): ShellAuthGate {
  const { cloudOnly } = useBranding();
  const { state } = useAuthStatus({ observeOnly: true });
  const hasUsableCloudSession = useSyncExternalStore(
    subscribeToStoredCloudSession,
    hasUsableStoredStewardToken,
    noStoredCloudSession,
  );
  return deriveShellAuthGate({
    cloudOnly: cloudOnly === true,
    authPhase: state.phase,
    hasUsableCloudSession,
  });
}

export type { ShellAuthGate, ShellAuthGatePhase } from "./shell-auth-gate";
