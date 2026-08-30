/**
 * Non-destructive runtime switch: repoints the app at a different agent
 * profile (local / cloud / remote) by updating the active-profile and
 * active-server records and clearing chat drafts, without wiping persisted
 * state. Consumed by the runtime picker and connect deep-links.
 */
import { logger } from "@elizaos/logger";
import { client } from "../api";
import {
  isMobileLocalAgentIpcBase,
  persistMobileRuntimeModeForServerTarget,
} from "../first-run/mobile-runtime-mode";
import { activeServerKindToFirstRunRuntimeTarget } from "../first-run/runtime-target";
import { getFrontendPlatform } from "../platform/platform-guards";
import type { AgentProfile } from "./agent-profile-types";
import {
  activeServerIdForAgentProfile,
  persistAgentProfileSelectionDurably,
  removeAgentProfileWithFallbackDurably,
} from "./agent-profiles";
import { clearAllChatDrafts } from "./ChatComposerContext.hooks";
import {
  createPersistedActiveServer,
  type PersistedActiveServer,
} from "./persistence";
import {
  isTrustedCloudApiBaseUrl,
  isTrustedRestoreApiBaseUrl,
} from "./runtime-url-trust";

export type SwitchRuntimeResult =
  | { ok: true; profile: AgentProfile }
  | {
      ok: false;
      reason:
        | "not-found"
        | "persistence-failed"
        | "untrusted-cloud"
        | "untrusted-remote";
    };

export type RemoveRuntimeProfileResult =
  | { ok: true; activeProfile: AgentProfile | null }
  | {
      ok: false;
      reason:
        | "not-found"
        | "persistence-failed"
        | "untrusted-cloud"
        | "untrusted-remote"
        | "build-pinned";
    };

export type RuntimeAuthoritySwitchPhase = "before" | "after";
type RuntimeAuthoritySwitchListener = (
  phase: RuntimeAuthoritySwitchPhase,
) => void;
const runtimeAuthoritySwitchListeners =
  new Set<RuntimeAuthoritySwitchListener>();

/**
 * Subscribe to explicit non-destructive runtime authority changes. Unlike the
 * client's raw base-url signal, this excludes temporary probes and the
 * shared-to-dedicated handoff that must preserve the live transcript.
 */
export function subscribeRuntimeAuthoritySwitch(
  listener: RuntimeAuthoritySwitchListener,
): () => void {
  runtimeAuthoritySwitchListeners.add(listener);
  return () => runtimeAuthoritySwitchListeners.delete(listener);
}

function notifyRuntimeAuthoritySwitch(
  phase: RuntimeAuthoritySwitchPhase,
): void {
  for (const listener of runtimeAuthoritySwitchListeners) {
    try {
      listener(phase);
    } catch (error) {
      logger.error(
        { error },
        "[switch-runtime] authority-switch listener failed",
      );
    }
  }
}

function hasValidNativeRemoteBinding(profile: AgentProfile): boolean {
  if (profile.connectionMode === "relay") {
    return Boolean(
      profile.remoteRelay &&
        profile.apiBase ===
          `eliza-remote://session/${profile.remoteRelay.sessionId}`,
    );
  }
  if (profile.connectionMode === "ssh") {
    return Boolean(
      profile.ssh &&
        profile.credentialRef === profile.id &&
        profile.apiBase === `eliza-ssh://runtime/${profile.id}`,
    );
  }
  return false;
}

type RuntimeProfileTrustFailure = "untrusted-cloud" | "untrusted-remote" | null;

function runtimeProfileTrustFailure(
  profile: AgentProfile,
): RuntimeProfileTrustFailure {
  if (
    profile.kind === "remote" &&
    !(
      hasValidNativeRemoteBinding(profile) ||
      (profile.connectionMode !== "relay" &&
        profile.connectionMode !== "ssh" &&
        isTrustedRestoreApiBaseUrl(profile.apiBase))
    )
  ) {
    return "untrusted-remote";
  }
  if (
    profile.kind === "cloud" &&
    !isTrustedCloudApiBaseUrl(
      profile.apiBase,
      profile.cloudRuntimeAgentId ?? profile.cloudAgentId,
    )
  ) {
    return "untrusted-cloud";
  }
  return null;
}

function persistedServerForRuntimeProfile(
  profile: AgentProfile,
): PersistedActiveServer {
  return createPersistedActiveServer({
    kind: profile.kind,
    id: activeServerIdForAgentProfile(profile),
    apiBase: profile.apiBase,
    accessToken: profile.accessToken,
    label: profile.label,
    cloudRuntimeAgentId: profile.cloudRuntimeAgentId,
    cloudRuntime: profile.cloudRuntime,
  });
}

async function publishRuntimeProfile(
  profile: AgentProfile | null,
): Promise<boolean> {
  notifyRuntimeAuthoritySwitch("before");
  try {
    let published = true;
    if (profile?.apiBase) {
      published = client.repointBaseUrl(
        profile.apiBase,
        profile.accessToken ?? null,
      );
    } else if (profile && typeof window !== "undefined") {
      client.setToken(null);
      published = client.repointBaseUrl(window.location.origin);
    } else {
      client.setToken(null);
      client.setBaseUrl(null);
    }
    if (!published) return false;

    clearAllChatDrafts();

    if (profile) {
      const platform = getFrontendPlatform();
      if (platform === "android" || platform === "ios") {
        const target =
          profile.kind === "local" || isMobileLocalAgentIpcBase(profile.apiBase)
            ? "local"
            : activeServerKindToFirstRunRuntimeTarget(profile.kind);
        persistMobileRuntimeModeForServerTarget(target);
      }
    }

    return true;
  } finally {
    // Always close the authority phase, including a rejected client publish;
    // subscribers can then rehydrate the still-current compensated selection.
    notifyRuntimeAuthoritySwitch("after");
  }
}

/**
 * Switch the active runtime IN PLACE — the "My Runtimes" non-destructive switch.
 *
 * Generalizes {@link silentlyRepointToDedicated} to any saved runtime profile
 * (local / cloud-dedicated / VPS-remote): persist it as the restorable active
 * server (so a reboot restores this runtime), mark it active in the
 * agent-profile registry, and re-point the live client with `repointBaseUrl`
 * (NOT `setBaseUrl` → no `SWITCH_AGENT` dispatch, no draft-clear, no
 * StartupScreen flash). The chat surface stays mounted throughout.
 *
 * Remote runtimes are **trust-gated**: a public URL is rejected; loopback,
 * RFC1918, CGNAT (`100.64/10`), tailscale (`*.ts.net` / `100.x`), and
 * same-origin are allowed — matching the startup restore guard
 * (`isTrustedRestoreApiBaseUrl`). This is why the cockpit "phone drives a remote
 * runtime" path expects the laptop/VPS over tailscale, not a bare public URL.
 */
export async function switchRuntimeNonDestructive(
  profileId: string,
): Promise<SwitchRuntimeResult> {
  let invalidProfileReason: RuntimeProfileTrustFailure = null;
  const persisted = await persistAgentProfileSelectionDurably(profileId, {
    createServer: (profile) => {
      invalidProfileReason = runtimeProfileTrustFailure(profile);
      return invalidProfileReason
        ? null
        : persistedServerForRuntimeProfile(profile);
    },
    // Keep durable selection and live publication inside the same serialized
    // transaction. This also orders fire-and-forget WebSocket switches.
    finalize: (profile) => publishRuntimeProfile(profile),
  });
  if (!persisted.ok) {
    if (persisted.reason === "not-found") {
      return { ok: false, reason: "not-found" };
    }
    return {
      ok: false,
      reason: invalidProfileReason ?? "persistence-failed",
    };
  }

  return { ok: true, profile: persisted.profile };
}

/** Remove a profile without exposing a split switch/delete authority window. */
export async function removeRuntimeProfileNonDestructive(
  profileId: string,
): Promise<RemoveRuntimeProfileResult> {
  let invalidFallbackReason: RuntimeProfileTrustFailure = null;
  const removed = await removeAgentProfileWithFallbackDurably(profileId, {
    createServer: (profile) => {
      invalidFallbackReason = runtimeProfileTrustFailure(profile);
      return invalidFallbackReason
        ? null
        : persistedServerForRuntimeProfile(profile);
    },
    finalize: (profile) => publishRuntimeProfile(profile),
  });
  if (removed.ok) return removed;
  if (removed.reason === "invalid-fallback") {
    return {
      ok: false,
      reason: invalidFallbackReason ?? "persistence-failed",
    };
  }
  return { ok: false, reason: removed.reason };
}
