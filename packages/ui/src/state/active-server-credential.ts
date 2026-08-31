/**
 * Persists a newly issued bearer credential across the active server and its
 * matching profile so every reconnect path observes the same authenticated
 * target. Pairing and bootstrap exchange both route through this boundary.
 */

import { setStorageValueIfCurrent } from "../bridge/storage-bridge";
import {
  type AgentProfileConnectionPersistenceOptions,
  getActiveProfile,
  loadAgentProfileRegistry,
  persistAgentProfileConnectionDurably,
  updateAgentProfile,
} from "./agent-profiles";
import {
  createPersistedActiveServer,
  loadPersistedActiveServer,
  savePersistedActiveServer,
  savePersistedActiveServerDurably,
} from "./persistence";

const ACTIVE_SERVER_STORAGE_KEY = "elizaos:active-server";
const AGENT_PROFILE_STORAGE_KEY = "elizaos:agent-profiles";

export async function persistActiveServerCredential(
  token: string,
  pairedApiBase?: string,
  options: AgentProfileConnectionPersistenceOptions = {},
): Promise<void> {
  if (options.validate?.() === false) {
    throw new DOMException(
      "Runtime credential publication was superseded.",
      "AbortError",
    );
  }
  const activeServer = loadPersistedActiveServer();
  const explicitPairingBase = pairedApiBase?.trim() || null;
  const sameOriginPairingBase =
    (!activeServer || activeServer.kind === "local") &&
    typeof window !== "undefined" &&
    (window.location.protocol === "http:" ||
      window.location.protocol === "https:")
      ? window.location.origin
      : null;
  const pairingBase = explicitPairingBase ?? sameOriginPairingBase;
  const fallbackRemote = pairingBase
    ? createPersistedActiveServer({
        kind: "remote",
        apiBase: pairingBase,
        accessToken: token,
      })
    : null;
  // An explicit pairing base is the credential authority. A stale active
  // Cloud/profile selection must never redirect that newly minted remote
  // bearer into its own record.
  const credentialTarget =
    fallbackRemote ??
    (activeServer && activeServer.kind !== "local"
      ? { ...activeServer, accessToken: token }
      : null);
  const activeProfile = getActiveProfile();
  const sameCredentialTarget =
    activeProfile &&
    credentialTarget &&
    activeProfile.kind === credentialTarget.kind &&
    activeProfile.apiBase?.replace(/\/+$/, "") ===
      credentialTarget.apiBase?.replace(/\/+$/, "");
  if (!credentialTarget) return;

  const profile = sameCredentialTarget
    ? (() => {
        const { id: _id, createdAt: _createdAt, ...rest } = activeProfile;
        return { ...rest, accessToken: token };
      })()
    : credentialTarget.kind === "remote"
      ? {
          kind: "remote" as const,
          label: credentialTarget.label,
          apiBase: credentialTarget.apiBase,
          accessToken: token,
        }
      : null;

  // A recovery transaction may not fall back to the single-record writer:
  // that path cannot retain a registry+server compensator across the sibling
  // pair-token commit. Ordinary pairing callers (no captured compensation)
  // keep the historical single-record fallback.
  if (!profile && options.captureCompensation) {
    throw new Error(
      "The active runtime profile required for transactional credential recovery is unavailable.",
    );
  }

  const persisted = profile
    ? await persistAgentProfileConnectionDurably(
        profile,
        credentialTarget,
        options,
      )
    : await savePersistedActiveServerDurably(credentialTarget, options);
  if (!persisted) {
    throw new Error("The authenticated runtime target could not be saved.");
  }
  if (options.validate?.() === false) {
    throw new DOMException(
      "Runtime credential publication was superseded.",
      "AbortError",
    );
  }
}

/**
 * Removes only the rejected bearer from the active target and profile. Other
 * saved targets keep their credentials so one expired agent cannot sign the
 * user out of every configured runtime.
 */
export function scrubRejectedActiveServerCredential(token: string): void {
  const rejected = token.trim();
  if (!rejected) return;

  const activeServer = loadPersistedActiveServer();
  if (activeServer?.accessToken === rejected) {
    const { accessToken: _rejected, ...serverWithoutToken } = activeServer;
    savePersistedActiveServer(serverWithoutToken);
  }

  const activeProfile = getActiveProfile();
  if (activeProfile?.accessToken === rejected) {
    updateAgentProfile(activeProfile.id, { accessToken: undefined });
  }
}

/**
 * Remove a definitively rejected bearer from the exact active-server/profile
 * records observed by this probe. These are terminal CAS transforms: once A is
 * scrubbed it is never restored, while a concurrent account/runtime B makes
 * the compare fail and remains untouched.
 */
export async function scrubRejectedActiveServerCredentialDurably(
  token: string,
): Promise<boolean> {
  const rejected = token.trim();
  if (!rejected || typeof localStorage === "undefined") return false;

  const registry = loadAgentProfileRegistry();
  const registryRaw = localStorage.getItem(AGENT_PROFILE_STORAGE_KEY);
  const activeServer = loadPersistedActiveServer();
  const activeServerRaw = localStorage.getItem(ACTIVE_SERVER_STORAGE_KEY);
  const activeProfileIndex = registry.profiles.findIndex(
    (profile) =>
      profile.id === registry.activeProfileId &&
      profile.accessToken === rejected,
  );
  const scrubServer = activeServer?.accessToken === rejected;
  const scrubProfile = activeProfileIndex >= 0;
  if (!scrubServer && !scrubProfile) return true;

  const nextRegistry = scrubProfile
    ? {
        ...registry,
        profiles: registry.profiles.map((profile, index) => {
          if (index !== activeProfileIndex) return profile;
          const { accessToken: _accessToken, ...rest } = profile;
          return rest;
        }),
      }
    : registry;
  const scrubs: Promise<boolean>[] = [];
  if (scrubProfile && registryRaw) {
    scrubs.push(
      setStorageValueIfCurrent(
        AGENT_PROFILE_STORAGE_KEY,
        registryRaw,
        JSON.stringify(nextRegistry),
        { compensateOnValidationFailure: false },
      ),
    );
  }
  if (scrubServer && activeServer && activeServerRaw) {
    const { accessToken: _accessToken, ...serverWithoutToken } = activeServer;
    scrubs.push(
      setStorageValueIfCurrent(
        ACTIVE_SERVER_STORAGE_KEY,
        activeServerRaw,
        JSON.stringify(serverWithoutToken),
        { compensateOnValidationFailure: false },
      ),
    );
  }
  await Promise.allSettled(scrubs);

  // A false CAS can mean either a safe newer B won or protected persistence
  // failed without mutation. Re-read both records and retry auth only when the
  // rejected A bearer is provably absent from every active credential mirror.
  const currentServer = loadPersistedActiveServer();
  const currentRegistry = loadAgentProfileRegistry();
  const currentProfile = currentRegistry.profiles.find(
    (profile) => profile.id === currentRegistry.activeProfileId,
  );
  return (
    currentServer?.accessToken !== rejected &&
    currentProfile?.accessToken !== rejected
  );
}
