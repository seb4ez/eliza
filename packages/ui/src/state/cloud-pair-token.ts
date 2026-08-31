/**
 * Removes durable Cloud-pair credentials from both browser storage channels.
 *
 * The write path mirrors each owner-scoped key into sessionStorage and
 * localStorage, so sign-out, unpairing, and agent deletion must clear both.
 *
 * Targeted stale-credential purges require a proven agent owner and preserve
 * every unrelated profile, active-server credential, and loopback owner hint.
 */

import {
  CLOUD_PAIR_LOCAL_OWNER_HINT_KEY,
  cloudPairTokenKeyForAgent,
} from "@elizaos/shared/contracts";
import {
  getStorageValue,
  setStorageValueIfCurrent,
} from "../bridge/storage-bridge";
import {
  CLOUD_PAIR_LOCAL_STORAGE_KEY,
  CLOUD_PAIR_SESSION_STORAGE_KEY,
} from "../components/auth/CloudPairRelay";
import { shellLocalStorage } from "../surface-realm-channel";
import type { RuntimeConnectionPersistenceLease } from "./agent-profiles";
import {
  type AgentProfile,
  type AgentProfileRegistry,
  loadAgentProfileRegistry,
  saveAgentProfileRegistry,
  withRuntimeConnectionPersistenceLock,
} from "./agent-profiles";
import {
  dedicatedAgentIdFromApiBase,
  resolveDedicatedAgentId,
} from "./agent-session-recovery";
import {
  loadPersistedActiveServer,
  type PersistedActiveServer,
  scrubPersistedActiveServerToken,
} from "./persistence";

const ACTIVE_SERVER_STORAGE_KEY = "elizaos:active-server";
const AGENT_PROFILE_STORAGE_KEY = "elizaos:agent-profiles";

/**
 * Mirrors the write channel's `tryPersistBrowserStorage` shape: report whether
 * the removal took, swallowing only storage-access failures. A failed purge is
 * logged so a dodgy storage channel cannot silently look like success
 * (error-policy:J6 best-effort removal).
 */
function tryRemoveFromStorage(remove: () => void, key?: string): boolean {
  try {
    remove();
    return true;
  } catch (_storageError) {
    // error-policy:J6 hardened settings can disable storage; a store we
    // cannot touch also cannot be re-adopted from, so the purge goal still
    // holds. Still log the failure so "disconnect succeeded" is not a lie.
    console.error(
      `Failed to remove cloud-pair token key${key ? ` (${key})` : ""} from storage.`,
    );
    return false;
  }
}

/** Remove one key from both storage backends, each deletion isolated so a
 * failing store cannot abort clearing the rest. */
function removePairKeyFromBothStorages(key: string): void {
  tryRemoveFromStorage(() => {
    shellLocalStorage.removeItem(key);
  }, key);
  tryRemoveFromStorage(() => {
    if (typeof window !== "undefined") {
      window.sessionStorage.removeItem(key);
    }
  }, key);
}

/** Remove a loopback owner hint only when it names the credential being purged. */
function clearLocalOwnerHintForAgent(agentId: string): void {
  try {
    if (
      window.localStorage.getItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY) === agentId
    ) {
      shellLocalStorage.removeItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY);
    }
  } catch (storageError) {
    // error-policy:J6 a storage backend that cannot be read cannot safely have
    // its possibly unrelated owner hint removed.
    console.warn(
      "Could not inspect localStorage for the cloud-pair owner-hint purge.",
      storageError,
    );
  }
  try {
    if (
      window.sessionStorage.getItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY) === agentId
    ) {
      window.sessionStorage.removeItem(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY);
    }
  } catch (storageError) {
    // error-policy:J6 preserve an unreadable hint rather than deleting another
    // agent's in-flight loopback owner selection.
    console.warn(
      "Could not inspect sessionStorage for the cloud-pair owner-hint purge.",
      storageError,
    );
  }
}

/** Prefix for all per-agent cloud-pair token keys */
const CLOUD_PAIR_SCOPED_PREFIX = "eliza:cloud-pair:api-token:";

interface CloudPairStorageSnapshot {
  key: string;
  localValue: string | null;
  sessionValue: string | null;
}

export interface CloudPairApiTokenClearAuthority {
  entries: readonly CloudPairStorageSnapshot[];
  ownerHint: CloudPairStorageSnapshot;
}

function readStorageValue(storage: Storage, key: string): string | null {
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

/**
 * Snapshot only pair credentials proven to belong to account A's agent ids.
 * The legacy unscoped key is included only when its bytes equal an A bearer.
 */
export function captureCloudPairApiTokenClearAuthority(
  agentIds: readonly string[],
  ownedTokens: readonly string[],
): CloudPairApiTokenClearAuthority {
  const owners = [...new Set(agentIds.map((id) => id.trim()).filter(Boolean))];
  const entries = owners.map((owner) => {
    const key = cloudPairTokenKeyForAgent(owner);
    return {
      key,
      localValue: readStorageValue(window.localStorage, key),
      sessionValue: readStorageValue(window.sessionStorage, key),
    };
  });
  const legacyLocal = readStorageValue(
    window.localStorage,
    CLOUD_PAIR_LOCAL_STORAGE_KEY,
  );
  const legacySession = readStorageValue(
    window.sessionStorage,
    CLOUD_PAIR_SESSION_STORAGE_KEY,
  );
  const tokenSet = new Set(
    ownedTokens.map((token) => token.trim()).filter(Boolean),
  );
  if (
    (legacyLocal !== null && tokenSet.has(legacyLocal)) ||
    (legacySession !== null && tokenSet.has(legacySession))
  ) {
    entries.push({
      key: CLOUD_PAIR_LOCAL_STORAGE_KEY,
      localValue:
        legacyLocal !== null && tokenSet.has(legacyLocal) ? legacyLocal : null,
      sessionValue:
        legacySession !== null && tokenSet.has(legacySession)
          ? legacySession
          : null,
    });
  }
  return {
    entries,
    ownerHint: {
      key: CLOUD_PAIR_LOCAL_OWNER_HINT_KEY,
      localValue: owners.includes(
        readStorageValue(
          window.localStorage,
          CLOUD_PAIR_LOCAL_OWNER_HINT_KEY,
        ) ?? "",
      )
        ? readStorageValue(window.localStorage, CLOUD_PAIR_LOCAL_OWNER_HINT_KEY)
        : null,
      sessionValue: owners.includes(
        readStorageValue(
          window.sessionStorage,
          CLOUD_PAIR_LOCAL_OWNER_HINT_KEY,
        ) ?? "",
      )
        ? readStorageValue(
            window.sessionStorage,
            CLOUD_PAIR_LOCAL_OWNER_HINT_KEY,
          )
        : null,
    },
  };
}

function removeSnapshotValueIfCurrent(
  storage: Storage,
  key: string,
  expected: string | null,
  remove: () => void,
): void {
  if (expected === null) return;
  try {
    if (storage.getItem(key) === expected) remove();
  } catch {
    // error-policy:J6 an unreadable channel is preserved rather than guessing.
  }
}

/** Remove only exact A bytes; a replacement B value or newly-created key wins. */
export function clearCloudPairApiTokenIfCurrent(
  authority: CloudPairApiTokenClearAuthority,
  _lease: RuntimeConnectionPersistenceLease,
): void {
  for (const entry of [...authority.entries, authority.ownerHint]) {
    removeSnapshotValueIfCurrent(
      window.localStorage,
      entry.key,
      entry.localValue,
      () => shellLocalStorage.removeItem(entry.key),
    );
    removeSnapshotValueIfCurrent(
      window.sessionStorage,
      entry.key,
      entry.sessionValue,
      () => window.sessionStorage.removeItem(entry.key),
    );
  }
}

/**
 * Remove all scoped cloud-pair token keys from localStorage.
 * Used when an explicit disconnect happens but we can't resolve a specific agentId.
 */
function clearAllScopedCloudPairKeys(): void {
  // shellLocalStorage only has setItem/removeItem/clear; enumerate via raw
  // localStorage (keys known), then remove each through the isolated helper so
  // one failing remove cannot abort clearing the rest.
  let scoped: string[] = [];
  try {
    for (let i = 0; i < window.localStorage.length; i++) {
      const key = window.localStorage.key(i);
      if (key?.startsWith(CLOUD_PAIR_SCOPED_PREFIX)) scoped.push(key);
    }
  } catch (storageError) {
    // error-policy:J6 hardened settings can block storage enumeration; a store
    // we cannot read also cannot be re-adopted from, but warn so a vacated
    // purge never silently looks like a full one.
    console.warn(
      "Could not enumerate localStorage for the cloud-pair purge; scoped pair keys may remain.",
      storageError,
    );
    scoped = [];
  }
  for (const k of scoped) removePairKeyFromBothStorages(k);
  // Legacy single-key format
  removePairKeyFromBothStorages(CLOUD_PAIR_LOCAL_STORAGE_KEY);
}

/**
 * Remove all scoped cloud-pair token keys from sessionStorage.
 */
function clearAllScopedCloudPairKeysSession(): void {
  if (typeof window === "undefined") return;
  let keysToRemove: string[] = [];
  try {
    for (let i = 0; i < window.sessionStorage.length; i++) {
      const key = window.sessionStorage.key(i);
      if (key?.startsWith(CLOUD_PAIR_SCOPED_PREFIX)) keysToRemove.push(key);
    }
  } catch (storageError) {
    // error-policy:J6 hardened settings can block storage enumeration; warn so
    // a vacated purge never silently looks like a full one.
    console.warn(
      "Could not enumerate sessionStorage for the cloud-pair purge; scoped pair keys may remain.",
      storageError,
    );
    keysToRemove = [];
  }
  // sessionStorage is addressed raw (no shellSessionStorage wrapper); the
  // isolated deletion below mirrors the write channel.
  for (const key of keysToRemove) {
    tryRemoveFromStorage(() => {
      window.sessionStorage.removeItem(key);
    }, key);
  }
  tryRemoveFromStorage(() => {
    window.sessionStorage.removeItem(CLOUD_PAIR_SESSION_STORAGE_KEY);
  }, CLOUD_PAIR_SESSION_STORAGE_KEY);
}

/**
 * Remove the durable pair token from BOTH storages the write channel targets.
 * Storage-scoped on purpose — the live bearer/boot-config are left alone so
 * in-flight requests are not broken; the auth wall renders next and the next
 * boot finds nothing to re-adopt. sessionStorage is addressed raw (mirroring
 * the write channel, which uses raw window storage; there is no
 * shellSessionStorage wrapper).
 *
 * With an `agentId`, ONLY that agent's per-agent key is removed. The legacy
 * global key is deliberately left alone: on a pre-migration install it holds
 * a credential whose owner is unknown, so deleting agent A must not destroy
 * what may be agent B's only bearer. Without an `agentId` (global disconnect /
 * sign-out intent), every scoped key AND the legacy key are purged.
 */
export function clearCloudPairApiToken(agentId?: string): void {
  const scopedKey = agentId?.trim()
    ? cloudPairTokenKeyForAgent(agentId.trim())
    : null;

  if (scopedKey) {
    removePairKeyFromBothStorages(scopedKey);
    clearLocalOwnerHintForAgent(agentId?.trim() ?? "");
  } else {
    // No agentId resolved — explicit disconnect with global intent.
    // Clear ALL scoped keys + legacy key from both storages.
    clearAllScopedCloudPairKeys();
    clearAllScopedCloudPairKeysSession();
    removePairKeyFromBothStorages(CLOUD_PAIR_LOCAL_OWNER_HINT_KEY);
  }
}

/** A cloud profile belongs to `agentId` via its explicit id or its API base. */
function profileMatchesDedicatedAgent(
  profile: AgentProfile,
  agentId: string,
): boolean {
  if (profile.kind !== "cloud") return false;
  if (profile.cloudAgentId === agentId) return true;
  return dedicatedAgentIdFromApiBase(profile.apiBase) === agentId;
}

/**
 * Purge the persisted credentials for ONE dedicated cloud agent whose adopted
 * bearer a caller has independently observed rejected. The pairing mint is
 * authorized by the Steward JWT, not the pair token, so a mint 401/403 alone
 * proves nothing about the pair token — only a caller that watched the agent
 * origin refuse the adopted bearer (e.g. `/api/auth/me` 401 with
 * `remote_auth_required`) may invoke this, and only for that agent.
 *
 * Scoped on every axis:
 * - The durable pair key is per-agent (#17579), so `agentId`'s scoped key is
 *   ALWAYS cleared — it provably belongs to the target. Other agents' scoped
 *   keys and the legacy global key (unknown owner) survive.
 * - The persisted active-server token is scrubbed ONLY when the active server
 *   resolves to `agentId`; a different agent's still-valid bearer survives.
 * - Agent-profile tokens are scrubbed ONLY for profiles that belong to
 *   `agentId`; unrelated profiles (other agents, local/remote runtimes) keep
 *   their still-valid credentials.
 */
export function clearStalePairCredentialsForAgent(agentId: string): void {
  const target = agentId.trim();
  if (!target) return;

  const activeServer = loadPersistedActiveServer();
  // The durable key is per-agent, so purge THIS agent's scoped key regardless
  // of which agent is the active server — it provably belongs to the target.
  clearCloudPairApiToken(target);
  // The persisted active-server bearer is ONLY scrubbed when it actually
  // belongs to the deleted agent; an active server for a different agent
  // keeps its still-valid credential.
  if (activeServer && resolveDedicatedAgentId(activeServer) === target) {
    scrubPersistedActiveServerToken();
  }

  const registry = loadAgentProfileRegistry();
  let changed = false;
  registry.profiles = registry.profiles.map((profile) => {
    if (!profile.accessToken) return profile;
    if (!profileMatchesDedicatedAgent(profile, target)) return profile;
    changed = true;
    const { accessToken: _dropped, ...rest } = profile;
    return rest;
  });
  if (changed) saveAgentProfileRegistry(registry);
}

export interface StalePairCredentialDurableClearOptions {
  agentId: string;
  /** Exact dedicated-agent bearer rejected by the runtime auth probe. */
  rejectedToken: string;
  /** Account generation + same-agent authority retained by the recovery hook. */
  validate: () => boolean;
}

interface StrictPairStorageSnapshot {
  key: string;
  storage: Storage;
  channel: "local" | "session";
  value: string | null;
}

function readStrictPairStorageSnapshot(
  storage: Storage,
  key: string,
  channel: StrictPairStorageSnapshot["channel"],
): StrictPairStorageSnapshot | null {
  try {
    return { key, storage, channel, value: storage.getItem(key) };
  } catch {
    return null;
  }
}

/**
 * Terminally remove one exact rejected pair bearer. A later compensation never
 * restores it: once the runtime proved this bearer invalid, absence (or a B
 * replacement) is the only safe successor state.
 */
function removeRejectedPairSnapshotIfCurrent(
  snapshot: StrictPairStorageSnapshot,
  rejectedToken: string,
  validate: () => boolean,
): boolean {
  if (snapshot.value !== rejectedToken) return true;
  if (!validate()) return false;
  try {
    if (snapshot.storage.getItem(snapshot.key) !== snapshot.value) return true;
    if (!validate()) return false;
    if (snapshot.channel === "local") {
      shellLocalStorage.removeItem(snapshot.key);
    } else {
      snapshot.storage.removeItem(snapshot.key);
    }
    return true;
  } catch {
    return false;
  }
}

function parseActiveServerSnapshot(
  raw: string | null,
): PersistedActiveServer | null | undefined {
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as PersistedActiveServer;
    return parsed?.id && parsed.kind && parsed.label ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function parseAgentProfileRegistrySnapshot(
  raw: string | null,
): AgentProfileRegistry | null | undefined {
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as AgentProfileRegistry;
    return parsed?.version === 1 && Array.isArray(parsed.profiles)
      ? parsed
      : undefined;
  } catch {
    return undefined;
  }
}

function rejectedTokenAbsentFromActiveServer(
  raw: string | null,
  agentId: string,
  rejectedToken: string,
): boolean {
  const activeServer = parseActiveServerSnapshot(raw);
  if (activeServer === undefined) return false;
  return !(
    activeServer &&
    resolveDedicatedAgentId(activeServer) === agentId &&
    activeServer.accessToken?.trim() === rejectedToken
  );
}

function rejectedTokenAbsentFromProfiles(
  raw: string | null,
  agentId: string,
  rejectedToken: string,
): boolean {
  const registry = parseAgentProfileRegistrySnapshot(raw);
  if (registry === undefined) return false;
  return !registry?.profiles.some(
    (profile) =>
      profileMatchesDedicatedAgent(profile, agentId) &&
      profile.accessToken?.trim() === rejectedToken,
  );
}

/**
 * Durably retire one runtime-rejected dedicated-agent bearer.
 *
 * Pair, active-server and profile snapshots are captured and transformed under
 * the same origin-wide runtime Web Lock used by every credential writer. Every
 * transform is terminal and exact-CAS: losing the validator never compensates
 * rejected A back into storage, while a newer B value never compares equal and
 * therefore survives. Success is reported only after a host-authoritative
 * reread proves the rejected bearer absent from every target-owned mirror.
 */
export async function clearStalePairCredentialsForAgentDurably(
  options: StalePairCredentialDurableClearOptions,
): Promise<boolean> {
  const agentId = options.agentId.trim();
  const rejectedToken = options.rejectedToken.trim();
  if (!agentId || !rejectedToken || !options.validate()) return false;
  if (typeof window === "undefined") return false;

  try {
    return await withRuntimeConnectionPersistenceLock(async () => {
      if (!options.validate()) return false;

      const pairKeys = [
        cloudPairTokenKeyForAgent(agentId),
        CLOUD_PAIR_LOCAL_STORAGE_KEY,
      ];
      const pairSnapshots = pairKeys.flatMap((key) => {
        const local = readStrictPairStorageSnapshot(
          window.localStorage,
          key,
          "local",
        );
        const session = readStrictPairStorageSnapshot(
          window.sessionStorage,
          key,
          "session",
        );
        return local && session ? [local, session] : [];
      });
      if (pairSnapshots.length !== pairKeys.length * 2) return false;

      const activeServerRaw = await getStorageValue(ACTIVE_SERVER_STORAGE_KEY);
      if (!options.validate()) return false;
      const registryRaw = await getStorageValue(AGENT_PROFILE_STORAGE_KEY);
      if (!options.validate()) return false;

      for (const snapshot of pairSnapshots) {
        if (
          !removeRejectedPairSnapshotIfCurrent(
            snapshot,
            rejectedToken,
            options.validate,
          )
        ) {
          break;
        }
      }

      const activeServer = parseActiveServerSnapshot(activeServerRaw);
      if (
        options.validate() &&
        activeServer &&
        resolveDedicatedAgentId(activeServer) === agentId &&
        activeServer.accessToken?.trim() === rejectedToken &&
        activeServerRaw !== null
      ) {
        const { accessToken: _rejected, ...scrubbed } = activeServer;
        await setStorageValueIfCurrent(
          ACTIVE_SERVER_STORAGE_KEY,
          activeServerRaw,
          JSON.stringify(scrubbed),
          {
            validate: options.validate,
            compensateOnValidationFailure: false,
          },
        );
      }

      const registry = parseAgentProfileRegistrySnapshot(registryRaw);
      if (options.validate() && registry && registryRaw !== null) {
        let changed = false;
        const profiles = registry.profiles.map((profile) => {
          if (
            !profileMatchesDedicatedAgent(profile, agentId) ||
            profile.accessToken?.trim() !== rejectedToken
          ) {
            return profile;
          }
          changed = true;
          const { accessToken: _rejected, ...scrubbed } = profile;
          return scrubbed;
        });
        if (changed) {
          await setStorageValueIfCurrent(
            AGENT_PROFILE_STORAGE_KEY,
            registryRaw,
            JSON.stringify({ ...registry, profiles }),
            {
              validate: options.validate,
              compensateOnValidationFailure: false,
            },
          );
        }
      }

      if (!options.validate()) return false;
      const finalPairSnapshots = pairKeys.flatMap((key) => {
        const local = readStrictPairStorageSnapshot(
          window.localStorage,
          key,
          "local",
        );
        const session = readStrictPairStorageSnapshot(
          window.sessionStorage,
          key,
          "session",
        );
        return local && session ? [local, session] : [];
      });
      if (finalPairSnapshots.length !== pairKeys.length * 2) return false;
      const finalActiveServerRaw = await getStorageValue(
        ACTIVE_SERVER_STORAGE_KEY,
      );
      if (!options.validate()) return false;
      const finalRegistryRaw = await getStorageValue(AGENT_PROFILE_STORAGE_KEY);
      if (!options.validate()) return false;

      return (
        finalPairSnapshots.every(
          (snapshot) => snapshot.value?.trim() !== rejectedToken,
        ) &&
        rejectedTokenAbsentFromActiveServer(
          finalActiveServerRaw,
          agentId,
          rejectedToken,
        ) &&
        rejectedTokenAbsentFromProfiles(
          finalRegistryRaw,
          agentId,
          rejectedToken,
        )
      );
    });
  } catch {
    // A refused Web Lock or protected-host write cannot authorize a terminal
    // reauth/manage fallback. The owning hook degrades to retry (or idle for B).
    return false;
  }
}
