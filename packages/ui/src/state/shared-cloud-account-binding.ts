/**
 * Atomically releases browser-persisted mirrors of an account-scoped shared
 * Cloud agent when its Steward account session ends.
 */

import { client } from "../api";
import type { StorageWriteValidationOptions } from "../bridge/storage-bridge";
import { isManagedCloudSharedAgentBase } from "../utils/cloud-agent-base";
import { clearElizaApiBase } from "../utils/eliza-globals";
import {
  clearManagedSharedCloudProfilesAndTokensDurably,
  removeManagedCloudAgentProfilesDurably,
  removeManagedSharedCloudAgentProfiles,
} from "./agent-profiles";
import { isManagedCloudAgentServer } from "./agent-session-recovery";
import {
  clearPersistedActiveServerDurably,
  clearPersistedSharedCloudActiveServer,
  clearPersistedSharedCloudActiveServerDurably,
  loadPersistedActiveServer,
} from "./persistence";

const STORED_API_BASE_KEY = "elizaos_api_base";

function clearLiveSharedCloudBindingMirrors(): void {
  client.setToken(null);
  client.setBaseUrl(null);
  clearElizaApiBase();
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(STORED_API_BASE_KEY);
    window.sessionStorage.removeItem(STORED_API_BASE_KEY);
  } catch {
    // error-policy:J6 canonical protected state is already committed; these
    // compatibility mirrors cannot re-authorize a shared Cloud session.
  }
}

/**
 * Clear the active server, matching profile, boot/global base, and legacy
 * client-base storage mirror. Returns false for dedicated or self-hosted
 * selections, whose independent agent credentials remain recoverable.
 */
export function clearSharedCloudAccountBinding(): boolean {
  const activeServer = loadPersistedActiveServer();
  const apiBase = activeServer?.apiBase;
  if (!apiBase || !clearPersistedSharedCloudActiveServer()) return false;

  removeManagedSharedCloudAgentProfiles();
  clearLiveSharedCloudBindingMirrors();
  return true;
}

/**
 * Await removal of the shared active selection and every shared profile before
 * clearing the live client/base mirrors or reporting success. Dedicated and
 * self-hosted selections do not satisfy the strict shared-base predicate.
 */
export async function clearSharedCloudAccountBindingDurably(
  options: StorageWriteValidationOptions = {},
): Promise<boolean> {
  if (options.validate?.() === false) return false;
  const activeServer = loadPersistedActiveServer();
  if (!isManagedCloudSharedAgentBase(activeServer?.apiBase)) return false;
  await clearManagedSharedCloudProfilesAndTokensDurably(options);
  if (options.validate?.() === false) return false;

  if (!(await clearPersistedSharedCloudActiveServerDurably(options))) {
    // A lost terminal authority never resurrects A. The exact profile scrub
    // remains safe, while a newer B registry/selection is host-CAS protected.
    return false;
  }

  if (options.validate?.() === false) return false;
  clearLiveSharedCloudBindingMirrors();
  return true;
}

/**
 * Releases every browser mirror whose authority comes from the ending Eliza
 * Cloud account while preserving unrelated local and self-hosted profiles.
 */
export async function clearManagedCloudAccountBinding(): Promise<void> {
  const activeServer = loadPersistedActiveServer();
  if (isManagedCloudAgentServer(activeServer)) {
    await clearPersistedActiveServerDurably();
    client.setToken(null);
    client.setBaseUrl(null);
    clearElizaApiBase();
    if (typeof window !== "undefined") {
      try {
        window.localStorage.removeItem(STORED_API_BASE_KEY);
        window.sessionStorage.removeItem(STORED_API_BASE_KEY);
      } catch {
        // error-policy:J6 account sign-out already cleared canonical managed
        // selection state; inaccessible compatibility mirrors cannot be reused.
      }
    }
  }
  await removeManagedCloudAgentProfilesDurably();
}
