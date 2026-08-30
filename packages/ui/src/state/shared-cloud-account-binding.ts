/**
 * Atomically releases browser-persisted mirrors of an account-scoped shared
 * Cloud agent when its Steward account session ends.
 */

import { readStoredStewardToken } from "@elizaos/shared/steward-session-client";
import { client } from "../api";
import type { StorageWriteValidationOptions } from "../bridge/storage-bridge";
import { getBootConfig } from "../config/boot-config";
import { clearElizaApiBase, getElizaApiToken } from "../utils/eliza-globals";
import {
  type CloudRuntimeAuthorityClearOptions,
  type CloudRuntimeAuthorityClearResult,
  clearCloudRuntimeAuthorityDurably,
  removeManagedSharedCloudAgentProfiles,
} from "./agent-profiles";
import {
  clearPersistedSharedCloudActiveServer,
  loadPersistedActiveServer,
} from "./persistence";

const STORED_API_BASE_KEY = "elizaos_api_base";

interface CloudBindingCredentialSnapshot {
  bootToken: string | null;
  stewardToken: string | null;
  windowToken: string | null;
}

function captureCloudBindingCredentialSnapshot(): CloudBindingCredentialSnapshot {
  return {
    bootToken: getBootConfig().apiToken?.trim() || null,
    stewardToken: readStoredStewardToken()?.trim() || null,
    windowToken: getElizaApiToken()?.trim() || null,
  };
}

function sameCloudBindingCredentialSnapshot(
  expected: CloudBindingCredentialSnapshot,
): boolean {
  const current = captureCloudBindingCredentialSnapshot();
  return (
    current.bootToken === expected.bootToken &&
    current.stewardToken === expected.stewardToken &&
    current.windowToken === expected.windowToken
  );
}

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
  return clearSharedCloudAccountBindingDurablyWithDependencies(
    options,
    clearCloudRuntimeAuthorityDurably,
  );
}

async function clearSharedCloudAccountBindingDurablyWithDependencies(
  options: StorageWriteValidationOptions,
  clearAuthority: (
    options: CloudRuntimeAuthorityClearOptions,
  ) => Promise<CloudRuntimeAuthorityClearResult>,
): Promise<boolean> {
  const credentialSnapshot = captureCloudBindingCredentialSnapshot();
  // This path is entered only after the caller proved there is no Cloud
  // account session. A token already present here belongs to a newer login B.
  if (credentialSnapshot.stewardToken !== null) return false;
  const validate = () =>
    options.validate?.() !== false &&
    sameCloudBindingCredentialSnapshot(credentialSnapshot);
  if (!validate()) return false;
  const result = await clearAuthority({
    ...options,
    scope: "shared",
    validate,
    finalize: () => {
      if (!validate()) {
        throw new Error("Cloud account authority changed during teardown");
      }
      clearLiveSharedCloudBindingMirrors();
    },
  });
  return result.ok && result.clearedActiveServer;
}

export const sharedCloudAccountBindingInternals = {
  clearSharedCloudAccountBindingDurablyWithDependencies,
};

/**
 * Releases every browser mirror whose authority comes from the ending Eliza
 * Cloud account while preserving unrelated local and self-hosted profiles.
 */
export async function clearManagedCloudAccountBinding(): Promise<void> {
  const credentialSnapshot = captureCloudBindingCredentialSnapshot();
  const validate = () => sameCloudBindingCredentialSnapshot(credentialSnapshot);
  const result = await clearCloudRuntimeAuthorityDurably({
    scope: "managed",
    validate,
    finalize: () => {
      if (!validate()) {
        throw new Error("Cloud account authority changed during teardown");
      }
      clearLiveSharedCloudBindingMirrors();
    },
  });
  if (!result.ok) {
    throw new Error(
      `Cloud runtime teardown could not prove authority (${result.reason}).`,
    );
  }
}
