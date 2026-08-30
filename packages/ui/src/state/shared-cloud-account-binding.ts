/**
 * Atomically releases browser-persisted mirrors of an account-scoped shared
 * Cloud agent when its Steward account session ends.
 */

import { readStoredStewardToken } from "@elizaos/shared/steward-session-client";
import { client } from "../api";
import type { StorageWriteValidationOptions } from "../bridge/storage-bridge";
import { readStewardSessionGeneration } from "../cloud/lib/steward-session-recovery-marker";
import {
  configuredStewardTenantId,
  DEFAULT_STEWARD_TENANT_ID,
} from "../cloud/shell/steward-config";
import { getBootConfig } from "../config/boot-config";
import { isManagedCloudSharedAgentBase } from "../utils/cloud-agent-base";
import { clearElizaApiBase, getElizaApiToken } from "../utils/eliza-globals";
import type { AgentProfileRegistry } from "./agent-profile-types";
import {
  type CloudRuntimeAuthorityClearOptions,
  type CloudRuntimeAuthorityClearResult,
  type CloudRuntimeAuthorityLease,
  captureCloudRuntimeAuthorityWithAuxiliaryDurably,
  clearCloudRuntimeAuthorityDurably,
  removeManagedSharedCloudAgentProfiles,
} from "./agent-profiles";
import { dedicatedAgentIdFromApiBase } from "./agent-session-recovery";
import {
  type CloudPairApiTokenClearAuthority,
  captureCloudPairApiTokenClearAuthority,
  clearCloudPairApiTokenIfCurrent,
} from "./cloud-pair-token";
import {
  captureFirstRunAccountResetAuthority,
  clearPersistedSharedCloudActiveServer,
  type FirstRunAccountResetAuthority,
  loadPersistedActiveServer,
  markFirstRunIncompleteForAccountIfCurrent,
  type PersistedActiveServer,
} from "./persistence";

const STORED_API_BASE_KEY = "elizaos_api_base";

export interface CloudBindingCredentialSnapshot {
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
    requireStewardTokenAbsent: true,
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

export interface ManagedCloudAccountBindingAuthority
  extends CloudRuntimeAuthorityLease {
  credentials: CloudBindingCredentialSnapshot;
  pairTokens: CloudPairApiTokenClearAuthority;
  firstRun: FirstRunAccountResetAuthority;
  sessionGeneration: string | null;
}

function captureManagedPairTokenAuthority(
  runtime: CloudRuntimeAuthorityLease,
): CloudPairApiTokenClearAuthority {
  const agentIds = new Set<string>();
  const ownedTokens = new Set<string>();
  if (runtime.stewardToken) ownedTokens.add(runtime.stewardToken);
  try {
    const active = runtime.activeServerRaw
      ? (JSON.parse(runtime.activeServerRaw) as PersistedActiveServer)
      : null;
    if (active?.accessToken) ownedTokens.add(active.accessToken);
    const activeAgentId = active?.apiBase
      ? dedicatedAgentIdFromApiBase(active.apiBase)
      : null;
    if (activeAgentId) agentIds.add(activeAgentId);
  } catch {
    // Invalid runtime authority is rejected by the durable clear boundary.
  }
  try {
    const registry = runtime.registryRaw
      ? (JSON.parse(runtime.registryRaw) as AgentProfileRegistry)
      : null;
    for (const profile of registry?.profiles ?? []) {
      if (
        profile.kind !== "cloud" &&
        !isManagedCloudSharedAgentBase(profile.apiBase)
      ) {
        continue;
      }
      if (profile.accessToken) ownedTokens.add(profile.accessToken);
      if (profile.cloudAgentId) agentIds.add(profile.cloudAgentId);
      const dedicatedId = dedicatedAgentIdFromApiBase(profile.apiBase);
      if (dedicatedId) agentIds.add(dedicatedId);
    }
  } catch {
    // Invalid runtime authority is rejected by the durable clear boundary.
  }
  return captureCloudPairApiTokenClearAuthority(
    [...agentIds],
    [...ownedTokens],
  );
}

/** Capture the exact host authority before an explicit account sign-out. */
export async function captureManagedCloudAccountBindingAuthority(expected?: {
  stewardToken: string;
  sessionGeneration: string | null;
}): Promise<ManagedCloudAccountBindingAuthority> {
  const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
  const generationBefore = readStewardSessionGeneration(tenantId);
  if (
    !generationBefore.storageAvailable ||
    (expected && generationBefore.generation !== expected.sessionGeneration)
  ) {
    throw new Error("Cloud account generation changed before sign-out.");
  }
  const captured = await captureCloudRuntimeAuthorityWithAuxiliaryDurably(
    expected?.stewardToken,
    (runtime) => {
      const credentials = captureCloudBindingCredentialSnapshot();
      if (credentials.stewardToken !== runtime.stewardToken) {
        throw new Error(
          "Cloud account credential mirrors changed while sign-out was captured.",
        );
      }
      return {
        credentials,
        firstRun: captureFirstRunAccountResetAuthority(),
        pairTokens: captureManagedPairTokenAuthority(runtime),
      };
    },
  );
  const runtime = captured.authority;
  const generationAfter = readStewardSessionGeneration(tenantId);
  if (
    !generationAfter.storageAvailable ||
    generationAfter.generation !== generationBefore.generation
  ) {
    throw new Error(
      "Cloud account generation changed while sign-out was captured.",
    );
  }
  return {
    ...runtime,
    credentials: captured.auxiliary.credentials,
    firstRun: captured.auxiliary.firstRun,
    pairTokens: captured.auxiliary.pairTokens,
    sessionGeneration: generationAfter.generation,
  };
}

/**
 * Releases every browser mirror whose authority comes from the ending Eliza
 * Cloud account while preserving unrelated local and self-hosted profiles.
 */
export async function clearManagedCloudAccountBinding(
  expectedAuthority: ManagedCloudAccountBindingAuthority,
  options: { sessionGeneration?: string | null } = {},
): Promise<void> {
  const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
  const expectedGeneration =
    options.sessionGeneration === undefined
      ? expectedAuthority.sessionGeneration
      : options.sessionGeneration;
  const validate = () => {
    const generation = readStewardSessionGeneration(tenantId);
    const currentCredentials = captureCloudBindingCredentialSnapshot();
    const initialCredentials = expectedAuthority.credentials;
    const exactInitial =
      currentCredentials.bootToken === initialCredentials.bootToken &&
      currentCredentials.stewardToken === initialCredentials.stewardToken &&
      currentCredentials.windowToken === initialCredentials.windowToken;
    const exactAndroidPostRevoke =
      currentCredentials.bootToken === initialCredentials.bootToken &&
      currentCredentials.stewardToken === null &&
      currentCredentials.windowToken === initialCredentials.windowToken;
    const exactSsoPostRevoke =
      currentCredentials.bootToken === null &&
      currentCredentials.stewardToken === null &&
      currentCredentials.windowToken === null;
    return (
      generation.storageAvailable &&
      generation.generation === expectedGeneration &&
      (exactInitial || exactAndroidPostRevoke || exactSsoPostRevoke)
    );
  };
  const result = await clearCloudRuntimeAuthorityDurably({
    expectedAuthority,
    scope: "managed",
    validate,
    finalize: (_server, lease) => {
      if (!validate()) {
        throw new Error("Cloud account authority changed during teardown");
      }
      clearCloudPairApiTokenIfCurrent(expectedAuthority.pairTokens, lease);
      if (
        !markFirstRunIncompleteForAccountIfCurrent(
          expectedAuthority.firstRun,
          expectedGeneration ?? "pre-session-generation",
          validate,
        )
      ) {
        throw new Error("Cloud onboarding authority changed during teardown");
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
