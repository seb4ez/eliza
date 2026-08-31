/** Resolves the credential forms accepted by native Cloud management routes. */
import { getElizaApiToken } from "@elizaos/shared";
import { BOOT_CONFIG_CHANGE_EVENT } from "@elizaos/shared/config/boot-config-store";
import {
  readStoredStewardToken,
  STEWARD_SESSION_CHANGE_EVENT,
} from "@elizaos/shared/steward-session-client";
import { useSyncExternalStore } from "react";
import { normalizeCloudApiKeyToken } from "../../../cloud/lib/cloud-api-key-token";
import {
  readStewardSessionRecovery,
  STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
} from "../../../cloud/lib/steward-session-recovery-marker";
import {
  configuredStewardTenantId,
  DEFAULT_STEWARD_TENANT_ID,
} from "../../../cloud/shell/steward-config";
import { getBootConfig } from "../../../config/boot-config";
import { captureStoredStewardLoginAuthority } from "../../../state/cloud-steward-login";

interface CloudManagementCredentialSources {
  stewardToken: string | null | undefined;
  bootApiToken: string | null | undefined;
  runtimeApiToken: string | null | undefined;
}

export interface CloudManagementAuthority {
  /** Exact Cloud control-plane origin selected at admission. */
  apiBase: string;
  /** Exact bearer selected at admission. */
  token: string;
  /** Recovery generation which admitted this account authority. */
  recoveryGeneration: string | null;
  /** Revalidate immediately before every post-await side effect. */
  validateAuthority(): boolean;
  /** Backward-compatible spelling used by the settings state machine. */
  isCurrent(): boolean;
}

function configuredCloudManagementApiBase(): string {
  const candidate = getBootConfig().cloudApiBase?.trim() || "https://eliza.app";
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return "";
    parsed.pathname = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return "";
  }
}

function readOwnerCloudApiKey(): string {
  return (
    normalizeCloudApiKeyToken(getBootConfig().apiToken) ??
    normalizeCloudApiKeyToken(getElizaApiToken()) ??
    ""
  );
}

function safelyReadStoredStewardToken(): string {
  try {
    return readStoredStewardToken()?.trim() ?? "";
  } catch {
    return "";
  }
}

function safelyReadCandidate(getManagementToken: () => string): string {
  try {
    return getManagementToken().trim();
  } catch {
    return "";
  }
}

function readCloudManagementRecovery() {
  return readStewardSessionRecovery(
    configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
  );
}

function isCloudManagementRecoveryClean(): boolean {
  const snapshot = readCloudManagementRecovery();
  return snapshot.storageAvailable && snapshot.receipts.length === 0;
}

/** Apply the same Steward-first, owner-key-fallback contract as the Cloud API transport. */
export function resolveCloudManagementToken({
  stewardToken,
  bootApiToken,
  runtimeApiToken,
}: CloudManagementCredentialSources): string {
  const steward = stewardToken?.trim();
  if (steward) return steward;
  return (
    normalizeCloudApiKeyToken(bootApiToken) ??
    normalizeCloudApiKeyToken(runtimeApiToken) ??
    ""
  );
}

/** Read the live credential chain available to this renderer window. */
export function currentCloudManagementToken(): string {
  // A durable login-B receipt quarantines the still-present account-A bearer.
  // Only a receipt-free recovery generation may win the Steward-first branch.
  // Every fallback also stops during recovery: an owner key is admissible only
  // in a clean generation where no stored Steward bearer can win transport.
  if (!isCloudManagementRecoveryClean()) return "";
  const stewardAuthority = captureStoredStewardLoginAuthority();
  if (stewardAuthority) return stewardAuthority.token;
  if (!isCloudManagementRecoveryClean()) return "";
  const ownerApiKey = readOwnerCloudApiKey();
  return ownerApiKey && isCloudManagementRecoveryClean() ? ownerApiKey : "";
}

/**
 * Capture the exact authority a Cloud-management action is about to use.
 *
 * Steward authority is fenced by both token identity and the origin-wide
 * recovery generation. Owner API keys are admitted only when no stored
 * Steward bearer can take precedence inside the shared Cloud transport. That
 * prevents a nominal owner-key fallback from dispatching with quarantined A.
 */
export function captureCloudManagementAuthority(
  getManagementToken: () => string = currentCloudManagementToken,
  apiBase = configuredCloudManagementApiBase(),
): CloudManagementAuthority | null {
  const exactApiBase = apiBase.trim().replace(/\/$/, "");
  if (!exactApiBase || exactApiBase !== configuredCloudManagementApiBase()) {
    return null;
  }
  const recovery = readCloudManagementRecovery();
  if (!recovery.storageAvailable || recovery.receipts.length > 0) return null;
  const token = safelyReadCandidate(getManagementToken);
  if (!token) return null;

  const stewardAuthority = captureStoredStewardLoginAuthority();
  if (stewardAuthority?.token === token) {
    const validateAuthority = () =>
      stewardAuthority.isCurrent() &&
      readCloudManagementRecovery().generation === recovery.generation &&
      configuredCloudManagementApiBase() === exactApiBase &&
      safelyReadCandidate(getManagementToken) === token;
    const authority: CloudManagementAuthority = {
      apiBase: exactApiBase,
      token,
      recoveryGeneration: recovery.generation,
      validateAuthority,
      isCurrent: validateAuthority,
    };
    return authority.isCurrent() ? authority : null;
  }

  if (!isCloudManagementRecoveryClean()) return null;
  // `getCloudAuthToken(client)` always prefers any stored Steward token. Do
  // not claim that an owner key is the dispatch authority while a different
  // (possibly quarantined) stored bearer would actually win that transport.
  if (safelyReadStoredStewardToken()) return null;
  const ownerApiKey = readOwnerCloudApiKey();
  if (!ownerApiKey || ownerApiKey !== token) return null;
  const validateAuthority = () =>
    isCloudManagementRecoveryClean() &&
    readCloudManagementRecovery().generation === recovery.generation &&
    configuredCloudManagementApiBase() === exactApiBase &&
    !safelyReadStoredStewardToken() &&
    readOwnerCloudApiKey() === token &&
    safelyReadCandidate(getManagementToken) === token;
  const authority: CloudManagementAuthority = {
    apiBase: exactApiBase,
    token,
    recoveryGeneration: recovery.generation,
    validateAuthority,
    isCurrent: validateAuthority,
  };
  return authority.isCurrent() ? authority : null;
}

export function hasCloudManagementCredential(): boolean {
  return currentCloudManagementToken().length > 0;
}

export function subscribeToCloudManagementCredential(
  onStoreChange: () => void,
): () => void {
  if (typeof window === "undefined") return () => undefined;

  const handleCredentialChange = () => onStoreChange();
  window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, handleCredentialChange);
  window.addEventListener(
    STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
    handleCredentialChange,
  );
  window.addEventListener("steward-token-sync", handleCredentialChange);
  window.addEventListener(BOOT_CONFIG_CHANGE_EVENT, handleCredentialChange);
  // Cross-document storage events cover Steward removal and persisted runtime
  // token changes without coupling this boundary to every storage key name.
  window.addEventListener("storage", handleCredentialChange);
  return () => {
    window.removeEventListener(
      STEWARD_SESSION_CHANGE_EVENT,
      handleCredentialChange,
    );
    window.removeEventListener(
      STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
      handleCredentialChange,
    );
    window.removeEventListener("steward-token-sync", handleCredentialChange);
    window.removeEventListener(
      BOOT_CONFIG_CHANGE_EVENT,
      handleCredentialChange,
    );
    window.removeEventListener("storage", handleCredentialChange);
  };
}

function noCloudManagementCredential(): boolean {
  return false;
}

/** Reactively track every credential form accepted by Cloud management. */
export function useHasCloudManagementCredential(): boolean {
  return useSyncExternalStore(
    subscribeToCloudManagementCredential,
    hasCloudManagementCredential,
    noCloudManagementCredential,
  );
}
