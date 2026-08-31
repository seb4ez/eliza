/**
 * Eliza Cloud state, one of the domain hooks AppContext composes.
 *
 * Manages:
 * - Cloud connection state (enabled, connected, persisted key, user ID)
 * - Credits state (balance, low/critical thresholds, errors, top-up URL)
 * - Login / disconnect flow (busy flags, error messages, poll timers)
 * - Cloud dashboard view preference
 * - Auth-rejected notice effect
 *
 * Cross-domain dependencies accepted as params:
 * - `setActionNotice`        — from useLifecycleState, used for disconnect / auth notices
 * - `loadWalletConfig`       — from useWalletState, called after successful login
 * - `t`                      — translation function, used for auth-rejected notice key
 */

import { Capacitor } from "@capacitor/core";
import { logger } from "@elizaos/logger";
import { isElizaCloudControlPlaneHostname } from "@elizaos/shared/elizacloud";
import {
  clearStoredStewardToken,
  readStoredStewardToken,
  replaceStoredStewardTokenIfCurrent,
  type StewardTokenWriteAuthority,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  ANDROID_CLOUD_AUTH_RESULT_EVENT,
  ANDROID_CLOUD_AUTH_STARTED_EVENT,
  type AndroidCloudAuthResult,
  beginAndroidCloudSignIn,
  cancelAndroidCloudSignIn,
  clearAndroidCloudAccountSwitchPending,
  isAndroidCloudAccountSwitchPending,
  markAndroidCloudAccountSwitchPending,
  navigateAndroidCloudSignInInApp,
  signOutAndroidCloud,
  takeLatestAndroidCloudCompletion,
} from "../android-cloud/android-cloud-auth";
import { type CloudCredits, type CloudStatus, client } from "../api";
import { supportsFullAppShellRoutes } from "../api/app-shell-capabilities";
import type { SessionTargetAuthority } from "../api/client-base";
import {
  cloudTokenSecsRemaining,
  getCloudAuthToken,
  refreshCloudStewardSession,
  resolveDirectCloudAuthApiBase,
  resolveDirectCloudWebBase,
  verifyDirectCloudStewardSession,
} from "../api/client-cloud";
import {
  invokeDesktopBridgeRequestWithTimeout,
  isElectrobunRuntime,
} from "../bridge";
import { isAppModeHost } from "../cloud/app-mode/app-mode";
import { publishCloudAuthComplete } from "../cloud/auth/cloud-auth-complete-signal";
import { enqueueStewardSessionMutation } from "../cloud/lib/steward-session-mutation-queue";
import {
  beginStewardSessionRecovery,
  createStewardSessionRecoveryPublicationFence,
  isStewardSessionRecoveryReceiptLive,
  readStewardSessionRecovery,
  rejectStewardSessionRecovery,
  type StewardSessionRecoveryPublicationRollback,
  type StewardSessionRecoveryReceipt,
} from "../cloud/lib/steward-session-recovery-marker";
import {
  configuredStewardTenantId,
  DEFAULT_STEWARD_TENANT_ID,
} from "../cloud/shell/steward-config";
import { signOutFromSsoBridgedHost } from "../cloud/sso-bridge/sso-bridge";
import { getBootConfig, setBootConfig } from "../config/boot-config";
import { dispatchElizaCloudStatusUpdated } from "../events";
import { isElizaCloudRuntimeLocked } from "../first-run/mobile-runtime-mode";
import {
  isAndroidCloudBuild,
  isAndroidLauncherBuild,
} from "../platform/android-runtime";
import { isViteDevUiShell } from "../platform/vite-dev-ui-shell";
import {
  closeExternalBrowser,
  confirmDesktopAction,
  isCloudStatusAuthenticated,
  isSafeNavigationUrl,
  listenForExternalBrowserFinished,
  navigatePreOpenedWindow,
  openExternalUrl,
  yieldHttpAfterNativeMessageBox,
} from "../utils";
import { scrubPersistedAgentProfileTokens } from "./agent-profiles";
import {
  bindDirectCloudLoginToPersonalAgent,
  type DirectCloudBindingAuthority,
} from "./bind-direct-cloud-login";
import {
  CLOUD_LOGIN_POPUP_NAME,
  isLoopbackStagingStewardDevelopment,
  navigateToSameTabCloudLogin,
  shouldUseSameTabCloudLogin,
  takeClaimedCloudLoginWindow,
  takePreparedDesktopCloudLoginSession,
} from "./cloud-login-launch";
import { clearCloudPairApiToken } from "./cloud-pair-token";
import {
  getInjectedEthereumProvider,
  siweLoginWithInjectedWalletAuthority,
} from "./cloud-siwe-login";
import {
  hasStewardLoginLauncher,
  hasUsableStoredStewardToken,
  launchStewardLogin,
} from "./cloud-steward-login";

import {
  loadPersistedActiveServer,
  scrubPersistedActiveServerToken,
} from "./persistence";
import { isPrivateNetworkHost } from "./private-network-host";
import { getBuildConfiguredRemoteApiBaseUrl } from "./runtime-url-trust";
import {
  captureManagedCloudAccountBindingAuthority,
  clearManagedCloudAccountBinding,
} from "./shared-cloud-account-binding";
import type { CloudLoginOptions } from "./types";

// ── Constants ──────────────────────────────────────────────────────────────

const ELIZA_CLOUD_LOGIN_POLL_INTERVAL_MS = 1000;
const ELIZA_CLOUD_LOGIN_RETURN_POLL_TIMEOUT_MS = 60_000;
const ELIZA_CLOUD_LOGIN_TIMEOUT_MS = 300_000;
const ELIZA_CLOUD_LOGIN_MAX_CONSECUTIVE_ERRORS = 3;
const ANDROID_CLOUD_AUTH_TIMEOUT_MS = 5 * 60_000;
const ANDROID_CLOUD_BROWSER_FINISH_GRACE_MS = 1_500;
const DEFAULT_DIRECT_CLOUD_BASE_URL = "https://eliza.app";
const CLOUD_SESSION_VERIFICATION_TRANSIENT_MESSAGE =
  "Eliza Cloud is temporarily unavailable. Retry in a moment.";
const ELIZA_CLOUD_LOGIN_COMPLETE_PARAM = "elizaCloudLogin";
const ELIZA_CLOUD_LOGIN_SESSION_PARAM = "elizaCloudLoginSession";

function beginCloudLoginAuthorityRecovery(): StewardSessionRecoveryReceipt {
  return beginStewardSessionRecovery(
    configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
    "provider",
  );
}

function rejectCloudLoginAuthorityRecovery(
  recovery: StewardSessionRecoveryReceipt,
): void {
  if (isStewardSessionRecoveryReceiptLive(recovery)) {
    rejectStewardSessionRecovery(recovery);
  }
}

/**
 * Publish one device-code authority transition while its durable intent still
 * owns the origin. A newer login can synchronously retire this receipt while
 * the old poll is in flight; in that case the old response never reaches
 * protected storage, boot config, or the active client.
 */
interface CloudLoginPublicationAuthority {
  restoreIfCurrent(): Promise<void>;
}

interface CommittedCloudLoginAuthority {
  /** Re-check after every await continuation before external completion UI. */
  isCurrent(): boolean;
  /** CAS-safe composite rollback for a continuation superseded after await. */
  restoreIfCurrent(): Promise<void>;
}

interface ExactCloudSessionAuthority {
  token: string | null;
  isCurrent(): boolean;
}

function captureExactCloudSessionAuthority(
  expectedToken: string | null = getCloudAuthToken(client),
): ExactCloudSessionAuthority | null {
  const token = expectedToken?.trim() || null;
  const tenantId = configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID);
  const snapshot = readStewardSessionRecovery(tenantId);
  if (!snapshot.storageAvailable || snapshot.receipts.length > 0) return null;
  return {
    token,
    isCurrent: () => {
      const current = readStewardSessionRecovery(tenantId);
      return (
        current.storageAvailable &&
        current.generation === snapshot.generation &&
        current.receipts.length === 0 &&
        getCloudAuthToken(client) === token
      );
    },
  };
}

async function commitCloudLoginAuthority(
  recovery: StewardSessionRecoveryReceipt,
  publish: (
    validate: () => boolean,
    finalizeReceipt: () => StewardSessionRecoveryPublicationRollback,
  ) => Promise<CloudLoginPublicationAuthority | false>,
): Promise<CommittedCloudLoginAuthority | null> {
  return enqueueStewardSessionMutation(async () => {
    const recoveryPublication =
      createStewardSessionRecoveryPublicationFence(recovery);
    const validate = recoveryPublication.validate;
    if (!validate()) return null;
    const publication = await publish(
      validate,
      recoveryPublication.finalizeBeforePublish,
    );
    if (publication === false) return null;
    if (!recoveryPublication.isFinalized() || !validate()) {
      await publication.restoreIfCurrent();
      return null;
    }
    const currentAfterRecoveryEvent = recoveryPublication.publishChange();
    return {
      isCurrent: () => currentAfterRecoveryEvent && validate(),
      restoreIfCurrent: publication.restoreIfCurrent,
    };
  });
}

async function rollbackCloudLoginPublication(options: {
  bindingAuthority: DirectCloudBindingAuthority | null;
  tokenAuthority: StewardTokenWriteAuthority | null;
  clientTargetAuthority: SessionTargetAuthority | null;
  previousBootConfig: ReturnType<typeof getBootConfig>;
  publishedBootConfig: ReturnType<typeof getBootConfig> | null;
}): Promise<void> {
  const failures: unknown[] = [];
  try {
    await options.bindingAuthority?.restoreIfCurrent();
  } catch (error) {
    failures.push(error);
  }
  let tokenRestored = false;
  try {
    tokenRestored =
      (await options.tokenAuthority?.restorePredecessor({
        deferPublication: true,
      })) === true;
  } catch (error) {
    failures.push(error);
  }
  if (options.clientTargetAuthority && !tokenRestored) {
    const bootOwned =
      options.publishedBootConfig !== null &&
      getBootConfig() === options.publishedBootConfig;
    try {
      const cleared = options.clientTargetAuthority.clearIfCurrent();
      if (bootOwned && cleared) setBootConfig(options.previousBootConfig);
    } catch (error) {
      failures.push(error);
    }
  } else if (
    !options.tokenAuthority &&
    !options.bindingAuthority &&
    options.publishedBootConfig !== null &&
    getBootConfig() === options.publishedBootConfig
  ) {
    try {
      setBootConfig(options.previousBootConfig);
    } catch (error) {
      failures.push(error);
    }
  }
  if (tokenRestored && options.tokenAuthority?.publish?.() !== true) {
    failures.push(
      new Error("Restored Steward authority could not be published."),
    );
  }
  if (failures.length > 0) {
    throw new AggregateError(
      failures,
      "Could not fully restore the superseded Cloud login publication.",
    );
  }
}

/** A stale clear must not erase a login that won before queue admission. */
async function clearStoredStewardTokenIfUnchanged(
  expectedToken: string,
): Promise<void> {
  await enqueueStewardSessionMutation(async () => {
    if (readStoredStewardToken()?.trim() !== expectedToken) return;
    await clearStoredStewardToken({ expectedToken });
  });
}

let activeCloudLoginPopup: Window | null = null;

class CloudSessionVerificationTransientError extends Error {
  override readonly name = "CloudSessionVerificationTransientError";

  constructor(cause: unknown) {
    super(CLOUD_SESSION_VERIFICATION_TRANSIENT_MESSAGE, { cause });
  }
}

/** Cloud=Steward token-lifecycle: how often to check the JWT for expiry. */
const STEWARD_REFRESH_CHECK_INTERVAL_MS = 60_000;
/** Refresh the Steward session this many seconds before the JWT `exp`. */
const STEWARD_REFRESH_AHEAD_SECS = 120;
/** Same-origin Steward refresh endpoint (web cookie path). */
const STEWARD_REFRESH_PATH = "/api/auth/steward-refresh";

// ── Helpers ────────────────────────────────────────────────────────────────

/** Publish server cloud snapshot for chat TTS (`useVoiceChat` + `loadVoiceConfig`). */
function publishElizaCloudVoiceSnapshot(
  setHasPersistedKey: (value: boolean) => void,
  snapshot: {
    apiConnected: boolean;
    enabled: boolean;
    cloudVoiceProxyAvailable: boolean;
    hasPersistedApiKey: boolean;
  },
  validateAuthority: () => boolean = () => true,
): boolean {
  // The status event is itself an externally observable publication. Fence it
  // before dispatch (a different renderer may have advanced the durable login
  // generation since the caller's last check), then fence the local state again
  // in case a synchronous listener starts a newer login while handling it.
  if (!validateAuthority()) return false;
  dispatchElizaCloudStatusUpdated({
    connected: snapshot.apiConnected,
    enabled: snapshot.enabled,
    hasPersistedApiKey: snapshot.hasPersistedApiKey,
    cloudVoiceProxyAvailable: snapshot.cloudVoiceProxyAvailable,
  });
  if (!validateAuthority()) return false;
  setHasPersistedKey(snapshot.hasPersistedApiKey);
  return true;
}

function isSameOriginLocalHttpBackend(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  const { hostname, protocol } = window.location;
  if (protocol !== "http:" && protocol !== "https:") {
    return false;
  }

  return isPrivateNetworkHost(hostname);
}

function isDevUiPortWithoutEmbeddedBackend(): boolean {
  return isViteDevUiShell();
}

function isTrustedCloudAuthMessageOrigin(
  origin: string,
  cloudApiBase: string,
): boolean {
  if (!origin) return false;
  try {
    return (
      new URL(origin).origin ===
      new URL(resolveDirectCloudWebBase(cloudApiBase)).origin
    );
  } catch (error) {
    void error;
    return false;
  }
}

function isMatchingCloudAuthCompleteMessage(
  data: unknown,
  sessionId: string,
): boolean {
  // Keep the message contract aligned with cloud-auth-complete-signal.ts
  // (BroadcastChannel + postMessage share the same payload shape).
  if (!sessionId || typeof data !== "object" || data === null) return false;
  const message = data as { type?: unknown; sessionId?: unknown };
  return (
    message.type === "eliza-cloud-auth-complete" &&
    message.sessionId === sessionId
  );
}

function readCloudLoginReturnSessionId(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const url = new URL(window.location.href);
    if (url.searchParams.get(ELIZA_CLOUD_LOGIN_COMPLETE_PARAM) !== "complete") {
      return null;
    }
    const sessionId = url.searchParams
      .get(ELIZA_CLOUD_LOGIN_SESSION_PARAM)
      ?.trim();
    return sessionId || null;
  } catch (error) {
    void error;
    return null;
  }
}

function clearCloudLoginReturnParams(): void {
  if (typeof window === "undefined") return;
  try {
    const url = new URL(window.location.href);
    let changed = false;
    for (const key of [
      ELIZA_CLOUD_LOGIN_COMPLETE_PARAM,
      ELIZA_CLOUD_LOGIN_SESSION_PARAM,
    ]) {
      if (url.searchParams.has(key)) {
        url.searchParams.delete(key);
        changed = true;
      }
    }
    if (changed) {
      const next = `${url.pathname}${url.search}${url.hash}`;
      window.history.replaceState(window.history.state, "", next);
    }
  } catch (error) {
    void error;
    // error-policy:J3 URL cleanup is cosmetic; auth polling can still proceed.
  }
}

function rememberCloudLoginPopup(popup: Window | null): void {
  if (popup && !popup.closed) {
    activeCloudLoginPopup = popup;
  }
}

function openNamedCloudLoginPopup(url: string): Window | null {
  if (typeof window === "undefined" || typeof window.open !== "function") {
    return null;
  }
  try {
    const popup = window.open(url, CLOUD_LOGIN_POPUP_NAME);
    rememberCloudLoginPopup(popup);
    return popup && !popup.closed ? popup : null;
  } catch (error) {
    void error;
    // error-policy:J4 popup launch can be blocked; caller owns fallback.
    return null;
  }
}

function closePopupWindow(
  popup: Window | null,
  validateClose: () => boolean = () => true,
): void {
  // A named browser window can be reused by a newer login. Validate before
  // every mutation, not only inside the fallback timer, so a stale continuation
  // cannot close or blank the popup now owned by that newer authority.
  if (!validateClose() || !popup || popup.closed) return;
  try {
    if (!validateClose()) return;
    popup.close();
  } catch (error) {
    void error;
    // error-policy:J6 best-effort popup teardown after auth return.
  }
  try {
    if (!validateClose()) return;
    if (!popup.closed) {
      popup.location.href = "about:blank";
      globalThis.setTimeout(() => {
        if (!validateClose()) return;
        try {
          popup.close();
        } catch (error) {
          void error;
          // error-policy:J6 best-effort delayed close after blanking the popup.
        }
      }, 0);
    }
  } catch (error) {
    void error;
    // error-policy:J6 cross-origin window policies can reject navigation.
  }
}

function closeCloudLoginPopup(
  popup: Window | null,
  validateClose: () => boolean = () => true,
): void {
  if (!validateClose()) return;

  const activePopupAtEntry = activeCloudLoginPopup;
  const hadKnownPopup = Boolean(popup || activePopupAtEntry);
  const candidates: Window[] = [];
  const addCandidate = (candidate: Window | null) => {
    if (!candidate || candidates.includes(candidate)) return;
    candidates.push(candidate);
  };
  addCandidate(popup);
  // An explicit handle owns only itself. Do not let an older caller collect a
  // different active handle that a newer login installed in the meantime.
  if (!popup || activePopupAtEntry === popup) {
    addCandidate(activePopupAtEntry);
  }
  if (!validateClose()) return;
  if (
    activePopupAtEntry &&
    activeCloudLoginPopup === activePopupAtEntry &&
    candidates.includes(activePopupAtEntry)
  ) {
    activeCloudLoginPopup = null;
  }
  if (
    hadKnownPopup &&
    validateClose() &&
    typeof window !== "undefined" &&
    typeof window.open === "function"
  ) {
    try {
      addCandidate(window.open("", CLOUD_LOGIN_POPUP_NAME));
    } catch (error) {
      void error;
      // error-policy:J6 reclaiming a named popup is opportunistic cleanup.
    }
  }
  for (const candidate of candidates) {
    closePopupWindow(candidate, validateClose);
  }
}

function closeActiveCloudLoginPopup(
  validateDelayedClose?: () => boolean,
): void {
  closeCloudLoginPopup(activeCloudLoginPopup, validateDelayedClose);
}

function closeReturnedAuthTabIfOpenerStillExists(): void {
  if (typeof window === "undefined") return;
  try {
    const opener = window.opener as Window | null;
    if (opener && !opener.closed) {
      window.close();
    }
  } catch (error) {
    void error;
    // error-policy:J6 best-effort close; a normal tab simply remains open.
  }
}

function isCapacitorNativeRuntime(): boolean {
  if (typeof globalThis === "undefined") return false;
  const capacitor = (
    globalThis as {
      Capacitor?: {
        isNativePlatform?: () => boolean;
      };
    }
  ).Capacitor;
  return Boolean(capacitor?.isNativePlatform?.());
}

function canUseMountedStewardLoginSurface(): boolean {
  if (isCapacitorNativeRuntime()) {
    return hasUsableStoredStewardToken();
  }
  return hasUsableStoredStewardToken() || hasStewardLoginLauncher();
}

function originsMatch(left: string, right: string): boolean {
  try {
    return new URL(left).origin === new URL(right).origin;
  } catch {
    // error-policy:J3 malformed URL input fails closed (no origin match).
    return false;
  }
}

function isConfiguredCloudSiteBase(baseUrl: string): boolean {
  const configuredCloudBase =
    getBootConfig().cloudApiBase?.trim() || DEFAULT_DIRECT_CLOUD_BASE_URL;
  if (originsMatch(baseUrl, configuredCloudBase)) return true;

  try {
    const host = new URL(baseUrl).hostname.toLowerCase();
    return isElizaCloudControlPlaneHostname(host);
  } catch {
    // error-policy:J3 malformed base URL fails closed (not a cloud site base).
    return false;
  }
}

function isCapacitorAssetBase(baseUrl: string): boolean {
  if (!isCapacitorNativeRuntime()) return false;
  try {
    const parsed = new URL(baseUrl);
    if (parsed.pathname !== "/" || parsed.search || parsed.hash) return false;
    return (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      parsed.hostname.toLowerCase() === "localhost" &&
      parsed.port === ""
    );
  } catch {
    // error-policy:J3 malformed base URL fails closed (not the asset base).
    return false;
  }
}

function isCloudOnlyElectrobunAssetBase(baseUrl: string): boolean {
  if (
    typeof window === "undefined" ||
    !isElectrobunRuntime() ||
    Reflect.get(window, "__ELIZA_DESKTOP_RUNTIME_MODE__") !== "cloud"
  ) {
    return false;
  }
  try {
    const parsed = new URL(baseUrl, window.location.href);
    return (
      parsed.origin === window.location.origin &&
      isPrivateNetworkHost(parsed.hostname)
    );
  } catch {
    // error-policy:J3 malformed base URL fails closed (not an asset base).
    return false;
  }
}

function hasCloudLoginBackend(): boolean {
  if (isCapacitorNativeRuntime()) return false;

  const explicitBase =
    typeof client.getBaseUrl === "function" ? client.getBaseUrl().trim() : "";
  if (explicitBase) {
    if (isCloudOnlyElectrobunAssetBase(explicitBase)) return false;
    return (
      !isConfiguredCloudSiteBase(explicitBase) &&
      !isCapacitorAssetBase(explicitBase)
    );
  }
  if (isDevUiPortWithoutEmbeddedBackend()) return false;
  if (isCloudOnlyElectrobunAssetBase(window.location.origin)) return false;
  return isSameOriginLocalHttpBackend();
}

function canPollCloudStatus(): boolean {
  // A remote client gets models and voice from its paired runtime, whether the
  // target is immutable at build time or selected during first run. Polling
  // that runtime's optional Cloud billing integration misclassifies an
  // unrelated server credential as the client's own authentication state.
  if (
    getBuildConfiguredRemoteApiBaseUrl() ||
    loadPersistedActiveServer()?.kind === "remote"
  ) {
    return false;
  }

  const explicitBase =
    typeof client.getBaseUrl === "function" ? client.getBaseUrl().trim() : "";
  if (isCapacitorNativeRuntime() || isElectrobunRuntime()) return true;
  if (explicitBase && isConfiguredCloudSiteBase(explicitBase)) return true;
  return hasCloudLoginBackend() && supportsFullAppShellRoutes(explicitBase);
}

type PollIntent = "ambient" | "session-verification";

/**
 * Resolve the Steward refresh endpoint for the current target. On hosted web
 * the same-origin cookie path works (the HttpOnly `steward-refresh-token`
 * cookie travels automatically). On native/Electrobun there is no same-origin
 * cookie, so refresh against the configured cloud API base (Bearer-refresh).
 * Returns `undefined` to use the shared default.
 */
function resolveStewardRefreshEndpoint(): string | undefined {
  if (!isCapacitorNativeRuntime() && !isElectrobunRuntime()) return undefined;
  const cloudBase =
    getBootConfig().cloudApiBase?.trim() || DEFAULT_DIRECT_CLOUD_BASE_URL;
  const apiBase = resolveDirectCloudAuthApiBase(cloudBase);
  try {
    new URL(apiBase);
  } catch {
    // error-policy:J3 malformed cloud base URL → use the shared default
    // refresh endpoint (the documented `undefined` contract of this helper).
    return undefined;
  }
  return `${apiBase}${STEWARD_REFRESH_PATH}`;
}

// ── Types ──────────────────────────────────────────────────────────────────

interface CloudStateParams {
  setActionNotice: (
    text: string,
    tone?: "info" | "success" | "error",
    ttlMs?: number,
    once?: boolean,
    busy?: boolean,
  ) => void;
  /** From useWalletState — called after successful cloud login to reload wallet. */
  loadWalletConfig: () => Promise<void>;
  /** Translation function — used for the auth-rejected notice. */
  t: (key: string) => string;
  /** Product/runtime policy can lock cloud auth on, hiding disconnect affordances. */
  disconnectLocked?: boolean;
}

// ── Hook ───────────────────────────────────────────────────────────────────

export function useCloudState({
  setActionNotice,
  loadWalletConfig,
  t,
  disconnectLocked = false,
}: CloudStateParams) {
  // ── State ──────────────────────────────────────────────────────────

  const [elizaCloudEnabled, setElizaCloudEnabled] = useState(false);
  const [elizaCloudVoiceProxyAvailable, setElizaCloudVoiceProxyAvailable] =
    useState(false);
  const [elizaCloudConnected, setElizaCloudConnected] = useState(false);
  const [elizaCloudHasPersistedKey, setElizaCloudHasPersistedKey] =
    useState(false);
  const [elizaCloudCredits, setElizaCloudCredits] = useState<number | null>(
    null,
  );
  const [elizaCloudCreditsLow, setElizaCloudCreditsLow] = useState(false);
  const [elizaCloudCreditsCritical, setElizaCloudCreditsCritical] =
    useState(false);
  const [elizaCloudAuthRejected, setElizaCloudAuthRejected] = useState(false);
  const [elizaCloudCreditsError, setElizaCloudCreditsError] = useState<
    string | null
  >(null);
  const [elizaCloudTopUpUrl, setElizaCloudTopUpUrl] =
    useState("/cloud/billing");
  const [elizaCloudUserId, setElizaCloudUserId] = useState<string | null>(null);
  const [elizaCloudStatusReason, setElizaCloudStatusReason] = useState<
    string | null
  >(null);
  const [cloudDashboardView, setCloudDashboardView] = useState<
    "overview" | "billing"
  >("overview");
  const [elizaCloudLoginBusy, setElizaCloudLoginBusy] = useState(false);
  const [elizaCloudLoginError, setElizaCloudLoginError] = useState<
    string | null
  >(null);
  const cloudLoginUiStateRef = useRef({
    connected: elizaCloudConnected,
    error: elizaCloudLoginError,
    userId: elizaCloudUserId,
  });
  // Preserve identity while React catches up to an explicitly published login
  // snapshot. Rollback uses that identity as its exact UI ownership receipt.
  if (
    cloudLoginUiStateRef.current.connected !== elizaCloudConnected ||
    cloudLoginUiStateRef.current.error !== elizaCloudLoginError ||
    cloudLoginUiStateRef.current.userId !== elizaCloudUserId
  ) {
    cloudLoginUiStateRef.current = {
      connected: elizaCloudConnected,
      error: elizaCloudLoginError,
      userId: elizaCloudUserId,
    };
  }
  /**
   * Verification URL returned by `POST /api/cloud/login`, shown to the user
   * as a manual fallback while the device-code flow is awaiting completion.
   *
   * The renderer also tries to open this URL automatically via
   * `openExternalUrl()` (Capacitor / Electrobun / window.open), but on some
   * desktops the system handler is wired to a browser that silently fails
   * to surface a window — e.g. Tails routes `xdg-open` through gtk-launch
   * to the Tor Browser flatpak, and if Tor has not bootstrapped yet the
   * browser hangs on its splash screen with no visible feedback in the
   * renderer. Always exposing the URL as a copyable link lets the user
   * complete sign-in on any device with internet access, matching the
   * standard OAuth device-code UX (gh auth login, npm login, stripe login).
   *
   * Set to a string when the cloud-login session is created, cleared when
   * polling stops (authenticated, errored, timed out, or user cancelled).
   */
  const [elizaCloudLoginFallbackUrl, setElizaCloudLoginFallbackUrl] = useState<
    string | null
  >(null);
  const [elizaCloudDisconnecting, setElizaCloudDisconnecting] = useState(false);

  // ── Refs ───────────────────────────────────────────────────────────

  /** Recurring interval that polls cloud credits every 60s while connected. */
  const elizaCloudPollInterval = useRef<number | null>(null);
  /** While true, ignore stale poll results (in-flight GETs may predate POST /api/cloud/disconnect). */
  const elizaCloudDisconnectInFlightRef = useRef(false);
  /**
   * After the user disconnects, keep the "Connect Eliza Cloud" screen until they start
   * login again, even if GET /api/cloud/status still reports `connected: true` (laggy
   * snapshot or proxy mismatch).
   */
  const elizaCloudPreferDisconnectedUntilLoginRef = useRef(false);
  /** Last `connected` applied by pollCloudCredits; used when a poll is skipped mid-flight. */
  const lastElizaCloudPollConnectedRef = useRef(false);
  /** Short-lived polling interval used during the browser-based login flow. */
  const elizaCloudLoginPollTimer = useRef<number | null>(null);
  const elizaCloudLoginCompletionRef = useRef<Promise<void> | null>(null);
  /** Synchronous lock to prevent duplicate login clicks in the same tick. */
  const elizaCloudLoginBusyRef = useRef(false);
  /** Tracks whether the auth-rejected notice has already been sent for the current rejection. */
  const elizaCloudAuthNoticeSentRef = useRef(false);
  /** Exact credential/generation which produced the currently displayed account. */
  const verifiedCloudAccountAuthorityRef = useRef<{
    sessionGeneration: string | null;
    stewardToken: string;
    userId: string;
  } | null>(null);

  // ── Callbacks ──────────────────────────────────────────────────────

  async function runCloudPoll(
    intent: PollIntent = "ambient",
    validateAuthority: () => boolean = () => true,
  ): Promise<boolean> {
    if (!validateAuthority()) return lastElizaCloudPollConnectedRef.current;
    const pollToken = getCloudAuthToken(client);
    const pollRecovery = readStewardSessionRecovery(
      configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
    );
    if (!pollRecovery.storageAvailable || pollRecovery.receipts.length > 0) {
      return lastElizaCloudPollConnectedRef.current;
    }
    const buildPinnedRemoteApiBase = getBuildConfiguredRemoteApiBaseUrl();
    if (intent === "ambient" && !canPollCloudStatus()) {
      if (elizaCloudPollInterval.current) {
        clearInterval(elizaCloudPollInterval.current);
        elizaCloudPollInterval.current = null;
      }
      return lastElizaCloudPollConnectedRef.current;
    }
    if (elizaCloudDisconnectInFlightRef.current || !validateAuthority()) {
      return lastElizaCloudPollConnectedRef.current;
    }

    let cloudStatus: CloudStatus | null;
    let prefetchedCloudCredits: CloudCredits | null | undefined;
    if (intent === "session-verification" && buildPinnedRemoteApiBase) {
      const stewardToken = readStoredStewardToken()?.trim();
      const cloudApiBase =
        getBootConfig().cloudApiBase?.trim() || DEFAULT_DIRECT_CLOUD_BASE_URL;
      if (!stewardToken) return false;
      const verification = await verifyDirectCloudStewardSession({
        cloudApiBase,
        stewardToken,
      }).catch((err: unknown) => {
        logger.warn(
          { err },
          "[useCloudState] direct Cloud session verification failed",
        );
        throw new CloudSessionVerificationTransientError(err);
      });
      cloudStatus = verification.status;
      prefetchedCloudCredits = verification.credits;
    } else {
      // error-policy:J4 transient poll failure degrades to the last known
      // snapshot (below) rather than flapping the UI into a false "disconnected"
      // state; a persistent failure surfaces via that stale-but-visible state.
      cloudStatus = await client.getCloudStatus().catch(() => null);
    }
    if (elizaCloudDisconnectInFlightRef.current) {
      return lastElizaCloudPollConnectedRef.current;
    }
    if (!cloudStatus) {
      return lastElizaCloudPollConnectedRef.current;
    }
    const currentRecovery = readStewardSessionRecovery(
      configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
    );
    const pollAuthorityIsCurrent = () => {
      const latestRecovery = readStewardSessionRecovery(
        configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
      );
      return (
        getCloudAuthToken(client) === pollToken &&
        validateAuthority() &&
        pollRecovery.storageAvailable &&
        pollRecovery.receipts.length === 0 &&
        latestRecovery.storageAvailable &&
        latestRecovery.generation === pollRecovery.generation &&
        latestRecovery.receipts.length === 0
      );
    };
    if (!currentRecovery.storageAvailable || !pollAuthorityIsCurrent()) {
      return lastElizaCloudPollConnectedRef.current;
    }
    const enabled = Boolean(cloudStatus.enabled ?? false);
    const cloudVoiceProxyAvailable = Boolean(
      cloudStatus.cloudVoiceProxyAvailable ?? false,
    );
    const hasPersistedApiKey = Boolean(cloudStatus.hasApiKey);
    // Trust `connected` from the server snapshot (it already folds in API key + CLOUD_AUTH).
    const isConnected = Boolean(cloudStatus.connected);
    if (isConnected && elizaCloudPreferDisconnectedUntilLoginRef.current) {
      if (
        !publishElizaCloudVoiceSnapshot(
          setElizaCloudHasPersistedKey,
          {
            apiConnected: isConnected,
            enabled,
            cloudVoiceProxyAvailable,
            hasPersistedApiKey,
          },
          pollAuthorityIsCurrent,
        )
      ) {
        return lastElizaCloudPollConnectedRef.current;
      }
      lastElizaCloudPollConnectedRef.current = false;
      return false;
    }
    if (!isConnected) {
      elizaCloudPreferDisconnectedUntilLoginRef.current = false;
    }
    let creditsFetchError: string | null = null;
    let credits: CloudCredits | null | undefined;
    if (isConnected) {
      // error-policy:J4 a transport failure fetching credits degrades to null
      // (no fabricated balance) but is carried into the visible credits-error
      // state below — the balance widget renders a real error, never
      // healthy-empty; the next poll interval retries.
      credits =
        prefetchedCloudCredits !== undefined
          ? prefetchedCloudCredits
          : await client.getCloudCredits().catch((err: unknown) => {
              creditsFetchError =
                err instanceof Error ? err.message : String(err);
              logger.warn(
                { err },
                "[useCloudState] cloud credits fetch failed",
              );
              return null;
            });
      if (
        elizaCloudDisconnectInFlightRef.current ||
        !pollAuthorityIsCurrent()
      ) {
        return lastElizaCloudPollConnectedRef.current;
      }
    }
    // Status and credits are collected before any account-A UI/event is
    // exposed. A newer login that starts during the final network await can
    // therefore discard the whole snapshot instead of leaving stale A state.
    if (
      !publishElizaCloudVoiceSnapshot(
        setElizaCloudHasPersistedKey,
        {
          apiConnected: isConnected,
          enabled,
          cloudVoiceProxyAvailable,
          hasPersistedApiKey,
        },
        pollAuthorityIsCurrent,
      )
    ) {
      return lastElizaCloudPollConnectedRef.current;
    }
    if (isConnected && cloudStatus.userId && pollToken) {
      verifiedCloudAccountAuthorityRef.current = {
        sessionGeneration: pollRecovery.generation,
        stewardToken: pollToken,
        userId: cloudStatus.userId,
      };
    } else if (!isConnected) {
      verifiedCloudAccountAuthorityRef.current = null;
    }
    setElizaCloudEnabled(enabled);
    setElizaCloudVoiceProxyAvailable(cloudVoiceProxyAvailable);
    setElizaCloudConnected(isConnected);
    setElizaCloudUserId(cloudStatus.userId ?? null);
    setElizaCloudStatusReason(
      isConnected &&
        typeof cloudStatus.reason === "string" &&
        cloudStatus.reason.trim()
        ? cloudStatus.reason.trim()
        : null,
    );
    if (cloudStatus.topUpUrl) setElizaCloudTopUpUrl(cloudStatus.topUpUrl);
    if (isConnected) {
      if (credits?.authRejected) {
        setElizaCloudAuthRejected(true);
        setElizaCloudCreditsError(null);
        setElizaCloudCredits(null);
        setElizaCloudCreditsLow(false);
        setElizaCloudCreditsCritical(false);
        if (credits.topUpUrl) setElizaCloudTopUpUrl(credits.topUpUrl);
      } else {
        setElizaCloudAuthRejected(false);
        const apiErr =
          credits &&
          typeof credits.error === "string" &&
          credits.error.trim() &&
          typeof credits.balance !== "number"
            ? credits.error.trim()
            : creditsFetchError;
        setElizaCloudCreditsError(apiErr);
        if (credits && typeof credits.balance === "number") {
          setElizaCloudCredits(credits.balance);
          setElizaCloudCreditsLow(credits.low ?? false);
          setElizaCloudCreditsCritical(credits.critical ?? false);
          if (credits.topUpUrl) setElizaCloudTopUpUrl(credits.topUpUrl);
        } else {
          setElizaCloudCredits(null);
          setElizaCloudCreditsLow(false);
          setElizaCloudCreditsCritical(false);
          if (credits?.topUpUrl) setElizaCloudTopUpUrl(credits.topUpUrl);
        }
      }
    } else {
      setElizaCloudCredits(null);
      setElizaCloudCreditsLow(false);
      setElizaCloudCreditsCritical(false);
      setElizaCloudAuthRejected(false);
      setElizaCloudCreditsError(null);
      setElizaCloudStatusReason(null);
    }
    lastElizaCloudPollConnectedRef.current = isConnected;
    // Self-manage the recurring poll interval: start when connected, stop when not.
    // A build-pinned remote may verify a deliberate login against the Cloud
    // control plane, but must never turn that one request into ambient polling.
    const canScheduleAmbientPolling = canPollCloudStatus();
    if (
      isConnected &&
      canScheduleAmbientPolling &&
      !elizaCloudPollInterval.current
    ) {
      elizaCloudPollInterval.current = window.setInterval(() => {
        if (
          typeof document !== "undefined" &&
          document.visibilityState !== "visible"
        ) {
          return;
        }
        void runCloudPoll();
      }, 60_000);
    } else if (
      (!isConnected || !canScheduleAmbientPolling) &&
      elizaCloudPollInterval.current
    ) {
      clearInterval(elizaCloudPollInterval.current);
      elizaCloudPollInterval.current = null;
    }
    return isConnected;
  }
  const pollCloudCredits = useCallback(runCloudPoll, []);

  const reconcileAndroidCloudSession = useCallback(
    async (cloudApiBase?: string): Promise<boolean> => {
      const token = readStoredStewardToken()?.trim();
      if (!token) return false;
      const sessionAuthority = captureExactCloudSessionAuthority(token);
      if (!sessionAuthority?.isCurrent()) return false;
      const authenticatedCloudApiBase = resolveDirectCloudAuthApiBase(
        cloudApiBase ??
          getBootConfig().cloudApiBase ??
          DEFAULT_DIRECT_CLOUD_BASE_URL,
      );
      const previousBootConfig = getBootConfig();
      const publishedBootConfig = {
        ...getBootConfig(),
        cloudApiBase: authenticatedCloudApiBase,
      };
      setBootConfig(publishedBootConfig);
      let clientTargetAuthority: SessionTargetAuthority | null = null;
      const restorePublishedTarget = () => {
        clientTargetAuthority?.restoreIfCurrent();
        if (getBootConfig() === publishedBootConfig) {
          setBootConfig(previousBootConfig);
        }
      };
      if (!getBuildConfiguredRemoteApiBaseUrl()) {
        clientTargetAuthority = client.stageSessionTarget(
          { baseUrl: authenticatedCloudApiBase, token },
          { persist: false },
        );
        if (
          !clientTargetAuthority ||
          !sessionAuthority.isCurrent() ||
          !clientTargetAuthority.publish()
        ) {
          restorePublishedTarget();
          return false;
        }
      }
      if (!sessionAuthority.isCurrent()) {
        restorePublishedTarget();
        return false;
      }
      try {
        await loadWalletConfig();
      } catch (err) {
        // error-policy:J4 Cloud auth is already durable at this boundary;
        // an unavailable wallet panel stays independently observable and must
        // not roll back or disguise the authenticated agent session.
        logger.warn(
          { err },
          "[useCloudState] wallet config unavailable after Cloud auth",
        );
      }
      if (!sessionAuthority.isCurrent()) {
        restorePublishedTarget();
        return false;
      }
      const connected = await pollCloudCredits(
        "session-verification",
        sessionAuthority.isCurrent,
      );
      if (!sessionAuthority.isCurrent()) {
        restorePublishedTarget();
        return false;
      }
      if (!connected) return false;
      setElizaCloudConnected(true);
      setElizaCloudLoginError(null);
      return true;
    },
    [loadWalletConfig, pollCloudCredits],
  );

  useEffect(() => {
    if (!isAndroidCloudBuild() || !Capacitor.isNativePlatform()) return;
    let cancelled = false;

    const reconcile = async (apiBase?: string) => {
      const expectedToken = readStoredStewardToken()?.trim() || null;
      const continuationAuthority = expectedToken
        ? captureExactCloudSessionAuthority(expectedToken)
        : null;
      try {
        const connected = await reconcileAndroidCloudSession(apiBase);
        if (!cancelled && !connected && continuationAuthority?.isCurrent()) {
          setElizaCloudLoginError(
            "Could not verify your Eliza Cloud session. Please sign in again.",
          );
        }
      } catch (err) {
        // error-policy:J4 designed degrade — a transient Android session probe
        // retains the credential and becomes an explicit user-visible retry.
        logger.warn(
          { err },
          "[useCloudState] Android Cloud session reconciliation failed",
        );
        if (!cancelled && continuationAuthority?.isCurrent()) {
          setElizaCloudLoginError(
            err instanceof CloudSessionVerificationTransientError
              ? CLOUD_SESSION_VERIFICATION_TRANSIENT_MESSAGE
              : "Could not verify your Eliza Cloud session. Retry in a moment.",
          );
        }
      }
    };
    const onResult = (event: Event) => {
      const result = (event as CustomEvent<AndroidCloudAuthResult>).detail;
      if (result?.ok) void reconcile(result.apiBase);
    };
    window.addEventListener(ANDROID_CLOUD_AUTH_RESULT_EVENT, onResult);

    const completion = takeLatestAndroidCloudCompletion();
    if (completion) {
      void reconcile(completion.apiBase);
    } else if (readStoredStewardToken()?.trim()) {
      void reconcile();
    }

    return () => {
      cancelled = true;
      window.removeEventListener(ANDROID_CLOUD_AUTH_RESULT_EVENT, onResult);
    };
  }, [reconcileAndroidCloudSession]);

  const handleCloudLogin = useCallback(
    async (
      prePoppedWindow: Window | null = null,
      options: CloudLoginOptions = {},
    ) => {
      rememberCloudLoginPopup(prePoppedWindow);
      const closePrePoppedWindow = (validateDelayedClose?: () => boolean) => {
        closeCloudLoginPopup(prePoppedWindow, validateDelayedClose);
      };
      let cloudAuthMessageHandler: ((event: MessageEvent) => void) | null =
        null;
      const removeCloudAuthMessageListener = () => {
        if (cloudAuthMessageHandler && typeof window !== "undefined") {
          window.removeEventListener("message", cloudAuthMessageHandler);
          cloudAuthMessageHandler = null;
        }
      };

      // A server-side API key is enough for Settings/credits, but onboarding
      // needs a renderer-held bearer for direct agent discovery/provisioning.
      // Only callers that declare that stronger requirement bypass the normal
      // connected-server short-circuits below.
      const hasRequiredClientAuth = () =>
        !options.requireClientAuth || Boolean(getCloudAuthToken(client));
      if (
        !options.forceReauth &&
        isCloudStatusAuthenticated(
          elizaCloudConnected,
          elizaCloudStatusReason,
        ) &&
        hasRequiredClientAuth()
      ) {
        closePrePoppedWindow();
        return;
      }
      if (elizaCloudLoginBusyRef.current || elizaCloudLoginBusy) {
        closePrePoppedWindow();
        await elizaCloudLoginCompletionRef.current;
        return;
      }
      elizaCloudLoginBusyRef.current = true;
      setElizaCloudLoginBusy(true);
      setElizaCloudLoginError(null);
      setElizaCloudLoginFallbackUrl(null);
      elizaCloudPreferDisconnectedUntilLoginRef.current = false;
      if (options.forceReauth) {
        // An opaque device-code credential has no local expiry metadata, so it
        // normally counts as usable. Once Cloud rejects it, however, retaining
        // it would let both the cached-status and Steward-token branches
        // resolve without opening a real sign-in, then reload into the same
        // rejected session. Drain only the canonical Cloud credential here;
        // `client` may hold the separate agent bearer needed by the proxy.
        const rejectedToken = readStoredStewardToken()?.trim();
        if (rejectedToken) {
          await clearStoredStewardTokenIfUnchanged(rejectedToken);
        }
      }
      let resolveLoginCompletion: () => void = () => {};
      let loginCompletionResolved = false;
      const loginCompletion = new Promise<void>((resolve) => {
        resolveLoginCompletion = resolve;
      });
      const completeLogin = () => {
        if (loginCompletionResolved) return;
        loginCompletionResolved = true;
        if (elizaCloudLoginCompletionRef.current === loginCompletion) {
          elizaCloudLoginCompletionRef.current = null;
        }
        resolveLoginCompletion();
      };
      elizaCloudLoginCompletionRef.current = loginCompletion;
      let deviceCodeRecoveryReceipt: StewardSessionRecoveryReceipt | null =
        null;
      let deviceCodeRecoveryIsCurrent: (() => boolean) | null = null;
      const finishSupersededDeviceCodeAttempt = () => {
        removeCloudAuthMessageListener();
        if (elizaCloudLoginCompletionRef.current === loginCompletion) {
          elizaCloudLoginBusyRef.current = false;
          setElizaCloudLoginBusy(false);
        }
        completeLogin();
      };

      // The Play build uses the same canonical first-run chat and full app as
      // every other platform. Only its hosted PKCE handoff is Android-specific:
      // the verifier stays in Keystore, the hosted Eliza Cloud page owns the
      // provider chooser, and the deep-link callback publishes the result back
      // into this already-mounted state machine.
      if (isAndroidCloudBuild() && Capacitor.isNativePlatform()) {
        const cloudApiBase =
          getBootConfig().cloudApiBase ?? DEFAULT_DIRECT_CLOUD_BASE_URL;
        let androidLoginError: unknown = null;
        let removeResultListener = () => {};
        let removeBrowserFinishedListener = async () => {};
        let browserFinishTimer: number | null = null;
        let authTimeoutTimer: number | null = null;
        let callbackIsRetrying = false;
        let callbackStarted = false;
        let attemptId: string | null = null;
        let removeCallbackStartedListener = () => {};
        try {
          let resolveAuthResult: (result: AndroidCloudAuthResult) => void =
            () => {};
          const authResult = new Promise<AndroidCloudAuthResult>((resolve) => {
            resolveAuthResult = resolve;
            const onResult = (event: Event) => {
              const result = (event as CustomEvent<AndroidCloudAuthResult>)
                .detail;
              if (!result || result.attemptId !== attemptId) return;
              if (result.retryable) {
                callbackIsRetrying = true;
                setElizaCloudLoginError(
                  result.error ??
                    "Eliza Cloud sign-in was interrupted and is retrying.",
                );
                return;
              }
              resolve(result);
            };
            window.addEventListener(ANDROID_CLOUD_AUTH_RESULT_EVENT, onResult);
            removeResultListener = () =>
              window.removeEventListener(
                ANDROID_CLOUD_AUTH_RESULT_EVENT,
                onResult,
              );
          });
          const attempt = await beginAndroidCloudSignIn(cloudApiBase, {
            switchAccount: isAndroidCloudAccountSwitchPending(),
          });
          attemptId = attempt.state;
          if (isAndroidLauncherBuild()) {
            if (!navigateAndroidCloudSignInInApp(attempt.browserUrl)) {
              await cancelAndroidCloudSignIn(attempt.state);
              throw new Error("Eliza Cloud returned an invalid sign-in URL.");
            }
            // Navigation replaces this renderer. Native code restores the
            // bundled shell before replaying the protected callback.
            return loginCompletion;
          }
          const onCallbackStarted = (event: Event) => {
            const startedAttemptId = (
              event as CustomEvent<{ attemptId?: string }>
            ).detail?.attemptId;
            if (startedAttemptId === attemptId) callbackStarted = true;
          };
          window.addEventListener(
            ANDROID_CLOUD_AUTH_STARTED_EVENT,
            onCallbackStarted,
          );
          removeCallbackStartedListener = () =>
            window.removeEventListener(
              ANDROID_CLOUD_AUTH_STARTED_EVENT,
              onCallbackStarted,
            );
          removeBrowserFinishedListener =
            await listenForExternalBrowserFinished(() => {
              if (browserFinishTimer !== null) return;
              browserFinishTimer = window.setTimeout(() => {
                browserFinishTimer = null;
                if (callbackStarted || callbackIsRetrying || !attemptId) return;
                resolveAuthResult({
                  attemptId,
                  error: "Eliza Cloud sign-in was cancelled.",
                  ok: false,
                });
              }, ANDROID_CLOUD_BROWSER_FINISH_GRACE_MS);
            });
          authTimeoutTimer = window.setTimeout(() => {
            if (!attemptId) return;
            resolveAuthResult({
              attemptId,
              error: "Eliza Cloud sign-in timed out. Please try again.",
              ok: false,
            });
          }, ANDROID_CLOUD_AUTH_TIMEOUT_MS);
          const opened = await openExternalUrl(attempt.browserUrl);
          if (!opened) {
            await cancelAndroidCloudSignIn(attempt.state);
            throw new Error("Couldn't open Eliza Cloud sign-in.");
          }
          const result = await authResult;
          if (!result.ok) {
            await cancelAndroidCloudSignIn(attempt.state);
            throw new Error(
              result.error ?? "Eliza Cloud sign-in could not be completed.",
            );
          }
          const connected = await reconcileAndroidCloudSession(
            result.apiBase ?? cloudApiBase,
          );
          if (!connected) {
            throw new Error(
              "Could not verify your Eliza Cloud session. Please sign in again.",
            );
          }
          try {
            clearAndroidCloudAccountSwitchPending();
          } catch (error) {
            // error-policy:J4 the replacement session is already verified;
            // retaining this non-secret marker only forces another explicit
            // account choice on a future login instead of weakening auth.
            logger.warn(
              { error },
              "[useCloudState] Could not clear Android account-switch marker",
            );
          }
        } catch (error) {
          androidLoginError = error;
          setElizaCloudLoginError(
            error instanceof Error ? error.message : "Eliza Cloud login failed",
          );
        } finally {
          if (browserFinishTimer !== null) {
            window.clearTimeout(browserFinishTimer);
          }
          if (authTimeoutTimer !== null) window.clearTimeout(authTimeoutTimer);
          removeResultListener();
          removeCallbackStartedListener();
          void removeBrowserFinishedListener();
          void closeExternalBrowser();
          closePrePoppedWindow();
          elizaCloudLoginBusyRef.current = false;
          setElizaCloudLoginBusy(false);
          completeLogin();
        }
        // First-run and native recovery explicitly require a renderer-held
        // credential before they can continue. Preserve the rejected promise
        // at that boundary so their existing in-chat/recovery error surfaces
        // replace the waiting state instead of treating a failed handoff as a
        // completed login with no token.
        if (androidLoginError && options.requireClientAuth) {
          throw androidLoginError;
        }
        return loginCompletion;
      }

      // Zero-interaction wallet SIWE (#13377) is the E2E HARNESS path ONLY.
      // A real browser wallet (Phantom, MetaMask, …) injects window.ethereum
      // too, so taking this branch for any injected provider auto-pops the
      // user's wallet the instant they click "Sign in with Eliza Cloud" —
      // even when they meant to pick Google — and leaves the pre-opened
      // popup blank (the "white page"). Real wallet sign-in is an EXPLICIT
      // choice behind the /login page's EVM/Solana buttons; only the harness
      // wallet (isElizaE2eWallet, packages/ui/src/platform/e2e-wallet.ts, which
      // by its own gates never installs on deployed web) may sign in headlessly.
      if (
        !hasUsableStoredStewardToken() &&
        getInjectedEthereumProvider()?.isElizaE2eWallet === true
      ) {
        const siweBase = getBootConfig().cloudApiBase ?? "https://eliza.app";
        try {
          const committedSiwe =
            await siweLoginWithInjectedWalletAuthority(siweBase);
          if (committedSiwe) {
            const finishSupersededSiweLogin = () => {
              elizaCloudLoginBusyRef.current = false;
              setElizaCloudLoginBusy(false);
              completeLogin();
              return loginCompletion;
            };
            if (!committedSiwe.authority.isCurrent()) {
              return finishSupersededSiweLogin();
            }
            closePrePoppedWindow(committedSiwe.authority.isCurrent);
            if (!committedSiwe.authority.isCurrent()) {
              return finishSupersededSiweLogin();
            }
            const connected = await pollCloudCredits(
              "session-verification",
              committedSiwe.authority.isCurrent,
            );
            if (!committedSiwe.authority.isCurrent()) {
              return finishSupersededSiweLogin();
            }
            // error-policy:J4 wallet config is a secondary panel; a failed
            // load must not undo a verified login.
            await loadWalletConfig().catch(() => undefined);
            if (!committedSiwe.authority.isCurrent()) {
              return finishSupersededSiweLogin();
            }
            if (connected) {
              setElizaCloudConnected(true);
              setElizaCloudLoginError(null);
            } else {
              setElizaCloudLoginError(
                "Could not verify your Eliza Cloud session. Please sign in again.",
              );
            }
            if (!committedSiwe.authority.isCurrent()) {
              return finishSupersededSiweLogin();
            }
            elizaCloudLoginBusyRef.current = false;
            setElizaCloudLoginBusy(false);
            completeLogin();
            return loginCompletion;
          }
        } catch (err) {
          // error-policy:J4 a declined/failed wallet handshake is a designed
          // degrade — the Steward / device-code paths below remain this
          // click's way in; the failure is logged for the harness.
          logger.warn(
            { err },
            "[useCloudState] SIWE wallet login failed; falling through",
          );
        }
      }

      // Cloud = Steward where the current surface can complete it. When the
      // shell-router has mounted the Steward provider it registers a launcher;
      // web/desktop can drive the in-app Steward sign-in (passkey / email /
      // OAuth / wallet) instead of the legacy device-code browser window.
      // Capacitor native cannot use Steward's browser WebAuthn surface without
      // a native bridge, so native only takes this branch for a still-usable
      // stored token and otherwise falls through to the external device-code
      // flow.
      //
      // Only take this branch when it can complete on THIS click: a still-usable
      // stored token (launchStewardLogin short-circuits on it) or a mounted
      // launcher. A stored-but-EXPIRED JWT with no launcher mounted used to
      // enter the branch anyway; launchStewardLogin drained the stale token and
      // then threw "the Steward login surface is not mounted", so the first
      // click dead-ended on an error and only the second click (token now gone)
      // reached the working device-code flow. Instead, drain the stale token
      // below and fall through to the device-code flow on the same click.
      if (canUseMountedStewardLoginSurface()) {
        let fallThroughToLegacyLogin = false;
        try {
          const reusedStoredCredential = hasUsableStoredStewardToken();
          if (!reusedStoredCredential) closePrePoppedWindow();
          let stewardLogin = await launchStewardLogin();
          if (!stewardLogin.authority.isCurrent()) return loginCompletion;
          let stewardLoginRecovery = readStewardSessionRecovery(
            configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
          );
          const stewardRecoveryIsCurrent = () => {
            const current = readStewardSessionRecovery(
              configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
            );
            return (
              stewardLoginRecovery.storageAvailable &&
              stewardLoginRecovery.receipts.length === 0 &&
              current.storageAvailable &&
              current.generation === stewardLoginRecovery.generation &&
              current.receipts.length === 0
            );
          };
          // Gate the connected state + success toast on an ACTUAL authed status
          // call. `launchStewardLogin` short-circuits on a stored token; if that
          // token is stale/revoked the status poll reports disconnected, so
          // declaring "connected" + toasting here would be a false success that
          // 401s the agent picker in a loop. Only celebrate a verified session;
          // otherwise surface the re-auth path the login UI already renders.
          let connected = await pollCloudCredits(
            "session-verification",
            stewardLogin.authority.isCurrent,
          );
          // A direct identity 401 clears only the exact rejected Steward
          // credential. When launchStewardLogin reused that credential, invoke
          // the mounted sign-in surface now and verify the replacement on this
          // same click instead of making the button appear inert.
          if (
            !connected &&
            reusedStoredCredential &&
            !readStoredStewardToken()?.trim()
          ) {
            if (hasStewardLoginLauncher()) {
              closePrePoppedWindow();
              stewardLogin = await launchStewardLogin();
              if (!stewardLogin.authority.isCurrent()) return loginCompletion;
              stewardLoginRecovery = readStewardSessionRecovery(
                configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
              );
              connected = await pollCloudCredits(
                "session-verification",
                stewardLogin.authority.isCurrent,
              );
            } else {
              // The opaque token was the only reason this branch was usable.
              // With it authoritatively rejected and no in-app provider,
              // preserve the prepared popup and continue into device-code
              // login below instead of requiring a second click.
              fallThroughToLegacyLogin = true;
            }
          }
          if (!fallThroughToLegacyLogin) {
            // A direct 401/403 clears the exact rejected token. That expected
            // token loss makes the token-based authority false, but it is not
            // a superseding login while the captured recovery generation is
            // still clean. Finish the rejected-session UI in that narrow case;
            // a concurrently planted receipt still suppresses every A effect.
            if (
              !connected &&
              !readStoredStewardToken()?.trim() &&
              stewardRecoveryIsCurrent()
            ) {
              closePrePoppedWindow(stewardRecoveryIsCurrent);
              if (!stewardRecoveryIsCurrent()) return loginCompletion;
              setElizaCloudConnected(false);
              setElizaCloudLoginError(
                "Could not verify your Eliza Cloud session. Please sign in again.",
              );
              return loginCompletion;
            }
            if (!stewardLogin.authority.isCurrent()) return loginCompletion;
            closePrePoppedWindow(stewardLogin.authority.isCurrent);
            if (!stewardLogin.authority.isCurrent()) return loginCompletion;
            // error-policy:J4 wallet config is a secondary panel; a failed
            // load must not undo a verified login. The wallet section renders
            // its own unavailable state from the empty config.
            await loadWalletConfig().catch(() => undefined);
            if (!stewardLogin.authority.isCurrent()) return loginCompletion;
            if (connected) {
              setElizaCloudConnected(true);
              setElizaCloudLoginError(null);
            } else {
              setElizaCloudLoginError(
                "Could not verify your Eliza Cloud session. Please sign in again.",
              );
            }
          }
        } catch (err) {
          setElizaCloudLoginError(
            err instanceof CloudSessionVerificationTransientError
              ? CLOUD_SESSION_VERIFICATION_TRANSIENT_MESSAGE
              : err instanceof Error
                ? err.message
                : "Eliza Cloud login failed",
          );
          if (
            options.requireClientAuth &&
            err instanceof CloudSessionVerificationTransientError
          ) {
            throw err;
          }
        } finally {
          if (!fallThroughToLegacyLogin) {
            elizaCloudLoginBusyRef.current = false;
            setElizaCloudLoginBusy(false);
            completeLogin();
          }
        }
        if (!fallThroughToLegacyLogin) return loginCompletion;
      }

      // A stored-but-stale Steward JWT with no launcher mounted: drain it so it
      // cannot shadow the device-code credentials in subsequent authed calls.
      // `hasUsableStoredStewardToken` also returns false for a usable account-A
      // token quarantined behind login B, however; only a provably clean
      // recovery snapshot permits treating the value as stale and deleting it.
      const staleStewardToken = readStoredStewardToken()?.trim();
      const recoveryBeforeLegacyLogin = readStewardSessionRecovery(
        configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
      );
      if (
        staleStewardToken &&
        recoveryBeforeLegacyLogin.storageAvailable &&
        recoveryBeforeLegacyLogin.receipts.length === 0
      ) {
        await clearStoredStewardTokenIfUnchanged(staleStewardToken);
      }

      // Legacy device-code fallback (retired for Cloud; preserved for the
      // Remote / self-hosted pairing handshake and for desktop/CLI builds where
      // the Steward surface is not yet mounted). Determine if we should use
      // direct cloud auth (no local backend) or go through the agent proxy.
      const hasBackend = hasCloudLoginBackend();
      const cloudApiBase = getBootConfig().cloudApiBase ?? "https://eliza.app";
      const usesHostedLoopbackStagingSession =
        isLoopbackStagingStewardDevelopment();
      let useDirectAuth = !hasBackend || usesHostedLoopbackStagingSession;

      if (hasBackend) {
        const statusAuthority = captureExactCloudSessionAuthority();
        if (!statusAuthority?.isCurrent()) {
          elizaCloudLoginBusyRef.current = false;
          setElizaCloudLoginBusy(false);
          completeLogin();
          return loginCompletion;
        }
        // error-policy:J4 a null status here is a designed branch: a
        // browser/dev shell with no local agent proxy falls back to the direct
        // Cloud auth flow (below), not an error state.
        const cloudStatus = await client.getCloudStatus().catch(() => null);
        if (!statusAuthority.isCurrent()) {
          elizaCloudLoginBusyRef.current = false;
          setElizaCloudLoginBusy(false);
          completeLogin();
          return loginCompletion;
        }
        if (cloudStatus === null) {
          // Browser/dev shells can run on localhost without a local agent proxy.
          // In that case, keep first-run Cloud usable via the direct Cloud flow.
          useDirectAuth = true;
        }
        const alreadyAuthenticated = isCloudStatusAuthenticated(
          Boolean(cloudStatus?.connected),
          cloudStatus?.reason,
        );
        if (
          !options.forceReauth &&
          alreadyAuthenticated &&
          hasRequiredClientAuth() &&
          statusAuthority.isCurrent()
        ) {
          closePrePoppedWindow(statusAuthority.isCurrent);
          if (!statusAuthority.isCurrent()) return loginCompletion;
          await pollCloudCredits(
            "session-verification",
            statusAuthority.isCurrent,
          );
          if (!statusAuthority.isCurrent()) return loginCompletion;
          await loadWalletConfig().catch((err: unknown) => {
            // error-policy:J4 already-authenticated login has succeeded; a
            // wallet config refresh failure must not wedge the login button.
            logger.warn(
              { err },
              "[useCloudState] wallet config refresh failed after cloud login",
            );
          });
          if (!statusAuthority.isCurrent()) return loginCompletion;
          setElizaCloudLoginError(null);
          if (!statusAuthority.isCurrent()) return loginCompletion;
          setActionNotice("Already connected to Eliza Cloud.", "info", 4000);
          elizaCloudLoginBusyRef.current = false;
          setElizaCloudLoginBusy(false);
          completeLogin();
          return loginCompletion;
        }
      }
      const shouldBindClientToDirectCloud =
        useDirectAuth && !(usesHostedLoopbackStagingSession && hasBackend);

      // #15143 mobile-web sign-in: when the popup path cannot work — the
      // pre-opened handle came back null (popup blocked; the runtime signal on
      // any browser) or this is a touch-primary browser where even a popup
      // that opens is a disorienting tab switch — navigate THIS tab to the
      // same-origin Steward /login page instead of starting a device-code
      // session whose browser window would never open. The returnTo round
      // trip lands back here and the stored Steward token completes the login
      // (first-run resumes via its marker + mount-time token poll). Direct
      // cloud targets normally require direct auth: an agent-proxied
      // (hasBackend) login stays on the device-code flow, whose copyable
      // fallback link is the designed degrade for blocked popups there. The
      // Loopback staging is intentionally excluded: its tenant rejects a local
      // OAuth callback, so it uses the hosted CLI-session flow below. Production
      // and self-hosted agent proxies retain device-code auth because their
      // CORS/pairing contracts differ.
      if (
        shouldUseSameTabCloudLogin(prePoppedWindow, {
          hasAgentProxy: !useDirectAuth,
        })
      ) {
        closePrePoppedWindow();
        navigateToSameTabCloudLogin();
        elizaCloudLoginBusyRef.current = false;
        setElizaCloudLoginBusy(false);
        completeLogin();
        return loginCompletion;
      }

      try {
        // This intent predates every remote device-code dispatch below. A
        // newer tab's successful login records this receipt as preexisting and
        // retires it, so a delayed authenticated poll can no longer publish A
        // after B has become authoritative.
        const deviceCodeRecovery = beginCloudLoginAuthorityRecovery();
        deviceCodeRecoveryReceipt = deviceCodeRecovery;
        const validateDeviceCodeRecovery = () =>
          isStewardSessionRecoveryReceiptLive(deviceCodeRecovery);
        deviceCodeRecoveryIsCurrent = validateDeviceCodeRecovery;
        let resp: {
          ok: boolean;
          apiBase?: string;
          browserUrl?: string;
          sessionId?: string;
          error?: string;
        };
        if (useDirectAuth) {
          const prepared = takePreparedDesktopCloudLoginSession(cloudApiBase);
          resp = prepared
            ? await prepared
            : await client.cloudLoginDirect(cloudApiBase);
          if (!deviceCodeRecoveryIsCurrent()) {
            finishSupersededDeviceCodeAttempt();
            return loginCompletion;
          }
          // The warm-up is speculative. If it failed while the CTA was idle,
          // retry on the deliberate click instead of surfacing a stale result.
          if (prepared && !resp.ok) {
            resp = await client.cloudLoginDirect(cloudApiBase);
          }
        } else {
          resp = await client.cloudLogin();
        }
        if (!deviceCodeRecoveryIsCurrent()) {
          finishSupersededDeviceCodeAttempt();
          return loginCompletion;
        }
        if (!resp.ok) {
          closePrePoppedWindow(deviceCodeRecoveryIsCurrent);
          if (!deviceCodeRecoveryIsCurrent()) {
            finishSupersededDeviceCodeAttempt();
            return loginCompletion;
          }
          setElizaCloudLoginError(
            resp.error || "Failed to start Eliza Cloud login",
          );
          elizaCloudLoginBusyRef.current = false;
          setElizaCloudLoginBusy(false);
          completeLogin();
          rejectCloudLoginAuthorityRecovery(deviceCodeRecovery);
          return loginCompletion;
        }

        const sessionId = resp.sessionId ?? "";
        const authenticatedCloudApiBase =
          useDirectAuth && resp.apiBase ? resp.apiBase : cloudApiBase;
        if (sessionId && typeof window !== "undefined") {
          cloudAuthMessageHandler = (event: MessageEvent) => {
            if (!deviceCodeRecoveryIsCurrent?.()) return;
            if (
              !isTrustedCloudAuthMessageOrigin(
                event.origin,
                authenticatedCloudApiBase,
              )
            ) {
              return;
            }
            if (!isMatchingCloudAuthCompleteMessage(event.data, sessionId)) {
              return;
            }
            closePrePoppedWindow(deviceCodeRecoveryIsCurrent);
            if (!deviceCodeRecoveryIsCurrent()) return;
            void closeExternalBrowser();
          };
          window.addEventListener("message", cloudAuthMessageHandler);
        }

        // Open the login URL in the system browser. On Capacitor iOS the
        // pre-opened window preserves the user-gesture context so WKWebView
        // routes the URL out to Safari instead of dropping it silently.
        //
        // Regardless of whether the auto-open succeeds, expose the URL via
        // `elizaCloudLoginFallbackUrl` so the renderer can render a
        // copyable "didn't open? visit this link" panel. Some desktop
        // handlers (e.g. Tails' Tor Browser flatpak when Tor has not
        // bootstrapped, or any environment where xdg-open silently fails)
        // open without crashing but never surface a usable window.
        if (resp.browserUrl && isSafeNavigationUrl(resp.browserUrl)) {
          if (!deviceCodeRecoveryIsCurrent()) {
            finishSupersededDeviceCodeAttempt();
            return loginCompletion;
          }
          setElizaCloudLoginFallbackUrl(resp.browserUrl);
          // Popup-hostile localhost browsers carry this tab through hosted
          // staging auth. The opaque CLI session returns to localhost for the
          // mount-time poll below; Steward never receives localhost as its
          // OAuth redirect_uri.
          if (
            usesHostedLoopbackStagingSession &&
            (!prePoppedWindow || prePoppedWindow.closed)
          ) {
            if (!deviceCodeRecoveryIsCurrent()) {
              finishSupersededDeviceCodeAttempt();
              return loginCompletion;
            }
            window.location.assign(resp.browserUrl);
            elizaCloudLoginBusyRef.current = false;
            setElizaCloudLoginBusy(false);
            completeLogin();
            return loginCompletion;
          }
          // Electrobun's `window.open` is another renderer/WebView surface,
          // not the user's browser. Sending Cloud authentication there makes a
          // click appear to activate Eliza while no system login window opens.
          // Desktop owns external navigation through its native RPC instead.
          if (isElectrobunRuntime()) {
            const opened = await openExternalUrl(resp.browserUrl);
            if (!deviceCodeRecoveryIsCurrent()) {
              finishSupersededDeviceCodeAttempt();
              return loginCompletion;
            }
            if (!opened) {
              setElizaCloudLoginError(
                `Couldn't open the sign-in browser. Open this link to log in: ${resp.browserUrl}`,
              );
            }
          } else if (prePoppedWindow) {
            if (!deviceCodeRecoveryIsCurrent()) {
              finishSupersededDeviceCodeAttempt();
              return loginCompletion;
            }
            navigatePreOpenedWindow(prePoppedWindow, resp.browserUrl, {
              preserveOpener: true,
            });
          } else {
            if (!deviceCodeRecoveryIsCurrent()) {
              finishSupersededDeviceCodeAttempt();
              return loginCompletion;
            }
            const popup = openNamedCloudLoginPopup(resp.browserUrl);
            if (!popup) {
              try {
                await openExternalUrl(resp.browserUrl);
                if (!deviceCodeRecoveryIsCurrent()) {
                  finishSupersededDeviceCodeAttempt();
                  return loginCompletion;
                }
              } catch {
                if (!deviceCodeRecoveryIsCurrent()) {
                  finishSupersededDeviceCodeAttempt();
                  return loginCompletion;
                }
                // error-policy:J4 browser launch failed — degrade to a visible
                // copyable link so the user can complete login manually.
                setElizaCloudLoginError(
                  `Open this link to log in: ${resp.browserUrl}`,
                );
              }
            }
          }
        } else {
          closePrePoppedWindow(deviceCodeRecoveryIsCurrent);
          if (!deviceCodeRecoveryIsCurrent()) {
            finishSupersededDeviceCodeAttempt();
            return loginCompletion;
          }
          if (resp.browserUrl) {
            // The login URL is a wire value assigned to a same-origin
            // pre-opened popup / named window — a non-http(s) target fails
            // closed and tears the attempt down with a visible error, like a
            // failed login start.
            setElizaCloudLoginError(
              "The login link returned by the server is not a valid URL.",
            );
            removeCloudAuthMessageListener();
            elizaCloudLoginBusyRef.current = false;
            setElizaCloudLoginBusy(false);
            completeLogin();
            rejectCloudLoginAuthorityRecovery(deviceCodeRecovery);
            return loginCompletion;
          }
        }

        let pollInFlight = false;
        let consecutivePollErrors = 0;
        const pollDeadline = Date.now() + ELIZA_CLOUD_LOGIN_TIMEOUT_MS;
        let pollingTimer: number | null = null;
        const stopCloudLoginPolling = (
          error: string | null = null,
          disposition: "preserve" | "reject" = "preserve",
        ) => {
          const authorityCurrent = validateDeviceCodeRecovery();
          if (pollingTimer !== null) {
            const timer = pollingTimer;
            pollingTimer = null;
            clearInterval(timer);
            if (elizaCloudLoginPollTimer.current === timer) {
              elizaCloudLoginPollTimer.current = null;
            }
          }
          removeCloudAuthMessageListener();
          if (elizaCloudLoginCompletionRef.current === loginCompletion) {
            elizaCloudLoginBusyRef.current = false;
            setElizaCloudLoginBusy(false);
            // Clear the manual-link fallback once this exact device-code
            // session is no longer active. A newer login owns its own state.
            setElizaCloudLoginFallbackUrl(null);
            if (error !== null && authorityCurrent) {
              setElizaCloudLoginError(error);
            }
          }
          completeLogin();
          if (disposition === "reject" && authorityCurrent) {
            rejectCloudLoginAuthorityRecovery(deviceCodeRecovery);
          }
        };

        // Start polling
        pollingTimer = window.setInterval(async () => {
          if (!validateDeviceCodeRecovery()) {
            stopCloudLoginPolling();
            return;
          }
          if (
            pollingTimer === null ||
            elizaCloudLoginPollTimer.current !== pollingTimer ||
            pollInFlight
          ) {
            return;
          }

          pollInFlight = true;
          try {
            if (elizaCloudLoginPollTimer.current !== pollingTimer) {
              stopCloudLoginPolling();
              return;
            }
            let poll: {
              status: string;
              organizationId?: string;
              token?: string;
              userId?: string;
              error?: string;
            };
            if (useDirectAuth) {
              poll = await client.cloudLoginPollDirect(
                authenticatedCloudApiBase,
                sessionId,
              );
            } else {
              poll = await client.cloudLoginPoll(sessionId);
            }
            if (!validateDeviceCodeRecovery()) {
              stopCloudLoginPolling();
              return;
            }
            if (!elizaCloudLoginPollTimer.current) return;

            consecutivePollErrors = 0;
            if (poll.status === "authenticated") {
              if (useDirectAuth) {
                if (!poll.token) {
                  stopCloudLoginPolling(
                    "Eliza Cloud login completed, but the cloud session did not return a session token.",
                    "reject",
                  );
                  return;
                }
              }

              const committed = await commitCloudLoginAuthority(
                deviceCodeRecovery,
                async (validate, finalizeReceipt) => {
                  const bindsElectrobunPersonalAgent =
                    useDirectAuth &&
                    Boolean(poll.token) &&
                    isElectrobunRuntime();
                  const previousBootConfig = getBootConfig();
                  let tokenAuthority: StewardTokenWriteAuthority | null = null;
                  let bindingAuthority: DirectCloudBindingAuthority | null =
                    null;
                  let clientTargetAuthority: SessionTargetAuthority | null =
                    null;
                  let publishedBootConfig: ReturnType<
                    typeof getBootConfig
                  > | null = null;
                  let standaloneRecoveryRollback: StewardSessionRecoveryPublicationRollback | null =
                    null;
                  let uiPublished = false;
                  const previousUiState = cloudLoginUiStateRef.current;
                  let publishedUiState: typeof previousUiState | null = null;
                  const rollbackStagedPublication = (
                    durableRestored: boolean,
                  ) => {
                    const bootOwned =
                      publishedBootConfig !== null &&
                      getBootConfig() === publishedBootConfig;
                    let clientRolledBack = true;
                    if (clientTargetAuthority) {
                      clientRolledBack = durableRestored
                        ? clientTargetAuthority.restoreIfCurrent()
                        : clientTargetAuthority.clearIfCurrent();
                    }
                    if (bootOwned && clientRolledBack) {
                      setBootConfig(previousBootConfig);
                    }
                  };
                  const rollback = async () => {
                    try {
                      // Canonical and subordinate authorities settle before
                      // React can expose their predecessor.
                      await rollbackCloudLoginPublication({
                        bindingAuthority,
                        tokenAuthority,
                        clientTargetAuthority,
                        previousBootConfig,
                        publishedBootConfig,
                      });
                    } finally {
                      try {
                        if (
                          uiPublished &&
                          publishedUiState !== null &&
                          cloudLoginUiStateRef.current === publishedUiState
                        ) {
                          cloudLoginUiStateRef.current = previousUiState;
                          setElizaCloudConnected(previousUiState.connected);
                          setElizaCloudLoginError(previousUiState.error);
                          setElizaCloudUserId(previousUiState.userId);
                        }
                        uiPublished = false;
                      } finally {
                        standaloneRecoveryRollback?.(false);
                      }
                    }
                  };
                  try {
                    if (
                      poll.token &&
                      typeof window !== "undefined" &&
                      !bindsElectrobunPersonalAgent
                    ) {
                      const sessionToken = poll.token;
                      // Protected token, its API authority, and every dependent
                      // client target publish before this exact receipt retires.
                      tokenAuthority = await writeStoredStewardToken(
                        sessionToken,
                        {
                          validate,
                          finalizeBeforePublish: () => {
                            const rollbackReceipt = finalizeReceipt();
                            try {
                              if (shouldBindClientToDirectCloud) {
                                clientTargetAuthority =
                                  client.stageSessionTarget(
                                    {
                                      baseUrl: authenticatedCloudApiBase,
                                      token: sessionToken,
                                    },
                                    { persist: false },
                                  );
                                if (!clientTargetAuthority) {
                                  throw new Error(
                                    "The Cloud login token was rejected by the active client authority.",
                                  );
                                }
                              }
                              publishedBootConfig = {
                                ...getBootConfig(),
                                cloudApiBase: authenticatedCloudApiBase,
                              };
                              setBootConfig(publishedBootConfig);
                            } catch (error) {
                              try {
                                rollbackStagedPublication(false);
                              } finally {
                                rollbackReceipt(false);
                              }
                              throw error;
                            }
                            return (durableRestored) => {
                              try {
                                rollbackStagedPublication(durableRestored);
                              } finally {
                                rollbackReceipt(durableRestored);
                              }
                            };
                          },
                          commitBeforePublish: () => {
                            if (
                              clientTargetAuthority &&
                              !clientTargetAuthority.publish()
                            ) {
                              return false;
                            }
                            return validate();
                          },
                        },
                      );
                      if (!tokenAuthority || !validate()) {
                        await rollback();
                        return false;
                      }
                    }

                    if (useDirectAuth && poll.token) {
                      if (bindsElectrobunPersonalAgent) {
                        bindingAuthority =
                          await bindDirectCloudLoginToPersonalAgent({
                            client,
                            cloudApiBase: authenticatedCloudApiBase,
                            token: poll.token,
                            validate,
                            finalizeRecoveryBeforePublish: finalizeReceipt,
                            finalize: () => {
                              publishedBootConfig = {
                                ...getBootConfig(),
                                cloudApiBase: authenticatedCloudApiBase,
                              };
                              setBootConfig(publishedBootConfig);
                              return () => {
                                if (getBootConfig() === publishedBootConfig) {
                                  setBootConfig(previousBootConfig);
                                }
                              };
                            },
                          });
                        if (!bindingAuthority || !validate()) {
                          await rollback();
                          return false;
                        }
                      }
                    }
                    if (!useDirectAuth && !poll.token) {
                      // Agent-proxied device-code authentication legitimately
                      // returns no browser token. Its durable completion fence
                      // is therefore the UI/client publication itself rather
                      // than a canonical token write.
                      standaloneRecoveryRollback = finalizeReceipt();
                    }
                    if (!validate()) {
                      await rollback();
                      return false;
                    }
                    uiPublished = true;
                    publishedUiState = {
                      connected: true,
                      error: null,
                      userId: poll.userId ?? previousUiState.userId,
                    };
                    cloudLoginUiStateRef.current = publishedUiState;
                    setElizaCloudConnected(true);
                    setElizaCloudLoginError(null);
                    if (poll.userId) setElizaCloudUserId(poll.userId);
                    if (!validate()) {
                      await rollback();
                      return false;
                    }
                    return { restoreIfCurrent: rollback };
                  } catch (error) {
                    try {
                      await rollback();
                    } catch (rollbackError) {
                      throw new AggregateError(
                        [error, rollbackError],
                        "Cloud login publication and rollback both failed.",
                      );
                    }
                    throw error;
                  }
                },
              );
              if (
                !committed?.isCurrent() ||
                (poll.token !== undefined &&
                  readStoredStewardToken() !== poll.token)
              ) {
                await committed?.restoreIfCurrent();
                // A newer login already owns the origin. Stop this stale poll
                // without publishing its UI/account metadata.
                stopCloudLoginPolling();
                return;
              }

              const committedSessionIsCurrent = () =>
                committed.isCurrent() &&
                (poll.token === undefined ||
                  readStoredStewardToken() === poll.token);
              closePrePoppedWindow(committedSessionIsCurrent);
              if (!committedSessionIsCurrent()) {
                await committed.restoreIfCurrent();
                stopCloudLoginPolling();
                return;
              }
              void closeExternalBrowser();
              if (!committedSessionIsCurrent()) {
                await committed.restoreIfCurrent();
                stopCloudLoginPolling();
                return;
              }
              // Same-origin Cloud auth tabs (orphaned /login) dismiss via BC.
              // Cross-origin openers already advanced via this poll.
              if (sessionId) {
                publishCloudAuthComplete(sessionId);
              }
              if (!committedSessionIsCurrent()) {
                await committed.restoreIfCurrent();
                stopCloudLoginPolling();
                return;
              }
              try {
                window.focus();
              } catch (error) {
                void error;
                // error-policy:J6 focus is best-effort after auth return.
              }
              if (!committedSessionIsCurrent()) {
                await committed.restoreIfCurrent();
                stopCloudLoginPolling();
                return;
              }

              stopCloudLoginPolling();

              // The backend owns the cloud-wallet bind + runtime reload now.
              // Startup/ws recovery will rehydrate wallet + cloud state once the
              // restart completes, so avoid kicking off a second client restart.
            } else if (poll.status === "expired" || poll.status === "error") {
              stopCloudLoginPolling(
                poll.error ?? "Login session expired. Please try again.",
                "reject",
              );
            } else if (Date.now() >= pollDeadline) {
              stopCloudLoginPolling(
                "Eliza Cloud login timed out. Please try again.",
                "reject",
              );
            }
          } catch (pollErr) {
            if (elizaCloudLoginPollTimer.current !== pollingTimer) {
              stopCloudLoginPolling();
              return;
            }
            if (!validateDeviceCodeRecovery()) {
              stopCloudLoginPolling();
              return;
            }

            consecutivePollErrors += 1;
            if (
              consecutivePollErrors >= ELIZA_CLOUD_LOGIN_MAX_CONSECUTIVE_ERRORS
            ) {
              const detail =
                pollErr instanceof Error && pollErr.message
                  ? ` Last error: ${pollErr.message}`
                  : "";
              stopCloudLoginPolling(
                `Eliza Cloud login check failed after repeated errors.${detail}`,
                "reject",
              );
            }
          } finally {
            pollInFlight = false;
          }
        }, ELIZA_CLOUD_LOGIN_POLL_INTERVAL_MS);
        elizaCloudLoginPollTimer.current = pollingTimer;
      } catch (err) {
        const validateFailureAuthority =
          deviceCodeRecoveryIsCurrent ?? (() => true);
        if (!validateFailureAuthority()) {
          finishSupersededDeviceCodeAttempt();
          return loginCompletion;
        }
        closePrePoppedWindow(validateFailureAuthority);
        removeCloudAuthMessageListener();
        if (
          validateFailureAuthority() &&
          elizaCloudLoginCompletionRef.current === loginCompletion
        ) {
          setElizaCloudLoginError(
            err instanceof Error ? err.message : "Eliza Cloud login failed",
          );
          // Drop the manual-link fallback on this attempt's failure path so we
          // don't show its stale verification URL after abandonment.
          setElizaCloudLoginFallbackUrl(null);
          elizaCloudLoginBusyRef.current = false;
          setElizaCloudLoginBusy(false);
        }
        completeLogin();
        if (deviceCodeRecoveryReceipt && validateFailureAuthority()) {
          rejectCloudLoginAuthorityRecovery(deviceCodeRecoveryReceipt);
        }
      }
      return loginCompletion;
    },
    [
      elizaCloudConnected,
      elizaCloudLoginBusy,
      elizaCloudStatusReason,
      setActionNotice,
      pollCloudCredits,
      loadWalletConfig,
      reconcileAndroidCloudSession,
    ],
  );

  useEffect(() => {
    const sessionId = readCloudLoginReturnSessionId();
    if (!sessionId) {
      clearCloudLoginReturnParams();
      return;
    }
    clearCloudLoginReturnParams();
    if (elizaCloudLoginBusyRef.current) return;

    let cancelled = false;
    const sleep = (ms: number) =>
      new Promise((resolve) => window.setTimeout(resolve, ms));

    void (async () => {
      elizaCloudLoginBusyRef.current = true;
      setElizaCloudLoginBusy(true);
      setElizaCloudLoginError(null);
      setElizaCloudLoginFallbackUrl(null);
      const cloudApiBase =
        getBootConfig().cloudApiBase ?? DEFAULT_DIRECT_CLOUD_BASE_URL;
      const authenticatedCloudApiBase =
        resolveDirectCloudAuthApiBase(cloudApiBase);
      const deadline = Date.now() + ELIZA_CLOUD_LOGIN_RETURN_POLL_TIMEOUT_MS;
      let lastError: string | null = null;
      let returnRecovery: StewardSessionRecoveryReceipt | null = null;

      try {
        // This mount owns the opaque session before its first token-producing
        // poll. The receipt deliberately survives effect cleanup/tab-close;
        // an in-flight response may already have produced remote authority.
        returnRecovery = beginCloudLoginAuthorityRecovery();
        while (!cancelled && Date.now() < deadline) {
          const poll = await client.cloudLoginPollDirect(
            authenticatedCloudApiBase,
            sessionId,
          );
          if (cancelled) return;

          if (poll.status === "authenticated") {
            if (!poll.token) {
              rejectCloudLoginAuthorityRecovery(returnRecovery);
              lastError =
                "Eliza Cloud login completed, but the cloud session did not return a session token.";
              break;
            }
            const sessionToken = poll.token;
            const committed = await commitCloudLoginAuthority(
              returnRecovery,
              async (validateReceipt, finalizeReceipt) => {
                const validateBeforePublication = () =>
                  !cancelled && validateReceipt();
                if (!validateBeforePublication()) return false;
                const previousBootConfig = getBootConfig();
                const preservesLocalBackend =
                  isLoopbackStagingStewardDevelopment() &&
                  hasCloudLoginBackend();
                let tokenAuthority: StewardTokenWriteAuthority | null = null;
                let clientTargetAuthority: SessionTargetAuthority | null = null;
                let publishedBootConfig: ReturnType<
                  typeof getBootConfig
                > | null = null;
                let uiPublished = false;
                const previousUiState = cloudLoginUiStateRef.current;
                let publishedUiState: typeof previousUiState | null = null;
                const rollbackStagedPublication = (
                  durableRestored: boolean,
                ) => {
                  const bootOwned =
                    publishedBootConfig !== null &&
                    getBootConfig() === publishedBootConfig;
                  let clientRolledBack = true;
                  if (clientTargetAuthority) {
                    clientRolledBack = durableRestored
                      ? clientTargetAuthority.restoreIfCurrent()
                      : clientTargetAuthority.clearIfCurrent();
                  }
                  if (bootOwned && clientRolledBack) {
                    setBootConfig(previousBootConfig);
                  }
                };
                const rollback = async () => {
                  try {
                    // Canonical and subordinate authorities settle before
                    // React can expose their predecessor.
                    await rollbackCloudLoginPublication({
                      bindingAuthority: null,
                      tokenAuthority,
                      clientTargetAuthority,
                      previousBootConfig,
                      publishedBootConfig,
                    });
                  } finally {
                    if (
                      uiPublished &&
                      publishedUiState !== null &&
                      cloudLoginUiStateRef.current === publishedUiState
                    ) {
                      cloudLoginUiStateRef.current = previousUiState;
                      setElizaCloudConnected(previousUiState.connected);
                      setElizaCloudLoginError(previousUiState.error);
                      setElizaCloudUserId(previousUiState.userId);
                    }
                    uiPublished = false;
                  }
                };
                try {
                  tokenAuthority = await writeStoredStewardToken(sessionToken, {
                    validate: validateBeforePublication,
                    finalizeBeforePublish: () => {
                      const rollbackReceipt = finalizeReceipt();
                      try {
                        if (!preservesLocalBackend) {
                          clientTargetAuthority = client.stageSessionTarget(
                            {
                              baseUrl: authenticatedCloudApiBase,
                              token: sessionToken,
                            },
                            { persist: false },
                          );
                          if (!clientTargetAuthority) {
                            throw new Error(
                              "The Cloud login token was rejected by the active client authority.",
                            );
                          }
                        }
                        publishedBootConfig = {
                          ...getBootConfig(),
                          cloudApiBase: authenticatedCloudApiBase,
                        };
                        setBootConfig(publishedBootConfig);
                      } catch (error) {
                        try {
                          rollbackStagedPublication(false);
                        } finally {
                          rollbackReceipt(false);
                        }
                        throw error;
                      }
                      return (durableRestored) => {
                        try {
                          rollbackStagedPublication(durableRestored);
                        } finally {
                          rollbackReceipt(durableRestored);
                        }
                      };
                    },
                    commitBeforePublish: () => {
                      if (
                        clientTargetAuthority &&
                        !clientTargetAuthority.publish()
                      ) {
                        return false;
                      }
                      return validateBeforePublication();
                    },
                  });
                  if (!tokenAuthority || !validateReceipt()) {
                    await rollback();
                    return false;
                  }
                  // A cleanup which runs after canonical authority publication
                  // suppresses this mount's UI only. It must not compensate a
                  // durable token whose receipt has already finalized.
                  if (!cancelled) {
                    uiPublished = true;
                    publishedUiState = {
                      connected: true,
                      error: null,
                      userId: poll.userId ?? previousUiState.userId,
                    };
                    cloudLoginUiStateRef.current = publishedUiState;
                    setElizaCloudConnected(true);
                    setElizaCloudLoginError(null);
                    if (poll.userId) setElizaCloudUserId(poll.userId);
                    if (!validateReceipt()) {
                      await rollback();
                      return false;
                    }
                  }
                  return { restoreIfCurrent: rollback };
                } catch (error) {
                  try {
                    await rollback();
                  } catch (rollbackError) {
                    throw new AggregateError(
                      [error, rollbackError],
                      "Cloud login return publication and rollback both failed.",
                    );
                  }
                  throw error;
                }
              },
            );
            if (
              !committed?.isCurrent() ||
              readStoredStewardToken() !== sessionToken
            ) {
              await committed?.restoreIfCurrent();
              return;
            }
            if (cancelled) return;
            const committedSessionIsCurrent = () =>
              committed.isCurrent() &&
              readStoredStewardToken() === sessionToken;
            if (!committedSessionIsCurrent()) {
              await committed.restoreIfCurrent();
              return;
            }
            closeActiveCloudLoginPopup(committedSessionIsCurrent);
            if (cancelled) return;
            if (!committedSessionIsCurrent()) {
              await committed.restoreIfCurrent();
              return;
            }
            closeReturnedAuthTabIfOpenerStillExists();
            if (cancelled) return;
            if (!committedSessionIsCurrent()) {
              await committed.restoreIfCurrent();
              return;
            }
            void closeExternalBrowser();
            return;
          }

          if (poll.status === "expired" || poll.status === "error") {
            rejectCloudLoginAuthorityRecovery(returnRecovery);
            lastError =
              poll.error ?? "Login session expired. Please sign in again.";
            break;
          }

          await sleep(ELIZA_CLOUD_LOGIN_POLL_INTERVAL_MS);
        }

        if (!cancelled) {
          rejectCloudLoginAuthorityRecovery(returnRecovery);
          setElizaCloudLoginError(
            lastError ??
              "Eliza Cloud login did not finish. Please sign in again.",
          );
        }
      } catch (err) {
        if (!cancelled) {
          if (returnRecovery) {
            rejectCloudLoginAuthorityRecovery(returnRecovery);
          }
          setElizaCloudLoginError(
            err instanceof Error
              ? err.message
              : "Eliza Cloud login did not finish. Please sign in again.",
          );
        }
      } finally {
        if (!cancelled) {
          elizaCloudLoginBusyRef.current = false;
          setElizaCloudLoginBusy(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  /**
   * Interactive Cloud login entry point for user-facing buttons (Settings,
   * dashboard, onboarding, connectors upsell). It is reached from a click
   * handler whose user activation the handler already used to pre-open the
   * popup synchronously (claimCloudLoginWindow); it consumes that handle here.
   * A window.open inside THIS function would run only after the awaits that
   * precede it (first-run provisioning, status probes), when transient user
   * activation has lapsed and the browser would block it — falling back to
   * same-tab and re-opening the #17064 defect. The type-level contract is
   * preserved: interactive call sites cannot omit the popup, and the raw
   * null-window path stays off AppActions (handleCloudLoginRecovery is the
   * only sanctioned route to it). Callers that deliberately need the same-tab
   * recovery path (non-interactive boot recovery, use-boot-recovery-conductor)
   * use `handleCloudLoginRecovery` with no window — separately named there.
   */
  const handleInteractiveCloudLogin = useCallback(
    (options?: CloudLoginOptions): Promise<void> => {
      // The handle MUST be claimed synchronously in the click handler via
      // claimCloudLoginWindow() while user activation is live. Interactive
      // callers (ConfigPageView, ElizaCloudDashboard, CloudOverviewSection,
      // CloudConnectorsUpsell, use-first-run-conductor) all do this.
      // No fallback to preOpenCloudLoginWindow() here — that would run after
      // the awaits in listOrAutoProvisionCloudAgent / runFirstRunFinish,
      // when transient user activation has lapsed, causing the popup to be
      // blocked and falling back to same-tab (#17064 regression).
      const prePoppedWindow = takeClaimedCloudLoginWindow();
      return handleCloudLogin(prePoppedWindow, options);
    },
    [handleCloudLogin],
  );

  // Deliberate same-tab recovery path (boot-recovery conductor, native
  // re-auth). This wrapper is the ONLY sanctioned way to reach the raw
  // null-window path from the app surface: it takes no window argument, so a
  // missed interactive caller cannot compile against it (the #17064 defect —
  // an interactive caller silently choosing document-destroying same-tab
  // navigation — is unrepresentable through the interactive entry point, and
  // the recovery entry point is separately named so only deliberate
  // non-interactive recovery sites can reach it, #17129).
  const handleCloudLoginRecovery = useCallback(
    (options?: CloudLoginOptions): Promise<void> =>
      handleCloudLogin(null, options),
    [handleCloudLogin],
  );

  const handleCloudDisconnect = useCallback(
    async (opts?: { skipConfirmation?: boolean }): Promise<void> => {
      const MAIN_CONFIRM_DISCONNECT_MS = 300_000;
      const MAIN_POST_ONLY_MS = 12_000;
      const RENDERER_DISCONNECT_MS = 12_000;
      const skipConfirmation = opts?.skipConfirmation === true;

      if (disconnectLocked || isElizaCloudRuntimeLocked()) {
        setActionNotice(
          "Eliza Cloud is required while this app is running in cloud mode.",
          "error",
        );
        return;
      }

      elizaCloudDisconnectInFlightRef.current = true;
      setElizaCloudDisconnecting(true);

      try {
        const wasConnected = elizaCloudConnected;
        let needRendererDisconnect = true;

        if (isElectrobunRuntime()) {
          if (!skipConfirmation) {
            const combined = await invokeDesktopBridgeRequestWithTimeout<
              { cancelled: true } | { ok: true } | { ok: false; error?: string }
            >({
              rpcMethod: "agentCloudDisconnectWithConfirm",
              ipcChannel: "agent:cloudDisconnectWithConfirm",
              params: {
                apiBase: client.getBaseUrl().trim() || undefined,
                bearerToken: client.getRestAuthToken() ?? undefined,
              },
              timeoutMs: MAIN_CONFIRM_DISCONNECT_MS,
            });

            if (combined.status === "ok" && combined.value) {
              const v = combined.value;
              if ("cancelled" in v && v.cancelled) {
                return;
              }
              if ("ok" in v) {
                if (
                  v.ok === false &&
                  typeof v.error === "string" &&
                  v.error.trim()
                ) {
                  throw new Error(v.error.trim());
                }
                if (v.ok === true) {
                  needRendererDisconnect = false;
                }
              }
            }
          }

          if (needRendererDisconnect) {
            if (
              !skipConfirmation &&
              !(await confirmDesktopAction({
                title: "Disconnect from Eliza Cloud",
                message:
                  "The agent will need a local AI provider to continue working.",
                confirmLabel: "Disconnect",
                cancelLabel: "Cancel",
                type: "warning",
              }))
            ) {
              return;
            }
            if (!skipConfirmation) {
              await yieldHttpAfterNativeMessageBox();
            }

            const postOutcome = await invokeDesktopBridgeRequestWithTimeout<{
              ok: boolean;
              error?: string;
            }>({
              rpcMethod: "agentPostCloudDisconnect",
              ipcChannel: "agent:postCloudDisconnect",
              params: {
                apiBase: client.getBaseUrl().trim() || undefined,
                bearerToken: client.getRestAuthToken() ?? undefined,
              },
              timeoutMs: MAIN_POST_ONLY_MS,
            });

            if (postOutcome.status === "ok" && postOutcome.value) {
              const mr = postOutcome.value;
              if (mr.ok === true) {
                needRendererDisconnect = false;
              } else if (
                mr.ok === false &&
                typeof mr.error === "string" &&
                mr.error.trim()
              ) {
                throw new Error(mr.error.trim());
              }
            }
          }
        } else if (!skipConfirmation) {
          if (
            !(await confirmDesktopAction({
              title: "Disconnect from Eliza Cloud",
              message:
                "The agent will need a local AI provider to continue working.",
              confirmLabel: "Disconnect",
              cancelLabel: "Cancel",
              type: "warning",
            }))
          ) {
            return;
          }
          await yieldHttpAfterNativeMessageBox();
        }

        if (needRendererDisconnect) {
          await Promise.race([
            client.cloudDisconnect(),
            new Promise<never>((_, reject) => {
              window.setTimeout(() => {
                reject(
                  new Error(
                    `Disconnect timed out after ${RENDERER_DISCONNECT_MS / 1000}s`,
                  ),
                );
              }, RENDERER_DISCONNECT_MS);
            }),
          ]);
        }
        // Confirm the protected credential is durably absent before any
        // signed-out UI or logical account state is published. A denied native
        // deletion stays in the connected/error path and cannot rehydrate a
        // token after the UI claimed a successful disconnect.
        await clearStoredStewardToken();
        setElizaCloudEnabled(false);
        setElizaCloudConnected(false);
        publishElizaCloudVoiceSnapshot(setElizaCloudHasPersistedKey, {
          apiConnected: false,
          enabled: false,
          cloudVoiceProxyAvailable: false,
          hasPersistedApiKey: false,
        });
        setElizaCloudVoiceProxyAvailable(false);
        setElizaCloudCredits(null);
        setElizaCloudCreditsLow(false);
        setElizaCloudCreditsCritical(false);
        setElizaCloudAuthRejected(false);
        setElizaCloudCreditsError(null);
        setElizaCloudUserId(null);
        setElizaCloudStatusReason(null);
        lastElizaCloudPollConnectedRef.current = false;
        elizaCloudPreferDisconnectedUntilLoginRef.current = true;
        // Drop the persisted JWT on disconnect. The full sign-out path
        // (StewardProviderRuntime) already scrubs it; cloud-disconnect cleared
        // in-memory state but left active-server.accessToken in localStorage —
        // an at-rest JWT leak readable by XSS / plugin views. Keep the server
        // selection (kind/apiBase/label) so we know where to re-authenticate.
        scrubPersistedActiveServerToken();
        // SECURITY: scrubbing active-server.accessToken alone is incomplete —
        // the LIVE cloud bearer also lives in (a) localStorage steward_session_token
        // (the JWT read on every /api/* call, and where the device-code flow
        // persists its session token) and (b) per-agent-profile accessToken
        // copies. Clear both on an explicit disconnect so no usable credential
        // survives at rest / in memory (XSS / same-origin plugin views).
        scrubPersistedAgentProfileTokens();
        // The durable cloud-pair API token (localStorage + sessionStorage,
        // written by CloudPairRelay and re-adopted at every boot) is a third
        // at-rest credential: without this, a rotated/revoked pair key
        // survives disconnect and gets re-adopted on the next launch.
        // Explicit disconnect is GLOBAL sign-out intent — clear EVERY
        // per-agent durable key + the legacy global key from both storages,
        // so a token for any other paired agent can never be silently
        // re-adopted on a later boot (#17579).
        clearCloudPairApiToken();
        if (wasConnected) {
          setActionNotice("Disconnected from Eliza Cloud.", "success");
        }
      } catch (err) {
        setActionNotice(
          `Failed to disconnect: ${err instanceof Error ? err.message : err}`,
          "error",
        );
      } finally {
        elizaCloudDisconnectInFlightRef.current = false;
        setElizaCloudDisconnecting(false);
        void pollCloudCredits();
      }
    },
    [disconnectLocked, elizaCloudConnected, pollCloudCredits, setActionNotice],
  );

  const handleCloudSignOut = useCallback(async (): Promise<void> => {
    // On a backend-backed session (local app-core / agent runtime) the Cloud
    // account is also persisted server-side and re-reported by
    // /api/cloud/status. Clearing only the renderer/Steward token there leaves
    // the backend connected, so a reload or fresh poll would resurface the same
    // account. Delegate to the real disconnect path (which clears the server
    // session) unless the runtime is locked. The account-only clear below is
    // Locked mobile runtimes and hosted Cloud app-mode both require an account
    // sign-out. A local backend disconnect either refuses (locked mode) or
    // leaves the browser's SSO session intact (hosted app-mode).
    if (!(disconnectLocked || isElizaCloudRuntimeLocked() || isAppModeHost())) {
      await handleCloudDisconnect({ skipConfirmation: true });
      return;
    }

    elizaCloudDisconnectInFlightRef.current = true;
    setElizaCloudDisconnecting(true);

    try {
      // Capture the exact protected A records before remote sign-out clears its
      // Steward bearer. A different renderer may publish account B while the
      // network request is in flight; the terminal transaction must then
      // reject instead of targeting whichever host records are current.
      const verifiedAuthority = verifiedCloudAccountAuthorityRef.current;
      if (
        !verifiedAuthority ||
        verifiedAuthority.userId !== cloudLoginUiStateRef.current.userId
      ) {
        throw new Error("Cloud session changed before sign-out.");
      }
      const runtimeAuthority =
        await captureManagedCloudAccountBindingAuthority(verifiedAuthority);
      if (!runtimeAuthority.stewardToken) {
        throw new Error("Cloud session changed before sign-out.");
      }
      // Hosted Cloud runs inside the normal agent shell now, so it no longer
      // inherits the retired console's sign-out menu. Preserve the hardened
      // cross-origin teardown here: synchronously suppress auto-bridging,
      // revoke the server session, then scrub the local Steward session.
      const nativeAndroidCloud =
        isAndroidCloudBuild() && Capacitor.isNativePlatform();
      let terminalGeneration = runtimeAuthority.sessionGeneration;
      if (nativeAndroidCloud) {
        const cloudApiBase =
          getBootConfig().cloudApiBase ?? DEFAULT_DIRECT_CLOUD_BASE_URL;
        await signOutAndroidCloud(cloudApiBase, runtimeAuthority.stewardToken);
        markAndroidCloudAccountSwitchPending();
      } else {
        const completion = await signOutFromSsoBridgedHost(
          window.location.hostname,
          fetch,
          {
            expectedSessionGeneration: runtimeAuthority.sessionGeneration,
            expectedToken: runtimeAuthority.stewardToken,
          },
        );
        terminalGeneration = completion.sessionGeneration;
      }
      // A managed agent selection is scoped to the account that proved
      // ownership. Account switching must not restore that target under the
      // next account or strand the cloud-only app in backend-unreachable.
      await clearManagedCloudAccountBinding(runtimeAuthority, {
        sessionGeneration: terminalGeneration,
      });
      setElizaCloudEnabled(false);
      setElizaCloudConnected(false);
      publishElizaCloudVoiceSnapshot(setElizaCloudHasPersistedKey, {
        apiConnected: false,
        enabled: false,
        cloudVoiceProxyAvailable: false,
        hasPersistedApiKey: false,
      });
      setElizaCloudVoiceProxyAvailable(false);
      setElizaCloudCredits(null);
      setElizaCloudCreditsLow(false);
      setElizaCloudCreditsCritical(false);
      setElizaCloudAuthRejected(false);
      setElizaCloudCreditsError(null);
      verifiedCloudAccountAuthorityRef.current = null;
      setElizaCloudUserId(null);
      setElizaCloudStatusReason(null);
      setElizaCloudLoginError(null);
      setElizaCloudLoginFallbackUrl(null);
      lastElizaCloudPollConnectedRef.current = false;
      elizaCloudPreferDisconnectedUntilLoginRef.current = true;
      setActionNotice("Signed out of Eliza Cloud.", "success", 5000);
    } finally {
      elizaCloudDisconnectInFlightRef.current = false;
      setElizaCloudDisconnecting(false);
      void pollCloudCredits();
    }
  }, [
    disconnectLocked,
    handleCloudDisconnect,
    pollCloudCredits,
    setActionNotice,
  ]);

  // ── Effects ────────────────────────────────────────────────────────

  useEffect(() => {
    if (elizaCloudAuthRejected) {
      if (!elizaCloudAuthNoticeSentRef.current) {
        elizaCloudAuthNoticeSentRef.current = true;
        setActionNotice(t("notice.elizaCloudAuthRejected"), "error", 14_000);
      }
    } else {
      elizaCloudAuthNoticeSentRef.current = false;
    }
  }, [elizaCloudAuthRejected, setActionNotice, t]);

  // Cloud=Steward token lifecycle (mirrors cloud-frontend's AuthTokenSync).
  // While a Steward session token is present, refresh it ahead of its JWT `exp`
  // so an authenticated cloud connection never silently expires. Web refreshes
  // via the same-origin cookie path; native refreshes against the cloud API
  // base (Bearer-refresh). A 401 / no-token outcome is left for the next
  // pollCloudCredits() to surface as auth-rejected.
  //
  // Armed on stored-token PRESENCE, not on `elizaCloudConnected`: a returning
  // user's stored JWT can already be expired at mount, and `elizaCloudConnected`
  // only flips true after a successful status/credits poll — which can't happen
  // while every call 401s on the dead token. Gating on the connection flag
  // therefore deadlocked expired-token users (nothing ever refreshed the token
  // that blocked the connection). Presence-gating breaks that: the check runs at
  // mount for any stored token and refreshes a near-expiry/expired JWT so the
  // next poll can succeed. A comfortably-valid token still no-ops (see the
  // `secs >= STEWARD_REFRESH_AHEAD_SECS` guard), so this adds no needless work.
  //
  // biome-ignore lint/correctness/useExhaustiveDependencies: elizaCloudConnected is an intentional re-arm trigger, not read inside — a fresh login writes a new token and flips connected, and the effect must re-run to arm the lifecycle refresh on that token. Presence of a stored token (checked at the top) is the real gate.
  useEffect(() => {
    if (!readStoredStewardToken()?.trim()) return;

    let disposed = false;
    const checkAndRefresh = async () => {
      const storedToken = readStoredStewardToken();
      if (!storedToken) return;
      const token = storedToken.trim();
      if (token.length === 0) return;
      const secs = cloudTokenSecsRemaining(token);
      // No `exp` (opaque token / device-code session) → nothing to refresh.
      if (secs === null) return;
      if (secs >= STEWARD_REFRESH_AHEAD_SECS) return;
      try {
        await refreshCloudStewardSession({
          endpoint: resolveStewardRefreshEndpoint(),
          commitRefreshedSession: async (session, authority) => {
            if (session.token && authority.validate()) {
              await replaceStoredStewardTokenIfCurrent(
                storedToken,
                session.token,
                { validate: authority.validate },
              );
            }
          },
        });
        if (disposed) return;
      } catch (err: unknown) {
        // error-policy:J4 a pre-emptive refresh or protected persistence
        // failure keeps the prior durable token until an auth boundary exposes
        // the re-auth path. No rejected token is published.
        logger.warn({ err }, "[useCloudState] steward session refresh failed");
        return;
      }
    };

    void checkAndRefresh();
    const interval = window.setInterval(() => {
      if (
        typeof document !== "undefined" &&
        document.visibilityState !== "visible"
      ) {
        return;
      }
      void checkAndRefresh();
    }, STEWARD_REFRESH_CHECK_INTERVAL_MS);

    return () => {
      disposed = true;
      clearInterval(interval);
    };
  }, [elizaCloudConnected]);

  // ── Return ─────────────────────────────────────────────────────────

  return {
    // State
    elizaCloudEnabled,
    setElizaCloudEnabled,
    elizaCloudVoiceProxyAvailable,
    setElizaCloudVoiceProxyAvailable,
    elizaCloudConnected,
    setElizaCloudConnected,
    elizaCloudHasPersistedKey,
    setElizaCloudHasPersistedKey,
    elizaCloudCredits,
    setElizaCloudCredits,
    elizaCloudCreditsLow,
    setElizaCloudCreditsLow,
    elizaCloudCreditsCritical,
    setElizaCloudCreditsCritical,
    elizaCloudAuthRejected,
    setElizaCloudAuthRejected,
    elizaCloudCreditsError,
    setElizaCloudCreditsError,
    elizaCloudTopUpUrl,
    setElizaCloudTopUpUrl,
    elizaCloudUserId,
    setElizaCloudUserId,
    elizaCloudStatusReason,
    setElizaCloudStatusReason,
    cloudDashboardView,
    setCloudDashboardView,
    elizaCloudLoginBusy,
    setElizaCloudLoginBusy,
    elizaCloudLoginError,
    setElizaCloudLoginError,
    elizaCloudLoginFallbackUrl,
    setElizaCloudLoginFallbackUrl,
    elizaCloudDisconnecting,
    setElizaCloudDisconnecting,
    // Refs (exposed for cleanup in AppContext's startup effect and for forward ref)
    elizaCloudPollInterval,
    elizaCloudDisconnectInFlightRef,
    elizaCloudPreferDisconnectedUntilLoginRef,
    lastElizaCloudPollConnectedRef,
    elizaCloudLoginPollTimer,
    elizaCloudLoginBusyRef,
    // Callbacks
    pollCloudCredits,
    handleCloudLogin,
    handleCloudLoginRecovery,
    handleInteractiveCloudLogin,
    handleCloudDisconnect,
    handleCloudSignOut,
  };
}
