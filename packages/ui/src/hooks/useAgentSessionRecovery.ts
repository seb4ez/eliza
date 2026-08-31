/**
 * useAgentSessionRecovery, bridges the unauthenticated auth state (#15132) to
 * a transparent re-pair instead of the password-wall dead-end.
 *
 * When `/api/auth/me` 401s AFTER a dedicated cloud agent's container upgrade,
 * the browser's persisted agent credential is stale but the cloud session is
 * still valid. This hook detects that exact case and re-runs the cloud pairing
 * exchange (the same flow first-pairing uses). Browser clients navigate through
 * `/pair`; native clients exchange and install the credential in-process, then
 * re-probe auth. Non-recoverable managed-native outcomes become explicit
 * reauth, retry, or Cloud-management states; self-hosted access remains idle so
 * the owner-password form can render.
 *
 * SECURITY (auth-adjacent): this NEVER bypasses the wall. Recovery only fires
 * when a valid cloud session exists to re-pair from; the server still gates the
 * pairing-token mint. Managed-native failures preserve the Cloud credential
 * unless Cloud actually rejected it; only self-hosted targets return to the
 * owner-password wall.
 */

import { logger } from "@elizaos/logger";
import { useEffect, useRef, useState } from "react";
import type { SessionTargetAuthority } from "../api/client-base";
import { getCloudAuthToken } from "../api/client-cloud";
import { isAppModeHost } from "../cloud/app-mode/app-mode";
import {
  readStewardSessionRecovery,
  STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
  type StewardSessionRecoverySnapshot,
} from "../cloud/lib/steward-session-recovery-marker";
import {
  configuredStewardTenantId,
  DEFAULT_STEWARD_TENANT_ID,
} from "../cloud/shell/steward-config";
import { persistCloudPairApiToken } from "../components/auth/CloudPairRelay";
import { getBootConfig } from "../config/boot-config";
import { persistActiveServerCredential } from "../state/active-server-credential";
import {
  type AgentSessionUnauthReason,
  agentSessionRepairNeedsCloudToken,
  isManagedCloudAgentServer,
  type ManagedCloudAgentRecoveryStatus,
  resolveAgentSessionRecovery,
  resolveDedicatedAgentId,
} from "../state/agent-session-recovery";
import { runAgentSessionRecovery } from "../state/agent-session-recovery-runner";
import { clearStalePairCredentialsForAgentDurably } from "../state/cloud-pair-token";
import { ensureCloudSessionForRepair } from "../state/cloud-session-refresh-for-repair";
import {
  captureStoredStewardLoginAuthority,
  isStoredStewardTokenUsable,
  type StoredStewardLoginAuthority,
} from "../state/cloud-steward-login";
import {
  loadPersistedActiveServer,
  type PersistedActiveServer,
} from "../state/persistence";
import { useIsAuthenticated } from "./useAuthStatus";

export type AgentSessionRecoveryStatus =
  /** Not a recoverable state, the auth gate should render the wall. */
  | "idle"
  /** A re-pair is in flight, the auth gate should hold (no wall yet). */
  | "recovering"
  /** Cloud rejected or lacks the credential needed for native recovery. */
  | "cloud-reauth-required"
  /** Native recovery failed without proving the Cloud credential invalid. */
  | "cloud-retry-required"
  /** The managed agent needs attention in Cloud; reauth/retry cannot fix it. */
  | "cloud-manage-required";

interface UseAgentSessionRecoveryOptions {
  /**
   * Whether the app is currently in the unauthenticated state, and (when so)
   * the `/api/auth/me` reason. `active: false` disables the hook entirely.
   */
  active: boolean;
  reason: AgentSessionUnauthReason;
  /** Injected navigate (tests). Defaults to a full-page window assignment. */
  navigate?: (url: string) => void;
  /** Re-probe agent auth immediately after an in-process native exchange. */
  onRecovered?: () => void;
}

function defaultNavigate(url: string): void {
  if (typeof window !== "undefined") {
    window.location.assign(url);
  }
}

/**
 * Whether recovery redeems the one-time pairing token in-process instead of
 * full-page navigating into the per-agent `/pair` relay.
 *
 * Native has always consumed in-process (it has no browser navigation). The
 * Eliza app hosts must too: `../cloud/app-mode/app-mode.ts` established the
 * chat floor because a cold-starting agent cannot consume a 60s one-time token
 * inside its TTL, so the redirect dead-ends on "Sign-in link expired" and the
 * user is bounced back through a second full sign-in. Entry stopped
 * pairing-redirecting there (#18016); recovery is the remaining caller that
 * did, which reopened the same dead-end on app-staging. The exchange endpoint
 * (`/api/auth/pair/native`) authenticates with the Cloud session the browser
 * already holds, so the app hosts can redeem it directly and stay same-origin.
 */
function isNativeRuntime(): boolean {
  try {
    const cap = (globalThis as Record<string, unknown>).Capacitor as
      | { isNativePlatform?: () => boolean }
      | undefined;
    return Boolean(cap?.isNativePlatform?.());
  } catch {
    // error-policy:J4 an unavailable native bridge means browser-style
    // navigation remains the compatible fallback.
    return false;
  }
}

function shouldConsumePairRedirectInProcess(): boolean {
  return isNativeRuntime() || isAppModeHost();
}

function normalizedOptionalValue(value: string | undefined): string {
  return value?.trim() ?? "";
}

function normalizedOptionalBase(value: string | undefined): string {
  return normalizedOptionalValue(value).replace(/\/+$/, "");
}

function recoveryTargetIdentityMatches(
  expected: PersistedActiveServer,
  current: PersistedActiveServer | null,
): boolean {
  return Boolean(
    current &&
      current.kind === expected.kind &&
      current.id === expected.id &&
      normalizedOptionalBase(current.apiBase) ===
        normalizedOptionalBase(expected.apiBase),
  );
}

/** A late recovery may commit only to the exact server record that started it. */
function recoveryTargetMatches(
  expected: PersistedActiveServer,
  current: PersistedActiveServer | null,
  acceptedReplacementToken: string | null = null,
): boolean {
  const currentAccessToken = normalizedOptionalValue(current?.accessToken);
  const expectedAccessToken = normalizedOptionalValue(expected.accessToken);
  const credentialMatches =
    currentAccessToken === expectedAccessToken ||
    (acceptedReplacementToken !== null &&
      currentAccessToken === normalizedOptionalValue(acceptedReplacementToken));
  return Boolean(
    recoveryTargetIdentityMatches(expected, current) && credentialMatches,
  );
}

function readStewardRecoverySnapshot(): StewardSessionRecoverySnapshot {
  return readStewardSessionRecovery(
    configuredStewardTenantId(DEFAULT_STEWARD_TENANT_ID),
  );
}

function recoveryAdmissionIsClean(
  snapshot: StewardSessionRecoverySnapshot,
): boolean {
  return snapshot.storageAvailable && snapshot.receipts.length === 0;
}

/** A clean admission remains live only within its exact monotonic generation. */
function recoveryAdmissionIsCurrent(
  expected: StewardSessionRecoverySnapshot,
): boolean {
  const current = readStewardRecoverySnapshot();
  return (
    recoveryAdmissionIsClean(expected) &&
    recoveryAdmissionIsClean(current) &&
    current.generation === expected.generation
  );
}

interface ActiveAgentSessionRecovery {
  authority: StoredStewardLoginAuthority;
  controller: AbortController;
}

interface PendingAgentSessionRecovery {
  authority: StoredStewardLoginAuthority | null;
  controller: AbortController;
  recoveryGeneration: string | null;
}

export function useAgentSessionRecovery(
  options: UseAgentSessionRecoveryOptions,
): AgentSessionRecoveryStatus {
  const { active, reason, navigate = defaultNavigate, onRecovered } = options;
  const [status, setStatus] = useState<AgentSessionRecoveryStatus>("idle");
  const isAuthenticated = useIsAuthenticated();
  // A loading refetch briefly leaves the unauthenticated state, so only a
  // confirmed session (or remount) may rearm recovery for a later genuine 401.
  const attemptedRef = useRef(false);
  const awaitingCloudTokenRef = useRef(false);
  const attemptedFallbackRef = useRef<ManagedCloudAgentRecoveryStatus>(
    "cloud-retry-required",
  );
  const activeRecoveryRef = useRef<ActiveAgentSessionRecovery | null>(null);
  const pendingRecoveryRef = useRef<PendingAgentSessionRecovery | null>(null);
  const [cloudTokenSnapshot, setCloudTokenSnapshot] = useState(() =>
    getCloudAuthToken(),
  );
  const [recoveryRevision, setRecoveryRevision] = useState(0);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const abortOwnedRecovery = () => {
      const activeRecovery = activeRecoveryRef.current;
      if (activeRecovery) {
        activeRecovery.controller.abort();
        if (activeRecoveryRef.current === activeRecovery) {
          activeRecoveryRef.current = null;
        }
      }
      const pendingRecovery = pendingRecoveryRef.current;
      if (pendingRecovery) {
        pendingRecovery.controller.abort();
        if (pendingRecoveryRef.current === pendingRecovery) {
          pendingRecoveryRef.current = null;
        }
      }
    };

    const rearmAfterCloudReauth = () => {
      const cloudToken = getCloudAuthToken();
      const activeRecovery = activeRecoveryRef.current;
      if (activeRecovery && !activeRecovery.authority.isCurrent()) {
        abortOwnedRecovery();
        attemptedRef.current = false;
        awaitingCloudTokenRef.current = false;
        setCloudTokenSnapshot(cloudToken);
        return;
      }
      // The cookie-recovery attempt writes its canonical token before its
      // promise can hand that token to this effect. Do not let that same sync
      // event tear down/abort the in-flight attempt; explicit reauth is armed
      // through `awaitingCloudTokenRef` and still re-renders below.
      if (attemptedRef.current && !awaitingCloudTokenRef.current) {
        return;
      }
      setCloudTokenSnapshot(cloudToken);
      if (!awaitingCloudTokenRef.current || !cloudToken?.trim()) {
        return;
      }
      awaitingCloudTokenRef.current = false;
      attemptedRef.current = false;
    };

    const retireSupersededRecovery = () => {
      // A durable login receipt changes the origin-wide account authority even
      // if it begins and retires before React commits this state update. Abort
      // synchronously; the captured generation fence stays false forever.
      abortOwnedRecovery();
      attemptedRef.current = false;
      awaitingCloudTokenRef.current = false;
      setStatus("idle");
      setCloudTokenSnapshot(getCloudAuthToken());
      setRecoveryRevision((revision) => revision + 1);
    };

    const retireCrossTabRecoveryIfSuperseded = () => {
      const activeRecovery = activeRecoveryRef.current;
      const pendingRecovery = pendingRecoveryRef.current;
      if (!activeRecovery && !pendingRecovery) return;
      const expectedGeneration =
        activeRecovery?.authority.recoveryGeneration ??
        pendingRecovery?.recoveryGeneration ??
        null;
      const current = readStewardRecoverySnapshot();
      const generationIsCurrent =
        recoveryAdmissionIsClean(current) &&
        current.generation === expectedGeneration;
      const tokenAuthorityIsCurrent =
        activeRecovery?.authority.isCurrent() ??
        pendingRecovery?.authority?.isCurrent() ??
        true;
      // StorageEvent is cross-document only. Re-read the exact generation and
      // token authority instead of aborting account A for an unrelated key.
      if (generationIsCurrent && tokenAuthorityIsCurrent) return;
      abortOwnedRecovery();
      attemptedRef.current = false;
      awaitingCloudTokenRef.current = false;
      setStatus("idle");
      setCloudTokenSnapshot(getCloudAuthToken());
      setRecoveryRevision((revision) => revision + 1);
    };

    window.addEventListener("steward-token-sync", rearmAfterCloudReauth);
    window.addEventListener(
      STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
      retireSupersededRecovery,
    );
    window.addEventListener("storage", retireCrossTabRecoveryIfSuperseded);
    return () => {
      window.removeEventListener("steward-token-sync", rearmAfterCloudReauth);
      window.removeEventListener(
        STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
        retireSupersededRecovery,
      );
      window.removeEventListener("storage", retireCrossTabRecoveryIfSuperseded);
    };
  }, []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: token/recovery event snapshots deliberately retrigger fresh authoritative storage reads.
  useEffect(() => {
    const consumeRedirectInProcess = shouldConsumePairRedirectInProcess();
    const activeServer = active ? loadPersistedActiveServer() : null;
    const recoveryAtAdmission = readStewardRecoverySnapshot();
    // Deliberately keyed to the native runtime, not to in-process redemption:
    // the app hosts now redeem in-process too, and this flag drives the
    // native-only managed-recovery status UI.
    const isManagedNative =
      isNativeRuntime() && isManagedCloudAgentServer(activeServer);
    const fallbackStatus = (
      managedStatus: ManagedCloudAgentRecoveryStatus = "cloud-retry-required",
    ): AgentSessionRecoveryStatus => (isManagedNative ? managedStatus : "idle");
    const showFallback = (
      managedStatus: ManagedCloudAgentRecoveryStatus = "cloud-retry-required",
      validatePublication: () => boolean = () =>
        recoveryAdmissionIsCurrent(recoveryAtAdmission),
    ) => {
      if (!validatePublication()) return;
      attemptedFallbackRef.current = managedStatus;
      awaitingCloudTokenRef.current =
        isManagedNative && managedStatus === "cloud-reauth-required";
      setStatus(fallbackStatus(managedStatus));
    };

    if (!active) {
      awaitingCloudTokenRef.current = false;
      if (isAuthenticated) {
        attemptedRef.current = false;
        attemptedFallbackRef.current = "cloud-retry-required";
      }
      setStatus("idle");
      return;
    }

    if (!recoveryAdmissionIsClean(recoveryAtAdmission)) {
      // A durable login B owns the origin, or storage cannot prove otherwise.
      // Keep every account-A repair side effect quarantined until that
      // generation publishes or is explicitly recovered.
      attemptedRef.current = false;
      awaitingCloudTokenRef.current = false;
      setStatus("idle");
      return;
    }

    if (attemptedRef.current) {
      // One attempt per cycle: a prior failed attempt must fall through to the
      // wall/notice, never loop.
      setStatus(fallbackStatus(attemptedFallbackRef.current));
      return;
    }

    let cancelled = false;
    const recoveryAbortController = new AbortController();
    const liveCloudToken = getCloudAuthToken()?.trim() || null;
    const capturedStoredAuthority = captureStoredStewardLoginAuthority();
    const storedAuthority =
      liveCloudToken &&
      capturedStoredAuthority?.token === liveCloudToken &&
      capturedStoredAuthority.recoveryGeneration ===
        recoveryAtAdmission.generation &&
      capturedStoredAuthority.isCurrent()
        ? capturedStoredAuthority
        : null;

    // A token whose clean generation cannot be captured is never passive
    // repair authority. In particular this blocks raw account A while login B
    // has made recovery storage unreadable or changed between the two reads.
    if (liveCloudToken && !storedAuthority) {
      setStatus("idle");
      return;
    }

    const resolveInput = (
      cloudToken: string | null,
      // The outer attempt guard lives on `attemptedRef`; this flag is for the
      // resolver's own loop-guard. When re-resolving AFTER a successful cookie
      // refresh we pass `false` so the freshly-recovered token can re-pair (the
      // refresh IS this cycle's one attempt, gated by the caller).
      alreadyAttempted: boolean = attemptedRef.current,
    ) => ({
      reason,
      activeServer,
      cloudToken,
      cloudApiBase: getBootConfig().cloudApiBase?.trim() || "https://eliza.app",
      alreadyAttempted,
    });

    const startRepair = (
      decision: ReturnType<typeof resolveAgentSessionRecovery>,
      authority: StoredStewardLoginAuthority,
    ) => {
      const cloudToken = authority.token;
      awaitingCloudTokenRef.current = false;
      if (
        cancelled ||
        !recoveryAdmissionIsCurrent(recoveryAtAdmission) ||
        !authority.isCurrent()
      ) {
        return;
      }
      if (decision.action !== "re-pair") {
        showFallback(
          cloudToken.trim() ? "cloud-manage-required" : "cloud-reauth-required",
          () =>
            recoveryAdmissionIsCurrent(recoveryAtAdmission) &&
            authority.isCurrent(),
        );
        return;
      }
      if (!activeServer) {
        showFallback(
          "cloud-manage-required",
          () =>
            recoveryAdmissionIsCurrent(recoveryAtAdmission) &&
            authority.isCurrent(),
        );
        return;
      }
      attemptedFallbackRef.current = "cloud-retry-required";
      let acceptedReplacementToken: string | null = null;
      const activeRecovery = {
        authority,
        controller: recoveryAbortController,
      };
      if (pendingRecoveryRef.current?.controller === recoveryAbortController) {
        pendingRecoveryRef.current = null;
      }
      activeRecoveryRef.current = activeRecovery;
      const isRecoveryOwnershipCurrent = () => {
        const currentServer = loadPersistedActiveServer();
        return (
          activeRecoveryRef.current === activeRecovery &&
          !cancelled &&
          !recoveryAbortController.signal.aborted &&
          authority.token === cloudToken &&
          authority.recoveryGeneration === recoveryAtAdmission.generation &&
          authority.isCurrent() &&
          recoveryAdmissionIsCurrent(recoveryAtAdmission) &&
          resolveDedicatedAgentId(activeServer) === decision.agentId &&
          currentServer !== null &&
          resolveDedicatedAgentId(currentServer) === decision.agentId &&
          recoveryTargetIdentityMatches(activeServer, currentServer)
        );
      };
      const isRecoveryTargetCurrent = () =>
        isRecoveryOwnershipCurrent() &&
        recoveryTargetMatches(
          activeServer,
          loadPersistedActiveServer(),
          acceptedReplacementToken,
        );
      const assertRecoveryTargetCurrent = () => {
        if (isRecoveryTargetCurrent()) return;
        recoveryAbortController.abort();
        throw new Error(
          "Agent session recovery target changed or authority was superseded before local publication",
        );
      };
      if (!isRecoveryTargetCurrent()) {
        recoveryAbortController.abort();
        if (activeRecoveryRef.current === activeRecovery) {
          activeRecoveryRef.current = null;
        }
        return;
      }
      setStatus("recovering");
      void runAgentSessionRecovery({
        cloudApiBase: decision.cloudApiBase,
        agentId: decision.agentId,
        cloudToken,
        consumeRedirectInProcess,
        signal: recoveryAbortController.signal,
        isRecoveryTargetCurrent,
        commitPairedInProcess: async (apiToken) => {
          let compensatePair: (() => Promise<void>) | null = null;
          let compensateRuntime: (() => Promise<void>) | null = null;
          let stagedClientTarget: SessionTargetAuthority | null = null;
          let previousLegacyBootConfig: unknown;
          let publishedLegacyBootConfig: unknown;
          const globals = globalThis as Record<string, unknown>;
          const restoreStagedClientTarget = async () => {
            if (
              publishedLegacyBootConfig !== undefined &&
              globals.__ELIZA_APP_BOOT_CONFIG__ === publishedLegacyBootConfig
            ) {
              if (previousLegacyBootConfig === undefined) {
                Reflect.deleteProperty(globals, "__ELIZA_APP_BOOT_CONFIG__");
              } else {
                globals.__ELIZA_APP_BOOT_CONFIG__ = previousLegacyBootConfig;
              }
            }
            stagedClientTarget?.restoreIfCurrent();
          };
          const compensate = async () => {
            const failures: unknown[] = [];
            for (const rollback of [compensateRuntime, compensatePair]) {
              if (!rollback) continue;
              try {
                await rollback();
              } catch (error) {
                failures.push(error);
              }
            }
            if (failures.length > 0) {
              throw new AggregateError(
                failures,
                "Agent session recovery compensation failed",
              );
            }
          };

          try {
            assertRecoveryTargetCurrent();
            const { client } = await import("../api");
            assertRecoveryTargetCurrent();
            await persistCloudPairApiToken(apiToken, decision.agentId, {
              validate: isRecoveryTargetCurrent,
              publishSession: false,
              captureCompensation: (rollback) => {
                compensatePair = rollback;
              },
            });
            assertRecoveryTargetCurrent();
            if (!compensatePair) {
              throw new Error(
                "Cloud pair credential rollback authority is unavailable.",
              );
            }

            // This transaction may now observe only its own replacement token.
            // Every other target/token still supersedes the recovery.
            acceptedReplacementToken = apiToken;
            assertRecoveryTargetCurrent();
            await persistActiveServerCredential(apiToken, undefined, {
              validate: isRecoveryTargetCurrent,
              finalize: async () => {
                assertRecoveryTargetCurrent();
                const apiBase = activeServer.apiBase?.trim();
                if (!apiBase) return false;
                stagedClientTarget = client.stageSessionTarget(
                  { baseUrl: apiBase, token: apiToken },
                  { persist: false },
                );
                if (!stagedClientTarget || !isRecoveryTargetCurrent()) {
                  stagedClientTarget?.restoreIfCurrent();
                  stagedClientTarget = null;
                  return false;
                }
                previousLegacyBootConfig = globals.__ELIZA_APP_BOOT_CONFIG__;
                publishedLegacyBootConfig = getBootConfig();
                globals.__ELIZA_APP_BOOT_CONFIG__ = publishedLegacyBootConfig;
                if (!isRecoveryTargetCurrent()) {
                  await restoreStagedClientTarget();
                  return false;
                }
                return true;
              },
              compensateFinalization: restoreStagedClientTarget,
              captureCompensation: (rollback) => {
                compensateRuntime = rollback;
              },
            });
            assertRecoveryTargetCurrent();
            const committedClientTarget =
              stagedClientTarget as SessionTargetAuthority | null;
            if (!compensateRuntime || !committedClientTarget) {
              throw new Error(
                "Runtime credential rollback authority is unavailable.",
              );
            }
            assertRecoveryTargetCurrent();
            if (
              !committedClientTarget.isCurrent() ||
              !committedClientTarget.publish()
            ) {
              throw new Error(
                "The recovered runtime credential could not be published.",
              );
            }
            assertRecoveryTargetCurrent();
            if (!committedClientTarget.isCurrent()) {
              throw new Error(
                "The recovered runtime credential was superseded during publication.",
              );
            }
            if (onRecovered) {
              onRecovered();
            }
          } catch (error) {
            try {
              await compensate();
            } catch (rollbackError) {
              throw new AggregateError(
                [error, rollbackError],
                "Agent session recovery and compensation failed",
              );
            }
            throw error;
          }
        },
        navigate: (url) => {
          if (isRecoveryTargetCurrent()) navigate(url);
        },
      })
        .then(async (result) => {
          const retireOwnedRecoveryToIdle = () => {
            if (activeRecoveryRef.current !== activeRecovery) return;
            activeRecoveryRef.current = null;
            recoveryAbortController.abort();
            attemptedRef.current = false;
            awaitingCloudTokenRef.current = false;
            setStatus("idle");
          };
          if (!result.ok && result.reason === "cancelled") {
            retireOwnedRecoveryToIdle();
            return;
          }
          if (!isRecoveryTargetCurrent()) {
            retireOwnedRecoveryToIdle();
            return;
          }
          // Browser success navigates through `/pair`; native success installs
          // the bearer in-process and triggers `onRecovered`. Failures retain
          // enough classification for reauth versus non-destructive retry.
          if (!result.ok) {
            logger.warn(
              {
                agentId: decision.agentId,
                reason: result.reason,
                message: result.message,
              },
              "[AgentSessionRecovery] managed-agent re-pair failed",
            );
            const fallback =
              result.reason === "unauthorized"
                ? "cloud-reauth-required"
                : result.reason === "manage-required"
                  ? "cloud-manage-required"
                  : "cloud-retry-required";
            const purgeRejectedAgentBearer =
              result.reason === "unauthorized" ||
              result.reason === "manage-required";
            if (purgeRejectedAgentBearer) {
              // `/api/auth/me` already proved this adopted agent bearer stale.
              // Purge only after result classification and while account,
              // generation and same-agent ownership are all still current.
              if (!isRecoveryTargetCurrent()) {
                retireOwnedRecoveryToIdle();
                return;
              }
              const rejectedToken = activeServer.accessToken?.trim() ?? "";
              const purgeAuthorityIsCurrent = () => {
                if (!isRecoveryOwnershipCurrent()) return false;
                const currentServer = loadPersistedActiveServer();
                if (
                  !recoveryTargetIdentityMatches(activeServer, currentServer)
                ) {
                  return false;
                }
                const currentToken = currentServer?.accessToken?.trim() ?? "";
                return !currentToken || currentToken === rejectedToken;
              };
              const purgeProvedRejectedBearerAbsent =
                rejectedToken.length > 0 &&
                (await clearStalePairCredentialsForAgentDurably({
                  agentId: decision.agentId,
                  rejectedToken,
                  validate: purgeAuthorityIsCurrent,
                }));
              if (!purgeProvedRejectedBearerAbsent) {
                if (isRecoveryOwnershipCurrent()) {
                  showFallback(
                    "cloud-retry-required",
                    isRecoveryOwnershipCurrent,
                  );
                  if (activeRecoveryRef.current === activeRecovery) {
                    activeRecoveryRef.current = null;
                  }
                } else {
                  retireOwnedRecoveryToIdle();
                }
                return;
              }
              if (!isRecoveryOwnershipCurrent()) {
                retireOwnedRecoveryToIdle();
                return;
              }
            }
            showFallback(
              fallback,
              purgeRejectedAgentBearer
                ? isRecoveryOwnershipCurrent
                : isRecoveryTargetCurrent,
            );
          } else {
            logger.info(
              {
                agentId: decision.agentId,
                mode: result.mode,
              },
              "[AgentSessionRecovery] managed-agent re-pair succeeded",
            );
          }
          if (activeRecoveryRef.current === activeRecovery) {
            activeRecoveryRef.current = null;
          }
        })
        .catch((error: unknown) => {
          // error-policy:J4 an unclassified repair failure keeps the existing
          // Cloud token and degrades to a non-destructive retry surface.
          const stillOwnsRecovery =
            activeRecoveryRef.current === activeRecovery;
          if (isRecoveryTargetCurrent()) {
            logger.warn(
              {
                agentId: decision.agentId,
                error:
                  error instanceof Error
                    ? error.message
                    : "Unknown recovery failure",
              },
              "[AgentSessionRecovery] managed-agent re-pair threw",
            );
            showFallback("cloud-retry-required", isRecoveryTargetCurrent);
          } else if (stillOwnsRecovery) {
            // Target/account cancellation is not a retryable account-A error.
            // Clear ownership first; a B event which already did so wins and is
            // never overwritten by this late catch.
            activeRecoveryRef.current = null;
            attemptedRef.current = false;
            awaitingCloudTokenRef.current = false;
            setStatus("idle");
          }
          if (activeRecoveryRef.current === activeRecovery) {
            activeRecoveryRef.current = null;
          }
        });
    };

    const initialInput = resolveInput(storedAuthority?.token ?? null);
    const initialDecision = resolveAgentSessionRecovery(initialInput);
    const initialCloudToken = initialInput.cloudToken?.trim();
    const storedTokenNeedsRefresh = Boolean(
      storedAuthority && !isStoredStewardTokenUsable(storedAuthority.token),
    );

    if (
      initialDecision.action === "re-pair" &&
      initialCloudToken &&
      storedAuthority &&
      !storedTokenNeedsRefresh
    ) {
      // Fast path: app-origin cloud token already present, re-pair immediately
      // (the classic post-upgrade stale-credential case).
      attemptedRef.current = true;
      startRepair(initialDecision, storedAuthority);
      return () => {
        cancelled = true;
        recoveryAbortController.abort();
        if (
          pendingRecoveryRef.current?.controller === recoveryAbortController
        ) {
          pendingRecoveryRef.current = null;
        }
        if (activeRecoveryRef.current?.controller === recoveryAbortController) {
          activeRecoveryRef.current = null;
        }
      };
    }

    if (
      !storedTokenNeedsRefresh &&
      !agentSessionRepairNeedsCloudToken(initialInput)
    ) {
      // Not a cookie-recoverable state (self-hosted, wrong 401 reason, no agent
      // id, or genuinely nothing to re-pair). The wall/notice is honest.
      showFallback(
        initialInput.cloudToken?.trim()
          ? "cloud-manage-required"
          : "cloud-reauth-required",
      );
      return;
    }

    // Re-pair-shaped in every dimension EXCEPT the app-origin cloud token: this
    // is the returning-PWA "Open this agent from Eliza Cloud" dead-end. The user
    // IS signed in to Eliza (through the canonical host's HttpOnly cookie), but
    // this origin's token mirror is empty. Recover the session through the
    // same-origin refresh bridge and re-pair instead of dropping to the notice.
    attemptedRef.current = true;
    setStatus("recovering");
    const pendingRecovery = {
      authority: storedAuthority,
      controller: recoveryAbortController,
      recoveryGeneration: recoveryAtAdmission.generation,
    };
    pendingRecoveryRef.current = pendingRecovery;
    const releasePendingRecovery = () => {
      if (pendingRecoveryRef.current === pendingRecovery) {
        pendingRecoveryRef.current = null;
      }
    };
    const retirePendingRecoveryToIdle = () => {
      if (pendingRecoveryRef.current !== pendingRecovery) return;
      pendingRecoveryRef.current = null;
      recoveryAbortController.abort();
      attemptedRef.current = false;
      awaitingCloudTokenRef.current = false;
      setStatus("idle");
    };
    const validateRefreshPublication = () =>
      pendingRecoveryRef.current === pendingRecovery &&
      !cancelled &&
      !recoveryAbortController.signal.aborted &&
      recoveryAdmissionIsCurrent(recoveryAtAdmission) &&
      Boolean(
        activeServer &&
          recoveryTargetMatches(activeServer, loadPersistedActiveServer()),
      );

    void ensureCloudSessionForRepair(
      storedTokenNeedsRefresh
        ? {
            forceRefresh: true,
            validate: validateRefreshPublication,
          }
        : { validate: validateRefreshPublication },
    )
      .then((token) => {
        if (
          cancelled ||
          !validateRefreshPublication() ||
          !recoveryAdmissionIsCurrent(recoveryAtAdmission)
        ) {
          retirePendingRecoveryToIdle();
          return;
        }
        if (!token) {
          // No cookie / refresh failed / timed out: the notice is honest now.
          releasePendingRecovery();
          showFallback("cloud-reauth-required");
          // Native SIWE can finish in the narrow window between the cookie
          // refresh resolving and the fallback being armed. Its sync event has
          // already fired, so re-check the canonical token once instead of
          // waiting forever for a second event.
          const lateCloudToken = getCloudAuthToken();
          if (awaitingCloudTokenRef.current && lateCloudToken?.trim()) {
            awaitingCloudTokenRef.current = false;
            attemptedRef.current = false;
            setCloudTokenSnapshot(lateCloudToken);
          }
          return;
        }
        const refreshedAuthority = captureStoredStewardLoginAuthority();
        if (
          !refreshedAuthority ||
          refreshedAuthority.token !== token.trim() ||
          refreshedAuthority.recoveryGeneration !==
            recoveryAtAdmission.generation ||
          !refreshedAuthority.isCurrent()
        ) {
          retirePendingRecoveryToIdle();
          return;
        }
        const decision = resolveAgentSessionRecovery(
          resolveInput(token, false),
        );
        releasePendingRecovery();
        startRepair(decision, refreshedAuthority);
      })
      .catch(() => {
        // error-policy:J4 cookie recovery is opportunistic; the explicit Cloud
        // reauthentication notice remains the safe user-driven fallback.
        if (!cancelled && recoveryAdmissionIsCurrent(recoveryAtAdmission)) {
          releasePendingRecovery();
          showFallback("cloud-reauth-required");
        }
      });

    return () => {
      cancelled = true;
      recoveryAbortController.abort();
      if (pendingRecoveryRef.current?.controller === recoveryAbortController) {
        pendingRecoveryRef.current = null;
      }
      if (activeRecoveryRef.current?.controller === recoveryAbortController) {
        activeRecoveryRef.current = null;
      }
    };
    // setStatus and attemptedRef are stable; all third-party inputs are listed.
  }, [
    active,
    reason,
    navigate,
    onRecovered,
    isAuthenticated,
    cloudTokenSnapshot,
    recoveryRevision,
  ]);

  return status;
}
