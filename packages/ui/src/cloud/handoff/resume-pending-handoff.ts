/**
 * Resumes a pending cloud handoff after a reload/redirect by rehydrating the
 * cloud auth token and shared-agent base.
 */
import { client } from "../../api";
import {
  compensateFreshCloudCompatAgentCreate,
  createFreshDedicatedCloudCompatAgentWithExactAuthority,
  getCloudAuthToken,
  getCloudCompatAgentWithExactAuthority,
  isDirectCloudSharedAgentBase,
} from "../../api/client-cloud";
import { getBootConfig } from "../../config/boot-config-store";
import {
  CLOUD_HANDOFF_RETRY_EVENT,
  type CloudHandoffRetryDetail,
  dispatchCloudHandoffPhase,
} from "../../events";
import {
  createPersistedActiveServer,
  loadPersistedActiveServer,
  type PersistedActiveServer,
} from "../../state/persistence";
import { isPersonalSharedElizaId } from "../../utils/cloud-agent-base";
import { reportRendererDiagnostic } from "../../utils/renderer-diagnostics";
import {
  clearPendingCloudHandoffIfCurrent,
  isPendingCloudHandoffCurrent,
  loadPendingCloudHandoff,
  type PendingCloudHandoff,
  savePendingCloudHandoffIfCurrent,
} from "./pending-handoff-store";
import { runCloudAgentHandoff } from "./run-cloud-agent-handoff";
import { silentlyRepointToDedicated } from "./silent-repoint";

let resumeAttemptedThisSession = false;
/** Live dead-target Retry listeners, abortable on relaunch/test reset. */
const deadTargetRetryListeners = new Set<AbortController>();

/** Test-only: allow a fresh resume attempt in the next call. */
export function __resetResumeForTests(): void {
  resumeAttemptedThisSession = false;
  for (const ac of deadTargetRetryListeners) ac.abort();
  deadTargetRetryListeners.clear();
}

function activeServerAuthorityMatches(
  current: PersistedActiveServer | null,
  expected: PersistedActiveServer,
): boolean {
  return (
    current?.kind === expected.kind &&
    current.id === expected.id &&
    current.apiBase === expected.apiBase &&
    current.accessToken === expected.accessToken &&
    current.cloudRuntimeAgentId === expected.cloudRuntimeAgentId &&
    current.cloudRuntime === expected.cloudRuntime
  );
}

function accountRuntimeAuthorityIsCurrent(
  authToken: string,
  active: PersistedActiveServer,
): boolean {
  return (
    getBootConfig().autoUpgradeSharedToDedicated === true &&
    getCloudAuthToken(client) === authToken &&
    activeServerAuthorityMatches(loadPersistedActiveServer(), active)
  );
}

function pendingResumeAuthorityIsCurrent(options: {
  authToken: string;
  active: PersistedActiveServer;
  pending: PendingCloudHandoff;
}): boolean {
  return (
    accountRuntimeAuthorityIsCurrent(options.authToken, options.active) &&
    isPendingCloudHandoffCurrent(options.pending)
  );
}

function supersededHandoffError(): Error {
  return new Error("Cloud handoff recovery was superseded by a newer session.");
}

type ResumedHandoffAuthority = {
  isCurrent(): boolean;
  publishCutover(containerBase: string): void;
  wasCutoverPublished(): boolean;
};

/** Own the exact Shared+marker → Dedicated+no-marker authority transition. */
function createResumedHandoffAuthority(options: {
  authToken: string;
  active: PersistedActiveServer;
  pending: PendingCloudHandoff;
}): ResumedHandoffAuthority {
  let dedicatedActive: PersistedActiveServer | null = null;
  let cutoverPublished = false;
  const isCurrent = () => {
    if (getBootConfig().autoUpgradeSharedToDedicated !== true) return false;
    if (getCloudAuthToken(client) !== options.authToken) return false;
    if (dedicatedActive) {
      return (
        activeServerAuthorityMatches(
          loadPersistedActiveServer(),
          dedicatedActive,
        ) && isPendingCloudHandoffCurrent(null)
      );
    }
    return (
      activeServerAuthorityMatches(
        loadPersistedActiveServer(),
        options.active,
      ) && isPendingCloudHandoffCurrent(options.pending)
    );
  };
  return {
    isCurrent,
    publishCutover: (containerBase) => {
      if (!isCurrent()) throw supersededHandoffError();
      const logicalAgentId = isPersonalSharedElizaId(
        options.pending.sharedAgentId,
      )
        ? options.pending.sharedAgentId
        : options.pending.dedicatedAgentId;
      const expectedDedicatedActive = createPersistedActiveServer({
        kind: "cloud",
        id: `cloud:${logicalAgentId}`,
        apiBase: containerBase,
        accessToken: options.authToken,
        cloudRuntimeAgentId: options.pending.dedicatedAgentId,
        cloudRuntime: "dedicated",
      });
      silentlyRepointToDedicated({
        containerBase,
        dedicatedAgentId: options.pending.dedicatedAgentId,
        authToken: options.authToken,
        ...(isPersonalSharedElizaId(options.pending.sharedAgentId)
          ? { personalElizaId: options.pending.sharedAgentId }
          : {}),
      });
      // The call above synchronously publishes the Dedicated runtime and clears
      // the old marker. Transition the validator only after it returns.
      dedicatedActive = expectedDedicatedActive;
      cutoverPublished = true;
      if (!isCurrent()) throw supersededHandoffError();
    },
    wasCutoverPublished: () => cutoverPublished,
  };
}

/** Verify the target with the immutable base + bearer captured by this resume. */
async function dedicatedHandoffTargetState(options: {
  pending: PendingCloudHandoff;
  authToken: string;
  validateAuthority: () => boolean;
}): Promise<"gone" | "invalid" | "live" | "unknown"> {
  if (!options.validateAuthority()) return "unknown";
  try {
    const res = await getCloudCompatAgentWithExactAuthority({
      client,
      agentId: options.pending.dedicatedAgentId,
      cloudApiBase: options.pending.cloudApiBase,
      authToken: options.authToken,
      validateAuthority: options.validateAuthority,
    });
    return res.success ? "live" : "gone";
  } catch (err) {
    // A superseded read has no authority to classify or clean this marker.
    if (!options.validateAuthority()) return "unknown";
    if (
      (err as { code?: unknown } | null)?.code ===
      "CLOUD_HANDOFF_UNTRUSTED_API_BASE"
    ) {
      return "invalid";
    }
    const status = (err as { status?: unknown } | null)?.status;
    return status === 404 ? "gone" : "unknown";
  }
}

async function deleteSharedBridgeIfCurrent(options: {
  pending: PendingCloudHandoff;
  authToken: string;
  validateAuthority: () => boolean;
  diagnosticScope: string;
}): Promise<void> {
  if (!options.validateAuthority()) return;
  const res = await client.deleteSharedBridgeAgent(
    options.pending.sharedAgentId,
    {
      cloudApiBase: options.pending.cloudApiBase,
      authToken: options.authToken,
    },
  );
  if (!options.validateAuthority()) return;
  if (!res.success) {
    reportRendererDiagnostic({
      scope: options.diagnosticScope,
      error: new Error(res.error ?? "Shared bridge cleanup failed"),
      severity: "warning",
      context: { sharedAgentId: options.pending.sharedAgentId },
    });
  }
}

function startAuthorizedHandoff(options: {
  pending: PendingCloudHandoff;
  authToken: string;
  active: PersistedActiveServer;
  compensateFreshTargetIfSuperseded?: () => Promise<void>;
  cleanupDiagnosticScope: string;
}): void {
  const authority = createResumedHandoffAuthority(options);
  let compensation: Promise<void> | null = null;
  const compensateIfNeeded = async (): Promise<void> => {
    if (
      authority.isCurrent() ||
      authority.wasCutoverPublished() ||
      !options.compensateFreshTargetIfSuperseded
    ) {
      return;
    }
    compensation ??= options.compensateFreshTargetIfSuperseded();
    await compensation;
  };
  const start = async () => {
    if (!authority.isCurrent()) throw supersededHandoffError();
    try {
      const result = await client.startCloudAgentHandoff({
        agentId: options.pending.sharedAgentId,
        sharedApiBase: options.pending.sharedApiBase,
        conversationId: options.pending.sharedAgentId,
        dedicatedAgentId: options.pending.dedicatedAgentId,
        cloudApiBase: options.pending.cloudApiBase,
        authToken: options.authToken,
        validateAuthority: authority.isCurrent,
        onSwitch: async (containerBase) => {
          authority.publishCutover(containerBase);
        },
      });
      await compensateIfNeeded();
      if (!authority.isCurrent()) throw supersededHandoffError();
      return result;
    } catch (error) {
      try {
        await compensateIfNeeded();
      } catch (cleanupError) {
        const aggregate = new AggregateError(
          [error, cleanupError],
          "The superseded resumed handoff target could not be conditionally removed.",
        );
        reportRendererDiagnostic({
          scope: "cloud-handoff.superseded-fresh-target-cleanup",
          error: aggregate,
          severity: "error",
          context: {
            sharedAgentId: options.pending.sharedAgentId,
            dedicatedAgentId: options.pending.dedicatedAgentId,
          },
        });
        throw aggregate;
      }
      throw error;
    }
  };
  runCloudAgentHandoff(
    options.pending.sharedAgentId,
    start,
    () =>
      deleteSharedBridgeIfCurrent({
        pending: options.pending,
        authToken: options.authToken,
        validateAuthority: authority.isCurrent,
        diagnosticScope: options.cleanupDiagnosticScope,
      }),
    authority.isCurrent,
  );
}

/** Resume an interrupted shared→dedicated handoff after a reload/relaunch. */
export function resumePendingCloudHandoff(): boolean {
  if (resumeAttemptedThisSession) return false;

  const pending = loadPendingCloudHandoff();
  if (!pending) return false;
  resumeAttemptedThisSession = true;

  if (getBootConfig().autoUpgradeSharedToDedicated !== true) {
    clearPendingCloudHandoffIfCurrent(pending);
    return false;
  }

  const active = loadPersistedActiveServer();
  if (active?.kind !== "cloud" || !active.apiBase) {
    clearPendingCloudHandoffIfCurrent(pending);
    return false;
  }
  const activeAgentId = active.id.startsWith("cloud:")
    ? active.id.slice("cloud:".length)
    : active.id;
  if (
    activeAgentId !== pending.sharedAgentId ||
    !isDirectCloudSharedAgentBase(active.apiBase) ||
    pending.sharedApiBase !== active.apiBase
  ) {
    // The persisted marker is untrusted input. The transcript bearer may only
    // be sent back to the exact trusted Shared runtime already selected by the
    // active-server authority; never follow a second marker-controlled base.
    clearPendingCloudHandoffIfCurrent(pending);
    return false;
  }

  const authToken = getCloudAuthToken(client) ?? "";
  if (!authToken) {
    // Cloud auth not restored yet — keep the marker; a later boot retries.
    resumeAttemptedThisSession = false;
    return false;
  }
  if (active.accessToken !== authToken) {
    // A newer Steward token can publish before its runtime selection. Never
    // borrow that account-B bearer for account A's persisted marker; keep the
    // marker until the active-server transaction converges and retry later.
    resumeAttemptedThisSession = false;
    return false;
  }

  const validatePendingAuthority = () =>
    pendingResumeAuthorityIsCurrent({ authToken, active, pending });
  void dedicatedHandoffTargetState({
    pending,
    authToken,
    validateAuthority: validatePendingAuthority,
  }).then((state) => {
    if (!validatePendingAuthority()) {
      // Let the new owner make its own resume decision if it calls again.
      resumeAttemptedThisSession = false;
      return;
    }
    if (state === "invalid") {
      clearPendingCloudHandoffIfCurrent(pending);
      reportRendererDiagnostic({
        scope: "cloud-handoff.untrusted-recovery-base",
        error: new Error("Pending handoff uses an untrusted Cloud API base"),
        severity: "warning",
        context: { cloudApiBase: pending.cloudApiBase },
      });
      return;
    }
    if (state === "gone") {
      if (!clearPendingCloudHandoffIfCurrent(pending)) return;
      const validateDeadTargetRetryAuthority = () =>
        accountRuntimeAuthorityIsCurrent(authToken, active) &&
        isPendingCloudHandoffCurrent(null);
      if (!validateDeadTargetRetryAuthority()) return;
      reportRendererDiagnostic({
        scope: "cloud-handoff.target-gone",
        error: new Error("Dedicated handoff target is no longer available"),
        severity: "warning",
        context: { dedicatedAgentId: pending.dedicatedAgentId },
      });
      dispatchCloudHandoffPhase({
        agentId: pending.sharedAgentId,
        phase: "failed",
        error: "Dedicated agent target is no longer available.",
      });
      armFreshRetryForDeadTarget({
        pending,
        authToken,
        active,
        validateAuthority: validateDeadTargetRetryAuthority,
      });
      return;
    }
    startAuthorizedHandoff({
      pending,
      authToken,
      active,
      cleanupDiagnosticScope: "cloud-handoff.shared-bridge-cleanup",
    });
  });
  return true;
}

const DEAD_TARGET_RETRY_TTL_MS = 10 * 60_000;

function armFreshRetryForDeadTarget(options: {
  pending: PendingCloudHandoff;
  authToken: string;
  active: PersistedActiveServer;
  validateAuthority: () => boolean;
}): void {
  if (typeof window === "undefined" || !options.validateAuthority()) return;
  const ac = new AbortController();
  deadTargetRetryListeners.add(ac);
  ac.signal.addEventListener(
    "abort",
    () => deadTargetRetryListeners.delete(ac),
    { once: true },
  );
  const ttl = setTimeout(() => ac.abort(), DEAD_TARGET_RETRY_TTL_MS);
  const onRetry = (event: Event) => {
    const detail = (event as CustomEvent<CloudHandoffRetryDetail>).detail;
    if (detail?.agentId !== options.pending.sharedAgentId) return;
    clearTimeout(ttl);
    ac.abort();
    if (!options.validateAuthority()) return;
    void runFreshDedicatedHandoff(options);
  };
  window.addEventListener(CLOUD_HANDOFF_RETRY_EVENT, onRetry, {
    signal: ac.signal,
  });
}

async function compensateFreshRetryTarget(options: {
  pending: PendingCloudHandoff;
  authToken: string;
  created: Awaited<
    ReturnType<typeof createFreshDedicatedCloudCompatAgentWithExactAuthority>
  >;
  marker?: PendingCloudHandoff;
}): Promise<void> {
  try {
    const removed = await compensateFreshCloudCompatAgentCreate({
      client,
      cloudApiBase: options.pending.cloudApiBase,
      authToken: options.authToken,
      created: options.created.created,
      agentId: options.created.data.agentId,
      agentName: options.created.data.agentName,
      createdAt: options.created.data.createdAt,
      executionTier: options.created.data.executionTier,
    });
    if (!removed) {
      throw new Error(
        "The fresh Retry target did not include a complete conditional-cleanup receipt.",
      );
    }
  } finally {
    // Retire only this exact stale instruction even when the external cleanup
    // fails. A marker B is deliberately left untouched by the CAS.
    if (options.marker) {
      clearPendingCloudHandoffIfCurrent(options.marker);
    }
  }
}

async function compensateFreshRetryTargetOrReport(
  options: Parameters<typeof compensateFreshRetryTarget>[0],
): Promise<void> {
  try {
    await compensateFreshRetryTarget(options);
  } catch (error) {
    // Stale A must not publish a UI failure over B, but a failed exact cleanup
    // is operationally material: retain a durable renderer diagnostic so the
    // potentially leaked fresh target is never silently masked.
    reportRendererDiagnostic({
      scope: "cloud-handoff.fresh-retry-compensation",
      error,
      severity: "error",
      context: {
        sharedAgentId: options.pending.sharedAgentId,
        dedicatedAgentId: options.created.data.agentId,
      },
    });
    throw error;
  }
}

/** Mint a fresh target only behind the explicit dead-target Retry event. */
async function runFreshDedicatedHandoff(options: {
  pending: PendingCloudHandoff;
  authToken: string;
  active: PersistedActiveServer;
  validateAuthority: () => boolean;
}): Promise<void> {
  if (!options.validateAuthority()) return;
  try {
    const created =
      await createFreshDedicatedCloudCompatAgentWithExactAuthority({
        client,
        cloudApiBase: options.pending.cloudApiBase,
        authToken: options.authToken,
        agentName: "Eliza",
        validateAuthority: options.validateAuthority,
      });
    if (!created.authorityCurrent || !options.validateAuthority()) {
      await compensateFreshRetryTargetOrReport({
        pending: options.pending,
        authToken: options.authToken,
        created,
      });
      return;
    }
    if (!created.success || !created.data.agentId) {
      await compensateFreshRetryTargetOrReport({
        pending: options.pending,
        authToken: options.authToken,
        created,
      });
      if (options.validateAuthority()) {
        dispatchCloudHandoffPhase({
          agentId: options.pending.sharedAgentId,
          phase: "failed",
          error:
            created.data.message ?? "Failed to create a fresh dedicated agent.",
        });
      }
      return;
    }
    const freshMarker: PendingCloudHandoff = {
      sharedAgentId: options.pending.sharedAgentId,
      dedicatedAgentId: created.data.agentId,
      sharedApiBase: options.pending.sharedApiBase,
      cloudApiBase: options.pending.cloudApiBase,
      startedAt: Date.now(),
    };
    if (
      !options.validateAuthority() ||
      !savePendingCloudHandoffIfCurrent(null, freshMarker)
    ) {
      await compensateFreshRetryTargetOrReport({
        pending: options.pending,
        authToken: options.authToken,
        created,
      });
      return;
    }
    startAuthorizedHandoff({
      pending: freshMarker,
      authToken: options.authToken,
      active: options.active,
      compensateFreshTargetIfSuperseded: () =>
        compensateFreshRetryTarget({
          pending: options.pending,
          authToken: options.authToken,
          created,
          marker: freshMarker,
        }),
      cleanupDiagnosticScope: "cloud-handoff.fresh-shared-bridge-cleanup",
    });
  } catch (err) {
    if (!options.validateAuthority()) return;
    dispatchCloudHandoffPhase({
      agentId: options.pending.sharedAgentId,
      phase: "failed",
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
