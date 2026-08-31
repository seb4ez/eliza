/**
 * Converts a direct Cloud account login into the durable personal-agent target
 * used by desktop startup, chat routing, and runtime-switch surfaces.
 */

import {
  type StewardTokenPublicationRollback,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { persistAgentProfileConnectionDurably } from "./agent-profiles";
import { createPersistedActiveServer } from "./persistence";

export interface DirectCloudBindingClient {
  getPersonalSharedEliza(options: {
    cloudApiBase: string;
    authToken: string;
    signal?: AbortSignal;
  }): Promise<{
    personalElizaId: string;
    activeAgentId: string;
    agentName: string;
    apiBase: string;
    runtime: "shared" | "dedicated";
  }>;
  stageSessionTarget(
    target: { baseUrl: string; token: string },
    options?: { persist?: boolean },
  ): {
    publish(): boolean;
    restoreIfCurrent(): boolean;
    clearIfCurrent(): boolean;
  } | null;
}

export interface DirectCloudPersonalAgent {
  personalElizaId: string;
  agentId: string;
  activeAgentId: string;
  agentName: string;
  apiBase: string;
  runtime: "shared" | "dedicated";
}

/** Exact composite rollback retained across the caller's first await boundary. */
export interface DirectCloudBindingAuthority {
  /** Exact read-only personal-runtime selection committed by this authority. */
  result: DirectCloudPersonalAgent;
  restoreIfCurrent(): Promise<void>;
}

export async function bindDirectCloudLoginToPersonalAgent(options: {
  client: DirectCloudBindingClient;
  cloudApiBase: string;
  token: string;
  signal?: AbortSignal;
  validate?: () => boolean;
  /** Publish synchronous boot metadata and return its exact rollback. */
  finalize?: () => undefined | (() => void);
  /** Rollbackably retire recovery proof before all authority events. */
  finalizeRecoveryBeforePublish?: () => StewardTokenPublicationRollback;
}): Promise<DirectCloudBindingAuthority | null> {
  const validateAuthority = () =>
    !options.signal?.aborted && (options.validate?.() ?? true);
  options.signal?.throwIfAborted();
  if (!validateAuthority()) return null;
  const personal = await options.client.getPersonalSharedEliza({
    cloudApiBase: options.cloudApiBase,
    authToken: options.token,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  options.signal?.throwIfAborted();
  if (!validateAuthority()) return null;
  const server = createPersistedActiveServer({
    kind: "cloud",
    id: `cloud:${personal.personalElizaId}`,
    label: personal.agentName,
    apiBase: personal.apiBase,
    accessToken: options.token,
    cloudRuntimeAgentId: personal.activeAgentId,
    cloudRuntime: personal.runtime,
  });
  if (!server.apiBase) {
    throw new Error("The production Cloud agent target could not be saved.");
  }
  const agentApiBase = server.apiBase;
  let tokenAuthority: Awaited<ReturnType<typeof writeStoredStewardToken>> =
    null;
  let sessionTargetAuthority: {
    publish(): boolean;
    restoreIfCurrent(): boolean;
    clearIfCurrent(): boolean;
  } | null = null;
  let rollbackFinalizer: (() => void) | null = null;
  let finalizationRolledBack = false;
  const rollbackStagedFinalization = (restorePredecessor: boolean): void => {
    if (finalizationRolledBack) return;
    finalizationRolledBack = true;
    rollbackFinalizer?.();
    if (restorePredecessor) sessionTargetAuthority?.restoreIfCurrent();
    else sessionTargetAuthority?.clearIfCurrent();
  };
  let compensation: Promise<void> | null = null;
  let compensateCommittedConnection: (() => Promise<void>) | null = null;
  const compensateFinalization = (): Promise<void> => {
    if (compensation) return compensation;
    compensation = (async () => {
      const failures: unknown[] = [];
      let tokenRestored = false;
      try {
        tokenRestored =
          (await tokenAuthority?.restorePredecessor({
            deferPublication: true,
          })) === true;
      } catch (error) {
        failures.push(error);
      }
      if (tokenRestored) {
        if (!tokenAuthority?.publish?.()) {
          failures.push(
            new Error("Restored Steward authority could not be published."),
          );
        }
      } else {
        try {
          // If a newer durable token won, never reintroduce A in the client.
          rollbackStagedFinalization(false);
        } catch (error) {
          failures.push(error);
        }
      }
      if (failures.length > 0) {
        throw new AggregateError(
          failures,
          "Direct Cloud binding finalization could not be compensated",
        );
      }
    })();
    return compensation;
  };
  const profile = await persistAgentProfileConnectionDurably(
    {
      kind: "cloud",
      label: server.label,
      cloudAgentId: personal.personalElizaId,
      cloudRuntimeAgentId: personal.activeAgentId,
      cloudRuntime: personal.runtime,
      apiBase: agentApiBase,
      accessToken: options.token,
    },
    server,
    {
      validate: validateAuthority,
      finalize: async (storageTransaction) => {
        if (!validateAuthority()) return false;
        tokenAuthority = await writeStoredStewardToken(options.token, {
          ...(storageTransaction
            ? { hostPersistenceContext: storageTransaction }
            : {}),
          validate: validateAuthority,
          finalizeBeforePublish: () => {
            const rollbackRecovery =
              options.finalizeRecoveryBeforePublish?.() ?? null;
            try {
              sessionTargetAuthority = options.client.stageSessionTarget(
                { baseUrl: agentApiBase, token: options.token },
                { persist: false },
              );
              if (!sessionTargetAuthority) {
                throw new Error(
                  "The production Cloud agent target was rejected by the active client authority.",
                );
              }
              // Staging installs apiToken in boot config without events. The
              // caller then derives its final cloud metadata from that exact
              // object, so its identity-CAS rollback remains valid.
              rollbackFinalizer = options.finalize?.() ?? null;
            } catch (error) {
              try {
                sessionTargetAuthority?.restoreIfCurrent();
              } finally {
                rollbackRecovery?.(false);
              }
              throw error;
            }
            const rollbackPublication = ((durableRestored: boolean) => {
              try {
                rollbackStagedFinalization(durableRestored);
              } finally {
                rollbackRecovery?.(durableRestored);
              }
            }) as StewardTokenPublicationRollback;
            rollbackPublication.beforeDurableRestore = () => {
              rollbackRecovery?.beforeDurableRestore?.();
            };
            return rollbackPublication;
          },
          commitBeforePublish: () => {
            return sessionTargetAuthority?.publish() === true;
          },
        });
        if (!tokenAuthority || !validateAuthority()) return false;
        return true;
      },
      compensateFinalization,
      captureCompensation: (compensate) => {
        compensateCommittedConnection = compensate;
      },
    },
  );
  if (!profile) {
    if (!validateAuthority()) {
      options.signal?.throwIfAborted();
      return null;
    }
    throw new Error("The production Cloud agent target could not be saved.");
  }
  const compensateCommitted = compensateCommittedConnection as
    | (() => Promise<void>)
    | null;
  if (!compensateCommitted) {
    throw new Error("The production Cloud binding rollback is unavailable.");
  }
  if (!validateAuthority()) {
    await compensateCommitted();
    options.signal?.throwIfAborted();
    return null;
  }
  let live = true;
  return {
    result: {
      personalElizaId: personal.personalElizaId,
      agentId: personal.personalElizaId,
      activeAgentId: personal.activeAgentId,
      agentName: personal.agentName || "Eliza",
      apiBase: agentApiBase,
      runtime: personal.runtime,
    },
    restoreIfCurrent: async () => {
      if (!live) return;
      live = false;
      await compensateCommitted();
    },
  };
}
