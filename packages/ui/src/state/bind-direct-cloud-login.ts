/**
 * Converts a direct Cloud account login into the durable personal-agent target
 * used by desktop startup, chat routing, and runtime-switch surfaces.
 */

import { writeStoredStewardToken } from "@elizaos/shared/steward-session-client";
import { persistAgentProfileConnectionDurably } from "./agent-profiles";
import { createPersistedActiveServer } from "./persistence";

interface DirectCloudBindingClient {
  ensurePersonalDedicatedEliza(options: {
    cloudApiBase: string;
    authToken: string;
  }): Promise<{
    personalElizaId: string;
    activeAgentId: string;
    agentName: string;
    apiBase: string;
    runtime: "dedicated";
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

/** Exact composite rollback retained across the caller's first await boundary. */
export interface DirectCloudBindingAuthority {
  restoreIfCurrent(): Promise<void>;
}

export async function bindDirectCloudLoginToPersonalAgent(options: {
  client: DirectCloudBindingClient;
  cloudApiBase: string;
  token: string;
  validate?: () => boolean;
  /** Publish synchronous boot metadata and return its exact rollback. */
  finalize?: () => undefined | (() => void);
  /** Retire the recovery receipt after staging and before all authority events. */
  commitBeforePublish?: () => boolean;
}): Promise<DirectCloudBindingAuthority | null> {
  if (options.validate?.() === false) return null;
  const personal = await options.client.ensurePersonalDedicatedEliza({
    cloudApiBase: options.cloudApiBase,
    authToken: options.token,
  });
  if (options.validate?.() === false) return null;
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
      validate: options.validate,
      finalize: async () => {
        if (options.validate?.() === false) return false;
        tokenAuthority = await writeStoredStewardToken(options.token, {
          validate: options.validate,
          finalizeBeforePublish: () => {
            sessionTargetAuthority = options.client.stageSessionTarget(
              { baseUrl: agentApiBase, token: options.token },
              { persist: false },
            );
            if (!sessionTargetAuthority) {
              throw new Error(
                "The production Cloud agent target was rejected by the active client authority.",
              );
            }
            try {
              // Staging installs apiToken in boot config without events. The
              // caller then derives its final cloud metadata from that exact
              // object, so its identity-CAS rollback remains valid.
              rollbackFinalizer = options.finalize?.() ?? null;
            } catch (error) {
              sessionTargetAuthority.restoreIfCurrent();
              throw error;
            }
            return (durableRestored) =>
              rollbackStagedFinalization(durableRestored);
          },
          commitBeforePublish: () => {
            if (options.commitBeforePublish?.() === false) return false;
            return sessionTargetAuthority?.publish() === true;
          },
        });
        if (options.validate?.() === false) return false;
        return true;
      },
      compensateFinalization,
      captureCompensation: (compensate) => {
        compensateCommittedConnection = compensate;
      },
    },
  );
  if (!profile) {
    if (options.validate?.() === false) return null;
    throw new Error("The production Cloud agent target could not be saved.");
  }
  if (!compensateCommittedConnection) {
    throw new Error("The production Cloud binding rollback is unavailable.");
  }
  let live = true;
  return {
    restoreIfCurrent: async () => {
      if (!live) return;
      live = false;
      await compensateCommittedConnection?.();
    },
  };
}
