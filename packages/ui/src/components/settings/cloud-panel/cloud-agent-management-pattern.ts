/**
 * Owns the shared cloud-agent management lifecycle used by both settings presentations.
 * Callers provide the management-token boundary and retain their own rendering contracts.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { client, ElizaClient } from "../../../api";
import {
  cleanupFreshCloudCompatAgentCreate,
  resolveCloudAgentApiBase,
} from "../../../api/client-cloud";
import type { CloudCompatAgent } from "../../../api/client-types-cloud";
import { getBootConfig } from "../../../config/boot-config";
import { useBranding } from "../../../config/branding";
import { useAppSelector } from "../../../state";
import { persistAgentProfileConnectionDurably } from "../../../state/agent-profiles";
import { clearStalePairCredentialsForAgent } from "../../../state/cloud-pair-token";
import {
  createPersistedActiveServer,
  loadPersistedActiveServer,
} from "../../../state/persistence";
import {
  type CloudManagementAuthority,
  captureCloudManagementAuthority,
  subscribeToCloudManagementCredential,
} from "./cloud-management-auth";

const DELETE_POLL_TIMEOUT_MS = 60_000;
const DELETE_POLL_INTERVAL_MS = 1_500;
const STATUS_POLL_INTERVAL_MS = 3_000;
const STATUS_POLL_ATTEMPTS = 5;
const WAKE_POLL_TIMEOUT_MS = 60_000;
const WAKE_POLL_INTERVAL_MS = 2_000;
const NON_RUNNING_STATES = new Set(["stopped", "sleeping", "suspended"]);
const ERROR_STATES = new Set(["error", "failed"]);
const MANAGEMENT_AUTHORITY_REQUIRED =
  "Your Eliza Cloud sign-in is changing. Wait for it to finish and try again.";

interface ConnectionCompensationRef {
  current: (() => Promise<void>) | null;
}

async function retainCommittedConnectionOnlyWhileCurrent(
  authority: CloudManagementAuthority,
  compensation: ConnectionCompensationRef,
  operation: string,
): Promise<boolean> {
  if (authority.isCurrent()) return true;
  if (!compensation.current) {
    throw new AggregateError(
      [new Error("The committed connection rollback was not captured.")],
      `${operation} lost authority after persistence and could not restore its predecessor.`,
    );
  }
  try {
    await compensation.current();
  } catch (rollbackError) {
    throw new AggregateError(
      [rollbackError],
      `${operation} lost authority after persistence and predecessor rollback failed.`,
    );
  }
  return false;
}

function isTransientManagementStatusPollError(error: unknown): boolean {
  const record =
    error && typeof error === "object"
      ? (error as { code?: unknown; status?: unknown })
      : null;
  if (record?.code === "STEWARD_SESSION_SUPERSEDED") return false;
  if (typeof record?.status !== "number") return true;
  return (
    record.status === 408 ||
    record.status === 409 ||
    record.status === 423 ||
    record.status === 429 ||
    record.status >= 500
  );
}

function activeCloudAgentId(): string | null {
  const active = loadPersistedActiveServer();
  if (active?.kind !== "cloud") return null;
  const id = active.id?.startsWith("cloud:")
    ? active.id.slice("cloud:".length)
    : "";
  return id && !id.includes("/") ? id : null;
}

export function useCloudAgentManagement(getManagementToken: () => string) {
  const elizaCloudConnected = useAppSelector((s) => s.elizaCloudConnected);
  const setActionNotice = useAppSelector((s) => s.setActionNotice);
  const { appName } = useBranding();
  const [agents, setAgents] = useState<CloudCompatAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  // The agent currently being woken (resumed + readiness-polled) before we
  // switch to it. Drives the "Waking <name>…" row state.
  const [wakingId, setWakingId] = useState<string | null>(null);
  const refreshRequestIdRef = useRef(0);
  const managementAuthorityKeyRef = useRef<string | null | undefined>(
    undefined,
  );
  const [activeId, setActiveId] = useState<string | null>(() =>
    activeCloudAgentId(),
  );

  const cloudApiBase = getBootConfig().cloudApiBase || "https://eliza.app";

  const captureManagementAuthority = useCallback(
    () => captureCloudManagementAuthority(getManagementToken, cloudApiBase),
    [getManagementToken, cloudApiBase],
  );

  const refresh = useCallback(async () => {
    const authority = captureManagementAuthority();
    if (!authority?.isCurrent()) {
      setLoading(false);
      setLoadError(MANAGEMENT_AUTHORITY_REQUIRED);
      return;
    }
    const requestId = ++refreshRequestIdRef.current;
    const ownsRefreshState = () => refreshRequestIdRef.current === requestId;
    const ownsAuthority = () => ownsRefreshState() && authority.isCurrent();
    setLoading(true);
    setLoadError(null);
    try {
      const res = await client.getCloudCompatAgents(authority);
      if (!ownsAuthority()) return;
      // A failed fetch is NOT an empty list — surface it so the user can retry
      // instead of seeing the indistinguishable "No cloud agents yet" copy.
      if (!res.success) {
        setLoadError(res.error || "Could not load your cloud agents.");
        return;
      }
      const list = [...res.data];
      list.sort((a, b) =>
        String(b.created_at).localeCompare(String(a.created_at)),
      );
      setAgents((previous) => (authority.isCurrent() ? list : previous));
    } catch (err) {
      if (!ownsAuthority()) return;
      setLoadError(
        err instanceof Error
          ? err.message
          : "Could not load your cloud agents.",
      );
    } finally {
      if (ownsAuthority()) setLoading(false);
    }
  }, [captureManagementAuthority]);

  useEffect(() => {
    const reconcileAuthority = () => {
      const authority = captureManagementAuthority();
      const authorityKey = authority
        ? `${authority.recoveryGeneration}\u0000${authority.apiBase}\u0000${authority.token}`
        : null;
      if (managementAuthorityKeyRef.current === authorityKey) return;
      managementAuthorityKeyRef.current = authorityKey;

      // Invalidate every account-A continuation before clearing its visible
      // state. The same event may be emitted more than once; the exact key
      // above coalesces it and starts exactly one refresh for clean account B.
      refreshRequestIdRef.current += 1;
      setAgents([]);
      setBusyId(null);
      setWakingId(null);
      setCreating(false);
      setCreateError(null);
      setNewName("");
      setEditingId(null);
      setEditName("");
      setActiveId(activeCloudAgentId());
      if (!authority) {
        setLoading(false);
        setLoadError(MANAGEMENT_AUTHORITY_REQUIRED);
        return;
      }
      setLoading(true);
      setLoadError(null);
      void refresh();
    };

    reconcileAuthority();
    const unsubscribe =
      subscribeToCloudManagementCredential(reconcileAuthority);
    return () => {
      refreshRequestIdRef.current += 1;
      unsubscribe();
    };
  }, [captureManagementAuthority, refresh]);

  const setLocalStatus = useCallback(
    (agentId: string, status: string, authority?: CloudManagementAuthority) => {
      setAgents((prev) =>
        authority && !authority.isCurrent()
          ? prev
          : prev.map((a) => (a.agent_id === agentId ? { ...a, status } : a)),
      );
    },
    [],
  );

  const bindAndReload = useCallback(
    async (
      agentId: string,
      apiBase: string,
      label: string,
      authority: CloudManagementAuthority,
      notice?: string,
    ) => {
      if (!authority.isCurrent()) return false;
      const token = authority.token;
      const persisted = createPersistedActiveServer({
        kind: "cloud",
        id: `cloud:${agentId}`,
        apiBase,
        ...(token ? { accessToken: token } : {}),
        label,
      });
      if (!authority.isCurrent()) return false;
      const compensation: ConnectionCompensationRef = { current: null };
      const profile = await persistAgentProfileConnectionDurably(
        {
          kind: "cloud",
          label,
          cloudAgentId: agentId,
          ...(persisted.apiBase !== undefined
            ? { apiBase: persisted.apiBase }
            : {}),
          ...(token ? { accessToken: token } : {}),
        },
        persisted,
        {
          validate: authority.validateAuthority,
          captureCompensation: (rollback) => {
            compensation.current = rollback;
          },
        },
      );
      if (!profile) return false;
      if (
        !(await retainCommittedConnectionOnlyWhileCurrent(
          authority,
          compensation,
          "Cloud agent binding",
        ))
      ) {
        return false;
      }
      setActionNotice(
        notice ?? `Switched to ${label}. Reloading…`,
        "success",
        3000,
      );
      // Re-boot the web app so startup restore re-binds the client + chat to
      // the newly-selected agent (same path a returning user takes).
      if (!authority.isCurrent()) return false;
      setTimeout(() => {
        if (authority.isCurrent()) window.location.reload();
      }, 250);
      return true;
    },
    [setActionNotice],
  );

  /**
   * Resume a non-running agent and gate entry on a short readiness poll, so we
   * only hand the user a live container. Resolves `true` once the agent reports
   * `running`; resolves `false` (with the failure surfaced) if the resume call
   * is rejected. Throws on timeout so the caller can decide whether to enter
   * anyway. Mirrors the delete-job poll loop.
   */
  const wakeUntilRunning = useCallback(
    async (agent: CloudCompatAgent, authority: CloudManagementAuthority) => {
      if (!authority.isCurrent()) return null;
      const res = await client.resumeCloudCompatAgent(
        agent.agent_id,
        authority,
      );
      if (!authority.isCurrent()) return null;
      if (!res.success) {
        return { ok: false as const, error: "Start failed" };
      }
      setLocalStatus(agent.agent_id, "resuming", authority);
      const deadline = Date.now() + WAKE_POLL_TIMEOUT_MS;
      while (Date.now() < deadline) {
        if (!authority.isCurrent()) return null;
        await new Promise((resolve) =>
          setTimeout(resolve, WAKE_POLL_INTERVAL_MS),
        );
        if (!authority.isCurrent()) return null;
        const statusRes = await client.getCloudCompatAgentStatus(
          agent.agent_id,
          authority,
        );
        if (!authority.isCurrent()) return null;
        const status = statusRes.success
          ? statusRes.data.status.toLowerCase()
          : "";
        if (status) setLocalStatus(agent.agent_id, status, authority);
        if (status === "running") return { ok: true as const };
        if (ERROR_STATES.has(status)) {
          return {
            ok: false as const,
            error: statusRes.data.suspendedReason || "Agent failed to start.",
          };
        }
      }
      throw new Error("Timed out waiting for the agent to start.");
    },
    [setLocalStatus],
  );

  const switchTo = useCallback(
    async (agent: CloudCompatAgent) => {
      if (agent.agent_id === activeId) return;
      const authority = captureManagementAuthority();
      if (!authority?.isCurrent()) {
        setActionNotice(MANAGEMENT_AUTHORITY_REQUIRED, "error", 5000);
        return;
      }
      const apiBase = resolveCloudAgentApiBase({
        bridgeUrl: agent.bridge_url,
        webUiUrl: agent.web_ui_url ?? agent.webUiUrl,
        agentId: agent.agent_id,
        cloudApiBase,
      });
      const label = agent.agent_name || "Eliza Cloud";
      const status = (agent.status || "").toLowerCase();
      if (ERROR_STATES.has(status)) {
        setActionNotice(
          agent.error_message ||
            `${label} failed to start. Resolve the failure before connecting.`,
          "error",
          5000,
        );
        return;
      }
      // A non-running agent has no live container to talk to — wake it and
      // wait for readiness before binding, so chat doesn't land on a 404.
      if (NON_RUNNING_STATES.has(status)) {
        setBusyId(agent.agent_id);
        setWakingId(agent.agent_id);
        setActionNotice(`Waking ${label}…`, "success", 3000);
        try {
          const outcome = await wakeUntilRunning(agent, authority);
          if (!authority.isCurrent() || outcome === null) return;
          if (!outcome.ok) {
            setActionNotice(outcome.error, "error", 4000);
            setBusyId(null);
            return;
          }
        } catch (err) {
          if (!authority.isCurrent()) return;
          // Readiness timed out — surface it and let the user retry rather
          // than binding to a container that may still be coming up.
          setActionNotice(
            err instanceof Error ? err.message : "Failed to start agent.",
            "error",
            4000,
          );
          setBusyId(null);
          return;
        } finally {
          if (authority.isCurrent()) setWakingId(null);
        }
      } else {
        setBusyId(agent.agent_id);
      }
      try {
        if (!authority.isCurrent()) return;
        // Probe with an isolated client. Mutating the shared singleton or the
        // persisted target before this succeeds would strand the whole shell
        // on a failed/unreachable agent after reload.
        const targetClient = new ElizaClient(apiBase, authority.token);
        await targetClient.listConversations();
        if (!authority.isCurrent()) return;
        const bound = await bindAndReload(
          agent.agent_id,
          apiBase,
          label,
          authority,
        );
        if (!bound && authority.isCurrent()) {
          throw new Error(
            "Could not durably save this Cloud agent. Your current agent is still active.",
          );
        }
      } catch (error) {
        if (!authority.isCurrent() && !(error instanceof AggregateError)) {
          return;
        }
        setActionNotice(
          error instanceof AggregateError && error.message
            ? error.message
            : `Could not connect to ${label}. Your current agent is still active.`,
          "error",
          5000,
        );
      } finally {
        if (authority.isCurrent()) setBusyId(null);
      }
    },
    [
      activeId,
      cloudApiBase,
      bindAndReload,
      setActionNotice,
      wakeUntilRunning,
      captureManagementAuthority,
    ],
  );

  const createAgent = useCallback(async () => {
    const name = newName.trim();
    if (!name) {
      const message = "Give your agent a name first.";
      setCreateError(message);
      setActionNotice(message, "error", 3000);
      return;
    }
    const managementAuthority = captureManagementAuthority();
    if (!managementAuthority?.isCurrent()) {
      const message = "Sign in to Eliza Cloud before creating an agent.";
      setCreateError(message);
      setActionNotice(message, "error", 4000);
      return;
    }
    setCreateError(null);
    setCreating(true);
    try {
      const result = await client.selectOrProvisionCloudAgent({
        cloudApiBase,
        authToken: managementAuthority.token,
        name,
        forceCreate: true,
        onProgress: () => {},
        validateAuthority: managementAuthority.validateAuthority,
        accountAuthority: managementAuthority,
      });
      const compensateSupersededResult = async (): Promise<boolean> => {
        // The client's final `ready` callback can enqueue login B in a
        // microtask before this await continuation resumes. Yield once, then
        // ask the captured A authority to conditionally clean up only A's
        // confirmed fresh create and restore its local token publication.
        await Promise.resolve();
        const publicationAuthority = result.authority ?? managementAuthority;
        if (publicationAuthority.isCurrent()) return false;
        try {
          await result.authority?.compensateIfSuperseded();
        } catch (cleanupError) {
          throw new AggregateError(
            [cleanupError],
            "The superseded Cloud agent could not be conditionally cleaned up.",
          );
        }
        // A newer login owns the renderer now. Compensation may clean up A's
        // accepted server mutation, but A must not publish UI into B.
        return true;
      };
      if (await compensateSupersededResult()) return;
      if (result.created !== true) {
        const message =
          "Eliza Cloud did not confirm that a new agent was created. No agent was opened; refresh your session and try again.";
        setCreateError(message);
        setActionNotice(message, "error", 7000);
        setCreating(false);
        return;
      } else {
        const publicationAuthority = result.authority ?? managementAuthority;
        if (!publicationAuthority.isCurrent()) {
          await compensateSupersededResult();
          return;
        }
        const validateBindingAuthority = () =>
          managementAuthority.isCurrent() && publicationAuthority.isCurrent();
        let bindingFailure: unknown = null;
        let bound = false;
        try {
          bound = await bindAndReload(result.agentId, result.apiBase, name, {
            ...managementAuthority,
            validateAuthority: validateBindingAuthority,
            isCurrent: validateBindingAuthority,
          });
        } catch (error) {
          bindingFailure = error;
        }
        if (!bound) {
          const persistenceError = new Error(
            "Could not durably save the new Cloud agent. The fresh agent was removed.",
          );
          if (!result.cleanupReceipt) {
            throw new AggregateError(
              [persistenceError, ...(bindingFailure ? [bindingFailure] : [])],
              "Cloud agent binding failed and its exact cleanup identity was unavailable.",
            );
          }
          try {
            await cleanupFreshCloudCompatAgentCreate({
              client,
              cloudApiBase: managementAuthority.apiBase,
              authToken: managementAuthority.token,
              agentId: result.agentId,
              cleanupReceipt: result.cleanupReceipt,
            });
          } catch (cleanupError) {
            throw new AggregateError(
              [
                persistenceError,
                ...(bindingFailure ? [bindingFailure] : []),
                cleanupError,
              ],
              "Cloud agent binding failed and conditional cleanup also failed.",
            );
          }
          if (bindingFailure) {
            throw new AggregateError(
              [persistenceError, bindingFailure],
              "Cloud agent binding lost authority, rollback failed, and the fresh agent was conditionally removed.",
            );
          }
          throw persistenceError;
        }
      }
    } catch (err) {
      // A successful stale compensation remains silent in account B. A failed
      // exact cleanup is account/billing critical and must still be surfaced;
      // swallowing it would leave a paid resource with no local binding.
      if (
        !managementAuthority.isCurrent() &&
        !(err instanceof AggregateError)
      ) {
        return;
      }
      const message =
        err instanceof Error ? err.message : "Failed to create agent.";
      setCreateError(message);
      setActionNotice(message, "error", 4000);
      setCreating(false);
    }
  }, [
    newName,
    cloudApiBase,
    bindAndReload,
    setActionNotice,
    captureManagementAuthority,
  ]);

  /**
   * Poll a delete job until it reaches a terminal state. Resolves `true` on a
   * completed teardown, `false` (with the failure surfaced) when the job
   * fails, and throws on timeout so the caller can fall back to a refresh.
   */
  const waitForDeleteJob = useCallback(
    async (jobId: string, authority: CloudManagementAuthority) => {
      const deadline = Date.now() + DELETE_POLL_TIMEOUT_MS;
      while (Date.now() < deadline) {
        if (!authority.isCurrent()) return null;
        const res = await client.getCloudCompatJobStatus(jobId, authority);
        if (!authority.isCurrent()) return null;
        const status = res.success ? res.data.status : "failed";
        if (status === "completed") return { ok: true as const };
        if (status === "failed") {
          return {
            ok: false as const,
            error: res.data.error || "Agent delete failed.",
          };
        }
        await new Promise((resolve) =>
          setTimeout(resolve, DELETE_POLL_INTERVAL_MS),
        );
      }
      throw new Error("Timed out waiting for the agent to be deleted.");
    },
    [],
  );

  const deleteAgent = useCallback(
    async (agent: CloudCompatAgent) => {
      // Destructive + irreversible — tears down the container and its data.
      // Confirm first (matches the window.confirm pattern in the other settings
      // sections: wallet keys, vault profiles, remote plugin hosts).
      if (
        !window.confirm(
          `Delete "${agent.agent_name || agent.agent_id}"? This permanently removes the agent and its data and can't be undone.`,
        )
      ) {
        return;
      }
      const authority = captureManagementAuthority();
      if (!authority?.isCurrent()) {
        setActionNotice(MANAGEMENT_AUTHORITY_REQUIRED, "error", 5000);
        return;
      }
      setBusyId(agent.agent_id);
      try {
        const res = await client.deleteCloudCompatAgent(
          agent.agent_id,
          undefined,
          authority,
        );
        if (!authority.isCurrent()) return;
        if (!res.success) {
          throw new Error(res.error || "Delete failed");
        }
        // A 202 async delete returns a jobId — the teardown may still fail
        // later, so poll the job and only drop the row once it actually
        // completes. A synchronous delete (no jobId) is already terminal.
        if (res.data.jobId) {
          const outcome = await waitForDeleteJob(res.data.jobId, authority);
          if (!authority.isCurrent() || outcome === null) return;
          if (!outcome.ok) {
            throw new Error(outcome.error);
          }
        }
        setAgents((prev) =>
          authority.isCurrent()
            ? prev.filter((a) => a.agent_id !== agent.agent_id)
            : prev,
        );
        if (!authority.isCurrent()) return;
        // Purge this agent's persisted pair credentials (durable pair key,
        // active-server token, profile accessTokens) so a deleted agent's
        // at-rest credentials are never re-adopted on a later boot. Scoped
        // to the deleted agent — other agents' credentials stay untouched.
        clearStalePairCredentialsForAgent(agent.agent_id);
        if (!authority.isCurrent()) return;
        setActionNotice(`Deleted ${agent.agent_name}.`, "success", 3000);
      } catch (err) {
        if (!authority.isCurrent()) return;
        setActionNotice(
          err instanceof Error ? err.message : "Failed to delete agent.",
          "error",
          4000,
        );
        // The teardown failed or timed out — re-sync so the row reflects the
        // real server state rather than a stale optimistic removal.
        void refresh();
      } finally {
        if (authority.isCurrent()) setBusyId(null);
      }
    },
    [setActionNotice, waitForDeleteJob, refresh, captureManagementAuthority],
  );

  const startRename = useCallback((agent: CloudCompatAgent) => {
    setEditingId(agent.agent_id);
    setEditName(agent.agent_name || "");
  }, []);

  const saveRename = useCallback(
    async (agent: CloudCompatAgent) => {
      const name = editName.trim();
      if (!name || name === agent.agent_name) {
        setEditingId(null);
        return;
      }
      const authority = captureManagementAuthority();
      if (!authority?.isCurrent()) {
        setActionNotice(MANAGEMENT_AUTHORITY_REQUIRED, "error", 5000);
        return;
      }
      setBusyId(agent.agent_id);
      try {
        const res = await client.updateCloudCompatAgent(
          agent.agent_id,
          { agentName: name },
          authority,
        );
        if (!authority.isCurrent()) return;
        if (!res.success) {
          throw new Error(res.error || "Rename failed");
        }
        // If we just renamed the agent bound as the active cloud server, refresh
        // the persisted label so the switcher/header reflect the new name without
        // waiting for a re-bind (mirrors how switchTo/create set the label).
        if (agent.agent_id === activeId) {
          const active = loadPersistedActiveServer();
          if (!authority.isCurrent()) return;
          if (active?.kind === "cloud") {
            const renamedServer = { ...active, label: name };
            const compensation: ConnectionCompensationRef = { current: null };
            const persisted = await persistAgentProfileConnectionDurably(
              {
                kind: "cloud",
                label: name,
                cloudAgentId: agent.agent_id,
                ...(renamedServer.apiBase
                  ? { apiBase: renamedServer.apiBase }
                  : {}),
                ...(renamedServer.accessToken
                  ? { accessToken: renamedServer.accessToken }
                  : { accessToken: authority.token }),
              },
              renamedServer,
              {
                validate: authority.validateAuthority,
                captureCompensation: (rollback) => {
                  compensation.current = rollback;
                },
              },
            );
            if (!persisted) {
              if (!authority.isCurrent()) return;
              throw new Error(
                "The agent was renamed, but its local runtime binding could not be saved.",
              );
            }
            if (
              !(await retainCommittedConnectionOnlyWhileCurrent(
                authority,
                compensation,
                "Cloud agent rename",
              ))
            ) {
              return;
            }
          }
        }
        if (!authority.isCurrent()) return;
        setAgents((prev) =>
          authority.isCurrent()
            ? prev.map((a) =>
                a.agent_id === agent.agent_id ? { ...a, agent_name: name } : a,
              )
            : prev,
        );
        if (!authority.isCurrent()) return;
        setActionNotice(`Renamed to ${name}.`, "success", 3000);
        setEditingId(null);
      } catch (err) {
        if (!authority.isCurrent() && !(err instanceof AggregateError)) return;
        setActionNotice(
          err instanceof Error ? err.message : "Failed to rename agent.",
          "error",
          4000,
        );
      } finally {
        if (authority.isCurrent()) setBusyId(null);
      }
    },
    [editName, activeId, setActionNotice, captureManagementAuthority],
  );

  /**
   * After a suspend/resume the row status lies (it shows the optimistic
   * transition) until a manual Refresh. Poll the agent's status a few times so
   * the row reconciles to the real server state as the daemon's job flips it.
   */
  const resyncStatus = useCallback(
    async (agentId: string, authority: CloudManagementAuthority) => {
      for (let attempt = 0; attempt < STATUS_POLL_ATTEMPTS; attempt++) {
        if (!authority.isCurrent()) return;
        await new Promise((resolve) =>
          setTimeout(resolve, STATUS_POLL_INTERVAL_MS),
        );
        if (!authority.isCurrent()) return;
        let res: Awaited<ReturnType<typeof client.getCloudCompatAgentStatus>>;
        try {
          res = await client.getCloudCompatAgentStatus(agentId, authority);
        } catch (error) {
          // A superseded A request must end the detached poll immediately.
          // A current transient failure behaves like an unsuccessful status
          // tick and consumes one bounded attempt without rejecting globally.
          if (!authority.isCurrent()) return;
          if (!isTransientManagementStatusPollError(error)) return;
          continue;
        }
        if (!authority.isCurrent()) return;
        if (!res.success) continue;
        const status = res.data.status.toLowerCase();
        if (!status) continue;
        setLocalStatus(agentId, status, authority);
        // Once the agent reaches a settled (non-transitional) state there is
        // nothing left to reconcile — stop polling early.
        if (status === "running" || NON_RUNNING_STATES.has(status)) return;
      }
    },
    [setLocalStatus],
  );

  const suspendAgent = useCallback(
    async (agent: CloudCompatAgent) => {
      const authority = captureManagementAuthority();
      if (!authority?.isCurrent()) {
        setActionNotice(MANAGEMENT_AUTHORITY_REQUIRED, "error", 5000);
        return;
      }
      setBusyId(agent.agent_id);
      try {
        const res = await client.suspendCloudCompatAgent(
          agent.agent_id,
          authority,
        );
        if (!authority.isCurrent()) return;
        if (!res.success) {
          throw new Error("Shutdown failed");
        }
        // Async job — show the transition optimistically, then re-sync the row
        // from the server so it reconciles to "stopped" once the container is
        // actually stopped (no manual Refresh needed).
        setLocalStatus(agent.agent_id, "stopping", authority);
        if (!authority.isCurrent()) return;
        setActionNotice(
          `Shutting down ${agent.agent_name || "agent"}…`,
          "success",
          3000,
        );
        void resyncStatus(agent.agent_id, authority);
      } catch (err) {
        if (!authority.isCurrent()) return;
        setActionNotice(
          err instanceof Error ? err.message : "Failed to shut down agent.",
          "error",
          4000,
        );
      } finally {
        if (authority.isCurrent()) setBusyId(null);
      }
    },
    [setActionNotice, setLocalStatus, resyncStatus, captureManagementAuthority],
  );

  const resumeAgent = useCallback(
    async (agent: CloudCompatAgent) => {
      const authority = captureManagementAuthority();
      if (!authority?.isCurrent()) {
        setActionNotice(MANAGEMENT_AUTHORITY_REQUIRED, "error", 5000);
        return;
      }
      setBusyId(agent.agent_id);
      try {
        const res = await client.resumeCloudCompatAgent(
          agent.agent_id,
          authority,
        );
        if (!authority.isCurrent()) return;
        if (!res.success) {
          throw new Error("Start failed");
        }
        setLocalStatus(agent.agent_id, "resuming", authority);
        if (!authority.isCurrent()) return;
        setActionNotice(
          `Starting ${agent.agent_name || "agent"}…`,
          "success",
          3000,
        );
        void resyncStatus(agent.agent_id, authority);
      } catch (err) {
        if (!authority.isCurrent()) return;
        setActionNotice(
          err instanceof Error ? err.message : "Failed to start agent.",
          "error",
          4000,
        );
      } finally {
        if (authority.isCurrent()) setBusyId(null);
      }
    },
    [setActionNotice, setLocalStatus, resyncStatus, captureManagementAuthority],
  );
  return {
    appName,
    elizaCloudConnected,
    agents,
    loading,
    loadError,
    busyId,
    creating,
    newName,
    setNewName,
    createError,
    setCreateError,
    editingId,
    setEditingId,
    editName,
    setEditName,
    wakingId,
    activeId,
    refresh,
    switchTo,
    createAgent,
    deleteAgent,
    startRename,
    saveRename,
    suspendAgent,
    resumeAgent,
  };
}
