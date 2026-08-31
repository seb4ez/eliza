/**
 * Rowless personal-Eliza resolution for the app-mode entry gate. After the
 * rowless personal rollout a clean account has ZERO `/api/v1/eliza/agents`
 * rows, so entry can no longer treat sandbox rows as the only proof that chat
 * can boot. This hook resolves the signed-in account's authoritative personal
 * Cloud binding (`cloud:personal:<uuid>`) by running the same read-only
 * `runJoinFlow` controller `/join` uses: it validates the identity against the
 * current Steward session token (never trusting localStorage alone), persists
 * the authoritative binding, and never provisions or starts paid compute.
 *
 * Callers gate on `enabled` so the request only fires for the rowless case;
 * resolution failure surfaces as a query error and the entry gate falls back
 * to `/join`, which owns the retryable error UI.
 */

import { type UseQueryResult, useQuery } from "@tanstack/react-query";
import { client } from "../../api";
import { bindDirectCloudLoginToPersonalAgent } from "../../state/bind-direct-cloud-login";
import {
  captureStoredStewardLoginAuthority,
  type StoredStewardLoginAuthority,
} from "../../state/cloud-steward-login";
import { savePersistedFirstRunComplete } from "../../state/persistence";
import { resolveJoinCloudApiBase } from "../join/lib/resolve-cloud-connection";
import { type JoinFlowResult, runJoinFlow } from "../join/lib/run-join-flow";

interface PersonalEntryHandoff {
  authToken: string;
  recoveryGeneration: string | null;
  result: JoinFlowResult;
}

let pendingPersonalEntryHandoff: PersonalEntryHandoff | null = null;
let personalEntryTokenGeneration = 0;
let personalEntryToken: string | null = null;
let personalEntryRecoveryGeneration: string | null | undefined;

function queryGenerationForAuthority(
  authority: StoredStewardLoginAuthority | null,
): number {
  const token = authority?.token ?? null;
  const recoveryGeneration = authority?.recoveryGeneration;
  if (
    personalEntryToken !== token ||
    personalEntryRecoveryGeneration !== recoveryGeneration
  ) {
    personalEntryToken = token;
    personalEntryRecoveryGeneration = recoveryGeneration;
    personalEntryTokenGeneration += 1;
  }
  return personalEntryTokenGeneration;
}

/**
 * Carry the already-authoritative `/join` result across the public-to-full
 * renderer swap. The Steward token binds the one-shot receipt to the session
 * that resolved it, so a later account can never consume stale identity state.
 */
export function publishPersonalEntryHandoff(
  authToken: string,
  result: JoinFlowResult,
): void {
  const authority = captureStoredStewardLoginAuthority();
  pendingPersonalEntryHandoff =
    authority?.token === authToken && authority.isCurrent()
      ? {
          authToken,
          recoveryGeneration: authority.recoveryGeneration,
          result,
        }
      : null;
}

function takePersonalEntryHandoff(
  authority: StoredStewardLoginAuthority,
): JoinFlowResult | null {
  const pending = pendingPersonalEntryHandoff;
  pendingPersonalEntryHandoff = null;
  return pending?.authToken === authority.token &&
    pending.recoveryGeneration === authority.recoveryGeneration
    ? pending.result
    : null;
}

/** The persisted-active-server id a resolved personal Eliza binds under. */
export function personalEntryBindingId(result: JoinFlowResult): string {
  return `cloud:${result.agentId}`;
}

/**
 * Resolve + persist the account's personal Eliza binding. Enabled only for the
 * authenticated rowless entry path; `retry: false` so an unavailable identity
 * endpoint fails over to `/join` promptly instead of holding the entry notice.
 */
export function usePersonalEntry(
  enabled: boolean,
): UseQueryResult<JoinFlowResult> {
  const authority = enabled ? captureStoredStewardLoginAuthority() : null;
  const tokenGeneration = queryGenerationForAuthority(authority);
  return useQuery<JoinFlowResult>({
    // The opaque generation changes for every exact bearer without retaining
    // credentials in React Query's inspectable cache keys.
    queryKey: ["app-mode", "personal-entry", tokenGeneration],
    queryFn: async ({ signal }) => {
      if (!authority) {
        throw new Error(
          "PersonalEntry: no clean Steward session authority for an authenticated entry.",
        );
      }
      const validateAuthority = () => !signal.aborted && authority.isCurrent();
      const assertAuthority = () => {
        signal.throwIfAborted();
        if (!validateAuthority()) {
          throw new DOMException(
            "Personal entry was superseded by a newer login.",
            "AbortError",
          );
        }
      };
      assertAuthority();
      const handedOff = takePersonalEntryHandoff(authority);
      if (handedOff) {
        assertAuthority();
        return handedOff;
      }
      assertAuthority();
      const result = await runJoinFlow({
        client,
        effects: {
          bindPersonalAgent: bindDirectCloudLoginToPersonalAgent,
          savePersistedFirstRunComplete,
        },
        cloudApiBase: resolveJoinCloudApiBase(),
        authToken: authority.token,
        signal,
        validateAuthority,
      });
      assertAuthority();
      return result;
    },
    enabled,
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
  });
}
