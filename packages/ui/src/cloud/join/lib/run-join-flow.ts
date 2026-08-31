/**
 * Opens the account-native personal Eliza after Steward authentication.
 *
 * Entry is deliberately read-only: an already-active Dedicated runtime is
 * reused, otherwise the rowless Shared adapter is bound. Dedicated activation
 * and cutover remain behind the explicit management quote/consent surface.
 */

import type {
  DirectCloudBindingAuthority,
  DirectCloudBindingClient,
} from "../../../state/bind-direct-cloud-login";

/** The slice of `ElizaClient` the join flow drives. */
export interface JoinFlowClient extends DirectCloudBindingClient {}

/** Persistence + lifecycle seams, injected so the controller stays testable. */
export interface JoinFlowEffects {
  bindPersonalAgent(options: {
    client: DirectCloudBindingClient;
    cloudApiBase: string;
    token: string;
    signal?: AbortSignal;
    validate?: () => boolean;
  }): Promise<DirectCloudBindingAuthority | null>;
  savePersistedFirstRunComplete(complete: boolean): void;
}

export interface RunJoinFlowArgs {
  client: JoinFlowClient;
  effects: JoinFlowEffects;
  cloudApiBase: string;
  authToken: string;
  onProgress?: (status: string, detail?: string) => void;
  signal?: AbortSignal;
  /** Exact login/generation authority captured by the caller. */
  validateAuthority?: () => boolean;
}

export interface JoinFlowResult {
  personalElizaId: string;
  agentId: string;
  activeAgentId: string;
  agentName: string;
  apiBase: string;
  runtime: "shared" | "dedicated";
}

function assertJoinFlowAuthority(
  signal: AbortSignal | undefined,
  validateAuthority: (() => boolean) | undefined,
): void {
  signal?.throwIfAborted();
  if (validateAuthority?.() === false) {
    throw new DOMException(
      "Personal Eliza resolution was superseded by a newer login.",
      "AbortError",
    );
  }
}

/** Resolve and persist the signed-in account's currently active personal runtime. */
export async function runJoinFlow(
  args: RunJoinFlowArgs,
): Promise<JoinFlowResult> {
  const {
    client,
    effects,
    cloudApiBase,
    authToken,
    onProgress,
    signal,
    validateAuthority,
  } = args;
  assertJoinFlowAuthority(signal, validateAuthority);
  onProgress?.("connecting", "Opening your personal Eliza…");
  assertJoinFlowAuthority(signal, validateAuthority);

  const binding = await effects.bindPersonalAgent({
    client,
    cloudApiBase,
    token: authToken,
    ...(signal ? { signal } : {}),
    ...(validateAuthority ? { validate: validateAuthority } : {}),
  });
  if (!binding) {
    assertJoinFlowAuthority(signal, validateAuthority);
    throw new Error("Cloud could not persist this personal Eliza binding.");
  }
  const selected = binding.result;

  try {
    assertJoinFlowAuthority(signal, validateAuthority);

    onProgress?.(
      "connecting",
      selected.runtime === "dedicated"
        ? "Connecting to your Dedicated agent…"
        : "Connecting to your personal Eliza…",
    );
    assertJoinFlowAuthority(signal, validateAuthority);

    if (
      !selected.personalElizaId ||
      selected.agentId !== selected.personalElizaId ||
      !selected.activeAgentId
    ) {
      throw new Error("Cloud did not return a personal Eliza to connect to.");
    }
    if (selected.runtime !== "shared" && selected.runtime !== "dedicated") {
      throw new Error(
        "Cloud returned an unknown runtime for this personal Eliza.",
      );
    }

    assertJoinFlowAuthority(signal, validateAuthority);
    onProgress?.("connecting", "Finishing setup…");
    assertJoinFlowAuthority(signal, validateAuthority);

    // This account-neutral completion bit is the final synchronous publication.
    // The exact runtime/token/profile/server transaction above remains
    // rollbackable until this line and has no await after it.
    effects.savePersistedFirstRunComplete(true);

    return selected;
  } catch (error) {
    try {
      await binding.restoreIfCurrent();
    } catch (restoreError) {
      throw new AggregateError(
        [error, restoreError],
        "The stale personal Eliza binding could not be fully restored.",
      );
    }
    throw error;
  }
}
