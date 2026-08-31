/**
 * Silent cloud-session recovery for the agent-subdomain re-pair path (#15132
 * follow-up: the "Open this agent from Eliza Cloud" dead-end).
 *
 * THE BUG THIS CLOSES: a returning PWA user opens the hosted Cloud app
 * directly. Their persisted agent credential is
 * stale (container upgraded / SW-refreshed), so `/api/auth/me` 401s with
 * `remote_auth_required`. The top-level auth gate wants to transparently
 * re-pair, but re-pairing needs a cloud session token, and
 * `getCloudAuthToken()` reads the APP-ORIGIN localStorage mirror — which a
 * cold PWA relaunch may not have. A host-only HttpOnly session cookie can
 * still be present on that same app origin, but nothing was consulting it at
 * the recovery gate, so the
 * user fell straight through to the terminal `CloudHostedAgentAuthNotice`
 * ("Re-open from Eliza Cloud") dead-end instead of a silent re-pair.
 *
 * This module makes the SAME cookie→session recovery that the startup restore
 * path already performs (`resolveRestoredStewardToken`) available at the
 * recovery gate: when there is no app-origin cloud token but a Steward authed
 * cookie exists, refresh the session from the cookie, persist it, and report
 * whether a token is now available. The recovery hook then re-pairs silently;
 * only a genuinely absent/expired cloud session falls through to the notice.
 *
 * SECURITY (auth-adjacent): this NEVER fabricates or bypasses a session. It
 * only exchanges an EXISTING, server-validated HttpOnly refresh cookie (web),
 * or rotates an existing Steward bearer against the configured Cloud API
 * (native/Electrobun). Without either authority, the notice/wall stands. It
 * writes only the canonical Steward token key, touching no unrelated agent
 * credential (i.e. it does NOT introduce #16673's over-broad purge).
 */

import {
  hasStewardAuthedCookie,
  readStoredStewardToken,
  STEWARD_REFRESH_ENDPOINT,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { refreshCloudStewardSession } from "../api/client-cloud";
import {
  DEFAULT_DIRECT_CLOUD_API_BASE_URL,
  resolveDirectCloudAuthApiBase,
} from "../api/direct-cloud-endpoints";
import { isElectrobunRuntime } from "../bridge/electrobun-runtime";
import { getBootConfig } from "../config/boot-config";

/** Bounded so the recovery gate can never hang on a slow refresh. */
export const CLOUD_REPAIR_REFRESH_TIMEOUT_MS = 6_000;

export interface EnsureCloudSessionForRepairDeps {
  /** Injected (tests). Defaults to the shared client cookie probe. */
  hasCookie?: (environment?: string | null) => boolean;
  /** Injected (tests). Defaults to the localStorage Steward mirror read. */
  readToken?: () => string | null | undefined;
  /** Injected (tests). Defaults to the canonical Steward refresh. */
  refreshFn?: typeof refreshCloudStewardSession;
  /** Injected (tests). Defaults to the localStorage Steward mirror write. */
  writeToken?: (
    token: string,
    options?: { validate?: () => boolean },
  ) => Promise<unknown> | unknown;
  /** Injected (tests). Defaults to the real refresh timeout. */
  timeoutMs?: number;
  /** Injected (tests). Defaults to real setTimeout-based race. */
  raceTimeout?: <T>(p: Promise<T>, ms: number) => Promise<T | null>;
  /** Ignore a present but expired/near-expiry JWT and rotate its session. */
  forceRefresh?: boolean;
  /** Exact recovery generation + runtime target authority owned by the caller. */
  validate?: () => boolean;
}

function defaultRaceTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), ms);
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function isBearerRefreshRuntime(): boolean {
  let isNative = false;
  try {
    isNative = Boolean(
      (
        globalThis as typeof globalThis & {
          Capacitor?: { isNativePlatform?: () => boolean };
        }
      ).Capacitor?.isNativePlatform?.(),
    );
  } catch {
    isNative = false;
  }
  return isNative || isElectrobunRuntime();
}

function resolveRepairRefreshEndpoint(
  bearerRefreshRuntime: boolean,
): string | undefined {
  if (bearerRefreshRuntime) {
    const configuredCloudBase =
      getBootConfig().cloudApiBase?.trim() || DEFAULT_DIRECT_CLOUD_API_BASE_URL;
    const resolvedApiBase = resolveDirectCloudAuthApiBase(configuredCloudBase);
    try {
      const parsed = new URL(resolvedApiBase);
      if (parsed.protocol === "https:" || parsed.protocol === "http:") {
        return `${resolvedApiBase.replace(/\/+$/, "")}${STEWARD_REFRESH_ENDPOINT}`;
      }
    } catch {
      // Fall through to the fixed direct Cloud API authority below.
    }
    return `${DEFAULT_DIRECT_CLOUD_API_BASE_URL}${STEWARD_REFRESH_ENDPOINT}`;
  }
  if (typeof window === "undefined") return undefined;
  // Refresh cookies are host-only. Pages proxies this same-origin endpoint to
  // the matching API Worker, preserving the browser cookie boundary.
  return `${window.location.origin}${STEWARD_REFRESH_ENDPOINT}`;
}

/**
 * Ensure an app-origin cloud session token exists for the re-pair exchange,
 * recovering it from the same-origin HttpOnly Eliza Cloud cookie when the
 * web mirror is empty, or rotating an existing native/desktop bearer.
 *
 * Returns the usable cloud token, or `null` when none can be recovered (no
 * cookie/native bearer, refresh failed/timed out, or refresh returned no
 * token). Callers MUST treat `null` as "no cloud session — keep the wall."
 *
 * At most one refresh network call per invocation; the caller gates invocation
 * to once per unauthenticated cycle so there is no refresh loop.
 */
export async function ensureCloudSessionForRepair(
  deps: EnsureCloudSessionForRepairDeps = {},
): Promise<string | null> {
  const {
    hasCookie = hasStewardAuthedCookie,
    readToken = readStoredStewardToken,
    refreshFn = refreshCloudStewardSession,
    writeToken = writeStoredStewardToken,
    timeoutMs = CLOUD_REPAIR_REFRESH_TIMEOUT_MS,
    raceTimeout = defaultRaceTimeout,
    forceRefresh = false,
    validate = () => true,
  } = deps;

  if (!validate()) return null;

  // Fast path: the app-origin mirror already has a token — nothing to recover.
  const existing = readToken()?.trim();
  if (existing && !forceRefresh) return existing;

  const bearerRefreshRuntime = isBearerRefreshRuntime();
  const canRefreshWithExistingBearer = Boolean(
    forceRefresh && existing && bearerRefreshRuntime,
  );

  // Web repair requires this host's HttpOnly session cookie. Native/Electrobun
  // instead rotate an expired existing bearer against the configured Cloud API
  // authority; those shells intentionally have no browser cookie to probe.
  if (typeof window === "undefined" || !validate()) return null;
  if (!canRefreshWithExistingBearer && (!hasCookie() || !validate())) {
    return null;
  }

  let recovered: Awaited<ReturnType<typeof refreshCloudStewardSession>> = null;
  let publicationOpen = true;
  const refreshCommit = {
    committed: false,
    finalizerInvoked: false,
    authority: null as { validate: () => boolean } | null,
  };
  const validatePublication = () =>
    publicationOpen &&
    validate() &&
    refreshCommit.authority?.validate() === true;
  try {
    // error-policy:J4 a failed/absent cookie refresh yields null → the caller
    // keeps the wall; it NEVER fabricates a session.
    recovered = await raceTimeout(
      refreshFn({
        endpoint: resolveRepairRefreshEndpoint(bearerRefreshRuntime),
        commitRefreshedSession: async (session, authority) => {
          refreshCommit.finalizerInvoked = true;
          refreshCommit.authority = authority;
          const token = session.token?.trim();
          if (!token || !validatePublication()) return;
          await writeToken(token, { validate: validatePublication });
          if (!validatePublication()) return;
          refreshCommit.committed = true;
          if (typeof CustomEvent === "function") {
            window.dispatchEvent(new CustomEvent("steward-token-sync"));
          }
        },
      }).catch(() => null),
      timeoutMs,
    );
  } catch {
    publicationOpen = false;
    return null;
  }

  const refreshWasSuperseded = refreshCommit.authority?.validate() === false;
  // `raceTimeout` does not cancel an ambiguous cookie mutation. Retire its
  // renderer publication as soon as this gate stops awaiting it so a late
  // response cannot install a token after the reauth notice has won.
  publicationOpen = false;
  const token = recovered?.token?.trim();
  if (!token) return null;
  if (refreshWasSuperseded || !validate()) return null;
  if (refreshCommit.finalizerInvoked && !refreshCommit.committed) return null;

  // Injected test/alternate refresh functions may predate the transactional
  // finalizer contract. Preserve compatibility, while the production helper
  // always commits under its origin-wide mutation lease above.
  if (!refreshCommit.committed) {
    await writeToken(token, { validate });
    if (!validate()) return null;
  }
  // error-policy:J6 best-effort nudge — token consumers re-read next tick.
  // dispatchEvent reports listener errors instead of rethrowing, so no
  // try/catch is needed; the guard only skips environments without
  // CustomEvent (never a real browser).
  if (!refreshCommit.committed && typeof CustomEvent === "function") {
    window.dispatchEvent(new CustomEvent("steward-token-sync"));
  }
  return token;
}
