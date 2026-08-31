/**
 * Shared Steward session plumbing for the cloud shell: token storage keys and the
 * session/refresh endpoints the Steward auth provider uses.
 */
import {
  clearStoredStewardToken,
  readStoredStewardToken,
  STEWARD_CSRF_HEADER,
  STEWARD_REFRESH_ENDPOINT,
  STEWARD_SESSION_ENDPOINT,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  StewardTokenRemovalError,
} from "@elizaos/shared/steward-session-client";
import { createContext } from "react";
import { client } from "../../api";
import { clearManagedSharedCloudProfilesAndTokensDurably } from "../../state/agent-profiles";
import { clearSharedOrScrubActiveServerTokenDurably } from "../../state/persistence";
import { clearElizaApiToken } from "../../utils/eliza-globals";
import { decodeJwtPayload } from "../lib/jwt";
import { invalidateStewardServerCookieSyncMarker } from "../lib/steward-session-cookie-sync-marker";
import {
  enqueueStewardSessionMutation,
  type StewardSessionMutationLease,
} from "../lib/steward-session-mutation-queue";
import { ELIZA_CLOUD_DIRECT_API_BY_HOST } from "./steward-url";

export function isPlaceholderValue(value: string | undefined): boolean {
  if (!value) return true;
  const normalized = value.trim().toLowerCase();
  return (
    normalized.length === 0 ||
    normalized.includes("your_steward_") ||
    normalized.includes("your-steward-") ||
    normalized.includes("replace_with") ||
    normalized.includes("placeholder")
  );
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

// On canonical Eliza UI hosts, session-sync and refresh stay same-origin via
// the Pages/Worker proxy. Steward cookies are host-only, so sending these calls
// directly to api.eliza.app would plant cookies on the API host and make them
// invisible to eliza.app/cloud.eliza.app. The host map is environment-aware;
// unknown/native origins may still use an explicit API base below.
function directCloudApiBase(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return ELIZA_CLOUD_DIRECT_API_BY_HOST[window.location.hostname.toLowerCase()];
}

function directStewardSessionEndpoint(): string | undefined {
  const base = directCloudApiBase();
  return base ? `${base}${STEWARD_SESSION_ENDPOINT}` : undefined;
}

function directStewardRefreshEndpoint(): string | undefined {
  const base = directCloudApiBase();
  return base ? `${base}${STEWARD_REFRESH_ENDPOINT}` : undefined;
}

export type LocalStewardAuthValue = {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: {
    id: string;
    email?: string | null;
    walletAddress?: string;
    wallet_address?: string;
  } | null;
  session: unknown;
  signOut: () => unknown;
  getToken: () => unknown;
  verifyEmailCallback: (
    token: string,
    email: string,
  ) => Promise<{ token: string; refreshToken?: string }>;
};

export const LocalStewardAuthContext =
  createContext<LocalStewardAuthValue | null>(null);

function configuredApiBase(): string | undefined {
  return (
    import.meta.env?.VITE_API_URL ||
    import.meta.env?.NEXT_PUBLIC_API_URL ||
    (typeof process !== "undefined"
      ? process.env.NEXT_PUBLIC_API_URL
      : undefined)
  );
}

export function configuredSessionEndpoint(): string {
  const direct = directStewardSessionEndpoint();
  if (direct) {
    return direct;
  }
  const apiBase = configuredApiBase();
  if (apiBase && !isPlaceholderValue(apiBase)) {
    return `${trimTrailingSlash(apiBase)}${STEWARD_SESSION_ENDPOINT}`;
  }
  return STEWARD_SESSION_ENDPOINT;
}

export function configuredRefreshEndpoint(): string {
  const direct = directStewardRefreshEndpoint();
  if (direct) {
    return direct;
  }
  const apiBase = configuredApiBase();
  if (apiBase && !isPlaceholderValue(apiBase)) {
    return `${trimTrailingSlash(apiBase)}${STEWARD_REFRESH_ENDPOINT}`;
  }
  return STEWARD_REFRESH_ENDPOINT;
}

function stewardSessionClearUrls(): string[] {
  if (typeof window === "undefined") return [configuredSessionEndpoint()];
  const urls = new Set([STEWARD_SESSION_ENDPOINT, configuredSessionEndpoint()]);
  const direct = directStewardSessionEndpoint();
  if (direct) {
    urls.add(direct);
  }
  return [...urls];
}

const STEWARD_COOKIE_CLEAR_TIMEOUT_MS = 10_000;

async function clearStewardSessionCookieAt(url: string): Promise<void> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<void>((resolve) => {
    timeout = setTimeout(() => {
      controller.abort();
      resolve();
    }, STEWARD_COOKIE_CLEAR_TIMEOUT_MS);
  });
  // Attach both handlers before racing so an adapter which ignores abort can
  // settle later without producing an unhandled rejection. The timeout itself
  // remains the authority that releases the origin-wide mutation lease.
  const requestSettled = fetch(url, {
    method: "DELETE",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      [STEWARD_CSRF_HEADER]: STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
    },
    signal: controller.signal,
  }).then(
    () => undefined,
    () => undefined,
  );
  try {
    await Promise.race([requestSettled, timedOut]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

export async function clearServerStewardSessionCookies(
  mutationLease?: StewardSessionMutationLease,
): Promise<void> {
  if (!mutationLease) {
    return enqueueStewardSessionMutation((lease) =>
      clearServerStewardSessionCookies(lease),
    );
  }
  // Invalidate before issuing any best-effort DELETE: a rejected request must
  // never leave a proof that can suppress a later session-establishing POST.
  invalidateStewardServerCookieSyncMarker();
  // Hosts are independent and this is best-effort teardown after canonical
  // credential invalidation. Bound them concurrently so one stalled adapter
  // cannot strand every later login/refresh behind the origin mutation lease.
  await Promise.all(stewardSessionClearUrls().map(clearStewardSessionCookieAt));
}

export function readStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return readStoredStewardToken();
  } catch {
    // error-policy:J3 storage unavailable reads as signed-out (fail-closed).
    return null;
  }
}

export function tokenIsExpired(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload) return true;
  // No exp claim ⇒ treat as expired. Steward always mints exp; an exp-less
  // token is foreign/malformed, and since the 401 handlers keep any
  // NON-expired token, an exp-less one would otherwise be uncloseable — no
  // 401 could ever clear it and it never ages out on its own.
  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
    return true;
  }
  return payload.exp * 1000 < Date.now();
}

export function tokenSecsRemaining(token: string): number | null {
  const payload = decodeJwtPayload(token);
  if (!payload?.exp) return null;
  return payload.exp - Date.now() / 1000;
}

export async function clearStaleStewardSession(
  mutationLease?: StewardSessionMutationLease,
  authority?: {
    expectedToken: string | null;
    validate: () => boolean;
  },
): Promise<boolean> {
  if (typeof window === "undefined") return false;
  if (!mutationLease) {
    return enqueueStewardSessionMutation((lease) =>
      clearStaleStewardSession(lease, authority),
    );
  }
  if (authority?.validate() === false) return false;
  // Unconditional sign-out retires its module-local proof before fallible
  // storage. A terminal-response clear waits for exact CAS success so a stale
  // A response cannot invalidate account B's newer cookie-sync proof.
  if (!authority) invalidateStewardServerCookieSyncMarker();
  let storedTokenClearError: unknown;
  try {
    const cleared = await clearStoredStewardToken(
      authority
        ? {
            expectedToken: authority.expectedToken,
            validate: authority.validate,
          }
        : undefined,
    );
    if (!cleared) return false;
  } catch (error) {
    if (error instanceof StewardTokenRemovalError) throw error;
    // error-policy:J2 canonical invalidation may already have succeeded before
    // obsolete refresh-key cleanup failed. Finish every credential teardown,
    // then rethrow the original storage error with its stack intact.
    storedTokenClearError = error;
  }
  if (authority) invalidateStewardServerCookieSyncMarker();
  // `ElizaClient` mirrors its live bearer into boot config, while native and
  // desktop hosts can independently inject the same owner key through the
  // window-scoped API token. Both are canonical request-authority sources and
  // must end in the same teardown transaction as the Steward JWT. Clearing
  // only persisted profiles would leave the running renderer authenticated
  // until reload (and native Cloud calls could keep using the injected key).
  client.clearTokenSilently();
  clearElizaApiToken();
  // SECURITY: also scrub the persisted accessToken mirrors so the secondary
  // sign-out / 401-self-heal paths that route through here (native apps-studio
  // signOut, the authorize-content edge, StewardProviderRuntime 401 clears) don't
  // leave a usable cloud bearer/API-key at rest in protected host storage.
  // These awaited helpers publish only after the native/desktop authority has
  // durably acknowledged each rewrite; the legacy synchronous facades are
  // deliberately only optimistic on those hosts.
  const terminalStorageOptions = authority
    ? {
        // A is already terminal. If B starts while an awaited scrub settles,
        // keep A absent instead of compensating the revoked bearer back in.
        compensateOnValidationFailure: false,
      }
    : undefined;
  // Each helper snapshots its record once and performs one exact host CAS.
  // Shared selections are deleted while dedicated/self-hosted selections are
  // retained without their rejected bearer; profiles use one combined
  // remove-shared-and-scrub-retained transform. A lost CAS never falls through
  // to a second read that could target account B.
  await clearSharedOrScrubActiveServerTokenDurably(terminalStorageOptions);
  await clearManagedSharedCloudProfilesAndTokensDurably(terminalStorageOptions);
  await clearServerStewardSessionCookies(mutationLease);
  if (authority?.validate() !== false) {
    try {
      window.dispatchEvent(new CustomEvent("steward-token-sync"));
    } catch {
      // error-policy:J6 best-effort sync notification after credentials are scrubbed.
    }
  }
  if (storedTokenClearError !== undefined) throw storedTokenClearError;
  return true;
}
