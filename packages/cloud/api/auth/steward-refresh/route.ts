/**
 * POST /api/auth/steward-refresh
 *
 * Server-side refresh-token rotation. The browser sends the request with
 * `credentials: 'include'`; the selected v1/v2 HttpOnly refresh cookie travels
 * automatically. The route:
 *
 *  1. Reads one complete cookie namespace (HttpOnly — JS can never see the
 *     refresh token), preferring v2 whenever any v2 authority exists.
 *  2. Forwards it to Steward `POST /auth/refresh`, which returns a fresh
 *     access token + rotated refresh token.
 *  3. Verifies the new access token (same path as
 *     `/api/auth/steward-session`).
 *  4. Rotates only an already-established host-bound v2 namespace.
 *  5. Returns `{ ok, expiresAt }`. Trusted first-party browser origins also
 *     receive the short-lived access token so the SPA can hydrate its
 *     localStorage mirror while route auth remains synchronous.
 *
 * Strict Origin plus Fetch Metadata checks mirror the cookie-writer lane of
 * `/api/auth/steward-session`.
 *
 * This route is the only way to refresh once the localStorage copy of the
 * refresh token is removed. Historical v1 cookies are never rotated here:
 * their Domain-era provenance is ambiguous, so clients must re-publish an
 * independently held access token through `/api/auth/steward-session`.
 */

import {
  STEWARD_CSRF_HEADER,
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  type StewardSessionErrorCode,
} from "@elizaos/shared/steward-session-client";
import { type Context, Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { checkStewardCookieWriterRequest } from "@/lib/auth/browser-origin-policy";
import { legacyCookieCleanupDomainForHost } from "@/lib/auth/cookie-domain";
import {
  mintStewardTokenFromClaims,
  STEWARD_AUTH_UPSTREAM_TIMEOUT_MS,
  type StewardTokenClaims,
  type StewardVerifyEnv,
  verifyStewardRefreshLineageToken,
  verifyStewardTokenCached,
} from "@/lib/auth/steward-client";
import {
  legacyStewardCookieNames,
  readStewardSessionMigrationCookieStateFromHeader,
  STEWARD_REFRESH_AUTHORITY_TTL_SECONDS,
  STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
  STEWARD_V2_AUTHORITY_TOMBSTONE,
  stewardCookieNames,
  stewardV2CookiesAreHostBound,
} from "@/lib/auth/steward-cookies";
import { isBlockedBySsoBridgeLogout } from "@/lib/services/sso-bridge-codes";
import { signStewardMutatingRequest } from "@/lib/steward/sign";
import { logger } from "@/lib/utils/logger";
import type { AppEnv } from "@/types/cloud-worker-env";

const BEARER_REFRESH_TTL_SECONDS = 60 * 60;

function readBearerToken(c: {
  req: { header: (name: string) => string | undefined };
}): string | null {
  const auth = c.req.header("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  const token = auth.slice("Bearer ".length).trim();
  return token || null;
}

function stewardSecretConfigured(env: StewardVerifyEnv): boolean {
  return Boolean(env.STEWARD_SESSION_SECRET || env.STEWARD_JWT_SECRET);
}

function errorBody(
  message: string,
  code: StewardSessionErrorCode,
): { error: string; code: StewardSessionErrorCode } {
  return { error: message, code };
}

type SsoLogoutBarrierResult = "allowed" | "blocked" | "unavailable";

async function checkSsoLogoutBarrier(
  claims: StewardTokenClaims,
): Promise<SsoLogoutBarrierResult> {
  try {
    return (await isBlockedBySsoBridgeLogout(claims.userId, claims.issuedAt))
      ? "blocked"
      : "allowed";
  } catch (error) {
    logger.error("[steward-refresh] SSO logout-marker store unavailable", {
      error: error instanceof Error ? error.message : String(error),
    });
    return "unavailable";
  }
}

function effectiveStewardTenantId(
  claims: StewardTokenClaims,
  expectedTenantId: string | undefined,
): string | null {
  const claimed = claims.tenantId?.trim();
  if (claimed) return claimed;
  const expected = expectedTenantId?.trim();
  return expected || null;
}

function isSameStewardIdentity(
  current: StewardTokenClaims,
  refreshed: StewardTokenClaims,
  expectedTenantId: string | undefined,
): boolean {
  return (
    current.userId === refreshed.userId &&
    effectiveStewardTenantId(current, expectedTenantId) ===
      effectiveStewardTenantId(refreshed, expectedTenantId)
  );
}

function deleteLegacyCookieInOwnedScopes(
  c: Context<AppEnv>,
  name: string,
): void {
  deleteCookie(c, name, { path: "/" });
  const domain = legacyCookieCleanupDomainForHost(c.req.header("host"));
  if (domain) deleteCookie(c, name, { path: "/", domain });
}

function tombstoneCurrentSession(c: Context<AppEnv>): void {
  const v2Secure = stewardV2CookiesAreHostBound(c.env.ENVIRONMENT);
  const v2Options = {
    path: "/",
    ...(v2Secure ? { secure: true } : {}),
  };
  const v2 = stewardCookieNames(c.env.ENVIRONMENT);
  const v1 = legacyStewardCookieNames(c.env.ENVIRONMENT);
  deleteCookie(c, v2.token, v2Options);
  deleteCookie(c, v2.refreshToken, v2Options);
  deleteLegacyCookieInOwnedScopes(c, v1.token);
  deleteLegacyCookieInOwnedScopes(c, v1.refreshToken);
  deleteLegacyCookieInOwnedScopes(c, v1.authed);
  setCookie(c, v2.authed, STEWARD_V2_AUTHORITY_TOMBSTONE, {
    httpOnly: false,
    secure: v2Secure,
    sameSite: "Lax",
    path: "/",
    maxAge: STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
  });
}

function clearLegacyAccessCookies(c: Context<AppEnv>): void {
  const v1 = legacyStewardCookieNames(c.env.ENVIRONMENT);
  deleteLegacyCookieInOwnedScopes(c, v1.token);
  deleteLegacyCookieInOwnedScopes(c, v1.authed);
}

function deleteCurrentRefreshCookie(
  c: Context<AppEnv>,
  cookieNames: ReturnType<typeof stewardCookieNames>,
  isV2: boolean,
): void {
  deleteCookie(c, cookieNames.refreshToken, {
    path: "/",
    ...(isV2 && stewardV2CookiesAreHostBound(c.env.ENVIRONMENT)
      ? { secure: true }
      : {}),
  });
}

function sessionMutationNamespace(
  c: Context<AppEnv>,
  cookieState: ReturnType<
    typeof readStewardSessionMigrationCookieStateFromHeader
  >,
): "v2" | "v1" | null {
  if (cookieState.ambiguous) return null;
  const marker = c.req.header(STEWARD_CSRF_HEADER);
  if (marker === STEWARD_SESSION_MUTATION_PROTOCOL_VALUE) return "v2";
  if (
    marker === STEWARD_CSRF_HEADER_VALUE &&
    cookieState.v2Authority === "absent" &&
    cookieState.source !== "v2"
  ) {
    return "v1";
  }
  return null;
}

let stewardRefreshMetricCounter = 0;
function logRefresh(outcome: string): void {
  stewardRefreshMetricCounter += 1;
  logger.info("[steward-refresh]", {
    timestamp: new Date().toISOString(),
    outcome,
    metric: stewardRefreshMetricCounter,
  });
}

function resolveStewardBaseUrl(env: AppEnv["Bindings"]): string | null {
  const candidates: Array<[string, string | undefined]> = [
    ["STEWARD_API_URL", env.STEWARD_API_URL],
    ["NEXT_PUBLIC_STEWARD_API_URL", env.NEXT_PUBLIC_STEWARD_API_URL],
  ];
  for (const [key, candidate] of candidates) {
    if (typeof candidate !== "string") continue;
    const trimmed = candidate.trim().replace(/\/+$/, "");
    if (trimmed.length === 0) continue;
    try {
      const url = new URL(trimmed);
      if (url.protocol !== "https:" && url.protocol !== "http:") continue;
      return trimmed;
    } catch (error) {
      // A non-empty candidate that fails to parse is a misconfiguration, not a
      // missing value. Name the env var so the resulting 503 is debuggable; never
      // log the value itself (it may contain credentials).
      logger.warn("[StewardAuth] Ignoring unparseable Steward base URL", {
        envVar: key,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return null;
}

interface StewardRefreshOk {
  ok: true;
  token: string;
  refreshToken: string;
  expiresIn?: number;
  expiresAt?: number;
}
interface StewardRefreshErr {
  ok: false;
  error?: string;
  code?: string;
}

interface StewardRefreshRequestContext {
  clientIp?: string;
  origin?: string;
  userAgent?: string;
}

function stewardRefreshRequestContext(
  c: {
    req: { url: string; header: (name: string) => string | undefined };
  },
  isProduction: boolean,
): StewardRefreshRequestContext {
  // Cloudflare owns cf-connecting-ip at the edge. Prefer it over caller-
  // supplied forwarding headers so Steward's per-client auth limiter cannot
  // be bypassed by spoofing X-Forwarded-For. A forwarding-header fallback is
  // accepted only on a direct loopback request, where the caller already owns
  // the local listener and the cookie path remains origin/CSRF gated.
  const hostname = new URL(c.req.url).hostname.toLowerCase();
  const isLoopback =
    hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  const edgeClientIp = c.req.header("cf-connecting-ip")?.trim();
  const localClientIp =
    !isProduction && isLoopback
      ? c.req.header("x-real-ip")?.trim() ||
        c.req.header("x-forwarded-for")?.split(",")[0]?.trim()
      : undefined;
  const clientIp = edgeClientIp || localClientIp || undefined;
  return {
    ...(clientIp ? { clientIp } : {}),
    ...(c.req.header("origin")?.trim()
      ? { origin: c.req.header("origin")?.trim() }
      : {}),
    ...(c.req.header("user-agent")?.trim()
      ? { userAgent: c.req.header("user-agent")?.trim() }
      : {}),
  };
}

async function callStewardRefresh(
  baseUrl: string,
  refreshToken: string,
  pinnedTenantId?: string,
  signingSecret?: string,
  requestContext: StewardRefreshRequestContext = {},
): Promise<
  | { kind: "ok"; data: StewardRefreshOk }
  | {
      kind: "error";
      status: number;
      data: StewardRefreshErr;
      retryAfter: string | null;
      responseKind: "json" | "non-json";
    }
  | { kind: "transport"; message: string }
> {
  const headers = new Headers({
    "Content-Type": "application/json",
    Accept: "application/json",
  });
  // Preserve the real browser identity across the direct Cloud -> Steward
  // hop. Without this, every Cloud refresh is bucketed under the shared
  // Worker/Railway egress IP and unrelated users can throttle each other.
  // Never forward inbound Cookie or Authorization headers: the refresh token
  // is carried only in the signed JSON body below.
  if (requestContext.clientIp) {
    headers.set("X-Forwarded-For", requestContext.clientIp);
  }
  if (requestContext.origin) headers.set("Origin", requestContext.origin);
  if (requestContext.userAgent) {
    headers.set("User-Agent", requestContext.userAgent);
  }
  // Pin the tenant per-env: this route bypasses the /steward/* proxy in
  // bootstrap-app.ts and would otherwise hit Steward without scoping,
  // letting a staging refresh land against the prod tenant.
  if (typeof pinnedTenantId === "string" && pinnedTenantId.trim().length > 0) {
    headers.set("X-Steward-Tenant", pinnedTenantId.trim());
  }
  const bodyText = JSON.stringify({ refreshToken });
  const bodyBytes = new TextEncoder().encode(bodyText);
  const refreshUrl = new URL(`${baseUrl}/auth/refresh`);
  // Steward's authorization-signature middleware gates mutating sensitive
  // paths (incl. /auth/refresh) on the signed-request contract. The
  // /steward/* embedded proxy signs automatically; this bypass route must
  // sign the same way or Steward 502s with "Request expiry header required",
  // which kicks the SPA back to /login after every magic-link verify.
  if (typeof signingSecret === "string" && signingSecret.length > 0) {
    await signStewardMutatingRequest(
      signingSecret,
      "POST",
      `${refreshUrl.pathname}${refreshUrl.search}`,
      headers,
      bodyBytes,
    );
  }
  let response: Response;
  try {
    response = await fetch(refreshUrl.toString(), {
      method: "POST",
      headers,
      body: bodyText,
      signal: AbortSignal.timeout(STEWARD_AUTH_UPSTREAM_TIMEOUT_MS),
    });
  } catch (err) {
    return {
      kind: "transport",
      message: err instanceof Error ? err.message : String(err),
    };
  }

  const text = await response.text();
  let parsed: StewardRefreshOk | StewardRefreshErr | null = null;
  try {
    parsed = text
      ? (JSON.parse(text) as StewardRefreshOk | StewardRefreshErr)
      : null;
  } catch {
    parsed = null;
  }

  if (!response.ok || !parsed || parsed.ok !== true) {
    return {
      kind: "error",
      status: response.status,
      data:
        parsed && parsed.ok === false
          ? (parsed as StewardRefreshErr)
          : {
              ok: false,
              error: "Steward refresh failed",
            },
      retryAfter: response.headers.get("retry-after"),
      responseKind: parsed ? "json" : "non-json",
    };
  }
  return { kind: "ok", data: parsed };
}

const app = new Hono<AppEnv>();

app.post("/", async (c) => {
  const isProduction = c.env.NODE_ENV === "production";
  const bearerToken = readBearerToken(c);
  if (bearerToken) {
    if (!stewardSecretConfigured(c.env)) {
      logRefresh("bearer-server-secret-missing");
      return c.json(
        errorBody(
          "Steward verification not configured on server",
          "server_secret_missing",
        ),
        503,
      );
    }

    const claims = await verifyStewardTokenCached(c.env, bearerToken);
    if (!claims) {
      logRefresh("bearer-invalid-token");
      return c.json(errorBody("Invalid token", "invalid_token"), 401);
    }
    // Staging QA sessions are deliberately non-renewable. Their absolute
    // one-hour maximum is signed into the source binding, and the bearer
    // convenience refresh must never move that window forward.
    if (claims.stagingSessionBinding) {
      logRefresh("bearer-staging-session-nonrenewable");
      return c.json(errorBody("Invalid token", "invalid_token"), 401);
    }

    const logoutBarrier = await checkSsoLogoutBarrier(claims);
    if (logoutBarrier === "unavailable") {
      logRefresh("bearer-sso-marker-unavailable");
      return c.json(
        errorBody("SSO bridge unavailable", "sso_unavailable"),
        503,
      );
    }
    if (logoutBarrier === "blocked") {
      logRefresh("bearer-session-ended");
      return c.json(errorBody("Session was signed out", "session_ended"), 401);
    }

    const refreshed = await mintStewardTokenFromClaims(
      c.env,
      claims,
      BEARER_REFRESH_TTL_SECONDS,
    );
    if (!refreshed) {
      logRefresh("bearer-mint-failed");
      return c.json(
        errorBody(
          "Steward verification not configured on server",
          "server_secret_missing",
        ),
        503,
      );
    }

    // Re-read the original session generation after mint. The mint gives the
    // replacement a fresh iat, so checking only that replacement could make a
    // logout committed during the await look older and accidentally revive
    // the session.
    const finalLogoutBarrier = await checkSsoLogoutBarrier(claims);
    if (finalLogoutBarrier === "unavailable") {
      logRefresh("bearer-sso-marker-unavailable-final");
      return c.json(
        errorBody("SSO bridge unavailable", "sso_unavailable"),
        503,
      );
    }
    if (finalLogoutBarrier === "blocked") {
      logRefresh("bearer-session-ended-final");
      return c.json(errorBody("Session was signed out", "session_ended"), 401);
    }

    logRefresh("ok-bearer");
    return c.json({
      ok: true,
      token: refreshed.token,
      expiresAt: refreshed.expiresAt,
      expiresIn: refreshed.expiresIn,
    });
  }

  const originCheck = checkStewardCookieWriterRequest(
    c.req,
    c.env.ENVIRONMENT,
    isProduction,
  );
  if (!originCheck.ok) {
    logRefresh("forbidden-origin");
    logger.warn("[steward-refresh] rejected cross-origin POST", {
      detail: originCheck.reason,
    });
    return c.json(errorBody("Forbidden", "forbidden_origin"), 403);
  }

  const cookieNames = stewardCookieNames(c.env.ENVIRONMENT);
  const requestCookieState = readStewardSessionMigrationCookieStateFromHeader(
    c.req.header("cookie") ?? null,
    c.env.ENVIRONMENT,
  );
  const mutationMarker = c.req.header(STEWARD_CSRF_HEADER);
  if (
    requestCookieState.ambiguous &&
    requestCookieState.v2Authority === "absent" &&
    requestCookieState.source !== "v2" &&
    (mutationMarker === STEWARD_SESSION_MUTATION_PROTOCOL_VALUE ||
      mutationMarker === STEWARD_CSRF_HEADER_VALUE)
  ) {
    // The browser can legitimately send both the host-only and historical
    // Domain copy during migration. Their values are never selected for auth
    // or forwarding, but a same-origin cleanup request must still retire both
    // scopes and close the v2 authority boundary.
    tombstoneCurrentSession(c);
    logRefresh("ambiguous-legacy-session-cleaned");
    return c.json(
      errorBody(
        "Session upgrade requires a verified login token",
        "session_mutation_protocol_required",
      ),
      409,
    );
  }
  // Read only this environment's named refresh cookie. Cookies are host-only;
  // the environment suffix remains a compatibility invariant and prevents a
  // preview accidentally treating an older unsuffixed cookie as its session.
  const refreshToken = requestCookieState.refreshToken;
  const accessToken = requestCookieState.token;
  // Any cookie-backed request can become a writer: the access-only recovery
  // branch below removes a revoked account's cookies. Gate before either
  // branch so a legacy response for account A cannot arrive after login B and
  // delete or replace B's fixed-name cookies.
  const mutationNamespace = sessionMutationNamespace(c, requestCookieState);
  if (
    !mutationNamespace &&
    (refreshToken || accessToken || requestCookieState.source === "v2")
  ) {
    logRefresh("session-mutation-protocol-required");
    return c.json(
      errorBody(
        "Session refresh client update required",
        "session_mutation_protocol_required",
      ),
      409,
    );
  }
  if (requestCookieState.source === "v1") {
    // No refresh protocol may rotate ambient v1 cookie authority: a sibling
    // user-content host could have planted those historical Domain cookies.
    // A current client must re-publish its independently held, verified access
    // token to POST /steward-session; only that route may carry a
    // same-identity v1 refresh cookie into the host-bound namespace. Legacy
    // clients can still establish v1 through independently authorized session
    // and nonce POSTs, but cookie-only refresh fails closed.
    logRefresh("legacy-session-upgrade-required");
    return c.json(
      errorBody(
        "Session upgrade requires a verified login token",
        "session_mutation_protocol_required",
      ),
      409,
    );
  }
  if (!refreshToken) {
    if (!accessToken) {
      if (requestCookieState.v2Authority === "active") {
        // The long-lived authority marker must never outlive both credentials
        // as a false authenticated signal. Retire it only after the current
        // Web-Locked client and strict browser-origin gate have won; an
        // ambiguous upstream rotation 401 deliberately does not use this path.
        tombstoneCurrentSession(c);
      } else if (
        mutationNamespace !== null &&
        requestCookieState.v2Authority === "absent" &&
        getCookie(c, legacyStewardCookieNames(c.env.ENVIRONMENT).authed) !==
          undefined
      ) {
        clearLegacyAccessCookies(c);
      }
    }
    // A session POST can commit its access cookie immediately before the
    // renderer is closed, while its auth result carries no refresh token (or
    // before the refresh cookie is stored). Durable login recovery must be
    // able to hydrate that already-verified first-party access cookie without
    // destructively treating the ordinary `steward-authed` bearer marker as a
    // dead refresh session. This read neither rotates nor clears cookies.
    if (accessToken) {
      if (!stewardSecretConfigured(c.env)) {
        logRefresh("access-cookie-server-secret-missing");
        return c.json(
          errorBody(
            "Steward verification not configured on server",
            "server_secret_missing",
          ),
          503,
        );
      }
      const claims = await verifyStewardTokenCached(c.env, accessToken);
      if (!claims) {
        logRefresh("access-cookie-invalid-token");
        return c.json(errorBody("Invalid token", "invalid_token"), 401);
      }
      const logoutBarrier = await checkSsoLogoutBarrier(claims);
      if (logoutBarrier === "unavailable") {
        logRefresh("access-cookie-sso-marker-unavailable");
        return c.json(
          errorBody("SSO bridge unavailable", "sso_unavailable"),
          503,
        );
      }
      if (logoutBarrier === "blocked") {
        // This is a positive, user-scoped revocation signal rather than a
        // refresh-rotation loser. Remove only this environment's access and
        // marker cookies; never touch sibling-environment or refresh cookies.
        if (mutationNamespace === "v1") {
          clearLegacyAccessCookies(c);
        } else {
          tombstoneCurrentSession(c);
        }
        logRefresh("access-cookie-session-ended");
        return c.json(
          errorBody("Session was signed out", "session_ended"),
          401,
        );
      }
      const expiresAt = claims.expiration;
      const finalLogoutBarrier = await checkSsoLogoutBarrier(claims);
      if (finalLogoutBarrier === "unavailable") {
        logRefresh("access-cookie-sso-marker-unavailable-final");
        return c.json(
          errorBody("SSO bridge unavailable", "sso_unavailable"),
          503,
        );
      }
      if (finalLogoutBarrier === "blocked") {
        if (mutationNamespace === "v1") {
          clearLegacyAccessCookies(c);
        } else {
          tombstoneCurrentSession(c);
        }
        logRefresh("access-cookie-session-ended-final");
        return c.json(
          errorBody("Session was signed out", "session_ended"),
          401,
        );
      }
      // Calculate after the final asynchronous authority check so the cookie's
      // Max-Age cannot outlive the signed JWT by time spent awaiting that
      // barrier. The verifier deliberately permits bounded clock skew, so
      // independently require positive cryptographic lifetime before
      // re-publishing a QA cookie. Ordinary/bridged lineages retain the
      // refresh-authority horizon below.
      const expiresIn = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
      if (claims.stagingSessionBinding && expiresIn < 1) {
        logRefresh("access-cookie-staging-session-expired");
        return c.json(errorBody("Invalid token", "invalid_token"), 401);
      }
      if (mutationNamespace === "v2") {
        const secure = stewardV2CookiesAreHostBound(c.env.ENVIRONMENT);
        const accessCookieMaxAge = claims.stagingSessionBinding
          ? expiresIn
          : STEWARD_REFRESH_AUTHORITY_TTL_SECONDS;
        setCookie(c, cookieNames.token, accessToken, {
          httpOnly: true,
          secure,
          sameSite: "Lax",
          path: "/",
          maxAge: accessCookieMaxAge,
        });
        setCookie(c, cookieNames.authed, "1", {
          httpOnly: false,
          secure,
          sameSite: "Lax",
          path: "/",
          maxAge: STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
        });
      }
      logRefresh("ok-access-cookie");
      return c.json({
        ok: true,
        token: accessToken,
        expiresAt,
        expiresIn,
      });
    }
    logRefresh("missing-refresh-cookie");
    return c.json(errorBody("Refresh token required", "missing_token"), 401);
  }

  if (!stewardSecretConfigured(c.env)) {
    logRefresh("server-secret-missing");
    return c.json(
      errorBody(
        "Steward verification not configured on server",
        "server_secret_missing",
      ),
      503,
    );
  }

  // Capture the verified access identity from this request before consuming
  // the single-use refresh token. If an access-only login for account B has
  // already replaced account A's access cookie but A's old refresh cookie
  // survived, the rotated A result must never overwrite B below.
  const currentAccessClaims = accessToken
    ? ((await verifyStewardTokenCached(c.env, accessToken)) ??
      (await verifyStewardRefreshLineageToken(c.env, accessToken)))
    : null;

  if (currentAccessClaims) {
    const admissionBarrier = await checkSsoLogoutBarrier(currentAccessClaims);
    if (admissionBarrier === "unavailable") {
      logRefresh("cookie-sso-marker-unavailable");
      return c.json(
        errorBody("SSO bridge unavailable", "sso_unavailable"),
        503,
      );
    }
    if (admissionBarrier === "blocked") {
      tombstoneCurrentSession(c);
      logRefresh("cookie-session-ended");
      return c.json(errorBody("Session was signed out", "session_ended"), 401);
    }
  }

  const stewardBaseUrl = resolveStewardBaseUrl(c.env);
  if (!stewardBaseUrl) {
    logRefresh("upstream-not-configured");
    return c.json(
      errorBody(
        "Steward upstream not configured",
        "steward_upstream_unavailable",
      ),
      503,
    );
  }

  const refresh = await callStewardRefresh(
    stewardBaseUrl,
    refreshToken,
    c.env.STEWARD_TENANT_ID,
    c.env.STEWARD_REQUEST_SIGNING_SECRET,
    stewardRefreshRequestContext(c, isProduction),
  );

  if (refresh.kind === "transport") {
    logRefresh("upstream-transport-error");
    logger.error("[steward-refresh] upstream transport failure", {
      message: refresh.message,
    });
    return c.json(
      errorBody("Steward upstream unavailable", "steward_upstream_unavailable"),
      502,
    );
  }

  if (refresh.kind === "error") {
    logRefresh(`upstream-${refresh.status}`);
    if (refresh.status !== 401) {
      logger.warn("[steward-refresh] upstream rejected refresh", {
        upstreamStatus: refresh.status,
        responseKind: refresh.responseKind,
        retryAfterPresent: refresh.retryAfter !== null,
      });
    }
    // Steward 401s BOTH for a genuinely dead token AND for the loser of a
    // refresh-token ROTATION RACE: tokens are single-use and two tabs on the
    // same host can fire their 15-min timers together — the second request
    // presents the just-consumed token. This branch used to deleteCookie() the
    // whole host session on any 401, which turned every lost race into sign-out (and the
    // delete could land AFTER the winner's Set-Cookie, destroying the fresh
    // host session too). Keep the cookies instead: in the race case the browser
    // jar already holds the winner's NEW token, so the very next refresh
    // succeeds and the session self-heals; for a genuinely dead token every
    // future refresh 401s and the login surface shows regardless — same
    // terminal UX, one extra failed call, no domain-wide nuke.
    if (refresh.status === 401) {
      return c.json(errorBody("Refresh token rejected", "invalid_token"), 401);
    }
    if (refresh.status === 429) {
      return c.json(
        errorBody(
          "Too many refresh attempts. Wait a moment and try again.",
          "internal_error",
        ),
        429,
        refresh.retryAfter ? { "Retry-After": refresh.retryAfter } : undefined,
      );
    }
    return c.json(
      errorBody(refresh.data.error || "Refresh failed", "internal_error"),
      502,
    );
  }

  const { token, refreshToken: newRefreshToken } = refresh.data;

  const claims = await verifyStewardTokenCached(c.env, token);
  if (!claims) {
    logRefresh("invalid-token-after-refresh");
    return c.json(errorBody("Invalid token", "invalid_token"), 401);
  }

  if (
    currentAccessClaims &&
    !isSameStewardIdentity(currentAccessClaims, claims, c.env.STEWARD_TENANT_ID)
  ) {
    // Unlike an upstream 401, this is not ambiguous with an ordinary
    // same-identity refresh-rotation loser: both signed identities are known
    // and disagree. Burn only the stale refresh cookie from this environment,
    // preserving account B's access + marker cookies and every sibling env.
    deleteCurrentRefreshCookie(c, cookieNames, true);
    logRefresh("access-refresh-identity-mismatch");
    return c.json(
      errorBody(
        "Refresh token does not match current session",
        "invalid_token",
      ),
      401,
    );
  }

  // An opaque refresh with no access cookie cannot prove when its original
  // session began. Admit its replacement with iat=0 so every still-live logout
  // marker blocks it, even though Steward assigned the replacement a fresh
  // iat after consuming the single-use refresh credential.
  const publicationBarrierClaims = currentAccessClaims ?? {
    ...claims,
    issuedAt: 0,
  };
  if (!currentAccessClaims) {
    const admissionBarrier = await checkSsoLogoutBarrier(
      publicationBarrierClaims,
    );
    if (admissionBarrier === "unavailable") {
      logRefresh("cookie-sso-marker-unavailable");
      return c.json(
        errorBody("SSO bridge unavailable", "sso_unavailable"),
        503,
      );
    }
    if (admissionBarrier === "blocked") {
      tombstoneCurrentSession(c);
      logRefresh("cookie-session-ended");
      return c.json(errorBody("Session was signed out", "session_ended"), 401);
    }
  }

  // Preserve that pre-refresh lineage through the final primary read. The
  // signed access JWT remains an HttpOnly identity artefact for the same 30-day
  // horizon as the opaque refresh cookie, but ordinary API auth still enforces
  // its one-hour cryptographic expiry.
  const finalBarrier = await checkSsoLogoutBarrier(publicationBarrierClaims);
  if (finalBarrier === "unavailable") {
    logRefresh("cookie-sso-marker-unavailable-final");
    return c.json(errorBody("SSO bridge unavailable", "sso_unavailable"), 503);
  }
  if (finalBarrier === "blocked") {
    tombstoneCurrentSession(c);
    logRefresh("cookie-session-ended-final");
    return c.json(errorBody("Session was signed out", "session_ended"), 401);
  }

  // Cookie-backed rotation reaches this point only for v2. Ambient v1 state
  // returned above before verification or upstream consumption.
  const secure = stewardV2CookiesAreHostBound(c.env.ENVIRONMENT);

  setCookie(c, cookieNames.token, token, {
    httpOnly: true,
    secure,
    sameSite: "Lax",
    path: "/",
    maxAge: STEWARD_REFRESH_AUTHORITY_TTL_SECONDS,
  });

  if (typeof newRefreshToken === "string" && newRefreshToken.length > 0) {
    setCookie(c, cookieNames.refreshToken, newRefreshToken, {
      httpOnly: true,
      secure,
      sameSite: "Lax",
      path: "/",
      maxAge: STEWARD_REFRESH_AUTHORITY_TTL_SECONDS,
    });
  }

  setCookie(c, cookieNames.authed, "1", {
    httpOnly: false,
    secure,
    sameSite: "Lax",
    path: "/",
    maxAge: STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
  });

  logRefresh("ok");
  return c.json({
    ok: true,
    expiresAt: refresh.data.expiresAt,
    expiresIn: refresh.data.expiresIn,
    token,
  });
});

export default app;
