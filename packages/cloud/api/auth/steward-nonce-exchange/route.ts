/**
 * POST /api/auth/steward-nonce-exchange
 *
 * Server-side half of the Steward `response_type=code` OAuth flow.
 *
 * 1. Browser arrives at the post-OAuth landing page with `?code=<nonce>` —
 *    no tokens in the URL.
 * 2. The page POSTs `{ code, redirectUri, tenantId }` here.
 * 3. This route forwards to Steward `POST /auth/oauth/exchange`, which
 *    consumes the code and returns `{ token, refreshToken, expiresAt }`.
 * 4. We verify the JWT (same path as `/api/auth/steward-session`), sync the
 *    user, set the HttpOnly cookies, and return `{ ok, userId }`. The
 *    elizaos.ai hardware checkout origin also receives the access token so
 *    its cross-site Stripe checkout POST can use Bearer auth; refresh stays
 *    cookie-only.
 *
 * The refresh token never enters the browser process; the access token is
 * returned only to the hardware checkout origin that still has to authenticate
 * a cross-site Stripe checkout request with Bearer auth.
 *
 * Cookie mode uses the strict Origin plus Fetch Metadata boundary from
 * `/api/auth/steward-session`; the exact hardware-checkout origins are a
 * separate cross-site bearer-only lane that emits no cookies.
 */

import {
  STEWARD_CSRF_HEADER,
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  type StewardSessionErrorCode,
} from "@elizaos/shared/steward-session-client";
import { type Context, Hono } from "hono";
import { setCookie } from "hono/cookie";
import {
  checkStewardNonceExchangeRequest,
  hasElizaNonSimpleRequestMarker,
} from "@/lib/auth/browser-origin-policy";
import { cookieDomainForHost } from "@/lib/auth/cookie-domain";
import {
  STEWARD_AUTH_UPSTREAM_TIMEOUT_MS,
  type StewardTokenClaims,
  type StewardVerifyEnv,
  verifyStewardTokenCached,
} from "@/lib/auth/steward-client";
import {
  legacyStewardCookieNames,
  readStewardSessionMigrationCookieStateFromHeader,
  STEWARD_REFRESH_AUTHORITY_TTL_SECONDS,
  STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
  stewardCookieNames,
  stewardV2CookiesAreHostBound,
} from "@/lib/auth/steward-cookies";
import {
  classifySsoBridgeLogout,
  type SsoBridgeLogoutClassification,
} from "@/lib/services/sso-bridge-codes";
import { signStewardMutatingRequest } from "@/lib/steward/sign";
import { describeSyncError, syncUserFromSteward } from "@/lib/steward-sync";
import { logger } from "@/lib/utils/logger";
import type { AppEnv } from "@/types/cloud-worker-env";

// ─── Helpers ──────────────────────────────────────────────────────────────

function stewardSecretConfigured(env: StewardVerifyEnv): boolean {
  return Boolean(env.STEWARD_SESSION_SECRET || env.STEWARD_JWT_SECRET);
}

function errorBody(
  message: string,
  code: StewardSessionErrorCode,
): { error: string; code: StewardSessionErrorCode } {
  return { error: message, code };
}

type SsoLogoutBarrierResult =
  | SsoBridgeLogoutClassification
  | { status: "unavailable" };

async function checkSsoLogoutBarrier(
  claims: StewardTokenClaims,
): Promise<SsoLogoutBarrierResult> {
  try {
    return await classifySsoBridgeLogout(claims.userId, claims.issuedAt);
  } catch (error) {
    logger.error(
      "[steward-nonce-exchange] SSO logout-marker store unavailable",
      { error: error instanceof Error ? error.message : String(error) },
    );
    return { status: "unavailable" };
  }
}

function logoutCooldownMessage(retryAfterSeconds: number): string {
  if (retryAfterSeconds <= 0) {
    return "You signed out moments ago. Sign in again to create a new session.";
  }
  const unit = retryAfterSeconds === 1 ? "second" : "seconds";
  return `You signed out moments ago. Wait ${retryAfterSeconds} ${unit}, then sign in again to create a new session.`;
}

function rejectLogoutClassification(
  c: Context<AppEnv>,
  classification: Exclude<SsoBridgeLogoutClassification, { status: "allowed" }>,
  metricSuffix: "admission" | "final",
): Response {
  if (classification.status === "definitely_revoked") {
    logExchange(
      metricSuffix === "final" ? "session-ended-final" : "session-ended",
    );
    return c.json(errorBody("Session was signed out", "session_ended"), 401);
  }

  logExchange(
    metricSuffix === "final" ? "logout-cooldown-final" : "logout-cooldown",
  );
  c.header("Retry-After", String(classification.retryAfterSeconds));
  return c.json(
    {
      error: logoutCooldownMessage(classification.retryAfterSeconds),
      code: "logout_cooldown" as const,
      retryAfterSeconds: classification.retryAfterSeconds,
      retryAtEpochSeconds: classification.retryAtEpochSeconds,
    },
    409,
  );
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

let stewardNonceMetricCounter = 0;
function logExchange(outcome: string): void {
  stewardNonceMetricCounter += 1;
  logger.info("[steward-nonce-exchange]", {
    timestamp: new Date().toISOString(),
    outcome,
    metric: stewardNonceMetricCounter,
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

// ─── Steward exchange call ────────────────────────────────────────────────

interface StewardExchangeOk {
  ok: true;
  token: string;
  refreshToken: string;
  expiresIn?: number;
  expiresAt?: number;
}
interface StewardExchangeErr {
  ok: false;
  error?: string;
  code?: string;
}

/**
 * POST to Steward `/auth/oauth/exchange`. The Steward API authenticates the
 * exchange purely by possession of the one-time `code` — there is no client
 * secret. Steward does verify that the `redirect_uri` + `tenant_id` match
 * what was bound at `/authorize` time, so we forward whatever the browser
 * supplied (the browser already proved it has the code by sending it to us).
 */
async function callStewardExchange(
  baseUrl: string,
  body: {
    code: string;
    redirect_uri: string;
    tenant_id: string | null;
    code_verifier?: string;
  },
  pinnedTenantId?: string,
  signingSecret?: string | null,
): Promise<
  | { kind: "ok"; data: StewardExchangeOk }
  | { kind: "error"; status: number; data: StewardExchangeErr }
  | { kind: "transport"; message: string }
> {
  const exchangeUrl = new URL(`${baseUrl}/auth/oauth/exchange`);
  const headers = new Headers({
    "Content-Type": "application/json",
    Accept: "application/json",
  });
  // Pin the tenant per-env: this route bypasses the /steward/* proxy in
  // bootstrap-app.ts. Steward's `/auth/oauth/exchange` reads tenant from
  // the body (auth.ts:2557-2563), but if a caller sends `tenant_id=null`
  // Steward falls back to STEWARD_DEFAULT_TENANT_ID. The header is a
  // belt-and-suspenders pin in case future Steward versions consult it.
  if (typeof pinnedTenantId === "string" && pinnedTenantId.trim().length > 0) {
    headers.set("X-Steward-Tenant", pinnedTenantId.trim());
  }
  // Steward gates mutating `/auth/*` on a freshness header AND an HMAC
  // signature (`X-Steward-Signature: v1=<hex>`). The `/steward/*` proxy signs
  // for browser-driven flows, but this route forwards to Steward directly (to
  // pin the tenant), so it must sign here too — otherwise the exchange 401s
  // with "X-Steward-Signature header required". Sign over the EXACT bytes we
  // send. Without a configured secret we send unsigned (same as the proxy) and
  // let Steward decide. See packages/cloud/api/src/steward/{embedded,sign}.ts.
  // (The signer mints a fresh Idempotency-Key per attempt — fine here because
  // the OAuth code is single-use; Steward 401s a replayed code anyway.)
  const bodyText = JSON.stringify(body);
  const bodyBytes = new TextEncoder().encode(bodyText);
  if (typeof signingSecret === "string" && signingSecret.length > 0) {
    await signStewardMutatingRequest(
      signingSecret,
      "POST",
      `${exchangeUrl.pathname}${exchangeUrl.search}`,
      headers,
      bodyBytes,
    );
  }
  let response: Response;
  try {
    response = await fetch(exchangeUrl.toString(), {
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
  let parsed: StewardExchangeOk | StewardExchangeErr | null = null;
  try {
    parsed = text
      ? (JSON.parse(text) as StewardExchangeOk | StewardExchangeErr)
      : null;
  } catch {
    parsed = null;
  }

  if (!response.ok || !parsed || parsed.ok !== true) {
    return {
      kind: "error",
      status: response.status,
      data: (parsed as StewardExchangeErr) ?? {
        ok: false,
        error: text || "Steward exchange failed",
      },
    };
  }
  return { kind: "ok", data: parsed };
}

// ─── Route ────────────────────────────────────────────────────────────────

const app = new Hono<AppEnv>();

app.post("/", async (c) => {
  const isProduction = c.env.NODE_ENV === "production";
  const originCheck = checkStewardNonceExchangeRequest(
    c.req,
    c.env.ENVIRONMENT,
    isProduction,
  );
  if (!originCheck.ok) {
    logExchange("forbidden-origin");
    logger.warn("[steward-nonce-exchange] rejected cross-origin POST", {
      detail: originCheck.reason,
    });
    return c.json(errorBody("Forbidden", "forbidden_origin"), 403);
  }
  // Same non-simple-marker CSRF layer as /api/auth/steward-session: forces a
  // preflight that user-content origins cannot pass.
  if (!hasElizaNonSimpleRequestMarker(c.req)) {
    logExchange("csrf-marker-missing");
    return c.json(errorBody("Forbidden", "csrf_marker_required"), 403);
  }
  let mutationNamespace: "v2" | "v1" | null = null;
  if (originCheck.responseMode === "cookie") {
    const requestCookieState = readStewardSessionMigrationCookieStateFromHeader(
      c.req.header("cookie") ?? null,
      c.env.ENVIRONMENT,
    );
    mutationNamespace = sessionMutationNamespace(c, requestCookieState);
    if (!mutationNamespace) {
      logExchange("session-mutation-protocol-required");
      return c.json(
        errorBody(
          "Session client update required",
          "session_mutation_protocol_required",
        ),
        409,
      );
    }
  }

  const body = (await c.req.json().catch(() => ({}))) as {
    code?: unknown;
    redirectUri?: unknown;
    redirect_uri?: unknown;
    tenantId?: unknown;
    tenant_id?: unknown;
    codeVerifier?: unknown;
    code_verifier?: unknown;
    telegramContinuation?: unknown;
  };

  const code = typeof body.code === "string" ? body.code.trim() : "";
  const redirectUri =
    typeof body.redirectUri === "string"
      ? body.redirectUri.trim()
      : typeof body.redirect_uri === "string"
        ? body.redirect_uri.trim()
        : "";
  const rawTenant =
    typeof body.tenantId === "string"
      ? body.tenantId.trim()
      : typeof body.tenant_id === "string"
        ? body.tenant_id.trim()
        : "";
  // Fall back to the Worker's pinned tenant when the SPA omits it (e.g. because
  // its `NEXT_PUBLIC_STEWARD_TENANT_ID` failed to inline). Without this, Steward
  // would resolve `body.tenant_id=null` to STEWARD_DEFAULT_TENANT_ID and a staging
  // OAuth exchange would mint a session against the prod tenant.
  const envTenant = c.env.STEWARD_TENANT_ID?.trim() ?? "";
  const tenantId =
    rawTenant.length > 0 ? rawTenant : envTenant.length > 0 ? envTenant : null;
  // PKCE verifier for `response_type=code`. The SPA stashes it before the
  // /authorize redirect and replays it here; we forward it to Steward, which
  // checks it against the challenge bound at /authorize. It is REQUIRED: the
  // hosted login always starts the flow with a S256 challenge, so a
  // verifier-less exchange can only be a pre-PKCE client or a planted
  // callback — both must fail closed.
  const codeVerifier =
    typeof body.codeVerifier === "string"
      ? body.codeVerifier.trim()
      : typeof body.code_verifier === "string"
        ? body.code_verifier.trim()
        : "";

  if (!code) {
    logExchange("missing-code");
    return c.json(errorBody("code required", "missing_code"), 400);
  }
  if (!redirectUri) {
    logExchange("missing-redirect-uri");
    return c.json(errorBody("redirectUri required", "missing_code"), 400);
  }
  if (!codeVerifier) {
    logExchange("missing-code-verifier");
    return c.json(
      errorBody("codeVerifier required", "missing_code_verifier"),
      400,
    );
  }
  if (body.telegramContinuation !== undefined) {
    logExchange("telegram-claim-not-permitted");
    return c.json(
      errorBody("Account confirmation required", "telegram_claim_conflict"),
      409,
    );
  }
  if (!stewardSecretConfigured(c.env)) {
    logExchange("server-secret-missing");
    return c.json(
      errorBody(
        "Steward verification not configured on server",
        "server_secret_missing",
      ),
      503,
    );
  }

  const stewardBaseUrl = resolveStewardBaseUrl(c.env);
  if (!stewardBaseUrl) {
    logExchange("upstream-not-configured");
    return c.json(
      errorBody(
        "Steward upstream not configured",
        "steward_upstream_unavailable",
      ),
      503,
    );
  }

  const exchange = await callStewardExchange(
    stewardBaseUrl,
    {
      code,
      redirect_uri: redirectUri,
      tenant_id: tenantId,
      code_verifier: codeVerifier,
    },
    c.env.STEWARD_TENANT_ID,
    c.env.STEWARD_REQUEST_SIGNING_SECRET,
  );

  if (exchange.kind === "transport") {
    logExchange("upstream-transport-error");
    logger.error("[steward-nonce-exchange] upstream transport failure", {
      message: exchange.message,
    });
    return c.json(
      errorBody("Steward upstream unavailable", "steward_upstream_unavailable"),
      502,
    );
  }

  if (exchange.kind === "error") {
    const upstreamCode = exchange.data.code;
    // Pass through the Steward error codes verbatim when they're in our known
    // set; otherwise default to `code_invalid` so the client wipes URL state
    // and re-prompts sign-in.
    const mapped: StewardSessionErrorCode =
      upstreamCode === "code_expired" ||
      upstreamCode === "code_redirect_mismatch" ||
      upstreamCode === "code_tenant_mismatch" ||
      upstreamCode === "code_invalid"
        ? upstreamCode
        : "code_invalid";
    logExchange(`upstream-${mapped}`);
    // Steward returns 401 for all of these. Anything else we collapse to
    // 502 so the client can disambiguate "your code is bad" from "Steward
    // is unhealthy" without us widening the Hono status union.
    const status: 401 | 502 = exchange.status === 401 ? 401 : 502;
    return c.json(
      errorBody(exchange.data.error || "Code exchange failed", mapped),
      status,
    );
  }

  const { token, refreshToken } = exchange.data;

  const claims = await verifyStewardTokenCached(c.env, token);
  if (!claims) {
    logExchange("invalid-token-after-exchange");
    return c.json(errorBody("Invalid token", "invalid_token"), 401);
  }

  const admissionBarrier = await checkSsoLogoutBarrier(claims);
  if (admissionBarrier.status === "unavailable") {
    logExchange("sso-marker-unavailable");
    return c.json(errorBody("SSO bridge unavailable", "sso_unavailable"), 503);
  }
  if (admissionBarrier.status !== "allowed") {
    return rejectLogoutClassification(c, admissionBarrier, "admission");
  }

  let cloudUser: Awaited<ReturnType<typeof syncUserFromSteward>>;
  try {
    cloudUser = await syncUserFromSteward({
      stewardUserId: claims.userId,
      email: claims.email,
      walletAddress: claims.walletAddress ?? claims.address,
      walletChainType: claims.walletChain,
    });
  } catch (error) {
    logExchange("sync-failed");
    // Workers Logs indexes only the message STRING — an Error passed in the
    // context object is dropped entirely (a week of these prod 500s was
    // unobservable because of exactly that). Inline everything.
    logger.error(
      `[steward-nonce-exchange] Failed to sync Steward user before setting cookie (stewardUserId=${claims.userId}): ${describeSyncError(error)}`,
    );
    return c.json(
      errorBody("Could not sync Steward user", "steward_user_sync_failed"),
      500,
    );
  }

  // User convergence can outlive a concurrent logout. Re-read the strongly
  // consistent marker immediately before either cookies or the JSON bearer
  // are published; both response modes represent new session authority.
  const finalBarrier = await checkSsoLogoutBarrier(claims);
  if (finalBarrier.status === "unavailable") {
    logExchange("sso-marker-unavailable-final");
    return c.json(errorBody("SSO bridge unavailable", "sso_unavailable"), 503);
  }
  if (finalBarrier.status !== "allowed") {
    return rejectLogoutClassification(c, finalBarrier, "final");
  }

  if (originCheck.responseMode === "cookie") {
    const isV2Mutation = mutationNamespace === "v2";
    const secure = isV2Mutation
      ? stewardV2CookiesAreHostBound(c.env.ENVIRONMENT)
      : c.env.NODE_ENV === "production";
    const domain = isV2Mutation
      ? undefined
      : cookieDomainForHost(c.req.header("host"));
    const cookieNames = isV2Mutation
      ? stewardCookieNames(c.env.ENVIRONMENT)
      : legacyStewardCookieNames(c.env.ENVIRONMENT);

    setCookie(c, cookieNames.token, token, {
      httpOnly: true,
      secure,
      sameSite: "Lax",
      path: "/",
      ...(domain ? { domain } : {}),
      maxAge: STEWARD_REFRESH_AUTHORITY_TTL_SECONDS,
    });

    if (typeof refreshToken === "string" && refreshToken.length > 0) {
      setCookie(c, cookieNames.refreshToken, refreshToken, {
        httpOnly: true,
        secure,
        sameSite: "Lax",
        path: "/",
        ...(domain ? { domain } : {}),
        maxAge: STEWARD_REFRESH_AUTHORITY_TTL_SECONDS,
      });
    }

    setCookie(c, cookieNames.authed, "1", {
      httpOnly: false,
      secure,
      sameSite: "Lax",
      path: "/",
      ...(domain ? { domain } : {}),
      maxAge:
        mutationNamespace === "v2"
          ? STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS
          : STEWARD_REFRESH_AUTHORITY_TTL_SECONDS,
    });
  }

  logExchange("ok");
  // Returning `token` here so the SPA can mirror it into localStorage. The
  // HttpOnly cookies above are the canonical session; the localStorage copy is
  // what @stwd/react's `useAuth()` and the SPA's
  // `readStewardSessionFromStorage()` actually read on `/cloud` route
  // mount to decide `isAuthenticated`. Without this, OAuth users land back
  // on `/login` after a successful exchange (wallet/SIWE keeps working only
  // because the Steward SDK writes its own localStorage copy). The original
  // "tokens never enter JS" design intent is aspirational — until the SPA
  // auth check trusts the steward-authed marker cookie alone, the JWT has
  // to be reachable from JS. The long-lived refresh token is NOT mirrored:
  // it stays in the HttpOnly cookie so a JS-readable token theft is bounded
  // to the short-lived access token.
  return c.json({
    ok: true,
    userId: cloudUser.id,
    stewardUserId: claims.userId,
    expiresAt: exchange.data.expiresAt,
    expiresIn: exchange.data.expiresIn,
    initialCreditsGranted: cloudUser.initialCreditsGranted,
    initialFreeCreditsUsd: cloudUser.initialFreeCreditsUsd,
    welcomeBonusWithheld: cloudUser.welcomeBonusWithheld === true,
    welcomeBonusWithheldReason: cloudUser.welcomeBonusWithheldReason,
    welcomeBonusWithheldMessage: cloudUser.welcomeBonusWithheldMessage,
    token,
  });
});

export default app;
