/**
 * POST /api/auth/steward-session — set steward-token cookie from a steward JWT.
 * DELETE /api/auth/steward-session — clear steward cookies (logout).
 */

import {
  STEWARD_CSRF_HEADER,
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
  type StewardSessionErrorCode,
  type StewardSessionRequest,
  type StewardSessionResponse,
  type StewardTelegramClaimConfirmationRequest,
  sanitizeTelegramAccountClaimContinuation,
} from "@elizaos/shared/steward-session-client";
import { type Context, Hono } from "hono";
import { deleteCookie, setCookie } from "hono/cookie";
import { getAuditDispatcher } from "@/api-app/services/audit-dispatcher-singleton";
import {
  checkStewardCookieWriterRequest,
  hasElizaNonSimpleRequestMarker,
} from "@/lib/auth/browser-origin-policy";
import {
  cookieDomainForHost,
  legacyCookieCleanupDomainForHost,
} from "@/lib/auth/cookie-domain";
import { primeVerifiedUserSessionCache } from "@/lib/auth/session-user-cache";
import { loadVerifiedStagingSessionUser } from "@/lib/auth/staging-session-binding";
import {
  type StewardTokenClaims,
  type StewardVerifyEnv,
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
import {
  getIpKey,
  getRequestIp,
  RateLimitPresets,
  rateLimit,
} from "@/lib/middleware/rate-limit-hono-cloudflare";
import {
  classifySsoBridgeLogout,
  type SsoBridgeLogoutClassification,
} from "@/lib/services/sso-bridge-codes";
import {
  StewardPhoneOwnershipError,
  verifyStewardBearerPhone,
} from "@/lib/services/steward-client";
import {
  describeSyncError,
  StewardPhoneAccountConflictError,
  type StewardSyncExecutionContext,
  StewardTelegramAccountClaimError,
  syncUserFromSteward,
} from "@/lib/steward-sync";
import { logger } from "@/lib/utils/logger";
import { settleOffResponsePath } from "@/lib/utils/settle-off-response-path";
import type { AppEnv } from "@/types/cloud-worker-env";

function stewardSecretConfigured(env: StewardVerifyEnv): boolean {
  return Boolean(env.STEWARD_SESSION_SECRET || env.STEWARD_JWT_SECRET);
}

/**
 * Second CSRF layer after the Origin policy: a cross-origin "simple request"
 * (the only kind that carries cookies without a preflight) cannot produce a
 * custom header or a JSON content type. Hono parses `text/plain` bodies as
 * JSON, so without this check an attacker page on a user-content subdomain
 * could plant a session with a preflight-less POST. Requiring the marker
 * forces the preflight that the first-party-only CORS layer fails for them.
 */
function checkNonSimpleMarker(c: {
  req: { header: (name: string) => string | undefined };
}): boolean {
  return hasElizaNonSimpleRequestMarker(c.req);
}

function getWorkerExecutionContext(
  c: Context<AppEnv>,
): StewardSyncExecutionContext | undefined {
  try {
    const candidate = c.executionCtx;
    return typeof candidate?.waitUntil === "function" ? candidate : undefined;
  } catch {
    // error-policy:J4 Hono throws when a route is invoked without a Worker
    // execution context; non-Worker callers preserve inline provisioning.
    return undefined;
  }
}

let stewardAuthMetricCounter = 0;
function logStewardAuth(outcome: string, ttl: number | null) {
  stewardAuthMetricCounter += 1;
  logger.info("[steward-auth]", {
    timestamp: new Date().toISOString(),
    ttl,
    outcome,
    metric: stewardAuthMetricCounter,
  });
}

function errorBody(
  message: string,
  code: StewardSessionErrorCode,
): { error: string; code: StewardSessionErrorCode } {
  return { error: message, code };
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
    logStewardAuth(
      metricSuffix === "final" ? "session-ended-final" : "session-ended",
      null,
    );
    return c.json(errorBody("Session was signed out", "session_ended"), 401);
  }

  logStewardAuth(
    metricSuffix === "final" ? "logout-cooldown-final" : "logout-cooldown",
    null,
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
  incoming: StewardTokenClaims,
  expectedTenantId: string | undefined,
): boolean {
  return (
    current.userId === incoming.userId &&
    effectiveStewardTenantId(current, expectedTenantId) ===
      effectiveStewardTenantId(incoming, expectedTenantId)
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
  // API deploys before Pages. The currently served pre-protocol bundle sends
  // the generic CSRF marker (`1`), so keep it on the v1 namespace while v2 is
  // wholly absent. Only the Web-Locked protocol activates v2. Once activated,
  // old tabs fail closed and their already-in-flight v1 responses stay inert.
  if (
    marker === STEWARD_CSRF_HEADER_VALUE &&
    cookieState.v2Authority === "absent" &&
    cookieState.source !== "v2"
  ) {
    return "v1";
  }
  return null;
}

function sessionCleanupMutationNamespace(
  c: Context<AppEnv>,
  cookieState: ReturnType<
    typeof readStewardSessionMigrationCookieStateFromHeader
  >,
): "v2" | "v1" | null {
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

function deleteLegacyCookieInOwnedScopes(
  c: Context<AppEnv>,
  name: string,
): void {
  deleteCookie(c, name, { path: "/" });
  const domain = legacyCookieCleanupDomainForHost(c.req.header("host"));
  if (domain) deleteCookie(c, name, { path: "/", domain });
}

const app = new Hono<AppEnv>();

// Pre-auth session-mint endpoint: the global Redis bucket is the primary
// throttle. If Redis is unreachable, keep login available but still bounded by
// a strict per-isolate bucket; top-up/payment routes stay hard fail-closed.
app.use(
  rateLimit({
    ...RateLimitPresets.STRICT,
    keyGenerator: getIpKey,
    failClosed: true,
    redisUnavailableFallback: {
      namespace: "steward-session",
    },
  }),
);

app.post("/", async (c) => {
  try {
    const isProduction = c.env.NODE_ENV === "production";
    const originCheck = checkStewardCookieWriterRequest(
      c.req,
      c.env.ENVIRONMENT,
      isProduction,
      { allowCanonicalOidcSameSite: true },
    );
    if (!originCheck.ok) {
      logStewardAuth("forbidden-origin", null);
      logger.warn("[steward-auth] rejected cross-origin POST", {
        detail: originCheck.reason,
      });
      return c.json(
        { error: "Forbidden", code: "forbidden_origin" as const },
        403,
      );
    }
    if (!checkNonSimpleMarker(c)) {
      logStewardAuth("csrf-marker-missing", null);
      return c.json(
        { error: "Forbidden", code: "csrf_marker_required" as const },
        403,
      );
    }
    const requestCookieState = readStewardSessionMigrationCookieStateFromHeader(
      c.req.header("cookie") ?? null,
      c.env.ENVIRONMENT,
    );
    const mutationNamespace = sessionMutationNamespace(c, requestCookieState);
    if (!mutationNamespace) {
      logStewardAuth("session-mutation-protocol-required", null);
      return c.json(
        errorBody(
          "Session client update required",
          "session_mutation_protocol_required",
        ),
        409,
      );
    }

    const body = (await c.req
      .json()
      .catch(() => ({}) as Partial<StewardSessionRequest>)) as Partial<
      StewardSessionRequest & StewardTelegramClaimConfirmationRequest
    >;
    const token = body.token;
    const refreshToken = body.refreshToken;
    const verifiedPhoneHint = body.verifiedPhone;
    const telegramContinuation = sanitizeTelegramAccountClaimContinuation(
      body.telegramContinuation,
    );

    if (!token || typeof token !== "string") {
      logStewardAuth("missing-token", null);
      return c.json(errorBody("Token required", "missing_token"), 400);
    }

    if (
      verifiedPhoneHint !== undefined &&
      (typeof verifiedPhoneHint !== "string" ||
        verifiedPhoneHint.trim().length === 0)
    ) {
      logStewardAuth("verified-phone-invalid", null);
      return c.json(
        errorBody("Verified phone must be a string", "verified_phone_invalid"),
        400,
      );
    }
    if (body.telegramContinuation !== undefined && !telegramContinuation) {
      logStewardAuth("telegram-claim-invalid", null);
      return c.json(
        errorBody("Invalid Telegram account claim", "telegram_claim_conflict"),
        409,
      );
    }
    if (telegramContinuation && body.telegramClaimConfirmation !== "explicit") {
      logStewardAuth("telegram-claim-confirmation-missing", null);
      return c.json(
        errorBody(
          "Telegram account confirmation required",
          "telegram_claim_conflict",
        ),
        409,
      );
    }
    if (
      body.telegramClaimConfirmation !== undefined &&
      (!telegramContinuation || body.telegramClaimConfirmation !== "explicit")
    ) {
      logStewardAuth("telegram-claim-confirmation-invalid", null);
      return c.json(
        errorBody(
          "Invalid Telegram account confirmation",
          "telegram_claim_conflict",
        ),
        409,
      );
    }

    if (!stewardSecretConfigured(c.env)) {
      // Worker can't verify any token — the deployment is missing
      // STEWARD_SESSION_SECRET / STEWARD_JWT_SECRET. Surface this distinctly
      // so the client doesn't treat it as a revocation and wipe localStorage.
      logStewardAuth("server-secret-missing", null);
      return c.json(
        errorBody(
          "Steward verification not configured on server",
          "server_secret_missing",
        ),
        503,
      );
    }

    const claims = await verifyStewardTokenCached(c.env, token);
    if (!claims) {
      logStewardAuth("invalid-token", null);
      await getAuditDispatcher()
        .emit({
          actor: { type: "user", id: "anonymous" },
          action: "auth.login.failed",
          result: "failure",
          resource: null,
          ip: getRequestIp(c),
          user_agent: c.req.header("user-agent") ?? undefined,
          request_id: c.get("requestId"),
          metadata: { provider: "steward", reason: "invalid_token" },
        })
        // error-policy:J7 audit write must not block the 401; a dropped auth audit is logged.
        .catch((err) =>
          logger.error("[StewardSession] audit emit for failed login failed", {
            error: err instanceof Error ? err.message : String(err),
          }),
        );
      return c.json(errorBody("Invalid token", "invalid_token"), 401);
    }

    const verifiedTelegramId =
      claims.authMethod === "telegram" ? claims.telegramId : undefined;
    if (claims.telegramId && !verifiedTelegramId) {
      logStewardAuth("telegram-claims-invalid", null);
      return c.json(errorBody("Invalid token", "invalid_token"), 401);
    }

    // A signed Telegram login and a browser-supplied DM continuation are two
    // independent authorities. Never let a caller combine them to select one
    // Telegram identity while authenticating as another.
    if (verifiedTelegramId && telegramContinuation) {
      logStewardAuth("telegram-authority-ambiguous", null);
      return c.json(
        errorBody(
          "Telegram login cannot consume an account continuation",
          "telegram_claim_conflict",
        ),
        409,
      );
    }

    // Cross-host logout is one user-session boundary, regardless of which
    // side originally minted the token. A direct token can survive host-bound
    // cookie deletion on the paired origin just as a bridge-issued token can;
    // both therefore consult the same durable marker before planting cookies.
    let logoutClassification: SsoBridgeLogoutClassification;
    try {
      logoutClassification = await classifySsoBridgeLogout(
        claims.userId,
        claims.issuedAt,
      );
    } catch (error) {
      // error-policy:J1 marker-store outage fails CLOSED for every session:
      // no host may re-plant cookies while global logout authority is unreadable.
      logStewardAuth("sso-marker-unavailable", null);
      logger.error("[steward-auth] SSO logout-marker store unavailable", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(
        errorBody("SSO bridge unavailable", "sso_unavailable"),
        503,
      );
    }
    if (logoutClassification.status !== "allowed") {
      return rejectLogoutClassification(c, logoutClassification, "admission");
    }

    let verifiedPhone: string | undefined;
    if (verifiedPhoneHint) {
      try {
        const ownership = await verifyStewardBearerPhone({
          env: c.env,
          bearerToken: token,
          tenantId: claims.tenantId,
          phoneNumber: verifiedPhoneHint,
        });
        if (ownership.status !== "verified") {
          logStewardAuth("verified-phone-mismatch", null);
          return c.json(
            errorBody(
              "Phone is not linked to this Steward session",
              "verified_phone_mismatch",
            ),
            403,
          );
        }
        verifiedPhone = ownership.phoneNumber;
      } catch (error) {
        if (
          error instanceof StewardPhoneOwnershipError &&
          error.code === "invalid_phone"
        ) {
          logStewardAuth("verified-phone-invalid", null);
          return c.json(
            errorBody("Invalid phone number", "verified_phone_invalid"),
            400,
          );
        }
        logStewardAuth("verified-phone-upstream-unavailable", null);
        logger.error("[steward-auth] Steward phone verification failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return c.json(
          errorBody(
            "Could not verify phone ownership",
            "steward_upstream_unavailable",
          ),
          503,
        );
      }
    }

    const executionCtx = getWorkerExecutionContext(c);
    let cloudUser: Awaited<ReturnType<typeof syncUserFromSteward>>;
    if (claims.stagingSessionBinding) {
      if (telegramContinuation) {
        logStewardAuth("telegram-claim-staging-session", null);
        return c.json(
          errorBody(
            "A QA session cannot claim a Telegram account",
            "telegram_claim_conflict",
          ),
          409,
        );
      }
      const boundCloudUser = await loadVerifiedStagingSessionUser({
        binding: claims.stagingSessionBinding,
        stewardUserId: claims.userId,
      });
      if (!boundCloudUser) {
        logStewardAuth("invalid-bound-subject", null);
        return c.json(errorBody("Invalid token", "invalid_token"), 401);
      }
      cloudUser = boundCloudUser;
    } else {
      try {
        cloudUser = await syncUserFromSteward({
          stewardUserId: claims.userId,
          email: claims.email,
          walletAddress: claims.walletAddress ?? claims.address,
          walletChainType: claims.walletChain,
          verifiedPhone,
          verifiedTelegramId,
          telegramContinuation: telegramContinuation ?? undefined,
          sharedRuntimeConversationNamespace:
            c.env.SHARED_RUNTIME_CONVERSATIONS,
          executionCtx,
          afterRequiredSignupProvisioning: async (user) => {
            try {
              // The first authenticated browser request follows immediately.
              // Prime its authorization projection after strict API-key
              // readiness but before optional onboarding work starts, so that
              // request does not race into the slower durable cache-miss path.
              await primeVerifiedUserSessionCache(token, user);
            } catch (error) {
              // error-policy:J4 Cache priming is a latency optimization. Identity is
              // already durable and the ordinary authenticated cache-miss path can
              // recover, so a cache write failure must not strand the new account.
              logger.warn(
                "[steward-auth] New-user session cache prime failed",
                {
                  userId: user.id,
                  error: error instanceof Error ? error.message : String(error),
                },
              );
            }
          },
        });
      } catch (error) {
        if (error instanceof StewardPhoneAccountConflictError) {
          logStewardAuth("verified-phone-conflict", null);
          return c.json(
            errorBody(
              "This phone account cannot be linked automatically",
              "verified_phone_conflict",
            ),
            409,
          );
        }
        if (error instanceof StewardTelegramAccountClaimError) {
          logStewardAuth("telegram-claim-conflict", null);
          return c.json(
            errorBody(
              "This Telegram chat cannot be linked automatically",
              "telegram_claim_conflict",
            ),
            409,
          );
        }
        logStewardAuth("sync-failed", null);
        // Workers Logs indexes only the message STRING — an Error passed in the
        // context object is dropped entirely. Inline everything (same fix as the
        // steward-nonce-exchange twin catch).
        logger.error(
          `[steward-auth] Failed to sync Steward user before setting cookie (stewardUserId=${claims.userId}): ${describeSyncError(error)}`,
        );
        return c.json(
          errorBody("Could not sync Steward user", "steward_user_sync_failed"),
          500,
        );
      }
    }

    const ttl = claims.expiration
      ? Math.max(0, claims.expiration - Math.floor(Date.now() / 1000))
      : null;

    const isV2Mutation = mutationNamespace === "v2";
    const secure = isV2Mutation
      ? stewardV2CookiesAreHostBound(c.env.ENVIRONMENT)
      : c.env.NODE_ENV === "production";
    const domain = isV2Mutation
      ? undefined
      : cookieDomainForHost(c.req.header("host"));

    const cookieNames =
      mutationNamespace === "v2"
        ? stewardCookieNames(c.env.ENVIRONMENT)
        : legacyStewardCookieNames(c.env.ENVIRONMENT);
    const incomingRefreshToken =
      typeof refreshToken === "string" && refreshToken.length > 0
        ? refreshToken
        : null;
    let accessOnlyRefreshMustBeDeleted = false;
    if (
      !incomingRefreshToken &&
      !claims.bridged &&
      !claims.stagingSessionBinding
    ) {
      const currentRefreshToken = requestCookieState.refreshToken;
      const currentAccessToken = requestCookieState.token;
      if (currentRefreshToken && currentAccessToken !== token) {
        const currentClaims = currentAccessToken
          ? await verifyStewardTokenCached(c.env, currentAccessToken)
          : null;
        accessOnlyRefreshMustBeDeleted =
          !currentClaims ||
          !isSameStewardIdentity(
            currentClaims,
            claims,
            c.env.STEWARD_TENANT_ID,
          );
      }
    }
    const refreshTokenToInstall =
      incomingRefreshToken ??
      (mutationNamespace === "v2" &&
      requestCookieState.source === "v1" &&
      !claims.bridged &&
      !claims.stagingSessionBinding &&
      !accessOnlyRefreshMustBeDeleted
        ? (requestCookieState.refreshToken ?? null)
        : null);

    // The admission check precedes potentially slow identity/phone sync and
    // prior-cookie identity verification. Re-read the primary only after all
    // of those awaits and immediately before configuring response cookies so
    // a logout stamped during any of them wins.
    try {
      logoutClassification = await classifySsoBridgeLogout(
        claims.userId,
        claims.issuedAt,
      );
    } catch (error) {
      logStewardAuth("sso-marker-unavailable-final", null);
      logger.error(
        "[steward-auth] SSO logout-marker store unavailable at cookie commit",
        {
          error: error instanceof Error ? error.message : String(error),
        },
      );
      return c.json(
        errorBody("SSO bridge unavailable", "sso_unavailable"),
        503,
      );
    }
    if (logoutClassification.status !== "allowed") {
      return rejectLogoutClassification(c, logoutClassification, "final");
    }

    // A renewable session retains its signed access JWT for the opaque
    // refresh-authority horizon so a later rotation/logout can still prove
    // identity lineage after the JWT's one-hour authorization window. A QA
    // session is deliberately non-renewable, so retaining that token for 30
    // days would outlive its source-bound session contract for no purpose.
    const accessCookieMaxAge = claims.stagingSessionBinding
      ? Math.max(1, ttl ?? 1)
      : STEWARD_REFRESH_AUTHORITY_TTL_SECONDS;

    setCookie(c, cookieNames.token, token, {
      httpOnly: true,
      secure,
      sameSite: "Lax",
      path: "/",
      ...(domain ? { domain } : {}),
      maxAge: accessCookieMaxAge,
    });

    if (
      claims.stagingSessionBinding ||
      (!incomingRefreshToken &&
        (claims.bridged || accessOnlyRefreshMustBeDeleted))
    ) {
      // QA and bridge sessions are deliberately access-only. A verified
      // account/tenant switch without a replacement refresh token is the same
      // identity boundary. If an older opaque refresh cookie exists, preserve
      // it only when the prior access token proves the same identity (or is the
      // exact token being installed); an absent, expired, malformed, or
      // different-identity access token cannot authorize that refresh to
      // survive. Otherwise it could later rotate account A back over newly
      // established account B.
      deleteCookie(c, cookieNames.refreshToken, {
        path: "/",
        ...(isV2Mutation && secure ? { secure: true } : {}),
        ...(domain ? { domain } : {}),
      });
    } else if (refreshTokenToInstall) {
      // Activating v2 from a same-identity v1 session must carry its opaque
      // HttpOnly refresh authority forward. Otherwise the new v2 marker would
      // suppress the only renewable credential immediately after migration.
      setCookie(c, cookieNames.refreshToken, refreshTokenToInstall, {
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

    logStewardAuth("ok", ttl);
    // The required sink remains owned by the Worker lifetime, but its database
    // RTT is not account readiness and must not delay the successful response.
    await settleOffResponsePath(executionCtx, async () => {
      await getAuditDispatcher()
        .emit({
          actor: { type: "user", id: cloudUser.id },
          action: "auth.login",
          result: "success",
          resource: null,
          org_id: cloudUser.organization_id ?? undefined,
          ip: getRequestIp(c),
          user_agent: c.req.header("user-agent") ?? undefined,
          request_id: c.get("requestId"),
          metadata: { provider: "steward", method: "session_exchange" },
        })
        // error-policy:J7 audit write must not block the login response; a dropped auth audit is logged.
        .catch((err) =>
          logger.error(
            "[StewardSession] audit emit for successful login failed",
            {
              userId: cloudUser.id,
              error: err instanceof Error ? err.message : String(err),
            },
          ),
        );
    });
    const response: StewardSessionResponse = {
      ok: true,
      userId: cloudUser.id,
      stewardUserId: claims.userId,
      initialCreditsGranted: cloudUser.initialCreditsGranted,
      initialFreeCreditsUsd: cloudUser.initialFreeCreditsUsd,
      welcomeBonusWithheld: cloudUser.welcomeBonusWithheld === true,
      welcomeBonusWithheldReason: cloudUser.welcomeBonusWithheldReason,
      welcomeBonusWithheldMessage: cloudUser.welcomeBonusWithheldMessage,
    };
    return c.json(response);
  } catch {
    logStewardAuth("error", null);
    return c.json(errorBody("Internal error", "internal_error"), 500);
  }
});

app.delete("/", (c) => {
  const isProduction = c.env.NODE_ENV === "production";
  const originCheck = checkStewardCookieWriterRequest(
    c.req,
    c.env.ENVIRONMENT,
    isProduction,
  );
  if (!originCheck.ok) {
    logStewardAuth("forbidden-origin-delete", null);
    return c.json({ error: "Forbidden" }, 403);
  }
  if (!checkNonSimpleMarker(c)) {
    logStewardAuth("csrf-marker-missing-delete", null);
    return c.json({ error: "Forbidden", code: "csrf_marker_required" }, 403);
  }
  const requestCookieState = readStewardSessionMigrationCookieStateFromHeader(
    c.req.header("cookie") ?? null,
    c.env.ENVIRONMENT,
  );
  const mutationNamespace = sessionCleanupMutationNamespace(
    c,
    requestCookieState,
  );
  if (!mutationNamespace) {
    logStewardAuth("session-mutation-protocol-required-delete", null);
    return c.json(
      errorBody(
        "Session client update required",
        "session_mutation_protocol_required",
      ),
      409,
    );
  }
  const v1 = legacyStewardCookieNames(c.env.ENVIRONMENT);
  const v2 = stewardCookieNames(c.env.ENVIRONMENT);
  const v2Secure = stewardV2CookiesAreHostBound(c.env.ENVIRONMENT);
  if (mutationNamespace === "v1") {
    deleteLegacyCookieInOwnedScopes(c, v1.token);
    deleteLegacyCookieInOwnedScopes(c, v1.refreshToken);
    deleteLegacyCookieInOwnedScopes(c, v1.authed);
    // Closing a legacy session also closes the v2 authority boundary. Without
    // this tombstone, a late/cached v1 response could make migration observable
    // again after logout.
    setCookie(c, v2.authed, STEWARD_V2_AUTHORITY_TOMBSTONE, {
      httpOnly: false,
      secure: v2Secure,
      sameSite: "Lax",
      path: "/",
      maxAge: STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
    });
    logStewardAuth("deleted-v1", null);
    return c.json({ ok: true });
  }

  const v2DeleteOpts = {
    path: "/",
    ...(v2Secure ? { secure: true } : {}),
  };
  deleteCookie(c, v2.token, v2DeleteOpts);
  deleteCookie(c, v2.refreshToken, v2DeleteOpts);
  deleteLegacyCookieInOwnedScopes(c, v1.token);
  deleteLegacyCookieInOwnedScopes(c, v1.refreshToken);
  deleteLegacyCookieInOwnedScopes(c, v1.authed);
  // Never delete the v2 authority marker: a persistent tombstone is what makes
  // a late v1 login response inert instead of reopening the migration fallback.
  setCookie(c, v2.authed, STEWARD_V2_AUTHORITY_TOMBSTONE, {
    httpOnly: false,
    secure: v2Secure,
    sameSite: "Lax",
    path: "/",
    maxAge: STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
  });
  logStewardAuth("deleted", null);
  return c.json({ ok: true });
});

export default app;
