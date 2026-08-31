/**
 * POST /api/auth/logout
 * Logs out the current user by ending all sessions and clearing auth cookies.
 * Also invalidates Redis caches to ensure immediate token invalidation.
 */

import {
  STEWARD_CSRF_HEADER,
  STEWARD_CSRF_HEADER_VALUE,
  STEWARD_SESSION_MUTATION_PROTOCOL_VALUE,
} from "@elizaos/shared/steward-session-client";
import { type Context, Hono } from "hono";
import { deleteCookie, setCookie } from "hono/cookie";
import { getAuditDispatcher } from "@/api-app/services/audit-dispatcher-singleton";
import { invalidateSessionCaches } from "@/lib/auth";
import { checkStewardCookieWriterRequest } from "@/lib/auth/browser-origin-policy";
import { legacyCookieCleanupDomainForHost } from "@/lib/auth/cookie-domain";
import {
  type StewardTokenClaims,
  verifyStewardRefreshLineageToken,
  verifyStewardTokenCached,
} from "@/lib/auth/steward-client";
import {
  legacyStewardCookieNames,
  readStewardSessionMigrationCookieStateFromHeader,
  STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
  STEWARD_V2_AUTHORITY_TOMBSTONE,
  stewardCookieNames,
  stewardV2CookiesAreHostBound,
} from "@/lib/auth/steward-cookies";
import {
  getExistingUserForVerifiedStewardClaims,
  readStewardSessionToken,
} from "@/lib/auth/workers-hono-auth";
import {
  getRequestIp,
  RateLimitPresets,
  rateLimit,
} from "@/lib/middleware/rate-limit-hono-cloudflare";
import {
  isInferenceStrongRevocationEnabled,
  revokeInferenceSessionsThrough,
} from "@/lib/services/inference-credential-revocation";
import { markSsoBridgeLogout } from "@/lib/services/sso-bridge-codes";
import { userSessionsService } from "@/lib/services/user-sessions";
import { logger } from "@/lib/utils/logger";
import type { AppEnv } from "@/types/cloud-worker-env";

const app = new Hono<AppEnv>();

function sessionMutationNamespace(
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

function clearPresentedSessionCookies(
  c: Context<AppEnv>,
  mutationNamespace: "v2" | "v1",
): void {
  const cookieNames = stewardCookieNames(c.env.ENVIRONMENT);
  const legacyCookieNames = legacyStewardCookieNames(c.env.ENVIRONMENT);
  const v2Secure = stewardV2CookiesAreHostBound(c.env.ENVIRONMENT);

  // Each environment clears only its own v1 names. On elizacloud.ai, emit both
  // a host-only and historical parent-Domain tombstone; staging keeps its
  // suffix, so it can never delete production's unsuffixed cookies.
  if (mutationNamespace === "v1") {
    deleteLegacyCookieInOwnedScopes(c, legacyCookieNames.token);
    deleteLegacyCookieInOwnedScopes(c, legacyCookieNames.refreshToken);
    deleteLegacyCookieInOwnedScopes(c, legacyCookieNames.authed);
  } else {
    const v2DeleteOpts = {
      path: "/",
      ...(v2Secure ? { secure: true } : {}),
    };
    deleteCookie(c, cookieNames.token, v2DeleteOpts);
    deleteCookie(c, cookieNames.refreshToken, v2DeleteOpts);
    deleteLegacyCookieInOwnedScopes(c, legacyCookieNames.token);
    deleteLegacyCookieInOwnedScopes(c, legacyCookieNames.refreshToken);
    deleteLegacyCookieInOwnedScopes(c, legacyCookieNames.authed);
  }
  setCookie(c, cookieNames.authed, STEWARD_V2_AUTHORITY_TOMBSTONE, {
    httpOnly: false,
    secure: v2Secure,
    sameSite: "Lax",
    path: "/",
    maxAge: STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS,
  });
  deleteCookie(c, "eliza-anon-session", { path: "/" });
}

app.use("*", rateLimit(RateLimitPresets.STANDARD));

app.post("/", async (c) => {
  const originCheck = checkStewardCookieWriterRequest(
    c.req,
    c.env.ENVIRONMENT,
    c.env.NODE_ENV === "production",
  );
  if (!originCheck.ok) {
    logger.warn("[Logout] Rejected cross-origin POST", {
      detail: originCheck.reason,
    });
    return c.json(
      { error: "Forbidden", code: "forbidden_origin" as const },
      403,
    );
  }
  const requestCookieState = readStewardSessionMigrationCookieStateFromHeader(
    c.req.header("cookie") ?? null,
    c.env.ENVIRONMENT,
  );
  const mutationNamespace = sessionMutationNamespace(c, requestCookieState);
  if (!mutationNamespace) {
    return c.json(
      {
        error: "Session client update required",
        code: "session_mutation_protocol_required" as const,
      },
      409,
    );
  }

  // A legacy logout deliberately selects only the exact unambiguous token from
  // the migration reader. A v2 logout, however, must revoke every distinct
  // Steward identity presented by the request. During lost-response recovery
  // the JS-visible bearer can still be account A while the committed HttpOnly
  // cookie already belongs to account B; choosing Bearer precedence would
  // falsely report success after stamping only A and deleting B's cookie.
  const stewardTokens = Array.from(
    new Set(
      (mutationNamespace === "v1"
        ? [requestCookieState.ambiguous ? null : requestCookieState.token]
        : [
            readStewardSessionToken(c),
            requestCookieState.ambiguous || requestCookieState.source !== "v2"
              ? null
              : requestCookieState.token,
          ]
      ).filter((token): token is string => Boolean(token)),
    ),
  );
  const unresolvedV2CookieAuthority =
    mutationNamespace === "v2" &&
    requestCookieState.source === "v2" &&
    (requestCookieState.ambiguous ||
      (!requestCookieState.token && Boolean(requestCookieState.refreshToken)));

  type ResolvedPresentedSession = {
    token: string;
    claims: StewardTokenClaims;
    existingUser: Awaited<
      ReturnType<typeof getExistingUserForVerifiedStewardClaims>
    >;
  };
  const resolvedSessions: ResolvedPresentedSession[] = [];
  let identityResolutionFailed = false;
  let identityVerificationFailed = false;
  let presentedTokenUnverifiable = false;
  for (const stewardToken of stewardTokens) {
    let verifiedClaims: StewardTokenClaims | null = null;
    try {
      verifiedClaims =
        (await verifyStewardTokenCached(c.env, stewardToken)) ??
        (await verifyStewardRefreshLineageToken(c.env, stewardToken));
    } catch (error) {
      identityVerificationFailed = true;
      logger.warn("[Logout] Presented session verification failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      continue;
    }

    if (!verifiedClaims) {
      // A caller which presents a credential is asking for its exact global
      // generation to be revoked. Cookie cleanup may still proceed, but an
      // unsigned/malformed/out-of-horizon token cannot become a false 200:
      // no user-scoped cross-host marker could be durably stamped.
      presentedTokenUnverifiable = true;
      continue;
    }

    let existingUser: ResolvedPresentedSession["existingUser"] = null;
    try {
      existingUser = await getExistingUserForVerifiedStewardClaims(
        c,
        verifiedClaims,
      );
    } catch (error) {
      // Keep the independently verified claims so the cross-host logout marker
      // and exact-token cache invalidation can still complete. User lookup is
      // required only for the optional strong inference cutoff and the
      // best-effort local session-record teardown.
      identityResolutionFailed = true;
      logger.warn("[Logout] Existing session identity resolution failed", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
    resolvedSessions.push({
      token: stewardToken,
      claims: verifiedClaims,
      existingUser,
    });
  }

  let strongRevocationFailed = false;
  const strongRevocationEnabled = isInferenceStrongRevocationEnabled(c.env);
  if (strongRevocationEnabled) {
    strongRevocationFailed = identityResolutionFailed;
    const strongBoundaries = new Map<
      string,
      {
        organizationId: string;
        userId: string;
        issuedAt: number;
      }
    >();
    for (const { claims, existingUser } of resolvedSessions) {
      if (!existingUser?.organization_id) {
        // Strong rollout means every verified presented identity needs a
        // durable inference boundary. A missing user/org mapping is therefore
        // a failed barrier, not a reason to silently skip that identity.
        strongRevocationFailed = true;
        continue;
      }
      const key = `${existingUser.organization_id}:${existingUser.id}`;
      const prior = strongBoundaries.get(key);
      if (!prior || claims.issuedAt > prior.issuedAt) {
        strongBoundaries.set(key, {
          organizationId: existingUser.organization_id,
          userId: existingUser.id,
          issuedAt: claims.issuedAt,
        });
      }
    }
    for (const boundary of strongBoundaries.values()) {
      try {
        await revokeInferenceSessionsThrough(
          boundary.organizationId,
          boundary.userId,
          boundary.issuedAt,
        );
      } catch (error) {
        // error-policy:J1 credentials deliberately remain intact for retry;
        // the server must not claim a globally complete logout until every
        // presented identity's strong inference boundary confirms denial.
        logger.error("[Logout] Strong inference-session revocation failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        strongRevocationFailed = true;
      }
    }
  }

  // Stamp the cross-host SSO logout marker before cookie mutation and in its
  // own guarded block:
  // the sso-bridge legs and the cookie-planting session-sync endpoint refuse
  // tokens issued before this moment, so an explicit logout cannot be silently
  // undone by the paired host bridging or re-syncing the other origin's
  // still-unexpired session back in. The marker lives in Postgres (same store
  // the bridge reads), so a store outage that loses this stamp also disables
  // the bridge itself — but a TRANSIENT stamp failure would leave a bridgeable
  // window once the store recovers, hence one retry and an error-level log
  // (never a silent downgrade to debug) when the stamp is unconfirmed.
  let ssoLogoutBarrierFailed = false;
  const stewardUserIds = new Set(
    resolvedSessions.map(({ claims }) => claims.userId),
  );
  for (const stewardUserId of stewardUserIds) {
    try {
      try {
        await markSsoBridgeLogout(stewardUserId);
      } catch {
        // error-policy:J6 single bounded retry of the required barrier; the
        // definitive failure is handled (loudly) by the outer catch.
        await markSsoBridgeLogout(stewardUserId);
      }
      logger.debug("[Logout] Stamped SSO bridge logout marker");
    } catch (error) {
      // Keep local credentials untouched: success cannot be claimed until the
      // cross-host revocation barrier is durable, and the client needs the same
      // A+B evidence to retry this idempotent boundary on non-2xx.
      ssoLogoutBarrierFailed = true;
      logger.error(
        "[Logout] FAILED to stamp SSO bridge logout marker — cross-host logout barrier not persisted",
        {
          error: error instanceof Error ? error.message : String(error),
        },
      );
    }
  }

  // A transient failure must leave the browser's exact credentials intact so
  // the same A+B request can retry every missing barrier. In particular, a
  // committed HttpOnly cookie B cannot be reconstructed from local bearer A
  // after a deletion response. Definitively invalid credentials are not an
  // authority: if at least one identity verified, complete that logout; if no
  // identity verified, return 401 without mutating browser state.
  if (
    identityVerificationFailed ||
    strongRevocationFailed ||
    ssoLogoutBarrierFailed
  ) {
    return c.json(
      {
        error: "Logout revocation is temporarily unavailable",
        code: "logout_revocation_unavailable" as const,
      },
      503,
    );
  }

  if (
    unresolvedV2CookieAuthority ||
    (presentedTokenUnverifiable && resolvedSessions.length === 0)
  ) {
    return c.json(
      {
        error: "Logout identity could not be verified",
        code: "invalid_token" as const,
      },
      401,
    );
  }

  // Only now is it safe to remove B: every required durable barrier for every
  // verified presented identity has completed, so no retry needs the HttpOnly
  // credential. Local session/cache cleanup below remains best-effort.
  clearPresentedSessionCookies(c, mutationNamespace);

  try {
    // Only tear down caches/sessions when the request presented a Steward JWT
    // through this environment's scoped cookie or Authorization header.
    for (const { token } of resolvedSessions) {
      await invalidateSessionCaches(token);
      logger.debug("[Logout] Invalidated session caches for token");
    }

    const existingUsers = new Map<
      string,
      NonNullable<ResolvedPresentedSession["existingUser"]>
    >();
    for (const { existingUser } of resolvedSessions) {
      if (existingUser) existingUsers.set(existingUser.id, existingUser);
    }
    for (const existingUser of existingUsers.values()) {
      await userSessionsService.endAllUserSessions(existingUser.id);
      await getAuditDispatcher()
        .emit({
          actor: { type: "user", id: existingUser.id },
          action: "auth.logout",
          result: "success",
          resource: null,
          org_id: existingUser.organization_id ?? undefined,
          ip: getRequestIp(c),
          user_agent: c.req.header("user-agent") ?? undefined,
          request_id: c.get("requestId"),
          metadata: { method: "steward_session" },
        })
        // error-policy:J7 audit write is diagnostic; logout already succeeded via
        // the cookie clear above, so a dropped audit event is logged, not fatal.
        .catch((err: unknown) => {
          logger.warn("[Logout] audit emit failed", {
            error: err instanceof Error ? err.message : String(err),
          });
        });
    }
  } catch (error) {
    // error-policy:J6 best-effort teardown — cookies are already cleared, so the
    // user is logged out client-side; a failed server-side session teardown must
    // not turn logout into a 500 that strands stale cookies. Caches expire on TTL.
    logger.warn(
      "[Logout] server-side teardown failed (cookies already cleared)",
      {
        error: error instanceof Error ? error.message : String(error),
      },
    );
  }

  return c.json({ success: true, message: "Logged out successfully" });
});

export default app;
