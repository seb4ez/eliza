/**
 * Environment-scoped Steward auth cookie names.
 *
 * Current Steward sessions use browser-enforced `__Host-` names in every
 * hosted environment. Historical v1 cookies may still be inspected by the
 * explicitly named migration reader, but they are never accepted by the
 * generic authentication reader.
 */

export interface StewardCookieNames {
  token: string;
  refreshToken: string;
  authed: string;
}

export interface StewardSessionCookieState {
  /** Duplicate or malformed auth-cookie names make the request ambiguous. */
  ambiguous: boolean;
  /** A v2 marker is authoritative even when its value is the logout tombstone. */
  v2Authority: "absent" | "active" | "tombstone";
  /** Credential namespace selected without ever mixing v1 and v2 values. */
  source: "v2" | "v1" | null;
  token: string | undefined;
  refreshToken: string | undefined;
}

const V1_BASE_TOKEN = "steward-token";
const V1_BASE_REFRESH = "steward-refresh-token";
const V1_BASE_AUTHED = "steward-authed";
const HOST_BOUND_V2_BASE_TOKEN = "__Host-steward-token-v2";
const HOST_BOUND_V2_BASE_REFRESH = "__Host-steward-refresh-token-v2";
const HOST_BOUND_V2_BASE_AUTHED = "__Host-steward-authed-v2";
const LOCAL_V2_BASE_TOKEN = "steward-token-v2";
const LOCAL_V2_BASE_REFRESH = "steward-refresh-token-v2";
const LOCAL_V2_BASE_AUTHED = "steward-authed-v2";

export const STEWARD_V2_AUTHORITY_ACTIVE = "1";
export const STEWARD_V2_AUTHORITY_TOMBSTONE = "0";

/**
 * Maximum lifetime of the opaque refresh authority and of the signed access
 * JWT retained beside it as identity lineage. Keeping the access cookie for
 * this duration does not extend authentication: every ordinary request still
 * verifies the JWT's one-hour cryptographic expiry.
 */
export const STEWARD_REFRESH_AUTHORITY_TTL_SECONDS = 30 * 24 * 60 * 60;

/**
 * Keep the v2 authority decision across browser restarts and longer than every
 * v1 credential. Chromium caps cookie lifetime at 400 days, so use that bound.
 * A successful v2 login refreshes the active marker; logout replaces it with
 * the tombstone instead of deleting it and exposing the v1 fallback again.
 */
export const STEWARD_V2_AUTHORITY_MAX_AGE_SECONDS = 400 * 24 * 60 * 60;

/**
 * The historical unsuffixed names. Production keeps them for compatibility.
 * Non-production uses suffixed names so previews and older deployments cannot
 * accidentally interpret a different environment's browser state.
 */
export const LEGACY_STEWARD_COOKIES: StewardCookieNames = {
  token: V1_BASE_TOKEN,
  refreshToken: V1_BASE_REFRESH,
  authed: V1_BASE_AUTHED,
};

/** Production v2 names. Non-production appends its environment suffix. */
export const STEWARD_V2_COOKIES: StewardCookieNames = {
  token: HOST_BOUND_V2_BASE_TOKEN,
  refreshToken: HOST_BOUND_V2_BASE_REFRESH,
  authed: HOST_BOUND_V2_BASE_AUTHED,
};

/** Loopback HTTP cannot accept `__Host-` cookies because they require Secure. */
export const LOCAL_STEWARD_V2_COOKIES: StewardCookieNames = {
  token: LOCAL_V2_BASE_TOKEN,
  refreshToken: LOCAL_V2_BASE_REFRESH,
  authed: LOCAL_V2_BASE_AUTHED,
};

function cookieNamesForEnvironment(
  base: StewardCookieNames,
  environment: string | undefined,
): StewardCookieNames {
  if (!environment || environment === "production") return base;
  return {
    token: `${base.token}-${environment}`,
    refreshToken: `${base.refreshToken}-${environment}`,
    authed: `${base.authed}-${environment}`,
  };
}

/**
 * Whether this Worker may mutate the historical unsuffixed cookie names.
 * Production owns those names and clears/rotates them; non-production must not
 * mutate them. Host-only cookies now isolate canonical deployments, while this
 * rule preserves compatibility with older and preview host layouts.
 */
export function canMutateLegacyStewardCookies(environment: string | undefined): boolean {
  return !environment || environment === "production";
}

/** Resolve the cookie names for a Worker environment (`c.env.ENVIRONMENT`).
 * Unset (local dev / tests) behaves as production: localhost cookies are
 * host-scoped (no shared parent zone), so there is nothing to collide with. */
export function legacyStewardCookieNames(environment: string | undefined): StewardCookieNames {
  return cookieNamesForEnvironment(LEGACY_STEWARD_COOKIES, environment);
}

/**
 * Resolve the rollout-isolated v2 names used by every current cookie writer.
 * The previous Worker knows only {@link legacyStewardCookieNames}, so a late
 * v1 response cannot overwrite or delete these cookies.
 */
export function stewardCookieNames(environment: string | undefined): StewardCookieNames {
  if (environment?.trim() === "local") {
    return cookieNamesForEnvironment(LOCAL_STEWARD_V2_COOKIES, "local");
  }
  return cookieNamesForEnvironment(STEWARD_V2_COOKIES, environment);
}

/**
 * Production, staging, previews, and fail-safe unset environments use the
 * browser-enforced `__Host-` contract. Only the explicit local environment is
 * allowed to use non-prefixed cookies so loopback HTTP remains usable.
 */
export function stewardV2CookiesAreHostBound(environment: string | undefined): boolean {
  return environment?.trim() !== "local";
}

interface UniqueCookieRead {
  value: string | undefined;
  ambiguous: boolean;
}

function readUniqueCookieValueFromHeader(
  cookieHeader: string | null,
  name: string,
): UniqueCookieRead {
  if (!cookieHeader) return { value: undefined, ambiguous: false };

  let value: string | undefined;
  let matches = 0;
  let malformed = false;
  for (const segment of cookieHeader.split(";")) {
    const trimmed = segment.trim();
    if (!trimmed.startsWith(`${name}=`)) continue;
    matches += 1;
    const raw = trimmed.slice(name.length + 1).trimStart();
    try {
      value = decodeURIComponent(raw);
    } catch {
      malformed = true;
    }
  }

  return {
    value: matches === 1 && !malformed ? value : undefined,
    ambiguous: matches > 1 || malformed,
  };
}

/**
 * Select the complete host-bound v2 cookie namespace. A present v2 marker is the
 * authority boundary: `1` enables only v2 credentials, while `0` (and any
 * malformed value) is a fail-closed tombstone. With no marker, partial v2
 * credentials still form one namespace. Historical v1 cookies are deliberately
 * invisible here so a parent-domain cookie planted by an untrusted child host
 * can never authenticate a request to the canonical application.
 */
export function readStewardSessionCookieStateFromHeader(
  cookieHeader: string | null,
  environment: string | undefined,
): StewardSessionCookieState {
  const v2 = stewardCookieNames(environment);
  const markerRead = readUniqueCookieValueFromHeader(cookieHeader, v2.authed);
  const v2TokenRead = readUniqueCookieValueFromHeader(cookieHeader, v2.token);
  const v2RefreshTokenRead = readUniqueCookieValueFromHeader(cookieHeader, v2.refreshToken);
  const v2Ambiguous = markerRead.ambiguous || v2TokenRead.ambiguous || v2RefreshTokenRead.ambiguous;
  const marker = markerRead.value;
  const v2Token = v2TokenRead.value;
  const v2RefreshToken = v2RefreshTokenRead.value;

  if (v2Ambiguous) {
    return {
      ambiguous: true,
      v2Authority: "tombstone",
      source: "v2",
      token: undefined,
      refreshToken: undefined,
    };
  }

  if (marker !== undefined) {
    if (marker !== STEWARD_V2_AUTHORITY_ACTIVE) {
      return {
        ambiguous: false,
        v2Authority: "tombstone",
        source: "v2",
        token: undefined,
        refreshToken: undefined,
      };
    }
    return {
      ambiguous: false,
      v2Authority: "active",
      source: "v2",
      token: v2Token,
      refreshToken: v2RefreshToken,
    };
  }

  if (v2Token !== undefined || v2RefreshToken !== undefined) {
    return {
      ambiguous: false,
      v2Authority: "absent",
      source: "v2",
      token: v2Token,
      refreshToken: v2RefreshToken,
    };
  }

  return {
    ambiguous: false,
    v2Authority: "absent",
    source: null,
    token: undefined,
    refreshToken: undefined,
  };
}

/**
 * Inspect v1 only as an explicit migration/cleanup source for cookie writers.
 * Callers must independently authorize the mutation (for example, a verified
 * token supplied in a session POST body); this state must never be used for
 * ambient request authentication.
 */
export function readStewardSessionMigrationCookieStateFromHeader(
  cookieHeader: string | null,
  environment: string | undefined,
): StewardSessionCookieState {
  const v2State = readStewardSessionCookieStateFromHeader(cookieHeader, environment);
  if (v2State.ambiguous || v2State.v2Authority !== "absent" || v2State.source === "v2") {
    return v2State;
  }

  const v1 = legacyStewardCookieNames(environment);
  const v1TokenRead = readUniqueCookieValueFromHeader(cookieHeader, v1.token);
  const v1RefreshTokenRead = readUniqueCookieValueFromHeader(cookieHeader, v1.refreshToken);
  const v1Ambiguous = v1TokenRead.ambiguous || v1RefreshTokenRead.ambiguous;
  const v1Token = v1TokenRead.value;
  const v1RefreshToken = v1RefreshTokenRead.value;
  return {
    ambiguous: v1Ambiguous,
    v2Authority: "absent",
    source: !v1Ambiguous && (v1Token !== undefined || v1RefreshToken !== undefined) ? "v1" : null,
    token: v1Ambiguous ? undefined : v1Token,
    refreshToken: v1Ambiguous ? undefined : v1RefreshToken,
  };
}

/**
 * Read this environment's host-bound v2 Steward access cookie. Historical v1
 * cookies are intentionally excluded even when no v2 marker exists.
 */
export function readStewardAccessCookieFromHeader(
  cookieHeader: string | null,
  environment: string | undefined,
): string | undefined {
  return readStewardSessionCookieStateFromHeader(cookieHeader, environment).token;
}
