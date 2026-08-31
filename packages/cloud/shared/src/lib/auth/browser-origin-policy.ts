/**
 * Canonical browser-origin and CSRF policy for Steward session mutations. It
 * permits the exact Eliza-owned UI hosts, explicit redirect-era hosts, and
 * same-origin requests without trusting arbitrary eliza.app subdomains.
 */

import {
  ELIZA_DOMAIN_CONTRACTS,
  type ElizaCloudEnvironment,
  LANDING_AB_HOSTNAMES,
  LEGACY_ELIZA_DOMAIN_CONTRACTS,
} from "@elizaos/shared/elizacloud";

const ELIZA_BROWSER_ORIGIN_HOSTS: ReadonlySet<string> = new Set([
  ...Object.values(ELIZA_DOMAIN_CONTRACTS).flatMap((contract) => [
    new URL(contract.marketingOrigin).hostname,
    new URL(contract.cloudAppOrigin).hostname,
  ]),
  `www.${new URL(ELIZA_DOMAIN_CONTRACTS.production.marketingOrigin).hostname}`,
  ...Object.values(LEGACY_ELIZA_DOMAIN_CONTRACTS).flatMap((contract) => [
    ...contract.marketingHostnames,
    ...contract.cloudAppHostnames,
  ]),
  "elizaos.ai",
  "www.elizaos.ai",
]);

const LOCAL_DEV_ORIGIN_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "0.0.0.0"]);

export interface RequestHeaderReader {
  header(name: string): string | undefined;
}

export interface RequestMetadataReader extends RequestHeaderReader {
  url: string;
}

export type BrowserOriginCheck = { ok: true } | { ok: false; reason: string };

export type StewardNonceExchangeOriginCheck =
  | { ok: true; responseMode: "cookie" | "bearer-only" }
  | { ok: false; reason: string };

const HARDWARE_CHECKOUT_ORIGINS: ReadonlySet<string> = new Set([
  "https://elizaos.ai",
  "https://www.elizaos.ai",
]);

const PRODUCTION_AB_ORIGINS: ReadonlySet<string> = new Set(
  LANDING_AB_HOSTNAMES.map((hostname) => `https://${hostname}`),
);
const STAGING_PAGES_ORIGIN = "https://develop.eliza-app.pages.dev";

/**
 * Custom header whose presence marks a non-simple request. A cross-origin
 * "simple request" — the only browser request kind that carries cookies
 * without a CORS preflight — cannot set custom headers or a JSON content
 * type, so requiring one of those markers on a cookie-authenticated mutation
 * forces a preflight that the first-party-only CORS layer fails for
 * user-content origins. Same convention as the app-core session CSRF header.
 */
export const ELIZA_CSRF_HEADER = "x-eliza-csrf";

export function hasElizaNonSimpleRequestMarker(req: RequestHeaderReader): boolean {
  const csrf = req.header(ELIZA_CSRF_HEADER);
  if (typeof csrf === "string" && csrf.trim().length > 0) return true;
  const contentType = req.header("content-type") ?? "";
  return contentType.toLowerCase().startsWith("application/json");
}

export function browserOriginHost(rawOrigin: string | undefined): string | null {
  if (!rawOrigin) return null;
  try {
    return new URL(rawOrigin).hostname.toLowerCase();
  } catch {
    // error-policy:J3 malformed browser origin is an explicit invalid result.
    return null;
  }
}

/**
 * Parse an Origin header only when it is already in the browser's serialized
 * origin form. Comparing the complete serialization prevents a scheme or port
 * variant from inheriting a hostname-only allowlist decision.
 */
export function serializedBrowserOrigin(rawOrigin: string | undefined): string | null {
  if (!rawOrigin || rawOrigin === "null") return null;
  try {
    const parsed = new URL(rawOrigin);
    return parsed.origin === rawOrigin ? parsed.origin : null;
  } catch {
    // error-policy:J3 malformed browser origin is an explicit invalid result.
    return null;
  }
}

function stewardEnvironment(environment: string | undefined): ElizaCloudEnvironment {
  return environment === "staging" ? "staging" : "production";
}

function requestUrlOrigin(req: RequestMetadataReader): string | null {
  try {
    return new URL(req.url).origin;
  } catch {
    // error-policy:J3 a malformed request URL fails the browser boundary.
    return null;
  }
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    const hostname = new URL(origin).hostname;
    return LOCAL_DEV_ORIGIN_HOSTS.has(hostname) || hostname === "::1";
  } catch {
    // error-policy:J3 malformed browser origin is an explicit invalid result.
    return false;
  }
}

function isHostedStewardFrontendOrigin(
  origin: string,
  environment: ElizaCloudEnvironment,
): boolean {
  const contract = ELIZA_DOMAIN_CONTRACTS[environment];
  if (origin === contract.marketingOrigin || origin === contract.cloudAppOrigin) {
    return true;
  }
  if (environment === "staging") return origin === STAGING_PAGES_ORIGIN;
  return environment === "production" && PRODUCTION_AB_ORIGINS.has(origin);
}

/**
 * Strict Fetch Metadata boundary for browser routes that may emit Steward
 * cookies. Hosted requests must come from a canonical Pages document in the
 * same environment and carry `Sec-Fetch-Site: same-origin`; API origins,
 * redirects, legacy hosts, sibling environments, and missing metadata fail.
 *
 * Session POST may opt into the one required cross-origin exception: the
 * canonical marketing origin calling its matching canonical API origin with
 * `Sec-Fetch-Site: same-site` during the OIDC continuation.
 */
export function checkStewardCookieWriterRequest(
  req: RequestMetadataReader,
  environment: string | undefined,
  isProduction: boolean,
  options: { allowCanonicalOidcSameSite?: boolean } = {},
): BrowserOriginCheck {
  const rawOrigin = req.header("origin");
  const origin = serializedBrowserOrigin(rawOrigin);
  if (!rawOrigin) return { ok: false, reason: "missing_origin" };
  if (!origin) return { ok: false, reason: "invalid_origin" };

  const fetchSite = req.header("sec-fetch-site");
  if (!fetchSite) return { ok: false, reason: "missing_sec_fetch_site" };

  const selectedEnvironment = stewardEnvironment(environment);
  if (fetchSite === "same-origin" && isHostedStewardFrontendOrigin(origin, selectedEnvironment)) {
    return { ok: true };
  }

  const targetOrigin = requestUrlOrigin(req);
  if (
    !isProduction &&
    fetchSite === "same-origin" &&
    targetOrigin === origin &&
    isLoopbackOrigin(origin)
  ) {
    return { ok: true };
  }

  const contract = ELIZA_DOMAIN_CONTRACTS[selectedEnvironment];
  if (
    options.allowCanonicalOidcSameSite === true &&
    fetchSite === "same-site" &&
    origin === contract.marketingOrigin &&
    targetOrigin === contract.cloudApiOrigin
  ) {
    return { ok: true };
  }

  return {
    ok: false,
    reason: `disallowed_origin_or_fetch_site:${fetchSite}`,
  };
}

/**
 * Nonce exchange has one non-cookie mode for the hardware checkout. The two
 * exact checkout origins may call the matching canonical API cross-site and
 * receive an access token, but the route must emit zero Set-Cookie headers.
 */
export function checkStewardNonceExchangeRequest(
  req: RequestMetadataReader,
  environment: string | undefined,
  isProduction: boolean,
): StewardNonceExchangeOriginCheck {
  const cookieWriter = checkStewardCookieWriterRequest(req, environment, isProduction);
  if (cookieWriter.ok) return { ok: true, responseMode: "cookie" };

  const origin = serializedBrowserOrigin(req.header("origin"));
  const selectedEnvironment = stewardEnvironment(environment);
  if (
    origin &&
    HARDWARE_CHECKOUT_ORIGINS.has(origin) &&
    req.header("sec-fetch-site") === "cross-site" &&
    requestUrlOrigin(req) === ELIZA_DOMAIN_CONTRACTS[selectedEnvironment].cloudApiOrigin
  ) {
    return { ok: true, responseMode: "bearer-only" };
  }
  return cookieWriter;
}

export function isPermittedElizaBrowserOrigin(
  origin: string | null,
  requestHost: string | null,
  isProduction: boolean,
): boolean {
  if (!origin) return false;
  if (ELIZA_BROWSER_ORIGIN_HOSTS.has(origin)) return true;
  if (requestHost && origin === requestHost) return true;
  return !isProduction && LOCAL_DEV_ORIGIN_HOSTS.has(origin);
}

export function checkElizaMutatingRequestOrigin(
  req: RequestHeaderReader,
  isProduction: boolean,
): BrowserOriginCheck {
  const origin = browserOriginHost(req.header("origin"));
  const referer = browserOriginHost(req.header("referer"));
  const requestHost = (req.header("host") ?? "").split(":")[0]?.toLowerCase() ?? "";
  if (!origin && !referer) {
    return { ok: false, reason: "missing_origin_and_referer" };
  }
  if (origin && isPermittedElizaBrowserOrigin(origin, requestHost, isProduction)) {
    return { ok: true };
  }
  if (!origin && referer && isPermittedElizaBrowserOrigin(referer, requestHost, isProduction)) {
    return { ok: true };
  }
  return {
    ok: false,
    reason: `origin=${origin ?? "null"} referer=${referer ?? "null"}`,
  };
}
