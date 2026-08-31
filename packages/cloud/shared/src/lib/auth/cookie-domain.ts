/**
 * Steward cookies are always host-only. The unified Pages artifact proxies
 * auth requests same-origin, while the one-time SSO bridge transfers sessions
 * between eliza.app and cloud.eliza.app without exposing cookies to dedicated
 * managed-agent or user-content subdomains.
 */
export function cookieDomainForHost(_host: string | undefined): string | undefined {
  return undefined;
}

const LEGACY_STEWARD_COOKIE_PARENT_DOMAIN = "elizacloud.ai";

/**
 * Return the historical parent domain only for destructive v1-cookie cleanup.
 *
 * Current credentials must stay host-only, so this intentionally lives beside
 * (rather than inside) {@link cookieDomainForHost}. Callers must first emit a
 * host-only tombstone, then may emit a second tombstone with this Domain. A
 * strict host-header parser prevents suffix confusion and never enables the
 * cleanup path on eliza.app, loopback, or an attacker-owned parent zone.
 */
export function legacyCookieCleanupDomainForHost(
  host: string | undefined,
): typeof LEGACY_STEWARD_COOKIE_PARENT_DOMAIN | undefined {
  const value = host?.trim();
  if (!value || value.startsWith("[")) return undefined;

  const match = value.match(/^([^:]+?)(?::(\d{1,5}))?$/);
  if (!match) return undefined;
  const port = match[2];
  if (port && Number(port) > 65_535) return undefined;

  const hostname = match[1]?.toLowerCase().replace(/\.+$/, "");
  if (!hostname || !/^[a-z0-9.-]+$/.test(hostname)) return undefined;
  if (hostname.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return undefined;
  }
  if (
    hostname !== LEGACY_STEWARD_COOKIE_PARENT_DOMAIN &&
    !hostname.endsWith(`.${LEGACY_STEWARD_COOKIE_PARENT_DOMAIN}`)
  ) {
    return undefined;
  }
  return LEGACY_STEWARD_COOKIE_PARENT_DOMAIN;
}
