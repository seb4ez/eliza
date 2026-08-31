/**
 * Destination resolution for the OIDC sign-in bounce. Pure functions, no DOM;
 * the build-time issuer is stubbed with `vi.stubEnv`, the way the other
 * `import.meta.env` consumers in this package are tested.
 *
 * Two properties are under test. `/oidc/continue` can only ever navigate to the
 * origin of the issuer this deployment was configured with — it is reachable by
 * anyone who can link to it, so a caller-influenced destination would make it an
 * open redirect. And a deployment that configured no issuer resolves to NOTHING
 * rather than to a guess: the provider answers only on the host its own issuer
 * names, so a wrong guess produces a resume that reports the user's sign-in as
 * expired and no evidence anywhere of why.
 */
// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";
import { enqueueStewardSessionMutation } from "../../lib/steward-session-mutation-queue";
import {
  beginStewardSessionRecovery,
  readStewardSessionRecovery,
  rejectStewardSessionRecovery,
  STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
} from "../../lib/steward-session-recovery-marker";

import {
  buildOidcResumeTarget,
  configuredOidcIssuerUrl,
  prepareOidcResumeTarget,
  resolveOidcIssuerOrigin,
} from "./oidc-continue";

const RID = `eoq_${"a".repeat(64)}`;

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function setDocumentCookie(value: string): void {
  Object.getOwnPropertyDescriptor(Document.prototype, "cookie")?.set?.call(
    document,
    value,
  );
}

afterEach(() => {
  vi.unstubAllEnvs();
  localStorage.clear();
  sessionStorage.clear();
});

function withIssuer(value: string): void {
  vi.stubEnv("VITE_OIDC_ISSUER_URL", value);
}

describe("resolveOidcIssuerOrigin", () => {
  it("derives the origin from the configured issuer, whatever the console host", () => {
    withIssuer("https://api.elizacloud.ai");
    for (const host of [
      "elizacloud.ai",
      "app.elizacloud.ai",
      "console.internal",
      "",
    ]) {
      expect(resolveOidcIssuerOrigin(host)).toBe("https://api.elizacloud.ai");
    }
  });

  it("keeps a staging console on the issuer staging was built with", () => {
    // The pairing is deployment configuration, not something derivable from the
    // console hostname: a staging session resuming on the prod issuer would
    // cross tenants and sessions.
    withIssuer("https://api-staging.elizacloud.ai");
    expect(resolveOidcIssuerOrigin("staging.elizacloud.ai")).toBe(
      "https://api-staging.elizacloud.ai",
    );
    expect(resolveOidcIssuerOrigin("staging.elizacloud.ai")).not.toBe(
      "https://api.elizacloud.ai",
    );
  });

  it("drops a path on the issuer, because the resume endpoint is served from the root", () => {
    withIssuer("https://api.elizacloud.ai/oidc/");
    expect(resolveOidcIssuerOrigin("elizacloud.ai")).toBe(
      "https://api.elizacloud.ai",
    );
  });

  it("uses the current origin on loopback, where the dev server proxies /api", () => {
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      expect(resolveOidcIssuerOrigin(host, `http://${host}:5173`)).toBe(
        `http://${host}:5173`,
      );
    }
  });

  it("prefers an explicitly configured issuer even in local development", () => {
    // The local Worker is a different port from the Vite server, and the
    // provider answers only on the host its issuer names.
    withIssuer("http://127.0.0.1:8787");
    expect(resolveOidcIssuerOrigin("127.0.0.1", "http://127.0.0.1:5173")).toBe(
      "http://127.0.0.1:8787",
    );
  });

  it("resolves NOTHING for an unconfigured non-loopback host", () => {
    // The old behavior — quietly defaulting to the production API host — sent
    // every self-hosted, preview, and custom-domain console to an issuer that
    // has never heard of its parked request.
    expect(configuredOidcIssuerUrl()).toBeUndefined();
    for (const host of ["elizacloud.ai", "console.example", "hub.internal"]) {
      expect(resolveOidcIssuerOrigin(host, `https://${host}`)).toBeNull();
    }
  });

  it("reports an unusable configured value rather than falling back to a guess", () => {
    withIssuer("api.elizacloud.ai");
    expect(resolveOidcIssuerOrigin("elizacloud.ai")).toBeNull();
    expect(
      resolveOidcIssuerOrigin("localhost", "http://localhost:5173"),
    ).toBeNull();
  });

  it.each(["javascript:alert(1)", "data:text/plain,issuer", "file:///api"])(
    "rejects a non-HTTP issuer scheme: %s",
    (issuer) => {
      withIssuer(issuer);
      expect(resolveOidcIssuerOrigin("staging.eliza.app")).toBeNull();
      expect(buildOidcResumeTarget(RID, "staging.eliza.app")).toEqual({
        status: "issuer_unconfigured",
      });
    },
  );

  it("reads only the VITE_ name Vite actually exposes to the bundle", () => {
    // The Next-era name was accepted here as a fallback, but Vite only inlines
    // `VITE_`-prefixed members, so that branch could never fire in a real build
    // — a deployment that set it would silently get the unconfigured screen.
    vi.stubEnv("NEXT_PUBLIC_OIDC_ISSUER_URL", "https://api.elizacloud.ai");
    expect(configuredOidcIssuerUrl()).toBeUndefined();
    expect(resolveOidcIssuerOrigin("elizacloud.ai")).toBeNull();

    withIssuer("https://api.elizacloud.ai");
    expect(configuredOidcIssuerUrl()).toBe("https://api.elizacloud.ai");
  });

  it("trims surrounding whitespace and treats a blank value as unset", () => {
    withIssuer("  https://api.elizacloud.ai  ");
    expect(resolveOidcIssuerOrigin("elizacloud.ai")).toBe(
      "https://api.elizacloud.ai",
    );
    withIssuer("   ");
    expect(configuredOidcIssuerUrl()).toBeUndefined();
    expect(resolveOidcIssuerOrigin("elizacloud.ai")).toBeNull();
  });
});

describe("buildOidcResumeTarget", () => {
  it("builds an absolute resume URL carrying the request id", () => {
    withIssuer("https://api.elizacloud.ai");
    expect(buildOidcResumeTarget(RID, "elizacloud.ai")).toEqual({
      status: "ok",
      url: `https://api.elizacloud.ai/api/oidc/authorize/resume?rid=${RID}`,
    });
  });

  it("refuses a missing or malformed request id rather than navigating", () => {
    withIssuer("https://api.elizacloud.ai");
    for (const rid of [
      null,
      undefined,
      "",
      "eoq_short",
      `eoq_${"A".repeat(64)}`,
      `eoc_${"a".repeat(64)}`,
      `${"a".repeat(64)}`,
      "../../evil",
    ]) {
      expect(buildOidcResumeTarget(rid, "elizacloud.ai").status).toBe(
        "invalid_request_id",
      );
    }
  });

  it("cannot be steered to another origin by the request id", () => {
    // Even a value shaped like a URL is rejected by the id pattern, so the
    // destination host is always the configured one.
    withIssuer("https://api.elizacloud.ai");
    expect(
      buildOidcResumeTarget("https://evil.example/x", "elizacloud.ai").status,
    ).toBe("invalid_request_id");
    const target = buildOidcResumeTarget(RID, "elizacloud.ai");
    expect(target.status).toBe("ok");
    expect(new URL(target.status === "ok" ? target.url : "").origin).toBe(
      "https://api.elizacloud.ai",
    );
  });

  it("separates a missing issuer from an expired link so the page can say which", () => {
    expect(
      buildOidcResumeTarget(RID, "console.example", "https://console.example"),
    ).toEqual({
      status: "issuer_unconfigured",
    });
    expect(buildOidcResumeTarget("nope", "console.example").status).toBe(
      "invalid_request_id",
    );
  });
});

describe("prepareOidcResumeTarget", () => {
  it("syncs the stored session to the configured staging issuer before resume", async () => {
    withIssuer("https://api-staging.eliza.app");
    const events: string[] = [];

    const target = await prepareOidcResumeTarget(
      RID,
      "staging.eliza.app",
      "https://staging.eliza.app",
      {
        readToken: () => "  steward-access-token  ",
        syncSession: async (token, endpoint) => {
          events.push(`${token} ${endpoint}`);
        },
      },
    );

    expect(events).toEqual([
      "steward-access-token https://api-staging.eliza.app/api/auth/steward-session",
    ]);
    expect(target).toEqual({
      status: "ok",
      url: `https://api-staging.eliza.app/api/oidc/authorize/resume?rid=${RID}`,
    });
    expect(target.status === "ok" && target.authority.isCurrent()).toBe(true);
  });

  it("does not return a stale resume when recovery publication queues login B", async () => {
    withIssuer("https://api-staging.eliza.app");
    let storedToken = "account-a";
    let recoveryEvents = 0;
    let newerLogin: ReturnType<typeof beginStewardSessionRecovery> | null =
      null;
    const readNewerLogin = () => newerLogin;
    const beginNewerLoginAfterPublication = () => {
      recoveryEvents += 1;
      if (recoveryEvents !== 2) return;
      queueMicrotask(() => {
        newerLogin = beginStewardSessionRecovery("elizacloud", "provider");
        storedToken = "account-b";
      });
    };
    window.addEventListener(
      STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
      beginNewerLoginAfterPublication,
    );

    try {
      await expect(
        prepareOidcResumeTarget(
          RID,
          "staging.eliza.app",
          "https://staging.eliza.app",
          {
            readToken: () => storedToken,
            syncSession: async () => undefined,
          },
        ),
      ).resolves.toEqual({ status: "session_sync_failed" });
      expect(storedToken).toBe("account-b");
      const recordedNewerLogin = readNewerLogin();
      expect(recordedNewerLogin).not.toBeNull();
      expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([
        recordedNewerLogin?.receipt,
      ]);
    } finally {
      window.removeEventListener(
        STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
        beginNewerLoginAfterPublication,
      );
      const recordedNewerLogin = readNewerLogin();
      if (recordedNewerLogin) {
        rejectStewardSessionRecovery(recordedNewerLogin);
      }
    }
  });

  it("keeps a durable receipt across tab-close until issuer sync is fully acknowledged", async () => {
    withIssuer("https://api-staging.eliza.app");
    const serverCommit = deferred<void>();
    const syncSession = vi.fn(() => serverCommit.promise);

    const pending = prepareOidcResumeTarget(
      RID,
      "staging.eliza.app",
      "https://staging.eliza.app",
      {
        readToken: () => "account-a",
        syncSession,
      },
    );
    await vi.waitFor(() => expect(syncSession).toHaveBeenCalledTimes(1));

    const beforeClose = readStewardSessionRecovery("elizacloud");
    expect(beforeClose.receipts).toHaveLength(1);
    sessionStorage.clear();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual(
      beforeClose.receipts,
    );

    serverCommit.resolve();
    await expect(pending).resolves.toMatchObject({ status: "ok" });
    expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(0);
  });

  it("does not replay a stored account while a newer login receipt is ambiguous", async () => {
    withIssuer("https://api-staging.eliza.app");
    const newerLogin = beginStewardSessionRecovery("elizacloud", "provider");
    const syncSession = vi.fn(() => Promise.resolve());
    try {
      await expect(
        prepareOidcResumeTarget(RID, "staging.eliza.app", undefined, {
          readToken: () => "stale-account-a",
          syncSession,
        }),
      ).resolves.toEqual({ status: "session_sync_failed" });
      expect(syncSession).not.toHaveBeenCalled();
      expect(readStewardSessionRecovery("elizacloud").receipts).toContain(
        newerLogin.receipt,
      );
    } finally {
      rejectStewardSessionRecovery(newerLogin);
    }
  });

  it("revalidates the exact token after waiting for the origin lease", async () => {
    withIssuer("https://api-staging.eliza.app");
    let storedToken = "account-a";
    let releaseLease: () => void = () => {};
    const leaseAcquired = deferred<void>();
    const heldLease = enqueueStewardSessionMutation(
      () =>
        new Promise<void>((resolve) => {
          releaseLease = resolve;
          leaseAcquired.resolve();
        }),
    );
    await leaseAcquired.promise;
    const syncSession = vi.fn(async () => undefined);
    const pending = prepareOidcResumeTarget(
      RID,
      "staging.eliza.app",
      "https://staging.eliza.app",
      { readToken: () => storedToken, syncSession },
    );
    storedToken = "account-b";
    releaseLease();

    await heldLease;
    await expect(pending).resolves.toEqual({ status: "session_sync_failed" });
    expect(syncSession).not.toHaveBeenCalled();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
  });

  it("keeps ambiguity when the exact token changes after issuer commit", async () => {
    withIssuer("https://api-staging.eliza.app");
    let storedToken = "account-a";
    const syncSession = vi.fn(async () => {
      storedToken = "account-b";
    });

    await expect(
      prepareOidcResumeTarget(
        RID,
        "staging.eliza.app",
        "https://staging.eliza.app",
        { readToken: () => storedToken, syncSession },
      ),
    ).resolves.toEqual({ status: "session_sync_failed" });

    expect(syncSession).toHaveBeenCalledWith(
      "account-a",
      "https://api-staging.eliza.app/api/auth/steward-session",
    );
    expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(1);
  });

  it("does not sync an invalid request id", async () => {
    withIssuer("https://api-staging.eliza.app");
    const syncSession = vi.fn(() => Promise.resolve());

    await expect(
      prepareOidcResumeTarget("invalid", "staging.eliza.app", undefined, {
        readToken: () => "token",
        syncSession,
      }),
    ).resolves.toEqual({ status: "invalid_request_id" });
    expect(syncSession).not.toHaveBeenCalled();
  });

  it("does not consume the request without a stored Steward session", async () => {
    withIssuer("https://api-staging.eliza.app");
    const syncSession = vi.fn(() => Promise.resolve());

    await expect(
      prepareOidcResumeTarget(RID, "staging.eliza.app", undefined, {
        readToken: () => "  ",
        syncSession,
      }),
    ).resolves.toEqual({ status: "session_missing" });
    expect(syncSession).not.toHaveBeenCalled();
  });

  it("keeps the parked request unconsumed when issuer session sync fails", async () => {
    withIssuer("https://api-staging.eliza.app");

    await expect(
      prepareOidcResumeTarget(RID, "staging.eliza.app", undefined, {
        readToken: () => "token",
        syncSession: () => Promise.reject(new Error("network unavailable")),
      }),
    ).resolves.toEqual({ status: "session_sync_failed" });
    expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(1);
  });

  it("retires issuer recovery on HTTP 500 without republishing a stale cookie account", async () => {
    withIssuer("https://api-staging.eliza.app");
    setDocumentCookie("steward-authed=1; path=/");
    const syncEvents: Event[] = [];
    const onSync = (event: Event) => syncEvents.push(event);
    window.addEventListener("steward-token-sync", onSync);

    try {
      await expect(
        prepareOidcResumeTarget(RID, "staging.eliza.app", undefined, {
          // The attempted account B is injected while durable browser storage
          // remains empty, matching a stale cookie-only account A document.
          readToken: () => "attempted-account-b",
          syncSession: () =>
            Promise.reject(
              Object.assign(new Error("Issuer session unavailable"), {
                status: 500,
              }),
            ),
        }),
      ).resolves.toEqual({ status: "session_sync_failed" });
      expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
      expect(localStorage.getItem("steward_session_token")).toBeNull();
      expect(syncEvents).toEqual([]);
    } finally {
      window.removeEventListener("steward-token-sync", onSync);
      setDocumentCookie("steward-authed=; Max-Age=0; path=/");
    }
  });
});
