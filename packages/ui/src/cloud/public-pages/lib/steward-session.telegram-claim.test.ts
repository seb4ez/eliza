/** Verifies Telegram claim authority survives Steward login without replay or loss. */
// @vitest-environment jsdom

import { STEWARD_TOKEN_KEY } from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearPendingOnboardingSession,
  peekPendingOnboardingSession,
  storePendingOnboardingSession,
  TELEGRAM_ACCOUNT_CLAIM_PURPOSE,
} from "../../join/lib/onboarding-continuation";
import { enqueueStewardSessionMutation } from "../../lib/steward-session-mutation-queue";
import {
  completeStewardSessionRecoverySnapshot,
  readStewardSessionRecovery,
  STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
} from "../../lib/steward-session-recovery-marker";
import {
  confirmTelegramAccountClaim,
  exchangeStewardCodeViaApi,
  syncStewardSessionCookie,
} from "./steward-session";

const TOKEN = "telegram-claim-test-token-00000001";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

beforeEach(() => {
  window.localStorage.setItem(STEWARD_TOKEN_KEY, "steward-token");
});

afterEach(() => {
  completeStewardSessionRecoverySnapshot(
    readStewardSessionRecovery("elizacloud"),
  );
  clearPendingOnboardingSession();
  window.sessionStorage.clear();
  window.localStorage.clear();
  vi.unstubAllGlobals();
});

describe("Steward Telegram account claim handoff", () => {
  it("establishes a JWT session without sending or consuming a pending claim", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await syncStewardSessionCookie("steward-token", "refresh-token");

    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      token: "steward-token",
      refreshToken: "refresh-token",
    });
    expect(peekPendingOnboardingSession(TELEGRAM_ACCOUNT_CLAIM_PURPOSE)).toBe(
      TOKEN,
    );
  });

  it("accepts explicit claim authority when the landing page is already authenticated", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await confirmTelegramAccountClaim("steward-token", TOKEN);

    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      token: "steward-token",
      telegramContinuation: TOKEN,
      telegramClaimConfirmation: "explicit",
    });
    expect(peekPendingOnboardingSession()).toBeNull();
  });

  it("clears the consumed claim before publishing recovery completion", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(Response.json({ ok: true })),
    );
    const continuationAtCompletion: Array<string | null> = [];
    const onRecovery = () => {
      if (readStewardSessionRecovery("elizacloud").receipts.length > 0) return;
      continuationAtCompletion.push(
        peekPendingOnboardingSession(TELEGRAM_ACCOUNT_CLAIM_PURPOSE),
      );
    };
    window.addEventListener(STEWARD_SESSION_RECOVERY_CHANGE_EVENT, onRecovery);

    try {
      await confirmTelegramAccountClaim("steward-token", TOKEN);
    } finally {
      window.removeEventListener(
        STEWARD_SESSION_RECOVERY_CHANGE_EVENT,
        onRecovery,
      );
    }

    expect(continuationAtCompletion).toEqual([null]);
  });

  it("rejects a guessable explicit claim before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      confirmTelegramAccountClaim(
        "steward-token",
        "platform:telegram:123456789",
      ),
    ).rejects.toThrow("Invalid Telegram account claim");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not require callers to opt out of claim consumption", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await syncStewardSessionCookie("steward-token", null);

    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      token: "steward-token",
    });
    expect(peekPendingOnboardingSession(TELEGRAM_ACCOUNT_CLAIM_PURPOSE)).toBe(
      TOKEN,
    );
  });

  it("keeps the claim for an idempotent retry when Cloud rejects the sync", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: "This Telegram chat cannot be linked automatically",
            code: "telegram_claim_conflict",
          }),
          { status: 409, headers: { "content-type": "application/json" } },
        ),
      ),
    );

    await expect(
      confirmTelegramAccountClaim("steward-token", TOKEN),
    ).rejects.toThrow("This Telegram chat cannot be linked automatically");
    expect(peekPendingOnboardingSession()).toBe(TOKEN);
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
  });

  it("does not clear a newer claim when an older explicit claim succeeds", async () => {
    const newerToken = "telegram-claim-test-token-00000002";
    storePendingOnboardingSession(newerToken, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    await confirmTelegramAccountClaim("steward-token", TOKEN);

    expect(peekPendingOnboardingSession(TELEGRAM_ACCOUNT_CLAIM_PURPOSE)).toBe(
      newerToken,
    );
  });

  it("exchanges an OAuth nonce without sending or consuming the claim", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
          userId: "cloud-user",
          stewardUserId: "steward-user",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const controller = new AbortController();
    await exchangeStewardCodeViaApi("one-time-code", {
      redirectUri: "https://cloud.eliza.app/login",
      tenantId: "elizacloud",
      codeVerifier: "verifier",
      signal: controller.signal,
    });

    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      code: "one-time-code",
      redirectUri: "https://cloud.eliza.app/login",
      tenantId: "elizacloud",
      codeVerifier: "verifier",
    });
    expect(fetchMock.mock.calls[0]?.[1]?.signal).toBe(controller.signal);
    expect(peekPendingOnboardingSession(TELEGRAM_ACCOUNT_CLAIM_PURPOSE)).toBe(
      TOKEN,
    );
  });

  it("leaves ordinary Discord and phone continuations on their confirm flow", async () => {
    storePendingOnboardingSession(TOKEN);
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await syncStewardSessionCookie("steward-token");

    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      token: "steward-token",
    });
    expect(peekPendingOnboardingSession()).toBe(TOKEN);
  });

  it("persists its receipt before waiting for the irreversible POST lease", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    const leaseAcquired = deferred<void>();
    const releaseLease = deferred<void>();
    const held = enqueueStewardSessionMutation(async () => {
      leaseAcquired.resolve();
      await releaseLease.promise;
    });
    await leaseAcquired.promise;
    const fetchMock = vi.fn().mockResolvedValue(Response.json({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    const confirmation = confirmTelegramAccountClaim("steward-token", TOKEN);
    const receipt = readStewardSessionRecovery("elizacloud");
    expect(receipt.receipts).toHaveLength(1);
    expect(fetchMock).not.toHaveBeenCalled();
    sessionStorage.clear();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual(
      receipt.receipts,
    );

    releaseLease.resolve();
    await held;
    await confirmation;
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
    expect(peekPendingOnboardingSession()).toBeNull();
  });

  it("retires its receipt when the origin lock rejects before dispatch", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const previousLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    const request = vi
      .fn()
      .mockRejectedValue(new Error("Origin session lock unavailable"));
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: { request },
    });

    try {
      await expect(
        confirmTelegramAccountClaim("steward-token", TOKEN),
      ).rejects.toThrow("Origin session lock unavailable");
    } finally {
      if (previousLocks) {
        Object.defineProperty(navigator, "locks", previousLocks);
      } else {
        Reflect.deleteProperty(navigator, "locks");
      }
    }

    expect(request).toHaveBeenCalledOnce();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
    expect(peekPendingOnboardingSession()).toBe(TOKEN);
  });

  it("preserves receipt and claim after an ambiguous response loss", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("response lost after commit");
      }),
    );

    await expect(
      confirmTelegramAccountClaim("steward-token", TOKEN),
    ).rejects.toThrow("response lost after commit");
    expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(1);
    expect(peekPendingOnboardingSession()).toBe(TOKEN);
  });

  it("does not dispatch account A after account B wins while waiting for the lease", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    const leaseAcquired = deferred<void>();
    const releaseLease = deferred<void>();
    const held = enqueueStewardSessionMutation(async () => {
      leaseAcquired.resolve();
      await releaseLease.promise;
    });
    await leaseAcquired.promise;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const confirmation = confirmTelegramAccountClaim("steward-token", TOKEN);
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-b-token");
    releaseLease.resolve();
    await held;

    await expect(confirmation).rejects.toThrow("account changed");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(readStewardSessionRecovery("elizacloud").receipts).toEqual([]);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-b-token");
  });

  it("never publishes A when B appears after the server may have committed", async () => {
    storePendingOnboardingSession(TOKEN, TELEGRAM_ACCOUNT_CLAIM_PURPOSE);
    const response = deferred<Response>();
    const fetchMock = vi.fn(() => response.promise);
    vi.stubGlobal("fetch", fetchMock);

    const confirmation = confirmTelegramAccountClaim("steward-token", TOKEN);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-b-token");
    response.resolve(Response.json({ ok: true }));

    await expect(confirmation).rejects.toThrow("superseded");
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-b-token");
    expect(readStewardSessionRecovery("elizacloud").receipts).toHaveLength(1);
    expect(peekPendingOnboardingSession()).toBe(TOKEN);
  });
});
