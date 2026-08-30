/** Verifies refreshCloudStewardSession native bearer refresh through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * Unit coverage for refreshing the Steward session token on native builds.
 * Capacitor forced native + CapacitorHttp mocked, no live cloud.
 */

import { STEWARD_TOKEN_KEY } from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enqueueStewardSessionMutation } from "../cloud/lib/steward-session-mutation-queue";

const capacitorMocks = vi.hoisted(() => ({
  request: vi.fn(),
}));

vi.mock("@capacitor/core", () => ({
  Capacitor: {
    isNativePlatform: () => true,
    registerPlugin: () => ({}),
  },
  CapacitorHttp: {
    request: capacitorMocks.request,
  },
}));

vi.mock("../bridge/electrobun-runtime", () => ({
  isElectrobunRuntime: () => false,
}));

import { refreshCloudStewardSession } from "./client-cloud";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

describe("refreshCloudStewardSession native bearer refresh", () => {
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    localStorage.clear();
    capacitorMocks.request.mockReset();
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("posts native refresh through CapacitorHttp with the stored Steward JWT as Bearer", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "stored-steward-jwt");
    globalThis.fetch = vi.fn() as unknown as typeof fetch;
    capacitorMocks.request.mockResolvedValue({
      status: 200,
      data: { ok: true, token: "fresh-steward-jwt", expiresIn: 3600 },
    });

    const result = await refreshCloudStewardSession({
      endpoint: "https://api.elizacloud.ai/api/auth/steward-refresh",
    });

    expect(capacitorMocks.request).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://api.elizacloud.ai/api/auth/steward-refresh",
        method: "POST",
        headers: expect.objectContaining({
          Accept: "application/json",
          Authorization: "Bearer stored-steward-jwt",
        }),
      }),
    );
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(result).toEqual({
      ok: true,
      token: "fresh-steward-jwt",
      expiresIn: 3600,
    });
  });

  it("does not require fetch for native bearer refresh", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "stored-steward-jwt");
    globalThis.fetch = undefined as unknown as typeof fetch;
    capacitorMocks.request.mockResolvedValue({
      status: 200,
      data: { token: "fresh-steward-jwt", expiresIn: 3600 },
    });

    await expect(
      refreshCloudStewardSession({
        endpoint: "https://api.elizacloud.ai/api/auth/steward-refresh",
      }),
    ).resolves.toEqual({
      token: "fresh-steward-jwt",
      expiresIn: 3600,
    });

    expect(capacitorMocks.request).toHaveBeenCalledTimes(1);
  });

  it("does not attempt a native refresh without a bearer token", async () => {
    globalThis.fetch = vi.fn() as unknown as typeof fetch;

    await expect(
      refreshCloudStewardSession({
        endpoint: "https://api.elizacloud.ai/api/auth/steward-refresh",
      }),
    ).resolves.toBeNull();

    expect(capacitorMocks.request).not.toHaveBeenCalled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("retires the exact native bearer after an explicit session_ended verdict", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "revoked-bridged-token");
    capacitorMocks.request.mockResolvedValue({
      status: 401,
      data: { code: "session_ended" },
    });

    await expect(
      refreshCloudStewardSession({
        endpoint: "https://api.elizacloud.ai/api/auth/steward-refresh",
      }),
    ).resolves.toBeNull();

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("preserves the native bearer on a non-authoritative invalid_token 401", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "still-valid-token");
    capacitorMocks.request.mockResolvedValue({
      status: 401,
      data: { code: "invalid_token" },
    });

    await expect(
      refreshCloudStewardSession({
        endpoint: "https://api.elizacloud.ai/api/auth/steward-refresh",
      }),
    ).resolves.toBeNull();

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("still-valid-token");
  });

  it("serializes native refresh publication before a newer login transaction", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a");
    capacitorMocks.request.mockResolvedValue({
      status: 200,
      data: { token: "account-a-refreshed" },
    });
    const publication = deferred<void>();
    const order: string[] = [];

    const refreshA = refreshCloudStewardSession({
      endpoint: "https://api.elizacloud.ai/api/auth/steward-refresh",
      commitRefreshedSession: async () => {
        order.push("refresh-a-publish-start");
        await publication.promise;
        order.push("refresh-a-publish-end");
      },
    });
    await vi.waitFor(() => expect(order).toEqual(["refresh-a-publish-start"]));
    const loginB = enqueueStewardSessionMutation(async () => {
      order.push("login-b");
    });

    await Promise.resolve();
    expect(order).toEqual(["refresh-a-publish-start"]);
    publication.resolve();
    await Promise.all([refreshA, loginB]);
    expect(order).toEqual([
      "refresh-a-publish-start",
      "refresh-a-publish-end",
      "login-b",
    ]);
  });
});
