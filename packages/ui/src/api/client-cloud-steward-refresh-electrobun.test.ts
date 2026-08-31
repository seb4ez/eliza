/** Real Electrobun transport coverage for Steward bearer refresh. */
// @vitest-environment jsdom

import { STEWARD_TOKEN_KEY } from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const capacitorMocks = vi.hoisted(() => ({
  request: vi.fn(),
}));

vi.mock("@capacitor/core", () => ({
  Capacitor: {
    isNativePlatform: () => false,
    registerPlugin: () => ({}),
  },
  CapacitorHttp: {
    request: capacitorMocks.request,
  },
}));

import { refreshCloudStewardSession } from "./client-cloud";

interface ElectrobunTestWindow extends Window {
  __electrobunWindowId?: number;
  __ELIZA_ELECTROBUN_RPC__?: {
    request: Record<string, (params?: unknown) => Promise<unknown>>;
    onMessage: (
      messageName: string,
      listener: (value: unknown) => void,
    ) => void;
    offMessage: (
      messageName: string,
      listener: (value: unknown) => void,
    ) => void;
  };
}

const desktopWindow = window as ElectrobunTestWindow;
const realFetch = globalThis.fetch;
const refreshEndpoint = "https://api.eliza.app/api/auth/steward-refresh";
const desktopHttpRequest = vi.fn<(params?: unknown) => Promise<unknown>>();

function installElectrobunRpc(): void {
  desktopWindow.__electrobunWindowId = 1;
  desktopWindow.__ELIZA_ELECTROBUN_RPC__ = {
    request: { desktopHttpRequest },
    onMessage: vi.fn(),
    offMessage: vi.fn(),
  };
}

describe("refreshCloudStewardSession Electrobun bearer transport", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    capacitorMocks.request.mockReset();
    desktopHttpRequest.mockReset();
    installElectrobunRpc();
    globalThis.fetch = vi.fn() as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    localStorage.clear();
    sessionStorage.clear();
    delete desktopWindow.__ELIZA_ELECTROBUN_RPC__;
    delete desktopWindow.__electrobunWindowId;
    vi.restoreAllMocks();
  });

  it("posts the exact bearer refresh through desktopHttpRequest only", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-a-steward-bearer");
    desktopHttpRequest.mockResolvedValue({
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: "account-a-refreshed-bearer",
        expiresIn: 3600,
      }),
    });
    const commitRefreshedSession = vi.fn();

    await expect(
      refreshCloudStewardSession({
        endpoint: refreshEndpoint,
        commitRefreshedSession,
      }),
    ).resolves.toEqual({
      token: "account-a-refreshed-bearer",
      expiresIn: 3600,
    });

    expect(desktopHttpRequest).toHaveBeenCalledWith({
      url: refreshEndpoint,
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: "Bearer account-a-steward-bearer",
      },
      body: null,
      timeoutMs: 30_000,
    });
    expect(commitRefreshedSession).toHaveBeenCalledWith(
      {
        token: "account-a-refreshed-bearer",
        expiresIn: 3600,
      },
      { validate: expect.any(Function) },
    );
    expect(capacitorMocks.request).not.toHaveBeenCalled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("preserves a stale opaque bearer after desktop invalid_token without transport fallback", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "stale-opaque-bearer");
    desktopHttpRequest.mockResolvedValue({
      status: 401,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: "invalid_token" }),
    });

    await expect(
      refreshCloudStewardSession({ endpoint: refreshEndpoint }),
    ).resolves.toBeNull();

    expect(desktopHttpRequest).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("stale-opaque-bearer");
    expect(capacitorMocks.request).not.toHaveBeenCalled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
