/** Verifies direct Cloud login becomes a durable personal-agent binding. */
// @vitest-environment jsdom

import { STEWARD_SESSION_CHANGE_EVENT } from "@elizaos/shared/steward-session-client";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getActiveProfile } from "./agent-profiles";
import { bindDirectCloudLoginToPersonalAgent } from "./bind-direct-cloud-login";
import { loadPersistedActiveServer } from "./persistence";

const STEWARD_TOKEN_KEY = "steward_session_token";

const PERSONAL_ID = "personal:00000000-0000-5000-8000-000000000001";
const DEDICATED_ID = "00000000-0000-4000-8000-000000000020";
const API_BASE = `https://${DEDICATED_ID}.cloud.eliza.app`;

describe("bindDirectCloudLoginToPersonalAgent", () => {
  beforeEach(() => localStorage.clear());

  it("replaces a stale staging target and repoints the live client", async () => {
    localStorage.setItem(
      "elizaos:active-server",
      JSON.stringify({
        id: "cloud:old",
        kind: "cloud",
        label: "Staging",
        apiBase: "https://api-staging.eliza.app/api/v1/eliza/agents/old",
        accessToken: "stale",
      }),
    );
    const client = {
      ensurePersonalDedicatedEliza: vi.fn(async () => ({
        personalElizaId: PERSONAL_ID,
        activeAgentId: DEDICATED_ID,
        agentName: "Eliza",
        apiBase: API_BASE,
        runtime: "dedicated" as const,
      })),
      stageSessionTarget: vi.fn(() => ({
        publish: vi.fn(() => true),
        restoreIfCurrent: vi.fn(() => true),
        clearIfCurrent: vi.fn(() => true),
      })),
    };

    await expect(
      bindDirectCloudLoginToPersonalAgent({
        client,
        cloudApiBase: "https://api.eliza.app",
        token: "production-token",
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        restoreIfCurrent: expect.any(Function),
      }),
    );

    expect(loadPersistedActiveServer()).toMatchObject({
      id: `cloud:${PERSONAL_ID}`,
      apiBase: API_BASE,
      accessToken: "production-token",
      cloudRuntimeAgentId: DEDICATED_ID,
      cloudRuntime: "dedicated",
    });
    expect(getActiveProfile()).toMatchObject({
      cloudAgentId: PERSONAL_ID,
      apiBase: API_BASE,
      accessToken: "production-token",
    });
    expect(client.stageSessionTarget).toHaveBeenCalledWith(
      { baseUrl: API_BASE, token: "production-token" },
      { persist: false },
    );
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("production-token");
  });

  it("rolls both records back and publishes nothing when B appears during active-server persistence", async () => {
    const client = {
      ensurePersonalDedicatedEliza: vi.fn(async () => ({
        personalElizaId: PERSONAL_ID,
        activeAgentId: DEDICATED_ID,
        agentName: "Eliza",
        apiBase: API_BASE,
        runtime: "dedicated" as const,
      })),
      stageSessionTarget: vi.fn(() => ({
        publish: vi.fn(() => true),
        restoreIfCurrent: vi.fn(() => true),
        clearIfCurrent: vi.fn(() => true),
      })),
    };
    let replacementObserved = false;
    await expect(
      bindDirectCloudLoginToPersonalAgent({
        client,
        cloudApiBase: "https://api.eliza.app",
        token: "stale-a-token",
        // Authority B is modeled by the first committed active-server value.
        // This remains deterministic when the secure-store proxy is already
        // installed by another test in the aggregate worker.
        validate: () => {
          if (replacementObserved) return false;
          replacementObserved = loadPersistedActiveServer() !== null;
          return !replacementObserved;
        },
      }),
    ).resolves.toBeNull();

    expect(loadPersistedActiveServer()).toBeNull();
    expect(getActiveProfile()).toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(client.stageSessionTarget).not.toHaveBeenCalled();
  });

  it("rolls token, records, boot finalizer, and client authority back when B appears during publication", async () => {
    let authorityLive = true;
    const restoreIfCurrent = vi.fn(() => true);
    const rollbackFinalizer = vi.fn();
    const client = {
      ensurePersonalDedicatedEliza: vi.fn(async () => ({
        personalElizaId: PERSONAL_ID,
        activeAgentId: DEDICATED_ID,
        agentName: "Eliza",
        apiBase: API_BASE,
        runtime: "dedicated" as const,
      })),
      stageSessionTarget: vi.fn(() => {
        authorityLive = false;
        return {
          publish: vi.fn(() => true),
          restoreIfCurrent,
          clearIfCurrent: vi.fn(() => true),
        };
      }),
    };

    await expect(
      bindDirectCloudLoginToPersonalAgent({
        client,
        cloudApiBase: "https://api.eliza.app",
        token: "stale-a-token",
        validate: () => authorityLive,
        finalize: () => rollbackFinalizer,
      }),
    ).resolves.toBeNull();

    expect(restoreIfCurrent).toHaveBeenCalledTimes(1);
    expect(rollbackFinalizer).toHaveBeenCalledTimes(1);
    expect(loadPersistedActiveServer()).toBeNull();
    expect(getActiveProfile()).toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("compensates durable records and token when the boot finalizer throws", async () => {
    const restoreIfCurrent = vi.fn(() => true);
    const client = {
      ensurePersonalDedicatedEliza: vi.fn(async () => ({
        personalElizaId: PERSONAL_ID,
        activeAgentId: DEDICATED_ID,
        agentName: "Eliza",
        apiBase: API_BASE,
        runtime: "dedicated" as const,
      })),
      stageSessionTarget: vi.fn(() => ({
        publish: vi.fn(() => true),
        restoreIfCurrent,
        clearIfCurrent: vi.fn(() => true),
      })),
    };

    await expect(
      bindDirectCloudLoginToPersonalAgent({
        client,
        cloudApiBase: "https://api.eliza.app",
        token: "stale-a-token",
        finalize: () => {
          throw new Error("boot config unavailable");
        },
      }),
    ).rejects.toThrow("boot config unavailable");

    expect(client.stageSessionTarget).toHaveBeenCalledTimes(1);
    expect(restoreIfCurrent).toHaveBeenCalledTimes(1);
    expect(loadPersistedActiveServer()).toBeNull();
    expect(getActiveProfile()).toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("retains an exact composite rollback across the caller await boundary", async () => {
    const restoreIfCurrent = vi.fn(() => true);
    const rollbackFinalizer = vi.fn();
    const client = {
      ensurePersonalDedicatedEliza: vi.fn(async () => ({
        personalElizaId: PERSONAL_ID,
        activeAgentId: DEDICATED_ID,
        agentName: "Eliza",
        apiBase: API_BASE,
        runtime: "dedicated" as const,
      })),
      stageSessionTarget: vi.fn(() => ({
        publish: vi.fn(() => true),
        restoreIfCurrent,
        clearIfCurrent: vi.fn(() => true),
      })),
    };

    const authority = await bindDirectCloudLoginToPersonalAgent({
      client,
      cloudApiBase: "https://api.eliza.app",
      token: "stale-a-token",
      finalize: () => rollbackFinalizer,
    });
    expect(authority).not.toBeNull();

    await authority?.restoreIfCurrent();

    expect(restoreIfCurrent).toHaveBeenCalledTimes(1);
    expect(rollbackFinalizer).toHaveBeenCalledTimes(1);
    expect(loadPersistedActiveServer()).toBeNull();
    expect(getActiveProfile()).toBeNull();
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("retires the recovery receipt before observers see the coherent client and token", async () => {
    let clientBase = "https://api.eliza.app";
    let clientToken = "old-token";
    let bootPublished = false;
    let receiptCommitted = false;
    const observations: Array<{
      base: string;
      token: string;
      bootPublished: boolean;
      receiptCommitted: boolean;
    }> = [];
    const onSession = () => {
      observations.push({
        base: clientBase,
        token: clientToken,
        bootPublished,
        receiptCommitted,
      });
    };
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, onSession);
    const client = {
      ensurePersonalDedicatedEliza: vi.fn(async () => ({
        personalElizaId: PERSONAL_ID,
        activeAgentId: DEDICATED_ID,
        agentName: "Eliza",
        apiBase: API_BASE,
        runtime: "dedicated" as const,
      })),
      stageSessionTarget: vi.fn(
        (target: { baseUrl: string; token: string }) => {
          const previousBase = clientBase;
          const previousToken = clientToken;
          clientBase = target.baseUrl;
          clientToken = target.token;
          return {
            publish: vi.fn(() => true),
            restoreIfCurrent: vi.fn(() => {
              clientBase = previousBase;
              clientToken = previousToken;
              return true;
            }),
            clearIfCurrent: vi.fn(() => {
              clientToken = "";
              return true;
            }),
          };
        },
      ),
    };

    try {
      await bindDirectCloudLoginToPersonalAgent({
        client,
        cloudApiBase: "https://api.eliza.app",
        token: "production-token",
        finalize: () => {
          bootPublished = true;
          return () => {
            bootPublished = false;
          };
        },
        commitBeforePublish: () => {
          receiptCommitted = true;
          return true;
        },
      });
    } finally {
      window.removeEventListener(STEWARD_SESSION_CHANGE_EVENT, onSession);
    }

    expect(observations).toEqual([
      {
        base: API_BASE,
        token: "production-token",
        bootPublished: true,
        receiptCommitted: true,
      },
    ]);
  });
});
