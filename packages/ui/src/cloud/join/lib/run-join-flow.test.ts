/** Verifies that Cloud join resolves and persists the current account without activating compute. */

import { describe, expect, test, vi } from "vitest";
import {
  type JoinFlowClient,
  type JoinFlowEffects,
  runJoinFlow,
} from "./run-join-flow";

const CLOUD_API_BASE = "https://api.eliza.app";
const PERSONAL_ID = "personal:00000000-0000-5000-8000-000000000001";
const DEDICATED_ID = "00000000-0000-4000-8000-000000000020";
const PERSONAL_BASE = `https://${DEDICATED_ID}.cloud.eliza.app`;
const SHARED_BASE = `${CLOUD_API_BASE}/api/v1/eliza/agents/${encodeURIComponent(PERSONAL_ID)}`;

function harness() {
  const getPersonalSharedEliza = vi.fn().mockResolvedValue({
    personalElizaId: PERSONAL_ID,
    agentId: PERSONAL_ID,
    activeAgentId: PERSONAL_ID,
    agentName: "Eliza",
    apiBase: SHARED_BASE,
    runtime: "shared" as const,
  });
  const ensurePersonalDedicatedEliza = vi.fn();
  const stageSessionTarget = vi.fn();
  const restoreIfCurrent = vi.fn(async () => undefined);
  const bindPersonalAgent = vi.fn(
    async (options: Parameters<JoinFlowEffects["bindPersonalAgent"]>[0]) => {
      options.signal?.throwIfAborted();
      if (options.validate?.() === false) return null;
      const personal = await options.client.getPersonalSharedEliza({
        cloudApiBase: options.cloudApiBase,
        authToken: options.token,
        ...(options.signal ? { signal: options.signal } : {}),
      });
      options.signal?.throwIfAborted();
      if (options.validate?.() === false) return null;
      return {
        result: {
          personalElizaId: personal.personalElizaId,
          agentId: personal.personalElizaId,
          activeAgentId: personal.activeAgentId,
          agentName: personal.agentName,
          apiBase: personal.apiBase,
          runtime: personal.runtime,
        },
        restoreIfCurrent,
      };
    },
  );
  const savePersistedFirstRunComplete = vi.fn();
  const client: JoinFlowClient = {
    getPersonalSharedEliza,
    stageSessionTarget,
  };
  const effects: JoinFlowEffects = {
    bindPersonalAgent,
    savePersistedFirstRunComplete,
  };
  return {
    client,
    effects,
    getPersonalSharedEliza,
    ensurePersonalDedicatedEliza,
    bindPersonalAgent,
    restoreIfCurrent,
    savePersistedFirstRunComplete,
  };
}

describe("runJoinFlow", () => {
  test("resolves and persists the account-native Shared identity without activation", async () => {
    const h = harness();
    const onProgress = vi.fn();

    const result = await runJoinFlow({
      client: h.client,
      effects: h.effects,
      cloudApiBase: CLOUD_API_BASE,
      authToken: "session-token",
      onProgress,
    });

    expect(h.getPersonalSharedEliza).toHaveBeenCalledWith({
      cloudApiBase: CLOUD_API_BASE,
      authToken: "session-token",
    });
    expect(h.ensurePersonalDedicatedEliza).not.toHaveBeenCalled();
    expect(h.bindPersonalAgent).toHaveBeenCalledWith({
      client: h.client,
      cloudApiBase: CLOUD_API_BASE,
      token: "session-token",
    });
    expect(onProgress).toHaveBeenCalledWith(
      "connecting",
      "Opening your personal Eliza…",
    );
    expect(h.savePersistedFirstRunComplete).toHaveBeenCalledWith(true);
    expect(result).toEqual({
      personalElizaId: PERSONAL_ID,
      agentId: PERSONAL_ID,
      activeAgentId: PERSONAL_ID,
      agentName: "Eliza",
      apiBase: SHARED_BASE,
      runtime: "shared",
    });
  });

  test("keeps the personal identity stable when Dedicated is already active", async () => {
    const h = harness();
    const dedicatedAgentId = "00000000-0000-4000-8000-000000000020";
    const dedicatedBase = `https://${dedicatedAgentId}.cloud.eliza.app`;
    h.getPersonalSharedEliza.mockResolvedValueOnce({
      personalElizaId: PERSONAL_ID,
      agentId: PERSONAL_ID,
      activeAgentId: dedicatedAgentId,
      agentName: "Eliza",
      apiBase: dedicatedBase,
      runtime: "dedicated" as const,
    });

    const result = await runJoinFlow({
      client: h.client,
      effects: h.effects,
      cloudApiBase: CLOUD_API_BASE,
      authToken: "session-token",
    });

    expect(result).toEqual({
      personalElizaId: PERSONAL_ID,
      agentId: PERSONAL_ID,
      activeAgentId: dedicatedAgentId,
      agentName: "Eliza",
      apiBase: dedicatedBase,
      runtime: "dedicated",
    });
  });

  test("fails closed without persisting when identity resolution fails", async () => {
    const h = harness();
    h.getPersonalSharedEliza.mockRejectedValueOnce(
      new Error("Cloud unavailable"),
    );

    await expect(
      runJoinFlow({
        client: h.client,
        effects: h.effects,
        cloudApiBase: CLOUD_API_BASE,
        authToken: "session-token",
      }),
    ).rejects.toThrow("Cloud unavailable");

    expect(h.restoreIfCurrent).not.toHaveBeenCalled();
    expect(h.savePersistedFirstRunComplete).not.toHaveBeenCalled();
  });

  test("does not resolve identity when already cancelled", async () => {
    const controller = new AbortController();
    controller.abort(new DOMException("cancelled", "AbortError"));
    const h = harness();

    await expect(
      runJoinFlow({
        client: h.client,
        effects: h.effects,
        cloudApiBase: CLOUD_API_BASE,
        authToken: "tok",
        signal: controller.signal,
      }),
    ).rejects.toThrow(/cancelled/i);
    expect(h.getPersonalSharedEliza).not.toHaveBeenCalled();
    expect(h.bindPersonalAgent).not.toHaveBeenCalled();
  });

  test("passes cancellation through the read-only identity request", async () => {
    const controller = new AbortController();
    const h = harness();

    await runJoinFlow({
      client: h.client,
      effects: h.effects,
      cloudApiBase: CLOUD_API_BASE,
      authToken: "tok",
      signal: controller.signal,
    });

    expect(h.getPersonalSharedEliza).toHaveBeenCalledWith({
      cloudApiBase: CLOUD_API_BASE,
      authToken: "tok",
      signal: controller.signal,
    });
  });

  test("does not persist when cancellation arrives after identity resolution", async () => {
    const controller = new AbortController();
    const h = harness();
    h.getPersonalSharedEliza.mockImplementationOnce(async () => {
      controller.abort(new DOMException("signed out", "AbortError"));
      return {
        personalElizaId: PERSONAL_ID,
        agentId: PERSONAL_ID,
        activeAgentId: DEDICATED_ID,
        agentName: "Eliza",
        apiBase: PERSONAL_BASE,
        runtime: "dedicated" as const,
      };
    });

    await expect(
      runJoinFlow({
        client: h.client,
        effects: h.effects,
        cloudApiBase: CLOUD_API_BASE,
        authToken: "tok",
        signal: controller.signal,
      }),
    ).rejects.toThrow(/signed out/i);
    expect(h.restoreIfCurrent).not.toHaveBeenCalled();
  });

  test("does not publish account A after account B wins during resolution", async () => {
    const h = harness();
    let authorityCurrent = true;
    const onProgress = vi.fn();
    h.getPersonalSharedEliza.mockImplementationOnce(async () => {
      authorityCurrent = false;
      return {
        personalElizaId: PERSONAL_ID,
        agentId: PERSONAL_ID,
        activeAgentId: PERSONAL_ID,
        agentName: "Eliza A",
        apiBase: SHARED_BASE,
        runtime: "shared" as const,
      };
    });

    await expect(
      runJoinFlow({
        client: h.client,
        effects: h.effects,
        cloudApiBase: CLOUD_API_BASE,
        authToken: "account-a-token",
        onProgress,
        validateAuthority: () => authorityCurrent,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });

    expect(onProgress).toHaveBeenCalledTimes(1);
    expect(h.restoreIfCurrent).not.toHaveBeenCalled();
    expect(h.savePersistedFirstRunComplete).not.toHaveBeenCalled();
  });

  test("rolls the committed binding back when a progress observer installs account B", async () => {
    const h = harness();
    let authorityCurrent = true;
    const onProgress = vi.fn((_status: string, detail?: string) => {
      if (detail?.includes("Connecting")) authorityCurrent = false;
    });

    await expect(
      runJoinFlow({
        client: h.client,
        effects: h.effects,
        cloudApiBase: CLOUD_API_BASE,
        authToken: "account-a-token",
        onProgress,
        validateAuthority: () => authorityCurrent,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });

    expect(h.restoreIfCurrent).toHaveBeenCalledTimes(1);
    expect(h.savePersistedFirstRunComplete).not.toHaveBeenCalled();
  });
});
