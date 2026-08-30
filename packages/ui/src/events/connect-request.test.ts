/** Verifies connect request handoff through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * Connection-event handoff coverage for native deep links that can arrive
 * before React mounts a startup or live-shell consumer.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { dispatchConnectRequest, listenForConnectRequests } from "./index";

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
});

describe("connect request handoff", () => {
  it("replays a request dispatched before the consumer mounts", async () => {
    const listener = vi.fn(() => true);

    const applied = dispatchConnectRequest({
      gatewayUrl: "http://127.0.0.1:31337",
      completeFirstRun: true,
    });
    cleanups.push(listenForConnectRequests(listener));

    await expect(applied).resolves.toBe(true);
    expect(listener).toHaveBeenCalledOnce();
    expect(listener).toHaveBeenCalledWith(
      expect.objectContaining({
        gatewayUrl: "http://127.0.0.1:31337",
        completeFirstRun: true,
      }),
    );
  });

  it("lets only one startup/shell consumer claim a queued request", async () => {
    const startupListener = vi.fn(() => true);
    const shellListener = vi.fn(() => true);

    const applied = dispatchConnectRequest({
      gatewayUrl: "http://127.0.0.1:31337",
    });
    cleanups.push(listenForConnectRequests(startupListener));
    cleanups.push(listenForConnectRequests(shellListener));

    await expect(applied).resolves.toBe(true);
    expect(startupListener).toHaveBeenCalledOnce();
    expect(shellListener).not.toHaveBeenCalled();
  });

  it("waits for the claimed consumer to finish before resolving", async () => {
    let finish!: (applied: boolean) => void;
    const listener = vi.fn(
      () =>
        new Promise<boolean>((resolve) => {
          finish = resolve;
        }),
    );
    cleanups.push(listenForConnectRequests(listener));

    let settled = false;
    const applied = dispatchConnectRequest({
      gatewayUrl: "https://agent.example.com",
    });
    void applied.then(() => {
      settled = true;
    });

    expect(listener).toHaveBeenCalledOnce();
    await Promise.resolve();
    expect(settled).toBe(false);

    finish(true);
    await expect(applied).resolves.toBe(true);
    expect(settled).toBe(true);
  });

  it("resolves false instead of leaking a listener rejection", async () => {
    const listener = vi.fn(async () => {
      throw new Error("durable write failed");
    });
    cleanups.push(listenForConnectRequests(listener));

    await expect(
      dispatchConnectRequest({ gatewayUrl: "https://agent.example.com" }),
    ).resolves.toBe(false);
    expect(listener).toHaveBeenCalledOnce();
  });

  it("settles an older unclaimed request false when a newer one replaces it", async () => {
    const first = dispatchConnectRequest({
      gatewayUrl: "https://first.example.com",
    });
    const second = dispatchConnectRequest({
      gatewayUrl: "https://second.example.com",
    });
    const listener = vi.fn(() => true);
    cleanups.push(listenForConnectRequests(listener));

    await expect(first).resolves.toBe(false);
    await expect(second).resolves.toBe(true);
    expect(listener).toHaveBeenCalledOnce();
    expect(listener).toHaveBeenCalledWith(
      expect.objectContaining({ gatewayUrl: "https://second.example.com" }),
    );
  });
});
