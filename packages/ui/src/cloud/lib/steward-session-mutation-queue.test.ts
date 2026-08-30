// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";
import { enqueueStewardSessionMutation } from "./steward-session-mutation-queue";

afterEach(() => {
  Reflect.deleteProperty(navigator, "locks");
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("Steward session mutation queue", () => {
  it("uses one exclusive origin lock and serializes two callers", async () => {
    let held: Promise<void> = Promise.resolve();
    const lockRequests: string[] = [];
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: vi.fn(
          async (
            name: string,
            _options: { mode: "exclusive" },
            callback: () => Promise<unknown>,
          ) => {
            lockRequests.push(name);
            const previous = held;
            let release: () => void = () => {};
            held = new Promise<void>((resolve) => {
              release = resolve;
            });
            await previous;
            try {
              return await callback();
            } finally {
              release();
            }
          },
        ),
      },
    });

    const order: string[] = [];
    let releaseFirst: () => void = () => {};
    const first = enqueueStewardSessionMutation(
      () =>
        new Promise<void>((resolve) => {
          order.push("first-start");
          releaseFirst = () => {
            order.push("first-end");
            resolve();
          };
        }),
    );
    const second = enqueueStewardSessionMutation(async () => {
      order.push("second");
    });

    await vi.waitFor(() => expect(order).toEqual(["first-start"]));
    releaseFirst();
    await Promise.all([first, second]);

    expect(order).toEqual(["first-start", "first-end", "second"]);
    expect(lockRequests).toEqual([
      "eliza-steward-session-mutation.v1",
      "eliza-steward-session-mutation.v1",
    ]);
  });

  it("releases both the module queue and origin lock after an error", async () => {
    const releaseCount = vi.fn();
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: vi.fn(
          async (
            _name: string,
            _options: { mode: "exclusive" },
            callback: () => Promise<unknown>,
          ) => {
            try {
              return await callback();
            } finally {
              releaseCount();
            }
          },
        ),
      },
    });

    await expect(
      enqueueStewardSessionMutation(async () => {
        throw new Error("mutation failed");
      }),
    ).rejects.toThrow("mutation failed");
    await expect(
      enqueueStewardSessionMutation(async () => "next"),
    ).resolves.toBe("next");
    expect(releaseCount).toHaveBeenCalledTimes(2);
  });

  it("shares the test fence across independently evaluated module instances", async () => {
    Reflect.deleteProperty(navigator, "locks");
    const moduleA = await import("./steward-session-mutation-queue");
    vi.resetModules();
    const moduleB = await import("./steward-session-mutation-queue");
    const order: string[] = [];
    let releaseA: () => void = () => {};

    const first = moduleA.enqueueStewardSessionMutation(
      () =>
        new Promise<void>((resolve) => {
          order.push("realm-a:start");
          releaseA = resolve;
        }),
    );
    const second = moduleB.enqueueStewardSessionMutation(async () => {
      order.push("realm-b:start");
    });

    await vi.waitFor(() => expect(order).toEqual(["realm-a:start"]));
    releaseA();
    await Promise.all([first, second]);
    expect(order).toEqual(["realm-a:start", "realm-b:start"]);
  });

  it("fails closed in two production module instances when Web Locks is unavailable", async () => {
    Reflect.deleteProperty(navigator, "locks");
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VITEST", "false");
    const moduleA = await import("./steward-session-mutation-queue");
    vi.resetModules();
    const moduleB = await import("./steward-session-mutation-queue");
    const mutationA = vi.fn(async () => undefined);
    const mutationB = vi.fn(async () => undefined);

    await expect(
      moduleA.enqueueStewardSessionMutation(mutationA),
    ).rejects.toMatchObject({
      name: "StewardSessionMutationLockUnavailableError",
    });
    await expect(
      moduleB.enqueueStewardSessionMutation(mutationB),
    ).rejects.toMatchObject({
      name: "StewardSessionMutationLockUnavailableError",
    });
    expect(mutationA).not.toHaveBeenCalled();
    expect(mutationB).not.toHaveBeenCalled();
  });
});
