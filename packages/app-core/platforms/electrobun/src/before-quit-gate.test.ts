import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { createBeforeQuitGate } from "./before-quit-gate";

describe("createBeforeQuitGate", () => {
  it("installs the production gate before main can await or create a renderer owner", () => {
    const source = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
    const mainStart = source.indexOf("async function main(): Promise<void>");
    const mainEnd = source.indexOf(
      "\nfunction resolveStartupCrashReportPath",
      mainStart,
    );
    const mainSource = source.slice(mainStart, mainEnd);

    expect(mainStart).toBeGreaterThanOrEqual(0);
    expect(mainEnd).toBeGreaterThan(mainStart);
    expect(mainSource.match(/setupShutdown\(\);/g)).toHaveLength(1);
    expect(mainSource.indexOf("setupShutdown();")).toBeLessThan(
      mainSource.indexOf("await "),
    );
    expect(mainSource.indexOf("setupShutdown();")).toBeLessThan(
      mainSource.indexOf("createDesktopRpc("),
    );
  });

  it("denies OS quit synchronously, waits for cleanup, then allows exactly the guarded retry", async () => {
    let finishCleanup: () => void = () => {};
    const cleanup = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finishCleanup = resolve;
        }),
    );
    const quit = vi.fn();
    const onCleanupError = vi.fn();
    const gate = createBeforeQuitGate({ cleanup, onCleanupError, quit });

    const firstEvent: { response?: { allow: boolean } } = {};
    gate.handle(firstEvent);
    expect(firstEvent.response).toEqual({ allow: false });
    expect(cleanup).toHaveBeenCalledOnce();
    expect(quit).not.toHaveBeenCalled();

    const repeatedEvent: { response?: { allow: boolean } } = {};
    gate.handle(repeatedEvent);
    expect(repeatedEvent.response).toEqual({ allow: false });
    expect(cleanup).toHaveBeenCalledOnce();

    finishCleanup();
    await vi.waitFor(() => expect(quit).toHaveBeenCalledOnce());
    expect(onCleanupError).not.toHaveBeenCalled();

    const retriedEvent: { response?: { allow: boolean } } = {};
    gate.handle(retriedEvent);
    expect(retriedEvent.response).toEqual({ allow: true });
    expect(cleanup).toHaveBeenCalledOnce();

    const laterOsQuit: { response?: { allow: boolean } } = {};
    gate.handle(laterOsQuit);
    expect(laterOsQuit.response).toEqual({ allow: false });
    expect(cleanup).toHaveBeenCalledTimes(2);
  });

  it("lets an already-clean programmatic quit pass without starting another cleanup", () => {
    const cleanup = vi.fn(async () => undefined);
    const gate = createBeforeQuitGate({
      cleanup,
      onCleanupError: vi.fn(),
      quit: vi.fn(),
    });
    gate.allowNextQuit();

    const event: { response?: { allow: boolean } } = {};
    gate.handle(event);

    expect(event.response).toEqual({ allow: true });
    expect(cleanup).not.toHaveBeenCalled();
  });
});
