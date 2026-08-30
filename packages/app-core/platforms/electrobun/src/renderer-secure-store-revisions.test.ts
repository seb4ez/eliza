import { describe, expect, it } from "vitest";
import { RendererSecureStoreRevisions } from "./renderer-secure-store-revisions";

const VAULT_ID = "renderer-revision-test-vault";
const KIND = "session.steward_token" as const;

describe("RendererSecureStoreRevisions", () => {
  it("broadcasts host revisions to every renderer without credential values", async () => {
    const revisions = new RendererSecureStoreRevisions();
    const rendererA: Array<{ message: string; payload: unknown }> = [];
    const rendererB: Array<{ message: string; payload: unknown }> = [];
    revisions.registerEndpoint((message, payload) => {
      rendererA.push({ message, payload });
    });
    revisions.registerEndpoint((message, payload) => {
      rendererB.push({ message, payload });
    });

    await expect(
      revisions.run(
        VAULT_ID,
        KIND,
        async () => ({ ok: true as const, rollbackReceipt: "opaque" }),
        { invalidates: (result) => result.ok },
      ),
    ).resolves.toEqual({ ok: true, rollbackReceipt: "opaque", revision: 1 });

    const expected = [
      {
        message: "secureStoreChanged",
        payload: { kind: KIND, revision: 1 },
      },
    ];
    expect(rendererA).toEqual(expected);
    expect(rendererB).toEqual(expected);
    expect(JSON.stringify(rendererA)).not.toContain("opaque");
  });

  it("isolates a closed renderer without losing a successful mutation receipt", async () => {
    const revisions = new RendererSecureStoreRevisions();
    let closedRendererCalls = 0;
    const rendererB: unknown[] = [];
    revisions.registerEndpoint(() => {
      closedRendererCalls += 1;
      throw new Error("renderer already closed");
    });
    revisions.registerEndpoint((_message, payload) => rendererB.push(payload));

    await expect(
      revisions.run(
        VAULT_ID,
        KIND,
        async () => ({ ok: true as const, rollbackReceipt: "receipt-1" }),
        { invalidates: (result) => result.ok },
      ),
    ).resolves.toEqual({
      ok: true,
      rollbackReceipt: "receipt-1",
      revision: 1,
    });
    await expect(
      revisions.run(
        VAULT_ID,
        KIND,
        async () => ({ ok: true as const, rollbackReceipt: "receipt-2" }),
        { invalidates: (result) => result.ok },
      ),
    ).resolves.toEqual({
      ok: true,
      rollbackReceipt: "receipt-2",
      revision: 2,
    });

    expect(closedRendererCalls).toBe(1);
    expect(rendererB).toEqual([
      { kind: KIND, revision: 1 },
      { kind: KIND, revision: 2 },
    ]);
  });

  it("keeps the SET revision stable for an idempotent mutation replay", async () => {
    const revisions = new RendererSecureStoreRevisions();
    const events: unknown[] = [];
    revisions.registerEndpoint((_message, payload) => events.push(payload));

    await expect(
      revisions.run(
        VAULT_ID,
        KIND,
        async () => ({ ok: true as const, changed: true }),
        { invalidates: (result) => result.changed !== false },
      ),
    ).resolves.toEqual({ ok: true, changed: true, revision: 1 });
    await expect(
      revisions.run(
        VAULT_ID,
        KIND,
        async () => ({ ok: true as const, changed: false }),
        { invalidates: (result) => result.changed !== false },
      ),
    ).resolves.toEqual({ ok: true, changed: false, revision: 1 });
    expect(events).toEqual([{ kind: KIND, revision: 1 }]);
  });

  it("returns an atomic older read before publishing the queued newer revision", async () => {
    const revisions = new RendererSecureStoreRevisions();
    let releaseRead: () => void = () => {};
    const readWait = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    const events: unknown[] = [];
    revisions.registerEndpoint((_message, payload) => events.push(payload));

    const read = revisions.run(
      VAULT_ID,
      KIND,
      async () => {
        await readWait;
        return { ok: true as const, value: "account-a-token" };
      },
      { invalidates: () => false },
    );
    const mutation = revisions.run(
      VAULT_ID,
      KIND,
      async () => ({ ok: true as const, deleted: true }),
      { invalidates: (result) => result.ok },
    );

    releaseRead();
    await expect(read).resolves.toEqual({
      ok: true,
      value: "account-a-token",
      revision: 0,
    });
    await expect(mutation).resolves.toEqual({
      ok: true,
      deleted: true,
      revision: 1,
    });
    expect(events).toEqual([{ kind: KIND, revision: 1 }]);
  });

  it("releases closed renderer endpoints", async () => {
    const revisions = new RendererSecureStoreRevisions();
    const closedRenderer: unknown[] = [];
    const release = revisions.registerEndpoint((_message, payload) => {
      closedRenderer.push(payload);
    });
    release();

    await revisions.run(
      VAULT_ID,
      KIND,
      async () => ({ ok: false as const, reason: "not_found" as const }),
      { invalidates: (result) => !result.ok && result.reason === "not_found" },
    );
    expect(closedRenderer).toEqual([]);
  });

  it("invalidates renderers when a host mutation throws with an ambiguous outcome", async () => {
    const revisions = new RendererSecureStoreRevisions();
    const events: unknown[] = [];
    revisions.registerEndpoint((_message, payload) => events.push(payload));

    await expect(
      revisions.run(
        VAULT_ID,
        KIND,
        async () => {
          throw new Error("host response lost after mutation attempt");
        },
        { invalidates: () => true, invalidatesOnError: true },
      ),
    ).rejects.toThrow("host response lost");
    expect(events).toEqual([{ kind: KIND, revision: 1 }]);
  });
});
