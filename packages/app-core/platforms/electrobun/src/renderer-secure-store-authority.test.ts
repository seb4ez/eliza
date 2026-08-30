/**
 * Proves cross-renderer rollback-receipt ordering at the host secure-store
 * boundary with a deterministic in-memory adapter.
 */

import { describe, expect, it } from "vitest";
import type {
  PlatformSecureStore,
  SecureStoreDeleteResult,
  SecureStoreGetResult,
  SecureStoreSecretKind,
  SecureStoreSetResult,
} from "../../../src/security/platform-secure-store";
import { RendererSecureStoreAuthority } from "./renderer-secure-store-authority";

const VAULT_ID = "renderer-authority-test-vault";
const TOKEN_KIND = "session.steward_token" as const;

class MemorySecureStore implements PlatformSecureStore {
  readonly backend = "none" as const;
  readonly operations: string[] = [];
  failNextDelete = false;
  failNextSet = false;
  mutateThenFailNextSet = false;

  constructor(public value: string | null = "prior-token") {}

  async get(
    _vaultId: string,
    _kind: SecureStoreSecretKind,
  ): Promise<SecureStoreGetResult> {
    this.operations.push(`get:${this.value ?? "missing"}`);
    return this.value === null
      ? { ok: false, reason: "not_found" }
      : { ok: true, value: this.value };
  }

  async set(
    _vaultId: string,
    _kind: SecureStoreSecretKind,
    value: string,
  ): Promise<SecureStoreSetResult> {
    this.operations.push(`set:${value}`);
    if (this.mutateThenFailNextSet) {
      this.mutateThenFailNextSet = false;
      this.value = value;
      return {
        ok: false,
        reason: "error",
        message: "injected post-mutation failure",
      };
    }
    if (this.failNextSet) {
      this.failNextSet = false;
      return { ok: false, reason: "error", message: "injected set failure" };
    }
    this.value = value;
    return { ok: true };
  }

  async delete(
    _vaultId: string,
    _kind: SecureStoreSecretKind,
  ): Promise<SecureStoreDeleteResult> {
    this.operations.push("delete");
    if (this.failNextDelete) {
      this.failNextDelete = false;
      return {
        ok: false,
        reason: "error",
        message: "injected delete failure",
      };
    }
    if (this.value === null) {
      return { ok: false, reason: "not_found" };
    }
    const deleted = this.value !== null;
    this.value = null;
    return { ok: true, deleted };
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }
}

function createAuthority(store: PlatformSecureStore) {
  let receiptSequence = 0;
  return new RendererSecureStoreAuthority(store, () => {
    receiptSequence += 1;
    return `rollback-receipt-${receiptSequence}`;
  });
}

function pendingReceiptCount(authority: RendererSecureStoreAuthority): number {
  const states = (
    authority as unknown as {
      slotStates: Map<string, { rollbacks: Map<string, unknown> }>;
    }
  ).slotStates;
  return Array.from(states.values()).reduce(
    (total, state) => total + state.rollbacks.size,
    0,
  );
}

describe("RendererSecureStoreAuthority", () => {
  it("turns a mutate-then-error backend acknowledgement into a receipt-bearing verified write", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    store.mutateThenFailNextSet = true;

    const write = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "mutated-before-error-token",
    );
    expect(write).toEqual({
      ok: true,
      rollbackReceipt: "rollback-receipt-1",
      changed: true,
    });
    if (!write.ok) throw new Error("mutate-then-error was not reconciled");
    expect(store.value).toBe("mutated-before-error-token");

    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
    expect(store.value).toBe("prior-token");
  });

  it("replays the same mutation id without a duplicate backend write", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const owner = Symbol("renderer-a");

    const first = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "idempotent-token",
      owner,
      "logical-mutation-1",
    );
    // Model loss of `first` on the transport and retry the same logical SET.
    const retry = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "idempotent-token",
      owner,
      "logical-mutation-1",
    );

    expect(first).toMatchObject({ ok: true, changed: true });
    expect(retry).toEqual({ ...first, changed: false });
    expect(
      store.operations.filter((operation) =>
        operation.startsWith("set:idempotent-token"),
      ),
    ).toHaveLength(1);
  });

  it("refuses new writes instead of evicting the only unresolved retry journal entry", async () => {
    const store = new MemorySecureStore();
    let receiptSequence = 0;
    const authority = new RendererSecureStoreAuthority(
      store,
      () => `bounded-receipt-${++receiptSequence}`,
      { journalCapacity: 2, journalTtlMs: 1 },
    );
    const owner = Symbol("renderer-a");
    const first = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "response-lost-token",
      owner,
      "response-lost-mutation",
    );

    await expect(
      authority.set(
        VAULT_ID,
        TOKEN_KIND,
        "must-not-be-written",
        owner,
        "second-mutation",
      ),
    ).resolves.toMatchObject({ ok: false, reason: "unavailable" });
    await expect(
      authority.set(
        VAULT_ID,
        TOKEN_KIND,
        "response-lost-token",
        owner,
        "response-lost-mutation",
      ),
    ).resolves.toEqual({ ...first, changed: false });
    expect(
      store.operations.filter((operation) => operation.startsWith("set:")),
    ).toEqual(["set:response-lost-token"]);
  });

  it("rolls every non-finalized receipt owned by a closing endpoint back", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const owner = Symbol("closing-renderer");
    const write = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "closing-renderer-token",
      owner,
      "closing-renderer-mutation",
    );
    expect(write.ok).toBe(true);

    await authority.releaseOwner(owner);

    expect(store.value).toBe("prior-token");
    expect(pendingReceiptCount(authority)).toBe(0);
    const ownerState = authority as unknown as {
      ownerIds: Map<symbol, number>;
      releasedOwners: Set<symbol>;
    };
    expect(ownerState.ownerIds.has(owner)).toBe(false);
    expect(ownerState.releasedOwners.has(owner)).toBe(false);
  });

  it("forgets a released ancestor owner after a descendant consumes its receipt", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const releasedOwner = Symbol("released-renderer");
    const activeOwner = Symbol("active-renderer");
    const ancestor = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "released-renderer-token",
      releasedOwner,
      "released-renderer-mutation",
    );
    const descendant = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "active-renderer-token",
      activeOwner,
      "active-renderer-mutation",
    );
    if (!ancestor.ok || !descendant.ok)
      throw new Error("renderer write failed");

    await authority.releaseOwner(releasedOwner);
    const ownerState = authority as unknown as {
      ownerIds: Map<symbol, number>;
      releasedOwners: Set<symbol>;
    };
    expect(ownerState.releasedOwners.has(releasedOwner)).toBe(true);

    await authority.compareAndRestore(
      VAULT_ID,
      TOKEN_KIND,
      descendant.rollbackReceipt,
      activeOwner,
    );
    await Promise.resolve();

    expect(ownerState.ownerIds.has(releasedOwner)).toBe(false);
    expect(ownerState.releasedOwners.has(releasedOwner)).toBe(false);
  });

  it("rejects renderer A's receipt after renderer B writes the same value", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const rendererA = {
      set: (value: string) => authority.set(VAULT_ID, TOKEN_KIND, value),
      rollback: (receipt: string) =>
        authority.compareAndRestore(VAULT_ID, TOKEN_KIND, receipt),
    };
    const rendererB = {
      set: (value: string) => authority.set(VAULT_ID, TOKEN_KIND, value),
    };

    const firstWrite = await rendererA.set("same-token");
    expect(firstWrite.ok).toBe(true);
    const secondWrite = await rendererB.set("same-token");
    expect(secondWrite.ok).toBe(true);
    if (!firstWrite.ok) throw new Error("renderer A write failed");
    if (!secondWrite.ok) throw new Error("renderer B write failed");
    expect(secondWrite.rollbackReceipt).not.toBe(firstWrite.rollbackReceipt);

    await expect(
      rendererA.rollback(firstWrite.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: false,
      value: "same-token",
    });
    expect(store.value).toBe("same-token");
  });

  it("skips a cancelled stale predecessor when the newer renderer also rolls back", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const rendererAWrite = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-a-aborted-token",
    );
    const rendererBWrite = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-b-aborted-token",
    );
    if (!rendererAWrite.ok) throw new Error("renderer A write failed");
    if (!rendererBWrite.ok) throw new Error("renderer B write failed");

    await expect(
      authority.compareAndRestore(
        VAULT_ID,
        TOKEN_KIND,
        rendererAWrite.rollbackReceipt,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: false,
      value: "renderer-b-aborted-token",
    });
    await expect(
      authority.compareAndRestore(
        VAULT_ID,
        TOKEN_KIND,
        rendererBWrite.rollbackReceipt,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
    expect(store.value).toBe("prior-token");
  });

  it("keeps the predecessor receipt live when descendants roll back newest first", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const rendererAWrite = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-a-aborted-token",
    );
    const rendererBWrite = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-b-aborted-token",
    );
    if (!rendererAWrite.ok) throw new Error("renderer A write failed");
    if (!rendererBWrite.ok) throw new Error("renderer B write failed");

    await expect(
      authority.compareAndRestore(
        VAULT_ID,
        TOKEN_KIND,
        rendererBWrite.rollbackReceipt,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "renderer-a-aborted-token",
    });
    await expect(
      authority.compareAndRestore(
        VAULT_ID,
        TOKEN_KIND,
        rendererAWrite.rollbackReceipt,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
    expect(store.value).toBe("prior-token");
  });

  it("replays a committed current receipt after its RPC response is lost", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const first = await authority.set(VAULT_ID, TOKEN_KIND, "first-token");
    const second = await authority.set(VAULT_ID, TOKEN_KIND, "second-token");
    if (!first.ok || !second.ok) throw new Error("renderer write failed");
    expect(pendingReceiptCount(authority)).toBe(2);

    await expect(
      authority.commitReceipt(VAULT_ID, TOKEN_KIND, second.rollbackReceipt),
    ).resolves.toEqual({ ok: true, committed: true });
    expect(pendingReceiptCount(authority)).toBe(0);
    await expect(
      authority.commitReceipt(VAULT_ID, TOKEN_KIND, second.rollbackReceipt),
    ).resolves.toEqual({ ok: true, committed: true });
    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, first.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: false,
      value: "second-token",
    });
  });

  it("compensates a committed receipt at its exact SET revision and replays response loss", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const owner = Symbol("renderer-a");
    const write = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-a-token",
      owner,
      "renderer-a-set",
    );
    if (!write.ok) throw new Error("renderer A write failed");
    await authority.commitReceipt(
      VAULT_ID,
      TOKEN_KIND,
      write.rollbackReceipt,
      owner,
    );

    await expect(
      authority.compensateCommittedReceipt(
        VAULT_ID,
        TOKEN_KIND,
        write.rollbackReceipt,
        1,
        1,
        owner,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      changed: true,
      value: "prior-token",
    });
    // Model loss of the first response after the host restored the predecessor.
    await expect(
      authority.compensateCommittedReceipt(
        VAULT_ID,
        TOKEN_KIND,
        write.rollbackReceipt,
        1,
        2,
        owner,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      changed: false,
      value: "prior-token",
    });
    expect(store.value).toBe("prior-token");
  });

  it("compensates a committed descendant past every cancelled ancestor", async () => {
    const store = new MemorySecureStore("pre-chain-token");
    const authority = createAuthority(store);
    const ownerA = Symbol("renderer-a");
    const ownerB = Symbol("renderer-b");
    const a = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "cancelled-a-token",
      ownerA,
      "cancelled-a-set",
    );
    const b = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "committed-b-token",
      ownerB,
      "committed-b-set",
    );
    if (!a.ok || !b.ok) throw new Error("renderer write failed");

    await expect(
      authority.commitReceipt(VAULT_ID, TOKEN_KIND, a.rollbackReceipt, ownerA),
    ).resolves.toEqual({ ok: true, committed: false });
    await expect(
      authority.commitReceipt(VAULT_ID, TOKEN_KIND, b.rollbackReceipt, ownerB),
    ).resolves.toEqual({ ok: true, committed: true });

    await expect(
      authority.compensateCommittedReceipt(
        VAULT_ID,
        TOKEN_KIND,
        b.rollbackReceipt,
        2,
        2,
        ownerB,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      changed: true,
      value: "pre-chain-token",
    });
    expect(store.value).toBe("pre-chain-token");
  });

  it("does not compensate an old receipt after same-value ABA advances the host revision", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const owner = Symbol("renderer-a");
    const firstA = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "same-token-a",
      owner,
      "first-a",
    );
    if (!firstA.ok) throw new Error("first A write failed");
    await authority.commitReceipt(
      VAULT_ID,
      TOKEN_KIND,
      firstA.rollbackReceipt,
      owner,
    );
    const b = await authority.set(VAULT_ID, TOKEN_KIND, "token-b", owner, "b");
    if (!b.ok) throw new Error("B write failed");
    await authority.commitReceipt(
      VAULT_ID,
      TOKEN_KIND,
      b.rollbackReceipt,
      owner,
    );
    const secondA = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "same-token-a",
      owner,
      "second-a",
    );
    if (!secondA.ok) throw new Error("second A write failed");
    await authority.commitReceipt(
      VAULT_ID,
      TOKEN_KIND,
      secondA.rollbackReceipt,
      owner,
    );

    await expect(
      authority.compensateCommittedReceipt(
        VAULT_ID,
        TOKEN_KIND,
        firstA.rollbackReceipt,
        1,
        3,
        owner,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: false,
      changed: false,
      value: "same-token-a",
    });
    expect(store.value).toBe("same-token-a");
  });

  it("lets durable B win but restores A before a marker-only B writes", async () => {
    const durableStore = new MemorySecureStore();
    const durableAuthority = createAuthority(durableStore);
    const ownerA = Symbol("renderer-a");
    const ownerB = Symbol("renderer-b");
    const durableA = await durableAuthority.set(
      VAULT_ID,
      TOKEN_KIND,
      "token-a",
      ownerA,
      "durable-a",
    );
    if (!durableA.ok) throw new Error("durable A failed");
    await durableAuthority.commitReceipt(
      VAULT_ID,
      TOKEN_KIND,
      durableA.rollbackReceipt,
      ownerA,
    );
    const durableB = await durableAuthority.set(
      VAULT_ID,
      TOKEN_KIND,
      "token-b",
      ownerB,
      "durable-b",
    );
    if (!durableB.ok) throw new Error("durable B failed");
    await expect(
      durableAuthority.compensateCommittedReceipt(
        VAULT_ID,
        TOKEN_KIND,
        durableA.rollbackReceipt,
        1,
        2,
        ownerA,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: false,
      changed: false,
      value: "token-b",
    });
    expect(durableStore.value).toBe("token-b");

    const markerStore = new MemorySecureStore();
    const markerAuthority = createAuthority(markerStore);
    const markerA = await markerAuthority.set(
      VAULT_ID,
      TOKEN_KIND,
      "token-a",
      ownerA,
      "marker-a",
    );
    if (!markerA.ok) throw new Error("marker A failed");
    await markerAuthority.commitReceipt(
      VAULT_ID,
      TOKEN_KIND,
      markerA.rollbackReceipt,
      ownerA,
    );
    // B has only published its renderer marker: host revision is still A's.
    await markerAuthority.compensateCommittedReceipt(
      VAULT_ID,
      TOKEN_KIND,
      markerA.rollbackReceipt,
      1,
      1,
      ownerA,
    );
    expect(markerStore.value).toBe("prior-token");
    const markerB = await markerAuthority.set(
      VAULT_ID,
      TOKEN_KIND,
      "token-b",
      ownerB,
      "marker-b",
    );
    if (!markerB.ok) throw new Error("marker B failed");
    await expect(
      markerAuthority.compareAndRestore(
        VAULT_ID,
        TOKEN_KIND,
        markerB.rollbackReceipt,
        ownerB,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
  });

  it("keeps a lost commit response replayable beyond one full RPC budget without evicting its tombstone", async () => {
    const store = new MemorySecureStore();
    let now = 1_000;
    let receiptSequence = 0;
    const authority = new RendererSecureStoreAuthority(
      store,
      () => `suspended-receipt-${++receiptSequence}`,
      { journalCapacity: 2, now: () => now },
    );
    const owner = Symbol("suspended-renderer");
    const write = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "suspension-safe-token",
      owner,
      "suspension-safe-mutation",
    );
    if (!write.ok) throw new Error("renderer write failed");

    await expect(
      authority.commitReceipt(
        VAULT_ID,
        TOKEN_KIND,
        write.rollbackReceipt,
        owner,
      ),
    ).resolves.toEqual({ ok: true, committed: true });

    // The first response is lost and the renderer remains suspended for the
    // exact ten-minute request ceiling before it can retry.
    now += 600_000;
    await expect(
      authority.set(
        VAULT_ID,
        TOKEN_KIND,
        "must-not-evict-commit",
        owner,
        "capacity-hostile-mutation",
      ),
    ).resolves.toMatchObject({ ok: false, reason: "unavailable" });
    await expect(
      authority.commitReceipt(
        VAULT_ID,
        TOKEN_KIND,
        write.rollbackReceipt,
        owner,
      ),
    ).resolves.toEqual({ ok: true, committed: true });
    expect(
      store.operations.filter((operation) => operation.startsWith("set:")),
    ).toEqual(["set:suspension-safe-token"]);
  });

  it("does not replay a committed receipt journal entry for another slot", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const owner = Symbol("renderer-a");
    const write = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "slot-bound-token",
      owner,
      "slot-bound-mutation",
    );
    if (!write.ok) throw new Error("renderer write failed");
    await expect(
      authority.commitReceipt(
        VAULT_ID,
        TOKEN_KIND,
        write.rollbackReceipt,
        owner,
      ),
    ).resolves.toEqual({ ok: true, committed: true });

    await expect(
      authority.commitReceipt(
        VAULT_ID,
        "session.device_auth",
        write.rollbackReceipt,
        owner,
      ),
    ).resolves.toEqual({ ok: true, committed: false });
  });

  it("rejects an ancestor commit and makes its descendant skip that stale value", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const first = await authority.set(VAULT_ID, TOKEN_KIND, "first-token");
    const second = await authority.set(VAULT_ID, TOKEN_KIND, "second-token");
    if (!first.ok || !second.ok) throw new Error("renderer write failed");

    await expect(
      authority.commitReceipt(VAULT_ID, TOKEN_KIND, first.rollbackReceipt),
    ).resolves.toEqual({ ok: true, committed: false });
    expect(pendingReceiptCount(authority)).toBe(2);
    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, second.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
    expect(pendingReceiptCount(authority)).toBe(0);
    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, first.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: false,
      value: "prior-token",
    });
  });

  it("does not let a late commit revive a receipt already cancelled stale", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const first = await authority.set(VAULT_ID, TOKEN_KIND, "aborted-first");
    const second = await authority.set(VAULT_ID, TOKEN_KIND, "aborted-second");
    if (!first.ok || !second.ok) throw new Error("renderer write failed");

    await authority.compareAndRestore(
      VAULT_ID,
      TOKEN_KIND,
      first.rollbackReceipt,
    );
    await expect(
      authority.commitReceipt(VAULT_ID, TOKEN_KIND, first.rollbackReceipt),
    ).resolves.toEqual({ ok: true, committed: false });
    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, second.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
    expect(store.value).toBe("prior-token");
    expect(pendingReceiptCount(authority)).toBe(0);
  });

  it("never publishes a non-current middle receipt in a cancelled ancestry", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const first = await authority.set(VAULT_ID, TOKEN_KIND, "aborted-first");
    const second = await authority.set(VAULT_ID, TOKEN_KIND, "accepted-second");
    const third = await authority.set(VAULT_ID, TOKEN_KIND, "aborted-third");
    if (!first.ok || !second.ok || !third.ok) {
      throw new Error("renderer write failed");
    }

    await authority.compareAndRestore(
      VAULT_ID,
      TOKEN_KIND,
      first.rollbackReceipt,
    );
    await expect(
      authority.commitReceipt(VAULT_ID, TOKEN_KIND, second.rollbackReceipt),
    ).resolves.toEqual({ ok: true, committed: false });
    expect(pendingReceiptCount(authority)).toBe(3);
    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, third.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
    expect(pendingReceiptCount(authority)).toBe(0);
  });

  it("does not overwrite a host value changed outside the renderer authority", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const write = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-aborted-token",
    );
    if (!write.ok) throw new Error("renderer write failed");
    store.value = "new-host-authority-token";

    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: false,
      value: "new-host-authority-token",
    });
    expect(store.value).toBe("new-host-authority-token");
  });

  it("detaches a fresh write from an externally replaced host predecessor", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const stale = await authority.set(VAULT_ID, TOKEN_KIND, "renderer-a-token");
    if (!stale.ok) throw new Error("renderer A write failed");
    store.value = "external-authority-token";
    const current = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-b-aborted-token",
    );
    if (!current.ok) throw new Error("renderer B write failed");

    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, stale.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: false,
      value: "renderer-b-aborted-token",
    });
    await expect(
      authority.compareAndRestore(
        VAULT_ID,
        TOKEN_KIND,
        current.rollbackReceipt,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "external-authority-token",
    });
  });

  it("restores the host predecessor when renderer B writes after A captured stale state but before A sets", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const stalePredecessorCapturedByRendererA = store.value;

    await authority.set(VAULT_ID, TOKEN_KIND, "renderer-b-token");
    const rendererAWrite = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-a-aborted-token",
    );
    if (!rendererAWrite.ok) throw new Error("renderer A write failed");

    await expect(
      authority.compareAndRestore(
        VAULT_ID,
        TOKEN_KIND,
        rendererAWrite.rollbackReceipt,
      ),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "renderer-b-token",
    });
    expect(store.value).toBe("renderer-b-token");
    expect(store.value).not.toBe(stalePredecessorCapturedByRendererA);
  });

  it("invalidates a set receipt when a newer renderer deletes the slot", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const write = await authority.set(VAULT_ID, TOKEN_KIND, "renderer-a-token");
    if (!write.ok) throw new Error("renderer A write failed");

    await authority.delete(VAULT_ID, TOKEN_KIND);

    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({ ok: true, restored: false, value: null });
    expect(store.value).toBeNull();
  });

  it("invalidates a live receipt when delete authoritatively observes not_found", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const write = await authority.set(VAULT_ID, TOKEN_KIND, "renderer-a-token");
    if (!write.ok) throw new Error("renderer A write failed");

    // Model removal by an OS-side authority before this renderer's logout.
    store.value = null;
    await expect(authority.delete(VAULT_ID, TOKEN_KIND)).resolves.toEqual({
      ok: false,
      reason: "not_found",
    });
    await expect(
      authority.commitReceipt(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({ ok: true, committed: false });
  });

  it("restores an empty host predecessor for the exact set receipt", async () => {
    const store = new MemorySecureStore(null);
    const authority = createAuthority(store);
    const write = await authority.set(
      VAULT_ID,
      TOKEN_KIND,
      "renderer-a-aborted-token",
    );
    if (!write.ok) throw new Error("renderer A write failed");

    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({ ok: true, restored: true, value: null });
    expect(store.value).toBeNull();
  });

  it("keeps a receipt retryable when predecessor restoration fails", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const write = await authority.set(VAULT_ID, TOKEN_KIND, "aborted-token");
    if (!write.ok) throw new Error("renderer write failed");
    store.failNextSet = true;

    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({
      ok: false,
      reason: "error",
      message: "injected set failure",
    });
    expect(pendingReceiptCount(authority)).toBe(1);
    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
    expect(pendingReceiptCount(authority)).toBe(0);
  });

  it("does not invalidate a live set receipt when delete fails", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const write = await authority.set(VAULT_ID, TOKEN_KIND, "aborted-token");
    if (!write.ok) throw new Error("renderer write failed");
    store.failNextDelete = true;

    await expect(authority.delete(VAULT_ID, TOKEN_KIND)).resolves.toEqual({
      ok: false,
      reason: "error",
      message: "injected delete failure",
    });
    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({
      ok: true,
      restored: true,
      value: "prior-token",
    });
  });

  it("does not let a stale terminal authority delete renderer B's value", async () => {
    const store = new MemorySecureStore("renderer-a-token");
    const authority = createAuthority(store);
    store.value = "renderer-b-token";

    await expect(
      authority.compareAndDelete(
        VAULT_ID,
        TOKEN_KIND,
        "renderer-a-token",
        4,
        5,
      ),
    ).resolves.toEqual({
      ok: true,
      deleted: false,
      changed: false,
      value: "renderer-b-token",
    });
    expect(store.value).toBe("renderer-b-token");
  });

  it("replays an exact CAS deletion after its first response is lost", async () => {
    const store = new MemorySecureStore("renderer-a-token");
    const authority = createAuthority(store);
    const owner = Symbol("renderer-a");

    await expect(
      authority.compareAndDelete(
        VAULT_ID,
        TOKEN_KIND,
        "renderer-a-token",
        8,
        8,
        owner,
        "terminal-delete-a",
      ),
    ).resolves.toEqual({
      ok: true,
      deleted: true,
      changed: true,
      value: null,
    });
    await expect(
      authority.compareAndDelete(
        VAULT_ID,
        TOKEN_KIND,
        "renderer-a-token",
        8,
        9,
        owner,
        "terminal-delete-a",
      ),
    ).resolves.toEqual({
      ok: true,
      deleted: true,
      changed: false,
      value: null,
    });
  });

  it("does not attribute renderer B's deletion to renderer A's mutation id", async () => {
    const store = new MemorySecureStore("shared-token");
    const authority = createAuthority(store);
    await authority.compareAndDelete(
      VAULT_ID,
      TOKEN_KIND,
      "shared-token",
      20,
      20,
      Symbol("renderer-b"),
      "terminal-delete-b",
    );

    await expect(
      authority.compareAndDelete(
        VAULT_ID,
        TOKEN_KIND,
        "shared-token",
        20,
        21,
        Symbol("renderer-a"),
        "terminal-delete-a",
      ),
    ).resolves.toEqual({
      ok: true,
      deleted: false,
      changed: false,
      value: null,
    });
    expect(store.value).toBeNull();
  });

  it("applies one exact terminal transform and replays it without rewriting", async () => {
    const store = new MemorySecureStore("profile-a-with-token");
    const authority = createAuthority(store);
    const owner = Symbol("terminal-renderer-a");

    const first = await authority.compareAndSet(
      VAULT_ID,
      "runtime.agent_profiles",
      "profile-a-with-token",
      "profile-a-scrubbed",
      7,
      7,
      owner,
      "terminal-transform-a",
    );
    const replay = await authority.compareAndSet(
      VAULT_ID,
      "runtime.agent_profiles",
      "profile-a-with-token",
      "profile-a-scrubbed",
      7,
      8,
      owner,
      "terminal-transform-a",
    );

    expect(first).toEqual({
      ok: true,
      applied: true,
      changed: true,
      value: "profile-a-scrubbed",
    });
    expect(replay).toEqual({ ...first, changed: false });
    expect(
      store.operations.filter(
        (operation) => operation === "set:profile-a-scrubbed",
      ),
    ).toHaveLength(1);
  });

  it("does not transform renderer B after an exact A snapshot goes stale", async () => {
    const store = new MemorySecureStore("profile-b-with-token");
    const authority = createAuthority(store);

    await expect(
      authority.compareAndSet(
        VAULT_ID,
        "runtime.agent_profiles",
        "profile-a-with-token",
        "profile-a-scrubbed",
        4,
        5,
        Symbol("renderer-a"),
        "stale-terminal-a",
      ),
    ).resolves.toEqual({
      ok: true,
      applied: false,
      changed: false,
      value: "profile-b-with-token",
    });
    expect(store.value).toBe("profile-b-with-token");
    expect(
      store.operations.filter((operation) => operation.startsWith("set:")),
    ).toEqual([]);
  });

  it("treats mutate-then-error terminal SET readback as authoritative", async () => {
    const store = new MemorySecureStore("active-a-with-token");
    const authority = createAuthority(store);
    store.mutateThenFailNextSet = true;

    await expect(
      authority.compareAndSet(
        VAULT_ID,
        "runtime.active_server",
        "active-a-with-token",
        "active-a-scrubbed",
        2,
        2,
        Symbol("renderer-a"),
        "mutate-error-terminal-a",
      ),
    ).resolves.toEqual({
      ok: true,
      applied: true,
      changed: true,
      value: "active-a-scrubbed",
    });
    expect(store.value).toBe("active-a-scrubbed");
  });

  it("keeps an empty-predecessor receipt retryable when deletion fails", async () => {
    const store = new MemorySecureStore(null);
    const authority = createAuthority(store);
    const write = await authority.set(VAULT_ID, TOKEN_KIND, "aborted-token");
    if (!write.ok) throw new Error("renderer write failed");
    store.failNextDelete = true;

    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({
      ok: false,
      reason: "error",
      message: "injected delete failure",
    });
    expect(pendingReceiptCount(authority)).toBe(1);
    await expect(
      authority.compareAndRestore(VAULT_ID, TOKEN_KIND, write.rollbackReceipt),
    ).resolves.toEqual({ ok: true, restored: true, value: null });
    expect(pendingReceiptCount(authority)).toBe(0);
  });
});
