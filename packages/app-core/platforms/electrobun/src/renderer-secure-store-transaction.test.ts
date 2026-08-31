import { describe, expect, it, vi } from "vitest";
import type {
  PlatformSecureStore,
  SecureStoreDeleteResult,
  SecureStoreGetResult,
  SecureStoreSecretKind,
  SecureStoreSetResult,
} from "../../../src/security/platform-secure-store";
import {
  createRendererSecureStoreOwner,
  RendererSecureStoreAuthority,
} from "./renderer-secure-store-authority";
import {
  type RendererConnectionTransactionParticipantInput,
  RendererSecureStoreTransactionAuthority,
} from "./renderer-secure-store-transaction";

const VAULT_ID = "runtime-connection-transaction-test";
const WAL_KIND = "runtime.connection_txn" as const;
const REGISTRY_KIND = "runtime.agent_profiles" as const;
const SERVER_KIND = "runtime.active_server" as const;
const TOKEN_KIND = "session.steward_token" as const;

const beforeValues = {
  [REGISTRY_KIND]: "registry-a",
  [SERVER_KIND]: "server-a",
  [TOKEN_KIND]: JSON.stringify({
    marker: "eliza.steward-token.v1",
    scope: "eliza-cloud:production",
    token: "token-a",
  }),
} as const;

const afterValues = {
  [REGISTRY_KIND]: "registry-b",
  [SERVER_KIND]: "server-b",
  [TOKEN_KIND]: JSON.stringify({
    marker: "eliza.steward-token.v1",
    scope: "eliza-cloud:staging",
    token: "token-b",
  }),
} as const;

type ParticipantKind = keyof typeof beforeValues;

class MemorySecureStore implements PlatformSecureStore {
  readonly backend = "none" as const;
  readonly values = new Map<string, string>();
  readonly failNextSet = new Set<SecureStoreSecretKind>();

  constructor() {
    for (const [kind, value] of Object.entries(beforeValues)) {
      this.values.set(this.key(VAULT_ID, kind as SecureStoreSecretKind), value);
    }
  }

  private key(vaultId: string, kind: SecureStoreSecretKind): string {
    return `${vaultId}\0${kind}`;
  }

  value(kind: SecureStoreSecretKind): string | null {
    return this.values.get(this.key(VAULT_ID, kind)) ?? null;
  }

  async get(
    vaultId: string,
    kind: SecureStoreSecretKind,
  ): Promise<SecureStoreGetResult> {
    const value = this.values.get(this.key(vaultId, kind));
    return value === undefined
      ? { ok: false, reason: "not_found" }
      : { ok: true, value };
  }

  async set(
    vaultId: string,
    kind: SecureStoreSecretKind,
    value: string,
  ): Promise<SecureStoreSetResult> {
    if (this.failNextSet.delete(kind)) {
      return { ok: false, reason: "error", message: "injected failure" };
    }
    this.values.set(this.key(vaultId, kind), value);
    return { ok: true };
  }

  async delete(
    vaultId: string,
    kind: SecureStoreSecretKind,
  ): Promise<SecureStoreDeleteResult> {
    return {
      ok: true,
      deleted: this.values.delete(this.key(vaultId, kind)),
    };
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }
}

function createAuthority(store: PlatformSecureStore) {
  let epoch = 0;
  return new RendererSecureStoreTransactionAuthority(store, {
    createEpoch: () => `epoch-${++epoch}`,
  });
}

function initialParticipants(): RendererConnectionTransactionParticipantInput[] {
  return [
    { kind: REGISTRY_KIND, value: afterValues[REGISTRY_KIND] },
    { kind: SERVER_KIND, value: afterValues[SERVER_KIND] },
  ];
}

async function setParticipant(
  store: PlatformSecureStore,
  kind: ParticipantKind,
  value: string = afterValues[kind],
): Promise<void> {
  await store.set(VAULT_ID, kind, value);
}

function expectParticipants(
  store: MemorySecureStore,
  expected: typeof beforeValues | typeof afterValues,
): void {
  for (const kind of Object.keys(expected) as ParticipantKind[]) {
    expect(store.value(kind)).toBe(expected[kind]);
  }
}

async function stageAndSetToken(
  authority: RendererSecureStoreTransactionAuthority,
  store: MemorySecureStore,
  owner: ReturnType<typeof createRendererSecureStoreOwner>,
  transactionId: string,
): Promise<void> {
  await authority.stage(VAULT_ID, owner, transactionId, {
    kind: TOKEN_KIND,
    value: afterValues[TOKEN_KIND],
  });
  await setParticipant(store, TOKEN_KIND);
}

async function prepareAllParticipants(
  authority: RendererSecureStoreTransactionAuthority,
  store: MemorySecureStore,
  owner: ReturnType<typeof createRendererSecureStoreOwner>,
  transactionId: string,
): Promise<void> {
  await authority.begin(VAULT_ID, owner, transactionId, initialParticipants());
  await setParticipant(store, REGISTRY_KIND);
  await setParticipant(store, SERVER_KIND);
  await stageAndSetToken(authority, store, owner, transactionId);
}

const receipts = [
  { kind: REGISTRY_KIND, rollbackReceipt: "registry-receipt" },
  { kind: SERVER_KIND, rollbackReceipt: "server-receipt" },
  { kind: TOKEN_KIND, rollbackReceipt: "token-receipt" },
] as const;

describe("RendererSecureStoreTransactionAuthority", () => {
  it("refuses to capture a renderer SET until its separate receipt RPC settles", async () => {
    const store = new MemorySecureStore();
    const transactionAuthority = createAuthority(store);
    const writer = createRendererSecureStoreOwner("generic-writer");
    const transactionOwner =
      createRendererSecureStoreOwner("transaction-owner");
    const receiptAuthority = new RendererSecureStoreAuthority(
      store,
      () => "pending-generic-receipt",
    );

    // Model the exact RPC gap: the host SET completed under the shared
    // transaction tail, but the renderer has not sent COMMIT receipt yet.
    const access = await transactionAuthority.runAccess(
      VAULT_ID,
      writer,
      undefined,
      undefined,
      () =>
        receiptAuthority.set(
          VAULT_ID,
          REGISTRY_KIND,
          "registry-c-uncommitted",
          writer,
          "generic-set-c",
        ),
    );
    const write = access.result;
    if (!write?.ok || !write.rollbackReceipt) {
      throw new Error("generic renderer SET did not produce a receipt");
    }
    expect(store.value(REGISTRY_KIND)).toBe("registry-c-uncommitted");

    await expect(
      transactionAuthority.begin(
        VAULT_ID,
        transactionOwner,
        "must-not-capture-pending-c",
        initialParticipants(),
        () => receiptAuthority.assertNoPendingReceipts(VAULT_ID),
      ),
    ).rejects.toThrow("secure-store receipts are pending");
    expect(store.value(WAL_KIND)).toBeNull();

    // The original writer can still settle its own failure. A process restart
    // then sees A, never a WAL that incorrectly treats uncommitted C as before.
    await expect(
      receiptAuthority.compareAndRestore(
        VAULT_ID,
        REGISTRY_KIND,
        write.rollbackReceipt,
        writer,
      ),
    ).resolves.toMatchObject({ ok: true, restored: true });
    await createAuthority(store).beforeAccess(
      VAULT_ID,
      createRendererSecureStoreOwner("renderer-after-restart"),
    );
    expectParticipants(store, beforeValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("settles prepared participant receipts on abort before allowing the next begin", async () => {
    const store = new MemorySecureStore();
    const transactionAuthority = createAuthority(store);
    const receiptAuthority = new RendererSecureStoreAuthority(
      store,
      () => "aborted-participant-receipt",
    );
    const owner = createRendererSecureStoreOwner("aborting-owner");
    await transactionAuthority.begin(
      VAULT_ID,
      owner,
      "aborting-transaction",
      initialParticipants(),
      () => receiptAuthority.assertNoPendingReceipts(VAULT_ID),
    );
    const writeAccess = await transactionAuthority.runAccess(
      VAULT_ID,
      owner,
      "aborting-transaction",
      {
        kind: REGISTRY_KIND,
        operation: "set",
        value: afterValues[REGISTRY_KIND],
      },
      () =>
        receiptAuthority.set(
          VAULT_ID,
          REGISTRY_KIND,
          afterValues[REGISTRY_KIND],
          owner,
          "aborted-participant-set",
        ),
    );
    const write = writeAccess.result;
    if (!write?.ok) throw new Error("participant SET failed");

    await transactionAuthority.abort(
      VAULT_ID,
      owner,
      "aborting-transaction",
      [{ kind: REGISTRY_KIND, rollbackReceipt: write.rollbackReceipt }],
      async (pending) => {
        for (const receipt of pending) {
          const settled = await receiptAuthority.compareAndRestore(
            VAULT_ID,
            receipt.kind,
            receipt.rollbackReceipt,
            owner,
          );
          if (!settled.ok) throw new Error("receipt settlement failed");
        }
      },
    );
    expect(store.value(REGISTRY_KIND)).toBe(beforeValues[REGISTRY_KIND]);
    expect(() =>
      receiptAuthority.assertNoPendingReceipts(VAULT_ID),
    ).not.toThrow();

    await expect(
      transactionAuthority.begin(
        VAULT_ID,
        owner,
        "transaction-after-abort",
        initialParticipants(),
        () => receiptAuthority.assertNoPendingReceipts(VAULT_ID),
      ),
    ).resolves.toMatchObject({ epoch: expect.any(String) });
  });

  it("settles a participant receipt whose every SET response was lost", async () => {
    const store = new MemorySecureStore();
    const transactionAuthority = createAuthority(store);
    const receiptAuthority = new RendererSecureStoreAuthority(
      store,
      () => "response-lost-participant-receipt",
    );
    const owner = createRendererSecureStoreOwner("response-lost-set-owner");
    const { epoch } = await transactionAuthority.begin(
      VAULT_ID,
      owner,
      "response-lost-set",
      initialParticipants(),
      () => receiptAuthority.assertNoPendingReceipts(VAULT_ID),
    );
    await transactionAuthority.runAccess(
      VAULT_ID,
      owner,
      "response-lost-set",
      {
        kind: REGISTRY_KIND,
        operation: "set",
        value: afterValues[REGISTRY_KIND],
      },
      () =>
        receiptAuthority.set(
          VAULT_ID,
          REGISTRY_KIND,
          afterValues[REGISTRY_KIND],
          owner,
          "response-lost-set-mutation",
        ),
      undefined,
      epoch,
    );
    expect(() => receiptAuthority.assertNoPendingReceipts(VAULT_ID)).toThrow();

    await transactionAuthority.abort(
      VAULT_ID,
      owner,
      "response-lost-set",
      [],
      async (_knownReceipts, participantKinds) => {
        for (const kind of participantKinds) {
          await receiptAuthority.releaseOwnerSlot(owner, VAULT_ID, kind);
        }
      },
      epoch,
    );
    expect(store.value(REGISTRY_KIND)).toBe(beforeValues[REGISTRY_KIND]);
    expect(() =>
      receiptAuthority.assertNoPendingReceipts(VAULT_ID),
    ).not.toThrow();
    await expect(
      transactionAuthority.begin(
        VAULT_ID,
        owner,
        "after-response-lost-set",
        initialParticipants(),
        () => receiptAuthority.assertNoPendingReceipts(VAULT_ID),
      ),
    ).resolves.toMatchObject({ epoch: expect.any(String) });
  });

  it.each([
    "prepared",
    "after-registry",
    "after-server",
    "after-token",
  ] as const)(
    "rolls an orphaned %s WAL back before the first read",
    async (checkpoint) => {
      const store = new MemorySecureStore();
      const owner = createRendererSecureStoreOwner("renderer-a");
      const authority = createAuthority(store);
      const transactionId = `transaction-${checkpoint}`;

      await authority.begin(
        VAULT_ID,
        owner,
        transactionId,
        initialParticipants(),
      );
      if (checkpoint !== "prepared") {
        await setParticipant(store, REGISTRY_KIND);
      }
      if (checkpoint === "after-server" || checkpoint === "after-token") {
        await setParticipant(store, SERVER_KIND);
      }
      if (checkpoint === "after-token") {
        await stageAndSetToken(authority, store, owner, transactionId);
      }

      const restarted = createAuthority(store);
      await restarted.beforeAccess(
        VAULT_ID,
        createRendererSecureStoreOwner("renderer-after-restart"),
      );

      expectParticipants(store, beforeValues);
      expect(store.value(WAL_KIND)).toBeNull();
    },
  );

  it("rolls every participant forward when the process dies after the committed decision", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("renderer-a");
    const authority = createAuthority(store);
    await prepareAllParticipants(authority, store, owner, "committed-crash");
    await authority.decideCommit(
      VAULT_ID,
      owner,
      "committed-crash",
      receipts,
      async () => undefined,
    );
    expect(store.value(WAL_KIND)).not.toBeNull();

    const restarted = createAuthority(store);
    await restarted.beforeAccess(
      VAULT_ID,
      createRendererSecureStoreOwner("renderer-after-restart"),
    );

    expectParticipants(store, afterValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("resumes an interrupted rollback idempotently and retains the WAL until it verifies", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("renderer-a");
    const authority = createAuthority(store);
    await prepareAllParticipants(authority, store, owner, "rollback-retry");
    store.failNextSet.add(SERVER_KIND);

    await expect(
      createAuthority(store).beforeAccess(
        VAULT_ID,
        createRendererSecureStoreOwner("first-restart"),
      ),
    ).rejects.toThrow("write did not verify");
    expect(store.value(REGISTRY_KIND)).toBe(beforeValues[REGISTRY_KIND]);
    expect(store.value(SERVER_KIND)).toBe(afterValues[SERVER_KIND]);
    expect(store.value(WAL_KIND)).not.toBeNull();

    const secondRestart = createAuthority(store);
    await secondRestart.beforeAccess(
      VAULT_ID,
      createRendererSecureStoreOwner("second-restart"),
    );
    await secondRestart.beforeAccess(
      VAULT_ID,
      createRendererSecureStoreOwner("second-read"),
    );
    expectParticipants(store, beforeValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("never lets a delayed DECIDE resurrect an interrupted durable ABORT", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("abort-decision-monotonicity");
    const authority = createAuthority(store);
    const { epoch } = await authority.begin(
      VAULT_ID,
      owner,
      "abort-decision-monotonicity",
      initialParticipants(),
    );
    await setParticipant(store, REGISTRY_KIND);
    await setParticipant(store, SERVER_KIND);
    store.failNextSet.add(REGISTRY_KIND);

    await expect(
      authority.abort(
        VAULT_ID,
        owner,
        "abort-decision-monotonicity",
        receipts.slice(0, 2),
        undefined,
        epoch,
      ),
    ).rejects.toThrow("write did not verify");
    expect(store.value(WAL_KIND)).toContain('"phase":"aborting"');
    const commitReceipts = vi.fn(async () => undefined);

    await expect(
      authority.decideCommit(
        VAULT_ID,
        owner,
        "abort-decision-monotonicity",
        receipts.slice(0, 2),
        commitReceipts,
        epoch,
      ),
    ).rejects.toThrow("already aborting");
    expect(commitReceipts).not.toHaveBeenCalled();
    expect(store.value(WAL_KIND)).toContain('"phase":"aborting"');
  });

  it("resumes an interrupted committed roll-forward idempotently", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("renderer-a");
    const authority = createAuthority(store);
    await prepareAllParticipants(authority, store, owner, "rollforward-retry");
    await authority.decideCommit(
      VAULT_ID,
      owner,
      "rollforward-retry",
      receipts,
      async () => undefined,
    );
    await setParticipant(store, REGISTRY_KIND, beforeValues[REGISTRY_KIND]);
    await setParticipant(store, SERVER_KIND, beforeValues[SERVER_KIND]);
    store.failNextSet.add(SERVER_KIND);

    await expect(
      createAuthority(store).beforeAccess(
        VAULT_ID,
        createRendererSecureStoreOwner("first-restart"),
      ),
    ).rejects.toThrow("write did not verify");
    expect(store.value(REGISTRY_KIND)).toBe(afterValues[REGISTRY_KIND]);
    expect(store.value(SERVER_KIND)).toBe(beforeValues[SERVER_KIND]);
    expect(store.value(WAL_KIND)).not.toBeNull();

    const secondRestart = createAuthority(store);
    await secondRestart.beforeAccess(
      VAULT_ID,
      createRendererSecureStoreOwner("second-restart"),
    );
    await secondRestart.beforeAccess(
      VAULT_ID,
      createRendererSecureStoreOwner("second-read"),
    );
    expectParticipants(store, afterValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("fails closed and retains the WAL when a participant has an unknown third value", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("renderer-a");
    const authority = createAuthority(store);
    await authority.begin(
      VAULT_ID,
      owner,
      "superseded-transaction",
      initialParticipants(),
    );
    await setParticipant(store, REGISTRY_KIND, "registry-c");

    await expect(
      createAuthority(store).beforeAccess(
        VAULT_ID,
        createRendererSecureStoreOwner("renderer-after-restart"),
      ),
    ).rejects.toThrow("superseded by an unknown value");
    expect(store.value(REGISTRY_KIND)).toBe("registry-c");
    expect(store.value(WAL_KIND)).not.toBeNull();
  });

  it("releases a prepared owner to all-before and a committed owner to all-after", async () => {
    const preparedStore = new MemorySecureStore();
    const preparedOwner = createRendererSecureStoreOwner("prepared-owner");
    const preparedAuthority = createAuthority(preparedStore);
    await prepareAllParticipants(
      preparedAuthority,
      preparedStore,
      preparedOwner,
      "prepared-release",
    );
    await preparedAuthority.releaseOwner(
      VAULT_ID,
      preparedOwner,
      async () => undefined,
    );
    expectParticipants(preparedStore, beforeValues);
    expect(preparedStore.value(WAL_KIND)).toBeNull();

    const committedStore = new MemorySecureStore();
    const committedOwner = createRendererSecureStoreOwner("committed-owner");
    const committedAuthority = createAuthority(committedStore);
    await prepareAllParticipants(
      committedAuthority,
      committedStore,
      committedOwner,
      "committed-release",
    );
    await committedAuthority.decideCommit(
      VAULT_ID,
      committedOwner,
      "committed-release",
      receipts,
      async () => undefined,
    );
    await committedAuthority.releaseOwner(
      VAULT_ID,
      committedOwner,
      async () => undefined,
    );
    expectParticipants(committedStore, afterValues);
    expect(committedStore.value(WAL_KIND)).toBeNull();
  });

  it("invalidates every committed participant on release even when no byte needs roll-forward", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("failed-publish-owner");
    const authority = createAuthority(store);
    await prepareAllParticipants(
      authority,
      store,
      owner,
      "committed-before-receipt-failure",
    );

    await expect(
      authority.decideCommit(
        VAULT_ID,
        owner,
        "committed-before-receipt-failure",
        receipts,
        async () => {
          throw new Error("injected receipt commit failure");
        },
      ),
    ).rejects.toThrow("injected receipt commit failure");
    expectParticipants(store, afterValues);
    expect(store.value(WAL_KIND)).not.toBeNull();

    const retryReceipts = vi.fn(async () => undefined);
    await expect(
      authority.releaseOwner(VAULT_ID, owner, retryReceipts),
    ).resolves.toEqual([REGISTRY_KIND, SERVER_KIND, TOKEN_KIND]);
    expect(retryReceipts).toHaveBeenCalledWith(receipts);
    expectParticipants(store, afterValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("keeps owner release behind an already-authorized participant operation", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("closing-renderer");
    const authority = createAuthority(store);
    await authority.begin(
      VAULT_ID,
      owner,
      "closing-transaction",
      initialParticipants(),
    );
    let startOperation!: () => void;
    const operationStarted = new Promise<void>((resolve) => {
      startOperation = resolve;
    });
    let finishOperation!: () => void;
    const operationGate = new Promise<void>((resolve) => {
      finishOperation = resolve;
    });
    const participantWrite = authority.runAccess(
      VAULT_ID,
      owner,
      "closing-transaction",
      {
        kind: REGISTRY_KIND,
        operation: "set",
        value: afterValues[REGISTRY_KIND],
      },
      async () => {
        startOperation();
        await operationGate;
        await setParticipant(store, REGISTRY_KIND);
        return true;
      },
    );
    await operationStarted;
    let released = false;
    const release = authority
      .releaseOwner(VAULT_ID, owner, async () => undefined)
      .then(() => {
        released = true;
      });
    await Promise.resolve();
    expect(released).toBe(false);

    finishOperation();
    await participantWrite;
    await release;
    expectParticipants(store, beforeValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("rejects a same-owner non-participant and a mismatched participant SET", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("renderer-a");
    const authority = createAuthority(store);
    await authority.begin(
      VAULT_ID,
      owner,
      "participant-bound-transaction",
      initialParticipants(),
    );
    const operation = vi.fn(async () => true);

    await expect(
      authority.runAccess(
        VAULT_ID,
        owner,
        "participant-bound-transaction",
        {
          kind: "session.device_auth" as never,
          operation: "set",
          value: "device-b",
        },
        operation,
      ),
    ).rejects.toThrow("not a participant");
    await expect(
      authority.runAccess(
        VAULT_ID,
        owner,
        "participant-bound-transaction",
        {
          kind: REGISTRY_KIND,
          operation: "set",
          value: "registry-c",
        },
        operation,
      ),
    ).rejects.toThrow("does not match its prepared value");
    expect(operation).not.toHaveBeenCalled();
    expect(store.value("session.device_auth")).toBeNull();
    expect(store.value(REGISTRY_KIND)).toBe(beforeValues[REGISTRY_KIND]);
  });

  it("rejects stale A control after B starts even when the participant bytes are ABA-identical", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const ownerA = createRendererSecureStoreOwner("renderer-a");
    const ownerB = createRendererSecureStoreOwner("renderer-b");
    const identicalParticipants = initialParticipants().map((participant) => ({
      ...participant,
      value: beforeValues[participant.kind],
    }));

    await authority.begin(
      VAULT_ID,
      ownerA,
      "transaction-a",
      identicalParticipants,
    );
    await expect(
      authority.abort(VAULT_ID, ownerA, "transaction-a"),
    ).resolves.toMatchObject({ aborted: true, committed: false });
    // A response-lost abort replays its tombstone, and the same logical id can
    // never be recycled into an ABA-identical transaction.
    await expect(
      authority.abort(VAULT_ID, ownerA, "transaction-a"),
    ).resolves.toMatchObject({ aborted: true, committed: false });
    await expect(
      authority.begin(VAULT_ID, ownerB, "transaction-a", identicalParticipants),
    ).rejects.toThrow("already completed");
    await authority.begin(
      VAULT_ID,
      ownerB,
      "transaction-b",
      identicalParticipants,
    );

    await expect(
      authority.decideCommit(
        VAULT_ID,
        ownerA,
        "transaction-a",
        receipts.slice(0, 2),
        async () => undefined,
      ),
    ).rejects.toThrow("already aborted");
    await expect(
      authority.abort(VAULT_ID, ownerA, "transaction-a"),
    ).resolves.toMatchObject({ aborted: true, committed: false });
    await expect(
      authority.runAccess(VAULT_ID, ownerB, "transaction-b", {
        kind: REGISTRY_KIND,
        operation: "read",
      }),
    ).resolves.toMatchObject({ changedKinds: [] });
    expect(store.value(WAL_KIND)).toContain("transaction-b");
  });

  it("replays a response-lost finish without reopening a completed transaction", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const owner = createRendererSecureStoreOwner("renderer-a");
    await prepareAllParticipants(authority, store, owner, "finish-retry");
    await authority.decideCommit(
      VAULT_ID,
      owner,
      "finish-retry",
      receipts,
      async () => undefined,
    );

    const first = await authority.finishCommit(VAULT_ID, owner, "finish-retry");
    await expect(
      authority.finishCommit(VAULT_ID, owner, "finish-retry"),
    ).resolves.toEqual(first);
    await expect(
      authority.begin(VAULT_ID, owner, "finish-retry", initialParticipants()),
    ).rejects.toThrow("already completed");
    expectParticipants(store, afterValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("revokes an older finished reverse authority when a new overlapping BEGIN starts", async () => {
    const store = new MemorySecureStore();
    const authority = createAuthority(store);
    const ownerA = createRendererSecureStoreOwner("finished-owner-a");
    const ownerB = createRendererSecureStoreOwner("overlapping-owner-b");
    const { epoch } = await authority.begin(
      VAULT_ID,
      ownerA,
      "finished-a",
      initialParticipants(),
    );
    await setParticipant(store, REGISTRY_KIND);
    await setParticipant(store, SERVER_KIND);
    await authority.stage(
      VAULT_ID,
      ownerA,
      "finished-a",
      { kind: TOKEN_KIND, value: afterValues[TOKEN_KIND] },
      epoch,
    );
    await setParticipant(store, TOKEN_KIND);
    await authority.decideCommit(
      VAULT_ID,
      ownerA,
      "finished-a",
      receipts,
      async () => undefined,
      epoch,
      async (kinds) => kinds.map((kind) => ({ kind, revision: 1 })),
    );
    await authority.finishCommit(VAULT_ID, ownerA, "finished-a", epoch);

    const next = await authority.begin(
      VAULT_ID,
      ownerB,
      "overlapping-b",
      initialParticipants(),
    );
    await authority.abort(
      VAULT_ID,
      ownerB,
      "overlapping-b",
      [],
      undefined,
      next.epoch,
    );

    await expect(
      authority.compensateFinishedCommit(
        VAULT_ID,
        ownerA,
        "finished-a",
        epoch,
        receipts.map((receipt) => ({ ...receipt, expectedRevision: 1 })),
        async () => {
          throw new Error("stale receipt callback must not run");
        },
        async () => [],
      ),
    ).rejects.toThrow("compensation expired");
    expect(store.value(WAL_KIND)).toBeNull();
    expectParticipants(store, afterValues);
  });

  it("rejects participant mutation when the durable WAL is missing or corrupted", async () => {
    for (const corruption of ["missing", "corrupted"] as const) {
      const store = new MemorySecureStore();
      const owner = createRendererSecureStoreOwner(`wal-${corruption}`);
      const authority = createAuthority(store);
      const { epoch } = await authority.begin(
        VAULT_ID,
        owner,
        `wal-${corruption}`,
        initialParticipants(),
      );
      if (corruption === "missing") await store.delete(VAULT_ID, WAL_KIND);
      else await store.set(VAULT_ID, WAL_KIND, "corrupted");
      const operation = vi.fn(async () => {
        await setParticipant(store, REGISTRY_KIND);
      });

      await expect(
        authority.runAccess(
          VAULT_ID,
          owner,
          `wal-${corruption}`,
          {
            kind: REGISTRY_KIND,
            operation: "set",
            value: afterValues[REGISTRY_KIND],
          },
          operation,
          undefined,
          epoch,
        ),
      ).rejects.toThrow("WAL authority was lost");
      expect(operation).not.toHaveBeenCalled();
      expect(store.value(REGISTRY_KIND)).toBe(beforeValues[REGISTRY_KIND]);
    }
  });

  it("rejects a participant SET after the global decision", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("post-decision-set");
    const authority = createAuthority(store);
    const { epoch } = await authority.begin(
      VAULT_ID,
      owner,
      "post-decision-set",
      initialParticipants(),
    );
    await setParticipant(store, REGISTRY_KIND);
    await setParticipant(store, SERVER_KIND);
    await authority.decideCommit(
      VAULT_ID,
      owner,
      "post-decision-set",
      receipts.slice(0, 2),
      async () => undefined,
      epoch,
    );
    const operation = vi.fn(async () => true);

    await expect(
      authority.runAccess(
        VAULT_ID,
        owner,
        "post-decision-set",
        {
          kind: REGISTRY_KIND,
          operation: "set",
          value: afterValues[REGISTRY_KIND],
        },
        operation,
        undefined,
        epoch,
      ),
    ).rejects.toThrow("no longer accepts participant SETs");
    expect(operation).not.toHaveBeenCalled();
  });

  it.each(["prepared", "committed"] as const)(
    "rejects terminal participant mutations while the WAL is %s",
    async (phase) => {
      const store = new MemorySecureStore();
      const owner = createRendererSecureStoreOwner(`terminal-${phase}`);
      const authority = createAuthority(store);
      const transactionId = `terminal-${phase}`;
      const { epoch } = await authority.begin(
        VAULT_ID,
        owner,
        transactionId,
        initialParticipants(),
      );
      if (phase === "committed") {
        await setParticipant(store, REGISTRY_KIND);
        await setParticipant(store, SERVER_KIND);
        await authority.decideCommit(
          VAULT_ID,
          owner,
          transactionId,
          receipts.slice(0, 2),
          async () => undefined,
          epoch,
        );
      }
      const mutation = vi.fn(async () => {
        await setParticipant(store, REGISTRY_KIND, "terminal-mutation-c");
      });

      await expect(
        authority.runAccess(
          VAULT_ID,
          owner,
          transactionId,
          { kind: REGISTRY_KIND, operation: "mutation" },
          mutation,
          undefined,
          epoch,
        ),
      ).rejects.toThrow("settled only by the coordinator");
      expect(mutation).not.toHaveBeenCalled();

      if (phase === "committed") {
        await authority.finishCommit(VAULT_ID, owner, transactionId, epoch);
        expect(store.value(REGISTRY_KIND)).toBe(afterValues[REGISTRY_KIND]);
      } else {
        await authority.abort(
          VAULT_ID,
          owner,
          transactionId,
          [],
          undefined,
          epoch,
        );
        expect(store.value(REGISTRY_KIND)).toBe(beforeValues[REGISTRY_KIND]);
      }
    },
  );

  it("keeps owner transaction-id tombstones after bounded replay eviction", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("owner-lifetime-tombstones");
    const authority = new RendererSecureStoreTransactionAuthority(store, {
      completedCapacity: 1,
      createEpoch: () => "stable-test-epoch",
    });
    for (const transactionId of ["old-a", "new-b"]) {
      const { epoch } = await authority.begin(
        VAULT_ID,
        owner,
        transactionId,
        initialParticipants(),
      );
      await authority.abort(
        VAULT_ID,
        owner,
        transactionId,
        [],
        undefined,
        epoch,
      );
    }
    await expect(
      authority.begin(VAULT_ID, owner, "old-a", initialParticipants()),
    ).rejects.toThrow("already completed");
  });

  it("rejects stale epochs on participant and decision capabilities", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("epoch-fence");
    const authority = createAuthority(store);
    const { epoch } = await authority.begin(
      VAULT_ID,
      owner,
      "epoch-fence",
      initialParticipants(),
    );
    const operation = vi.fn(async () => true);

    await expect(
      authority.runAccess(
        VAULT_ID,
        owner,
        "epoch-fence",
        { kind: REGISTRY_KIND, operation: "read" },
        operation,
        undefined,
        `${epoch}-stale`,
      ),
    ).rejects.toThrow("in progress");
    await expect(
      authority.stage(
        VAULT_ID,
        owner,
        "epoch-fence",
        { kind: TOKEN_KIND, value: afterValues[TOKEN_KIND] },
        `${epoch}-stale`,
      ),
    ).rejects.toThrow("no longer active");
    expect(operation).not.toHaveBeenCalled();
  });

  it("invalidates all orphan participants even when recovery rewrites no bytes", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("orphan-visibility");
    const authority = createAuthority(store);
    await prepareAllParticipants(authority, store, owner, "orphan-visibility");
    await authority.decideCommit(
      VAULT_ID,
      owner,
      "orphan-visibility",
      receipts,
      async () => undefined,
    );

    await expect(
      createAuthority(store).beforeAccess(
        VAULT_ID,
        createRendererSecureStoreOwner("surviving-renderer"),
      ),
    ).resolves.toEqual([REGISTRY_KIND, SERVER_KIND, TOKEN_KIND]);
    expectParticipants(store, afterValues);
  });

  it.each([1, 2, 3])(
    "rolls a reverse WAL with %i already-restored participants back to the sealed successor",
    async (restoredCount) => {
      const store = new MemorySecureStore();
      const owner = createRendererSecureStoreOwner(
        `reverse-prepared-${restoredCount}`,
      );
      const authority = createAuthority(store);
      const { epoch } = await authority.begin(
        VAULT_ID,
        owner,
        `reverse-prepared-${restoredCount}`,
        initialParticipants(),
      );
      await setParticipant(store, REGISTRY_KIND);
      await setParticipant(store, SERVER_KIND);
      await authority.stage(
        VAULT_ID,
        owner,
        `reverse-prepared-${restoredCount}`,
        { kind: TOKEN_KIND, value: afterValues[TOKEN_KIND] },
        epoch,
      );
      await setParticipant(store, TOKEN_KIND);
      await authority.decideCommit(
        VAULT_ID,
        owner,
        `reverse-prepared-${restoredCount}`,
        receipts,
        async () => undefined,
        epoch,
      );
      await authority.finishCommit(
        VAULT_ID,
        owner,
        `reverse-prepared-${restoredCount}`,
        epoch,
      );
      const kinds = [REGISTRY_KIND, SERVER_KIND, TOKEN_KIND] as const;
      await expect(
        authority.compensateFinishedCommit(
          VAULT_ID,
          owner,
          `reverse-prepared-${restoredCount}`,
          epoch,
          receipts.map((receipt) => ({ ...receipt, expectedRevision: 1 })),
          async () => {
            for (const kind of kinds.slice(0, restoredCount)) {
              await setParticipant(store, kind, beforeValues[kind]);
            }
            throw new Error("injected reverse crash");
          },
          async () => [],
        ),
      ).rejects.toThrow("injected reverse crash");

      await createAuthority(store).beforeAccess(
        VAULT_ID,
        createRendererSecureStoreOwner("after-reverse-crash"),
      );
      expectParticipants(store, afterValues);
      expect(store.value(WAL_KIND)).toBeNull();
    },
  );

  it("rolls a committed reverse WAL forward after publication response loss", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("reverse-committed-crash");
    const authority = createAuthority(store);
    const { epoch } = await authority.begin(
      VAULT_ID,
      owner,
      "reverse-committed-crash",
      initialParticipants(),
    );
    await setParticipant(store, REGISTRY_KIND);
    await setParticipant(store, SERVER_KIND);
    await authority.stage(
      VAULT_ID,
      owner,
      "reverse-committed-crash",
      { kind: TOKEN_KIND, value: afterValues[TOKEN_KIND] },
      epoch,
    );
    await setParticipant(store, TOKEN_KIND);
    await authority.decideCommit(
      VAULT_ID,
      owner,
      "reverse-committed-crash",
      receipts,
      async () => undefined,
      epoch,
    );
    await authority.finishCommit(
      VAULT_ID,
      owner,
      "reverse-committed-crash",
      epoch,
    );

    await expect(
      authority.compensateFinishedCommit(
        VAULT_ID,
        owner,
        "reverse-committed-crash",
        epoch,
        receipts.map((receipt) => ({ ...receipt, expectedRevision: 1 })),
        async () => {
          for (const kind of [
            REGISTRY_KIND,
            SERVER_KIND,
            TOKEN_KIND,
          ] as const) {
            await setParticipant(store, kind, beforeValues[kind]);
          }
        },
        async () => {
          throw new Error("lost collective publication response");
        },
      ),
    ).rejects.toThrow("lost collective publication response");
    expect(store.value(WAL_KIND)).not.toBeNull();

    await createAuthority(store).beforeAccess(
      VAULT_ID,
      createRendererSecureStoreOwner("after-reverse-decision-crash"),
    );
    expectParticipants(store, beforeValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("replays compensated revisions through owner and epoch bound status", async () => {
    const store = new MemorySecureStore();
    const owner = createRendererSecureStoreOwner("compensated-status");
    const authority = createAuthority(store);
    const { epoch } = await authority.begin(
      VAULT_ID,
      owner,
      "compensated-status",
      initialParticipants(),
    );
    await setParticipant(store, REGISTRY_KIND);
    await setParticipant(store, SERVER_KIND);
    await authority.stage(
      VAULT_ID,
      owner,
      "compensated-status",
      { kind: TOKEN_KIND, value: afterValues[TOKEN_KIND] },
      epoch,
    );
    await setParticipant(store, TOKEN_KIND);
    await authority.decideCommit(
      VAULT_ID,
      owner,
      "compensated-status",
      receipts,
      async () => undefined,
      epoch,
      async (kinds) => kinds.map((kind) => ({ kind, revision: 1 })),
    );
    await authority.finishCommit(VAULT_ID, owner, "compensated-status", epoch);
    const revisions = receipts.map(({ kind }) => ({ kind, revision: 2 }));
    await expect(
      authority.compensateFinishedCommit(
        VAULT_ID,
        owner,
        "compensated-status",
        epoch,
        receipts.map((receipt) => ({ ...receipt, expectedRevision: 1 })),
        async () => {
          for (const kind of [
            REGISTRY_KIND,
            SERVER_KIND,
            TOKEN_KIND,
          ] as const) {
            await setParticipant(store, kind, beforeValues[kind]);
          }
        },
        async () => revisions,
      ),
    ).resolves.toEqual({ compensated: true, revisions });

    await expect(
      authority.status(owner, "compensated-status", epoch),
    ).resolves.toEqual({ epoch, revisions, status: "compensated" });
    expectParticipants(store, beforeValues);
    expect(store.value(WAL_KIND)).toBeNull();
  });

  it("fails closed and retains a corrupted encrypted-slot WAL", async () => {
    const store = new MemorySecureStore();
    await store.set(VAULT_ID, WAL_KIND, "corrupted-envelope");

    await expect(
      createAuthority(store).beforeAccess(
        VAULT_ID,
        createRendererSecureStoreOwner("renderer-after-restart"),
      ),
    ).rejects.toThrow("WAL is malformed");
    expect(store.value(WAL_KIND)).toBe("corrupted-envelope");
  });
});
