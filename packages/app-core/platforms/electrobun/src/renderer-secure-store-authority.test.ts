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
    this.value = value;
    return { ok: true };
  }

  async delete(
    _vaultId: string,
    _kind: SecureStoreSecretKind,
  ): Promise<SecureStoreDeleteResult> {
    this.operations.push("delete");
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

describe("RendererSecureStoreAuthority", () => {
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
});
