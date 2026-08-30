/**
 * Multi-agent profile registry.
 *
 * Stores a catalogue of known agent connections (local, cloud, remote) in
 * localStorage so users can manage and switch between multiple agents.
 */

import { logger } from "@elizaos/logger";
import {
  getStorageValue,
  removeStorageValueIfCurrent,
  type StorageWriteCompensation,
  type StorageWriteValidationOptions,
  setStorageValue,
  setStorageValueIfCurrent,
  setStorageValueWithCompensation,
} from "../bridge/storage-bridge";
import { shellLocalStorage } from "../surface-realm-channel";
import { isManagedCloudSharedAgentBase } from "../utils/cloud-agent-base";
import type { AgentProfile, AgentProfileRegistry } from "./agent-profile-types";
import {
  hasBuildPinnedActiveServerTarget,
  isPersistedActiveServerAllowedByBuildTarget,
  type PersistedActiveServer,
  savePersistedActiveServer,
} from "./persistence";

export type { AgentProfile, AgentProfileRegistry } from "./agent-profile-types";

export interface AgentProfileConnectionPersistenceOptions
  extends StorageWriteValidationOptions {
  /** Final awaited authority step run while both record compensators are live. */
  finalize?: () => Promise<boolean>;
  /** Roll back a partially/finally published authority before record rollback. */
  compensateFinalization?: () => Promise<void>;
  /** Capture the exact composite compensator after the transaction commits. */
  captureCompensation?: (compensate: () => Promise<void>) => void;
}

export interface AgentProfileSelectionPersistenceOptions
  extends Omit<AgentProfileConnectionPersistenceOptions, "finalize"> {
  createServer: (profile: AgentProfile) => PersistedActiveServer | null;
  finalize?: (
    profile: AgentProfile,
    server: PersistedActiveServer,
  ) => Promise<boolean>;
}

export type AgentProfileSelectionPersistenceResult =
  | { ok: true; profile: AgentProfile }
  | {
      ok: false;
      reason: "not-found" | "invalid-profile" | "persistence-failed";
    };

export interface AgentProfileRemovalPersistenceOptions {
  createServer: (profile: AgentProfile) => PersistedActiveServer | null;
  finalize: (
    profile: AgentProfile | null,
    server: PersistedActiveServer | null,
  ) => Promise<boolean>;
}

export type AgentProfileRemovalPersistenceResult =
  | { ok: true; activeProfile: AgentProfile | null }
  | {
      ok: false;
      reason:
        | "not-found"
        | "invalid-fallback"
        | "persistence-failed"
        | "build-pinned";
    };

export interface CloudRuntimeAuthorityClearOptions
  extends StorageWriteValidationOptions {
  scope: "shared" | "managed";
  /** Publish the terminal live-client state while the runtime lock is held. */
  finalize?: (server: PersistedActiveServer) => void | Promise<void>;
}

export type CloudRuntimeAuthorityClearResult =
  | {
      ok: true;
      clearedActiveServer: boolean;
      registryMutation: "missing" | "unchanged" | "applied";
    }
  | {
      ok: false;
      reason: "not-target" | "authority-lost" | "invalid-state" | "conflict";
    };

function samePersistedActiveServer(
  left: PersistedActiveServer,
  right: PersistedActiveServer,
): boolean {
  return (
    left.id === right.id &&
    left.kind === right.kind &&
    left.label === right.label &&
    left.apiBase === right.apiBase &&
    left.accessToken === right.accessToken &&
    left.cloudRuntimeAgentId === right.cloudRuntimeAgentId &&
    left.cloudRuntime === right.cloudRuntime
  );
}

/* ── Helpers ─────────────────────────────────────────────────────────── */

const STORAGE_KEY = "elizaos:agent-profiles";
const ACTIVE_SERVER_KEY = "elizaos:active-server";
const RUNTIME_CONNECTION_PERSISTENCE_LOCK =
  "elizaos:runtime-connection-persistence";
let runtimeConnectionPersistenceTail: Promise<void> = Promise.resolve();

class RuntimeConnectionPersistenceBoundaryError extends Error {
  readonly cause: unknown;

  constructor(cause: unknown) {
    super("The origin-wide runtime persistence lock is unavailable");
    this.name = "RuntimeConnectionPersistenceBoundaryError";
    this.cause = cause;
  }
}

async function runWithOriginRuntimeConnectionLock<T>(
  operation: () => Promise<T>,
): Promise<T> {
  let lockManager: LockManager | undefined;
  try {
    lockManager =
      typeof navigator === "undefined" ? undefined : navigator.locks;
  } catch (cause) {
    throw new RuntimeConnectionPersistenceBoundaryError(cause);
  }
  if (!lockManager) return operation();

  let entered = false;
  try {
    return await lockManager.request(
      RUNTIME_CONNECTION_PERSISTENCE_LOCK,
      { mode: "exclusive" },
      async () => {
        entered = true;
        return operation();
      },
    );
  } catch (cause) {
    // Callback failures are transaction failures, not lock-acquisition
    // failures. Only a boundary that was never entered is translated into the
    // fail-closed sentinel handled by public persistence APIs.
    if (entered) throw cause;
    throw new RuntimeConnectionPersistenceBoundaryError(cause);
  }
}

/**
 * Serialize every registry + active-server transaction in this realm, then
 * extend that exclusion origin-wide through Web Locks when the runtime offers
 * them. A rejected origin lock never falls back to an unsafe unlocked write.
 */
function serializeRuntimeConnectionPersistence<T>(
  operation: () => Promise<T>,
): Promise<T> {
  const result = runtimeConnectionPersistenceTail
    .catch(() => undefined)
    .then(() => runWithOriginRuntimeConnectionLock(operation));
  runtimeConnectionPersistenceTail = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

function warnRuntimePersistenceBoundaryUnavailable(cause: unknown): void {
  logger.warn(
    `[agent-profiles] refused an unlocked runtime persistence transaction: ${describePersistenceError(cause)}`,
  );
}

function tryLocalStorage<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    // error-policy:J3 inaccessible or malformed browser storage is an invalid
    // persisted state, so readers return their explicit bootstrap fallback.
    return fallback;
  }
}

function describePersistenceError(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

function generateId(): string {
  return crypto.randomUUID();
}

function emptyRegistry(): AgentProfileRegistry {
  return { version: 1, activeProfileId: null, profiles: [] };
}

/**
 * Attempt to migrate a single-agent `PersistedActiveServer` entry into a
 * profile registry.  Returns null if no prior server is found.
 */
function migrateFromPersistedActiveServer(
  raw: string | null,
): AgentProfileRegistry | null {
  if (!raw) return null;

  let parsed: PersistedActiveServer;
  try {
    parsed = JSON.parse(raw) as PersistedActiveServer;
  } catch {
    // error-policy:J3 corrupt persisted server entry — migration starts from
    // an empty registry rather than wedging profile bootstrap.
    return null;
  }

  if (!parsed.kind || !parsed.id || !parsed.label) return null;

  const profile: AgentProfile = {
    // The migration is intentionally pure. A deterministic id/timestamp keeps
    // repeated sync reads stable until the next awaited durable mutation
    // persists the final registry under the transaction lock.
    id: parsed.id,
    label: parsed.label,
    kind: parsed.kind,
    ...(parsed.kind === "cloud" && parsed.id.startsWith("cloud:")
      ? { cloudAgentId: parsed.id.slice("cloud:".length) }
      : {}),
    ...(parsed.kind === "cloud" && parsed.cloudRuntimeAgentId
      ? { cloudRuntimeAgentId: parsed.cloudRuntimeAgentId }
      : {}),
    ...(parsed.kind === "cloud" && parsed.cloudRuntime
      ? { cloudRuntime: parsed.cloudRuntime }
      : {}),
    apiBase: parsed.apiBase,
    accessToken: parsed.accessToken,
    createdAt: "1970-01-01T00:00:00.000Z",
  };

  const registry: AgentProfileRegistry = {
    version: 1,
    activeProfileId: profile.id,
    profiles: [profile],
  };

  return registry;
}

function parseAgentProfileRegistry(
  raw: string | null,
): AgentProfileRegistry | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as AgentProfileRegistry;
    return parsed?.version === 1 && Array.isArray(parsed.profiles)
      ? parsed
      : null;
  } catch {
    return null;
  }
}

function parsePersistedActiveServer(
  raw: string | null,
): PersistedActiveServer | null | undefined {
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as PersistedActiveServer;
    return parsed?.id && parsed.kind && parsed.label ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function isManagedCloudServer(server: PersistedActiveServer): boolean {
  return (
    server.kind === "cloud" || isManagedCloudSharedAgentBase(server.apiBase)
  );
}

function transformCloudRuntimeRegistry(
  registry: AgentProfileRegistry,
  scope: CloudRuntimeAuthorityClearOptions["scope"],
): AgentProfileRegistry | null {
  let changed = false;
  const profiles = registry.profiles.flatMap((profile) => {
    const remove =
      scope === "shared"
        ? isManagedCloudSharedAgentBase(profile.apiBase)
        : profile.kind === "cloud" ||
          isManagedCloudSharedAgentBase(profile.apiBase);
    if (remove) {
      changed = true;
      return [];
    }
    if (scope !== "shared" || !profile.accessToken) return [profile];
    changed = true;
    const { accessToken: _accessToken, ...scrubbed } = profile;
    return [scrubbed];
  });
  if (!changed) return null;
  const activeStillPresent = profiles.some(
    (profile) => profile.id === registry.activeProfileId,
  );
  return {
    ...registry,
    activeProfileId: activeStillPresent ? registry.activeProfileId : null,
    profiles,
  };
}

/** Read both migration inputs from the host authority while holding the lock. */
async function loadAgentProfileRegistryDurably(): Promise<AgentProfileRegistry> {
  const stored = parseAgentProfileRegistry(await getStorageValue(STORAGE_KEY));
  if (stored) return stored;
  return (
    migrateFromPersistedActiveServer(
      await getStorageValue(ACTIVE_SERVER_KEY),
    ) ?? emptyRegistry()
  );
}

/* ── Public API ──────────────────────────────────────────────────────── */

export function loadAgentProfileRegistry(): AgentProfileRegistry {
  return tryLocalStorage(() => {
    const stored = parseAgentProfileRegistry(localStorage.getItem(STORAGE_KEY));
    if (stored) return stored;
    // No registry yet — try migrating from legacy single-server entry.
    return (
      migrateFromPersistedActiveServer(
        localStorage.getItem(ACTIVE_SERVER_KEY),
      ) ?? emptyRegistry()
    );
  }, emptyRegistry());
}

export function saveAgentProfileRegistry(
  registry: AgentProfileRegistry,
): boolean {
  try {
    shellLocalStorage.setItem(STORAGE_KEY, JSON.stringify(registry));
    return true;
  } catch (cause) {
    // error-policy:J1 localStorage boundary returns a visible failure signal to
    // connection-switch callers instead of fabricating a successful write.
    logger.warn(
      `[agent-profiles] failed to save registry: ${describePersistenceError(cause)}`,
    );
    return false;
  }
}

/** Await the host-authoritative registry write before reporting success. */
export async function saveAgentProfileRegistryDurably(
  registry: AgentProfileRegistry,
  options: StorageWriteValidationOptions = {},
): Promise<boolean> {
  try {
    return (
      (await setStorageValueWithCompensation(
        STORAGE_KEY,
        JSON.stringify(registry),
        options,
      )) !== null
    );
  } catch (cause) {
    // error-policy:J1 security-critical connection mutations treat a rejected
    // protected write as a transaction failure and publish no live switch.
    logger.warn(
      `[agent-profiles] failed to durably save registry: ${describePersistenceError(cause)}`,
    );
    return false;
  }
}

/**
 * Resolve a free-text switch query (from the AGENT_SWITCH action / `shell:
 * switch-agent` WS event) to a saved profile: exact id, then exact label
 * (case-insensitive), then a unique label substring match, then a unique
 * kind match ("cloud"/"local"/"remote"). Returns null when nothing matches or
 * a substring/kind is ambiguous — the caller reports "not-found" rather than
 * switching to the wrong agent.
 */
export function resolveAgentProfileByQuery(
  query: string,
  registry: AgentProfileRegistry = loadAgentProfileRegistry(),
): AgentProfile | null {
  const q = query.trim().toLowerCase();
  if (!q) return null;
  const profiles = registry.profiles;

  const byId = profiles.find((p) => p.id.toLowerCase() === q);
  if (byId) return byId;

  const byLabel = profiles.find((p) => p.label.trim().toLowerCase() === q);
  if (byLabel) return byLabel;

  const bySubstring = profiles.filter((p) =>
    p.label.trim().toLowerCase().includes(q),
  );
  if (bySubstring.length === 1) return bySubstring[0];

  if (q === "local" || q === "cloud" || q === "remote") {
    const byKind = profiles.filter((p) => p.kind === q);
    if (byKind.length === 1) return byKind[0];
  }

  return null;
}

export function getActiveProfile(): AgentProfile | null {
  const registry = loadAgentProfileRegistry();
  if (!registry.activeProfileId) return null;
  return (
    registry.profiles.find((p) => p.id === registry.activeProfileId) ?? null
  );
}

export function setActiveProfileId(id: string): boolean {
  const registry = loadAgentProfileRegistry();
  if (!registry.profiles.some((p) => p.id === id)) return false;
  registry.activeProfileId = id;
  return saveAgentProfileRegistry(registry);
}

/**
 * Persist both records that define a runtime selection before the live client
 * moves. The profile registry is written first because the active-server record
 * is the boot authority; if that second write fails, the unchanged server still
 * controls reload and the registry rollback keeps the runtime picker aligned
 * whenever storage accepts the compensating write.
 */
export function persistAgentProfileSelection(
  profileId: string,
  server: PersistedActiveServer,
): boolean {
  const registry = loadAgentProfileRegistry();
  if (!registry.profiles.some((profile) => profile.id === profileId)) {
    return false;
  }

  const nextRegistry: AgentProfileRegistry = {
    ...registry,
    activeProfileId: profileId,
  };
  if (!saveAgentProfileRegistry(nextRegistry)) return false;
  if (savePersistedActiveServer(server)) return true;

  if (!saveAgentProfileRegistry(registry)) {
    logger.error(
      "[agent-profiles] failed to roll back active profile after active-server persistence failed",
    );
  }
  return false;
}

/**
 * Await both records that define a runtime selection. If the boot-authority
 * write fails after the registry committed, restore the exact registry
 * predecessor before returning false. This is serialized by each caller's
 * awaited control flow; cross-renderer ordering remains host-revision fenced.
 */
export async function persistAgentProfileSelectionDurably(
  profileId: string,
  options: AgentProfileSelectionPersistenceOptions,
): Promise<AgentProfileSelectionPersistenceResult> {
  try {
    return await serializeRuntimeConnectionPersistence(async () => {
      const registry = await loadAgentProfileRegistryDurably();
      const profile = registry.profiles.find(
        (candidate) => candidate.id === profileId,
      );
      if (!profile) return { ok: false, reason: "not-found" };
      const server = options.createServer(profile);
      if (!server) return { ok: false, reason: "invalid-profile" };
      const nextRegistry: AgentProfileRegistry = {
        ...registry,
        activeProfileId: profileId,
      };
      const finalize = options.finalize;
      const transactionOptions: AgentProfileConnectionPersistenceOptions = {
        ...(options.validate ? { validate: options.validate } : {}),
        ...(options.compensateOnValidationFailure !== undefined
          ? {
              compensateOnValidationFailure:
                options.compensateOnValidationFailure,
            }
          : {}),
        ...(options.compensateFinalization
          ? { compensateFinalization: options.compensateFinalization }
          : {}),
        ...(options.captureCompensation
          ? { captureCompensation: options.captureCompensation }
          : {}),
        ...(finalize ? { finalize: () => finalize(profile, server) } : {}),
      };
      const persisted = await persistRegistryAndServerDurably(
        nextRegistry,
        server,
        transactionOptions,
      );
      return persisted
        ? { ok: true, profile }
        : { ok: false, reason: "persistence-failed" };
    });
  } catch (cause) {
    if (cause instanceof RuntimeConnectionPersistenceBoundaryError) {
      warnRuntimePersistenceBoundaryUnavailable(cause.cause);
      return { ok: false, reason: "persistence-failed" };
    }
    throw cause;
  }
}

async function persistRegistryAndServerDurably(
  registry: AgentProfileRegistry,
  server: PersistedActiveServer,
  options: AgentProfileConnectionPersistenceOptions,
): Promise<boolean> {
  if (options.validate?.() === false) return false;
  if (!isPersistedActiveServerAllowedByBuildTarget(server)) {
    logger.warn(
      "[agent-profiles] rejected registry transaction outside the build-pinned remote target",
    );
    return false;
  }
  let registryWrite: Awaited<
    ReturnType<typeof setStorageValueWithCompensation>
  > = null;
  try {
    registryWrite = await setStorageValueWithCompensation(
      STORAGE_KEY,
      JSON.stringify(registry),
      options,
    );
  } catch (cause) {
    logger.warn(
      `[agent-profiles] failed to durably save registry transaction: ${describePersistenceError(cause)}`,
    );
    return false;
  }
  if (!registryWrite) return false;

  let serverWrite: Awaited<ReturnType<typeof setStorageValueWithCompensation>> =
    null;
  try {
    serverWrite = await setStorageValueWithCompensation(
      ACTIVE_SERVER_KEY,
      JSON.stringify(server),
      options,
    );
  } catch (cause) {
    await compensateStorageWrites(registryWrite);
    logger.warn(
      `[agent-profiles] failed to durably save active server: ${describePersistenceError(cause)}`,
    );
    return false;
  }
  if (!serverWrite) {
    await compensateStorageWrites(registryWrite);
    return false;
  }
  if (options.validate?.() === false) {
    await compensateStorageWrites(serverWrite, registryWrite);
    return false;
  }
  let transactionCompensation: Promise<void> | null = null;
  const compensateTransaction = (): Promise<void> => {
    transactionCompensation ??= compensateConnectionWrites(
      options.compensateFinalization,
      serverWrite,
      registryWrite,
    );
    return transactionCompensation;
  };
  if (options.finalize) {
    let finalized: boolean;
    try {
      finalized = await options.finalize();
    } catch (cause) {
      try {
        await compensateTransaction();
      } catch (rollbackError) {
        throw new AggregateError(
          [cause, rollbackError],
          "Connection finalization and protected-record compensation failed",
        );
      }
      throw cause;
    }
    if (!finalized || options.validate?.() === false) {
      await compensateTransaction();
      return false;
    }
  }
  options.captureCompensation?.(compensateTransaction);
  return true;
}

async function compensateStorageWrites(
  ...writes: StorageWriteCompensation[]
): Promise<void> {
  const outcomes = await Promise.allSettled(
    writes.map((write) => write.compensate()),
  );
  const failures = outcomes.flatMap((outcome) =>
    outcome.status === "rejected"
      ? [outcome.reason]
      : outcome.value
        ? []
        : [new Error("A protected connection rollback was superseded")],
  );
  if (failures.length > 0) {
    throw new AggregateError(
      failures,
      "One or more protected connection records could not be compensated",
    );
  }
}

async function compensateConnectionWrites(
  compensateFinalization: (() => Promise<void>) | undefined,
  ...writes: StorageWriteCompensation[]
): Promise<void> {
  const failures: unknown[] = [];
  if (compensateFinalization) {
    try {
      // Durable token authority must settle before client/boot publication is
      // changed; the finalizer owns that dependency ordering internally.
      await compensateFinalization();
    } catch (error) {
      failures.push(error);
    }
  }
  const outcomes = await Promise.allSettled(
    writes.map((write) => write.compensate()),
  );
  failures.push(
    ...outcomes.flatMap((outcome) =>
      outcome.status === "rejected"
        ? [outcome.reason]
        : outcome.value
          ? []
          : [new Error("A protected connection rollback was superseded")],
    ),
  );
  if (failures.length > 0) {
    throw new AggregateError(
      failures,
      "Connection finalization and protected-record compensation failed",
    );
  }
}

export function addAgentProfile(
  profile: Omit<AgentProfile, "id" | "createdAt">,
  options: { activate?: boolean; id?: string } = {},
): AgentProfile {
  const registry = loadAgentProfileRegistry();
  const full: AgentProfile = {
    ...profile,
    id: options.id ?? generateId(),
    createdAt: new Date().toISOString(),
  };
  registry.profiles.push(full);
  if (options.activate !== false) registry.activeProfileId = full.id;
  saveAgentProfileRegistry(registry);
  return full;
}

/** Add a profile only after its protected host write has committed. */
export async function addAgentProfileDurably(
  profile: Omit<AgentProfile, "id" | "createdAt">,
  options: { activate?: boolean; id?: string } = {},
): Promise<AgentProfile | null> {
  try {
    return await serializeRuntimeConnectionPersistence(async () => {
      const registry = await loadAgentProfileRegistryDurably();
      const full: AgentProfile = {
        ...profile,
        id: options.id ?? generateId(),
        createdAt: new Date().toISOString(),
      };
      const nextRegistry: AgentProfileRegistry = {
        ...registry,
        profiles: [...registry.profiles, full],
        activeProfileId:
          options.activate === false ? registry.activeProfileId : full.id,
      };
      return (await saveAgentProfileRegistryDurably(nextRegistry))
        ? full
        : null;
    });
  } catch (cause) {
    if (cause instanceof RuntimeConnectionPersistenceBoundaryError) {
      warnRuntimePersistenceBoundaryUnavailable(cause.cause);
      return null;
    }
    throw cause;
  }
}

/** Trailing-slash-insensitive apiBase compare (both sides may be normalized differently). */
function sameApiBase(a: string | undefined, b: string | undefined): boolean {
  const norm = (v: string | undefined) => (v ?? "").replace(/\/+$/, "");
  return norm(a) === norm(b);
}

/**
 * Explicit Cloud owner ids outrank transport addresses: one managed adapter
 * URL must never collapse two owners into a single credential-bearing row.
 * An older unbound row may match an incoming bound profile so the
 * authoritative upsert enriches it; a bound row never accepts unbound input.
 */
function sameProfileIdentity(
  stored: AgentProfile,
  incoming: Omit<AgentProfile, "id" | "createdAt">,
): boolean {
  if (stored.kind !== incoming.kind) return false;
  if (stored.kind === "cloud" && incoming.kind === "cloud") {
    if (stored.cloudAgentId && incoming.cloudAgentId) {
      return stored.cloudAgentId === incoming.cloudAgentId;
    }
    if (stored.cloudAgentId && !incoming.cloudAgentId) return false;
  }
  return sameApiBase(stored.apiBase, incoming.apiBase);
}

function upsertAgentProfileRegistry(
  registry: AgentProfileRegistry,
  profile: Omit<AgentProfile, "id" | "createdAt">,
): { profile: AgentProfile; registry: AgentProfileRegistry } {
  const nextRegistry: AgentProfileRegistry = {
    ...registry,
    profiles: [...registry.profiles],
  };
  const existingIdx = nextRegistry.profiles.findIndex((stored) =>
    sameProfileIdentity(stored, profile),
  );
  if (existingIdx === -1) {
    const full: AgentProfile = {
      ...profile,
      id: generateId(),
      createdAt: new Date().toISOString(),
    };
    nextRegistry.profiles.push(full);
    nextRegistry.activeProfileId = full.id;
    return { profile: full, registry: nextRegistry };
  }
  const current = nextRegistry.profiles[existingIdx];
  const merged: AgentProfile = {
    ...current,
    label: profile.label || current.label,
    ...(profile.cloudAgentId ? { cloudAgentId: profile.cloudAgentId } : {}),
    ...(profile.cloudRuntimeAgentId
      ? { cloudRuntimeAgentId: profile.cloudRuntimeAgentId }
      : {}),
    ...(profile.cloudRuntime ? { cloudRuntime: profile.cloudRuntime } : {}),
    ...(profile.apiBase !== undefined ? { apiBase: profile.apiBase } : {}),
    // A fresh token supersedes a stale one; an absent token leaves the prior in
    // place (a re-activate that carries no new token must not blank it out).
    ...(profile.accessToken ? { accessToken: profile.accessToken } : {}),
  };
  nextRegistry.profiles[existingIdx] = merged;
  nextRegistry.activeProfileId = merged.id;
  return { profile: merged, registry: nextRegistry };
}

/**
 * Idempotently record + activate a connection in the profile registry so every
 * runtime-switch surface ("My Runtimes", Settings) stays truthful. Bound Cloud
 * profiles match by owner; other profiles retain the kind/base match so an
 * authoritative Cloud reconnect can enrich an older unbound row. Matching
 * profiles are re-activated and refreshed; otherwise a new profile is added.
 */
export function upsertAndActivateAgentProfile(
  profile: Omit<AgentProfile, "id" | "createdAt">,
): AgentProfile {
  const registry = loadAgentProfileRegistry();
  const upserted = upsertAgentProfileRegistry(registry, profile);
  saveAgentProfileRegistry(upserted.registry);
  return upserted.profile;
}

/** Persist an upserted profile without publishing an optimistic cache entry. */
export async function upsertAndActivateAgentProfileDurably(
  profile: Omit<AgentProfile, "id" | "createdAt">,
): Promise<AgentProfile | null> {
  try {
    return await serializeRuntimeConnectionPersistence(async () => {
      const registry = await loadAgentProfileRegistryDurably();
      const upserted = upsertAgentProfileRegistry(registry, profile);
      return (await saveAgentProfileRegistryDurably(upserted.registry))
        ? upserted.profile
        : null;
    });
  } catch (cause) {
    if (cause instanceof RuntimeConnectionPersistenceBoundaryError) {
      warnRuntimePersistenceBoundaryUnavailable(cause.cause);
      return null;
    }
    throw cause;
  }
}

/**
 * Persist an upserted profile and its boot-authoritative active server as one
 * fail-closed renderer transaction. The previous registry is restored if the
 * second durable write rejects, and callers receive null so they cannot switch
 * or publish credentials.
 */
export async function persistAgentProfileConnectionDurably(
  profile: Omit<AgentProfile, "id" | "createdAt">,
  server: PersistedActiveServer,
  options: AgentProfileConnectionPersistenceOptions = {},
): Promise<AgentProfile | null> {
  if (options.validate?.() === false) return null;
  try {
    return await serializeRuntimeConnectionPersistence(async () => {
      // Re-read and upsert only after the transaction owns the cross-key
      // boundary. A queued B connection must include A's committed registry
      // row instead of publishing a stale pre-lock snapshot over it.
      const registry = await loadAgentProfileRegistryDurably();
      const upserted = upsertAgentProfileRegistry(registry, profile);
      return (await persistRegistryAndServerDurably(
        upserted.registry,
        server,
        options,
      ))
        ? upserted.profile
        : null;
    });
  } catch (cause) {
    if (cause instanceof RuntimeConnectionPersistenceBoundaryError) {
      warnRuntimePersistenceBoundaryUnavailable(cause.cause);
      return null;
    }
    throw cause;
  }
}

/** Preserve a cloud agent's platform identity when a profile becomes active. */
export function activeServerIdForAgentProfile(profile: AgentProfile): string {
  return profile.kind === "cloud" && profile.cloudAgentId
    ? `cloud:${profile.cloudAgentId}`
    : profile.id;
}

/** Remove every profile owned by the ending shared Cloud account session. */
export function removeManagedSharedCloudAgentProfiles(): void {
  const registry = loadAgentProfileRegistry();
  const profiles = registry.profiles.filter(
    (profile) => !isManagedCloudSharedAgentBase(profile.apiBase),
  );
  if (profiles.length === registry.profiles.length) return;
  const activeStillPresent = profiles.some(
    (profile) => profile.id === registry.activeProfileId,
  );
  saveAgentProfileRegistry({
    version: 1,
    activeProfileId: activeStillPresent ? registry.activeProfileId : null,
    profiles,
  });
}

/**
 * Clear account-scoped Cloud runtime records from one pair of host-authority
 * snapshots. Registry mutation, exact active-server deletion, and live-client
 * publication all remain inside the runtime Web Lock, so a queued login B can
 * only publish after terminal account A has fully settled.
 */
export async function clearCloudRuntimeAuthorityDurably(
  options: CloudRuntimeAuthorityClearOptions,
): Promise<CloudRuntimeAuthorityClearResult> {
  if (options.validate?.() === false) {
    return { ok: false, reason: "authority-lost" };
  }
  try {
    return await serializeRuntimeConnectionPersistence(async () => {
      if (options.validate?.() === false) {
        return { ok: false, reason: "authority-lost" };
      }

      const activeServerRaw = await getStorageValue(ACTIVE_SERVER_KEY);
      const activeServer = parsePersistedActiveServer(activeServerRaw);
      if (activeServer === undefined) {
        return { ok: false, reason: "invalid-state" };
      }
      const activeServerMatches =
        activeServer !== null &&
        (options.scope === "shared"
          ? isManagedCloudSharedAgentBase(activeServer.apiBase)
          : isManagedCloudServer(activeServer));
      if (options.scope === "shared" && !activeServerMatches) {
        return { ok: false, reason: "not-target" };
      }

      const registryRaw = await getStorageValue(STORAGE_KEY);
      const registry = parseAgentProfileRegistry(registryRaw);
      if (registryRaw !== null && !registry) {
        return { ok: false, reason: "invalid-state" };
      }
      const nextRegistry = registry
        ? transformCloudRuntimeRegistry(registry, options.scope)
        : null;
      let registryMutation: Extract<
        CloudRuntimeAuthorityClearResult,
        { ok: true }
      >["registryMutation"] = registryRaw === null ? "missing" : "unchanged";
      if (registryRaw !== null && nextRegistry) {
        const applied = await setStorageValueIfCurrent(
          STORAGE_KEY,
          registryRaw,
          JSON.stringify(nextRegistry),
          { ...options, compensateOnValidationFailure: false },
        );
        if (!applied) return { ok: false, reason: "conflict" };
        registryMutation = "applied";
      }

      if (options.validate?.() === false) {
        return { ok: false, reason: "authority-lost" };
      }
      if (activeServerMatches && activeServerRaw !== null) {
        const cleared = await removeStorageValueIfCurrent(
          ACTIVE_SERVER_KEY,
          activeServerRaw,
          options,
        );
        if (!cleared) return { ok: false, reason: "conflict" };
      }
      if (options.validate?.() === false) {
        return { ok: false, reason: "authority-lost" };
      }

      if (activeServerMatches && activeServer && options.finalize) {
        await options.finalize(activeServer);
      }
      return {
        ok: true,
        clearedActiveServer: activeServerMatches,
        registryMutation,
      };
    });
  } catch (cause) {
    if (cause instanceof RuntimeConnectionPersistenceBoundaryError) {
      warnRuntimePersistenceBoundaryUnavailable(cause.cause);
      return { ok: false, reason: "conflict" };
    }
    throw cause;
  }
}

/**
 * Removes managed Cloud profiles only after the protected native rewrite has
 * committed, so account sign-out cannot resolve over stale profile authority.
 */
export async function removeManagedCloudAgentProfilesDurably(): Promise<void> {
  await serializeRuntimeConnectionPersistence(async () => {
    const registry = await loadAgentProfileRegistryDurably();
    const profiles = registry.profiles.filter(
      (profile) =>
        profile.kind !== "cloud" &&
        !isManagedCloudSharedAgentBase(profile.apiBase),
    );
    if (profiles.length === registry.profiles.length) return;
    const activeStillPresent = profiles.some(
      (profile) => profile.id === registry.activeProfileId,
    );
    await setStorageValue(
      STORAGE_KEY,
      JSON.stringify({
        version: 1,
        activeProfileId: activeStillPresent ? registry.activeProfileId : null,
        profiles,
      } satisfies AgentProfileRegistry),
    );
  });
}

/** Remove only shared, account-owned Cloud rows; keep Dedicated/self-hosted rows. */
export async function removeManagedSharedCloudAgentProfilesDurably(
  options: StorageWriteValidationOptions = {},
): Promise<boolean> {
  if (options.validate?.() === false || typeof window === "undefined") {
    return false;
  }
  const raw = await getStorageValue(STORAGE_KEY);
  if (!raw) return false;
  let registry: AgentProfileRegistry;
  try {
    registry = JSON.parse(raw) as AgentProfileRegistry;
  } catch {
    return false;
  }
  if (registry?.version !== 1 || !Array.isArray(registry.profiles)) {
    return false;
  }
  const profiles = registry.profiles.filter(
    (profile) => !isManagedCloudSharedAgentBase(profile.apiBase),
  );
  if (profiles.length === registry.profiles.length) return false;
  const activeStillPresent = profiles.some(
    (profile) => profile.id === registry.activeProfileId,
  );
  return setStorageValueIfCurrent(
    STORAGE_KEY,
    raw,
    JSON.stringify({
      version: 1,
      activeProfileId: activeStillPresent ? registry.activeProfileId : null,
      profiles,
    } satisfies AgentProfileRegistry),
    { ...options, compensateOnValidationFailure: false },
  );
}

/**
 * One exact terminal transform for account teardown: remove shared-managed A
 * rows and scrub bearer copies on every retained dedicated/self-hosted row.
 * Combining both operations prevents a second read from ever targeting B.
 */
export async function clearManagedSharedCloudProfilesAndTokensDurably(
  options: StorageWriteValidationOptions = {},
): Promise<boolean> {
  if (options.validate?.() === false || typeof window === "undefined") {
    return false;
  }
  const raw = await getStorageValue(STORAGE_KEY);
  if (!raw) return false;
  let registry: AgentProfileRegistry;
  try {
    registry = JSON.parse(raw) as AgentProfileRegistry;
  } catch {
    return false;
  }
  if (registry?.version !== 1 || !Array.isArray(registry.profiles)) {
    return false;
  }
  let changed = false;
  const profiles = registry.profiles.flatMap((profile) => {
    if (isManagedCloudSharedAgentBase(profile.apiBase)) {
      changed = true;
      return [];
    }
    if (!profile.accessToken) return [profile];
    changed = true;
    const { accessToken: _accessToken, ...scrubbed } = profile;
    return [scrubbed];
  });
  if (!changed) return false;
  const activeStillPresent = profiles.some(
    (profile) => profile.id === registry.activeProfileId,
  );
  return setStorageValueIfCurrent(
    STORAGE_KEY,
    raw,
    JSON.stringify({
      version: 1,
      activeProfileId: activeStillPresent ? registry.activeProfileId : null,
      profiles,
    } satisfies AgentProfileRegistry),
    { ...options, compensateOnValidationFailure: false },
  );
}

export function removeAgentProfile(id: string): void {
  const registry = loadAgentProfileRegistry();
  registry.profiles = registry.profiles.filter((p) => p.id !== id);
  if (registry.activeProfileId === id) {
    registry.activeProfileId = registry.profiles[0]?.id ?? null;
  }
  saveAgentProfileRegistry(registry);
}

/** Remove a profile only after its protected registry rewrite commits. */
export async function removeAgentProfileDurably(
  id: string,
  options: StorageWriteValidationOptions = {},
): Promise<boolean> {
  try {
    return await serializeRuntimeConnectionPersistence(async () => {
      const registry = await loadAgentProfileRegistryDurably();
      if (!registry.profiles.some((profile) => profile.id === id)) return true;
      // Removing the active row without changing the boot/live authority in the
      // same transaction would create an unresolvable selection. Active
      // removal must use removeAgentProfileWithFallbackDurably below.
      if (registry.activeProfileId === id) return false;
      const profiles = registry.profiles.filter((profile) => profile.id !== id);
      return saveAgentProfileRegistryDurably(
        { ...registry, profiles },
        options,
      );
    });
  } catch (cause) {
    if (cause instanceof RuntimeConnectionPersistenceBoundaryError) {
      warnRuntimePersistenceBoundaryUnavailable(cause.cause);
      return false;
    }
    throw cause;
  }
}

/**
 * Remove a runtime and, when it is active, publish its fallback (or complete
 * clear) inside the same origin-wide transaction as the registry rewrite.
 */
export async function removeAgentProfileWithFallbackDurably(
  id: string,
  options: AgentProfileRemovalPersistenceOptions,
): Promise<AgentProfileRemovalPersistenceResult> {
  try {
    return await serializeRuntimeConnectionPersistence(async () => {
      const registry = await loadAgentProfileRegistryDurably();
      const target = registry.profiles.find((profile) => profile.id === id);
      if (!target) return { ok: false, reason: "not-found" };

      const profiles = registry.profiles.filter((profile) => profile.id !== id);
      if (registry.activeProfileId !== id) {
        return (await saveAgentProfileRegistryDurably({
          ...registry,
          profiles,
        }))
          ? { ok: true, activeProfile: null }
          : { ok: false, reason: "persistence-failed" };
      }

      const fallback =
        profiles.find((profile) => profile.kind === "local") ?? profiles[0];
      if (fallback) {
        const server = options.createServer(fallback);
        if (!server) return { ok: false, reason: "invalid-fallback" };
        if (!isPersistedActiveServerAllowedByBuildTarget(server)) {
          return { ok: false, reason: "build-pinned" };
        }
        const persisted = await persistRegistryAndServerDurably(
          { ...registry, activeProfileId: fallback.id, profiles },
          server,
          {
            finalize: () => options.finalize(fallback, server),
          },
        );
        return persisted
          ? { ok: true, activeProfile: fallback }
          : { ok: false, reason: "persistence-failed" };
      }

      // A pinned build must always retain its sole configured boot authority;
      // reject the last-profile removal before either protected record changes.
      if (hasBuildPinnedActiveServerTarget()) {
        return { ok: false, reason: "build-pinned" };
      }

      const expectedServer = options.createServer(target);
      if (!expectedServer) {
        return { ok: false, reason: "persistence-failed" };
      }
      const activeServerRaw = await getStorageValue(ACTIVE_SERVER_KEY);
      if (activeServerRaw) {
        try {
          const activeServer = JSON.parse(
            activeServerRaw,
          ) as PersistedActiveServer;
          if (!samePersistedActiveServer(activeServer, expectedServer)) {
            return { ok: false, reason: "persistence-failed" };
          }
        } catch {
          // error-policy:J3 malformed boot authority cannot be safely deleted.
          return { ok: false, reason: "persistence-failed" };
        }
      }

      const registryWrite = await setStorageValueWithCompensation(
        STORAGE_KEY,
        JSON.stringify({
          ...registry,
          activeProfileId: null,
          profiles,
        } satisfies AgentProfileRegistry),
      );
      if (!registryWrite) {
        return { ok: false, reason: "persistence-failed" };
      }

      let serverCleared = activeServerRaw === null;
      try {
        if (activeServerRaw !== null) {
          serverCleared = await removeStorageValueIfCurrent(
            ACTIVE_SERVER_KEY,
            activeServerRaw,
          );
        }
      } catch (cause) {
        try {
          await compensateStorageWrites(registryWrite);
        } catch (rollbackError) {
          throw new AggregateError(
            [cause, rollbackError],
            "Active-server deletion and registry compensation failed",
          );
        }
        throw cause;
      }
      if (!serverCleared) {
        await compensateStorageWrites(registryWrite);
        return { ok: false, reason: "persistence-failed" };
      }

      // Persistent state is already coherently empty. The UI boundary surfaces
      // a live-client publication failure rather than resurrecting a deleted
      // boot authority with an unfenced write.
      const finalized = await options.finalize(null, null);
      if (!finalized) {
        return { ok: false, reason: "persistence-failed" };
      }
      return { ok: true, activeProfile: null };
    });
  } catch (cause) {
    if (cause instanceof RuntimeConnectionPersistenceBoundaryError) {
      warnRuntimePersistenceBoundaryUnavailable(cause.cause);
      return { ok: false, reason: "persistence-failed" };
    }
    throw cause;
  }
}

/**
 * Drop the bearer access token from every persisted agent profile while keeping
 * the rest of each profile (label/kind/apiBase/active selection). Call this on
 * sign-out: the token is a JWT and leaving copies in localStorage after sign-out
 * is an at-rest leak, but clearing the whole registry would needlessly forget
 * which backends to re-authenticate against.
 */
export function scrubPersistedAgentProfileTokens(): void {
  const registry = loadAgentProfileRegistry();
  let changed = false;
  registry.profiles = registry.profiles.map((profile) => {
    if (!profile.accessToken) return profile;
    changed = true;
    const { accessToken, ...rest } = profile;
    return rest;
  });
  if (changed) saveAgentProfileRegistry(registry);
}

/** Remove persisted profile bearers while retaining every runtime selection. */
export async function scrubPersistedAgentProfileTokensDurably(
  options: StorageWriteValidationOptions = {},
): Promise<boolean> {
  if (options.validate?.() === false) return false;
  if (typeof window === "undefined") return false;
  const raw = await getStorageValue(STORAGE_KEY);
  if (!raw) return false;
  let registry: AgentProfileRegistry;
  try {
    registry = JSON.parse(raw) as AgentProfileRegistry;
  } catch {
    return false;
  }
  if (registry?.version !== 1 || !Array.isArray(registry.profiles)) {
    return false;
  }
  let changed = false;
  const profiles = registry.profiles.map((profile) => {
    if (!profile.accessToken) return profile;
    changed = true;
    const { accessToken: _accessToken, ...rest } = profile;
    return rest;
  });
  if (!changed) return false;
  return setStorageValueIfCurrent(
    STORAGE_KEY,
    raw,
    JSON.stringify({ ...registry, profiles }),
    { ...options, compensateOnValidationFailure: false },
  );
}

export function updateAgentProfile(
  id: string,
  updates: Partial<Omit<AgentProfile, "id" | "createdAt">>,
): void {
  const registry = loadAgentProfileRegistry();
  const idx = registry.profiles.findIndex((p) => p.id === id);
  if (idx === -1) return;
  registry.profiles[idx] = { ...registry.profiles[idx], ...updates };
  saveAgentProfileRegistry(registry);
}
