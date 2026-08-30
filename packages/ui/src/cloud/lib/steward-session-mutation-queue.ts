/**
 * Origin-wide ordering boundary for cookie-mutating Steward auth requests.
 *
 * A passive parent sync can already be in flight when the login child starts
 * account B. The child persists its durable ambiguity receipt first, then
 * enters this queue. Waiting for the admitted account-A request to settle
 * before dispatching B guarantees B is the last server-cookie commit; aborting
 * A alone would not provide that guarantee because fetch cancellation is an
 * ambiguous commit.
 */

const STEWARD_SESSION_MUTATION_LOCK = "eliza-steward-session-mutation.v1";
const LEASE = Symbol("steward-session-mutation-lease");
const TEST_ORIGIN_QUEUE = Symbol.for(
  "eliza.steward-session-mutation.test-origin-queue.v1",
);

export interface StewardSessionMutationLease {
  readonly [LEASE]: true;
}

type BrowserLockManager = {
  request<T>(
    name: string,
    options: { mode: "exclusive" },
    callback: () => Promise<T>,
  ): Promise<T>;
};

let mutationTail: Promise<void> = Promise.resolve();

export class StewardSessionMutationLockUnavailableError extends Error {
  constructor() {
    super(
      "This browser cannot safely serialize Eliza Cloud session changes across tabs. Close other tabs or use a browser with Web Locks support, then retry.",
    );
    this.name = "StewardSessionMutationLockUnavailableError";
  }
}

interface TestOriginQueueState {
  tail: Promise<void>;
}

function isTestRuntime(): boolean {
  return (
    typeof process !== "undefined" &&
    (process.env.NODE_ENV === "test" || process.env.VITEST === "true")
  );
}

function testOriginQueueState(): TestOriginQueueState {
  const shared = globalThis as typeof globalThis & {
    [TEST_ORIGIN_QUEUE]?: TestOriginQueueState;
  };
  const existing = shared[TEST_ORIGIN_QUEUE];
  if (existing) return existing;
  const created = { tail: Promise.resolve() };
  shared[TEST_ORIGIN_QUEUE] = created;
  return created;
}

function runWithTestOriginLock<T>(operation: () => Promise<T>): Promise<T> {
  const state = testOriginQueueState();
  const result = state.tail.then(operation, operation);
  state.tail = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

function browserLockManager(): BrowserLockManager | null {
  if (typeof navigator === "undefined") return null;
  const candidate = (navigator as Navigator & { locks?: unknown }).locks;
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    typeof (candidate as { request?: unknown }).request !== "function"
  ) {
    return null;
  }
  return candidate as BrowserLockManager;
}

async function runWithOriginLock<T>(
  mutation: (lease: StewardSessionMutationLease) => Promise<T>,
): Promise<T> {
  const execute = () => mutation({ [LEASE]: true });
  const locks = browserLockManager();
  if (!locks) {
    // There is no safe crash-recoverable localStorage/BroadcastChannel lock:
    // expiring a crashed tab's lease can overlap a suspended callback, while a
    // non-expiring lease can strand the origin forever. Production therefore
    // fails closed. SSR has no competing browser realm, and Vitest uses one
    // explicit global queue so independently loaded module instances remain
    // deterministic without weakening the shipped boundary.
    if (typeof window === "undefined") return execute();
    if (isTestRuntime()) return runWithTestOriginLock(execute);
    throw new StewardSessionMutationLockUnavailableError();
  }
  return locks.request(
    STEWARD_SESSION_MUTATION_LOCK,
    { mode: "exclusive" },
    execute,
  );
}

export function enqueueStewardSessionMutation<T>(
  mutation: (lease: StewardSessionMutationLease) => Promise<T>,
): Promise<T> {
  // This tail avoids reordering inside one module instance. Web Locks is the
  // production origin-wide fence; the test-only global queue above covers
  // independently evaluated copies of this module in the same harness.
  const run = () => runWithOriginLock(mutation);
  const result = mutationTail.then(run, run);
  mutationTail = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}
