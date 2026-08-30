/**
 * Constructs renderer RPC endpoints and owns their secure-store cleanup until
 * shutdown has observed every release. Failed cleanup remains registered so a
 * later shutdown attempt can retry instead of forgetting rollback authority.
 */

import { BrowserView } from "electrobun/bun";
import { logger } from "./logger";
import {
  createRendererSecureStoreOwner,
  type RendererSecureStoreOwner,
} from "./renderer-secure-store-authority";
import { rendererSecureStoreRevisions } from "./renderer-secure-store-revisions";
import {
  buildBunRpcHandlers,
  type RendererSecureStoreDocumentAuthority,
  releaseRendererSecureStoreOwner,
} from "./rpc-handlers";
import type { ElizaDesktopRPCSchema } from "./rpc-schema";
import { registerShellSyncEndpoint } from "./shell-sync-relay";
import type { SendToWebview } from "./types";

export type ElizaDesktopRpc = ReturnType<
  typeof BrowserView.defineRPC<ElizaDesktopRPCSchema>
>;

interface PendingOwnerRelease {
  activeOperations: number;
  drainWaiters: Set<() => void>;
  label: string;
  owner: RendererSecureStoreOwner;
  promise: Promise<void> | null;
  releaseStarted: boolean;
}

interface RendererDocumentLifecycle {
  executeJavascript(script: string): void;
  on(
    name: "will-navigate" | "did-commit-navigation" | "dom-ready",
    handler: (event?: unknown) => void,
  ): void;
}

export type BlockedRendererNavigationHandler = (url: string) => void;

interface RendererNavigationEventLike {
  url?: unknown;
  detail?: unknown;
  data?: { detail?: unknown };
  preventDefault?: () => void;
  response?: { allow: boolean };
}

type PrivilegedRendererAuthority =
  | { kind: "origin"; origin: string; protocol: "http:" | "https:" }
  | {
      kind: "file";
      canonicalUrl: string;
      hostname: string;
      pathname: string;
    };

export interface PrivilegedRendererOriginPolicy {
  allows(candidateUrl: string): boolean;
  readonly javascriptLocationGuard: string;
  readonly navigationRules: readonly string[];
}

function parsePrivilegedRendererAuthority(
  configuredRendererUrl: string,
): PrivilegedRendererAuthority {
  let configured: URL;
  try {
    configured = new URL(configuredRendererUrl);
  } catch {
    throw new Error(
      `Privileged renderer URL is invalid: ${configuredRendererUrl}`,
    );
  }

  if (configured.protocol === "http:" || configured.protocol === "https:") {
    if (configured.origin.includes("*")) {
      throw new Error("Privileged renderer origins cannot contain wildcards.");
    }
    return {
      kind: "origin",
      origin: configured.origin,
      protocol: configured.protocol,
    };
  }

  if (configured.protocol === "file:") {
    configured.search = "";
    configured.hash = "";
    if (configured.href.includes("*")) {
      throw new Error(
        "Privileged renderer file URLs cannot contain wildcards.",
      );
    }
    return {
      kind: "file",
      canonicalUrl: configured.href,
      hostname: configured.hostname,
      pathname: configured.pathname,
    };
  }

  throw new Error(
    `Privileged renderer URL must use http:, https:, or an exact file: URL; received ${configured.protocol}`,
  );
}

/**
 * Resolve the sole document authority for a preload/RPC-bearing renderer.
 * Loopback aliases, ports, custom schemes, and sibling file paths are not
 * interchangeable: the exact configured renderer URL defines the boundary.
 */
export function createPrivilegedRendererOriginPolicy(
  configuredRendererUrl: string,
): PrivilegedRendererOriginPolicy {
  const authority = parsePrivilegedRendererAuthority(configuredRendererUrl);
  if (authority.kind === "origin") {
    return {
      allows: (candidateUrl) => {
        try {
          const candidate = new URL(candidateUrl);
          return (
            candidate.protocol === authority.protocol &&
            candidate.origin === authority.origin
          );
        } catch {
          return false;
        }
      },
      javascriptLocationGuard: [
        `globalThis.location?.protocol === ${JSON.stringify(authority.protocol)}`,
        `globalThis.location?.origin === ${JSON.stringify(authority.origin)}`,
      ].join(" && "),
      navigationRules: ["^*", `${authority.origin}/*`],
    };
  }

  return {
    allows: (candidateUrl) => {
      try {
        const candidate = new URL(candidateUrl);
        candidate.search = "";
        candidate.hash = "";
        return candidate.href === authority.canonicalUrl;
      } catch {
        return false;
      }
    },
    javascriptLocationGuard: [
      `globalThis.location?.protocol === "file:"`,
      `globalThis.location?.hostname === ${JSON.stringify(authority.hostname)}`,
      `globalThis.location?.pathname === ${JSON.stringify(authority.pathname)}`,
    ].join(" && "),
    navigationRules: [
      "^*",
      authority.canonicalUrl,
      `${authority.canonicalUrl}?*`,
      `${authority.canonicalUrl}#*`,
    ],
  };
}

export function serializePrivilegedRendererNavigationRules(
  configuredRendererUrl: string,
): string {
  return JSON.stringify(
    createPrivilegedRendererOriginPolicy(configuredRendererUrl).navigationRules,
  );
}

function readRendererNavigationUrl(event: unknown): string {
  if (typeof event === "string") return event;
  if (!event || typeof event !== "object") return "";
  const candidate = event as RendererNavigationEventLike;
  if (typeof candidate.url === "string") return candidate.url;
  if (typeof candidate.detail === "string") return candidate.detail;
  return typeof candidate.data?.detail === "string"
    ? candidate.data.detail
    : "";
}

function blockRendererNavigation(event: unknown): void {
  if (!event || typeof event !== "object") return;
  const candidate = event as RendererNavigationEventLike;
  candidate.preventDefault?.();
  candidate.response = { allow: false };
}

interface RendererDocumentOwner extends PendingOwnerRelease {
  documentCapability: string;
  generation: number;
}

const pendingOwnerReleases = new Map<
  RendererSecureStoreOwner,
  PendingOwnerRelease
>();
const MAX_RPC_REQUEST_TIME_MS = 600_000;

function documentAuthorityError(message: string): Error {
  return new Error(`Secure credential document authority denied: ${message}`);
}

function asRpcSend(
  send: unknown,
): (message: string, payload?: unknown) => void {
  return send as (message: string, payload?: unknown) => void;
}

function startOwnerRelease(entry: PendingOwnerRelease): Promise<void> {
  if (entry.promise) return entry.promise;
  entry.releaseStarted = true;
  const release = async (): Promise<void> => {
    if (entry.activeOperations > 0) {
      await new Promise<void>((resolve) => entry.drainWaiters.add(resolve));
    }
    await releaseRendererSecureStoreOwner(entry.owner);
  };
  const promise = release().then(
    () => {
      if (pendingOwnerReleases.get(entry.owner) === entry) {
        pendingOwnerReleases.delete(entry.owner);
      }
    },
    (error: unknown) => {
      // Keep the owner registered and clear only the attempt. Shutdown can
      // retry the still-live rollback receipts after a transient store error.
      if (pendingOwnerReleases.get(entry.owner) === entry) {
        entry.promise = null;
      }
      throw error;
    },
  );
  entry.promise = promise;
  // error-policy:J5 the same rejection remains observable through the tracker
  // and awaitDesktopRpcSecureStoreCleanup; this branch prevents an unhandled
  // rejection when a window closes before shutdown begins.
  void promise.catch((error) => {
    logger.warn(
      `[secure-store:${entry.label}] endpoint cleanup failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  });
  return promise;
}

/** Wait for every released renderer owner, retrying a prior failed attempt. */
export async function awaitDesktopRpcSecureStoreCleanup(): Promise<void> {
  while (pendingOwnerReleases.size > 0) {
    const entries = Array.from(pendingOwnerReleases.values());
    const results = await Promise.allSettled(
      entries.map((entry) => startOwnerRelease(entry)),
    );
    const failures = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (failures.length > 0) {
      throw new AggregateError(
        failures,
        "One or more renderer secure-store releases are still pending.",
      );
    }
  }
}

/** Invoke the process quit primitive only after the complete cleanup settles. */
export async function quitAfterDesktopCleanup(
  cleanup: () => Promise<void>,
  quit: () => void,
): Promise<void> {
  await cleanup();
  quit();
}

/** Build one fully wired renderer RPC endpoint. */
export function createDesktopRpc(label: string): {
  rpc: ElizaDesktopRpc;
  sendToWebview: SendToWebview;
  bindRendererLifecycle: (
    lifecycle: RendererDocumentLifecycle,
    configuredRendererUrl: string,
    onBlockedNavigation?: BlockedRendererNavigationHandler,
  ) => void;
  releaseShellSync: () => void;
} {
  let rpc: ElizaDesktopRpc | undefined;
  let released = false;
  let lifecycleBound = false;
  let ownerGeneration = 0;
  let documentGeneration = 0;
  let publishableGeneration: number | null = null;
  let initialPublicationAttempted = false;
  let rendererDocumentAuthorized = true;

  const createOwnerRelease = (generation: number): RendererDocumentOwner => {
    ownerGeneration += 1;
    const entry: RendererDocumentOwner = {
      activeOperations: 0,
      documentCapability: crypto.randomUUID(),
      drainWaiters: new Set(),
      generation,
      label: `${label}:document-${ownerGeneration}`,
      owner: createRendererSecureStoreOwner(
        `renderer-secure-store-owner:${label}:document-${ownerGeneration}`,
      ),
      promise: null,
      releaseStarted: false,
    };
    pendingOwnerReleases.set(entry.owner, entry);
    return entry;
  };

  let currentDocument: RendererDocumentOwner | null =
    createOwnerRelease(documentGeneration);
  let ownerReady: Promise<void> = Promise.resolve();

  const transitionRendererDocument = (authorized: boolean): void => {
    if (released) return;
    rendererDocumentAuthorized = authorized;
    documentGeneration += 1;
    const successorGeneration = documentGeneration;
    publishableGeneration = null;
    ownerReady = ownerReady
      .catch(() => undefined)
      .then(async () => {
        const predecessor = currentDocument;
        if (predecessor) await startOwnerRelease(predecessor);
        if (successorGeneration !== documentGeneration) return;
        currentDocument = null;
        if (!released && authorized) {
          currentDocument = createOwnerRelease(successorGeneration);
          publishableGeneration = successorGeneration;
          requestCapabilityPublication();
        }
      });
    // error-policy:J5 secure RPC and shutdown observe the same tracked owner
    // cleanup rejection; this prevents an unhandled lifecycle callback.
    void ownerReady.catch((error) => {
      logger.warn(
        `[secure-store:${label}] document rollover failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
  };

  const secureStoreDocuments: RendererSecureStoreDocumentAuthority = {
    run: async (documentCapability, operation) => {
      const observedReady = ownerReady;
      await observedReady;
      const current = currentDocument;
      if (
        released ||
        !current ||
        current.documentCapability !== documentCapability ||
        current.releaseStarted
      ) {
        throw documentAuthorityError("document is not active");
      }
      current.activeOperations += 1;
      try {
        return await operation(current.owner);
      } finally {
        // Electrobun routes responses through the socket currently attached to
        // this webview id. Keep the document fenced for one host turn after the
        // handler settles so its response packet is dispatched before a new
        // document receives a capability and can reuse the same request id.
        setTimeout(() => {
          current.activeOperations = Math.max(0, current.activeOperations - 1);
          if (current.activeOperations !== 0) return;
          const waiters = Array.from(current.drainWaiters);
          current.drainWaiters.clear();
          for (const resolve of waiters) resolve();
        }, 0);
      }
    },
  };

  const sendToWebview: SendToWebview = (message, payload) => {
    if (!rpc) {
      logger.warn(
        `[sendToWebview:${label}] RPC not yet initialised; dropping message: ${message}`,
      );
      return;
    }
    try {
      asRpcSend(rpc.send)(message, payload ?? null);
    } catch (error) {
      logger.warn(
        `[sendToWebview:${label}] send(${message}) failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      // The revision authority must observe delivery failure so it can
      // quarantine this endpoint. Renderer caches independently expire via a
      // secret-free revision lease, bounding any missed event.
      throw error;
    }
  };

  let rendererLifecycle: RendererDocumentLifecycle | null = null;
  let rendererOriginPolicy: PrivilegedRendererOriginPolicy | null = null;
  let capabilityPublication: Promise<void> | null = null;
  let capabilityPublicationQueued = false;

  const requestCapabilityPublication = (): void => {
    if (capabilityPublication) {
      capabilityPublicationQueued = true;
      return;
    }
    if (
      released ||
      !rendererLifecycle ||
      !rendererOriginPolicy ||
      publishableGeneration !== documentGeneration
    ) {
      return;
    }
    const targetGeneration = documentGeneration;
    const targetLifecycle = rendererLifecycle;
    const targetPolicy = rendererOriginPolicy;
    const publication = (async () => {
      await ownerReady;
      const current = currentDocument;
      if (
        released ||
        rendererOriginPolicy !== targetPolicy ||
        publishableGeneration !== targetGeneration ||
        !current ||
        current.generation !== targetGeneration ||
        current.releaseStarted
      ) {
        return;
      }
      const payload = JSON.stringify({
        documentCapability: current.documentCapability,
        generation: targetGeneration,
      });
      targetLifecycle.executeJavascript(
        `if (${targetPolicy.javascriptLocationGuard}) globalThis.__ELIZA_ACCEPT_SECURE_STORE_DOCUMENT_CAPABILITY__?.(${payload});`,
      );
      if (targetGeneration === 0) initialPublicationAttempted = true;
    })();
    capabilityPublication = publication;
    // error-policy:J5 a later renderer-ready hint or dom-ready can retry the
    // same host capability; never rotate authority on a delivery failure.
    void publication
      .catch((error) => {
        logger.warn(
          `[secure-store:${label}] capability publication failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      })
      .finally(() => {
        if (capabilityPublication === publication) {
          capabilityPublication = null;
        }
        if (capabilityPublicationQueued) {
          capabilityPublicationQueued = false;
          requestCapabilityPublication();
        }
      });
  };

  type BunRpcRequestsHandlers = NonNullable<
    Parameters<
      typeof BrowserView.defineRPC<ElizaDesktopRPCSchema>
    >[0]["handlers"]
  >["requests"];
  type BunRpcMessagesHandlers = NonNullable<
    Parameters<
      typeof BrowserView.defineRPC<ElizaDesktopRPCSchema>
    >[0]["handlers"]
  >["messages"];

  const shellSyncEndpoint = registerShellSyncEndpoint(label, sendToWebview);
  const releaseSecureStoreRevisions =
    rendererSecureStoreRevisions.registerEndpoint(sendToWebview);

  rpc = BrowserView.defineRPC<ElizaDesktopRPCSchema>({
    maxRequestTime: MAX_RPC_REQUEST_TIME_MS,
    handlers: {
      messages: {
        secureStoreDocumentReady: () => {
          requestCapabilityPublication();
        },
      } as BunRpcMessagesHandlers,
      requests: buildBunRpcHandlers({
        sendToWebview,
        secureStoreDocuments,
        shellControllerEndpoint: shellSyncEndpoint,
      }) as BunRpcRequestsHandlers,
    },
  });

  return {
    rpc,
    sendToWebview,
    bindRendererLifecycle: (
      lifecycle,
      configuredRendererUrl,
      onBlockedNavigation,
    ) => {
      if (lifecycleBound) return;
      const policy = createPrivilegedRendererOriginPolicy(
        configuredRendererUrl,
      );
      lifecycleBound = true;
      rendererLifecycle = lifecycle;
      rendererOriginPolicy = policy;
      lifecycle.on("will-navigate", (event) => {
        // A pre-commit navigation may still be cancelled by another listener.
        // Disable resends, but keep A fully active until an authenticated
        // native did-commit event schedules its rollback.
        publishableGeneration = null;
        const url = readRendererNavigationUrl(event);
        if (policy.allows(url)) return;
        blockRendererNavigation(event);
        if (!url || !onBlockedNavigation) return;
        try {
          onBlockedNavigation(url);
        } catch (error) {
          logger.warn(
            `[secure-store:${label}] blocked-navigation handoff failed: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      });
      lifecycle.on("did-commit-navigation", (event) => {
        const url = readRendererNavigationUrl(event);
        transitionRendererDocument(policy.allows(url));
      });
      lifecycle.on("dom-ready", (event) => {
        const url = readRendererNavigationUrl(event);
        if (!policy.allows(url)) {
          // Native navigation rules are the synchronous barrier. This second
          // fence covers a missing/malformed commit signal and makes an
          // externally committed document incapable of retaining authority.
          if (rendererDocumentAuthorized) transitionRendererDocument(false);
          return;
        }
        // Electrobun implements dom-ready in renderer JavaScript. It is safe
        // only for bootstrapping generation zero, never as rollover authority.
        if (documentGeneration === 0 && !initialPublicationAttempted) {
          publishableGeneration = 0;
          requestCapabilityPublication();
        }
      });
    },
    releaseShellSync: () => {
      if (released) return;
      released = true;
      rendererLifecycle = null;
      rendererOriginPolicy = null;
      rendererDocumentAuthorized = false;
      publishableGeneration = null;
      releaseSecureStoreRevisions();
      shellSyncEndpoint.release();
      if (currentDocument) void startOwnerRelease(currentDocument);
    },
  };
}
