/**
 * Exercises non-destructive runtime switching across the client, active
 * profile, restorable server, and composer-draft boundaries with jsdom storage.
 */
// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AgentProfile } from "./agent-profile-types";

const mocks = vi.hoisted(() => ({
  setBaseUrl: vi.fn(),
  repointBaseUrl: vi.fn(
    (_baseUrl?: string, _accessToken?: string | null) => true,
  ),
  setToken: vi.fn(),
  loadAgentProfileRegistry: vi.fn(),
  persistAgentProfileSelectionDurably: vi.fn(),
  activeServerIdForAgentProfile: vi.fn((profile: AgentProfile) =>
    profile.kind === "cloud" && profile.cloudAgentId
      ? `cloud:${profile.cloudAgentId}`
      : profile.id,
  ),
  createPersistedActiveServer: vi.fn((args: Record<string, unknown>) => ({
    ...args,
  })),
  isTrustedCloudApiBaseUrl: vi.fn(() => true),
  isTrustedRestoreApiBaseUrl: vi.fn(() => true),
  clearAllChatDrafts: vi.fn(),
  getFrontendPlatform: vi.fn(() => "web"),
  isMobileLocalAgentIpcBase: vi.fn(() => false),
  persistMobileRuntimeModeForServerTarget: vi.fn(),
  activeServerKindToFirstRunRuntimeTarget: vi.fn((k: string) =>
    k === "cloud" ? "elizacloud" : "remote",
  ),
}));

vi.mock("../api", () => ({
  client: {
    setBaseUrl: mocks.setBaseUrl,
    repointBaseUrl: mocks.repointBaseUrl,
    setToken: mocks.setToken,
  },
}));
vi.mock("./agent-profiles", () => ({
  activeServerIdForAgentProfile: mocks.activeServerIdForAgentProfile,
  loadAgentProfileRegistry: mocks.loadAgentProfileRegistry,
  persistAgentProfileSelectionDurably:
    mocks.persistAgentProfileSelectionDurably,
}));
vi.mock("./persistence", () => ({
  createPersistedActiveServer: mocks.createPersistedActiveServer,
}));
vi.mock("./runtime-url-trust", () => ({
  isTrustedCloudApiBaseUrl: mocks.isTrustedCloudApiBaseUrl,
  isTrustedRestoreApiBaseUrl: mocks.isTrustedRestoreApiBaseUrl,
}));
vi.mock("./ChatComposerContext.hooks", () => ({
  clearAllChatDrafts: mocks.clearAllChatDrafts,
}));
vi.mock("../platform/platform-guards", () => ({
  getFrontendPlatform: mocks.getFrontendPlatform,
}));
vi.mock("../first-run/mobile-runtime-mode", () => ({
  isMobileLocalAgentIpcBase: mocks.isMobileLocalAgentIpcBase,
  persistMobileRuntimeModeForServerTarget:
    mocks.persistMobileRuntimeModeForServerTarget,
}));
vi.mock("../first-run/runtime-target", () => ({
  activeServerKindToFirstRunRuntimeTarget:
    mocks.activeServerKindToFirstRunRuntimeTarget,
}));

import {
  subscribeRuntimeAuthoritySwitch,
  switchRuntimeNonDestructive,
} from "./switch-runtime";

const LOCAL: AgentProfile = {
  id: "local-1",
  label: "This device",
  kind: "local",
  createdAt: "2026-06-01T00:00:00.000Z",
};
const CLOUD: AgentProfile = {
  id: "cloud-1",
  label: "Cloud agent",
  kind: "cloud",
  cloudAgentId: "11111111-1111-4111-8111-111111111111",
  apiBase: "https://11111111-1111-4111-8111-111111111111.elizacloud.ai",
  accessToken: "tok-cloud",
  createdAt: "2026-06-02T00:00:00.000Z",
};
const LOCAL_DOCKER_CLOUD: AgentProfile = {
  id: "profile-local-docker",
  label: "Local Docker agent",
  kind: "cloud",
  cloudAgentId: "55555555-5555-4555-8555-555555555555",
  apiBase: "http://127.0.0.1:43123",
  accessToken: "tok-local-agent",
  createdAt: "2026-08-10T00:00:00.000Z",
};
const REMOTE: AgentProfile = {
  id: "vps-1",
  label: "My VPS",
  kind: "remote",
  apiBase: "http://100.72.1.4:3000",
  accessToken: "tok-vps",
  createdAt: "2026-06-03T00:00:00.000Z",
};
const RELAY: AgentProfile = {
  id: "relay-1",
  label: "Studio Mac",
  kind: "remote",
  apiBase: "eliza-remote://session/session-1",
  connectionMode: "relay",
  createdAt: "2026-08-22T00:00:00.000Z",
  remoteRelay: {
    ownerId: "owner-1",
    controllerDeviceId: "controller-1",
    controllerKeyId: "controller-key-1",
    grantId: "grant-1",
    grantRevision: 1,
    sessionId: "session-1",
    targetRuntimeId: "host-1",
    targetKeyId: "target-key-1",
    targetDisplayName: "Studio Mac",
    targetCreatedAt: Date.parse("2026-08-22T00:00:00.000Z"),
    targetPlatform: "macos",
    targetSigningPublicKeyJwk: {},
    targetEncryptionPublicKeyJwk: {},
    expiresAt: null,
  },
};

function withRegistry(profiles: AgentProfile[]) {
  mocks.loadAgentProfileRegistry.mockReturnValue({
    version: 1,
    activeProfileId: profiles[0]?.id ?? null,
    profiles,
  });
}

describe("switchRuntimeNonDestructive", () => {
  beforeEach(() => {
    for (const fn of Object.values(mocks)) fn.mockClear();
    mocks.isTrustedRestoreApiBaseUrl.mockReturnValue(true);
    mocks.isTrustedCloudApiBaseUrl.mockReturnValue(true);
    mocks.repointBaseUrl.mockReturnValue(true);
    mocks.persistAgentProfileSelectionDurably.mockImplementation(
      async (
        profileId: string,
        options: {
          createServer: (profile: AgentProfile) => unknown | null;
          finalize?: (
            profile: AgentProfile,
            server: unknown,
          ) => Promise<boolean>;
        },
      ) => {
        const profile = mocks
          .loadAgentProfileRegistry()
          .profiles.find(
            (candidate: AgentProfile) => candidate.id === profileId,
          );
        if (!profile) return { ok: false, reason: "not-found" };
        const server = options.createServer(profile);
        if (!server) return { ok: false, reason: "invalid-profile" };
        if (options.finalize && !(await options.finalize(profile, server))) {
          return { ok: false, reason: "persistence-failed" };
        }
        return { ok: true, profile };
      },
    );
    mocks.createPersistedActiveServer.mockImplementation((a) => ({ ...a }));
    mocks.getFrontendPlatform.mockReturnValue("web");
    mocks.isMobileLocalAgentIpcBase.mockReturnValue(false);
    mocks.activeServerKindToFirstRunRuntimeTarget.mockImplementation((k) =>
      k === "cloud" ? "elizacloud" : "remote",
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it("returns not-found for an unknown id and touches nothing", async () => {
    withRegistry([LOCAL]);
    await expect(switchRuntimeNonDestructive("nope")).resolves.toEqual({
      ok: false,
      reason: "not-found",
    });
    expect(mocks.persistAgentProfileSelectionDurably).toHaveBeenCalledWith(
      "nope",
      expect.objectContaining({ createServer: expect.any(Function) }),
    );
    expect(mocks.repointBaseUrl).not.toHaveBeenCalled();
  });

  it("switches to a cloud runtime: persists, activates, re-points seamlessly (not setBaseUrl)", async () => {
    withRegistry([LOCAL, CLOUD]);
    const authorityPhase = vi.fn();
    const unsubscribe = subscribeRuntimeAuthoritySwitch(authorityPhase);
    const res = await switchRuntimeNonDestructive("cloud-1");
    unsubscribe();
    expect(res).toEqual({ ok: true, profile: CLOUD });
    expect(mocks.persistAgentProfileSelectionDurably).toHaveBeenCalledWith(
      "cloud-1",
      expect.objectContaining({
        createServer: expect.any(Function),
        finalize: expect.any(Function),
      }),
    );
    expect(mocks.repointBaseUrl).toHaveBeenCalledWith(
      "https://11111111-1111-4111-8111-111111111111.elizacloud.ai",
      "tok-cloud",
    );
    expect(mocks.setBaseUrl).not.toHaveBeenCalled();
    expect(authorityPhase.mock.calls).toEqual([["before"], ["after"]]);
    expect(authorityPhase.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.repointBaseUrl.mock.invocationCallOrder[0] ??
        Number.POSITIVE_INFINITY,
    );
    expect(mocks.repointBaseUrl.mock.invocationCallOrder[0]).toBeLessThan(
      authorityPhase.mock.invocationCallOrder[1] ?? Number.POSITIVE_INFINITY,
    );
  });

  it("does not emit authority phases for a raw client repoint", () => {
    const authorityPhase = vi.fn();
    const unsubscribe = subscribeRuntimeAuthoritySwitch(authorityPhase);

    mocks.repointBaseUrl("https://dedicated.example.test", "token");

    unsubscribe();
    expect(authorityPhase).not.toHaveBeenCalled();
  });

  it("does not move the live client or clear drafts when durable selection fails", async () => {
    mocks.persistAgentProfileSelectionDurably.mockResolvedValue({
      ok: false,
      reason: "persistence-failed",
    });
    withRegistry([LOCAL, CLOUD]);
    const authorityPhase = vi.fn();
    const unsubscribe = subscribeRuntimeAuthoritySwitch(authorityPhase);

    await expect(switchRuntimeNonDestructive("cloud-1")).resolves.toEqual({
      ok: false,
      reason: "persistence-failed",
    });
    unsubscribe();
    expect(authorityPhase).not.toHaveBeenCalled();
    expect(mocks.repointBaseUrl).not.toHaveBeenCalled();
    expect(mocks.setToken).not.toHaveBeenCalled();
    expect(mocks.clearAllChatDrafts).not.toHaveBeenCalled();
    expect(
      mocks.persistMobileRuntimeModeForServerTarget,
    ).not.toHaveBeenCalled();
  });

  it("fails the durable transaction when the live client refuses publication", async () => {
    mocks.repointBaseUrl.mockReturnValue(false);
    withRegistry([LOCAL, CLOUD]);
    const authorityPhase = vi.fn();
    const unsubscribe = subscribeRuntimeAuthoritySwitch(authorityPhase);

    await expect(switchRuntimeNonDestructive("cloud-1")).resolves.toEqual({
      ok: false,
      reason: "persistence-failed",
    });

    unsubscribe();
    expect(mocks.clearAllChatDrafts).not.toHaveBeenCalled();
    expect(authorityPhase.mock.calls).toEqual([["before"], ["after"]]);
  });

  it("rejects a Cloud profile whose persisted base is outside the Cloud trust boundary", async () => {
    mocks.isTrustedCloudApiBaseUrl.mockReturnValue(false);
    const untrustedCloud: AgentProfile = {
      ...CLOUD,
      apiBase: "https://credential-sink.example.test",
    };
    withRegistry([LOCAL, untrustedCloud]);
    const authorityPhase = vi.fn();
    const unsubscribe = subscribeRuntimeAuthoritySwitch(authorityPhase);

    await expect(
      switchRuntimeNonDestructive(untrustedCloud.id),
    ).resolves.toEqual({
      ok: false,
      reason: "untrusted-cloud",
    });
    unsubscribe();
    expect(authorityPhase).not.toHaveBeenCalled();
    expect(mocks.setToken).not.toHaveBeenCalled();
    expect(mocks.repointBaseUrl).not.toHaveBeenCalled();
    expect(mocks.persistAgentProfileSelectionDurably).toHaveBeenCalledOnce();
    expect(mocks.createPersistedActiveServer).not.toHaveBeenCalled();
  });

  it("switching to a tokenless Cloud profile clears the previous runtime bearer", async () => {
    const tokenlessCloud: AgentProfile = {
      id: "cloud-tokenless",
      label: "Tokenless Cloud agent",
      kind: "cloud",
      cloudAgentId: CLOUD.cloudAgentId,
      apiBase: CLOUD.apiBase,
      createdAt: CLOUD.createdAt,
    };
    withRegistry([REMOTE, tokenlessCloud]);

    expect((await switchRuntimeNonDestructive(tokenlessCloud.id)).ok).toBe(
      true,
    );
    expect(mocks.repointBaseUrl).toHaveBeenCalledWith(
      "https://11111111-1111-4111-8111-111111111111.elizacloud.ai",
      null,
    );
  });

  it("persists a local-Docker Cloud profile with its platform agent identity", async () => {
    withRegistry([LOCAL, LOCAL_DOCKER_CLOUD]);

    await switchRuntimeNonDestructive(LOCAL_DOCKER_CLOUD.id);

    expect(mocks.createPersistedActiveServer).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "cloud",
        id: "cloud:55555555-5555-4555-8555-555555555555",
        apiBase: "http://127.0.0.1:43123",
        accessToken: "tok-local-agent",
      }),
    );
  });

  it("switches to a local runtime: persists + activates + re-points same-origin + clears the stale token", async () => {
    withRegistry([LOCAL, CLOUD]);
    const res = await switchRuntimeNonDestructive("local-1");
    expect(res.ok).toBe(true);
    expect(mocks.persistAgentProfileSelectionDurably).toHaveBeenCalledWith(
      "local-1",
      expect.objectContaining({
        createServer: expect.any(Function),
        finalize: expect.any(Function),
      }),
    );
    // local is same-origin: re-point to the app host + drop any prior
    // remote/cloud bearer (regression guard for the stale-base/token bug).
    expect(mocks.repointBaseUrl).toHaveBeenCalledWith(window.location.origin);
    expect(mocks.setToken).toHaveBeenCalledWith(null);
    expect(mocks.setBaseUrl).not.toHaveBeenCalled();
  });

  it("rejects an untrusted remote (public URL) without switching", async () => {
    mocks.isTrustedRestoreApiBaseUrl.mockReturnValue(false);
    withRegistry([LOCAL, REMOTE]);
    await expect(switchRuntimeNonDestructive("vps-1")).resolves.toEqual({
      ok: false,
      reason: "untrusted-remote",
    });
    expect(mocks.persistAgentProfileSelectionDurably).toHaveBeenCalledOnce();
    expect(mocks.createPersistedActiveServer).not.toHaveBeenCalled();
    expect(mocks.repointBaseUrl).not.toHaveBeenCalled();
  });

  it("allows a trusted remote (tailscale/RFC1918) and re-points", async () => {
    mocks.isTrustedRestoreApiBaseUrl.mockReturnValue(true);
    withRegistry([LOCAL, REMOTE]);
    const res = await switchRuntimeNonDestructive("vps-1");
    expect(res.ok).toBe(true);
    expect(mocks.repointBaseUrl).toHaveBeenCalledWith(
      "http://100.72.1.4:3000",
      "tok-vps",
    );
  });

  it("allows only an exactly bound native relay pseudo-URL", async () => {
    withRegistry([LOCAL, RELAY]);
    expect((await switchRuntimeNonDestructive(RELAY.id)).ok).toBe(true);
    expect(mocks.repointBaseUrl).toHaveBeenCalledWith(RELAY.apiBase, null);

    const forged = {
      ...RELAY,
      id: "relay-forged",
      apiBase: "https://credential-sink.example.test",
    };
    withRegistry([LOCAL, forged]);
    await expect(switchRuntimeNonDestructive(forged.id)).resolves.toEqual({
      ok: false,
      reason: "untrusted-remote",
    });
  });

  it("switching to a TOKENLESS remote CLEARS the token (no inherited bearer)", async () => {
    mocks.isTrustedRestoreApiBaseUrl.mockReturnValue(true);
    const tokenless: AgentProfile = {
      id: "vps-2",
      label: "Tokenless VPS",
      kind: "remote",
      apiBase: "http://100.72.1.9:3000",
      createdAt: "2026-06-04T00:00:00.000Z",
    };
    withRegistry([CLOUD, tokenless]);
    const res = await switchRuntimeNonDestructive("vps-2");
    expect(res.ok).toBe(true);
    expect(mocks.repointBaseUrl).toHaveBeenCalledWith(
      "http://100.72.1.9:3000",
      null,
    );
  });

  it("clears chat drafts on a switch (no cross-runtime draft bleed)", async () => {
    withRegistry([LOCAL, CLOUD]);
    await switchRuntimeNonDestructive("cloud-1");
    expect(mocks.clearAllChatDrafts).toHaveBeenCalledTimes(1);
  });

  it("on mobile, persists the runtime-mode so the switch survives a reboot", async () => {
    mocks.getFrontendPlatform.mockReturnValue("android");
    withRegistry([LOCAL, CLOUD]);
    await switchRuntimeNonDestructive("cloud-1");
    expect(mocks.persistMobileRuntimeModeForServerTarget).toHaveBeenCalledWith(
      "elizacloud",
    );
  });

  it("does NOT persist mobile runtime-mode on web", async () => {
    mocks.getFrontendPlatform.mockReturnValue("web");
    withRegistry([LOCAL, CLOUD]);
    await switchRuntimeNonDestructive("cloud-1");
    expect(
      mocks.persistMobileRuntimeModeForServerTarget,
    ).not.toHaveBeenCalled();
  });
});
