/** Pure state-reconciliation and destructive-cleanup tests for Devices & Runtimes. */
import { describe, expect, it, vi } from "vitest";

import type {
  RemoteHostDirectory,
  RemoteHostSummary,
  RemoteSessionSummary,
} from "../../api/remote-control-cloud-client";
import type { AgentProfile } from "../../state";
import { devicesRuntimesInternals } from "./DevicesRuntimesContainer";

const PUBLIC_JWK: JsonWebKey = {
  kty: "EC",
  crv: "P-256",
  x: "x",
  y: "y",
};

const HOST: RemoteHostSummary = {
  id: "host-1",
  deviceId: "target-device",
  displayName: "Studio Mac",
  platform: "macos" as const,
  connectionMode: "relay",
  runtimeKeyId: "target-key",
  signingPublicKeyJwk: PUBLIC_JWK,
  encryptionPublicKeyJwk: PUBLIC_JWK,
  status: "active",
  lastSeenAt: null,
  createdAt: "2026-08-22T00:00:00.000Z",
  revokedAt: null,
};

const SESSION: RemoteSessionSummary = {
  id: "session-1",
  ownerId: "owner-1",
  grantId: "grant-1",
  grantRevision: 1,
  hostId: "host-1",
  targetRuntimeId: "host-1",
  status: "active",
  controllerDeviceId: "other-device",
  controllerKeyId: "other-key",
  targetKeyId: "target-key",
  grantExpiresAt: "2026-08-23T00:00:00.000Z",
  createdAt: "2026-08-22T00:00:00.000Z",
  updatedAt: "2026-08-22T00:00:00.000Z",
};

const PROFILE: AgentProfile = {
  id: "profile-1",
  label: "Studio Mac",
  kind: "remote",
  apiBase: "eliza-remote://session/session-1",
  connectionMode: "relay",
  createdAt: "2026-08-22T00:00:00.000Z",
  remoteRelay: {
    ownerId: "owner-1",
    controllerDeviceId: "this-device",
    controllerKeyId: "this-key",
    grantId: "grant-1",
    grantRevision: 1,
    sessionId: "session-1",
    targetRuntimeId: "host-1",
    targetKeyId: "target-key",
    targetDisplayName: "Studio Mac",
    targetCreatedAt: Date.parse("2026-08-22T00:00:00.000Z"),
    targetPlatform: "macos",
    targetSigningPublicKeyJwk: PUBLIC_JWK,
    targetEncryptionPublicKeyJwk: PUBLIC_JWK,
    expiresAt: "2026-08-23T00:00:00.000Z",
  },
};

const SSH_PROFILE: AgentProfile = {
  id: "ssh-profile",
  label: "Production VPS",
  kind: "remote",
  apiBase: "eliza-ssh://runtime/ssh-profile",
  credentialRef: "ssh-profile",
  connectionMode: "ssh",
  createdAt: "2026-08-21T00:00:00.000Z",
  ssh: {
    target: "eliza@vps.example",
    sshPort: 22,
    remoteApiPort: 3000,
    hostFingerprint: `SHA256:${"A".repeat(43)}`,
  },
};

const CONTROLLER = {
  version: 1 as const,
  role: "controller" as const,
  ownerId: "owner-1",
  deviceId: "this-device",
  keyId: "this-key",
  displayName: "Linux",
  platform: "linux" as const,
  signingPublicKeyJwk: PUBLIC_JWK,
  encryptionPublicKeyJwk: PUBLIC_JWK,
  createdAt: 1,
};

describe("Devices & Runtimes reconciliation", () => {
  it("does not expose another controller's active session as this device's grant", () => {
    const target = devicesRuntimesInternals.hostTarget(
      HOST,
      new Map([[HOST.id, [SESSION]]]),
      CONTROLLER,
    );
    expect(target.activity).toBe("Paired on another controller");
    expect(target.canPair).toBe(true);
    expect(target.canRevoke).toBe(false);
  });

  it("marks a stale local relay profile as an error instead of connected", () => {
    const directory: RemoteHostDirectory = {
      ownerId: "owner-1",
      hosts: [HOST],
    };
    const target = devicesRuntimesInternals.profileTarget(
      PROFILE,
      PROFILE.id,
      new Map(),
      directory,
      new Map([[HOST.id, [{ ...SESSION, status: "revoked" }]]]),
    );
    expect(target.status).toBe("error");
    expect(target.error).toMatch(/no longer active/);
  });

  it("surfaces an actionable SSH restart block instead of generic offline state", () => {
    const lastError =
      "The trusted SSH host fingerprint no longer matches this runtime. Inspect and reconnect it manually.";
    const target = devicesRuntimesInternals.profileTarget(
      SSH_PROFILE,
      null,
      new Map([
        [
          SSH_PROFILE.id,
          {
            running: false,
            localPort: null,
            startedAt: null,
            reconnectState: "blocked" as const,
            lastError,
          },
        ],
      ]),
      null,
      new Map(),
    );

    expect(target).toMatchObject({
      status: "error",
      activity: "Reconnect blocked",
      error: lastError,
    });
  });

  it("revokes Cloud before local cleanup and retains the profile after partial failure", async () => {
    const events: string[] = [];
    const removeProfile = vi.fn(() => {
      events.push("remove");
    });
    await devicesRuntimesInternals.removeRuntimeWithAuthority(PROFILE, {
      revokeSession: vi.fn(async () => {
        events.push("revoke");
      }),
      clearSession: vi.fn(async () => events.push("clear")),
      stopSsh: vi.fn(),
      deleteCredential: vi.fn(),
      removeProfile,
    });
    expect(events).toEqual(["revoke", "clear", "remove"]);

    const failedRemove = vi.fn();
    await expect(
      devicesRuntimesInternals.removeRuntimeWithAuthority(PROFILE, {
        revokeSession: vi.fn(async () => {
          throw new Error("Cloud unavailable");
        }),
        clearSession: vi.fn(),
        stopSsh: vi.fn(),
        deleteCredential: vi.fn(),
        removeProfile: failedRemove,
      }),
    ).rejects.toThrow("Cloud unavailable");
    expect(failedRemove).not.toHaveBeenCalled();
  });

  it("resolves host-card authority to its matching relay profile and removes it last", async () => {
    const ownSession = {
      ...SESSION,
      controllerDeviceId: CONTROLLER.deviceId,
      controllerKeyId: CONTROLLER.keyId,
    };
    const authority = devicesRuntimesInternals.resolveRelayRevocationAuthority(
      `host:${HOST.id}`,
      [PROFILE],
      new Map([[HOST.id, [ownSession]]]),
      CONTROLLER,
    );
    expect(authority).toMatchObject({
      sessionId: SESSION.id,
      ownerId: SESSION.ownerId,
      controllerDeviceId: CONTROLLER.deviceId,
      profile: { id: PROFILE.id },
    });
    if (!authority) throw new Error("Expected a relay revocation authority.");

    const events: string[] = [];
    await devicesRuntimesInternals.revokeRelayAuthorityWithCleanup(authority, {
      revokeSession: vi.fn(async () => {
        events.push("revoke");
      }),
      clearSession: vi.fn(async () => events.push("clear")),
      removeProfile: vi.fn(() => {
        events.push("remove");
      }),
    });
    expect(events).toEqual(["revoke", "clear", "remove"]);
  });

  it("retains the relay profile when controller cleanup fails so retry can finish", async () => {
    const removeProfile = vi.fn();
    await expect(
      devicesRuntimesInternals.revokeRelayAuthorityWithCleanup(
        {
          sessionId: SESSION.id,
          ownerId: SESSION.ownerId,
          controllerDeviceId: CONTROLLER.deviceId,
          profile: PROFILE,
        },
        {
          revokeSession: vi.fn(async () => undefined),
          clearSession: vi.fn(async () => {
            throw new Error("credential store unavailable");
          }),
          removeProfile,
        },
      ),
    ).rejects.toThrow("credential store unavailable");
    expect(removeProfile).not.toHaveBeenCalled();
  });

  it("retains relay retry state when paged Cloud revocation is interrupted", async () => {
    const clearSession = vi.fn();
    const removeProfile = vi.fn();
    await expect(
      devicesRuntimesInternals.revokeRelayAuthorityWithCleanup(
        {
          sessionId: SESSION.id,
          ownerId: SESSION.ownerId,
          controllerDeviceId: CONTROLLER.deviceId,
          profile: PROFILE,
        },
        {
          revokeSession: vi.fn(async () => {
            throw new Error("session cleanup interrupted");
          }),
          clearSession,
          removeProfile,
        },
      ),
    ).rejects.toThrow("session cleanup interrupted");
    expect(clearSession).not.toHaveBeenCalled();
    expect(removeProfile).not.toHaveBeenCalled();
  });

  it("rejects a restored relay session whose target key differs from its host", () => {
    expect(() =>
      devicesRuntimesInternals.restoredRelayProfile(
        HOST,
        { ...SESSION, targetKeyId: "different-target-key" },
        CONTROLLER,
      ),
    ).toThrow("target key does not match");
    expect(
      devicesRuntimesInternals.restoredRelayProfile(
        HOST,
        { ...SESSION, targetKeyId: HOST.runtimeKeyId },
        CONTROLLER,
      ).remoteRelay,
    ).toMatchObject({
      targetKeyId: HOST.runtimeKeyId,
      targetSigningPublicKeyJwk: HOST.signingPublicKeyJwk,
      targetEncryptionPublicKeyJwk: HOST.encryptionPublicKeyJwk,
    });
  });

  it("deduplicates a paired relay profile from its host summary card", () => {
    const ownSession = {
      ...SESSION,
      controllerDeviceId: CONTROLLER.deviceId,
      controllerKeyId: CONTROLLER.keyId,
    };
    const targets = devicesRuntimesInternals.buildRuntimeTargets(
      {
        version: 1,
        activeProfileId: PROFILE.id,
        profiles: [PROFILE],
      },
      new Map(),
      { ownerId: "owner-1", hosts: [HOST] },
      new Map([[HOST.id, [ownSession]]]),
      CONTROLLER,
    );
    expect(targets.map((target) => target.id)).toEqual([PROFILE.id]);
  });

  it("delegates active fallback and profile deletion to one atomic operation", async () => {
    const removeRuntimeProfile = vi.fn(async () => ({ ok: true }));

    await devicesRuntimesInternals.removeProfileWithoutStaleSelection(
      PROFILE.id,
      { removeRuntimeProfile },
    );

    expect(removeRuntimeProfile).toHaveBeenCalledOnce();
    expect(removeRuntimeProfile).toHaveBeenCalledWith(PROFILE.id);
  });

  it("reports an atomic fallback/deletion persistence failure", async () => {
    await expect(
      devicesRuntimesInternals.removeProfileWithoutStaleSelection(PROFILE.id, {
        removeRuntimeProfile: vi.fn(async () => ({
          ok: false,
          reason: "persistence-failed",
        })),
      }),
    ).rejects.toThrow("fallback or cleared selection could not be saved");
  });

  it("reports a protected clear rejection without issuing another removal", async () => {
    const removeRuntimeProfile = vi.fn(async () => {
      throw new Error("protected delete rejected");
    });

    await expect(
      devicesRuntimesInternals.removeProfileWithoutStaleSelection(PROFILE.id, {
        removeRuntimeProfile,
      }),
    ).rejects.toThrow("protected delete rejected");
    expect(removeRuntimeProfile).toHaveBeenCalledOnce();
  });

  it("refuses removal of the build-pinned runtime", async () => {
    await expect(
      devicesRuntimesInternals.removeProfileWithoutStaleSelection(PROFILE.id, {
        removeRuntimeProfile: vi.fn(async () => ({
          ok: false,
          reason: "build-pinned",
        })),
      }),
    ).rejects.toThrow("requires its configured remote runtime");
  });

  it("revokes a Linux host in Cloud before native credential cleanup", async () => {
    const events: string[] = [];
    await devicesRuntimesInternals.revokeLinuxHostCloudFirst("host-1", {
      revokeHost: vi.fn(async () => {
        events.push("cloud");
      }),
      finalizeLocal: vi.fn(async () => {
        events.push("native");
        return true;
      }),
    });
    expect(events).toEqual(["cloud", "native"]);

    const finalizeLocal = vi.fn();
    await expect(
      devicesRuntimesInternals.revokeLinuxHostCloudFirst("host-1", {
        revokeHost: vi.fn(async () => {
          throw new Error("Cloud unavailable");
        }),
        finalizeLocal,
      }),
    ).rejects.toThrow("Cloud unavailable");
    expect(finalizeLocal).not.toHaveBeenCalled();
  });

  it("preserves the SSH start failure when credential cleanup also fails", async () => {
    const startCause = new Error("Tunnel failed");
    const cleanupCause = new Error("Credential cleanup failed");
    const operation = devicesRuntimesInternals.startSshWithCredentialCleanup(
      "runtime-1",
      {
        label: "Studio",
        target: "studio.example.com",
        sshPort: 22,
        remoteApiPort: 3000,
        expectedFingerprint: "SHA256:trusted",
        accessToken: "secret-token",
      },
      {
        start: vi.fn(async () => {
          throw startCause;
        }),
        deleteCredential: vi.fn(async () => {
          throw cleanupCause;
        }),
      },
    );

    await expect(operation).rejects.toMatchObject({
      cause: startCause,
      errors: [startCause, cleanupCause],
    });
  });
});
