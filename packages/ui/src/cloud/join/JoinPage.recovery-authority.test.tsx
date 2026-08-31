/** Verifies /join cannot publish account A after login B reserves recovery. */
// @vitest-environment jsdom
// @vitest-environment-options {"url": "https://cloud.eliza.app/join"}

import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginStewardSessionRecovery,
  rejectStewardSessionRecovery,
} from "../lib/steward-session-recovery-marker";

const stubs = vi.hoisted(() => ({
  getPersonalSharedEliza: vi.fn(),
  persistAgentProfileConnectionDurably: vi.fn(),
  publishPersonalEntryHandoff: vi.fn(),
  savePersistedFirstRunComplete: vi.fn(),
  stageSessionTarget: vi.fn(),
}));

vi.mock("react-router-dom", () => ({
  Navigate: ({ to }: { to: string }) => <div data-testid="navigate">{to}</div>,
}));

vi.mock("../../api", () => ({
  client: {
    getPersonalSharedEliza: stubs.getPersonalSharedEliza,
    stageSessionTarget: stubs.stageSessionTarget,
  },
}));

vi.mock("../../state/agent-profiles", () => ({
  persistAgentProfileConnectionDurably:
    stubs.persistAgentProfileConnectionDurably,
}));

vi.mock("../../state/persistence", () => ({
  createPersistedActiveServer: (value: object) => value,
  savePersistedFirstRunComplete: stubs.savePersistedFirstRunComplete,
}));

vi.mock("../app-mode/app-mode", () => ({
  appModeNavigation: { assign: vi.fn(), replace: vi.fn() },
}));

vi.mock("../app-mode/use-personal-entry", () => ({
  publishPersonalEntryHandoff: stubs.publishPersonalEntryHandoff,
}));

vi.mock("../shell/CloudI18nProvider", () => ({
  useCloudT: () => (_key: string, options?: { defaultValue?: string }) =>
    options?.defaultValue ?? "",
}));

vi.mock("../sso-bridge/sso-bridge", () => ({
  redirectToSsoBridge: vi.fn(async () => false),
  shouldAutoBridgeToSso: vi.fn(() => false),
}));

vi.mock("./lib/apex-app-handoff", () => ({
  resolveApexJoinHandoff: () => null,
}));

vi.mock("./lib/resolve-cloud-connection", () => ({
  resolveJoinAuthToken: () =>
    window.localStorage.getItem("steward_session_token"),
  resolveJoinCloudApiBase: () => "https://api.eliza.app",
}));

vi.mock("./lib/use-join-session", () => ({
  useJoinSessionAuth: () => ({
    ready: true,
    authenticated: true,
    authToken: window.localStorage.getItem("steward_session_token"),
  }),
}));

import JoinPage from "./JoinPage";

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  localStorage.setItem("steward_session_token", "account-a-token");
});

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe("JoinPage recovery authority", () => {
  it("does not persist, retarget, complete, or hand off A when login B begins during its personal GET", async () => {
    let releasePersonal!: () => void;
    const personalReleased = new Promise<void>((resolve) => {
      releasePersonal = resolve;
    });
    stubs.getPersonalSharedEliza.mockImplementationOnce(async () => {
      await personalReleased;
      return {
        personalElizaId: "personal:00000000-0000-5000-8000-000000000001",
        activeAgentId: "shared-runtime-a",
        agentName: "Eliza A",
        apiBase: "https://api.eliza.app/api/v1/eliza/agents/shared-runtime-a",
        runtime: "shared" as const,
      };
    });
    render(<JoinPage />);
    await waitFor(() =>
      expect(stubs.getPersonalSharedEliza).toHaveBeenCalledTimes(1),
    );

    let loginB!: ReturnType<typeof beginStewardSessionRecovery>;
    act(() => {
      loginB = beginStewardSessionRecovery("elizacloud", "provider");
    });
    try {
      await act(async () => {
        releasePersonal();
        await personalReleased;
      });
      await waitFor(() => {
        expect(
          stubs.persistAgentProfileConnectionDurably,
        ).not.toHaveBeenCalled();
        expect(stubs.stageSessionTarget).not.toHaveBeenCalled();
        expect(stubs.savePersistedFirstRunComplete).not.toHaveBeenCalled();
        expect(stubs.publishPersonalEntryHandoff).not.toHaveBeenCalled();
      });
      expect(screen.queryByTestId("navigate")).toBeNull();
    } finally {
      cleanup();
      rejectStewardSessionRecovery(loginB);
    }
  });
});
