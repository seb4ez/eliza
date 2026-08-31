/** Verifies that managed-app /join completes the PKCE SSO bridge before resolving the account-native personal Eliza. */
// @vitest-environment jsdom
// @vitest-environment-options {"url": "https://cloud.eliza.app/join"}

import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { appModeNavigation } from "../app-mode/app-mode";
import { markSsoLoggedOut } from "../sso-bridge/sso-bridge";

const { authenticatedRef, publishHandoffMock, runJoinFlowMock, tokenRef } =
  vi.hoisted(() => ({
    authenticatedRef: { current: false },
    publishHandoffMock: vi.fn(),
    runJoinFlowMock: vi.fn(),
    tokenRef: { current: "steward-token" },
  }));

vi.mock("react-router-dom", () => ({
  Navigate: ({ to }: { to: string }) => <div data-testid="navigate">{to}</div>,
}));

vi.mock("./lib/use-join-session", () => ({
  useJoinSessionAuth: () => ({
    ready: true,
    authenticated: authenticatedRef.current,
    authToken: authenticatedRef.current ? tokenRef.current : null,
  }),
}));

vi.mock("./lib/run-join-flow", () => ({
  runJoinFlow: runJoinFlowMock,
}));

vi.mock("./lib/resolve-cloud-connection", () => ({
  resolveJoinAuthToken: () => tokenRef.current,
  resolveJoinCloudApiBase: () => "https://api.eliza.app",
}));

vi.mock("../app-mode/use-personal-entry", () => ({
  publishPersonalEntryHandoff: publishHandoffMock,
}));

vi.mock("../shell/CloudI18nProvider", () => ({
  useCloudT: () => (_key: string, options?: { defaultValue?: string }) =>
    options?.defaultValue ?? "",
}));

import JoinPage from "./JoinPage";

const realReplace = appModeNavigation.replace;
const realAssign = appModeNavigation.assign;
let replacedUrls: string[];
let assignedUrls: string[];

beforeEach(() => {
  authenticatedRef.current = false;
  tokenRef.current = "steward-token";
  localStorage.setItem("steward_session_token", tokenRef.current);
  publishHandoffMock.mockReset();
  runJoinFlowMock.mockReset();
  replacedUrls = [];
  assignedUrls = [];
  appModeNavigation.replace = (url: string) => replacedUrls.push(url);
  appModeNavigation.assign = (url: string) => assignedUrls.push(url);
});

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
  // biome-ignore lint/suspicious/noDocumentCookie: jsdom exposes no Cookie Store API.
  document.cookie =
    "steward-authed=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  appModeNavigation.replace = realReplace;
  appModeNavigation.assign = realAssign;
});

describe("JoinPage managed-app SSO handoff", () => {
  it("bridges a live apex session back to /join before identity resolution", async () => {
    // biome-ignore lint/suspicious/noDocumentCookie: jsdom exposes no Cookie Store API.
    document.cookie = "steward-authed=1; path=/";
    render(<JoinPage />);

    await waitFor(() => expect(replacedUrls).toHaveLength(1));
    const bridge = new URL(replacedUrls[0]);
    expect(bridge.origin).toBe("https://eliza.app");
    expect(bridge.pathname).toBe("/auth/bridge");
    expect(bridge.searchParams.get("returnTo")).toBe("/join");
    expect(bridge.searchParams.get("state")).toMatch(/^[0-9a-f]{64}$/);
    expect(bridge.searchParams.get("challenge")).toMatch(/^[0-9a-f]{64}$/);
    expect(runJoinFlowMock).not.toHaveBeenCalled();
    expect(screen.queryByTestId("navigate")).toBeNull();
  });

  it("falls back to the local login after an explicit logout", async () => {
    markSsoLoggedOut();
    render(<JoinPage />);

    expect((await screen.findByTestId("navigate")).textContent).toBe(
      "/login?returnTo=/join",
    );
    expect(replacedUrls).toEqual([]);
    expect(runJoinFlowMock).not.toHaveBeenCalled();
  });

  it("resolves identity exactly once after the bridge restores authentication", async () => {
    authenticatedRef.current = true;
    runJoinFlowMock.mockResolvedValue({ agentId: "agent-1" });
    render(<JoinPage />);

    await waitFor(() => expect(runJoinFlowMock).toHaveBeenCalledTimes(1));
    expect((await screen.findByTestId("navigate")).textContent).toBe("/");
    expect(assignedUrls).toEqual([]);
    expect(replacedUrls).toEqual([]);
  });

  it("does not erase an in-flight logout marker while old auth is still rendered", async () => {
    authenticatedRef.current = true;
    markSsoLoggedOut();
    runJoinFlowMock.mockResolvedValue({ agentId: "agent-1" });
    render(<JoinPage />);

    await waitFor(() => expect(runJoinFlowMock).toHaveBeenCalledTimes(1));
    expect(localStorage.getItem("eliza_sso_logged_out")).toBe("1");
  });

  it("restarts a join request cancelled by the StrictMode probe", async () => {
    authenticatedRef.current = true;
    runJoinFlowMock
      .mockImplementationOnce(
        ({ signal }: { signal: AbortSignal }) =>
          new Promise((_resolve, reject) => {
            signal.addEventListener("abort", () => reject(signal.reason), {
              once: true,
            });
          }),
      )
      .mockResolvedValueOnce({ agentId: "agent-1" });

    render(
      <StrictMode>
        <JoinPage />
      </StrictMode>,
    );

    await waitFor(() => expect(runJoinFlowMock).toHaveBeenCalledTimes(2));
    expect((await screen.findByTestId("navigate")).textContent).toBe("/");
  });

  it("restarts for token B and suppresses every late publication from token A", async () => {
    authenticatedRef.current = true;
    let finishA: ((value: { agentId: string }) => void) | null = null;
    let finishB: ((value: { agentId: string }) => void) | null = null;
    let accountAProgress: ((status: string, detail?: string) => void) | null =
      null;
    runJoinFlowMock
      .mockImplementationOnce(
        ({
          onProgress,
        }: {
          onProgress: (status: string, detail?: string) => void;
        }) => {
          accountAProgress = onProgress;
          return new Promise((resolve) => {
            finishA = resolve;
          });
        },
      )
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            finishB = resolve;
          }),
      );

    const view = render(<JoinPage />);
    await waitFor(() => expect(runJoinFlowMock).toHaveBeenCalledTimes(1));

    tokenRef.current = "steward-token-b";
    localStorage.setItem("steward_session_token", tokenRef.current);
    view.rerender(<JoinPage />);

    await waitFor(() => expect(runJoinFlowMock).toHaveBeenCalledTimes(2));
    expect(runJoinFlowMock.mock.calls[0]?.[0].validateAuthority()).toBe(false);
    expect(runJoinFlowMock.mock.calls[1]?.[0].validateAuthority()).toBe(true);
    await act(async () => {
      finishB?.({ agentId: "agent-b" });
    });
    expect((await screen.findByTestId("navigate")).textContent).toBe("/");

    await act(async () => {
      accountAProgress?.("connecting", "Wrong account A");
      finishA?.({ agentId: "agent-a" });
    });

    expect(publishHandoffMock).toHaveBeenCalledTimes(1);
    expect(publishHandoffMock).toHaveBeenCalledWith(
      "steward-token-b",
      expect.objectContaining({ agentId: "agent-b" }),
    );
    expect(screen.queryByText("Wrong account A")).toBeNull();
  });
});
