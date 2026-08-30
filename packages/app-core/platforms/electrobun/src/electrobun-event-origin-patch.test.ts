import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";

const require = createRequire(import.meta.url);
const packageRoot = join(
  dirname(require.resolve("electrobun/bun")),
  "../../..",
);
const installedNativeSource = readFileSync(
  join(packageRoot, "dist/api/bun/proc/native.ts"),
  "utf8",
);
const installedRpcPath = join(packageRoot, "dist/api/shared/rpc.ts");
const installedRpcSource = readFileSync(installedRpcPath, "utf8");
const generatedPreloadSource = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "preload.js"),
  "utf8",
);
const patchSource = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    "../../../../../patches/electrobun@1.18.1.patch",
  ),
  "utf8",
);

const rendererEventAllowlist = new Set([
  "dom-ready",
  "did-navigate-in-page",
  "new-window-open",
  "host-message",
]);

function readPatchedRendererAllowlists(source: string): string[][] {
  const normalizedSource = source.replace(/^\+/gm, "");
  return Array.from(
    normalizedSource.matchAll(
      /payload\?\.id !== _id \|\|\s*!\[([\s\S]*?)\]\.includes\(payload\?\.eventName\)/g,
    ),
    (match) =>
      Array.from(
        match[1]?.matchAll(/"([^"]+)"/g) ?? [],
        (item) => item[1] ?? "",
      ),
  );
}

function acceptsRendererEvent(
  sourceWebviewId: number,
  payload: { eventName: string; id: number },
): boolean {
  return (
    payload.id === sourceWebviewId &&
    rendererEventAllowlist.has(payload.eventName)
  );
}

describe("Electrobun renderer event-origin patch", () => {
  it("keeps both renderer bridges bound to their native id and renderer-only allowlist", () => {
    expect(installedNativeSource.match(/payload\?\.id !== _id/g)).toHaveLength(
      2,
    );
    expect(
      installedNativeSource.match(
        /webviewEventHandler\(_id, payload\.eventName, payload\.detail\)/g,
      ),
    ).toHaveLength(2);
    expect(patchSource.match(/payload\?\.id !== _id/g)).toHaveLength(2);
    expect(readPatchedRendererAllowlists(installedNativeSource)).toEqual([
      Array.from(rendererEventAllowlist),
      Array.from(rendererEventAllowlist),
    ]);
    expect(readPatchedRendererAllowlists(patchSource)).toEqual([
      Array.from(rendererEventAllowlist),
      Array.from(rendererEventAllowlist),
    ]);

    expect(acceptsRendererEvent(7, { id: 8, eventName: "dom-ready" })).toBe(
      false,
    );
    expect(
      acceptsRendererEvent(7, {
        id: 7,
        eventName: "did-commit-navigation",
      }),
    ).toBe(false);
    expect(acceptsRendererEvent(7, { id: 7, eventName: "will-navigate" })).toBe(
      false,
    );
    expect(acceptsRendererEvent(7, { id: 7, eventName: "dom-ready" })).toBe(
      true,
    );
    expect(acceptsRendererEvent(7, { id: 7, eventName: "host-message" })).toBe(
      true,
    );
  });

  it("keeps late A responses isolated from B when both documents reuse request id 1", async () => {
    expect(installedRpcSource).toContain("instanceId: rpcInstanceId");
    expect(installedRpcSource).toContain(
      "if (message.instanceId !== rpcInstanceId) return;",
    );
    expect(patchSource).toContain("instanceId: rpcInstanceId");
    expect(patchSource).toContain(
      "if (message.instanceId !== rpcInstanceId) return;",
    );
    expect(generatedPreloadSource).toContain("instanceId");
    expect(generatedPreloadSource).toContain(
      "RPC instance isolation requires secure randomness.",
    );

    const { createRPC } = (await import(
      pathToFileURL(installedRpcPath).href
    )) as {
      createRPC(options: Record<string, unknown>): {
        request(
          method: string,
          params: { document: "A" | "B" },
        ): Promise<string>;
      };
    };
    type PacketHandler = (packet: unknown) => void | Promise<void>;
    const resolvers = new Map<"A" | "B", (value: string) => void>();
    let hostHandler: PacketHandler | null = null;
    let currentClientHandler: PacketHandler | null = null;

    createRPC({
      maxRequestTime: Number.POSITIVE_INFINITY,
      requestHandler: async (
        _method: string,
        params: { document: "A" | "B" },
      ) =>
        await new Promise<string>((resolve) => {
          resolvers.set(params.document, resolve);
        }),
      transport: {
        registerHandler(handler: PacketHandler) {
          hostHandler = handler;
        },
        send(packet: unknown) {
          void currentClientHandler?.(packet);
        },
      },
    });

    const createClient = (): {
      handler: PacketHandler;
      request: (
        method: string,
        params: { document: "A" | "B" },
      ) => Promise<string>;
    } => {
      let clientHandler: PacketHandler | null = null;
      const rpc = createRPC({
        maxRequestTime: Number.POSITIVE_INFINITY,
        transport: {
          registerHandler(handler: PacketHandler) {
            clientHandler = handler;
          },
          send(packet: unknown) {
            void hostHandler?.(packet);
          },
        },
      });
      if (!clientHandler) throw new Error("client RPC handler missing");
      return {
        handler: clientHandler,
        request: rpc.request.bind(rpc),
      };
    };

    const clientA = createClient();
    currentClientHandler = clientA.handler;
    void clientA.request("read", { document: "A" });
    await vi.waitFor(() => expect(resolvers.has("A")).toBe(true));

    const clientB = createClient();
    currentClientHandler = clientB.handler;
    let resultB: string | null = null;
    const pendingB = clientB
      .request("diagnostic", { document: "B" })
      .then((value) => {
        resultB = value;
        return value;
      });
    await vi.waitFor(() => expect(resolvers.has("B")).toBe(true));

    resolvers.get("A")?.("secret-token-a");
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(resultB).toBeNull();

    resolvers.get("B")?.("response-b");
    await expect(pendingB).resolves.toBe("response-b");
    expect(resultB).toBe("response-b");
  });
});
