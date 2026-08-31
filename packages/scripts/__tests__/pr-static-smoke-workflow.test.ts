/** Verifies PR admission combines static, auth, billing, and Windows security lanes. */

import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { assertUiSmokePlaywrightReport } from "../../app/scripts/ui-smoke-pr-specs.mjs";
import { listPackages } from "../lib/workspaces.mjs";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));
const source = readFileSync(
  join(repoRoot, ".github/workflows/pr-static-smoke.yml"),
  "utf8",
);
const workflowReadme = readFileSync(
  join(repoRoot, ".github/workflows/README.md"),
  "utf8",
);

interface WorkflowStep {
  id?: string;
  name?: string;
  if?: string;
  uses?: string;
  env?: Record<string, string>;
  run?: string;
  with?: Record<string, unknown>;
}

interface WorkflowJob {
  name?: string;
  uses?: string;
  needs?: string[];
  env?: Record<string, string>;
  steps?: WorkflowStep[];
}

const workflow = Bun.YAML.parse(source) as {
  concurrency?: { group?: string; "cancel-in-progress"?: boolean };
  jobs?: Record<string, WorkflowJob>;
};
const scenarioSource = readFileSync(
  join(repoRoot, ".github/workflows/scenario-pr.yml"),
  "utf8",
);
const scenarioWorkflow = Bun.YAML.parse(scenarioSource) as {
  jobs?: Record<string, WorkflowJob>;
};

function requireJob(candidate: typeof workflow, name: string): WorkflowJob {
  const job = candidate.jobs?.[name];
  expect(job, `missing workflow job: ${name}`).toBeDefined();
  return job ?? {};
}

function requireStep(job: WorkflowJob, name: string): WorkflowStep {
  const step = job.steps?.find((candidate) => candidate.name === name);
  expect(step, `missing workflow step: ${name}`).toBeDefined();
  return step ?? {};
}

function passingReport(expectedFile: string, tests: number): unknown {
  return passingReportForFiles([{ file: expectedFile, tests }]);
}

function passingReportForFiles(
  expectedFiles: Array<{ file: string; tests: number }>,
): unknown {
  const tests = expectedFiles.reduce((total, entry) => total + entry.tests, 0);
  return {
    errors: [],
    stats: {
      expected: tests,
      unexpected: 0,
      flaky: 0,
      skipped: 0,
    },
    suites: [
      {
        specs: expectedFiles.flatMap((entry) =>
          Array.from({ length: entry.tests }, (_, index) => ({
            file: entry.file,
            ok: true,
            title: `${entry.file} behavior ${index + 1}`,
            tests: [
              {
                expectedStatus: "passed",
                status: "expected",
                results: [{ status: "passed" }],
              },
            ],
          })),
        ),
      },
    ],
  };
}

function splitWords(value: string | undefined): string[] {
  return value?.trim().split(/\s+/).filter(Boolean) ?? [];
}

function githubExpression(value: string): string {
  return `\${{ ${value} }}`;
}

function workspaceClosure(seedDirs: readonly string[]): Set<string> {
  const workspaces = listPackages({ repoRoot });
  const byName = new Map(
    workspaces
      .filter(
        (workspace): workspace is typeof workspace & { name: string } =>
          typeof workspace.name === "string" && workspace.name.length > 0,
      )
      .map((workspace) => [workspace.name, workspace]),
  );
  const seeds = workspaces.filter(({ dir }) => seedDirs.includes(dir));
  expect(seeds.map(({ dir }) => dir).sort()).toEqual([...seedDirs].sort());

  const closure = new Set<string>();
  const pending = seeds.map(({ name }) => name);
  while (pending.length > 0) {
    const name = pending.pop();
    if (!name) continue;
    const workspace = byName.get(name);
    if (!workspace || closure.has(workspace.dir)) continue;
    closure.add(workspace.dir);
    for (const dependency of Object.keys({
      ...workspace.packageJson.dependencies,
      ...workspace.packageJson.optionalDependencies,
      ...workspace.packageJson.peerDependencies,
    })) {
      if (byName.has(dependency)) pending.push(dependency);
    }
  }
  return closure;
}

describe("PR Static Smoke workflow", () => {
  test("owns cancelable source, auth, billing, and Windows lanes behind the stable admission context", () => {
    expect(workflow.concurrency?.group).toContain(
      "github.event.pull_request.number",
    );
    expect(workflow.concurrency?.["cancel-in-progress"]).toBeTrue();
    expect(Object.keys(workflow.jobs ?? {})).toEqual([
      "source-smoke",
      "billing-payment-replay-e2e",
      "auth-session-admission",
      "browser-bridge-windows-security",
      "static-smoke",
    ]);
    expect(workflow.jobs?.["browser-bridge-windows-security"]?.uses).toBe(
      "./.github/workflows/browser-bridge-windows-security.yml",
    );
    expect(workflow.jobs?.["static-smoke"]?.needs).toEqual([
      "source-smoke",
      "browser-bridge-windows-security",
      "billing-payment-replay-e2e",
      "auth-session-admission",
    ]);
    expect(workflow.jobs?.["static-smoke"]?.name).toBe("All Tests Passed");
  });

  test("runs exact-head auth behavior and rejects vacuous browser success", () => {
    const authJob = requireJob(workflow, "auth-session-admission");
    const checkout = authJob.steps?.find((step) =>
      step.uses?.startsWith("actions/checkout@"),
    );
    expect(checkout?.with?.ref).toBe(
      githubExpression(
        "github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.event.merge_group.head_sha",
      ),
    );
    expect(checkout?.with?.["fetch-depth"]).toBe(0);
    expect(checkout?.with?.["persist-credentials"]).toBeFalse();

    const detect = requireStep(authJob, "Detect auth/session contract changes");
    expect(detect.run).toContain('git merge-base "$BASE_SHA" "$HEAD_SHA"');
    expect(detect.run).toContain(
      'git diff --quiet "$merge_base"..."$HEAD_SHA"',
    );
    expect(splitWords(authJob.env?.AUTH_ADMISSION_PATH_INPUTS)).toEqual(
      expect.arrayContaining([
        "packages/app",
        "packages/app-core",
        "packages/auth",
        "packages/cloud",
        "packages/shared",
        "packages/ui",
        "patches",
        ".github/workflows/pr-static-smoke.yml",
        ".github/workflows/scenario-pr.yml",
      ]),
    );

    expect(
      requireStep(authJob, "Run shared Steward session authority tests").run,
    ).toContain(
      "bun run --cwd packages/shared test -- src/steward-session-client/index.test.ts",
    );
    const nativeSecureStore = requireStep(
      authJob,
      "Run native secure-store authority tests",
    ).run;
    expect(nativeSecureStore).toContain(
      "packages/app-core/platforms/electrobun/src/renderer-secure-store-authority.test.ts",
    );
    expect(nativeSecureStore).toContain(
      "packages/app-core/platforms/electrobun/src/renderer-secure-store-transaction.test.ts",
    );
    expect(nativeSecureStore).toContain(
      "packages/app-core/platforms/electrobun/src/renderer-secure-store-revisions.test.ts",
    );
    expect(
      requireStep(authJob, "Run wallet recovery retry regression tests").run,
    ).toContain(
      "bun run --cwd packages/ui test -- src/cloud/public-pages/pages/login/steward-login-section.wallet-collapse.test.tsx",
    );

    const production = requireStep(
      authJob,
      "Run production-mode hosted wallet authority proof",
    );
    expect(production.env?.VITE_PLAYWRIGHT_TEST_AUTH).toBe("false");
    expect(production.run).toContain(
      "test/ui-smoke/hosted-signin-wallet-capability.spec.ts",
    );
    expect(production.run).toContain("--project=chromium --reporter=json");
    expect(
      requireStep(authJob, "Require non-vacuous hosted wallet authority proof")
        .run,
    ).toContain("--assert-report hosted-signin-wallet-capability");

    const cli = requireStep(authJob, "Run CLI auth completion proof");
    expect(cli.env?.VITE_PLAYWRIGHT_TEST_AUTH).toBe("true");
    expect(cli.env?.ELIZA_UI_SMOKE_SKIP_VIEW_BUILD).toBe("1");
    expect(cli.run).toContain("test/ui-smoke/cli-auth-completion.spec.ts");
    expect(cli.run).toContain("--project=chromium --reporter=json");
    expect(
      requireStep(authJob, "Require two CLI auth completions with zero skipped")
        .run,
    ).toContain("--assert-report cli-auth-completion");

    const supplemental = requireStep(
      authJob,
      "Run supplemental test-authenticated managed surfaces",
    );
    expect(supplemental.env?.VITE_PLAYWRIGHT_TEST_AUTH).toBe("true");
    expect(supplemental.env?.ELIZA_UI_SMOKE_SKIP_VIEW_BUILD).toBe("1");
    expect(supplemental.run).toContain("--list-test-auth-supplemental");
    expect(supplemental.run).toContain("cloud console route wiring");
    expect(supplemental.run).toContain("--reporter=json");
    expect(
      requireStep(
        authJob,
        "Require nine supplemental test-auth passes with zero skipped",
      ).run,
    ).toContain("--assert-report test-auth-supplemental");

    const guarded = authJob.steps?.slice(2) ?? [];
    expect(guarded.length).toBeGreaterThan(0);
    for (const step of guarded) {
      expect(step.if).toBe("steps.auth-diff.outputs.run == 'true'");
    }

    const sourceContracts = requireStep(
      requireJob(workflow, "source-smoke"),
      "Test PR admission and Cloud Pages workflow contracts",
    ).run;
    expect(sourceContracts).toContain(
      "packages/scripts/__tests__/pr-static-smoke-workflow.test.ts",
    );

    const admission = requireStep(
      requireJob(workflow, "static-smoke"),
      "Require every admission lane",
    );
    expect(admission.env?.RESULTS).toContain(
      `auth-session-admission=${githubExpression("needs.auth-session-admission.result")}`,
    );
  });

  test("the report verifier accepts only exact non-skipped auth results", () => {
    const valid = passingReport("test/ui-smoke/cli-auth-completion.spec.ts", 2);
    expect(assertUiSmokePlaywrightReport(valid, "cli-auth-completion")).toEqual(
      {
        contract: "cli-auth-completion",
        files: ["test/ui-smoke/cli-auth-completion.spec.ts"],
        passed: 2,
      },
    );

    const allSkipped = structuredClone(valid) as {
      stats: { expected: number; skipped: number };
    };
    allSkipped.stats.expected = 0;
    allSkipped.stats.skipped = 2;
    expect(() =>
      assertUiSmokePlaywrightReport(allSkipped, "cli-auth-completion"),
    ).toThrow("expected stats.expected=2");

    const hiddenSkip = structuredClone(valid) as {
      suites: Array<{
        specs: Array<{
          tests: Array<{
            expectedStatus: string;
            status: string;
            results: Array<{ status: string }>;
          }>;
        }>;
      }>;
    };
    hiddenSkip.suites[0].specs[0].tests[0] = {
      expectedStatus: "skipped",
      status: "skipped",
      results: [{ status: "skipped" }],
    };
    expect(() =>
      assertUiSmokePlaywrightReport(hiddenSkip, "cli-auth-completion"),
    ).toThrow("was not an expected pass");

    const supplemental = passingReportForFiles([
      { file: "test/ui-smoke/cloud-console-routes.spec.ts", tests: 3 },
      { file: "test/ui-smoke/managed-login-stability.spec.ts", tests: 6 },
    ]);
    expect(
      assertUiSmokePlaywrightReport(supplemental, "test-auth-supplemental"),
    ).toEqual({
      contract: "test-auth-supplemental",
      files: [
        "test/ui-smoke/cloud-console-routes.spec.ts",
        "test/ui-smoke/managed-login-stability.spec.ts",
      ],
      passed: 9,
    });

    const wrongPerFileCount = structuredClone(supplemental) as {
      suites: Array<{ specs: Array<{ file: string }> }>;
    };
    wrongPerFileCount.suites[0].specs[0].file =
      "test/ui-smoke/managed-login-stability.spec.ts";
    expect(() =>
      assertUiSmokePlaywrightReport(
        wrongPerFileCount,
        "test-auth-supplemental",
      ),
    ).toThrow(
      "expected 3 test(s) from test/ui-smoke/cloud-console-routes.spec.ts, received 2",
    );
  });

  test("keeps Scenario auto-discovery production-mode and supplements its test-auth coverage", () => {
    const auto = requireStep(
      requireJob(scenarioWorkflow, "app-browser-auto-discovered"),
      "Actual app auto-discovered ui-smoke browser coverage",
    );
    expect(auto.env?.VITE_PLAYWRIGHT_TEST_AUTH).toBeUndefined();

    const authEnvSteps = Object.entries(scenarioWorkflow.jobs ?? {}).flatMap(
      ([jobName, job]) =>
        (job.steps ?? [])
          .filter((step) => step.env?.VITE_PLAYWRIGHT_TEST_AUTH !== undefined)
          .map((step) => ({
            jobName,
            stepName: step.name,
            value: step.env?.VITE_PLAYWRIGHT_TEST_AUTH,
          })),
    );
    expect(authEnvSteps).toEqual([
      {
        jobName: "app-browser-cli-auth-completion",
        stepName: "Actual CLI auth completion browser coverage",
        value: "true",
      },
      {
        jobName: "app-browser-cli-auth-completion",
        stepName: "Actual supplemental test-authenticated managed surfaces",
        value: "true",
      },
    ]);

    const cliJob = requireJob(
      scenarioWorkflow,
      "app-browser-cli-auth-completion",
    );
    expect(
      requireStep(cliJob, "Require two CLI auth completions with zero skipped")
        .run,
    ).toContain("--assert-report cli-auth-completion");
    expect(
      requireStep(
        cliJob,
        "Require nine supplemental test-auth passes with zero skipped",
      ).run,
    ).toContain("--assert-report test-auth-supplemental");
    const aggregate = requireJob(scenarioWorkflow, "deterministic-scenario");
    expect(aggregate.needs).toContain("app-browser-cli-auth-completion");
    expect(
      requireStep(aggregate, "Check deterministic E2E slices").run,
    ).toContain(
      `app-browser-cli-auth-completion:${githubExpression("needs.app-browser-cli-auth-completion.result")}`,
    );

    const inventory = JSON.parse(
      execFileSync(
        process.execPath,
        [
          join(repoRoot, "packages/app/scripts/ui-smoke-pr-specs.mjs"),
          "--json",
        ],
        { encoding: "utf8" },
      ),
    ) as {
      autoDiscovered: string[];
      namedInWorkflow: string[];
      testAuthSupplemental: string[];
    };
    expect(inventory.autoDiscovered).not.toContain(
      "cli-auth-completion.spec.ts",
    );
    expect(inventory.namedInWorkflow).toContain("cli-auth-completion.spec.ts");
    expect(inventory.testAuthSupplemental).toEqual([
      "cloud-console-routes.spec.ts",
      "managed-login-stability.spec.ts",
    ]);
    for (const spec of inventory.testAuthSupplemental) {
      expect(inventory.autoDiscovered).toContain(spec);
      expect(inventory.namedInWorkflow).not.toContain(spec);
    }
  });

  test("runs billing replay in parallel and fails closed over its contract surface", () => {
    const billingJob = workflow.jobs?.["billing-payment-replay-e2e"];
    expect(billingJob?.needs).toBeUndefined();

    const workspaceSeeds = splitWords(
      billingJob?.env?.BILLING_REPLAY_WORKSPACE_SEEDS,
    );
    expect(workspaceSeeds).toEqual([
      "packages/cloud/api",
      "packages/cloud/e2e",
      "packages/cloud/shared",
      "packages/ui",
    ]);
    const closure = workspaceClosure(workspaceSeeds);
    expect([...closure]).toEqual(
      expect.arrayContaining([
        "packages/cloud/api",
        "packages/cloud/e2e",
        "packages/cloud/shared",
        "packages/core",
        "packages/logger",
        "packages/prompts",
        "packages/registry",
        "packages/shared",
        "packages/ui",
        "plugins/plugin-cloud-apps",
        "plugins/plugin-elizacloud",
        "plugins/plugin-sql",
      ]),
    );

    const explicitInputs = splitWords(
      billingJob?.env?.BILLING_REPLAY_PATH_INPUTS,
    );
    expect(explicitInputs).toEqual(
      expect.arrayContaining([
        "packages/cloud",
        "packages/app",
        "packages/app-core",
        "packages/scripts",
        ".github/actions/cloud-setup-test-env",
        ".github/develop-surface-graph.json",
        ".github/workflows/develop-full.yml",
        ".github/workflows/pr-static-smoke.yml",
        ".github/workflows/cloud-tests.yml",
      ]),
    );

    const detect = billingJob?.steps?.find(
      (step) => step.id === "billing-diff",
    )?.run;
    expect(detect).toContain("listPackages");
    expect(detect).toContain('git(["merge-base", baseSha, headSha], [0])');
    expect(detect).toContain("...manifest.dependencies");
    expect(detect).toContain("...manifest.optionalDependencies");
    expect(detect).toContain("...manifest.peerDependencies");
    expect(detect).toContain(
      "if (byName.has(dependency)) pending.push(dependency)",
    );
    expect(detect).toContain('["diff", "--quiet"');
    expect(detect).toContain("[0, 1]");
    expect(detect).toContain('appendFileSync(requiredEnv("GITHUB_OUTPUT")');
    expect(detect).toContain("diff.status === 1");

    const replay = billingJob?.steps?.find(
      (step) => step.name === "Run billing payment replay spec",
    )?.run;
    expect(replay).toContain("billing-payment-replay\\.spec\\.ts$");

    const admission = workflow.jobs?.["static-smoke"]?.steps?.find(
      (step) => step.name === "Require every admission lane",
    );
    expect(admission?.env?.RESULTS).toContain("billing-payment-replay-e2e=${{");
    expect(admission?.run).not.toContain('result" = "skipped');
  });

  test("fails closed over mergeability, secrets, workflows, and affected static checks", () => {
    const commands = (workflow.jobs?.["source-smoke"]?.steps ?? [])
      .map((step) => step.run ?? "")
      .join("\n");
    expect(commands).toContain("git merge-tree --write-tree");
    expect(commands).toContain("git diff --check");
    expect(commands).toContain("gitleaks detect");
    expect(commands).toContain("actionlint");
    expect(commands).toContain("bun run build:core");
    expect(commands).toContain("run lint:check --concurrency=4 --affected");
    expect(commands).toContain("run typecheck --concurrency=4 --affected");
    expect(commands).toContain("run build --concurrency=4 --affected");
  });

  test("does not acquire effect credentials or run live qualification", () => {
    expect(source).not.toMatch(/\bsecrets\.[A-Z0-9_]+/);
    expect(source.match(/test:e2e/g)).toHaveLength(3);
    expect(source).not.toContain("E2E_RECORD=1");
    expect(source).not.toContain("test:server");
    expect(source).not.toContain("test:client");
    expect(source).not.toContain("test:plugins");
    expect(source).not.toContain("environment:");
    expect(source).not.toContain("self-hosted");
  });

  test("documents the required keyless Billing and auth admission lanes", () => {
    expect(workflowReadme).toContain(
      "mock-backed payment replay Playwright proof",
    );
    expect(workflowReadme).toContain("production-mode hosted-wallet boundary");
    expect(workflowReadme).toMatch(
      /exact expected per-file\s+pass count with zero skips/,
    );
    expect(workflowReadme).toContain("supplemental test-auth pass");
    expect(workflowReadme).toContain("VITE_PLAYWRIGHT_TEST_AUTH=true");
    expect(workflowReadme).toContain("no provider credential");
    expect(workflowReadme).not.toMatch(/does\s+not run tests/);
  });
});
