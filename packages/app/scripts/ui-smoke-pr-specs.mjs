#!/usr/bin/env node
// Directory-driven ui-smoke spec discovery for the keyless PR lane (issue #9943).
//
// The PR lane used to hand-name most ui-smoke specs across several jobs, which
// left the rest silently off the PR path. This script makes the run
// directory-driven instead: it walks every test/ui-smoke/**/*.spec.ts, subtracts
// the explicit, checked-in deny-list (.pr-deny-list.json), and emits the set of
// specs that should run keyless. Any NEW spec is on the PR path by default; the
// only way to exclude one is to record it in the deny-list with a category and a
// reason. The script's --check mode validates the deny-list itself.
//
// Modes:
//   --list        (default) print every runnable spec (all specs - deny-list),
//                 one relative path per line.
//   --list-auto   print the runnable specs that are NOT already hand-named in
//                 scenario-pr.yml — i.e. the catch-all set the auto-discovered
//                 workflow job runs — space-separated on one line. New specs land
//                 here automatically, so they always run on PR.
//   --list-test-auth-supplemental
//                 print specs that must run once in production-mode auto
//                 discovery and once with the test-auth renderer, space-separated.
//   --json        print a machine-readable breakdown.
//   --check       validate the deny-list (entries reference real specs, have a
//                 valid category + non-empty reason, no duplicates) and exit
//                 non-zero on any problem.
//   --assert-report <contract> <path>
//                 fail closed unless a Playwright JSON report proves the exact
//                 expected file/test count with zero skipped or flaky tests.
//
// Paths are printed relative to packages/app (e.g. test/ui-smoke/foo.spec.ts),
// which is the cwd Playwright runs in via `bun run --cwd packages/app test:e2e`.

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const APP_DIR = path.resolve(SCRIPT_DIR, "..");
const REPO_ROOT = path.resolve(APP_DIR, "../..");
const UI_SMOKE_DIR = path.join(APP_DIR, "test", "ui-smoke");
const DENY_LIST_PATH = path.join(UI_SMOKE_DIR, ".pr-deny-list.json");
const WORKFLOW_PATH = path.join(
  REPO_ROOT,
  ".github",
  "workflows",
  "scenario-pr.yml",
);

const VALID_CATEGORIES = new Set([
  "live-only",
  "dedicated-tool",
  "keyless-debt",
]);

const TEST_AUTH_SUPPLEMENTAL_SPEC_NAMES = Object.freeze([
  "cloud-console-routes.spec.ts",
  "managed-login-stability.spec.ts",
]);

const REPORT_CONTRACTS = Object.freeze({
  "cli-auth-completion": Object.freeze({
    expectedFiles: Object.freeze([
      Object.freeze({
        file: "test/ui-smoke/cli-auth-completion.spec.ts",
        tests: 2,
      }),
    ]),
  }),
  "hosted-signin-wallet-capability": Object.freeze({
    expectedFiles: Object.freeze([
      Object.freeze({
        file: "test/ui-smoke/hosted-signin-wallet-capability.spec.ts",
        tests: 2,
      }),
    ]),
  }),
  "test-auth-supplemental": Object.freeze({
    expectedFiles: Object.freeze([
      Object.freeze({
        file: "test/ui-smoke/cloud-console-routes.spec.ts",
        tests: 3,
      }),
      Object.freeze({
        file: "test/ui-smoke/managed-login-stability.spec.ts",
        tests: 6,
      }),
    ]),
  }),
});

/** All spec file paths under test/ui-smoke, relative to that directory, sorted. */
function allSpecs() {
  const specs = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }
      if (entry.isFile() && entry.name.endsWith(".spec.ts")) {
        specs.push(
          path.relative(UI_SMOKE_DIR, fullPath).split(path.sep).join("/"),
        );
      }
    }
  };
  walk(UI_SMOKE_DIR);
  return specs.sort();
}

/** Parsed deny-list manifest. */
function loadDenyList() {
  const raw = JSON.parse(readFileSync(DENY_LIST_PATH, "utf8"));
  if (!Array.isArray(raw.specs)) {
    throw new Error(`${DENY_LIST_PATH}: expected a "specs" array`);
  }
  return raw.specs;
}

/** Set of deny-listed spec paths relative to test/ui-smoke. */
function deniedSpecNames() {
  return new Set(loadDenyList().map((entry) => entry.spec));
}

/** Spec paths hand-named in scenario-pr.yml (test/ui-smoke/<path>.spec.ts). */
function namedInWorkflow() {
  const workflow = readFileSync(WORKFLOW_PATH, "utf8");
  return new Set(
    [...workflow.matchAll(/test\/ui-smoke\/([A-Za-z0-9_./-]+\.spec\.ts)/g)].map(
      (m) => m[1],
    ),
  );
}

/** Runnable specs = every spec that is not deny-listed. */
function runnableSpecs() {
  const denied = deniedSpecNames();
  return allSpecs().filter((name) => !denied.has(name));
}

/** Auto-discovered specs = runnable specs not already hand-named in the workflow. */
function autoDiscoveredSpecs() {
  const named = namedInWorkflow();
  return runnableSpecs().filter((name) => !named.has(name));
}

function toRelative(name) {
  return `test/ui-smoke/${name}`;
}

function collectReportSpecs(suites, result = []) {
  if (!Array.isArray(suites)) return result;
  for (const suite of suites) {
    if (Array.isArray(suite?.specs)) result.push(...suite.specs);
    collectReportSpecs(suite?.suites, result);
  }
  return result;
}

function normalizedReportFile(file) {
  return typeof file === "string" ? file.replaceAll("\\", "/") : "";
}

function reportFileMatchesExpected(file, expectedFile) {
  const normalized = normalizedReportFile(file);
  return (
    normalized === expectedFile ||
    normalized.endsWith(`/${expectedFile}`) ||
    // Playwright reports paths relative to testDir. This suite's testDir is
    // test/ui-smoke, so a top-level spec is serialized as its basename only.
    normalized === path.posix.basename(expectedFile)
  );
}

/**
 * Validate the non-vacuous Playwright result consumed by the hosted auth lanes.
 * A Playwright process exits zero when every selected test is skipped, so the
 * admission workflow must additionally prove the exact expected pass count.
 */
export function assertUiSmokePlaywrightReport(report, contractName) {
  const contract = REPORT_CONTRACTS[contractName];
  if (!contract) {
    throw new Error(`Unknown ui-smoke report contract: ${contractName}`);
  }
  if (report === null || typeof report !== "object") {
    throw new Error(
      `${contractName}: expected a Playwright JSON report object`,
    );
  }

  const { stats } = report;
  const expectedTests = contract.expectedFiles.reduce(
    (total, entry) => total + entry.tests,
    0,
  );
  const expectedStats = {
    expected: expectedTests,
    unexpected: 0,
    flaky: 0,
    skipped: 0,
  };
  for (const [field, expected] of Object.entries(expectedStats)) {
    if (stats?.[field] !== expected) {
      throw new Error(
        `${contractName}: expected stats.${field}=${expected}, received ${String(stats?.[field])}`,
      );
    }
  }
  if (Array.isArray(report.errors) && report.errors.length > 0) {
    throw new Error(`${contractName}: Playwright reported top-level errors`);
  }

  const specs = collectReportSpecs(report.suites);
  const testsByFile = new Map(
    contract.expectedFiles.map((entry) => [entry.file, 0]),
  );
  const unexpectedFiles = [];
  for (const spec of specs) {
    const file = normalizedReportFile(spec?.file);
    const expectedFile = contract.expectedFiles.find((entry) =>
      reportFileMatchesExpected(file, entry.file),
    );
    if (!expectedFile) {
      unexpectedFiles.push(file);
      continue;
    }
    const specTests = Array.isArray(spec?.tests) ? spec.tests.length : 0;
    testsByFile.set(
      expectedFile.file,
      (testsByFile.get(expectedFile.file) ?? 0) + specTests,
    );
  }
  if (unexpectedFiles.length > 0) {
    throw new Error(
      `${contractName}: report contains ${unexpectedFiles.length} unexpected spec file(s)`,
    );
  }

  const tests = specs.flatMap((spec) =>
    Array.isArray(spec?.tests) ? spec.tests : [],
  );
  if (tests.length !== expectedTests) {
    throw new Error(
      `${contractName}: expected ${expectedTests} reported tests, received ${tests.length}`,
    );
  }
  for (const expectedFile of contract.expectedFiles) {
    const observed = testsByFile.get(expectedFile.file) ?? 0;
    if (observed !== expectedFile.tests) {
      throw new Error(
        `${contractName}: expected ${expectedFile.tests} test(s) from ${expectedFile.file}, received ${observed}`,
      );
    }
  }
  for (const spec of specs) {
    if (spec?.ok !== true) {
      throw new Error(`${contractName}: a reported spec did not pass`);
    }
  }
  for (const test of tests) {
    if (test?.expectedStatus !== "passed" || test?.status !== "expected") {
      throw new Error(
        `${contractName}: a reported test was not an expected pass`,
      );
    }
    if (
      !Array.isArray(test.results) ||
      test.results.length === 0 ||
      test.results.some((result) => result?.status !== "passed")
    ) {
      throw new Error(
        `${contractName}: a reported test has no clean pass result`,
      );
    }
  }

  return {
    contract: contractName,
    files: contract.expectedFiles.map((entry) => entry.file),
    passed: expectedTests,
  };
}

function assertReportFromFile(contractName, reportPath) {
  if (!reportPath) {
    throw new Error(`--assert-report ${contractName}: missing report path`);
  }
  const report = JSON.parse(readFileSync(reportPath, "utf8"));
  const verdict = assertUiSmokePlaywrightReport(report, contractName);
  console.log(
    `${verdict.contract} report OK: ${verdict.passed}/${verdict.passed} passed, 0 skipped`,
  );
}

function runCheck() {
  const specs = new Set(allSpecs());
  const entries = loadDenyList();
  const problems = [];
  const seen = new Set();
  for (const entry of entries) {
    if (typeof entry.spec !== "string" || entry.spec.length === 0) {
      problems.push(`entry missing "spec": ${JSON.stringify(entry)}`);
      continue;
    }
    if (seen.has(entry.spec)) {
      problems.push(`duplicate deny-list entry: ${entry.spec}`);
    }
    seen.add(entry.spec);
    if (!specs.has(entry.spec)) {
      problems.push(
        `deny-list references a spec that does not exist: ${entry.spec}`,
      );
    }
    if (!VALID_CATEGORIES.has(entry.category)) {
      problems.push(
        `${entry.spec}: invalid category "${entry.category}" (expected one of ${[...VALID_CATEGORIES].join(", ")})`,
      );
    }
    if (typeof entry.reason !== "string" || entry.reason.trim().length === 0) {
      problems.push(`${entry.spec}: missing or empty reason`);
    }
  }
  if (problems.length > 0) {
    console.error("ui-smoke deny-list check FAILED:");
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  const runnable = runnableSpecs();
  const auto = autoDiscoveredSpecs();
  for (const supplemental of TEST_AUTH_SUPPLEMENTAL_SPEC_NAMES) {
    if (!runnable.includes(supplemental)) {
      problems.push(
        `test-auth supplemental spec is not runnable: ${supplemental}`,
      );
    }
  }
  if (problems.length > 0) {
    console.error("ui-smoke test-auth supplemental check FAILED:");
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  console.log(
    `ui-smoke deny-list OK: ${specs.size} specs total, ${entries.length} denied, ` +
      `${runnable.length} runnable on PR (${auto.length} via auto-discovery).`,
  );
}

function main() {
  const mode = process.argv[2] ?? "--list";

  switch (mode) {
    case "--check":
      runCheck();
      break;
    case "--assert-report":
      assertReportFromFile(process.argv[3], process.argv[4]);
      break;
    case "--list-auto":
      process.stdout.write(autoDiscoveredSpecs().map(toRelative).join(" "));
      process.stdout.write("\n");
      break;
    case "--list-test-auth-supplemental":
      process.stdout.write(
        TEST_AUTH_SUPPLEMENTAL_SPEC_NAMES.map(toRelative).join(" "),
      );
      process.stdout.write("\n");
      break;
    case "--json":
      console.log(
        JSON.stringify(
          {
            total: allSpecs().length,
            denied: [...deniedSpecNames()].sort(),
            runnable: runnableSpecs(),
            namedInWorkflow: [...namedInWorkflow()].sort(),
            autoDiscovered: autoDiscoveredSpecs(),
            testAuthSupplemental: TEST_AUTH_SUPPLEMENTAL_SPEC_NAMES,
          },
          null,
          2,
        ),
      );
      break;
    case "--list":
      for (const name of runnableSpecs()) console.log(toRelative(name));
      break;
    default:
      console.error(`Unknown mode: ${mode}`);
      console.error(
        "Usage: ui-smoke-pr-specs.mjs [--list|--list-auto|--list-test-auth-supplemental|--json|--check|--assert-report <contract> <path>]",
      );
      process.exit(2);
  }
}

if (
  typeof process.argv[1] === "string" &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
