import {
  backupControllerEvidence,
  readFreeSubscription,
  verifyFreeSubscription,
  verifyPublishedFreeLimits,
} from "../scripts/backup-controller-evidence.ts";
import { objectStorage } from "../scripts/oci-weekly-audit.ts";
import { RetryableObservationError } from "../scripts/online-backup-contract.ts";
import { runUnattendedStep } from "../scripts/pi-recovery-session.ts";

Deno.test("unattended handoff waits for a real writer guard and rechecks before continuing", async () => {
  let competingWriter = true;
  let mutations = 0;
  const evidence = backupControllerEvidence(
    {
      ociCliPath: "oci",
      ociProfile: "DEFAULT",
      tenancyId: "tenancy",
      source: {
        instanceId: "instance",
        bootVolumeId: "boot",
        rootVolumeId: "root",
        compartmentId: "tenancy",
        region: "region",
      },
    },
    () =>
      Promise.resolve({
        code: 0,
        stdout: "1 0 init init" +
          (competingWriter ? "\n30 1 oci oci bv backup create" : ""),
        stderr: "",
      }),
  );
  const step = () =>
    runUnattendedStep(async () => {
      await evidence.assertNoOtherController();
      mutations++;
      return "CONSOLE_PENDING";
    });
  assert(await step() === "CONTROLLER_BUSY");
  assert(mutations === 0);
  competingWriter = false;
  assert(await step() === "CONSOLE_PENDING");
  assert(Number(mutations) === 1);
  for (
    const failure of [
      new Error("Another backup or infrastructure writer is active"),
      new Error("Uncertain create response"),
      new Error("Approval expired"),
    ]
  ) {
    let caught: unknown;
    try {
      await runUnattendedStep(() => Promise.reject(failure));
    } catch (error) {
      caught = error;
    }
    assert(caught === failure);
  }
});

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function refuses(run: () => unknown) {
  try {
    run();
  } catch (error) {
    assert(error instanceof Error);
    return error.message;
  }
  throw new Error("Expected refusal");
}
const terms =
  "first 1,500 OCPU hours and 9,000 GB hours per month for free; equivalent to 2 OCPUs and 12 GB of memory; total of 200 GB of Block Volume storage, and five volume backups; amounts apply to both boot volumes and block volumes combined; 20 GB of combined Standard tier, Infrequent Access tier, and Archive tier data";
const trialSubscription = {
  id: "subscription",
  "compartment-id": "tenancy",
  "lifecycle-state": "ACTIVE",
  "subscription-tier": "FREE_AND_TRIAL",
  "payment-model": "FREE_TRIAL",
};
Deno.test("published allowance changes fail closed", () => {
  assert(verifyPublishedFreeLimits(terms) === 5);
  refuses(() =>
    verifyPublishedFreeLimits(terms.replace("five volume", "four volume"))
  );
  refuses(() => verifyPublishedFreeLimits("Access denied"));
});
Deno.test("account proof rejects and describes unsupported Organizations values", () => {
  assert(
    refuses(() => verifyFreeSubscription(trialSubscription, "other-tenancy"))
      .includes("compartment-matches-tenancy=false"),
  );
  for (
    const [field, values] of [
      ["lifecycle-state", ["INACTIVE", "UNKNOWN"]],
      ["subscription-tier", ["PAYG", "ALWAYS_FREE", "free", "UNKNOWN"]],
      ["payment-model", [
        "FREE",
        "PAY_AS_YOU_GO",
        "pay-as-you-go",
        "MONTHLY_COMMITMENT",
        "ANNUAL_COMMITMENT",
        "UNKNOWN",
      ]],
    ] as const
  ) {
    for (const tier of ["FREE_AND_TRIAL", "FREE"]) {
      for (const value of [...values, null, undefined, {}]) {
        const message = refuses(() =>
          verifyFreeSubscription({
            ...trialSubscription,
            "subscription-tier": tier,
            [field]: value,
          }, "tenancy")
        );
        const observed = value === undefined
          ? "missing"
          : value !== null && typeof value === "object"
          ? "object"
          : JSON.stringify(value);
        assert(message.includes(`${field}=${observed}`));
        assert(message.includes("subscription-tier="));
        assert(message.includes("payment-model="));
      }
    }
  }
});

Deno.test("Organizations proof refuses ambiguous inventory and mismatched details", async () => {
  const listed = { id: trialSubscription.id };
  for (
    const items of [undefined, [], [listed, listed], [null], [{}], [{ id: "" }]]
  ) {
    let calls = 0;
    const error: unknown = await readFreeSubscription(() => {
      calls++;
      return Promise.resolve({ data: { items } });
    }, "tenancy").catch((error) => error);
    assert(error instanceof Error && calls === 1);
  }
  for (const id of [undefined, "other-subscription"]) {
    const error: unknown = await readFreeSubscription(
      (args) =>
        Promise.resolve({
          data: args[2] === "list"
            ? { items: [listed] }
            : { ...trialSubscription, id },
        }),
      "tenancy",
    ).catch((error) => error);
    assert(
      error instanceof Error && error.message.includes("identities differ"),
    );
  }
});

Deno.test("controller proves account and limits for active trial and post-trial Free Tier", async () => {
  for (const tier of ["FREE_AND_TRIAL", "FREE"] as const) {
    const evidence = backupControllerEvidence({
      ociCliPath: "oci",
      ociProfile: "DEFAULT",
      tenancyId: "tenancy",
      source: {
        instanceId: "instance",
        bootVolumeId: "boot",
        rootVolumeId: "root",
        compartmentId: "tenancy",
        region: "region",
      },
    }, (command, args) => {
      assert(command === "oci");
      const start = args.findIndex((arg) =>
        ["organizations", "os", "iam", "compute", "bv"].includes(arg)
      );
      assert(start >= 0);
      const operation = args.slice(start);
      let data: unknown = [];
      switch (operation.slice(0, 3).join(" ")) {
        case "organizations subscription list":
          assert(operation.includes("--all") && operation.includes("tenancy"));
          data = { items: [{ id: trialSubscription.id }] };
          break;
        case "organizations subscription get":
          assert(operation.includes(trialSubscription.id));
          data = {
            ...trialSubscription,
            "subscription-tier": tier,
            promotion: [{ status: tier === "FREE" ? "EXPIRED" : "ACTIVE" }],
          };
          break;
        case "os ns get":
          data = "namespace";
          break;
        case "iam availability-domain list":
          data = [{ name: "fixture-domain" }];
          break;
        case "iam compartment list":
        case "os bucket list":
        case "compute image list":
        case "bv boot-volume list":
        case "bv volume list":
          break;
        default:
          throw new Error("Unexpected OCI operation in fixture");
      }
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify({ data }),
        stderr: "",
      });
    }, () => Promise.resolve(terms));
    const proof = await evidence.verify();
    assert(proof.accountAndLimitsProved && proof.backupLimit === 5);
    assert(proof.objectStorageComplete && proof.objectStorageWithinLimit);
  }
});
Deno.test("suspended versioning still counts older Object Storage versions", async () => {
  let versionsRead = false;
  const storage = await objectStorage({
    ociCliPath: "oci",
    ociProfile: "DEFAULT",
    region: "region",
    compartmentId: "tenancy",
    instanceId: "instance",
    objectStorageLimitGb: 20,
  }, (_command, args) => {
    const command = args.join(" ");
    let data: unknown;
    if (command.includes("os ns get")) data = "namespace";
    else if (command.includes("iam compartment list")) data = [];
    else if (command.includes("os bucket list")) data = [{ name: "bucket" }];
    else if (command.includes("os bucket get")) {
      data = { versioning: "Suspended" };
    } else if (command.includes("os object list-object-versions")) {
      data = [{ size: 100 }, { size: 200 }];
      versionsRead = true;
    } else if (command.includes("os object list")) data = [{ size: 100 }];
    else if (command.includes("os multipart list")) data = [];
    else throw new Error("Unexpected command");
    return Promise.resolve({
      code: 0,
      stdout: JSON.stringify({ data }),
      stderr: "",
    });
  });
  assert(versionsRead && storage.bytes === 300 && storage.storedObjects === 2);
});

Deno.test("online controller permits ordinary SSH but refuses infrastructure writers", async () => {
  let processes =
    "1 0 init init\n20 1 ssh ssh codex@vps.pavlovcik.com true\n21 1 chromium chromium\n22 1 bash bash";
  const evidence = backupControllerEvidence({
    ociCliPath: "oci",
    ociProfile: "DEFAULT",
    tenancyId: "tenancy",
    source: {
      instanceId: "instance",
      bootVolumeId: "boot",
      rootVolumeId: "root",
      compartmentId: "tenancy",
      region: "region",
    },
  }, () => Promise.resolve({ code: 0, stdout: processes, stderr: "" }));
  await evidence.assertNoOtherController();
  for (
    const writer of [
      "30 1 oci oci bv backup create",
      "31 1 deno deno run scripts/backup-runtime.ts",
      "33 1 deno deno run scripts/pi-machine-recovery.ts",
      "32 1 rsync rsync files pi:/home/pi/ops/weekly-backup-controller",
    ]
  ) {
    const original = processes;
    processes += "\n" + writer;
    let rejected = false;
    try {
      await evidence.assertNoOtherController();
    } catch {
      rejected = true;
    }
    assert(rejected);
    processes = original;
  }
});

Deno.test("official terms transport failure is retryable before OCI reads", async () => {
  const evidence = backupControllerEvidence({
    ociCliPath: "oci",
    ociProfile: "DEFAULT",
    tenancyId: "tenancy",
    source: {
      instanceId: "instance",
      bootVolumeId: "boot",
      rootVolumeId: "root",
      compartmentId: "tenancy",
      region: "region",
    },
  }, () => {
    throw new Error("OCI should not be called after an unavailable terms page");
  }, () => Promise.reject(new Error("network unavailable")));
  let failure: unknown;
  try {
    await evidence.verify();
  } catch (error) {
    failure = error;
  }
  assert(failure instanceof RetryableObservationError);
});

Deno.test("controller guard accepts only fixture-backed named writer proof", async () => {
  const lockPath = "/fixture/.private/backup-controller.lock";
  const holderRow = (overrides: Record<string, unknown> = {}) => ({
    pid: Deno.pid,
    type: "FLOCK",
    mode: "WRITE",
    path: lockPath,
    blocker: null,
    inode: 123,
    "maj:min": "179:2",
    ...overrides,
  });
  const waiterRow = (overrides: Record<string, unknown> = {}) => ({
    pid: 10000000,
    type: "FLOCK",
    mode: "WRITE*",
    path: lockPath,
    blocker: Deno.pid,
    inode: 123,
    "maj:min": "179:2",
    ...overrides,
  });
  const processes = [
    "1 0 init init",
    `${Deno.pid} 1 deno deno test`,
    "10000000 1 deno deno run scripts/backup-scheduled.ts",
  ].join("\n");
  type Fixture = {
    processes?: string;
    locks?: unknown[];
    lockOutput?: string;
    lslocksCode?: number;
  };
  const cases: Fixture[] = [
    { locks: [holderRow()] },
    { locks: [waiterRow()] },
    { locks: [holderRow(), holderRow(), waiterRow()] },
    { locks: [holderRow(), waiterRow(), waiterRow()] },
    {
      locks: [holderRow(), waiterRow({ path: "/fixture/.private/other.lock" })],
    },
    { locks: [holderRow(), waiterRow({ "maj:min": "178:2" })] },
    { locks: [holderRow(), waiterRow({ inode: 124 })] },
    { locks: [holderRow(), waiterRow({ blocker: null })] },
    { locks: [holderRow(), waiterRow({ type: "POSIX" })] },
    { locks: [holderRow(), waiterRow({ mode: "WRITE" })] },
    { locks: [holderRow({ inode: "123" }), waiterRow()] },
    { locks: [] },
    { locks: [null] },
    { lockOutput: "not json" },
    { lslocksCode: 1 },
    {
      processes: processes + "\n500 1 oci oci bv backup create",
      locks: [holderRow(), waiterRow(), waiterRow({ pid: 500 })],
    },
    {
      processes: processes +
        "\n600 1 rsync rsync files pi:/home/pi/ops/weekly-backup-controller",
      locks: [holderRow(), waiterRow(), waiterRow({ pid: 600 })],
    },
  ];
  const options = {
    ociCliPath: "oci",
    ociProfile: "DEFAULT",
    tenancyId: "tenancy",
    source: {
      instanceId: "instance",
      bootVolumeId: "boot",
      rootVolumeId: "root",
      compartmentId: "tenancy",
      region: "region",
    },
  };
  const evidence = (fixture: Fixture) =>
    backupControllerEvidence(options, (command: string) => {
      if (command === "ps") {
        return Promise.resolve({
          code: 0,
          stdout: fixture.processes ?? processes,
          stderr: "",
        });
      }
      if (command === "lslocks") {
        return Promise.resolve({
          code: fixture.lslocksCode ?? 0,
          stdout: fixture.lockOutput ??
            JSON.stringify({ locks: fixture.locks ?? [] }),
          stderr: "",
        });
      }
      throw new Error("Unexpected command");
    });
  const originalRealPath = Deno.realPath;
  let seen = "";
  try {
    Deno.realPath = (input: string | URL) => {
      seen = String(input);
      assert(input === ".private");
      return Promise.resolve("/fixture/.private");
    };
    await evidence({ locks: [holderRow(), waiterRow()] })
      .assertNoOtherController();
    assert(seen === ".private");
    for (const fixture of cases) {
      let rejected = false;
      try {
        await evidence(fixture).assertNoOtherController();
      } catch {
        rejected = true;
      }
      if (!rejected) throw new Error("Guard accepted an invalid fixture");
    }
  } finally {
    Deno.realPath = originalRealPath;
  }
});

const startupFixtureOptions = {
  ociCliPath: "oci",
  ociProfile: "DEFAULT",
  tenancyId: "tenancy",
  source: {
    instanceId: "instance",
    bootVolumeId: "boot",
    rootVolumeId: "root",
    compartmentId: "tenancy",
    region: "region",
  },
};
const startupFixtureLockPath = "/fixture/.private/backup-controller.lock";
const startupHolder = (overrides: Record<string, unknown> = {}) => ({
  pid: Deno.pid,
  type: "FLOCK",
  mode: "WRITE",
  path: startupFixtureLockPath,
  blocker: null,
  inode: 123,
  "maj:min": "179:2",
  ...overrides,
});
const startupWaiter = (
  pid: number,
  overrides: Record<string, unknown> = {},
) => ({
  pid,
  type: "FLOCK",
  mode: "WRITE*",
  path: startupFixtureLockPath,
  blocker: Deno.pid,
  inode: 123,
  "maj:min": "179:2",
  ...overrides,
});
type StartupObservation = { processes: string; locks: unknown[] };
type StartupStats = { ps: number; lslocks: number };
function startupEvidence(
  steps: ReadonlyArray<StartupObservation>,
  stats: StartupStats,
) {
  let activeObservation = steps[0]!;
  let next = 0;
  return backupControllerEvidence(startupFixtureOptions, (command: string) => {
    if (command === "ps") {
      activeObservation = steps[Math.min(next, steps.length - 1)]!;
      next += 1;
      stats.ps += 1;
      return Promise.resolve({
        code: 0,
        stdout: activeObservation.processes,
        stderr: "",
      });
    }
    if (command === "lslocks") {
      stats.lslocks += 1;
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify({ locks: activeObservation.locks }),
        stderr: "",
      });
    }
    throw new Error("Unexpected command");
  });
}
async function insideStartupFixture(run: () => Promise<void>) {
  const originalRealPath = Deno.realPath;
  let seen = "";
  Deno.realPath = (input: string | URL) => {
    seen = String(input);
    assert(input === ".private");
    return Promise.resolve("/fixture/.private");
  };
  try {
    await run();
    assert(seen === ".private");
  } finally {
    Deno.realPath = originalRealPath;
  }
}
const startupWrapperProcesses = (queuedDeno: number) =>
  [
    "1 0 init init",
    `${Deno.pid} 1 deno deno test`,
    "70001 1 bash /usr/local/bin/safepi -- deno run scripts/backup-scheduled.ts",
    "70002 1 systemd-run systemd-run --user --scope --collect --working-directory=/tmp" +
    " -- nice -n10 -- deno run scripts/backup-scheduled.ts",
    `${queuedDeno} 1 nice nice -n10 -- deno run scripts/backup-scheduled.ts`,
  ].join("\n");
const queuedDenoProcesses = (deno: number) =>
  [
    "1 0 init init",
    `${Deno.pid} 1 deno deno test`,
    `${deno} 1 deno deno run scripts/backup-scheduled.ts`,
  ].join("\n");

Deno.test("startup wrapper may prove its exact queued Deno within bounded observations", async () => {
  const queuedDeno = 70003;
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: startupWrapperProcesses(queuedDeno),
      locks: [startupHolder()],
    },
    {
      processes: queuedDenoProcesses(queuedDeno),
      locks: [startupHolder(), startupWaiter(queuedDeno)],
    },
  ], stats);
  await insideStartupFixture(async () => {
    await evidence.assertNoOtherController();
    assert(stats.ps === 2 && stats.lslocks === 2);
  });
});

Deno.test("persistent startup wrapper fails after bounded observations", async () => {
  const queuedDeno = 70003;
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: startupWrapperProcesses(queuedDeno),
      locks: [startupHolder()],
    },
  ], stats);
  await insideStartupFixture(async () => {
    let rejected = false;
    try {
      await evidence.assertNoOtherController();
    } catch {
      rejected = true;
    }
    assert(rejected);
    assert(stats.ps === 3 && stats.lslocks === 3);
  });
});

Deno.test("OCI writer appearing during startup observation fails immediately", async () => {
  const queuedDeno = 70003;
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: startupWrapperProcesses(queuedDeno),
      locks: [startupHolder()],
    },
    {
      processes: startupWrapperProcesses(queuedDeno) +
        "\n90000 1 oci oci bv backup create",
      locks: [startupHolder()],
    },
  ], stats);
  await insideStartupFixture(async () => {
    let rejected = false;
    try {
      await evidence.assertNoOtherController();
    } catch {
      rejected = true;
    }
    assert(rejected);
    assert(stats.ps === 2 && stats.lslocks === 1);
  });
});

Deno.test("moved owned lock identity during startup observation rejects", async () => {
  const queuedDeno = 70003;
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: startupWrapperProcesses(queuedDeno),
      locks: [startupHolder()],
    },
    {
      processes: startupWrapperProcesses(queuedDeno),
      locks: [startupHolder({ inode: 124 })],
    },
  ], stats);
  await insideStartupFixture(async () => {
    let rejected = false;
    try {
      await evidence.assertNoOtherController();
    } catch {
      rejected = true;
    }
    assert(rejected);
    assert(stats.ps === 2 && stats.lslocks === 2);
  });
});

Deno.test("queued Deno on a different lock object never satisfies the startup proof", async () => {
  const queuedDeno = 70003;
  const wrongWaiter = {
    processes: queuedDenoProcesses(queuedDeno),
    locks: [startupHolder(), startupWaiter(queuedDeno, { inode: 999 })],
  };
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: startupWrapperProcesses(queuedDeno),
      locks: [startupHolder()],
    },
    wrongWaiter,
    wrongWaiter,
  ], stats);
  await insideStartupFixture(async () => {
    let rejected = false;
    try {
      await evidence.assertNoOtherController();
    } catch {
      rejected = true;
    }
    assert(rejected);
    assert(stats.ps === 3 && stats.lslocks === 3);
  });
});

Deno.test("already-proved queued waiter succeeds on the first observation", async () => {
  const queuedDeno = 70011;
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: queuedDenoProcesses(queuedDeno),
      locks: [startupHolder(), startupWaiter(queuedDeno)],
    },
  ], stats);
  await insideStartupFixture(async () => {
    await evidence.assertNoOtherController();
    assert(stats.ps === 1 && stats.lslocks === 1);
  });
});

Deno.test("wrapper that becomes an unproved Deno may use remaining observations", async () => {
  const queuedDeno = 70003;
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: startupWrapperProcesses(queuedDeno),
      locks: [startupHolder()],
    },
    {
      processes: queuedDenoProcesses(queuedDeno),
      locks: [startupHolder()],
    },
    {
      processes: queuedDenoProcesses(queuedDeno),
      locks: [startupHolder(), startupWaiter(queuedDeno)],
    },
  ], stats);
  await insideStartupFixture(async () => {
    await evidence.assertNoOtherController();
    assert(stats.ps === 3 && stats.lslocks === 3);
  });
});

Deno.test("wrapper then vanished candidates re-prove the same holder", async () => {
  const queuedDeno = 70003;
  const noCandidates = [
    "1 0 init init",
    `${Deno.pid} 1 deno deno test`,
  ].join("\n");
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: startupWrapperProcesses(queuedDeno),
      locks: [startupHolder()],
    },
    {
      processes: noCandidates,
      locks: [startupHolder()],
    },
  ], stats);
  await insideStartupFixture(async () => {
    await evidence.assertNoOtherController();
    assert(stats.ps === 2 && stats.lslocks === 2);
  });
});

Deno.test("wrapper then vanished candidates with moved or absent holder rejects", async () => {
  const queuedDeno = 70003;
  const noCandidates = [
    "1 0 init init",
    `${Deno.pid} 1 deno deno test`,
  ].join("\n");
  for (const secondLocks of [[], [startupHolder({ inode: 124 })]]) {
    const stats: StartupStats = { ps: 0, lslocks: 0 };
    const evidence = startupEvidence([
      {
        processes: startupWrapperProcesses(queuedDeno),
        locks: [startupHolder()],
      },
      {
        processes: noCandidates,
        locks: secondLocks,
      },
    ], stats);
    await insideStartupFixture(async () => {
      let rejected = false;
      try {
        await evidence.assertNoOtherController();
      } catch {
        rejected = true;
      }
      assert(rejected);
      assert(stats.ps === 2 && stats.lslocks === 2);
    });
  }
});

Deno.test("mixed ordinary unproved process cannot open the startup window", async () => {
  const queuedDeno = 70003;
  const stats: StartupStats = { ps: 0, lslocks: 0 };
  const evidence = startupEvidence([
    {
      processes: startupWrapperProcesses(queuedDeno) + "\n" +
        "70020 1 deno deno run scripts/backup-scheduled.ts",
      locks: [startupHolder()],
    },
  ], stats);
  await insideStartupFixture(async () => {
    let rejected = false;
    try {
      await evidence.assertNoOtherController();
    } catch {
      rejected = true;
    }
    assert(rejected);
    assert(stats.ps === 1 && stats.lslocks === 1);
  });
});
