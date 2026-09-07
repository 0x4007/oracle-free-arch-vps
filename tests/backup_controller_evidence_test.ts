import {
  backupControllerEvidence,
  verifyFreeSubscription,
  verifyPublishedFreeLimits,
} from "../scripts/backup-controller-evidence.ts";
import { objectStorage } from "../scripts/oci-weekly-audit.ts";
import { RetryableObservationError } from "../scripts/online-backup-contract.ts";

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function refuses(run: () => unknown) {
  let rejected = false;
  try {
    run();
  } catch {
    rejected = true;
  }
  assert(rejected);
}
const terms =
  "first 1,500 OCPU hours and 9,000 GB hours per month for free; equivalent to 2 OCPUs and 12 GB of memory; total of 200 GB of Block Volume storage, and five volume backups; amounts apply to both boot volumes and block volumes combined; 20 GB of combined Standard tier, Infrequent Access tier, and Archive tier data";
Deno.test("published allowance changes fail closed", () => {
  assert(verifyPublishedFreeLimits(terms) === 5);
  refuses(() =>
    verifyPublishedFreeLimits(terms.replace("five volume", "four volume"))
  );
  refuses(() => verifyPublishedFreeLimits("Access denied"));
});
Deno.test("account proof rejects paid, inactive and wrong-tenancy subscriptions", () => {
  const account = {
    "compartment-id": "tenancy",
    "lifecycle-state": "ACTIVE",
    "subscription-tier": "FREE_AND_TRIAL",
    "payment-model": "FREE_TRIAL",
  };
  verifyFreeSubscription(account, "tenancy");
  refuses(() =>
    verifyFreeSubscription(
      { ...account, "payment-model": "PAY_AS_YOU_GO" },
      "tenancy",
    )
  );
  refuses(() =>
    verifyFreeSubscription(
      { ...account, "lifecycle-state": "INACTIVE" },
      "tenancy",
    )
  );
  refuses(() => verifyFreeSubscription(account, "other-tenancy"));
  refuses(() =>
    verifyFreeSubscription(
      { ...account, "subscription-tier": "FREE", "payment-model": "FREE" },
      "tenancy",
    )
  );
  refuses(() =>
    verifyFreeSubscription(
      { ...account, "subscription-tier": "ALWAYS_FREE" },
      "tenancy",
    )
  );
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
    Deno.realPath = async (input: string | URL) => {
      seen = String(input);
      assert(input === ".private");
      return "/fixture/.private";
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
