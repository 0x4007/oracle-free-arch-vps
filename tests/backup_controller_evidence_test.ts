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
