import { ociBackupOperations } from "../scripts/oci-backup-operations.ts";
import type { BackupPolicy } from "../scripts/weekly-backup.ts";

function fixture(recovery = false) {
  const source = {
    instanceId: "instance",
    bootVolumeId: "boot",
    rootVolumeId: "root",
    compartmentId: "tenancy",
    region: "us-ashburn-1",
  };
  const policy: BackupPolicy = {
    source,
    standingApproval: {
      source,
      approvedAtUtc: "2026-09-05T01:51:00Z",
      exactOperation: "weekly paired backup rotation",
    },
    acceptedPair: {
      suffix: "20260903T191507Z",
      bootId: "old-boot",
      rootId: "old-root",
    },
    retainPreviousPair: true,
    allowFifthSlot: false,
  };
  const calls: string[][] = [];
  const noop = () => Promise.resolve();
  const ops = ociBackupOperations(
    { source, tenancyId: "tenancy", ociProfile: "DEFAULT", ociCliPath: "oci" },
    policy,
    {
      assertNoActiveWork: recovery
        ? () => Promise.reject(new Error("New browser session is active"))
        : noop,
      quiesce: noop,
      verifyQuiesced: noop,
      acceptSource: noop,
    },
    {
      assertNoOtherController: noop,
      verify: () => Promise.reject(new Error("Unused inventory")),
    },
    noop,
    (_command, args) => {
      calls.push(args);
      if (recovery && args.includes("list")) {
        const boot = args.includes("boot-volume-attachment");
        return Promise.resolve({
          code: 0,
          stderr: "",
          stdout: JSON.stringify({
            data: [{
              "instance-id": "instance",
              "lifecycle-state": "ATTACHED",
              "attachment-type": "paravirtualized",
              [boot ? "boot-volume-id" : "volume-id"]: boot ? "boot" : "root",
            }],
          }),
        });
      }
      return Promise.resolve({
        code: 0,
        stderr: "",
        stdout: JSON.stringify({
          etag: "current-stop",
          data: {
            id: "instance",
            "compartment-id": "tenancy",
            shape: "VM.Standard.A1.Flex",
            "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
            "lifecycle-state": recovery ? "RUNNING" : "STOPPED",
            "availability-domain": "ad",
          },
        }),
      });
    },
    { now: () => new Date("2026-09-06T08:00:00Z"), sleep: noop },
  );
  return { ops, calls };
}

for (const operation of ["start", "create"] as const) {
  Deno.test(`OCI ${operation} rejects a changed stopped epoch before mutation`, async () => {
    const { ops, calls } = fixture();
    let refused = false;
    try {
      if (operation === "start") await ops.start("previous-stop");
      else await ops.createBackup("boot", "20260906T080000Z", "previous-stop");
    } catch {
      refused = true;
    }
    if (!refused || calls.length !== 1 || !calls[0].includes("get")) {
      throw new Error("Mutation was not blocked");
    }
  });
}

Deno.test("OCI START binds fresh ETag and disables automatic CLI retries", async () => {
  const { ops, calls } = fixture();
  await ops.start("current-stop");
  const mutation = calls[1];
  if (
    calls.length !== 2 || !mutation.includes("START") ||
    !mutation.includes("--no-retry") ||
    mutation[mutation.indexOf("--if-match") + 1] !== "current-stop"
  ) throw new Error("Missing conditional START protection");
});

Deno.test("new guest work blocks shutdown but permits restoring stopped applications", async () => {
  const { ops, calls } = fixture(true);
  let refused = false;
  try {
    await ops.softStop();
  } catch {
    refused = true;
  }
  if (!refused || calls.length !== 0) {
    throw new Error("Shutdown did not refuse the new guest work");
  }
  const snapshot = await ops.recoverySnapshot();
  if (
    snapshot.instanceState !== "RUNNING" ||
    !snapshot.sourceAttachmentsProved || !snapshot.writersAbsent ||
    calls.some((args) => args.includes("action"))
  ) throw new Error("Safe application recovery was blocked or mutated OCI");
});
