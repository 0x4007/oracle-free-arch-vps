import {
  assessOracleBootDrillEvidence,
  assessOracleRetry,
} from "../scripts/backup-watchdog.ts";
import {
  type GroupRestorePlan,
  groupRestorePlanDigest,
} from "../scripts/oci-group-restore-drill.ts";
import type { GroupRestoreAcceptanceReceipt } from "../scripts/oci-group-restore-executor.ts";
import type { OnlineBackupRetry } from "../scripts/online-backup-contract.ts";

const now = new Date("2026-09-06T23:00:00Z");
const retry: OnlineBackupRetry = {
  disposition: "retryable",
  resumePhase: "backing-up",
  attempts: 1,
  firstFailureAtUtc: "2026-09-06T22:55:00Z",
  nextAttemptAtUtc: "2026-09-06T23:10:00Z",
  deadlineAtUtc: "2026-09-07T02:55:00Z",
};
function assertStatus(value: OnlineBackupRetry, expected: string) {
  const result = assessOracleRetry({ phase: "failed", retry: value }, now);
  if (result?.status !== expected || result.healthy !== false) {
    throw new Error(`Expected visible unresolved ${expected}`);
  }
}
Deno.test("retry watchdog distinguishes waiting, due, cooldown and ambiguity", () => {
  assertStatus(retry, "BACKUP_RETRY_WAITING");
  assertStatus(
    { ...retry, nextAttemptAtUtc: now.toISOString() },
    "BACKUP_RETRY_DUE",
  );
  assertStatus(
    { ...retry, nextAttemptAtUtc: "2026-09-07T23:00:00Z" },
    "BACKUP_RETRY_COOLDOWN",
  );
  assertStatus(
    { ...retry, disposition: "blocked" },
    "BACKUP_BLOCKED_RECONCILIATION",
  );
});
Deno.test("retry watchdog refuses malformed or future evidence", () => {
  assertStatus({ ...retry, attempts: -1 }, "INVALID_RETRY_STATE");
  assertStatus(
    { ...retry, nextAttemptAtUtc: "invalid" },
    "INVALID_RETRY_STATE",
  );
  assertStatus(
    { ...retry, firstFailureAtUtc: "2026-09-07T00:00:00Z" },
    "INVALID_RETRY_STATE",
  );
});
Deno.test("retry watchdog does not overwrite accepted or legacy failure assessments", () => {
  if (
    assessOracleRetry({ phase: "complete", retry }, now) !== undefined ||
    assessOracleRetry({ phase: "failed" }, now) !== undefined
  ) {
    throw new Error("Unexpected retry assessment");
  }
});

async function oracleProof() {
  const plan: GroupRestorePlan = {
    source: {
      instanceId: "source-instance",
      bootVolumeId: "source-boot",
      rootVolumeId: "source-root",
      compartmentId: "tenancy",
      region: "us-ashburn-1",
    },
    availabilityDomain: "AD-1",
    volumeGroupId: "source-group",
    volumeGroupBackupId: "accepted-group",
    bootMemberBackupId: "boot-member",
    rootMemberBackupId: "root-member",
    productionSubnetId: "production-subnet",
    productionVcnId: "production-vcn",
    productionReservedIpId: "production-ip",
    isolatedSubnetId: "clone-subnet",
    isolatedVcnId: "clone-vcn",
    isolatedCidrBlock: "10.77.0.0/28",
    controllerIpv4: "192.0.2.1",
    suffix: "20260906T200000Z",
    maxDurationHours: 4,
    spendingCapUsd: 0.5,
  };
  const acceptance: GroupRestoreAcceptanceReceipt = {
    status: "RESTORE_DRILL_PROVED",
    observedAtUtc: "2026-09-06T22:00:00.000Z",
    suffix: plan.suffix,
    planSha256: await groupRestorePlanDigest(plan),
    checks: {
      productionOnline: true,
      targetBooted: true,
      ssh: true,
      mounts: true,
      bootParity: true,
      representativeData: true,
      applications: true,
      desktop: true,
      isolation: true,
      metadataBlocked: true,
      duplicateJobsMasked: true,
    },
    rootUuid: "11111111-1111-4111-8111-111111111111",
    stagingUuid: "22222222-2222-4222-8222-222222222222",
    rootPartitionStartSector: 1050624,
    kernelSha256: "a".repeat(64),
    initramfsSha256: "b".repeat(64),
    grubSha256: "c".repeat(64),
  };
  return { plan, acceptance };
}

Deno.test("Oracle watchdog keeps dated group proof separate from a later capture", async () => {
  const proof = await oracleProof();
  for (
    const [current, expected] of [
      ["accepted-group", true],
      ["new-group", false],
      [undefined, null],
    ] as const
  ) {
    const result = await assessOracleBootDrillEvidence(proof, now, current);
    if (
      result.status !== "RESTORE_DRILL_PROVED" ||
      result.generation !== "accepted-group" ||
      result.bootMemberBackupId !== "boot-member" ||
      result.rootMemberBackupId !== "root-member" ||
      result.currentCaptureProved !== expected
    ) throw Error("Dated proof was lost or transferred to another capture");
  }
});

Deno.test("Oracle watchdog rejects substituted group/member bindings and incomplete proof", async () => {
  const original = await oracleProof();
  const mutations = [
    (p: typeof original) => {
      p.plan.volumeGroupBackupId = "other-group";
    },
    (p: typeof original) => {
      p.plan.rootMemberBackupId = "other-root";
    },
    (p: typeof original) => {
      p.acceptance.checks.desktop = false;
    },
    (p: typeof original) => {
      p.acceptance.observedAtUtc = "2026-09-07T00:00:00.000Z";
    },
  ];
  for (const mutate of mutations) {
    const proof = structuredClone(original);
    mutate(proof);
    let rejected = false;
    try {
      await assessOracleBootDrillEvidence(proof, now);
    } catch {
      rejected = true;
    }
    if (!rejected) throw Error("Invalid Oracle proof accepted");
  }
});
