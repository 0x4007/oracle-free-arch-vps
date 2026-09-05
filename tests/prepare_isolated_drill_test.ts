import { acceptedDrillPair } from "../scripts/prepare-isolated-drill.ts";
import {
  type BackupPolicy,
  newBackupJournal,
} from "../scripts/weekly-backup.ts";
import type { GuestJournal } from "../scripts/backup-guest.ts";
function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function rejects(run: () => unknown) {
  let failed = false;
  try {
    run();
  } catch {
    failed = true;
  }
  assert(failed);
}
Deno.test("drill preparation requires the fresh cycle and accepted source recovery", () => {
  const source = {
    instanceId: "source",
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
    allowFifthSlot: true,
  };
  const cycle = newBackupJournal(policy, new Date("2026-09-05T08:00:00Z"));
  const guest: GuestJournal = {
    rootUuid: "root-uuid",
    stagingUuid: "stage-uuid",
    containers: [],
    units: [],
    restored: true,
  };
  const state = { policy, cycle, guest };
  const now = new Date("2026-09-05T10:00:00Z");
  rejects(() => acceptedDrillPair(state, now));
  cycle.phase = "complete";
  cycle.bootId = "new-boot";
  cycle.rootId = "new-root";
  cycle.sourceAcceptedAtUtc = "2026-09-05T09:00:00Z";
  assert(acceptedDrillPair(state, now).bootId === "new-boot");
  rejects(() =>
    acceptedDrillPair({ ...state, guest: { ...guest, restored: false } }, now)
  );
  rejects(() =>
    acceptedDrillPair({
      ...state,
      cycle: { ...cycle, createdAtUtc: "invalid" },
    }, now)
  );
  rejects(() =>
    acceptedDrillPair({
      ...state,
      cycle: { ...cycle, sourceAcceptedAtUtc: "2026-09-06T09:00:00Z" },
    }, now)
  );
});
