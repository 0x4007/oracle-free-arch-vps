import {
  activeVolumeTotal,
  classifySoftStopResult,
  pairSuffix,
  validateBackupPair,
  validateRestoreStateBinding,
} from "../scripts/oci-restore.ts";

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

Deno.test("pairSuffix accepts the shared UTC suffix", () => {
  assertEquals(
    pairSuffix("arch-stage-golden-20260903T191507Z"),
    "20260903T191507Z",
  );
  assertEquals(pairSuffix("arch-stage-golden-invalid"), undefined);
});

Deno.test("validateBackupPair accepts one available 50/150 pair", () => {
  validateBackupPair(
    {
      "display-name": "arch-stage-golden-20260903T191507Z",
      "lifecycle-state": "AVAILABLE",
      "size-in-gbs": 50,
      type: "FULL",
    },
    {
      "display-name": "arch-root-golden-20260903T191507Z",
      "lifecycle-state": "AVAILABLE",
      "size-in-gbs": 150,
      type: "FULL",
    },
    "20260903T191507Z",
  );
});

Deno.test("validateBackupPair rejects a mismatched suffix", () => {
  let rejected = false;
  try {
    validateBackupPair(
      {
        "display-name": "arch-stage-golden-20260903T191507Z",
        "lifecycle-state": "AVAILABLE",
        "size-in-gbs": 50,
        type: "FULL",
      },
      {
        "display-name": "arch-root-golden-20260903T191508Z",
        "lifecycle-state": "AVAILABLE",
        "size-in-gbs": 150,
        type: "FULL",
      },
      "20260903T191507Z",
    );
  } catch {
    rejected = true;
  }
  assertEquals(rejected, true);
});

Deno.test("activeVolumeTotal excludes terminal volumes", () => {
  assertEquals(
    activeVolumeTotal([
      { "lifecycle-state": "AVAILABLE", "size-in-gbs": 150 },
      { "lifecycle-state": "TERMINATED", "size-in-gbs": 50 },
      { "lifecycle-state": "TERMINATING", "size-in-gbs": 50 },
      { "lifecycle-state": "PROVISIONING", "size-in-gbs": 50 },
    ]),
    250,
  );
});

Deno.test("group restore requires exact live membership even with provider-generated names", () => {
  const common = {
    "display-name": "provider-generated",
    "lifecycle-state": "AVAILABLE",
    type: "FULL",
    "compartment-id": "compartment",
    "volume-group-backup-id": "capture",
    "time-created": "2026-09-06T15:00:01Z",
  };
  const boot = {
    ...common,
    id: "boot-backup",
    "size-in-gbs": 50,
    "boot-volume-id": "boot-source",
  };
  const root = {
    ...common,
    id: "root-backup",
    "size-in-gbs": 150,
    "volume-id": "root-source",
  };
  const group = {
    id: "capture",
    "volume-group-id": "group",
    "compartment-id": "compartment",
    "lifecycle-state": "AVAILABLE",
    type: "FULL",
    "time-created": "2026-09-06T15:00:00Z",
    "volume-backup-ids": ["boot-backup", "root-backup"],
  };
  const validate = (record = group) =>
    validateBackupPair(
      boot,
      root,
      "20260906T150000Z",
      "boot-source",
      "root-source",
      "compartment",
      {
        group: record,
        volumeGroupId: "group",
        volumeGroupBackupId: "capture",
      },
    );
  validate();
  for (
    const record of [
      { ...group, "volume-backup-ids": ["boot-backup", "unrelated"] },
      { ...group, "volume-group-id": "another-group" },
      { ...group, type: "INCREMENTAL" },
    ]
  ) {
    let rejected = false;
    try {
      validate(record);
    } catch {
      rejected = true;
    }
    assertEquals(rejected, true);
  }
});

Deno.test("restore state rejects an unapproved availability domain", () => {
  let rejected = false;
  try {
    validateRestoreStateBinding(
      { pairSuffix: "20260903T191507Z", availabilityDomain: "AD-4" },
      "20260903T191507Z",
      ["AD-1", "AD-2", "AD-3"],
    );
  } catch {
    rejected = true;
  }
  assertEquals(rejected, true);
});

Deno.test("SOFTSTOP results remain fail-closed", () => {
  assertEquals(classifySoftStopResult(false, false, "STOPPED"), "STOPPED");
  assertEquals(classifySoftStopResult(true, false, "STOPPED"), "STOPPED");
  assertEquals(
    classifySoftStopResult(false, true, "STOPPING"),
    "SOFTSTOP_TIMEOUT",
  );
  assertEquals(
    classifySoftStopResult(true, false, "RUNNING"),
    "SOFTSTOP_FAILED",
  );
  assertEquals(
    classifySoftStopResult(false, false, "RUNNING"),
    "UNEXPECTED_LIFECYCLE_STATE",
  );
});
