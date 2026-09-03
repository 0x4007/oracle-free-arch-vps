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
