import { ociBackupOperations } from "../scripts/oci-backup-operations.ts";
import type { BackupInventoryConfig } from "../scripts/oci-backup-inventory.ts";
import type { CommandResult, JsonRecord } from "../scripts/oci.ts";
import type { BackupGuestControl } from "../scripts/oci-backup-operations.ts";
import type { BackupPair, BackupPolicy } from "../scripts/weekly-backup.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

const source = {
  instanceId: "instance",
  bootVolumeId: "boot",
  rootVolumeId: "root",
  compartmentId: "tenancy",
  region: "us-ashburn-1",
};
const suffix = "20260906T080000Z";
const sourceBootId = "boot-1";
const sourceRootId = "root-1";
const sourceGroupBackupId = "group-1";

function instance(): JsonRecord {
  return {
    id: source.instanceId,
    "compartment-id": source.compartmentId,
    "availability-domain": "ad-1",
    "lifecycle-state": "RUNNING",
    shape: "VM.Standard.A1.Flex",
    "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
  };
}

function volume(
  id: string,
  size: number,
): JsonRecord {
  return {
    id,
    "compartment-id": source.compartmentId,
    "availability-domain": "ad-1",
    "lifecycle-state": "AVAILABLE",
    "size-in-gbs": size,
    "vpus-per-gb": 10,
  };
}

function member(
  kind: "boot" | "root",
  id: string,
  groupBackupId: string | null = sourceGroupBackupId,
): JsonRecord {
  return {
    id,
    "compartment-id": source.compartmentId,
    "lifecycle-state": "AVAILABLE",
    "size-in-gbs": kind === "boot" ? 50 : 150,
    type: "FULL",
    "time-created": "2026-09-06T08:00:01.000Z",
    "volume-group-backup-id": groupBackupId,
    [kind === "boot" ? "boot-volume-id" : "volume-id"]: kind === "boot"
      ? source.bootVolumeId
      : source.rootVolumeId,
  };
}

function groupBackup(
  id: string,
  bootId = sourceBootId,
  rootId = sourceRootId,
  lifecycleState = "AVAILABLE",
  volumeGroupId = "volume-group",
): JsonRecord {
  return {
    id,
    "compartment-id": source.compartmentId,
    "volume-group-id": volumeGroupId,
    "volume-backup-ids": [bootId, rootId],
    "lifecycle-state": lifecycleState,
    type: "FULL",
    "time-created": "2026-09-06T08:00:00.000Z",
    "display-name": `arch-online-golden-${suffix}`,
  };
}

interface MockState {
  calls: string[][];
  sourceVolumeIds: string[];
  bootBackups: JsonRecord[];
  rootBackups: JsonRecord[];
  group?: JsonRecord;
  groupGetStates?: string[];
  groupGetIndex: number;
  deleted: boolean;
}

function json(data: unknown, extra: JsonRecord = {}): CommandResult {
  return {
    code: 0,
    stderr: "",
    stdout: JSON.stringify({ ...extra, data }),
  };
}

function policy(
  acceptedPair: BackupPair = {
    suffix: "20260905T080000Z",
    bootId: "old-boot",
    rootId: "old-root",
  },
): BackupPolicy {
  return {
    source: structuredClone(source),
    volumeGroupId: "volume-group",
    standingApproval: {
      source: structuredClone(source),
      approvedAtUtc: "2026-09-05T01:51:00Z",
      exactOperation: "weekly paired backup rotation",
    },
    acceptedPair,
    retainPreviousPair: false,
    allowFifthSlot: true,
  };
}

function config(): BackupInventoryConfig {
  return {
    ociCliPath: "oci",
    ociProfile: "TEST",
    tenancyId: source.compartmentId,
    source: structuredClone(source),
    volumeGroupId: "volume-group",
    groupAccountingProved: true,
  };
}

function createState(
  options: {
    grouped?: boolean;
    groupVolumeId?: string;
    sourceVolumeIds?: string[];
    groupGetStates?: string[];
  } = {},
): MockState {
  const grouped = options.grouped === true;
  return {
    calls: [],
    sourceVolumeIds: options.sourceVolumeIds ?? [
      source.bootVolumeId,
      source.rootVolumeId,
    ],
    bootBackups: grouped ? [member("boot", sourceBootId)] : [],
    rootBackups: grouped ? [member("root", sourceRootId)] : [],
    group: grouped
      ? groupBackup(
        sourceGroupBackupId,
        sourceBootId,
        sourceRootId,
        "AVAILABLE",
        options.groupVolumeId ?? "volume-group",
      )
      : undefined,
    groupGetStates: options.groupGetStates,
    groupGetIndex: 0,
    deleted: false,
  };
}

function runnerFor(state: MockState) {
  // The synchronous fixture still implements the asynchronous command runner.
  // deno-lint-ignore require-await
  return async (_command: string, args: string[]): Promise<CommandResult> => {
    state.calls.push(args);

    if (args.includes("region-subscription")) {
      return json([{
        "is-home-region": true,
        "region-name": source.region,
      }]);
    }
    if (args.includes("compartment")) return json([]);
    if (args.includes("iam") && args.includes("availability-domain")) {
      return json([{ name: "ad-1" }]);
    }
    if (
      args.includes("compute") && args.includes("instance") &&
      args.includes("get")
    ) {
      return json(instance(), { etag: "instance-etag" });
    }
    if (args.includes("boot-volume-attachment")) {
      return json([{
        "instance-id": source.instanceId,
        "boot-volume-id": source.bootVolumeId,
        "lifecycle-state": "ATTACHED",
      }]);
    }
    if (args.includes("volume-attachment")) {
      return json([{
        "instance-id": source.instanceId,
        "volume-id": source.rootVolumeId,
        "lifecycle-state": "ATTACHED",
        "attachment-type": "paravirtualized",
      }]);
    }
    if (
      args.includes("compute") && args.includes("instance") &&
      args.includes("list")
    ) return json([instance()]);
    if (
      args.includes("bv") && args.includes("boot-volume") &&
      args.includes("list")
    ) return json([volume(source.bootVolumeId, 50)]);
    if (
      args.includes("bv") && args.includes("volume-group") &&
      args.includes("list")
    ) {
      return json([{
        id: "volume-group",
        "compartment-id": source.compartmentId,
        "availability-domain": "ad-1",
        "lifecycle-state": "AVAILABLE",
        "volume-ids": state.sourceVolumeIds,
      }]);
    }
    if (
      args.includes("bv") && args.includes("volume") &&
      args.includes("list")
    ) return json([volume(source.rootVolumeId, 150)]);
    if (
      args.includes("bv") && args.includes("boot-volume-backup") &&
      args.includes("list")
    ) return json(state.deleted ? [] : state.bootBackups);
    if (
      args.includes("bv") && args.includes("backup") &&
      args.includes("list")
    ) return json(state.deleted ? [] : state.rootBackups);
    if (
      args.includes("bv") && args.includes("volume-group-backup") &&
      args.includes("list")
    ) {
      const result = state.deleted || !state.group ? [] : [{ ...state.group }];
      if (state.group?.["lifecycle-state"] === "TERMINATING") {
        state.deleted = true;
        state.bootBackups = [];
        state.rootBackups = [];
      }
      return json(result);
    }
    if (args.includes("network") && args.includes("public-ip")) {
      return json([{ id: "public-ip", "lifecycle-state": "ASSIGNED" }]);
    }
    if (
      args.includes("bv") && args.includes("volume-group-backup") &&
      args.includes("create")
    ) {
      const id = "created-group";
      state.group = groupBackup(id, "created-boot", "created-root");
      state.bootBackups = [member("boot", "created-boot", id)];
      state.rootBackups = [member("root", "created-root", id)];
      state.groupGetStates = ["CREATING", "AVAILABLE"];
      state.groupGetIndex = 0;
      return json({ id });
    }
    if (
      args.includes("bv") && args.includes("volume-group-backup") &&
      args.includes("get")
    ) {
      assert(state.group, "The mock group is absent");
      const next = state.groupGetStates?.[state.groupGetIndex++];
      if (next === "TERMINATED") {
        state.deleted = true;
        state.bootBackups = [];
        state.rootBackups = [];
      }
      return json({
        ...state.group,
        "lifecycle-state": next ?? state.group["lifecycle-state"],
      });
    }
    if (
      args.includes("bv") && args.includes("volume-group-backup") &&
      args.includes("delete")
    ) {
      assert(state.group, "The mock group is absent");
      // OCI can remove the object before GET can ever return TERMINATED.
      state.deleted = true;
      state.bootBackups = [];
      state.rootBackups = [];
      return json([]);
    }
    throw new Error(`Unhandled OCI command: ${args.join(" ")}`);
  };
}

function operations(state: MockState, selectedPolicy = policy()) {
  const guest: BackupGuestControl = {
    acceptSource: () => Promise.resolve(),
    observeSource: () =>
      Promise.resolve({
        bootId: "boot-identity",
        serviceInvocations: { "system:caddy.service": "invocation" },
        observedAtUtc: "2026-09-06T08:00:00.000Z",
      }),
  };
  const evidence = {
    assertNoOtherController: () => Promise.resolve(),
    verify: () =>
      Promise.resolve({
        accountAndLimitsProved: true,
        backupLimit: 5,
        objectStorageComplete: true,
        objectStorageWithinLimit: true,
        groupAccountingProved: true,
      }),
  };
  return ociBackupOperations(
    config(),
    selectedPolicy,
    guest,
    evidence,
    () => Promise.resolve(),
    runnerFor(state),
    {
      now: () => new Date("2026-09-06T08:00:00.000Z"),
      sleep: () => Promise.resolve(),
    },
  );
}

async function rejects(run: () => Promise<unknown>, message: string) {
  let rejected = false;
  try {
    await run();
  } catch {
    rejected = true;
  }
  assert(rejected, message);
}

Deno.test("group creation checks the live source and uses one OCI group request", async () => {
  const state = createState();
  const ops = operations(state);
  const id = await ops.createBackupGroup(suffix);
  assert(id === "created-group", "Provider group ID was not returned");
  const create = state.calls.find((args) =>
    args.includes("volume-group-backup") && args.includes("create")
  );
  assert(create, "Group creation was not issued");
  assert(
    create[create.indexOf("--volume-group-id") + 1] === "volume-group" &&
      create[create.indexOf("--type") + 1] === "FULL" &&
      create[create.indexOf("--display-name") + 1] ===
        `arch-online-golden-${suffix}`,
    "Group request did not bind the approved source and display name",
  );
  assert(
    state.calls.filter((args) =>
      args.includes("volume-group-backup") && args.includes("create")
    ).length === 1,
    "The adapter issued more than one group create",
  );
});

Deno.test("source volume-group drift refuses creation before the provider mutation", async () => {
  const state = createState({
    sourceVolumeIds: [source.bootVolumeId, "other"],
  });
  const ops = operations(state);
  await rejects(
    () => ops.createBackupGroup(suffix),
    "Source group drift must fail closed",
  );
  assert(
    !state.calls.some((args) =>
      args.includes("volume-group-backup") && args.includes("create")
    ),
    "Group creation ran after source group drift",
  );
});

Deno.test("recorded group identity drift refuses cascading deletion", async () => {
  const state = createState({ groupVolumeId: "different-group" });
  const ops = operations(state);
  await rejects(
    () =>
      ops.deleteBackupGroup(sourceGroupBackupId, {
        bootId: sourceBootId,
        rootId: sourceRootId,
      }),
    "Recorded group drift must fail closed",
  );
  assert(
    !state.calls.some((args) =>
      args.includes("volume-group-backup") && args.includes("delete")
    ),
    "Group deletion ran after identity drift",
  );
});

Deno.test("group waiter waits through COMMITTED until AVAILABLE", async () => {
  const state = createState({
    grouped: true,
    groupGetStates: ["CREATING", "COMMITTED", "AVAILABLE"],
  });
  const ops = operations(state);
  await ops.waitBackupGroup(sourceGroupBackupId);
  assert(state.groupGetIndex === 3, "Waiter did not observe the final state");
  assert(
    state.calls.filter((args) =>
      args.includes("volume-group-backup") && args.includes("get")
    ).length === 3,
    "Waiter did not poll the group backup",
  );
});

Deno.test("grouped retention deletes one wrapper and proves member cascade", async () => {
  const state = createState({ grouped: true });
  const ops = operations(
    state,
    policy({
      suffix: "20260905T080000Z",
      bootId: sourceBootId,
      rootId: sourceRootId,
      volumeGroupBackupId: sourceGroupBackupId,
    }),
  );
  await ops.deleteBackupGroup(sourceGroupBackupId, {
    bootId: sourceBootId,
    rootId: sourceRootId,
  });
  assert(state.deleted, "Group termination was not observed");
  assert(state.bootBackups.length === 0 && state.rootBackups.length === 0);
  assert(
    state.calls.some((args) =>
      args.includes("volume-group-backup") && args.includes("delete") &&
      args.includes("--force")
    ),
    "Grouped retention did not delete the wrapper",
  );
  assert(
    !state.calls.some((args) =>
      args.includes("boot-volume-backup") && args.includes("delete")
    ) && !state.calls.some((args) =>
      args.includes("bv") && args.includes("backup") && args.includes("delete")
    ),
    "Grouped retention issued standalone member deletion",
  );
  const inventoryLists = state.calls.filter((args) =>
    args.includes("volume-group-backup") && args.includes("list")
  );
  assert(
    inventoryLists.length >= 2,
    "Cascade was not checked with a later inventory",
  );
});

Deno.test("group deletion resumes with a missing member and never repeats DELETE", async () => {
  const state = createState({ grouped: true });
  state.group!["lifecycle-state"] = "TERMINATING";
  state.bootBackups = [];
  state.rootBackups[0]["lifecycle-state"] = "TERMINATING";
  const selected = policy({
    suffix: "20260905T080000Z",
    bootId: sourceBootId,
    rootId: sourceRootId,
    volumeGroupBackupId: sourceGroupBackupId,
  });
  await operations(state, selected).deleteBackupGroup(sourceGroupBackupId, {
    bootId: sourceBootId,
    rootId: sourceRootId,
  });
  assert(!state.calls.some((args) => args.includes("delete")));
  assert(state.deleted);
});

Deno.test("online operations expose no outage or recovery methods", () => {
  const state = createState();
  const ops = operations(state) as unknown as Record<string, unknown>;
  for (
    const method of [
      "assertNoActiveWork",
      "quiesce",
      "verifyQuiesced",
      "softStop",
      "waitStopped",
      "createBackup",
      "waitBackup",
      "start",
      "recoverySnapshot",
    ]
  ) {
    assert(!(method in ops), `Legacy method remains exposed: ${method}`);
  }
});
