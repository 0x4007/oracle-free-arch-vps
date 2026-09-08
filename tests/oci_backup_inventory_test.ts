import {
  type BackupInventory,
  type ControllerInventoryConfig,
  INVENTORY_CONTROLLER_CONFIG_PATH,
  proveFreeVolumeSettings,
  proveNoBillableCustomImages,
  readFreeResourceSurfaceEvidence,
  runReadOnlyInventory,
} from "../scripts/oci-backup-inventory.ts";
import type { CommandResult } from "../scripts/oci.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

const compliantBootVolume = {
  id: "boot",
  "lifecycle-state": "AVAILABLE",
  "vpus-per-gb": 10,
  "is-auto-tune-enabled": false,
  "autotune-policies": [],
  "boot-volume-replicas": [],
};

const compliantBlockVolume = {
  id: "root",
  "lifecycle-state": "AVAILABLE",
  "vpus-per-gb": 10,
  "is-auto-tune-enabled": false,
  "autotune-policies": [],
  "block-volume-replicas": [],
};

Deno.test("free volume proof requires balanced, non-autotuned, non-replicated resources", () => {
  const boot = proveFreeVolumeSettings(
    [compliantBootVolume],
    "boot-volume-replicas",
  );
  const block = proveFreeVolumeSettings(
    [compliantBlockVolume],
    "block-volume-replicas",
  );
  assert(
    boot.performanceProved && boot.autotuneProved && boot.replicationProved,
  );
  assert(
    block.performanceProved && block.autotuneProved &&
      block.replicationProved,
  );
});

Deno.test("free volume proof refuses missing or paid volume settings", () => {
  const missing = proveFreeVolumeSettings(
    [{ "lifecycle-state": "AVAILABLE", "vpus-per-gb": 10 }],
    "block-volume-replicas",
  );
  assert(!missing.autotuneProved && !missing.replicationProved);

  const paid = proveFreeVolumeSettings(
    [{
      ...compliantBlockVolume,
      "vpus-per-gb": 20,
      "is-auto-tune-enabled": true,
      "autotune-policies": [{ name: "automatic" }],
      "block-volume-replicas": [{ id: "replica" }],
    }],
    "block-volume-replicas",
  );
  assert(!paid.performanceProved && !paid.autotuneProved);
  assert(!paid.replicationProved);
});

Deno.test("custom image proof requires explicit zero billable size", () => {
  assert(proveNoBillableCustomImages([{
    id: "platform",
    "compartment-id": null,
    "lifecycle-state": "AVAILABLE",
    "billable-size-in-gbs": 0,
  }]));
  assert(
    !proveNoBillableCustomImages([{
      id: "custom",
      "compartment-id": "tenancy",
      "lifecycle-state": "AVAILABLE",
      "billable-size-in-gbs": 50,
    }]),
  );
  assert(
    !proveNoBillableCustomImages([{
      id: "unknown",
      "lifecycle-state": "AVAILABLE",
    }]),
  );
  assert(proveNoBillableCustomImages([{
    id: "deleted",
    "lifecycle-state": "DELETED",
  }]));
});

Deno.test("resource surface inventory reads every cost-sensitive API", async () => {
  const calls: string[][] = [];
  const runner = (
    _command: string,
    args: string[],
  ): Promise<CommandResult> => {
    calls.push(args);
    let data: unknown;
    if (args.includes("iam") && args.includes("compartment")) data = [];
    else if (args.includes("availability-domain")) data = [{ name: "ad-1" }];
    else if (args.includes("compute") && args.includes("image")) {
      data = [{
        id: "platform",
        "compartment-id": null,
        "lifecycle-state": "AVAILABLE",
        "billable-size-in-gbs": 0,
      }];
    } else if (args.includes("boot-volume")) data = [compliantBootVolume];
    else if (args.includes("bv") && args.includes("volume")) {
      data = [compliantBlockVolume];
    } else throw new Error(`Unexpected command: ${args.join(" ")}`);
    return Promise.resolve({
      code: 0,
      stdout: JSON.stringify({ data }),
      stderr: "",
    });
  };
  const evidence = await readFreeResourceSurfaceEvidence({
    ociCliPath: "oci",
    ociProfile: "TEST",
    tenancyId: "tenancy",
    source: {
      instanceId: "instance",
      bootVolumeId: "boot",
      rootVolumeId: "root",
      compartmentId: "tenancy",
      region: "region",
    },
  }, runner);
  assert(evidence.freeResourceSurfaceProved);
  assert(evidence.activeBootVolumes.length === 1);
  assert(evidence.activeBlockVolumes.length === 1);
  assert(evidence.activeImages.length === 1);
  assert(
    calls.every((args) =>
      args.includes("--no-retry") && args.includes("--connection-timeout") &&
      args.includes("--read-timeout")
    ),
  );
});

Deno.test("provider null replicas and platform image sizes do not imply paid resources", () => {
  for (
    const field of ["boot-volume-replicas", "block-volume-replicas"] as const
  ) {
    assert(
      proveFreeVolumeSettings(
        [{ ...compliantBootVolume, [field]: null }],
        field,
      ).replicationProved,
    );
    assert(
      !proveFreeVolumeSettings(
        [{ ...compliantBootVolume, [field]: undefined }],
        field,
      ).replicationProved,
    );
    assert(
      !proveFreeVolumeSettings([{
        ...compliantBootVolume,
        [field]: [{ id: "replica" }],
      }], field).replicationProved,
    );
  }
  assert(
    proveNoBillableCustomImages([{
      id: "oracle-platform",
      "compartment-id": null,
      "lifecycle-state": "AVAILABLE",
      "billable-size-in-gbs": 6,
    }]),
  );
  assert(
    !proveNoBillableCustomImages([{
      id: "tenant-custom",
      "compartment-id": "tenancy",
      "lifecycle-state": "AVAILABLE",
      "billable-size-in-gbs": 6,
    }]),
  );
  assert(
    !proveNoBillableCustomImages([{
      id: "unknown",
      "lifecycle-state": "AVAILABLE",
      "billable-size-in-gbs": 0,
    }]),
  );
});

const controllerSource = {
  instanceId: "instance",
  bootVolumeId: "boot",
  rootVolumeId: "root",
  compartmentId: "tenancy",
  region: "region",
};

/** Current controller config shape: runtime action plus binding/evidence, with
 * the extra policy carried by the controller configuration. */
const controllerConfig = (action: "cycle" | "preflight") => ({
  action,
  ociCliPath: "oci",
  ociProfile: "TEST",
  tenancyId: "tenancy",
  source: controllerSource,
  volumeGroupId: "volume-group",
  groupAccountingProved: true,
  policy: {
    source: controllerSource,
    volumeGroupId: "volume-group",
    standingApproval: {
      approvedAtUtc: "2026-09-05T01:51:00Z",
      exactOperation: "weekly paired backup rotation",
      source: controllerSource,
    },
    acceptedPair: {
      suffix: "20260903T191507Z",
      bootId: "boot",
      rootId: "root",
    },
    retainPreviousPair: true,
    allowFifthSlot: true,
  },
  guest: {
    host: "codex@controller",
    rootUuid: "root-uuid",
    stagingUuid: "staging-uuid",
    activityScriptPath:
      "/home/codex/ops/weekly-backup-controller/backup-guest-activity.ts",
  },
});

const cannedInventory: BackupInventory = {
  observedAtUtc: "2026-09-05T00:00:00.000Z",
  source: controllerSource,
  homeRegion: "region",
  compartments: 1,
  instance: { id: "instance" },
  instanceEtag: "etag",
  bootVolume: { id: "boot" },
  rootVolume: { id: "root" },
  bootAttachments: [],
  rootAttachments: [],
  bootBackups: [],
  rootBackups: [],
  volumeGroups: [],
  volumeGroupBackups: [],
  sourceVolumeGroup: { id: "volume-group" },
  sourceVolumeGroupProved: true,
  publicIps: [],
  totals: {
    instances: 1,
    ocpus: 2,
    memoryGb: 12,
    liveVolumeGb: 200,
    backups: 0,
    volumeGroupBackups: 0,
    volumeGroups: 1,
    publicIps: 1,
  },
  sourceAttachmentsProved: true,
  groupAccountingProved: true,
};

Deno.test("inventory entry point loads the current controller config and never the legacy path", async () => {
  const requested: string[] = [];
  const written = [] as { path: string; value: BackupInventory }[];
  const inventory = await runReadOnlyInventory({
    readConfig: (path: string) => {
      requested.push(path);
      if (path !== INVENTORY_CONTROLLER_CONFIG_PATH) {
        throw new Error(`Reading an unexpected entry-point config: ${path}`);
      }
      return Promise.resolve(controllerConfig("preflight"));
    },
    inventory: () => Promise.resolve(cannedInventory),
    writeReport: (path, value) => {
      written.push({ path, value });
      return Promise.resolve();
    },
  });
  assert(requested.length === 1);
  assert(requested[0] === ".private/backup-controller.json");
  assert(!requested.includes(".private/weekly-backup.json"));
  assert(written.length === 1);
  assert(
    written[0].path === ".private/reports/weekly-controller-inventory.json",
  );
  assert(written[0].value === inventory);
});

Deno.test("cycle and preflight controller configs are accepted by the inventory loader without cloud calls", async () => {
  for (const action of ["cycle", "preflight"] as const) {
    let inventoryReads = 0;
    let reportWrites = 0;
    let received: ControllerInventoryConfig | undefined;
    const config = controllerConfig(action);
    const inventory = await runReadOnlyInventory({
      readConfig: () => Promise.resolve(config),
      inventory: (loaded) => {
        inventoryReads += 1;
        received = loaded;
        return Promise.resolve(cannedInventory);
      },
      writeReport: () => {
        reportWrites += 1;
        return Promise.resolve();
      },
    });
    assert(inventoryReads === 1);
    assert(reportWrites === 1);
    assert(received?.action === action);
    assert(received?.volumeGroupId === "volume-group");
    assert(received?.groupAccountingProved === true);
    assert(
      JSON.stringify(received?.source) === JSON.stringify(config.source),
    );
    assert(inventory.sourceVolumeGroupProved);
    assert(inventory.groupAccountingProved);
  }
});

Deno.test("inventory entry point stays fail-closed when the controller config is unreadable", async () => {
  let inventoryReads = 0;
  let reportWrites = 0;
  let thrown: unknown;
  try {
    await runReadOnlyInventory({
      readConfig: () => {
        throw new Error("Missing or malformed current controller config");
      },
      inventory: () => {
        inventoryReads += 1;
        return Promise.resolve(cannedInventory);
      },
      writeReport: () => {
        reportWrites += 1;
        return Promise.resolve();
      },
    });
  } catch (error) {
    thrown = error;
  }
  assert(
    thrown instanceof Error &&
      thrown.message.includes("Missing or malformed current controller config"),
  );
  assert(inventoryReads === 0);
  assert(reportWrites === 0);
});
