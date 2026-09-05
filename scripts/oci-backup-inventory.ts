import {
  type CommandRunner,
  dataArray,
  dataObject,
  defaultRunner,
  type JsonRecord,
  numberField,
  runJson,
  stringField,
} from "./oci.ts";
import { type BackupSnapshot, type BackupSource } from "./weekly-backup.ts";

export interface BackupInventoryConfig {
  ociCliPath: string;
  ociProfile: string;
  tenancyId: string;
  source: BackupSource;
}

export interface BackupInventory {
  observedAtUtc: string;
  source: BackupSource;
  homeRegion: string;
  compartments: number;
  instance: JsonRecord;
  instanceEtag: string;
  bootVolume: JsonRecord;
  rootVolume: JsonRecord;
  bootAttachments: JsonRecord[];
  rootAttachments: JsonRecord[];
  bootBackups: JsonRecord[];
  rootBackups: JsonRecord[];
  publicIps: JsonRecord[];
  totals: {
    instances: number;
    ocpus: number;
    memoryGb: number;
    liveVolumeGb: number;
    backups: number;
    publicIps: number;
  };
  sourceAttachmentsProved: boolean;
}

/** All calls are read-only. Inaccessible compartments or malformed responses
 * reject the inventory rather than turning incomplete accounting into zero use.
 */
export async function readBackupInventory(
  config: BackupInventoryConfig,
  runner: CommandRunner = defaultRunner,
): Promise<BackupInventory> {
  const call = (args: string[]) =>
    runJson(config.ociCliPath, [
      "--profile",
      config.ociProfile,
      "--region",
      config.source.region,
      ...args,
    ], runner);
  const subscriptions = dataArray(
    await call(["iam", "region-subscription", "list"]),
  );
  const homes = subscriptions.filter((item) => item["is-home-region"] === true);
  if (homes.length !== 1 || homes[0]["region-name"] !== config.source.region) {
    throw new Error(
      "Backup controller must operate in the tenancy home region",
    );
  }
  // Any additional subscription must be accounted for before mutation. This
  // first deployment has exactly one region; do not silently omit another.
  if (subscriptions.length !== 1) {
    throw new Error("Additional regions require tenancy-wide accounting");
  }
  const compartments = dataArray(
    await call([
      "iam",
      "compartment",
      "list",
      "--compartment-id",
      config.tenancyId,
      "--compartment-id-in-subtree",
      "true",
      "--access-level",
      "ANY",
      "--all",
    ]),
  );
  const ids = [
    config.tenancyId,
    ...compartments.filter((item) => item["lifecycle-state"] === "ACTIVE")
      .map((item) => stringField(item, "id")),
  ];
  if (!ids.includes(config.source.compartmentId)) {
    throw new Error("Source compartment is outside the tenancy inventory");
  }
  const domains = dataArray(
    await call([
      "iam",
      "availability-domain",
      "list",
      "--compartment-id",
      config.tenancyId,
    ]),
  );
  if (domains.length === 0) throw new Error("No availability domains returned");
  const instances: JsonRecord[] = [],
    bootVolumes: JsonRecord[] = [],
    rootVolumes: JsonRecord[] = [];
  const bootBackups: JsonRecord[] = [],
    rootBackups: JsonRecord[] = [],
    publicIps: JsonRecord[] = [];
  for (const id of ids) {
    for (
      const [target, args] of [
        [instances, ["compute", "instance", "list"]],
        [rootVolumes, ["bv", "volume", "list"]],
        [bootBackups, ["bv", "boot-volume-backup", "list"]],
        [rootBackups, ["bv", "backup", "list"]],
        [publicIps, ["network", "public-ip", "list", "--scope", "REGION"]],
      ] as [JsonRecord[], string[]][]
    ) {
      target.push(
        ...dataArray(await call([...args, "--compartment-id", id, "--all"])),
      );
    }
    for (const domain of domains) {
      bootVolumes.push(
        ...dataArray(
          await call([
            "bv",
            "boot-volume",
            "list",
            "--compartment-id",
            id,
            "--availability-domain",
            stringField(domain, "name"),
            "--all",
          ]),
        ),
      );
      // Ephemeral IPs use availability-domain scope; regional scope contains
      // reserved addresses and cannot establish the whole public-IP total.
      publicIps.push(
        ...dataArray(
          await call([
            "network",
            "public-ip",
            "list",
            "--compartment-id",
            id,
            "--scope",
            "AVAILABILITY_DOMAIN",
            "--availability-domain",
            stringField(domain, "name"),
            "--all",
          ]),
        ),
      );
    }
  }
  const active = (items: JsonRecord[]) =>
    items.filter((item) => item["lifecycle-state"] !== "TERMINATED");
  const exact = (items: JsonRecord[], id: string, label: string) => {
    const matches = active(items).filter((item) => item.id === id);
    if (matches.length !== 1) {
      throw new Error(`Exact ${label} is missing or duplicated`);
    }
    return matches[0];
  };
  exact(
    instances,
    config.source.instanceId,
    "source instance",
  );
  const instanceResponse = await call([
    "compute",
    "instance",
    "get",
    "--instance-id",
    config.source.instanceId,
  ]);
  const instance = dataObject(instanceResponse);
  const instanceEtag = stringField(instanceResponse, "etag");
  const bootVolume = exact(
    bootVolumes,
    config.source.bootVolumeId,
    "source boot volume",
  );
  const rootVolume = exact(
    rootVolumes,
    config.source.rootVolumeId,
    "source root volume",
  );
  for (const item of [instance, bootVolume, rootVolume]) {
    if (item["compartment-id"] !== config.source.compartmentId) {
      throw new Error("Source compartment changed");
    }
  }
  if (
    instance.shape !== "VM.Standard.A1.Flex" ||
    numberField(bootVolume, "size-in-gbs") !== 50 ||
    numberField(rootVolume, "size-in-gbs") !== 150 ||
    numberField(bootVolume, "vpus-per-gb") !== 10 ||
    numberField(rootVolume, "vpus-per-gb") !== 10
  ) throw new Error("Source shape or storage contract changed");
  const bootAttachments = dataArray(
    await call([
      "compute",
      "boot-volume-attachment",
      "list",
      "--compartment-id",
      config.source.compartmentId,
      "--instance-id",
      config.source.instanceId,
      "--availability-domain",
      stringField(instance, "availability-domain"),
      "--all",
    ]),
  );
  const rootAttachments = dataArray(
    await call([
      "compute",
      "volume-attachment",
      "list",
      "--compartment-id",
      config.source.compartmentId,
      "--instance-id",
      config.source.instanceId,
      "--all",
    ]),
  );
  const attachedBoot = bootAttachments.filter((a) =>
    a["lifecycle-state"] !== "DETACHED"
  );
  const attachedRoot = rootAttachments.filter((a) =>
    a["lifecycle-state"] !== "DETACHED"
  );
  const sourceAttachmentsProved = attachedBoot.length === 1 &&
    attachedRoot.length === 1 &&
    attachedBoot[0]["boot-volume-id"] === config.source.bootVolumeId &&
    attachedRoot[0]["volume-id"] === config.source.rootVolumeId &&
    attachedBoot[0]["instance-id"] === config.source.instanceId &&
    attachedRoot[0]["instance-id"] === config.source.instanceId &&
    attachedBoot[0]["lifecycle-state"] === "ATTACHED" &&
    attachedRoot[0]["lifecycle-state"] === "ATTACHED" &&
    String(attachedRoot[0]["attachment-type"]).toLowerCase() ===
      "paravirtualized";
  let ocpus = 0, memoryGb = 0;
  for (const item of active(instances)) {
    const shape = dataObject({ data: item["shape-config"] });
    ocpus += numberField(shape, "ocpus");
    memoryGb += numberField(shape, "memory-in-gbs");
  }
  return {
    observedAtUtc: new Date().toISOString(),
    source: config.source,
    homeRegion: config.source.region,
    compartments: ids.length,
    instance,
    instanceEtag,
    bootVolume,
    rootVolume,
    bootAttachments,
    rootAttachments,
    bootBackups,
    rootBackups,
    publicIps,
    totals: {
      instances: active(instances).length,
      ocpus,
      memoryGb,
      liveVolumeGb: active([...bootVolumes, ...rootVolumes]).reduce(
        (n, item) => n + numberField(item, "size-in-gbs"),
        0,
      ),
      backups: active([...bootBackups, ...rootBackups]).length,
      publicIps: new Set(publicIps.map((item) => stringField(item, "id"))).size,
    },
    sourceAttachmentsProved,
  };
}

/** Account/official-limit and writer evidence must come from the controller's
 * separate current checks, not from resource metadata alone.
 */
export function backupSnapshot(
  inventory: BackupInventory,
  evidence: {
    accountAndLimitsProved: boolean;
    writersAbsent: boolean;
    backupLimit: number;
  },
): BackupSnapshot {
  const totals = inventory.totals;
  return {
    source: inventory.source,
    instanceState: stringField(inventory.instance, "lifecycle-state"),
    stoppedEpoch: inventory.instance["lifecycle-state"] === "STOPPED"
      ? inventory.instanceEtag
      : undefined,
    bootBackups: inventory.bootBackups,
    rootBackups: inventory.rootBackups,
    allBackupCount: totals.backups,
    freeBackupLimit: evidence.backupLimit,
    sourceAttachmentsProved: inventory.sourceAttachmentsProved,
    freeEligibilityProved: evidence.accountAndLimitsProved &&
      totals.instances === 1 &&
      totals.ocpus <= 2 && totals.memoryGb <= 12 &&
      totals.liveVolumeGb === 200 && totals.publicIps === 1,
    writersAbsent: evidence.writersAbsent,
  };
}

if (import.meta.main) {
  const { readPrivateJson, writePrivateJson, redactOcid } = await import(
    "./oci.ts"
  );
  try {
    const config = await readPrivateJson<
      BackupInventoryConfig & { action: string }
    >(".private/weekly-backup.json");
    if (config.action !== "inventory") {
      throw new Error("This entry point only permits read-only inventory");
    }
    const inventory = await readBackupInventory(config);
    await writePrivateJson(
      ".private/reports/weekly-controller-inventory.json",
      inventory,
    );
    console.log(JSON.stringify(
      {
        status: "INVENTORY_RECORDED",
        observedAtUtc: inventory.observedAtUtc,
        homeRegion: inventory.homeRegion,
        compartments: inventory.compartments,
        totals: inventory.totals,
        sourceAttachmentsProved: inventory.sourceAttachmentsProved,
        backupCreated: false,
        restoreDrillProved: false,
      },
      null,
      2,
    ));
  } catch (error) {
    console.error(
      redactOcid(error instanceof Error ? error.message : String(error)),
    );
    Deno.exitCode = 1;
  }
}
