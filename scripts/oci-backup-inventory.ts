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
  /** Existing source group; it is never created by the inventory reader. */
  volumeGroupId?: string;
  /** Set only after the primary has proved provider wrapper accounting live. */
  groupAccountingProved?: boolean;
}

export interface FreeResourceSurfaceEvidence {
  /** Every active boot/block volume was observed with the balanced setting. */
  volumePerformanceProved: boolean;
  /** Every active boot/block volume explicitly reports autotune disabled. */
  volumeAutotuneProved: boolean;
  /** Every active boot/block volume explicitly reports no replica members. */
  volumeReplicationProved: boolean;
  /** Every active image returned by the tenancy inventory has zero billable size. */
  customImagesProved: boolean;
  /** No cost-sensitive surface was missing or outside the free-only envelope. */
  freeResourceSurfaceProved: boolean;
  activeBootVolumes: JsonRecord[];
  activeBlockVolumes: JsonRecord[];
  activeImages: JsonRecord[];
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
  volumeGroups: JsonRecord[];
  volumeGroupBackups: JsonRecord[];
  sourceVolumeGroup?: JsonRecord;
  sourceVolumeGroupProved: boolean;
  publicIps: JsonRecord[];
  totals: {
    instances: number;
    ocpus: number;
    memoryGb: number;
    liveVolumeGb: number;
    backups: number;
    volumeGroupBackups: number;
    volumeGroups: number;
    publicIps: number;
  };
  sourceAttachmentsProved: boolean;
  groupAccountingProved: boolean;
}

function active(items: JsonRecord[]): JsonRecord[] {
  return items.filter((item) => item["lifecycle-state"] !== "TERMINATED");
}

function uniqueById(items: JsonRecord[]): JsonRecord[] {
  const byId = new Map<string, JsonRecord>();
  for (const item of items) {
    const id = item.id;
    if (typeof id === "string") byId.set(id, item);
    else byId.set(`${byId.size}:${JSON.stringify(item)}`, item);
  }
  return [...byId.values()];
}

function activeImages(items: JsonRecord[]): JsonRecord[] {
  return items.filter((item) =>
    !["TERMINATED", "DELETED"].includes(String(item["lifecycle-state"]))
  );
}

function hasEmptyList(item: JsonRecord, field: string): boolean {
  return Array.isArray(item[field]) && item[field].length === 0;
}

/**
 * Validate the provider fields that determine whether volume resources can
 * remain in the Always Free envelope. Missing fields are unknown evidence and
 * therefore fail closed. The field names are the OCI API response names.
 */
export function proveFreeVolumeSettings(
  volumes: JsonRecord[],
  replicaField: "boot-volume-replicas" | "block-volume-replicas",
): {
  performanceProved: boolean;
  autotuneProved: boolean;
  replicationProved: boolean;
} {
  const activeVolumes = active(volumes);
  return {
    performanceProved: activeVolumes.every((item) =>
      item["vpus-per-gb"] === 10
    ),
    autotuneProved: activeVolumes.every((item) =>
      item["is-auto-tune-enabled"] === false &&
      hasEmptyList(item, "autotune-policies")
    ),
    replicationProved: activeVolumes.every((item) =>
      item[replicaField] === null || hasEmptyList(item, replicaField)
    ),
  };
}

/**
 * Oracle platform images have an explicit null compartment. Their size fields
 * are not tenant storage charges. Require identity and compartment metadata;
 * tenant-owned images must explicitly have zero billable size.
 */
export function proveNoBillableCustomImages(
  images: JsonRecord[],
): boolean {
  return activeImages(images).every((image) =>
    typeof image.id === "string" && image.id.length > 0 &&
    (image["compartment-id"] === null ||
      (typeof image["compartment-id"] === "string" &&
        image["compartment-id"].length > 0 &&
        image["billable-size-in-gbs"] === 0))
  );
}

/**
 * Prove the cost-sensitive surfaces that are outside the paired backup
 * identity. The caller must supply the complete tenancy inventory; an
 * inaccessible or malformed list must reject before reaching this function.
 */
export function proveFreeResourceSurfaces(
  bootVolumes: JsonRecord[],
  blockVolumes: JsonRecord[],
  images: JsonRecord[],
): FreeResourceSurfaceEvidence {
  const bootProof = proveFreeVolumeSettings(
    bootVolumes,
    "boot-volume-replicas",
  );
  const blockProof = proveFreeVolumeSettings(
    blockVolumes,
    "block-volume-replicas",
  );
  const customImagesProved = proveNoBillableCustomImages(images);
  const volumePerformanceProved = bootProof.performanceProved &&
    blockProof.performanceProved;
  const volumeAutotuneProved = bootProof.autotuneProved &&
    blockProof.autotuneProved;
  const volumeReplicationProved = bootProof.replicationProved &&
    blockProof.replicationProved;
  return {
    volumePerformanceProved,
    volumeAutotuneProved,
    volumeReplicationProved,
    customImagesProved,
    freeResourceSurfaceProved: volumePerformanceProved &&
      volumeAutotuneProved && volumeReplicationProved && customImagesProved,
    activeBootVolumes: bootVolumes,
    activeBlockVolumes: blockVolumes,
    activeImages: images,
  };
}

/**
 * Read the cost-sensitive resource surfaces that are outside the paired
 * backup inventory. All calls are read-only. Any inaccessible or malformed
 * response rejects through runJson/dataArray instead of becoming zero use.
 */
export async function readFreeResourceSurfaceEvidence(
  config: BackupInventoryConfig,
  runner: CommandRunner = defaultRunner,
): Promise<FreeResourceSurfaceEvidence> {
  const call = (args: string[]) =>
    runJson(config.ociCliPath, [
      "--profile",
      config.ociProfile,
      "--region",
      config.source.region,
      "--no-retry",
      "--connection-timeout",
      "10",
      "--read-timeout",
      "60",
      ...args,
    ], runner);
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
  const compartmentIds = [
    config.tenancyId,
    ...compartments.filter((item) => item["lifecycle-state"] === "ACTIVE")
      .map((item) => stringField(item, "id")),
  ];
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
  const bootVolumes: JsonRecord[] = [];
  const blockVolumes: JsonRecord[] = [];
  const images: JsonRecord[] = [];
  for (const compartmentId of compartmentIds) {
    images.push(
      ...dataArray(
        await call([
          "compute",
          "image",
          "list",
          "--compartment-id",
          compartmentId,
          "--all",
        ]),
      ),
    );
    for (const domain of domains) {
      const availabilityDomain = stringField(domain, "name");
      bootVolumes.push(
        ...dataArray(
          await call([
            "bv",
            "boot-volume",
            "list",
            "--compartment-id",
            compartmentId,
            "--availability-domain",
            availabilityDomain,
            "--all",
          ]),
        ),
      );
      blockVolumes.push(
        ...dataArray(
          await call([
            "bv",
            "volume",
            "list",
            "--compartment-id",
            compartmentId,
            "--availability-domain",
            availabilityDomain,
            "--all",
          ]),
        ),
      );
    }
  }
  const activeBootVolumes = uniqueById(bootVolumes).filter((item) =>
    item["lifecycle-state"] !== "TERMINATED"
  );
  const activeBlockVolumes = uniqueById(blockVolumes).filter((item) =>
    item["lifecycle-state"] !== "TERMINATED"
  );
  const activeImagesList = uniqueById(images).filter((item) =>
    !["TERMINATED", "DELETED"].includes(String(item["lifecycle-state"]))
  );
  const surface = proveFreeResourceSurfaces(
    activeBootVolumes,
    activeBlockVolumes,
    activeImagesList,
  );
  return {
    ...surface,
    activeBootVolumes,
    activeBlockVolumes,
    activeImages: activeImagesList,
  };
}

function volumeIds(group: JsonRecord): string[] {
  const value = group["volume-ids"];
  if (!Array.isArray(value) || value.some((id) => typeof id !== "string")) {
    throw new Error("Source volume group has no valid volume member list");
  }
  return value as string[];
}

function proveSourceVolumeGroup(
  groups: JsonRecord[],
  config: BackupInventoryConfig,
  availabilityDomain: string,
): JsonRecord | undefined {
  if (!config.volumeGroupId) return undefined;
  const matches = active(groups).filter((item) =>
    item.id === config.volumeGroupId
  );
  if (matches.length !== 1) {
    throw new Error("Exact source volume group is missing or duplicated");
  }
  const group = matches[0];
  const ids = volumeIds(group);
  if (
    group["compartment-id"] !== config.source.compartmentId ||
    group["availability-domain"] !== availabilityDomain ||
    ids.length !== 2 || new Set(ids).size !== 2 ||
    !ids.includes(config.source.bootVolumeId) ||
    !ids.includes(config.source.rootVolumeId)
  ) {
    throw new Error(
      "Source volume group does not bind exactly both source volumes",
    );
  }
  return group;
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
      "--no-retry",
      "--connection-timeout",
      "10",
      "--read-timeout",
      "60",
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
  // controller has one home-region accounting boundary.
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
  const instances: JsonRecord[] = [];
  const bootVolumes: JsonRecord[] = [];
  const rootVolumes: JsonRecord[] = [];
  const bootBackups: JsonRecord[] = [];
  const rootBackups: JsonRecord[] = [];
  const volumeGroups: JsonRecord[] = [];
  const volumeGroupBackups: JsonRecord[] = [];
  const publicIps: JsonRecord[] = [];
  for (const id of ids) {
    for (
      const [target, args] of [
        [instances, ["compute", "instance", "list"]],
        [rootVolumes, ["bv", "volume", "list"]],
        [bootBackups, ["bv", "boot-volume-backup", "list"]],
        [rootBackups, ["bv", "backup", "list"]],
        [volumeGroupBackups, ["bv", "volume-group-backup", "list"]],
        [publicIps, ["network", "public-ip", "list", "--scope", "REGION"]],
      ] as [JsonRecord[], string[]][]
    ) {
      target.push(
        ...dataArray(await call([...args, "--compartment-id", id, "--all"])),
      );
    }
    for (const domain of domains) {
      const domainName = stringField(domain, "name");
      bootVolumes.push(
        ...dataArray(
          await call([
            "bv",
            "boot-volume",
            "list",
            "--compartment-id",
            id,
            "--availability-domain",
            domainName,
            "--all",
          ]),
        ),
      );
      volumeGroups.push(
        ...dataArray(
          await call([
            "bv",
            "volume-group",
            "list",
            "--compartment-id",
            id,
            "--availability-domain",
            domainName,
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
            domainName,
            "--all",
          ]),
        ),
      );
    }
  }
  const allInstances = uniqueById(instances);
  const allBootVolumes = uniqueById(bootVolumes);
  const allRootVolumes = uniqueById(rootVolumes);
  const allBootBackups = uniqueById(bootBackups);
  const allRootBackups = uniqueById(rootBackups);
  const allVolumeGroups = uniqueById(volumeGroups);
  const allVolumeGroupBackups = uniqueById(volumeGroupBackups);
  const exact = (items: JsonRecord[], id: string, label: string) => {
    const matches = active(items).filter((item) => item.id === id);
    if (matches.length !== 1) {
      throw new Error(`Exact ${label} is missing or duplicated`);
    }
    return matches[0];
  };
  exact(allInstances, config.source.instanceId, "source instance");
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
    allBootVolumes,
    config.source.bootVolumeId,
    "source boot volume",
  );
  const rootVolume = exact(
    allRootVolumes,
    config.source.rootVolumeId,
    "source root volume",
  );
  for (const item of [instance, bootVolume, rootVolume]) {
    if (item["compartment-id"] !== config.source.compartmentId) {
      throw new Error("Source compartment changed");
    }
  }
  const availabilityDomain = stringField(instance, "availability-domain");
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
      availabilityDomain,
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
  const sourceVolumeGroup = proveSourceVolumeGroup(
    allVolumeGroups,
    config,
    availabilityDomain,
  );
  let ocpus = 0;
  let memoryGb = 0;
  for (const item of active(allInstances)) {
    const shape = dataObject({ data: item["shape-config"] });
    ocpus += numberField(shape, "ocpus");
    memoryGb += numberField(shape, "memory-in-gbs");
  }
  const activeBootBackups = active(allBootBackups);
  const activeRootBackups = active(allRootBackups);
  const activeGroups = active(allVolumeGroups);
  const activeGroupBackups = active(allVolumeGroupBackups);
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
    bootBackups: activeBootBackups,
    rootBackups: activeRootBackups,
    volumeGroups: activeGroups,
    volumeGroupBackups: activeGroupBackups,
    sourceVolumeGroup,
    sourceVolumeGroupProved: sourceVolumeGroup !== undefined,
    publicIps: uniqueById(publicIps),
    totals: {
      instances: active(allInstances).length,
      ocpus,
      memoryGb,
      liveVolumeGb: active([...allBootVolumes, ...allRootVolumes]).reduce(
        (n, item) => n + numberField(item, "size-in-gbs"),
        0,
      ),
      backups: activeBootBackups.length + activeRootBackups.length,
      volumeGroupBackups: activeGroupBackups.length,
      volumeGroups: activeGroups.length,
      publicIps: uniqueById(publicIps).length,
    },
    sourceAttachmentsProved,
    groupAccountingProved: config.groupAccountingProved === true,
  };
}

/** Account/official-limit and writer evidence must come from the controller's
 * separate current checks, not from resource metadata alone. */
export function backupSnapshot(
  inventory: BackupInventory,
  evidence: {
    accountAndLimitsProved: boolean;
    writersAbsent: boolean;
    backupLimit: number;
    groupAccountingProved?: boolean;
  },
): BackupSnapshot {
  const totals = inventory.totals;
  const groupAccountingProved = evidence.groupAccountingProved === true ||
    inventory.groupAccountingProved === true;
  return {
    source: inventory.source,
    instanceState: stringField(inventory.instance, "lifecycle-state"),
    bootBackups: inventory.bootBackups,
    rootBackups: inventory.rootBackups,
    allBackupCount: totals.backups,
    allVolumeGroupBackupCount: totals.volumeGroupBackups,
    freeBackupLimit: evidence.backupLimit,
    volumeGroups: inventory.volumeGroups,
    volumeGroupBackups: inventory.volumeGroupBackups,
    sourceAttachmentsProved: inventory.sourceAttachmentsProved,
    sourceVolumeGroupProved: inventory.sourceVolumeGroupProved,
    groupAccountingProved,
    freeEligibilityProved: evidence.accountAndLimitsProved &&
      totals.instances === 1 &&
      totals.ocpus <= 2 && totals.memoryGb <= 12 &&
      totals.liveVolumeGb === 200 && totals.publicIps === 1 &&
      inventory.sourceAttachmentsProved && inventory.sourceVolumeGroupProved &&
      groupAccountingProved,
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
    >(
      ".private/weekly-backup.json",
    );
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
        sourceVolumeGroupProved: inventory.sourceVolumeGroupProved,
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
