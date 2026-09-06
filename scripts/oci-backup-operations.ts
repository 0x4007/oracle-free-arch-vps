import type { SourceContinuityEvidence } from "./online-backup-contract.ts";
import {
  type CommandRunner,
  dataObject,
  defaultRunner,
  type JsonRecord,
  numberField,
  runJson,
  stringField,
} from "./oci.ts";
import {
  type BackupInventoryConfig,
  backupSnapshot,
  readBackupInventory,
} from "./oci-backup-inventory.ts";
import {
  type BackupJournal,
  type BackupOperations,
  type BackupPair,
  type BackupPolicy,
  validateStandingApproval,
} from "./weekly-backup.ts";

/** The guest adapter is read-only. It cannot stop, start, freeze, kill or
 * otherwise repair the production source. */
export interface BackupGuestControl {
  acceptSource(): Promise<void>;
  observeSource(): Promise<SourceContinuityEvidence>;
}

export interface BackupControllerEvidence {
  verify(): Promise<{
    accountAndLimitsProved: boolean;
    backupLimit: number;
    objectStorageComplete: boolean;
    objectStorageWithinLimit: boolean;
    objectStorageBytes?: number;
    objectStorageHeadroomBytes?: number;
    /** Optional until the primary's live group SKU/accounting audit passes. */
    groupAccountingProved?: boolean;
  }>;
  assertNoOtherController(): Promise<void>;
}

export interface BackupClock {
  now(): Date;
  sleep(milliseconds: number): Promise<void>;
}

const clock: BackupClock = {
  now: () => new Date(),
  sleep: (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
};

function active(items: JsonRecord[]): JsonRecord[] {
  return items.filter((item) => item["lifecycle-state"] !== "TERMINATED");
}

function validId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function member(
  item: JsonRecord,
  kind: "boot" | "root",
  policy: BackupPolicy,
): void {
  if (stringField(item, "lifecycle-state") !== "AVAILABLE") {
    throw new Error(`The ${kind} backup is not AVAILABLE`);
  }
  if (stringField(item, "type") !== "FULL") {
    throw new Error(`The ${kind} backup is not FULL`);
  }
  if (numberField(item, "size-in-gbs") !== (kind === "boot" ? 50 : 150)) {
    throw new Error(`The ${kind} backup size changed`);
  }
  const sourceKey = kind === "boot" ? "boot-volume-id" : "volume-id";
  const sourceId = kind === "boot"
    ? policy.source.bootVolumeId
    : policy.source.rootVolumeId;
  if (
    item[sourceKey] !== sourceId ||
    item["compartment-id"] !== policy.source.compartmentId ||
    !validId(item.id)
  ) throw new Error(`The ${kind} backup source changed`);
  if (
    typeof item["time-created"] !== "string" ||
    !Number.isFinite(Date.parse(item["time-created"]))
  ) {
    throw new Error(`The ${kind} backup timestamp is invalid`);
  }
}

function sameMembers(
  ids: unknown,
  members: Pick<BackupPair, "bootId" | "rootId">,
): boolean {
  return Array.isArray(ids) && ids.length === 2 &&
    new Set(ids).size === 2 &&
    ids.every((id) => typeof id === "string") &&
    (ids as string[]).includes(members.bootId) &&
    (ids as string[]).includes(members.rootId);
}

/** Creates real OCI operations, but performs no mutation until called by the
 * journaled online state machine under the controller lock. The returned group
 * backup ID is persisted by the caller before waitBackupGroup is invoked. */
export function ociBackupOperations(
  config: BackupInventoryConfig,
  policy: BackupPolicy,
  guest: BackupGuestControl,
  evidence: BackupControllerEvidence,
  save: (journal: BackupJournal) => Promise<void>,
  runner: CommandRunner = defaultRunner,
  time: BackupClock = clock,
): BackupOperations {
  const authorize = () => {
    validateStandingApproval(policy, time.now());
    if (
      config.volumeGroupId !== undefined &&
      config.volumeGroupId !== policy.volumeGroupId
    ) throw new Error("OCI volume group differs from standing approval");
    for (
      const key of [
        "instanceId",
        "bootVolumeId",
        "rootVolumeId",
        "compartmentId",
        "region",
      ] as const
    ) {
      if (config.source[key] !== policy.source[key]) {
        throw new Error("OCI targets differ from standing approval");
      }
    }
  };
  const inventoryConfig = (): BackupInventoryConfig => ({
    ...config,
    volumeGroupId: policy.volumeGroupId,
  });
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
  const instance = async () => {
    const response = await call([
      "compute",
      "instance",
      "get",
      "--instance-id",
      policy.source.instanceId,
    ]);
    const value = dataObject(response);
    if (
      value.id !== policy.source.instanceId ||
      value["compartment-id"] !== policy.source.compartmentId ||
      value.shape !== "VM.Standard.A1.Flex" ||
      (value["shape-config"] as JsonRecord)?.ocpus !== 2 ||
      (value["shape-config"] as JsonRecord)?.["memory-in-gbs"] !== 12
    ) throw new Error("Source instance identity changed");
    return { value, etag: stringField(response, "etag") };
  };
  const sourceInventory = async () => {
    authorize();
    await evidence.assertNoOtherController();
    const current = await readBackupInventory(inventoryConfig(), runner);
    if (
      current.instance["lifecycle-state"] !== "RUNNING" ||
      !current.sourceAttachmentsProved ||
      !current.sourceVolumeGroupProved
    ) {
      throw new Error(
        "Source is not running with the approved volume group bound",
      );
    }
    return current;
  };
  const backupGet = async (kind: "boot" | "root", id: string) =>
    dataObject(
      await call([
        "bv",
        kind === "boot" ? "boot-volume-backup" : "backup",
        "get",
        kind === "boot" ? "--boot-volume-backup-id" : "--volume-backup-id",
        id,
      ]),
    );
  const groupBackupGet = async (id: string) =>
    dataObject(
      await call([
        "bv",
        "volume-group-backup",
        "get",
        "--volume-group-backup-id",
        id,
      ]),
    );
  const wait = async (
    read: () => Promise<JsonRecord>,
    desired: string,
    pending: string[],
    seconds: number,
  ) => {
    const deadline = time.now().getTime() + seconds * 1000;
    while (true) {
      const item = await read();
      const state = stringField(item, "lifecycle-state");
      if (state === desired) return;
      if (!pending.includes(state)) {
        throw new Error(`Unexpected OCI lifecycle state: ${state}`);
      }
      if (time.now().getTime() >= deadline) {
        throw new Error(`OCI ${desired} wait timed out; last state ${state}`);
      }
      await time.sleep(5_000);
    }
  };
  return {
    now: time.now,
    save,
    snapshot: async () => {
      authorize();
      const proof = await evidence.verify();
      if (
        !Number.isInteger(proof.backupLimit) ||
        proof.backupLimit < 2 || proof.backupLimit > 5
      ) throw new Error("Current free backup allowance is not proved");
      await evidence.assertNoOtherController();
      const inventory = await readBackupInventory(inventoryConfig(), runner);
      return backupSnapshot(inventory, {
        accountAndLimitsProved: proof.accountAndLimitsProved &&
          proof.objectStorageComplete && proof.objectStorageWithinLimit,
        backupLimit: proof.backupLimit,
        groupAccountingProved: proof.groupAccountingProved,
        writersAbsent: true,
      });
    },
    observeSource: () => guest.observeSource(),
    acceptSource: () => guest.acceptSource(),
    createBackupGroup: async (suffix) => {
      authorize();
      if (!/^\d{8}T\d{6}Z$/.test(suffix)) {
        throw new Error("Invalid backup suffix");
      }
      // This is the final source/group/attachment check before mutation. It
      // also gives an ambiguous provider response a complete inventory to
      // reconcile, rather than blindly issuing a second create.
      const inventory = await sourceInventory();
      const displayName = `arch-online-golden-${suffix}`;
      if (
        active(inventory.volumeGroupBackups).some((item) =>
          item["display-name"] === displayName
        )
      ) {
        throw new Error(
          "Matching group backup already exists; reconcile intent",
        );
      }
      const response = dataObject(
        await call([
          "bv",
          "volume-group-backup",
          "create",
          "--volume-group-id",
          policy.volumeGroupId,
          "--type",
          "FULL",
          "--display-name",
          displayName,
        ]),
      );
      return stringField(response, "id");
    },
    waitBackupGroup: (id) =>
      wait(() => groupBackupGet(id), "AVAILABLE", [
        "REQUEST_RECEIVED",
        "CREATING",
        "PROVISIONING",
      ], 3600),
    deleteBackupGroup: async (id, members) => {
      authorize();
      await evidence.assertNoOtherController();
      const source = await instance();
      if (source.value["lifecycle-state"] !== "RUNNING") {
        throw new Error("Source must remain RUNNING during retention");
      }
      const group = await groupBackupGet(id);
      if (
        group.id !== id ||
        group["volume-group-id"] !== policy.volumeGroupId ||
        group["compartment-id"] !== policy.source.compartmentId ||
        !sameMembers(group["volume-backup-ids"], members) ||
        stringField(group, "type") !== "FULL" ||
        !["AVAILABLE", "TERMINATING"].includes(
          stringField(group, "lifecycle-state"),
        )
      ) {
        throw new Error(
          "Recorded group backup identity changed before deletion",
        );
      }
      const inventory = await readBackupInventory(inventoryConfig(), runner);
      const boot = inventory.bootBackups.find((item) =>
        item.id === members.bootId
      );
      const root = inventory.rootBackups.find((item) =>
        item.id === members.rootId
      );
      if (!boot || !root) {
        throw new Error("Recorded group backup member is missing");
      }
      member(boot, "boot", policy);
      member(root, "root", policy);
      if (
        boot["volume-group-backup-id"] !== id ||
        root["volume-group-backup-id"] !== id
      ) throw new Error("Recorded member is not bound to the group backup");
      if (stringField(group, "lifecycle-state") !== "TERMINATING") {
        await call([
          "bv",
          "volume-group-backup",
          "delete",
          "--volume-group-backup-id",
          id,
          "--force",
        ]);
      }
      await wait(() => groupBackupGet(id), "TERMINATED", ["TERMINATING"], 1200);
      // Group deletion cascades members. Require a successful complete
      // inventory and prove both recorded member IDs disappeared.
      const after = await readBackupInventory(inventoryConfig(), runner);
      if (
        after.bootBackups.some((item) => item.id === members.bootId) ||
        after.rootBackups.some((item) => item.id === members.rootId) ||
        after.volumeGroupBackups.some((item) => item.id === id)
      ) throw new Error("Group deletion did not remove its exact members");
    },
    deleteBackup: async (kind, id) => {
      authorize();
      await evidence.assertNoOtherController();
      const source = await instance();
      if (source.value["lifecycle-state"] !== "RUNNING") {
        throw new Error("Source must remain RUNNING during retention");
      }
      if (
        policy.acceptedPair.volumeGroupBackupId ||
        id !==
          (kind === "boot"
            ? policy.acceptedPair.bootId
            : policy.acceptedPair.rootId)
      ) {
        throw new Error(
          "Retention refuses a backup outside the exact standalone pair",
        );
      }
      const inventory = await readBackupInventory(inventoryConfig(), runner);
      const item =
        (kind === "boot" ? inventory.bootBackups : inventory.rootBackups)
          .find((backup) => backup.id === id);
      if (!item) return;
      member(item, kind, policy);
      if (
        item["volume-group-backup-id"] !== null &&
        item["volume-group-backup-id"] !== undefined
      ) {
        throw new Error("Grouped members must be deleted through their group");
      }
      if (stringField(item, "lifecycle-state") !== "TERMINATING") {
        await call([
          "bv",
          kind === "boot" ? "boot-volume-backup" : "backup",
          "delete",
          kind === "boot" ? "--boot-volume-backup-id" : "--volume-backup-id",
          id,
          "--force",
        ]);
      }
      await wait(
        () => backupGet(kind, id),
        "TERMINATED",
        ["TERMINATING"],
        1200,
      );
      const after = await readBackupInventory(inventoryConfig(), runner);
      const items = kind === "boot" ? after.bootBackups : after.rootBackups;
      if (items.some((backup) => backup.id === id)) {
        throw new Error(
          "Standalone backup deletion was not observed in inventory",
        );
      }
    },
  };
}
