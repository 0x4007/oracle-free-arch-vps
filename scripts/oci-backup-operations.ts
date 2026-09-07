import type { SourceContinuityEvidence } from "./online-backup-contract.ts";
import {
  type CommandRunner,
  dataObject,
  defaultRunner,
  type JsonRecord,
  numberField,
  OciCommandError,
  runJson,
  stringField,
} from "./oci.ts";
import { RetryableObservationError } from "./online-backup-contract.ts";
import {
  type BackupInventoryConfig,
  backupSnapshot,
  type FreeResourceSurfaceEvidence,
  readBackupInventory,
} from "./oci-backup-inventory.ts";
import {
  type BackupJournal,
  type BackupOperations,
  type BackupPair,
  type BackupPolicy,
  OnlineBackupBlockedError,
  OnlineBackupRetryableError,
  type ResumableBackupPhase,
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
    freeResourceSurface?: FreeResourceSurfaceEvidence;
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
  allowTerminating = false,
): void {
  if (
    !["AVAILABLE", ...(allowTerminating ? ["TERMINATING"] : [])].includes(
      stringField(item, "lifecycle-state"),
    )
  ) {
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
  const transportRunner: CommandRunner = async (command, args) => {
    try {
      return await runner(command, args);
    } catch {
      throw new RetryableObservationError("OCI command transport failed");
    }
  };
  const call = async (
    args: string[],
    resumePhase: ResumableBackupPhase,
    kind: "external-read" | "recorded-operation" = "external-read",
  ) => {
    try {
      return await runJson(config.ociCliPath, [
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
      ], transportRunner);
    } catch (error) {
      if (
        error instanceof RetryableObservationError ||
        error instanceof OciCommandError
      ) {
        throw new OnlineBackupRetryableError(
          "OCI command transport failed",
          resumePhase,
          kind,
        );
      }
      throw error;
    }
  };
  const instance = async (resumePhase: ResumableBackupPhase) => {
    const response = await call([
      "compute",
      "instance",
      "get",
      "--instance-id",
      policy.source.instanceId,
    ], resumePhase);
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
  const sourceInventory = async (resumePhase: ResumableBackupPhase) => {
    authorize();
    await evidence.assertNoOtherController();
    let current;
    try {
      current = await readBackupInventory(inventoryConfig(), transportRunner);
    } catch (error) {
      if (
        error instanceof RetryableObservationError ||
        error instanceof OciCommandError
      ) {
        throw new OnlineBackupRetryableError(
          "OCI inventory transport failed",
          resumePhase,
          "external-read",
        );
      }
      throw error;
    }
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
  const groupBackupGet = async (
    id: string,
    resumePhase: ResumableBackupPhase,
  ) =>
    dataObject(
      await call([
        "bv",
        "volume-group-backup",
        "get",
        "--volume-group-backup-id",
        id,
      ], resumePhase),
    );
  const wait = async (
    read: () => Promise<JsonRecord>,
    desired: string,
    pending: string[],
    seconds: number,
    resumePhase: ResumableBackupPhase,
    kind: "external-read" | "recorded-operation" = "external-read",
  ) => {
    const deadline = time.now().getTime() + seconds * 1000;
    while (true) {
      let item: JsonRecord;
      try {
        item = await read();
      } catch (error) {
        if (error instanceof OnlineBackupRetryableError) throw error;
        throw error;
      }
      const state = stringField(item, "lifecycle-state");
      if (state === desired) return;
      if (!pending.includes(state)) {
        throw new Error(`Unexpected OCI lifecycle state: ${state}`);
      }
      if (time.now().getTime() >= deadline) {
        throw new OnlineBackupRetryableError(
          `OCI ${desired} wait timed out; last state ${state}`,
          resumePhase,
          kind,
        );
      }
      await time.sleep(5_000);
    }
  };
  const waitAbsent = async (
    ids: string[],
    resumePhase: ResumableBackupPhase,
  ) => {
    const deadline = time.now().getTime() + 1200_000;
    while (true) {
      // A successful tenancy-wide LIST proves disappearance. GET 404 alone
      // cannot distinguish deletion from lost permission.
      let current;
      try {
        current = await readBackupInventory(inventoryConfig(), transportRunner);
      } catch (error) {
        if (
          error instanceof RetryableObservationError ||
          error instanceof OciCommandError
        ) {
          throw new OnlineBackupRetryableError(
            "OCI inventory transport failed while waiting for deletion",
            resumePhase,
            "external-read",
          );
        }
        throw error;
      }
      if (
        ![
          ...current.bootBackups,
          ...current.rootBackups,
          ...current.volumeGroupBackups,
        ]
          .some((item) => ids.includes(String(item.id)))
      ) return;
      if (time.now().getTime() >= deadline) {
        throw new OnlineBackupRetryableError(
          "Backup deletion inventory wait timed out",
          resumePhase,
          "recorded-operation",
        );
      }
      await time.sleep(5000);
    }
  };
  return {
    now: time.now,
    save,
    snapshot: async () => {
      authorize();
      let proof;
      try {
        proof = await evidence.verify();
      } catch (error) {
        if (
          error instanceof RetryableObservationError ||
          error instanceof OciCommandError
        ) {
          throw new OnlineBackupRetryableError(
            "Controller evidence transport failed",
            undefined,
            "external-read",
          );
        }
        throw error;
      }
      if (
        !Number.isInteger(proof.backupLimit) ||
        proof.backupLimit < 2 || proof.backupLimit > 5
      ) throw new Error("Current free backup allowance is not proved");
      await evidence.assertNoOtherController();
      let inventory;
      try {
        inventory = await readBackupInventory(
          inventoryConfig(),
          transportRunner,
        );
      } catch (error) {
        if (
          error instanceof RetryableObservationError ||
          error instanceof OciCommandError
        ) {
          throw new OnlineBackupRetryableError(
            "OCI inventory transport failed",
            undefined,
            "external-read",
          );
        }
        throw error;
      }
      return backupSnapshot(inventory, {
        accountAndLimitsProved: proof.accountAndLimitsProved &&
          proof.objectStorageComplete && proof.objectStorageWithinLimit,
        backupLimit: proof.backupLimit,
        groupAccountingProved: proof.groupAccountingProved,
        writersAbsent: true,
      });
    },
    observeSource: async () => {
      try {
        return await guest.observeSource();
      } catch (error) {
        if (error instanceof RetryableObservationError) {
          throw new OnlineBackupRetryableError(
            "Guest observation transport failed",
            undefined,
            "external-read",
          );
        }
        throw error;
      }
    },
    acceptSource: async () => {
      try {
        await guest.acceptSource();
      } catch (error) {
        if (error instanceof RetryableObservationError) {
          throw new OnlineBackupRetryableError(
            "Guest acceptance transport failed",
            "pair-available",
            "external-read",
          );
        }
        throw error;
      }
    },
    createBackupGroup: async (suffix) => {
      authorize();
      if (!/^\d{8}T\d{6}Z$/.test(suffix)) {
        throw new Error("Invalid backup suffix");
      }
      // This is the final source/group/attachment check before mutation. It
      // also gives an ambiguous provider response a complete inventory to
      // reconcile, rather than blindly issuing a second create.
      const inventory = await sourceInventory("backing-up");
      if (inventory.totals.backups + 2 > (policy.allowFifthSlot ? 5 : 4)) {
        throw new OnlineBackupBlockedError(
          "Two free backup slots are unavailable at final creation check",
          "backing-up",
        );
      }
      const displayName = `arch-online-golden-${suffix}`;
      if (
        active(inventory.volumeGroupBackups).some((item) =>
          item["display-name"] === displayName
        )
      ) {
        throw new OnlineBackupBlockedError(
          "Matching group backup already exists; reconcile intent",
          "backing-up",
        );
      }
      const response = dataObject(
        await call(
          [
            "bv",
            "volume-group-backup",
            "create",
            "--volume-group-id",
            policy.volumeGroupId,
            "--type",
            "FULL",
            "--display-name",
            displayName,
          ],
          "backing-up",
          "recorded-operation",
        ),
      );
      return stringField(response, "id");
    },
    waitBackupGroup: (id) =>
      wait(
        () => groupBackupGet(id, "backing-up"),
        "AVAILABLE",
        [
          "REQUEST_RECEIVED",
          "CREATING",
          "COMMITTED",
          "PROVISIONING",
        ],
        3600,
        "backing-up",
        "recorded-operation",
      ),
    deleteBackupGroup: async (id, members) => {
      authorize();
      await evidence.assertNoOtherController();
      const source = await instance("retiring");
      if (source.value["lifecycle-state"] !== "RUNNING") {
        throw new Error("Source must remain RUNNING during retention");
      }
      if (
        id !== policy.acceptedPair.volumeGroupBackupId ||
        members.bootId !== policy.acceptedPair.bootId ||
        members.rootId !== policy.acceptedPair.rootId
      ) {
        throw new Error(
          "Retention refuses a group outside the exact accepted pair",
        );
      }
      const inventory = await sourceInventory("retiring");
      const group = inventory.volumeGroupBackups.find((item) => item.id === id);
      if (
        group && (
          group.id !== id ||
          group["volume-group-id"] !== policy.volumeGroupId ||
          group["compartment-id"] !== policy.source.compartmentId ||
          !sameMembers(group["volume-backup-ids"], members) ||
          stringField(group, "type") !== "FULL" ||
          !["AVAILABLE", "TERMINATING"].includes(
            stringField(group, "lifecycle-state"),
          )
        )
      ) {
        throw new Error(
          "Recorded group backup identity changed before deletion",
        );
      }
      const boot = inventory.bootBackups.find((item) =>
        item.id === members.bootId
      );
      const root = inventory.rootBackups.find((item) =>
        item.id === members.rootId
      );
      const deleting = !group || group["lifecycle-state"] === "TERMINATING";
      if ((!boot || !root) && !deleting) {
        throw new Error("Recorded group backup member is missing");
      }
      if (boot) member(boot, "boot", policy, deleting);
      if (root) member(root, "root", policy, deleting);
      if (
        (boot && boot["volume-group-backup-id"] !== id) ||
        (root && root["volume-group-backup-id"] !== id)
      ) throw new Error("Recorded member is not bound to the group backup");
      if (!deleting) {
        await call(
          [
            "bv",
            "volume-group-backup",
            "delete",
            "--volume-group-backup-id",
            id,
            "--force",
          ],
          "retiring",
          "recorded-operation",
        );
      }
      await waitAbsent([id, members.bootId, members.rootId], "retiring");
    },
    deleteBackup: async (kind, id) => {
      authorize();
      await evidence.assertNoOtherController();
      const source = await instance("retiring");
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
      const inventory = await sourceInventory("retiring");
      const item =
        (kind === "boot" ? inventory.bootBackups : inventory.rootBackups)
          .find((backup) => backup.id === id);
      if (!item) return;
      member(item, kind, policy, true);
      if (
        item["volume-group-backup-id"] !== null &&
        item["volume-group-backup-id"] !== undefined
      ) {
        throw new Error("Grouped members must be deleted through their group");
      }
      if (stringField(item, "lifecycle-state") !== "TERMINATING") {
        await call(
          [
            "bv",
            kind === "boot" ? "boot-volume-backup" : "backup",
            "delete",
            kind === "boot" ? "--boot-volume-backup-id" : "--volume-backup-id",
            id,
            "--force",
          ],
          "retiring",
          "recorded-operation",
        );
      }
      await waitAbsent([id], "retiring");
    },
  };
}
