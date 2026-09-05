import {
  type CommandRunner,
  dataArray,
  dataObject,
  defaultRunner,
  type JsonRecord,
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
  type BackupPolicy,
  validateStandingApproval,
} from "./weekly-backup.ts";

export interface BackupGuestControl {
  assertNoActiveWork(): Promise<void>;
  quiesce(): Promise<void>;
  verifyQuiesced(): Promise<void>;
  acceptSource(): Promise<void>;
}

export interface BackupControllerEvidence {
  verify(): Promise<{
    accountAndLimitsProved: boolean;
    backupLimit: number;
    objectStorageComplete: boolean;
    objectStorageWithinLimit: boolean;
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

/** Creates real OCI operations, but performs nothing until called by the
 * journaled state machine under the controller lock. No CLI waiter is attached
 * to creation: the returned ID must be saved before polling begins.
 */
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
  const guard = async (expected: string, checkGuest: boolean) => {
    authorize();
    await evidence.assertNoOtherController();
    if (checkGuest) await guest.assertNoActiveWork();
    const current = await instance();
    if (current.value["lifecycle-state"] !== expected) {
      throw new Error(`Source must be ${expected} before mutation`);
    }
    return current;
  };
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
        // The read above is the mandatory final state observation, including
        // on SOFTSTOP timeout. There is no hard-stop or reset fallback.
        throw new Error(`OCI ${desired} wait timed out; last state ${state}`);
      }
      await time.sleep(5_000);
    }
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
  return {
    now: time.now,
    save,
    snapshot: async () => {
      const proof = await evidence.verify();
      if (
        !Number.isInteger(proof.backupLimit) || proof.backupLimit < 2 ||
        proof.backupLimit > 5
      ) {
        throw new Error("Current free backup allowance is not proved");
      }
      await evidence.assertNoOtherController();
      const inventory = await readBackupInventory(config, runner);
      if (inventory.instance["lifecycle-state"] === "RUNNING") {
        await guest.assertNoActiveWork();
      }
      return backupSnapshot(inventory, {
        accountAndLimitsProved: proof.accountAndLimitsProved &&
          proof.objectStorageComplete && proof.objectStorageWithinLimit,
        backupLimit: proof.backupLimit,
        writersAbsent: true,
      });
    },
    recoverySnapshot: async () => {
      authorize();
      await evidence.assertNoOtherController();
      const current = await instance();
      const bootAttachments = dataArray(
        await call([
          "compute",
          "boot-volume-attachment",
          "list",
          "--compartment-id",
          policy.source.compartmentId,
          "--instance-id",
          policy.source.instanceId,
          "--availability-domain",
          stringField(current.value, "availability-domain"),
          "--all",
        ]),
      ).filter((item) => item["lifecycle-state"] !== "DETACHED");
      const rootAttachments = dataArray(
        await call([
          "compute",
          "volume-attachment",
          "list",
          "--compartment-id",
          policy.source.compartmentId,
          "--instance-id",
          policy.source.instanceId,
          "--all",
        ]),
      ).filter((item) => item["lifecycle-state"] !== "DETACHED");
      const bound = bootAttachments.length === 1 &&
        rootAttachments.length === 1 &&
        bootAttachments[0]["boot-volume-id"] === policy.source.bootVolumeId &&
        rootAttachments[0]["volume-id"] === policy.source.rootVolumeId &&
        rootAttachments[0]["attachment-type"] === "paravirtualized" &&
        [...bootAttachments, ...rootAttachments].every((item) =>
          item["instance-id"] === policy.source.instanceId &&
          item["lifecycle-state"] === "ATTACHED"
        );
      if (!bound) throw new Error("Recovery source attachments changed");
      // New guest work must prevent shutdown, but must not prevent restoring
      // applications that this transaction already stopped. Recovery preserves
      // that work; source identity, attachments and controller ownership still
      // have to match, and START retains its separate stopped-ETag guard.
      return {
        source: policy.source,
        instanceState: stringField(current.value, "lifecycle-state"),
        stoppedEpoch: current.value["lifecycle-state"] === "STOPPED"
          ? current.etag
          : undefined,
        sourceAttachmentsProved: bound,
        writersAbsent: true,
      };
    },
    quiesce: async () => {
      await guard("RUNNING", true);
      await guest.quiesce();
    },
    verifyQuiesced: () => guest.verifyQuiesced(),
    softStop: async () => {
      const before = await guard("RUNNING", true);
      await guest.verifyQuiesced();
      try {
        await call([
          "compute",
          "instance",
          "action",
          "--instance-id",
          policy.source.instanceId,
          "--action",
          "SOFTSTOP",
          "--if-match",
          before.etag,
        ]);
      } catch (error) {
        // Observe the same source after an ambiguous command result. Even if
        // STOPPED, fail this backup cycle and let its recovery path restart it.
        try {
          await instance();
        } catch { /* original failure remains authoritative */ }
        throw error;
      }
    },
    waitStopped: () =>
      wait(async () => (await instance()).value, "STOPPED", [
        "RUNNING",
        "STOPPING",
      ], 1200),
    createBackup: async (kind, suffix, stoppedEpoch) => {
      const before = await guard("STOPPED", false);
      if (!stoppedEpoch || before.etag !== stoppedEpoch) {
        throw new Error("Source stopped epoch changed before backup creation");
      }
      if (!/^\d{8}T\d{6}Z$/.test(suffix)) {
        throw new Error("Invalid backup suffix");
      }
      const response = dataObject(
        await call([
          "bv",
          kind === "boot" ? "boot-volume-backup" : "backup",
          "create",
          kind === "boot" ? "--boot-volume-id" : "--volume-id",
          kind === "boot"
            ? policy.source.bootVolumeId
            : policy.source.rootVolumeId,
          "--type",
          "FULL",
          "--display-name",
          `arch-${kind === "boot" ? "stage" : "root"}-golden-${suffix}`,
        ]),
      );
      return stringField(response, "id");
    },
    waitBackup: (kind, id) =>
      wait(() => backupGet(kind, id), "AVAILABLE", [
        "REQUEST_RECEIVED",
        "CREATING",
      ], 3600),
    start: async (stoppedEpoch) => {
      const before = await guard("STOPPED", false);
      if (!stoppedEpoch || before.etag !== stoppedEpoch) {
        throw new Error("Source stopped epoch changed before START");
      }
      await call([
        "compute",
        "instance",
        "action",
        "--instance-id",
        policy.source.instanceId,
        "--action",
        "START",
        "--if-match",
        before.etag,
      ]);
    },
    acceptSource: async () => {
      await wait(
        async () => (await instance()).value,
        "RUNNING",
        ["STARTING"],
        1200,
      );
      await guest.acceptSource();
    },
    deleteBackup: async (kind, id) => {
      await guard("RUNNING", true);
      if (
        policy.retainPreviousPair ||
        id !==
          (kind === "boot"
            ? policy.acceptedPair.bootId
            : policy.acceptedPair.rootId)
      ) {
        throw new Error(
          "Retention refuses a backup outside the exact previous pair",
        );
      }
      const backup = await backupGet(kind, id);
      const sourceKey = kind === "boot" ? "boot-volume-id" : "volume-id";
      const sourceId = kind === "boot"
        ? policy.source.bootVolumeId
        : policy.source.rootVolumeId;
      if (
        backup[sourceKey] !== sourceId ||
        backup["compartment-id"] !== policy.source.compartmentId ||
        backup["display-name"] !==
          `arch-${
            kind === "boot" ? "stage" : "root"
          }-golden-${policy.acceptedPair.suffix}`
      ) {
        throw new Error("Previous backup identity changed before deletion");
      }
      if (backup["lifecycle-state"] === "TERMINATED") return;
      if (backup["lifecycle-state"] !== "TERMINATING") {
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
        async () => {
          // Deleted objects can return an ambiguous NotAuthorizedOrNotFound
          // from GET. Require a successful complete inventory after deletion
          // instead of interpreting that error as proof of removal.
          const remaining = dataArray(
            await call([
              "bv",
              kind === "boot" ? "boot-volume-backup" : "backup",
              "list",
              "--compartment-id",
              policy.source.compartmentId,
              "--all",
            ]),
          ).find((item) => item.id === id);
          return remaining ?? { "lifecycle-state": "TERMINATED" };
        },
        "TERMINATED",
        ["TERMINATING"],
        1200,
      );
    },
  };
}
