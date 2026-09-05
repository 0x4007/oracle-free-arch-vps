import { validateBackupPair } from "./oci-restore.ts";
import { type JsonRecord, stringField } from "./oci.ts";

export interface BackupSource {
  instanceId: string;
  bootVolumeId: string;
  rootVolumeId: string;
  compartmentId: string;
  region: string;
}

export interface BackupPair {
  suffix: string;
  bootId: string;
  rootId: string;
}

export interface BackupPolicy {
  source: BackupSource;
  standingApproval: {
    approvedAtUtc: string;
    exactOperation: "weekly paired backup rotation";
    source: BackupSource;
  };
  acceptedPair: BackupPair;
  // The initial pair stays until the separately recorded restore drill passes.
  retainPreviousPair: boolean;
  allowFifthSlot: boolean;
}

export type BackupPhase =
  | "planned"
  | "quiescing"
  | "quiesced"
  | "stop-requested"
  | "stopped"
  | "backing-up"
  | "pair-available"
  | "start-requested"
  | "source-accepted"
  | "retiring"
  | "complete"
  | "failed";

export interface BackupJournal {
  source: BackupSource;
  previousPair: BackupPair;
  suffix: string;
  phase: BackupPhase;
  createdAtUtc: string;
  updatedAtUtc: string;
  stoppedEpoch?: string;
  bootIntent?: boolean;
  rootIntent?: boolean;
  bootId?: string;
  rootId?: string;
  outageStartedAtUtc?: string;
  sourceAcceptedAtUtc?: string;
  recoveryStatus?: "needed" | "running-accepted" | "failed";
  failure?: string;
}

export interface BackupSnapshot {
  source: BackupSource;
  instanceState: string;
  // OCI instance ETag while STOPPED; changes on another start/stop.
  stoppedEpoch?: string;
  bootBackups: JsonRecord[];
  rootBackups: JsonRecord[];
  allBackupCount: number;
  freeBackupLimit: number;
  sourceAttachmentsProved: boolean;
  freeEligibilityProved: boolean;
  writersAbsent: boolean;
}

/** Runtime operations must reconcile exact targets and reject active writers.
 * Journal writes complete before the next external mutation starts.
 * The caller holds an OS lock across load, run, and every save.
 */
export interface BackupOperations {
  now(): Date;
  snapshot(): Promise<BackupSnapshot>;
  recoverySnapshot(): Promise<
    Pick<
      BackupSnapshot,
      | "source"
      | "instanceState"
      | "stoppedEpoch"
      | "sourceAttachmentsProved"
      | "writersAbsent"
    >
  >;
  save(journal: BackupJournal): Promise<void>;
  quiesce(): Promise<void>;
  verifyQuiesced(): Promise<void>;
  softStop(): Promise<void>;
  waitStopped(): Promise<void>;
  createBackup(
    kind: "boot" | "root",
    suffix: string,
    stoppedEpoch: string,
  ): Promise<string>;
  waitBackup(kind: "boot" | "root", id: string): Promise<void>;
  start(stoppedEpoch: string): Promise<void>;
  acceptSource(): Promise<void>;
  deleteBackup(kind: "boot" | "root", id: string): Promise<void>;
}

function equalSource(a: BackupSource, b: BackupSource): boolean {
  return (Object.keys(a) as (keyof BackupSource)[]).length === 5 &&
    ([
      "instanceId",
      "bootVolumeId",
      "rootVolumeId",
      "compartmentId",
      "region",
    ] as const)
      .every((key) =>
        typeof a[key] === "string" && a[key] !== "" && a[key] === b[key]
      );
}

export function validateStandingApproval(
  policy: BackupPolicy,
  now: Date,
): void {
  const date = Date.parse(policy.standingApproval.approvedAtUtc);
  if (
    policy.standingApproval.exactOperation !==
      "weekly paired backup rotation" ||
    !Number.isFinite(date) || date > now.getTime() ||
    !equalSource(policy.source, policy.standingApproval.source)
  ) throw new Error("Standing backup approval does not bind the exact source");
  if (
    !/^\d{8}T\d{6}Z$/.test(policy.acceptedPair.suffix) ||
    !policy.acceptedPair.bootId || !policy.acceptedPair.rootId ||
    policy.acceptedPair.bootId === policy.acceptedPair.rootId
  ) {
    throw new Error("Accepted backup pair is not configured");
  }
}

function verifyPair(
  snapshot: BackupSnapshot,
  pair: BackupPair,
  source: BackupSource,
): void {
  const boot = snapshot.bootBackups.find((item) => item.id === pair.bootId);
  const root = snapshot.rootBackups.find((item) => item.id === pair.rootId);
  if (!boot || !root) {
    throw new Error("A required backup pair member is missing");
  }
  validateBackupPair(
    boot,
    root,
    pair.suffix,
    source.bootVolumeId,
    source.rootVolumeId,
    source.compartmentId,
  );
  for (const item of [boot, root]) {
    const created = Date.parse(stringField(item, "time-created"));
    if (!Number.isFinite(created)) {
      throw new Error("Backup timestamp is invalid");
    }
  }
}

export function newBackupJournal(
  policy: BackupPolicy,
  now: Date,
): BackupJournal {
  validateStandingApproval(policy, now);
  const suffix = now.toISOString().replace(/[-:]/g, "").replace(
    /\.\d{3}Z$/,
    "Z",
  );
  if (suffix === policy.acceptedPair.suffix) {
    throw new Error("Backup suffix collision");
  }
  return {
    source: structuredClone(policy.source),
    previousPair: structuredClone(policy.acceptedPair),
    suffix,
    phase: "planned",
    createdAtUtc: now.toISOString(),
    updatedAtUtc: now.toISOString(),
  };
}

function replacement(journal: BackupJournal): BackupPair {
  if (!journal.bootId || !journal.rootId) {
    throw new Error("Replacement pair is incomplete");
  }
  if (
    journal.bootId === journal.previousPair.bootId ||
    journal.rootId === journal.previousPair.rootId ||
    journal.bootId === journal.rootId
  ) {
    throw new Error("Replacement pair reuses a retained backup ID");
  }
  return {
    suffix: journal.suffix,
    bootId: journal.bootId,
    rootId: journal.rootId,
  };
}

/** Never replay a creation whose intent was saved without a returned ID.
 * Adopt only a single exactly matching object observed in OCI. An empty list
 * can be eventual consistency, so absence does not permit another create.
 */
export function reconcileBackupCreation(
  kind: "boot" | "root",
  journal: BackupJournal,
  snapshot: BackupSnapshot,
): string | undefined {
  const name = `arch-${
    kind === "boot" ? "stage" : "root"
  }-golden-${journal.suffix}`;
  const items = kind === "boot" ? snapshot.bootBackups : snapshot.rootBackups;
  const matches = items.filter((item) => item["display-name"] === name);
  const id = kind === "boot" ? journal.bootId : journal.rootId;
  const intent = kind === "boot" ? journal.bootIntent : journal.rootIntent;
  if (matches.length > 1) {
    throw new Error("Duplicate backup names require reconciliation");
  }
  const match = matches[0];
  if (match) {
    const sourceKey = kind === "boot" ? "boot-volume-id" : "volume-id";
    const sourceId = kind === "boot"
      ? journal.source.bootVolumeId
      : journal.source.rootVolumeId;
    const created = Date.parse(stringField(match, "time-created"));
    if (
      !intent || (id && match.id !== id) || match[sourceKey] !== sourceId ||
      match["compartment-id"] !== journal.source.compartmentId ||
      match.type !== "FULL" ||
      match["size-in-gbs"] !== (kind === "boot" ? 50 : 150) ||
      !Number.isFinite(created) ||
      created < Date.parse(journal.createdAtUtc) - 1000 ||
      ["FAULTY", "TERMINATING", "TERMINATED"].includes(
        String(match["lifecycle-state"]),
      )
    ) {
      throw new Error(
        "Backup creation result does not match the recorded intent",
      );
    }
    return stringField(match, "id");
  }
  if (intent || id) {
    throw new Error("Ambiguous backup creation; do not retry creation");
  }
  return undefined;
}

export interface BackupRunControl {
  recoveryOnly?: boolean;
  beforeQuiesce?: () => Promise<void>;
}

export function needsSourceRecovery(journal: BackupJournal): boolean {
  return [
    "quiescing",
    "quiesced",
    "stop-requested",
    "stopped",
    "backing-up",
    "pair-available",
    "start-requested",
  ].includes(journal.phase) ||
    (journal.phase === "failed" &&
      ["needed", "failed"].includes(journal.recoveryStatus ?? ""));
}

export async function runBackupCycle(
  policy: BackupPolicy,
  journal: BackupJournal,
  ops: BackupOperations,
  control: BackupRunControl = {},
): Promise<void> {
  validateStandingApproval(policy, ops.now());
  if (
    ![
      "planned",
      "quiescing",
      "quiesced",
      "stop-requested",
      "stopped",
      "backing-up",
      "pair-available",
      "start-requested",
      "source-accepted",
      "retiring",
      "complete",
      "failed",
    ].includes(journal.phase)
  ) {
    throw new Error("Backup journal has an unknown phase");
  }
  if (
    !equalSource(journal.source, policy.source) ||
    JSON.stringify(journal.previousPair) !==
      JSON.stringify(policy.acceptedPair) ||
    !/^\d{8}T\d{6}Z$/.test(journal.suffix) ||
    journal.suffix === journal.previousPair.suffix
  ) {
    throw new Error("Backup journal belongs to another source or rotation");
  }
  if (journal.phase === "failed" && !control.recoveryOnly) {
    throw new Error("Failed cycle requires operator reconciliation");
  }
  if (control.recoveryOnly && !needsSourceRecovery(journal)) {
    throw new Error("No interrupted source outage requires recovery");
  }
  const save = async (phase: BackupPhase = journal.phase) => {
    journal.phase = phase;
    journal.updatedAtUtc = ops.now().toISOString();
    await ops.save(structuredClone(journal));
  };
  const snapshot = async (retiring = false) => {
    const current = await ops.snapshot();
    if (
      !equalSource(current.source, policy.source) ||
      !current.sourceAttachmentsProved ||
      !current.freeEligibilityProved || !current.writersAbsent
    ) {
      throw new Error(
        "Source, eligibility, attachment or active-writer preflight failed",
      );
    }
    if (!retiring) verifyPair(current, journal.previousPair, policy.source);
    return current;
  };
  const stopped = async () => {
    const current = await snapshot();
    if (
      current.instanceState !== "STOPPED" || !journal.stoppedEpoch ||
      current.stoppedEpoch !== journal.stoppedEpoch
    ) {
      throw new Error("Source is not in this cycle's verified stopped epoch");
    }
    return current;
  };
  // A failed read-only recheck must not rewrite an accepted cycle as failed.
  if (journal.phase === "complete") {
    verifyPair(await snapshot(true), replacement(journal), policy.source);
    return;
  }
  try {
    if (control.recoveryOnly) {
      // Use the failure recovery path without inventory, creation or retention.
      throw new Error("Interrupted cycle requires recovery only");
    }
    if (journal.phase === "planned") {
      const current = await snapshot();
      const ceiling = Math.min(
        current.freeBackupLimit,
        policy.allowFifthSlot ? 5 : 4,
      );
      if (
        current.instanceState !== "RUNNING" ||
        current.allBackupCount + 2 > ceiling
      ) {
        throw new Error(
          "Source is not running or two approved backup slots are unavailable",
        );
      }
      await control.beforeQuiesce?.();
      await save("quiescing");
      await ops.quiesce();
      await ops.verifyQuiesced();
      await save("quiesced");
    }
    // A crash during quiescence cannot prove which guest operations completed.
    if (journal.phase === "quiescing") {
      throw new Error("Interrupted quiescence requires recovery");
    }
    if (journal.phase === "quiesced") {
      // A stop allocates no resources. Recheck the exact source and attachments
      // here without another slow tenancy-wide inventory while apps are down.
      // Full allowance and backup-pair reconciliation still precedes quiescence
      // and every backup creation; the guest is checked again immediately below.
      const current = await ops.recoverySnapshot();
      if (
        !equalSource(current.source, policy.source) ||
        !current.sourceAttachmentsProved || !current.writersAbsent ||
        current.instanceState !== "RUNNING"
      ) {
        throw new Error("Source changed before stop");
      }
      await ops.verifyQuiesced();
      journal.outageStartedAtUtc = ops.now().toISOString();
      await save("stop-requested");
      await ops.softStop();
    }
    if (journal.phase === "stop-requested") {
      await ops.waitStopped();
      const current = await snapshot();
      if (current.instanceState !== "STOPPED" || !current.stoppedEpoch) {
        throw new Error("SOFTSTOP did not produce a verifiable stopped epoch");
      }
      journal.stoppedEpoch = current.stoppedEpoch;
      await save("stopped");
    }
    if (journal.phase === "stopped" || journal.phase === "backing-up") {
      await save("backing-up");
      for (const kind of ["boot", "root"] as const) {
        const current = await stopped();
        const found = reconcileBackupCreation(kind, journal, current);
        if (found) {
          if (kind === "boot") journal.bootId = found;
          else journal.rootId = found;
          await save();
        } else {
          const ceiling = Math.min(
            current.freeBackupLimit,
            policy.allowFifthSlot ? 5 : 4,
          );
          if (current.allBackupCount + 1 > ceiling) {
            throw new Error("Backup allowance changed");
          }
          if (kind === "boot") journal.bootIntent = true;
          else journal.rootIntent = true;
          await save();
          const id = await ops.createBackup(
            kind,
            journal.suffix,
            journal.stoppedEpoch!,
          );
          if (kind === "boot") journal.bootId = id;
          else journal.rootId = id;
          await save();
        }
      }
      const pair = replacement(journal);
      await ops.waitBackup("boot", pair.bootId);
      await ops.waitBackup("root", pair.rootId);
      verifyPair(await stopped(), pair, policy.source);
      await save("pair-available");
    }
    if (journal.phase === "pair-available") {
      await stopped();
      await save("start-requested");
      await ops.start(journal.stoppedEpoch!);
    }
    if (journal.phase === "start-requested") {
      const current = await snapshot();
      if (current.instanceState === "STOPPED") {
        if (
          !journal.stoppedEpoch || current.stoppedEpoch !== journal.stoppedEpoch
        ) {
          throw new Error("Resumed restart belongs to another stopped epoch");
        }
        await ops.start(journal.stoppedEpoch!);
      }
      await ops.acceptSource();
      verifyPair(await snapshot(), replacement(journal), policy.source);
      journal.sourceAcceptedAtUtc = ops.now().toISOString();
      await save("source-accepted");
    }
    if (journal.phase === "source-accepted") {
      if (policy.retainPreviousPair) {
        await save("complete");
        return;
      }
      await save("retiring");
    }
    if (journal.phase === "retiring") {
      if (policy.retainPreviousPair) {
        throw new Error("Retention policy prohibits deletion");
      }
      if (!journal.sourceAcceptedAtUtc) {
        throw new Error("Source acceptance is absent");
      }
      for (const kind of ["boot", "root"] as const) {
        const current = await snapshot(true);
        verifyPair(current, replacement(journal), policy.source);
        if (current.instanceState !== "RUNNING") {
          throw new Error("Source is not running during retention");
        }
        const id = kind === "boot"
          ? journal.previousPair.bootId
          : journal.previousPair.rootId;
        const items = kind === "boot"
          ? current.bootBackups
          : current.rootBackups;
        const item = items.find((backup) => backup.id === id);
        if (item && item["lifecycle-state"] !== "TERMINATED") {
          // Target membership was validated as a complete pair before retirement.
          await ops.deleteBackup(kind, id);
        }
      }
      const current = await snapshot(true);
      verifyPair(current, replacement(journal), policy.source);
      const remaining = [...current.bootBackups, ...current.rootBackups].some((
        item,
      ) =>
        [journal.previousPair.bootId, journal.previousPair.rootId].includes(
          String(item.id),
        ) &&
        item["lifecycle-state"] !== "TERMINATED"
      );
      if (remaining) {
        throw new Error("Old backup deletion has not reached terminal state");
      }
      await save("complete");
    }
  } catch (error) {
    const failedPhase = journal.phase;
    journal.failure = error instanceof Error ? error.message : String(error);
    const recoveryNeeded = ![
      "planned",
      "complete",
      "source-accepted",
      "retiring",
    ].includes(failedPhase);
    // Persist this with the failed phase so a crash before/during recovery
    // still leaves an actionable journal for the independent recovery timer.
    if (recoveryNeeded) journal.recoveryStatus = "needed";
    let journalWriteFailed = false;
    try {
      await save("failed");
    } catch {
      // A full controller disk must not suppress source recovery.
      journalWriteFailed = true;
    }
    if (recoveryNeeded) {
      try {
        // Recovery still checks source identity and writers; never force START
        // through STOPPING or another ambiguous lifecycle transition.
        const current = await ops.recoverySnapshot();
        if (
          !equalSource(current.source, policy.source) ||
          !current.sourceAttachmentsProved || !current.writersAbsent
        ) {
          throw new Error("Source identity or writer recovery check failed");
        }
        if (current.instanceState === "STOPPED") {
          if (
            journal.stoppedEpoch &&
            current.stoppedEpoch !== journal.stoppedEpoch
          ) {
            throw new Error(
              "Another stop epoch requires operator reconciliation",
            );
          }
          if (!current.stoppedEpoch) {
            throw new Error("Recovery stop epoch is absent");
          }
          await ops.start(current.stoppedEpoch);
        } else if (
          current.instanceState !== "RUNNING" &&
          current.instanceState !== "STARTING"
        ) {
          throw new Error(
            "Source recovery awaits an unambiguous lifecycle state",
          );
        }
        await ops.acceptSource();
        journal.recoveryStatus = "running-accepted";
      } catch {
        journal.recoveryStatus = "failed";
      }
      try {
        await save();
      } catch {
        journalWriteFailed = true;
      }
    }
    if (journalWriteFailed) {
      throw new AggregateError(
        [error],
        "Backup failed and its journal could not be persisted; inspect source recovery",
      );
    }
    throw error;
  }
}
