import { withBackupLock } from "./backup-lock.ts";
import { backupControllerEvidence } from "./backup-controller-evidence.ts";
import {
  backupGuestControl,
  type GuestJournal,
  type GuestPolicy,
} from "./backup-guest.ts";
import {
  type BackupInventoryConfig,
  backupSnapshot,
  readBackupInventory,
} from "./oci-backup-inventory.ts";
import { ociBackupOperations } from "./oci-backup-operations.ts";
import { readPrivateJson, redactOcid, writePrivateJson } from "./oci.ts";
import {
  type BackupJournal,
  type BackupPolicy,
  type BackupRunControl,
  newBackupJournal,
  runBackupCycle,
  validateStandingApproval,
} from "./weekly-backup.ts";

interface RuntimeConfig extends BackupInventoryConfig {
  action: "preflight" | "cycle";
  policy: BackupPolicy;
  guest: GuestPolicy;
}
interface RuntimeState {
  policy: BackupPolicy;
  cycle: BackupJournal;
  guest?: GuestJournal;
}
const CONFIG = ".private/backup-controller.json";
const STATE = ".private/backup-runtime.json";

async function loadState(): Promise<RuntimeState | undefined> {
  try {
    return await readPrivateJson<RuntimeState>(STATE);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return undefined;
    throw error;
  }
}

/** One persistent transaction contains the backup phase and guest stop intent.
 * The run lock covers config/state reads, all mutations, and final acceptance.
 * This entry point never installs a timer or provisions a restore clone.
 */
export async function main(
  beforeCycle?: (
    state: RuntimeState | undefined,
  ) => Promise<BackupRunControl | void>,
): Promise<void> {
  await withBackupLock(".private/backup-controller.lock", async () => {
    const config = await readPrivateJson<RuntimeConfig>(CONFIG);
    if (!["preflight", "cycle"].includes(config.action)) {
      throw new Error("Runtime action must be preflight or cycle");
    }
    validateStandingApproval(config.policy, new Date());
    if (
      JSON.stringify(config.source) !== JSON.stringify(config.policy.source)
    ) throw new Error("Runtime OCI source differs from standing approval");
    let state = await loadState();
    if (
      state && (
        JSON.stringify(state.policy.source) !==
          JSON.stringify(config.policy.source) ||
        JSON.stringify(state.policy.standingApproval) !==
          JSON.stringify(config.policy.standingApproval)
      )
    ) {
      throw new Error(
        "Runtime state belongs to another source or standing approval",
      );
    }
    let control: BackupRunControl | void = undefined;
    if (beforeCycle) {
      if (config.action !== "cycle") {
        throw new Error("Scheduled execution requires cycle mode");
      }
      control = await beforeCycle(state);
    }
    const evidence = backupControllerEvidence(config);
    const guest = backupGuestControl(
      config.guest,
      () => state?.guest,
      async (journal) => {
        if (!state || config.action !== "cycle") {
          throw new Error("Guest mutation has no backup transaction");
        }
        state.guest = journal;
        await writePrivateJson(STATE, state);
      },
    );
    if (config.action === "preflight") {
      await evidence.assertNoOtherController();
      await guest.assertNoActiveWork();
      const proof = await evidence.verify();
      const inventory = await readBackupInventory(config);
      const snapshot = backupSnapshot(inventory, {
        accountAndLimitsProved: proof.accountAndLimitsProved &&
          proof.objectStorageComplete && proof.objectStorageWithinLimit,
        backupLimit: proof.backupLimit,
        writersAbsent: true,
      });
      if (
        !snapshot.sourceAttachmentsProved || !snapshot.freeEligibilityProved
      ) throw new Error("Read-only source or eligibility preflight failed");
      // No restoration can occur in read-only mode, even if an interrupted
      // transaction has guest stop intents. Operator recovery uses cycle mode.
      if (state?.guest && !state.guest.restored) {
        throw new Error("Interrupted guest transaction requires recovery");
      }
      const readOnlyGuest = backupGuestControl(
        config.guest,
        () => undefined,
        () => Promise.reject(new Error("Read-only preflight")),
      );
      await readOnlyGuest.acceptSource();
      const report = {
        status: "PREFLIGHT_PASSED",
        observedAtUtc: new Date().toISOString(),
        totals: inventory.totals,
        proof,
        twoBackupSlotsApproved: inventory.totals.backups + 2 <=
          Math.min(proof.backupLimit, config.policy.allowFifthSlot ? 5 : 4),
        mutationPerformed: false,
      };
      await writePrivateJson(".private/reports/backup-preflight.json", report);
      console.log(JSON.stringify(report));
      return;
    }
    if (!state) {
      state = {
        policy: structuredClone(config.policy),
        cycle: newBackupJournal(config.policy, new Date()),
      };
      await writePrivateJson(STATE, state);
    }
    let reportedPhase: string | undefined;
    const operations = () =>
      ociBackupOperations(
        config,
        state!.policy,
        guest,
        evidence,
        async (cycle) => {
          state!.cycle = cycle;
          await writePrivateJson(STATE, state);
          if (cycle.phase !== reportedPhase) {
            reportedPhase = cycle.phase;
            console.error(JSON.stringify({
              phase: cycle.phase,
              updatedAtUtc: cycle.updatedAtUtc,
            }));
          }
        },
      );
    if (state.cycle.phase === "complete") {
      await runBackupCycle(state.policy, state.cycle, operations());
      if (state.policy.retainPreviousPair) {
        throw new Error(
          "First restore drill and retained-pair reconciliation are required before another cycle",
        );
      }
      await writePrivateJson(
        `.private/cycles/${state.cycle.suffix}.json`,
        state,
      );
      const policy: BackupPolicy = {
        ...state.policy,
        acceptedPair: {
          suffix: state.cycle.suffix,
          bootId: state.cycle.bootId!,
          rootId: state.cycle.rootId!,
        },
        allowFifthSlot: config.policy.allowFifthSlot,
      };
      state = { policy, cycle: newBackupJournal(policy, new Date()) };
      await writePrivateJson(STATE, state);
    }
    const cycle = state.cycle;
    try {
      await runBackupCycle(state.policy, cycle, operations(), control ?? {});
    } finally {
      // The engine also mutates the in-memory object before calling save.
      // Preserve its final recovery result in the same authoritative record.
      state.cycle = cycle;
      await writePrivateJson(STATE, state);
    }
    console.log(
      JSON.stringify({
        status: "BACKUP_CYCLE_ACCEPTED",
        suffix: cycle.suffix,
        previousPairRetained: state.policy.retainPreviousPair,
        sourceAcceptedAtUtc: cycle.sourceAcceptedAtUtc,
      }),
    );
  });
}
if (import.meta.main) {
  try {
    await main();
  } catch (error) {
    console.error(
      redactOcid(error instanceof Error ? error.message : String(error)),
    );
    Deno.exitCode = 1;
  }
}
