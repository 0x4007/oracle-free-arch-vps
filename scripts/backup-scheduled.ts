import {
  main,
  type RuntimeConfig,
  type RuntimeState,
} from "./backup-runtime.ts";
import { assertBackblazeLaunchAllowed } from "./backblaze-controller-contract.ts";
import { backupControllerEvidence } from "./backup-controller-evidence.ts";
import {
  type BackupSchedule,
  currentWindow,
  duePeriod,
  periodAt,
  periodDate,
  validateSchedule,
} from "./backup-schedule.ts";
import {
  ONLINE_RETRY_POLICY,
  type OnlineBackupRetry,
} from "./online-backup-contract.ts";
import {
  type BackupInventory,
  readBackupInventory,
} from "./oci-backup-inventory.ts";
import { readPrivateJson, redactOcid, writePrivateJson } from "./oci.ts";
import {
  CLAIM_INCIDENT_AGE_MS,
  CLAIM_PATH,
  currentClaimOwner,
  CYCLE_SUFFIX,
  LEGACY_CLAIM_MIN_AGE_MS,
  ScheduledClaimCustodyError,
  type ScheduledClaimOwner,
  scheduledClaimOwnerState,
  validateClaimOwner,
} from "./scheduled-claim-custody.ts";

export type ScheduledClaimStatus =
  | "started"
  | "complete"
  | "failed"
  | "reconciliation-required";

/** Durable operator action recorded when a one-time acceptance claim expires
 * with no recorded OCI capture. Nothing here may allocate a capture identity.
 */
export interface ScheduledClaimReconciliation {
  requiredAtUtc: string;
  /** Exact expiry of the one-time acceptance window that produced the claim. */
  expiredAtUtc: string;
  /** False only when the runtime journal records no create intent or group ID. */
  captureStarted: false;
  /** Bounded read-only instruction; the exact procedure is in
   * 06-TROUBLESHOOTING.md and never names an OCI resource to create. */
  instruction: string;
}

/** The approved schedule authority a claim was planned under. */
export interface ApprovedSchedule {
  approvedAtUtc: string;
  timeZone: string;
  weekday: number; // Sunday = 0
  hour: number;
  minute: number;
  acceptanceWindow?: {
    approvedAtUtc: string;
    startsAtUtc: string;
    expiresAtUtc: string;
    exactOperation: "one online scheduler acceptance capture";
  };
}

export interface WindowClaim {
  /** Kept as windowId for compatibility with existing private claim readers. */
  windowId: string;
  /** Weekly due-period identity, independent of an acceptance-window trigger. */
  periodId?: string;
  previousCycleSuffix?: string;
  status: ScheduledClaimStatus;
  updatedAtUtc: string;
  /** Approved schedule authority the claim was planned under. */
  approvedSchedule?: ApprovedSchedule;
  /** Set only on a terminal reconciliation-required claim. */
  reconciliation?: ScheduledClaimReconciliation;
  /** Bound to one controller attempt. Older live claims omit this record. */
  owner?: ScheduledClaimOwner;
  failure?: {
    reason:
      | "CONTROLLER_EXITED"
      | "LEGACY_CONTROLLER_EXITED"
      | "PREPARATION_FAILED";
    observedAtUtc: string;
  };
}

export interface ScheduledCycleState {
  phase?: string;
  suffix?: string;
  createdAtUtc?: string;
  updatedAtUtc?: string;
  sourceAcceptedAtUtc?: string;
  captureIdentity?: { captureTimeUtc?: string };
  /** Durable group create intent and returned ID from the runtime journal. */
  volumeGroupBackupIntent?: boolean;
  volumeGroupBackupId?: string;
  retry?: OnlineBackupRetry;
}

export interface ScheduledRuntimeState {
  cycle?: ScheduledCycleState;
  lastSuccessfulCaptureAtUtc?: string;
}

export type ScheduledDecision =
  | {
    action: "skip";
    reason: string;
    completedClaim?: WindowClaim;
    /** Terminal claim to persist when an operator action is required. */
    reconciliationClaim?: WindowClaim;
  }
  | { action: "run"; claim: WindowClaim };

class Skipped extends Error {}

function isAcceptanceWindowId(value: string): boolean {
  return value.startsWith("acceptance@");
}

function parseTimestamp(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

const TIME_ZONE_PATTERN = /^[A-Za-z_]+(?:\/[A-Za-z_+-]+)*$/;

/** Canonical approved schedule binding stored on a claim. */
export function approvedScheduleOf(
  schedule: BackupSchedule,
): ApprovedSchedule {
  return {
    approvedAtUtc: schedule.approvedAtUtc,
    timeZone: schedule.timeZone,
    weekday: schedule.weekday,
    hour: schedule.hour,
    minute: schedule.minute,
    ...(schedule.acceptanceWindow
      ? { acceptanceWindow: structuredClone(schedule.acceptanceWindow) }
      : {}),
  };
}

function sameApprovedSchedule(
  a: ApprovedSchedule,
  b: ApprovedSchedule,
): boolean {
  if (
    a.approvedAtUtc !== b.approvedAtUtc ||
    a.timeZone !== b.timeZone ||
    a.weekday !== b.weekday ||
    a.hour !== b.hour ||
    a.minute !== b.minute
  ) return false;
  const aw = a.acceptanceWindow;
  const bw = b.acceptanceWindow;
  if ((aw === undefined) !== (bw === undefined)) return false;
  return aw === undefined || (
    aw.approvedAtUtc === bw!.approvedAtUtc &&
    aw.startsAtUtc === bw!.startsAtUtc &&
    aw.expiresAtUtc === bw!.expiresAtUtc &&
    aw.exactOperation === bw!.exactOperation
  );
}

function validateApprovedSchedule(value: ApprovedSchedule): void {
  if (
    !parseTimestamp(value.approvedAtUtc) ||
    !TIME_ZONE_PATTERN.test(value.timeZone) ||
    !Number.isInteger(value.weekday) || value.weekday < 0 ||
    value.weekday > 6 ||
    !Number.isInteger(value.hour) || value.hour < 0 || value.hour > 23 ||
    !Number.isInteger(value.minute) || value.minute < 0 || value.minute > 59
  ) throw new Error("Scheduled claim has an invalid approved schedule binding");
  if (value.acceptanceWindow !== undefined) {
    const window = value.acceptanceWindow;
    const approved = parseTimestamp(window.approvedAtUtc);
    const starts = parseTimestamp(window.startsAtUtc);
    const expires = parseTimestamp(window.expiresAtUtc);
    if (
      window.exactOperation !== "one online scheduler acceptance capture" ||
      approved === undefined || starts === undefined || expires === undefined ||
      approved > starts || expires <= starts ||
      expires - approved > 4 * 3_600_000
    ) throw new Error("Scheduled claim has an invalid acceptance binding");
  }
}

/** Fail closed when a pending capture is no longer authorized by the latest
 * approved schedule: a revoked, malformed or future approval, a changed
 * weekly or one-time authority, or a closed one-time acceptance window.
 */
export function assertCaptureStillAuthorized(
  latest: BackupSchedule,
  claim: WindowClaim,
  now: Date,
): void {
  validateSchedule(latest, now);
  if (!claim.approvedSchedule) {
    throw new Error("Scheduled claim has no approved schedule binding");
  }
  if (
    !sameApprovedSchedule(claim.approvedSchedule, approvedScheduleOf(latest))
  ) {
    throw new Error("Approved schedule changed while the capture was pending");
  }
  if (
    isAcceptanceWindowId(claim.windowId) &&
    currentWindow(latest, now) !== claim.windowId
  ) {
    throw new Error("One-time scheduler acceptance window closed");
  }
}

function captureTimestamp(
  state: ScheduledRuntimeState | undefined,
): number | undefined {
  const cycle = state?.cycle;
  if (cycle?.phase !== "complete") return undefined;
  return parseTimestamp(
    cycle.captureIdentity?.captureTimeUtc ?? cycle.sourceAcceptedAtUtc ??
      state?.lastSuccessfulCaptureAtUtc,
  );
}

function periodIsSatisfied(
  schedule: BackupSchedule,
  due: string,
  state: ScheduledRuntimeState | undefined,
): boolean {
  const captured = captureTimestamp(state);
  if (captured === undefined) return false;
  const capturedPeriod = periodAt(schedule, new Date(captured));
  const dueDate = periodDate(due);
  const capturedDate = periodDate(capturedPeriod);
  return dueDate !== "" && capturedDate !== "" && capturedDate >= dueDate;
}

function retryDecision(
  state: ScheduledRuntimeState | undefined,
  now: Date,
): string | undefined {
  const retry = state?.cycle?.retry;
  if (!retry) return undefined;
  const firstFailure = parseTimestamp(retry.firstFailureAtUtc);
  const nextAttempt = parseTimestamp(retry.nextAttemptAtUtc);
  const deadline = parseTimestamp(retry.deadlineAtUtc);
  if (
    (retry.disposition !== "retryable" && retry.disposition !== "blocked") ||
    ![
      "planned",
      "backing-up",
      "pair-available",
      "source-accepted",
      "retiring",
    ].includes(retry.resumePhase) ||
    !Number.isInteger(retry.attempts) || retry.attempts < 0 ||
    retry.attempts > ONLINE_RETRY_POLICY.maximumAttempts ||
    firstFailure === undefined || nextAttempt === undefined ||
    deadline === undefined || nextAttempt < firstFailure ||
    deadline < firstFailure
  ) return "BACKUP_RETRY_METADATA_INVALID";
  if (retry.disposition === "blocked") return "BACKUP_RETRY_BLOCKED";
  if (now.getTime() < nextAttempt) return "BACKUP_RETRY_NOT_DUE";
  return undefined;
}

function validateClaim(claim: WindowClaim): void {
  if (
    typeof claim.windowId !== "string" || claim.windowId === "" ||
    ![
      "started",
      "complete",
      "failed",
      "reconciliation-required",
    ].includes(claim.status) ||
    !parseTimestamp(claim.updatedAtUtc)
  ) throw new Error("Scheduled claim has an unknown status");
  if (claim.periodId !== undefined && claim.periodId === "") {
    throw new Error("Scheduled claim has no period identity");
  }
  if (claim.approvedSchedule !== undefined) {
    validateApprovedSchedule(claim.approvedSchedule);
  }
  if (claim.owner !== undefined) validateClaimOwner(claim.owner);
  if (claim.status === "reconciliation-required") {
    const reconciliation = claim.reconciliation;
    if (
      !reconciliation || reconciliation.captureStarted !== false ||
      !parseTimestamp(reconciliation.requiredAtUtc) ||
      !parseTimestamp(reconciliation.expiredAtUtc) ||
      typeof reconciliation.instruction !== "string" ||
      reconciliation.instruction === "" ||
      reconciliation.instruction.length > 400
    ) {
      throw new Error("Scheduled reconciliation claim is invalid");
    }
  } else if (claim.reconciliation !== undefined) {
    throw new Error(
      "Scheduled reconciliation marker requires a terminal claim",
    );
  }
}

/** True when the runtime journal records a create intent or group ID.
 * Either field means an OCI group backup operation may have occurred and the
 * claim must keep the strict block instead of suggesting removal.
 */
function captureStarted(state: ScheduledRuntimeState | undefined): boolean {
  const cycle = state?.cycle;
  return cycle?.volumeGroupBackupIntent === true ||
    (typeof cycle?.volumeGroupBackupId === "string" &&
      cycle.volumeGroupBackupId !== "");
}

const RECONCILIATION_INSTRUCTION =
  "Verify no OCI volume-group backup was created for this claim, then archive " +
  "the failed runtime journal and this stale scheduler claim under the shared " +
  "controller lock using the read-only steps in 06-TROUBLESHOOTING.md.";

function reconciliationClaimFor(
  existing: WindowClaim,
  now: Date,
): WindowClaim {
  const expiredAtUtc = parseTimestamp(
    existing.approvedSchedule?.acceptanceWindow?.expiresAtUtc,
  );
  if (expiredAtUtc === undefined) {
    throw new Error("Stale claim has no recorded acceptance expiry");
  }
  return {
    ...existing,
    status: "reconciliation-required",
    updatedAtUtc: now.toISOString(),
    reconciliation: {
      requiredAtUtc: now.toISOString(),
      expiredAtUtc: new Date(expiredAtUtc).toISOString(),
      captureStarted: false,
      instruction: RECONCILIATION_INSTRUCTION,
    },
  };
}

/** Return the terminal claim only when a bounded acceptance claim is past its
 * recorded expiry and the runtime proves that OCI creation never started.
 * Keeping this check separate lets it run before a blocked retry can mask the
 * operator-reconciliation state produced by a failed pre-capture guard.
 */
function expiredReconciliationClaim(
  schedule: BackupSchedule,
  now: Date,
  state: ScheduledRuntimeState | undefined,
  existing: WindowClaim | undefined,
): WindowClaim | undefined {
  if (
    !existing || !isAcceptanceWindowId(existing.windowId) ||
    state?.cycle?.phase === "complete" ||
    currentWindow(schedule, now) === existing.windowId
  ) return undefined;
  const expiry = parseTimestamp(
    existing.approvedSchedule?.acceptanceWindow?.expiresAtUtc,
  );
  if (
    expiry === undefined || now.getTime() <= expiry || captureStarted(state)
  ) return undefined;
  return reconciliationClaimFor(existing, now);
}

function claimFor(
  triggerId: string,
  due: string,
  now: Date,
  state: ScheduledRuntimeState | undefined,
  existing: WindowClaim | undefined,
  schedule: BackupSchedule,
): WindowClaim {
  const { owner: _owner, failure: _failure, ...prior } = existing ?? {};
  return {
    ...prior,
    windowId: existing?.windowId ?? triggerId,
    periodId: existing?.periodId ?? due,
    previousCycleSuffix: state?.cycle?.phase === "complete"
      ? state.cycle.suffix
      : existing?.previousCycleSuffix,
    approvedSchedule: existing?.approvedSchedule ??
      approvedScheduleOf(schedule),
    status: "started",
    updatedAtUtc: now.toISOString(),
  };
}

/** Decide one scheduler invocation without touching the runtime or OCI.
 *
 * A completed capture is matched to its weekly civil period. A late trigger
 * therefore observes the same due period and skips it, while a missed period
 * starts one current claim. An unfinished cycle always reuses its claim and
 * journal, even when the clock has crossed a later preferred Sunday.
 */
export function planScheduledClaim(
  schedule: BackupSchedule,
  now: Date,
  state: ScheduledRuntimeState | undefined,
  existing: WindowClaim | undefined,
): ScheduledDecision {
  const due = duePeriod(schedule, now);
  const triggerId = currentWindow(schedule, now);
  if (existing) validateClaim(existing);

  if (existing?.status === "reconciliation-required") {
    // The terminal claim is the operator's action surface. It stays distinct
    // until the operator removes only that stale claim; nothing here allocates
    // a capture identity or bypasses the latest schedule approval.
    return {
      action: "skip",
      reason: "SCHEDULE_CLAIM_RECONCILIATION_REQUIRED",
    };
  }

  const cycleComplete = state?.cycle?.phase === "complete";
  const reconciliationClaim = !cycleComplete
    ? expiredReconciliationClaim(schedule, now, state, existing)
    : undefined;
  const acceptanceDue = isAcceptanceWindowId(triggerId) &&
    (captureTimestamp(state) ?? -Infinity) <
      Date.parse(triggerId.slice("acceptance@".length));
  if (
    cycleComplete && !acceptanceDue && periodIsSatisfied(schedule, due, state)
  ) {
    return {
      action: "skip",
      reason: "PERIOD_ALREADY_SATISFIED",
      ...(existing?.status === "started" && state?.cycle?.suffix &&
          state.cycle.suffix !== existing.previousCycleSuffix
        ? {
          completedClaim: {
            ...existing,
            status: "complete" as const,
            updatedAtUtc: now.toISOString(),
          },
        }
        : {}),
    };
  }

  const retry = retryDecision(state, now);
  if (retry) {
    // A pre-capture authorization failure is persisted as a blocked retry.
    // Surface the same terminal no-capture reconciliation state instead of
    // letting the generic retry block permanently hide it.
    if (
      retry === "BACKUP_RETRY_BLOCKED" && reconciliationClaim !== undefined
    ) {
      return {
        action: "skip",
        reason: "SCHEDULE_CLAIM_RECONCILIATION_REQUIRED",
        reconciliationClaim,
      };
    }
    return { action: "skip", reason: retry };
  }

  if (reconciliationClaim !== undefined) {
    return {
      action: "skip",
      reason: "SCHEDULE_CLAIM_RECONCILIATION_REQUIRED",
      reconciliationClaim,
    };
  }

  if (!cycleComplete && existing && isAcceptanceWindowId(existing.windowId)) {
    // A one-time approval cannot silently turn into a standing approval after
    // its exact bounded window expires. The existing journal remains for
    // explicit reconciliation, and no new identity is allocated here.
    if (currentWindow(schedule, now) !== existing.windowId) {
      return { action: "skip", reason: "ACCEPTANCE_WINDOW_EXPIRED" };
    }
  }

  if (!cycleComplete && existing) {
    return {
      action: "run",
      claim: claimFor(
        existing.windowId,
        existing.periodId ?? due,
        now,
        state,
        existing,
        schedule,
      ),
    };
  }

  return {
    action: "run",
    claim: claimFor(triggerId, due, now, state, undefined, schedule),
  };
}

async function readOptional<T>(path: string): Promise<T | undefined> {
  try {
    return await readPrivateJson<T>(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return undefined;
    throw error;
  }
}

interface ClaimRecovery {
  /** The exact known remote operation, if one was already committed. */
  knownGroupId?: string;
  knownGroupSuffix?: string;
  expectedGroupSuffix?: string;
  inventorySince: number;
  status: "failed" | "complete";
}

function recoveryFor(
  claim: WindowClaim,
  state: RuntimeState | undefined,
  updated: number,
  now: number,
): ClaimRecovery | undefined {
  const cycle = state?.cycle;
  if (!cycle) {
    return claim.owner?.journalSuffix === null &&
        claim.previousCycleSuffix === undefined
      ? { status: "failed", inventorySince: updated }
      : undefined;
  }
  const createdAt = parseTimestamp(cycle.createdAtUtc);
  const updatedAt = parseTimestamp(cycle.updatedAtUtc);
  if (
    cycle.mode !== "online" || !CYCLE_SUFFIX.test(cycle.suffix) ||
    createdAt === undefined || updatedAt === undefined ||
    createdAt > updatedAt ||
    updatedAt > now ||
    (cycle.volumeGroupBackupIntent !== undefined &&
      typeof cycle.volumeGroupBackupIntent !== "boolean") ||
    (cycle.volumeGroupBackupId !== undefined &&
      (typeof cycle.volumeGroupBackupId !== "string" ||
        cycle.volumeGroupBackupId === ""))
  ) return undefined;
  if (
    cycle.phase === "complete" && cycle.suffix === claim.previousCycleSuffix
  ) {
    if (
      updatedAt > updated ||
      (claim.owner !== undefined && claim.owner.journalSuffix !== cycle.suffix)
    ) return undefined;
    return {
      status: "failed",
      inventorySince: updatedAt,
      knownGroupId: cycle.captureIdentity?.volumeGroupBackupId ??
        cycle.volumeGroupBackupId,
      knownGroupSuffix: cycle.suffix,
    };
  }
  // Only a new-format claim can bind a crash within a new or resumed
  // journal. Legacy migration is confined to the unchanged predecessor.
  const owner = claim.owner;
  const ownsJournal = owner
    ? owner.journalSuffix === cycle.suffix ||
      (createdAt >= Date.parse(owner.startedAtUtc) &&
        (owner.journalSuffix === null || owner.journalSuffix ===
                claim.previousCycleSuffix &&
            cycle.previousPair.suffix === claim.previousCycleSuffix))
    : cycle.phase === "complete" && createdAt >= updated &&
      cycle.previousPair.suffix === claim.previousCycleSuffix;
  if (!ownsJournal) return undefined;
  if (cycle.phase === "complete") {
    return {
      status: "complete",
      inventorySince: createdAt,
      knownGroupId: cycle.captureIdentity?.volumeGroupBackupId ??
        cycle.volumeGroupBackupId,
      knownGroupSuffix: cycle.suffix,
    };
  }
  if (
    !owner ||
    ![
      "planned",
      "backing-up",
      "pair-available",
      "source-accepted",
      "retiring",
      "failed",
    ].includes(cycle.phase)
  ) return undefined;
  return {
    status: "failed",
    inventorySince: Math.min(createdAt, Date.parse(owner.startedAtUtc)),
    knownGroupId: cycle.volumeGroupBackupId,
    knownGroupSuffix: cycle.suffix,
    ...(captureStarted(state) ? { expectedGroupSuffix: cycle.suffix } : {}),
  };
}

type ClaimStore = {
  read(path: string): Promise<unknown>;
  write(path: string, value: WindowClaim): Promise<void>;
};

interface ClaimRecoveryDeps extends ClaimStore {
  ownerState: typeof scheduledClaimOwnerState;
  proveIdle(recovery: ClaimRecovery): Promise<void>;
}

const claimStore: ClaimStore = {
  read: readOptional,
  write: writePrivateJson,
};

async function archiveClaim(
  claim: WindowClaim,
  store: ClaimStore,
): Promise<void> {
  const original = JSON.stringify(claim);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(original),
  );
  const path = `.private/cycles/scheduled-claim-${
    Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0")).join("")
  }.abandoned.json`;
  const prior = await store.read(path);
  if (prior === undefined) await store.write(path, claim);
  else if (JSON.stringify(prior) !== original) {
    throw new ScheduledClaimCustodyError("SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
  }
}

/** Called only while the shared controller flock is held. Claim recovery is
 * a durable transition after proof. The runtime journal and remote artifacts
 * stay available to their existing exact-operation reconciliation. */
export async function recoverScheduledClaim(
  claim: WindowClaim | undefined,
  state: RuntimeState | undefined,
  schedule: BackupSchedule,
  now: Date,
  deps: ClaimRecoveryDeps,
): Promise<WindowClaim | undefined> {
  if (claim === undefined) return undefined;
  validateClaim(claim);
  if (claim.status !== "started") return claim;
  const updated = Date.parse(claim.updatedAtUtc);
  const nowMs = now.getTime();
  const oldPeriod = (ageMs: number) =>
    claim.periodId !== undefined && claim.windowId === claim.periodId &&
    claim.periodId === periodAt(schedule, new Date(updated)) &&
    claim.periodId <= periodAt(schedule, new Date(nowMs - ageMs));
  validateSchedule(schedule, now);
  if (
    updated > nowMs ||
    (claim.owner !== undefined &&
      claim.owner.startedAtUtc !== claim.updatedAtUtc)
  ) throw new ScheduledClaimCustodyError("SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
  const overdue = claim.owner === undefined
    ? oldPeriod(CLAIM_INCIDENT_AGE_MS) ||
      nowMs - updated >= CLAIM_INCIDENT_AGE_MS
    : nowMs - updated >= CLAIM_INCIDENT_AGE_MS;
  const undecidable = () =>
    new ScheduledClaimCustodyError(
      overdue
        ? "SCHEDULED_CLAIM_CUSTODY_OVERDUE"
        : "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE",
    );
  if (
    !claim.approvedSchedule ||
    !sameApprovedSchedule(claim.approvedSchedule, approvedScheduleOf(schedule))
  ) throw undecidable();
  if (claim.owner !== undefined) {
    let ownerState;
    try {
      ownerState = await deps.ownerState(claim.owner);
    } catch {
      throw undecidable();
    }
    if (ownerState === "live") {
      throw new ScheduledClaimCustodyError("SCHEDULED_CLAIM_OWNER_LIVE");
    }
    if (ownerState !== "dead") throw undecidable();
  } else if (!oldPeriod(LEGACY_CLAIM_MIN_AGE_MS)) {
    throw undecidable();
  }
  try {
    const recovery = recoveryFor(claim, state, updated, nowMs);
    if (!recovery) throw undecidable();
    await deps.proveIdle(recovery);
    await archiveClaim(claim, deps);
    const recovered: WindowClaim = {
      ...claim,
      status: recovery.status,
      updatedAtUtc: now.toISOString(),
      ...(recovery.status === "failed"
        ? {
          failure: {
            reason: claim.owner
              ? "CONTROLLER_EXITED"
              : "LEGACY_CONTROLLER_EXITED",
            observedAtUtc: now.toISOString(),
          },
        }
        : {}),
    };
    await deps.write(CLAIM_PATH, recovered);
    return recovered;
  } catch {
    throw undecidable();
  }
}

export function assertClaimInventorySettled(
  inventory: Pick<
    BackupInventory,
    | "observedAtUtc"
    | "instance"
    | "sourceAttachmentsProved"
    | "sourceVolumeGroupProved"
    | "sourceVolumeGroup"
    | "volumeGroupBackups"
  >,
  config: Pick<RuntimeConfig, "policy" | "source">,
  recovery: ClaimRecovery,
): void {
  const groupId = config.policy.volumeGroupId;
  const observedAt = Date.parse(inventory.observedAtUtc);
  if (
    !groupId || inventory.instance["lifecycle-state"] !== "RUNNING" ||
    !inventory.sourceAttachmentsProved || !inventory.sourceVolumeGroupProved ||
    inventory.sourceVolumeGroup?.id !== groupId || !Number.isFinite(observedAt)
  ) throw new Error("Claim source custody is unproved");
  let expected = 0;
  let known = 0;
  for (const group of inventory.volumeGroupBackups) {
    const id = group.id;
    const groupSource = group["volume-group-id"];
    const displayName = group["display-name"];
    const isExpected = recovery.expectedGroupSuffix !== undefined &&
      displayName === `arch-online-golden-${recovery.expectedGroupSuffix}`;
    if (
      groupSource !== groupId && !isExpected && id !== recovery.knownGroupId
    ) {
      if (typeof groupSource === "string" && groupSource !== "") continue;
      throw new Error("Group custody is unproved");
    }
    const created = Date.parse(String(group["time-created"] ?? ""));
    if (
      typeof id !== "string" || id === "" || groupSource !== groupId ||
      group["compartment-id"] !== config.source.compartmentId ||
      group["lifecycle-state"] !== "AVAILABLE" ||
      !Number.isFinite(created) || created > observedAt
    ) throw new Error("Group operation has not settled");
    if (id === recovery.knownGroupId) {
      if (
        group.type !== "FULL" ||
        displayName !== `arch-online-golden-${recovery.knownGroupSuffix}`
      ) throw new Error("Previously known group differs");
      known++;
    }
    if (isExpected) {
      if (
        group.type !== "FULL" || created < recovery.inventorySince ||
        (recovery.knownGroupId !== undefined && id !== recovery.knownGroupId)
      ) throw new Error("Recorded group operation differs");
      expected++;
    } else if (
      created >= recovery.inventorySince && id !== recovery.knownGroupId
    ) {
      throw new Error("Unexpected group operation after the prior checkpoint");
    }
  }
  if (recovery.knownGroupId !== undefined && known !== 1) {
    throw new Error("Previously known group is missing or ambiguous");
  }
  if (recovery.expectedGroupSuffix !== undefined && expected !== 1) {
    throw new Error("Recorded group creation is ambiguous");
  }
}

function realClaimRecovery(
  config: RuntimeConfig,
  state: RuntimeState | undefined,
  proveSourceIdle = async () => {
    const source = await import("./backblaze-file-backup.ts");
    await source.proveBackblazeSourceIdle(
      source.realRemoteSeam(source.realRemoteRunner),
    );
  },
): ClaimRecoveryDeps {
  return {
    ...claimStore,
    ownerState: scheduledClaimOwnerState,
    async proveIdle(recovery) {
      if (
        config.action !== "cycle" ||
        JSON.stringify(config.source) !==
          JSON.stringify(config.policy.source) ||
        config.volumeGroupId !== config.policy.volumeGroupId ||
        (state && (JSON.stringify(state.policy.source) !==
            JSON.stringify(config.source) ||
          state.policy.volumeGroupId !== config.policy.volumeGroupId ||
          JSON.stringify(state.policy.standingApproval) !==
            JSON.stringify(config.policy.standingApproval)))
      ) throw new Error("Claim source or standing approval differs");
      if (state?.cycle.phase === "complete") {
        assertBackblazeLaunchAllowed(state, undefined);
      }
      const evidence = backupControllerEvidence(config);
      await evidence.assertNoOtherController();
      assertClaimInventorySettled(
        await readBackupInventory(config),
        config,
        recovery,
      );
      await proveSourceIdle();
      await evidence.assertNoOtherController();
    },
  };
}

/** Fresh Backblaze admission only. The existing gate and Oracle validators
 * still run. A recovery must not bypass the completed-Oracle-source rule. */
export async function readScheduledClaimForBackblaze(
  state: unknown,
  claim: unknown,
  now: Date,
  proveSourceIdle: () => Promise<void>,
): Promise<unknown> {
  if (
    !claim || typeof claim !== "object" ||
    (claim as { status?: unknown }).status !== "started"
  ) return claim;
  const runtime = state as RuntimeState;
  const config = await readPrivateJson<RuntimeConfig>(
    ".private/backup-controller.json",
  );
  const schedule = await readPrivateJson<BackupSchedule>(
    ".private/backup-schedule.json",
  );
  const deps = realClaimRecovery(config, runtime, proveSourceIdle);
  return await recoverScheduledClaim(
    claim as WindowClaim,
    runtime,
    schedule,
    now,
    {
      ...deps,
      proveIdle: (recovery) => {
        assertBackblazeLaunchAllowed(state, undefined);
        return deps.proveIdle(recovery);
      },
    },
  );
}

export async function runScheduledBackup(): Promise<"HEALTHY" | "DEFERRED"> {
  let completed = false;
  try {
    await main(async (state, config) => {
      // The shared lock serializes capture; normal source activity stays online.
      const now = new Date();
      const schedule = await readPrivateJson<BackupSchedule>(
        ".private/backup-schedule.json",
      );
      const existing = await readOptional<WindowClaim>(CLAIM_PATH);
      // Preserve the existing operator path for expired one-time approvals.
      // That path retains the claim and never releases it for Backblaze.
      const expiredLegacy = existing?.owner === undefined &&
        existing?.status === "started" &&
        expiredReconciliationClaim(schedule, now, state, existing) !==
          undefined;
      const reconciled = expiredLegacy ? existing : await recoverScheduledClaim(
        existing,
        state,
        schedule,
        now,
        realClaimRecovery(config, state),
      );
      const decision = planScheduledClaim(schedule, now, state, reconciled);
      if (decision.action === "skip") {
        // Repair a crash between durable runtime completion and afterCycle
        // before releasing the shared lock or allowing the B2 launch gate.
        if (decision.completedClaim) {
          await writePrivateJson(CLAIM_PATH, decision.completedClaim);
        }
        // Persist the terminal claim before failing: a later invocation must
        // keep skipping with its distinct reason until the operator reconciles
        // both this stale claim and the matching failed runtime journal.
        if (decision.reconciliationClaim) {
          await writePrivateJson(CLAIM_PATH, decision.reconciliationClaim);
        }
        if (
          [
            "BACKUP_RETRY_BLOCKED",
            "BACKUP_RETRY_METADATA_INVALID",
            "ACCEPTANCE_WINDOW_EXPIRED",
            "SCHEDULE_CLAIM_RECONCILIATION_REQUIRED",
          ].includes(decision.reason)
        ) throw new Error(decision.reason);
        throw new Skipped(decision.reason);
      }
      const claim: WindowClaim = {
        ...decision.claim,
        owner: await currentClaimOwner(
          decision.claim.updatedAtUtc,
          state?.cycle.suffix ?? null,
        ),
      };
      await writePrivateJson(CLAIM_PATH, claim);
      return {
        afterPreparationFailure: async () => {
          const observedAtUtc = new Date().toISOString();
          await writePrivateJson(
            CLAIM_PATH,
            {
              ...claim,
              status: "failed",
              updatedAtUtc: observedAtUtc,
              failure: { reason: "PREPARATION_FAILED", observedAtUtc },
            } satisfies WindowClaim,
          );
        },
        afterCycle: async (cycle) => {
          await writePrivateJson(CLAIM_PATH, {
            ...claim,
            status: cycle.phase === "complete" ? "complete" : "failed",
            updatedAtUtc: new Date().toISOString(),
          });
          completed = cycle.phase === "complete";
        },
        beforeCapture: async () => {
          const latest = await readPrivateJson<BackupSchedule>(
            ".private/backup-schedule.json",
          );
          // Every capture re-reads the latest approval immediately before
          // creation. A revoked, malformed, future or changed approval, a
          // changed weekly or one-time authority, or a closed one-time
          // acceptance window cannot authorize a stale capture. Weekly claims
          // stay due after the grace period; only the bounded acceptance
          // trigger must also still be active when OCI creation starts.
          assertCaptureStillAuthorized(latest, claim, new Date());
        },
      };
    }, { skipWhenOracleMutationBlocked: true });
  } catch (error) {
    if (error instanceof Skipped) {
      console.log(error.message);
      return error.message === "PERIOD_ALREADY_SATISFIED"
        ? "HEALTHY"
        : "DEFERRED";
    }
    throw error;
  }
  return completed ? "HEALTHY" : "DEFERRED";
}

if (import.meta.main) {
  try {
    await runScheduledBackup();
  } catch (error) {
    console.error(
      redactOcid(error instanceof Error ? error.message : String(error)),
    );
    Deno.exitCode = 1;
  }
}
