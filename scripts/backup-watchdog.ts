import {
  assessBackupWatchdog,
  type BackupSchedule,
  type BackupWatchdogState,
  validateSchedule,
} from "./backup-schedule.ts";
import { readPrivateJson, writePrivateJson } from "./oci.ts";
import { notifyMac } from "./backup-mac-alert.ts";
import { readGate } from "./backblaze-controller-gate.ts";
import type { OnlineBackupRetry } from "./online-backup-contract.ts";
import type { GroupRestorePlan } from "./oci-group-restore-drill.ts";
import {
  type GroupRestoreAcceptanceReceipt,
  validateGroupRestoreAcceptance,
} from "./oci-group-restore-executor.ts";
import {
  assessBackblazeWatchdog,
  type ControllerState,
  type ObservedSource,
  realRemoteRunner,
  realRemoteSeam,
  STALE_AFTER_MS,
  validateControllerState,
  type WatchdogAssessment,
  weekWindow,
} from "./backblaze-file-backup.ts";
import {
  backupRuntimeCatalog,
  type BackupV2ControllerObservation,
  type BackupV2ControllerState,
  observeBackupV2Source,
  readBackupRuntimeGate,
  validateBackupV2ControllerState,
} from "./backup-v2-controller.ts";
import {
  type BackupV2Gate,
  validateBackupV2Gate,
  validateBackupV2Status,
} from "./backup-v2-runtime-contract.ts";

export const B2_REPORT_PATH = ".private/reports/backblaze-file-backup.json";
export const ORACLE_REPORT_PATH = ".private/reports/backup-watchdog.json";
export const B2_STATE_PATH = ".private/file-backup/controller.json";

/** Actual capture intervals and independently accepted receipts determine
 * freshness. A request, heartbeat or new verification date cannot refresh it. */
export function acceptedBackupRuntimeCapture(value: unknown, now: Date) {
  const window = weekWindow(now),
    start = Date.parse(window.startAtUtc),
    end = Date.parse(window.endAtUtc);
  let unknown = false;
  const entries = backupRuntimeCatalog(value).flatMap((entry) => {
    const verifiedAtUtc = entry.schemaVersion === 1
      ? entry.entry.receipt.verifiedAtUtc
      : entry.receipt.verifiedAtUtc;
    const acceptedAtUtc = entry.schemaVersion === 1
      ? entry.entry.acceptedAtUtc
      : entry.acceptedAtUtc;
    const starts = entry.schemaVersion === 1
      ? [entry.entry.index.captureStartedAtUtc]
      : entry.selectedRoot.root.roles.map((role) => role.captureStartedAtUtc);
    const finishes = entry.schemaVersion === 1
      ? [entry.entry.index.captureFinishedAtUtc]
      : entry.selectedRoot.root.roles.map((role) => role.captureFinishedAtUtc);
    const captured = Math.max(...finishes.map(Date.parse)),
      verified = Date.parse(verifiedAtUtc),
      accepted = Date.parse(acceptedAtUtc);
    if (
      ![captured, verified, accepted, ...starts.map(Date.parse)].every(
        Number.isFinite,
      ) || captured > verified || verified > now.getTime() ||
      accepted > now.getTime()
    ) {
      unknown = true;
      return [];
    }
    return [{
      entry,
      captureStartedAtUtc: new Date(Math.min(...starts.map(Date.parse)))
        .toISOString(),
      captureFinishedAtUtc: new Date(captured).toISOString(),
      verifiedAtUtc,
      current: captured >= start && captured < end,
    }];
  }).sort((a, b) =>
    Date.parse(b.captureFinishedAtUtc) - Date.parse(a.captureFinishedAtUtc)
  );
  return {
    latest: entries[0] ?? null,
    current: entries.find((entry) => entry.current) ?? null,
    periodKey: window.periodKey,
    unknown,
  };
}

export function assessBackupV2Watchdog(
  stateInput: unknown,
  gateInput: unknown | null,
  now: Date,
  source?: BackupV2ControllerObservation,
  progress?: unknown,
): WatchdogAssessment {
  const state = validateBackupV2ControllerState(stateInput), job = state.job;
  let gate: BackupV2Gate | null = null;
  try {
    gate = gateInput === null ? null : validateBackupV2Gate(gateInput);
  } catch {
    return { status: "B2_BACKUP_GATE_UNKNOWN", healthy: false };
  }
  const jobId = job?.settings.envelope.request.jobId;
  if (
    gate?.state === "CANCELLATION_BLOCKED" ||
    job?.phase === "CANCELLATION_BLOCKED"
  ) {
    return {
      status: `B2_CANCELLATION_BLOCKED:${
        jobId ?? gate?.envelope.request.jobId
      }`,
      healthy: false,
    };
  }
  const accepted = acceptedBackupRuntimeCapture(state, now);
  if (accepted.unknown) {
    return {
      status: "B2_BACKUP_ACCEPTANCE_UNKNOWN",
      healthy: false,
      detail: "Accepted capture timestamps are future or contradictory",
    };
  }
  if (!job || job.phase === "COMPLETE") {
    if (gate !== null) {
      return {
        status: `B2_BACKUP_GATE_HELD:${gate.envelope.request.jobId}`,
        healthy: false,
      };
    }
    const entry = accepted.current?.entry;
    const acceptedJob = entry?.schemaVersion === 2
      ? entry.envelope.request.jobId
      : entry?.entry.index.generation.replace(/^generation-/, "job-");
    return accepted.current
      ? { status: `B2_BACKUP_CURRENT:${acceptedJob}`, healthy: true }
      : { status: `B2_PERIOD_MISSED:${accepted.periodKey}`, healthy: false };
  }
  if (job.phase === "FAILED") {
    return { status: `B2_BACKUP_FAILED:${jobId}`, healthy: false };
  }
  if (!["WORKER", "VERIFY"].includes(job.phase)) {
    return {
      status: `B2_BACKUP_PENDING:${jobId}`,
      healthy: false,
      detail: "Bounded v2 controller transition; acceptance remains separate",
    };
  }
  const expected = job.activeKind === "worker"
    ? job.workerGate
    : job.verifierGate;
  if (
    gate === null || gate.state !== "ACTIVE" || !gate.custody ||
    gate.gateId !== expected.gateId ||
    gate.sourceBootId !== expected.sourceBootId ||
    gate.envelope.requestSha256 !== expected.envelope.requestSha256 ||
    JSON.stringify(gate.custody) !== JSON.stringify(expected.custody)
  ) return { status: `B2_BACKUP_ACTIVE_UNBOUND:${jobId}`, healthy: false };
  const liveIdentity = source?.identity;
  if (
    !source || source.sourceBootId !== gate.sourceBootId || !liveIdentity ||
    Object.keys(liveIdentity).length !== 5 ||
    !([
      "unitName",
      "invocationId",
      "mainPid",
      "mainStartTicks",
      "cgroup",
    ] as const).every((key) => liveIdentity[key] === gate.custody![key])
  ) return { status: `B2_BACKUP_SOURCE_UNKNOWN:${jobId}`, healthy: false };
  let status;
  try {
    status = validateBackupV2Status(source.status, gate);
  } catch {
    return { status: `B2_BACKUP_SOURCE_MISMATCH:${jobId}`, healthy: false };
  }
  if (status.phase === "CANCELLATION_BLOCKED" || status.phase === "FAILED") {
    return { status: `B2_BACKUP_${status.phase}:${jobId}`, healthy: false };
  }
  if (["CLOUD_COMPLETE", "ACCEPTED", "CLEANED"].includes(status.phase)) {
    return {
      status: `B2_BACKUP_PENDING:${jobId}`,
      healthy: false,
      detail:
        "Source terminal artifact awaits independent controller acceptance and settlement",
    };
  }
  if (source.unit !== "RUNNING") {
    return { status: `B2_BACKUP_SOURCE_UNKNOWN:${jobId}`, healthy: false };
  }
  if (
    Date.parse(status.updatedAtUtc) > now.getTime() ||
    now.getTime() - Date.parse(status.updatedAtUtc) > STALE_AFTER_MS
  ) return { status: `B2_BACKUP_SOURCE_STALE:${jobId}`, healthy: false };
  const report = progress as {
    schemaVersion?: unknown;
    jobId?: unknown;
    observedAtUtc?: unknown;
    state?: unknown;
    sample?: { format?: unknown; processBound?: unknown; v2Status?: unknown };
  } | null;
  const observed = Date.parse(String(report?.observedAtUtc));
  if (
    report?.schemaVersion !== 1 || report.jobId !== jobId ||
    report.sample?.format !== "backup-v2" ||
    report.sample.processBound !== true || !Number.isFinite(observed) ||
    observed > now.getTime() || now.getTime() - observed > 75 * 60_000
  ) return { status: `B2_BACKUP_PROGRESS_UNKNOWN:${jobId}`, healthy: false };
  try {
    const reported = validateBackupV2Status(report.sample.v2Status, gate);
    if (
      [
        "CLOUD_COMPLETE",
        "ACCEPTED",
        "CLEANED",
        "FAILED",
        "CANCELLATION_BLOCKED",
      ].includes(reported.phase)
    ) throw Error("Report is terminal");
  } catch {
    return { status: `B2_BACKUP_PROGRESS_UNKNOWN:${jobId}`, healthy: false };
  }
  if (["STALLED", "BEHIND_SCHEDULE", "FAILED"].includes(String(report.state))) {
    return {
      status: `B2_PROGRESS_${String(report.state)}:${jobId}`,
      healthy: false,
    };
  }
  if (report.state !== "PROGRESSING") {
    return {
      status: `B2_BACKUP_PROGRESS_UNKNOWN:${jobId}`,
      healthy: false,
      detail:
        "Current process is bound; useful work has no comparable advancing observation",
    };
  }
  return {
    status: `B2_BACKUP_ACTIVE:${jobId}`,
    healthy: true,
    detail:
      "Bound source useful work advanced; the due period still needs independent catalog acceptance",
  };
}

/** Only fresh alarms for the currently observed source invocation affect alerts. */
export function assessHourlyProgress(
  value: unknown,
  jobId: string,
  invocationId: string | null,
  now: Date,
): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const report = value as Record<string, unknown>;
  const sample = report.sample as Record<string, unknown> | undefined;
  const observed = Date.parse(String(report.observedAtUtc));
  if (
    report.schemaVersion !== 1 || report.jobId !== jobId ||
    !invocationId || sample?.invocationId !== invocationId ||
    !Number.isFinite(observed) || observed > now.getTime() ||
    now.getTime() - observed > 75 * 60_000 ||
    !["STALLED", "BEHIND_SCHEDULE"].includes(String(report.state))
  ) return undefined;
  return {
    status: `B2_PROGRESS_${String(report.state)}:${jobId}`,
    healthy: false,
    progress: report,
    detail: report.detail,
  };
}

/** Retry is an unresolved backup failure, even when automatic recovery is due.
 * Keep its deadline and prior usable capture visible to the operator. */
export function assessOracleRetry(
  cycle: { phase: string; retry?: OnlineBackupRetry } | undefined,
  now: Date,
) {
  if (cycle?.phase !== "failed" || !cycle.retry) return undefined;
  const retry = cycle.retry;
  const next = Date.parse(retry.nextAttemptAtUtc);
  const first = Date.parse(retry.firstFailureAtUtc);
  const deadline = Date.parse(retry.deadlineAtUtc);
  if (
    ![next, first, deadline].every(Number.isFinite) ||
    first > now.getTime() || deadline <= first || next < first ||
    !Number.isInteger(retry.attempts) || retry.attempts < 1 ||
    !["retryable", "blocked"].includes(retry.disposition) ||
    !["planned", "backing-up", "pair-available", "source-accepted", "retiring"]
      .includes(retry.resumePhase)
  ) return { status: "INVALID_RETRY_STATE", healthy: false };
  return {
    status: retry.disposition === "blocked"
      ? "BACKUP_BLOCKED_RECONCILIATION"
      : now.getTime() >= next
      ? "BACKUP_RETRY_DUE"
      : next > deadline
      ? "BACKUP_RETRY_COOLDOWN"
      : "BACKUP_RETRY_WAITING",
    healthy: false,
    retryDisposition: retry.disposition,
    retryAttempts: retry.attempts,
    retryResumePhase: retry.resumePhase,
    nextAttemptAtUtc: retry.nextAttemptAtUtc,
    retryDeadlineAtUtc: retry.deadlineAtUtc,
  };
}

/** Dated boot evidence is independent of per-generation archive verification. */
export async function readBootDrillEvidence(path: string, now: Date) {
  try {
    const proof = await readPrivateJson<Record<string, unknown>>(path);
    const checks = proof.checks as Record<string, unknown> | undefined;
    const bootedAt = Date.parse(String(proof.bootedAtUtc));
    if (
      proof.status !== "RESTORE_DRILL_PROVED" || !Number.isFinite(bootedAt) ||
      bootedAt > now.getTime() || !checks ||
      !["ssh", "mounts", "bootParity", "preservedData", "desktop", "isolation"]
        .every((name) => checks[name] === true)
    ) {
      return { status: "BOOT_DRILL_EVIDENCE_INVALID", bootedAtUtc: null };
    }
    return {
      status: "RESTORE_DRILL_PROVED",
      bootedAtUtc: proof.bootedAtUtc,
      generation: typeof proof.generation === "string"
        ? proof.generation
        : null,
    };
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      return { status: "BOOT_DRILL_UNPROVED", bootedAtUtc: null };
    }
    return { status: "BOOT_DRILL_EVIDENCE_UNREADABLE", bootedAtUtc: null };
  }
}

/** Read the retained typed Oracle receipt with its digest-bound plan. This is
 * dated proof for exactly that group and its two members, never a claim that a
 * later capture has booted. No deleted clone or live source is needed. */
export async function assessOracleBootDrillEvidence(
  proof: { plan: GroupRestorePlan; acceptance: GroupRestoreAcceptanceReceipt },
  now: Date,
  currentGroupBackupId?: string,
) {
  await validateGroupRestoreAcceptance(proof.acceptance, proof.plan, now);
  return {
    status: "RESTORE_DRILL_PROVED",
    observedAtUtc: proof.acceptance.observedAtUtc,
    generation: proof.plan.volumeGroupBackupId,
    bootMemberBackupId: proof.plan.bootMemberBackupId,
    rootMemberBackupId: proof.plan.rootMemberBackupId,
    planSha256: proof.acceptance.planSha256,
    currentCaptureProved: currentGroupBackupId === undefined
      ? null
      : currentGroupBackupId === proof.plan.volumeGroupBackupId,
  };
}

export async function readOracleBootDrillEvidence(
  path: string,
  now: Date,
  currentGroupBackupId?: string,
) {
  try {
    return await assessOracleBootDrillEvidence(
      await readPrivateJson(path),
      now,
      currentGroupBackupId,
    );
  } catch (error) {
    return {
      status: error instanceof Deno.errors.NotFound
        ? "BOOT_DRILL_UNPROVED"
        : "BOOT_DRILL_EVIDENCE_INVALID",
      observedAtUtc: null,
      currentCaptureProved: null,
    };
  }
}

/** Preserve the existing Oracle assessment report and add the Backblaze
 * job/gate assessment; both notifications reuse the same bounded status
 * string and job UUID form. A delivery failure always remains visible.
 *
 * The Backblaze assessment includes a metadata-only live source observation
 * (unit properties plus the bounded status file) through the same source
 * observe command the controller uses, never inside the controller lock. A
 * failed observation is reported as unreachable so a fresh Pi polling time
 * can never stand in for a missing source heartbeat. */
async function observeLiveSource(
  jobId: string,
  unitName: string,
  now: Date,
): Promise<ObservedSource> {
  const observed = await realRemoteSeam(realRemoteRunner).observe(
    unitName,
    jobId,
  );
  return {
    observedAtUtc: now.toISOString(),
    reachable: observed.reachable,
    invocationId: observed.props.get("InvocationID") ?? null,
    status: observed.status,
  };
}

export async function main(): Promise<void> {
  const now = new Date();
  let oracleReport: Record<string, unknown>;
  try {
    const schedule = await readPrivateJson<BackupSchedule>(
      ".private/backup-schedule.json",
    );
    validateSchedule(schedule, now);
    let state: {
      lastSuccessfulCaptureAtUtc?: string;
      cycle: BackupWatchdogState & {
        captureIdentity?: {
          captureTimeUtc: string;
          volumeGroupBackupId: string;
        };
        retry?: OnlineBackupRetry;
      };
    } | undefined;
    try {
      state = await readPrivateJson(".private/backup-runtime.json");
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    oracleReport = {
      ...assessBackupWatchdog(state?.cycle, now, schedule),
      ...assessOracleRetry(state?.cycle, now),
      lastSuccessfulCaptureAtUtc: state?.cycle.phase === "complete"
        ? state.cycle.captureIdentity?.captureTimeUtc ??
          state.lastSuccessfulCaptureAtUtc ?? null
        : state?.lastSuccessfulCaptureAtUtc ?? null,
      lastArchiveVerificationAtUtc: null,
      lastBootDrill: await readOracleBootDrillEvidence(
        ".private/reports/online-oracle-boot.json",
        now,
        state?.cycle.captureIdentity?.volumeGroupBackupId,
      ),
      observedAtUtc: now.toISOString(),
      notificationSent: false,
    };
  } catch (error) {
    oracleReport = {
      status: error instanceof Deno.errors.NotFound
        ? "SCHEDULE_NOT_CONFIGURED"
        : "WATCHDOG_CHECK_FAILED",
      healthy: false,
      observedAtUtc: now.toISOString(),
      notificationSent: false,
    };
  }
  let b2Report: Record<string, unknown>;
  let v2Dispatch = false;
  try {
    let rawState: unknown;
    try {
      rawState = await readPrivateJson(B2_STATE_PATH);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    v2Dispatch =
      (rawState as { schemaVersion?: unknown } | undefined)?.schemaVersion ===
        2;
    if (v2Dispatch) {
      const state: BackupV2ControllerState = validateBackupV2ControllerState(
          rawState,
        ),
        gate = await readBackupRuntimeGate();
      let source: BackupV2ControllerObservation | undefined, progress: unknown;
      if (gate?.schemaVersion === 2 && state.job) {
        try {
          source = await observeBackupV2Source(gate);
        } catch { /* unavailable source is unknown, not a fresh heartbeat */ }
        if (source?.unit === "RUNNING") {
          try {
            const read = await realRemoteSeam(realRemoteRunner).root(
              "cat /var/lib/arch-vps-backup-progress/report.json",
            );
            if (read.code === 0 && read.stdout.length <= 64 * 1024) {
              progress = JSON.parse(read.stdout);
            }
          } catch { /* no usable work observation */ }
        }
      }
      const observedNow = new Date(),
        accepted = acceptedBackupRuntimeCapture(state, observedNow);
      b2Report = {
        lastSuccessfulCaptureAtUtc: accepted.latest?.captureFinishedAtUtc ??
          null,
        lastArchiveVerificationAtUtc: accepted.latest?.verifiedAtUtc ?? null,
        captureStartedAtUtc: accepted.latest?.captureStartedAtUtc ?? null,
        lastBootDrill: await readBootDrillEvidence(
          ".private/reports/backblaze-machine-boot.json",
          observedNow,
        ),
        ...assessBackupV2Watchdog(state, gate, observedNow, source, progress),
        observedAtUtc: observedNow.toISOString(),
        notificationSent: false,
      };
    } else {
      let controllerState: ControllerState | undefined;
      if (rawState !== undefined) {
        controllerState = validateControllerState(rawState);
      }
      const gate = await readGate();
      let source: ObservedSource | undefined;
      if (gate !== null && controllerState?.job !== undefined) {
        try {
          source = await observeLiveSource(
            gate.jobId,
            gate.unitName,
            now,
          );
        } catch {
          source = {
            observedAtUtc: now.toISOString(),
            reachable: false,
            invocationId: null,
            status: null,
          };
        }
      }
      const latestAccepted = controllerState?.catalog.slice().sort((a, b) =>
        Date.parse(b.acceptedAtUtc) - Date.parse(a.acceptedAtUtc)
      )[0];
      b2Report = {
        lastSuccessfulCaptureAtUtc:
          latestAccepted?.index.captureFinishedAtUtc ??
            null,
        lastArchiveVerificationAtUtc: latestAccepted?.receipt.verifiedAtUtc ??
          null,
        lastBootDrill: await readBootDrillEvidence(
          ".private/reports/backblaze-machine-boot.json",
          now,
        ),
        ...assessBackblazeWatchdog(controllerState, gate, now, source),
        observedAtUtc: now.toISOString(),
        notificationSent: false,
      };
    }
  } catch (error) {
    b2Report = {
      status: "B2_WATCHDOG_CHECK_FAILED",
      healthy: false,
      observedAtUtc: now.toISOString(),
      notificationSent: false,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
  // Read only the small hourly report; this never restarts or recaptures a job.
  if (b2Report.healthy === true && !v2Dispatch) {
    try {
      const state = await readPrivateJson<ControllerState>(B2_STATE_PATH);
      if (state.job) {
        const observed = await realRemoteSeam(realRemoteRunner).root(
          "cat /var/lib/arch-vps-backup-progress/report.json",
        );
        if (observed.code === 0 && observed.stdout.length <= 64 * 1024) {
          const report = JSON.parse(observed.stdout);
          const job = state.job;
          const invocationId = job.verifierInvocationId ??
            job.workerInvocationId;
          const alarm = assessHourlyProgress(
            report,
            job.envelope.request.jobId,
            invocationId,
            now,
          );
          if (alarm) Object.assign(b2Report, alarm);
        }
      }
    } catch {
      // Existing live source/gate checks still own missing-source failures.
    }
  }
  await writePrivateJson(ORACLE_REPORT_PATH, oracleReport);
  await writePrivateJson(B2_REPORT_PATH, b2Report);
  // notifyMac keeps ONE last-status ledger: two separate per-report calls
  // alternate the last status every pass, so any existing alert makes two
  // identical hourly passes emit four notifications. One combined bounded
  // stable status carrying both assessment statuses yields one record per
  // transition; the single delivery outcome is shared by both preserved
  // individual reports and a delivery failure still stays visible on both.
  let delivery:
    | {
      notificationConfigured: boolean;
      notificationSent: boolean;
      pendingAlerts: number;
    }
    | undefined;
  try {
    delivery = await notifyMac({
      status: `B2:${String(b2Report.status)};ORACLE:${
        String(oracleReport.status)
      }`,
      healthy: oracleReport.healthy === true && b2Report.healthy === true,
      observedAtUtc: now.toISOString(),
    });
  } catch {
    for (const report of [b2Report, oracleReport]) {
      report.notificationError = "MAC_ALERT_RECORD_OR_DELIVERY_FAILED";
    }
  }
  if (delivery !== undefined) {
    for (const report of [b2Report, oracleReport]) {
      Object.assign(report, delivery);
    }
  }
  await writePrivateJson(ORACLE_REPORT_PATH, oracleReport);
  await writePrivateJson(B2_REPORT_PATH, b2Report);
  console.log(JSON.stringify({ oracle: oracleReport, b2: b2Report }));
  if (
    !oracleReport.healthy || !b2Report.healthy ||
    oracleReport.notificationError || b2Report.notificationError ||
    Number(oracleReport.pendingAlerts) > 0 ||
    Number(b2Report.pendingAlerts) > 0
  ) {
    Deno.exitCode = 1;
  }
}
if (import.meta.main) await main();
