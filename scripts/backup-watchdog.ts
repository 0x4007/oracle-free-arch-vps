import {
  assessBackupWatchdog,
  type BackupSchedule,
  type BackupWatchdogState,
  validateSchedule,
} from "./backup-schedule.ts";
import { readPrivateJson, writePrivateJson } from "./oci.ts";
import {
  type BackupAlertDelivery,
  type BackupAlertObservation,
  type BackupAlertOutcome,
  backupAlertReason,
  backupRetentionAlert,
  notifyBackupAlerts,
  outstandingBackblazeDamageAlert,
} from "./backup-mac-alert.ts";
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
  realPrivateSeam,
  realRemoteRunner,
  realRemoteSeam,
  STALE_AFTER_MS,
  validateControllerState,
  type WatchdogAssessment,
} from "./backblaze-file-backup.ts";
import {
  acceptedBackupRuntimeCapture,
  type BackupV2ControllerObservation,
  type BackupV2ControllerState,
  normalizeBackupV2ControllerState,
  observeBackupV2Source,
  readBackupRuntimeGate,
  readBackupV2RetentionControl,
  validateBackupV2ControllerState,
} from "./backup-v2-controller.ts";
import {
  type BackupV2Gate,
  type BackupV2RequestEnvelope,
  validateBackupV2Gate,
  validateBackupV2RequestEnvelope,
  validateBackupV2Status,
} from "./backup-v2-runtime-contract.ts";

import {
  B2_CATALOG_DAMAGED_ALERT,
  type BackblazeMaintenanceResult,
  readBackblazeMaintenance,
} from "./backup-v2-retention-report.ts";
import {
  addBackblazeFailureReason,
  backblazeReportExplanation,
} from "./backup-v2-report-reasons.ts";

export { acceptedBackupRuntimeCapture };

export const B2_REPORT_PATH = ".private/reports/backblaze-file-backup.json";
export const ORACLE_REPORT_PATH = ".private/reports/backup-watchdog.json";
export const B2_STATE_PATH = ".private/file-backup/controller.json";

export function assessBackupV2Watchdog(
  stateInput: unknown,
  gateInput: unknown | null,
  now: Date,
  source?: BackupV2ControllerObservation,
  progress?: unknown,
  damaged: readonly string[] = [],
): WatchdogAssessment {
  const report = assessBackupV2BackupHealth(
    stateInput,
    gateInput,
    now,
    source,
    progress,
    damaged,
  );
  return report.reason
    ? report
    : addBackblazeFailureReason(report, "B2_WATCHDOG_CHECK_FAILED");
}

function assessBackupV2BackupHealth(
  stateInput: unknown,
  gateInput: unknown | null,
  now: Date,
  source: BackupV2ControllerObservation | undefined,
  progress: unknown,
  damaged: readonly string[],
): WatchdogAssessment {
  const state = validateBackupV2ControllerState(stateInput), job = state.job;
  let gate: BackupV2Gate | null;
  try {
    gate = gateInput === null ? null : validateBackupV2Gate(gateInput);
    if (gate?.kind === "prune") gate = null;
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
      ...backblazeReportExplanation(
        job?.cancellationBlockedReason ?? "B2_CANCELLATION_BLOCKED",
      ),
    };
  }
  const accepted = acceptedBackupRuntimeCapture(state, now, damaged);
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
    if (accepted.current) {
      return { status: `B2_BACKUP_CURRENT:${acceptedJob}`, healthy: true };
    }
    if (damaged.length && acceptedBackupRuntimeCapture(state, now).current) {
      return {
        status: B2_CATALOG_DAMAGED_ALERT,
        healthy: false,
        ...backblazeReportExplanation("DAMAGED_ACCEPTED_GENERATION"),
      };
    }
    return { status: `B2_PERIOD_MISSED:${accepted.periodKey}`, healthy: false };
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
    return {
      status: `B2_BACKUP_${status.phase}:${jobId}`,
      healthy: false,
      ...backblazeReportExplanation(
        status.phase === "FAILED"
          ? "SOURCE_STATUS_FAILED"
          : "SOURCE_STATUS_CANCELLATION_BLOCKED",
      ),
    };
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

/** Project the existing core retention control; backup acceptance alone is
 * never retention/cleanup completion. This observer never advances its phase. */
export function assessBackupV2Retention(
  envelopeInput: BackupV2RequestEnvelope,
  liveGate: BackupV2Gate | null,
  now: Date,
  value: unknown,
  source?: BackupV2ControllerObservation,
): WatchdogAssessment {
  let stage: "PLAN" | "EXECUTE", phase: string, gate: BackupV2Gate;
  const envelope = validateBackupV2RequestEnvelope(envelopeInput);
  let control: Record<string, unknown>;
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw Error("Missing retention control");
    }
    control = value as Record<string, unknown>;
    const input = control.input as Record<string, unknown>;
    if (
      control.schemaVersion !== 2 && control.schemaVersion !== 3 ||
      control.format !== "backup-v2-retention-controller" || !input ||
      input.schemaVersion !== 2 || input.format !== "backup-v2-prune" ||
      !["PLAN", "EXECUTE"].includes(String(input.stage)) ||
      ![
        "REQUESTED",
        "RUNNING",
        "SETTLED",
        "COMPLETE",
        "PARTIAL",
        "CANCELLATION_BLOCKED",
      ].includes(String(control.phase))
    ) throw Error("Invalid retention control");
    gate = validateBackupV2Gate(control.gate);
    const original = validateBackupV2Gate(input.gate);
    if (
      gate.kind !== "prune" || original.kind !== "prune" ||
      gate.envelope.requestSha256 !== envelope.requestSha256 ||
      original.envelope.requestSha256 !== envelope.requestSha256 ||
      original.gateId !== gate.gateId ||
      original.sourceBootId !== gate.sourceBootId
    ) throw Error("Retention identity differs");
    if (
      liveGate &&
      (liveGate.kind !== "prune" || liveGate.gateId !== gate.gateId ||
        liveGate.sourceBootId !== gate.sourceBootId ||
        liveGate.envelope.requestSha256 !== envelope.requestSha256)
    ) throw Error("Live prune gate differs");
    stage = input.stage as "PLAN" | "EXECUTE";
    phase = liveGate?.state === "CANCELLATION_BLOCKED" ||
        gate.state === "CANCELLATION_BLOCKED"
      ? "CANCELLATION_BLOCKED"
      : String(control.phase);
  } catch {
    return {
      status: "B2_RETENTION_UNKNOWN",
      healthy: false,
      ...backblazeReportExplanation("B2_RETENTION_CONTROL_INVALID"),
    };
  }
  let healthy = false;
  if (phase === "COMPLETE") {
    const result = control.result as Record<string, unknown> | null;
    try {
      const completed = validateBackupV2Gate(result?.gate),
        input = control.input as Record<string, unknown>;
      healthy = stage === "EXECUTE" && liveGate === null &&
        result?.schemaVersion === 2 &&
        result.format === "backup-v2-prune-result" &&
        result.stage === "EXECUTE" && result.state === "COMPLETE" &&
        result.transactionId === input.transactionId &&
        /^[a-f0-9]{64}$/.test(String(result.nativeCustodySha256)) &&
        completed.kind === "prune" && completed.gateId === gate.gateId &&
        completed.sourceBootId === gate.sourceBootId &&
        completed.envelope.requestSha256 === envelope.requestSha256;
    } catch { /* Incomplete cleanup evidence remains unhealthy. */ }
  } else if (
    phase === "RUNNING" && liveGate?.state === "ACTIVE" &&
    source?.unit === "RUNNING" && source.sourceBootId === gate.sourceBootId
  ) {
    try {
      const status = validateBackupV2Status(source.status, liveGate);
      validateBackupV2Status({ ...status, custody: source.identity }, liveGate);
      if (status.phase === "CANCELLATION_BLOCKED") {
        phase = "CANCELLATION_BLOCKED";
      } else if (status.phase === "FAILED") phase = "PARTIAL";
      else {healthy = status.phase === "PRUNING" &&
          Date.parse(status.updatedAtUtc) <= now.getTime() &&
          now.getTime() - Date.parse(status.updatedAtUtc) <= 60_000 &&
          Math.max(
              status.lease.usefulProgressExpiresAtMs,
              status.lease.retryEpisode?.expiresAtMs ?? 0,
              status.lease.transferEpisode?.expiresAtMs ?? 0,
            ) > status.lease.observedMonotonicMs;}
    } catch { /* Unknown source evidence never proves retention progress. */ }
  }
  return {
    status: `B2_RETENTION_${stage}_${phase}`,
    healthy,
    ...(phase === "COMPLETE" && healthy ? {} : backblazeReportExplanation(
      phase === "CANCELLATION_BLOCKED"
        ? "B2_RETENTION_CUSTODY_UNPROVED"
        : healthy || phase === "REQUESTED" || phase === "SETTLED"
        ? "B2_RETENTION_RECONCILIATION_PENDING"
        : "B2_RETENTION_STATUS_UNPROVED",
    )),
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

export function watchdogAlertOutcome(
  report: Record<string, unknown>,
  fallback: "WATCHDOG_CHECK_FAILED" | "B2_WATCHDOG_CHECK_FAILED",
): BackupAlertOutcome {
  const status = typeof report.status === "string"
    ? report.status.split(":", 1)[0]
    : "";
  if (status === "B2_BACKUP_PENDING") return "DEFERRED";
  if (report.healthy === true) {
    if (
      [
        "BACKUP_IN_PROGRESS",
        "B2_BACKUP_ACTIVE",
        "B2_BACKUP_IDLE",
        "B2_BACKUP_RETIRING",
      ].includes(status) ||
      (status.startsWith("B2_RETENTION_") && !status.endsWith("_COMPLETE"))
    ) return "DEFERRED";
    return "HEALTHY";
  }
  if (status === B2_CATALOG_DAMAGED_ALERT) return "B2_BACKUP_FAILED";
  if (status.startsWith("B2_RETENTION_")) return "B2_RETENTION_BLOCKED";
  if (status === "B2_BACKUP_CANCELLATION_BLOCKED") {
    return "B2_CANCELLATION_BLOCKED";
  }
  return backupAlertReason(status, fallback);
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
  const { reports: maintenance, damaged } = await readBackblazeMaintenance(
    realPrivateSeam(),
    new Date(),
  );
  let b2Report: Record<string, unknown>;
  let v2Dispatch = false;
  try {
    let rawState: unknown;
    try {
      rawState = await readPrivateJson(B2_STATE_PATH);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    const runtimeGate = await readBackupRuntimeGate();
    const version = (rawState as { schemaVersion?: unknown } | undefined)
      ?.schemaVersion;
    const original = rawState as
      | ControllerState
      | BackupV2ControllerState
      | undefined;
    const legacyActive = original?.schemaVersion === 1 && original.job &&
      !["COMPLETE", "FAILED"].includes(original.job.phase);
    v2Dispatch = version === 2 ||
      !legacyActive &&
        (runtimeGate?.schemaVersion === 2 && runtimeGate.kind === "prune" ||
          damaged.length > 0);
    if (v2Dispatch) {
      const state = normalizeBackupV2ControllerState(
        original ?? { schemaVersion: 1, catalog: [] },
      );
      const gate = runtimeGate;
      let source: BackupV2ControllerObservation | undefined,
        progress: unknown,
        retention: unknown,
        catalogMaintenance = false;
      if (gate?.schemaVersion === 2 && gate.kind === "prune") {
        try {
          const privateIO = realPrivateSeam();
          for (const verifyCatalogOnly of [false, true]) {
            const control = await readBackupV2RetentionControl(
              privateIO,
              verifyCatalogOnly,
            );
            if (control?.gate.gateId === gate.gateId) {
              retention = control;
              catalogMaintenance = verifyCatalogOnly;
              break;
            }
          }
          if (retention === undefined && state.job?.phase === "COMPLETE") {
            retention = await readPrivateJson(
              `.private/file-backup/retention/${state.job.settings.envelope.request.jobId}.json`,
            );
          }
        } catch {
          retention = null;
        }
      }
      if (gate?.schemaVersion === 2 && (state.job || gate.kind === "prune")) {
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
      const observedNow = new Date();
      if (gate?.schemaVersion === 2 && gate.kind === "prune") {
        const key = catalogMaintenance ? "catalog" : "retention";
        const assessed = assessBackupV2Retention(
          gate.envelope,
          gate,
          observedNow,
          retention,
          source,
        );
        const live: BackblazeMaintenanceResult = {
          ...assessed,
          observedAtUtc: observedNow.toISOString(),
        };
        if (
          assessed.healthy || !maintenance[key] || maintenance[key]?.healthy
        ) maintenance[key] = live;
      }
      const accepted = acceptedBackupRuntimeCapture(
        state,
        observedNow,
        damaged,
      );
      b2Report = {
        lastSuccessfulCaptureAtUtc: accepted.latest?.captureFinishedAtUtc ??
          null,
        lastArchiveVerificationAtUtc: accepted.latest?.verifiedAtUtc ?? null,
        captureStartedAtUtc: accepted.latest?.captureStartedAtUtc ?? null,
        lastBootDrill: await readBootDrillEvidence(
          ".private/reports/backblaze-machine-boot.json",
          observedNow,
        ),
        ...assessBackupV2Watchdog(
          state,
          gate,
          observedNow,
          source,
          progress,
          damaged,
        ),
        observedAtUtc: observedNow.toISOString(),
        notificationSent: false,
      };
    } else {
      let controllerState: ControllerState | undefined;
      if (rawState !== undefined) {
        controllerState = validateControllerState(rawState);
      }
      if (runtimeGate?.schemaVersion === 2) {
        throw Error("Backup gate and controller versions differ");
      }
      const gate = runtimeGate;
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
      const { status, healthy } = assessBackblazeWatchdog(
        controllerState,
        gate,
        now,
        source,
      );
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
        ...addBackblazeFailureReason(
          { status, healthy },
          "B2_WATCHDOG_CHECK_FAILED",
        ),
        observedAtUtc: now.toISOString(),
        notificationSent: false,
      };
    }
  } catch {
    b2Report = {
      status: "B2_WATCHDOG_CHECK_FAILED",
      healthy: false,
      observedAtUtc: now.toISOString(),
      notificationSent: false,
      ...backblazeReportExplanation("B2_WATCHDOG_CHECK_FAILED"),
    };
  }
  if (Object.keys(maintenance).length) b2Report.maintenance = maintenance;
  if (damaged.length) b2Report.damagedCaptureIds = damaged;
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
          if (alarm) {
            Object.assign(
              b2Report,
              addBackblazeFailureReason(
                alarm as { status: string; healthy: boolean },
                "B2_WATCHDOG_CHECK_FAILED",
              ),
            );
          }
        }
      }
    } catch {
      // Existing live source/gate checks still own missing-source failures.
    }
  }
  let delivery: BackupAlertDelivery | undefined;
  try {
    const observations: BackupAlertObservation[] = [
      {
        stream: "oracle-watchdog",
        outcome: watchdogAlertOutcome(oracleReport, "WATCHDOG_CHECK_FAILED"),
      },
      {
        stream: "backblaze-watchdog",
        outcome: watchdogAlertOutcome(b2Report, "B2_WATCHDOG_CHECK_FAILED"),
      },
    ];
    for (const kind of ["retention", "catalog"] as const) {
      const report = maintenance[kind];
      if (!report) continue;
      const alert = backupRetentionAlert(
        report,
        kind === "catalog"
          ? "backblaze-catalog-verification"
          : "backblaze-retention",
      );
      if (alert) observations.push(alert);
    }
    const unreportedDamage = outstandingBackblazeDamageAlert(
      damaged.filter((capture) =>
        !observations.some((observation) =>
          observation.retention?.summary.damagedCaptureIds.includes(capture)
        )
      ),
    );
    if (unreportedDamage) observations.push(unreportedDamage);
    else if (!damaged.length) {
      observations.push({
        stream: "backblaze-catalog-integrity",
        outcome: "HEALTHY",
      });
    }
    delivery = await notifyBackupAlerts(observations);
  } catch {
    for (const report of [b2Report, oracleReport]) {
      report.notificationError = "BACKUP_ALERT_RECORD_FAILED";
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
