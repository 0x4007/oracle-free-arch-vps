/** Operator diagnostics use fixed codes and text. Provider messages and
 * exception strings may contain credentials or private object identifiers. */
import { B2CredentialError } from "./backblaze-storage.ts";

const messages = {
  B2_BACKUP_ACCEPTANCE_UNKNOWN:
    "Accepted capture timestamps are future or contradictory. Inspect the private catalog receipts.",
  B2_BACKUP_ACTIVE_UNBOUND:
    "The live gate does not bind the active backup invocation. Reconcile the exact job and source gate.",
  B2_BACKUP_FAILED:
    "The backup did not complete. Inspect the exact job's private controller and source records.",
  B2_BACKUP_INCOMPLETE:
    "The reconciliation ended before completion. Inspect the exact job and its immutable deadline.",
  B2_BACKUP_GATE_HELD:
    "An unresolved source gate still holds backup custody. Inspect and reconcile the exact job before retrying.",
  B2_BACKUP_GATE_UNKNOWN:
    "The source gate could not be validated. Inspect the private gate and its exact source invocation.",
  B2_BACKUP_MISSING:
    "No accepted backup is available for the current window. Check the scheduled controller.",
  B2_BACKUP_OVERDEADLINE:
    "The backup exceeded its immutable request deadline. Reconcile its exact source custody.",
  B2_BACKUP_PENDING:
    "The backup awaits a controller transition or independent acceptance. Reconcile the same job.",
  B2_BACKUP_PROGRESS_UNKNOWN:
    "Useful work could not be proved for the current source invocation. Inspect the source progress report.",
  B2_BACKUP_SOURCE_MISMATCH:
    "The source status does not bind the exact job and invocation. Inspect the source and controller records.",
  B2_BACKUP_SOURCE_STALE:
    "The bound source status is stale. Check the exact running source unit before retrying.",
  B2_BACKUP_SOURCE_STATUS_MISSING:
    "The source status file is missing or unreadable. Check the bound source unit and its private records.",
  B2_BACKUP_SOURCE_UNBOUND:
    "The source status could not be tied to an observed unit invocation. Reconcile the exact source gate.",
  B2_BACKUP_SOURCE_UNKNOWN:
    "The exact source invocation could not be observed. Check source reachability and custody.",
  B2_BACKUP_STALE:
    "The backup heartbeat is stale. Check the exact source unit and its progress evidence.",
  B2_BACKUP_STEP_FAILED:
    "The backup controller could not finish a reconciliation step. Inspect the exact saved job and gate.",
  B2_CANCELLATION_BLOCKED:
    "Source cancellation or terminal settlement needs additional proof. Inspect the exact job and gate.",
  B2_CLEANUP_FAILED:
    "Backup scratch cleanup failed. Inspect the exact job's private cleanup record.",
  B2_CONTROLLER_CWD_INVALID:
    "Run the command from the deployed Pi controller directory.",
  B2_CONTROLLER_LOCK_UNPROVED:
    "The Pi controller lock could not be acquired or released. Check its private file and the active controller.",
  B2_CONTROLLER_STATE_UNREADABLE:
    "The private backup controller state could not be read or validated. Inspect its permissions and schema.",
  B2_CREDENTIAL_AUTH_UNPROVED:
    "Backblaze could not authorize the selected credential. Check the installed key and provider availability.",
  B2_CREDENTIAL_SCOPE_REJECTED:
    "The selected credential lacks the required Backblaze scope or capabilities. Check the runbook and credential installation.",
  B2_CREDENTIAL_SETTINGS_INVALID:
    "The private Backblaze writer settings are missing or invalid. Check the installed credential and bucket identity.",
  B2_BUCKET_IDENTITY_MISMATCH:
    "Backblaze did not prove the configured bucket identity. Check the private bucket name and ID before retrying.",
  B2_DEPLOYMENT_UNPROVED:
    "The installed Pi deployment identity or immutable release could not be verified. Check the deployment receipt and archive.",
  B2_JOB_ORPHANED:
    "The controller could not settle custody of the prior backup job. Inspect the exact job and source gate.",
  B2_PERIOD_MISSED:
    "No intact, independently accepted backup was captured during the current weekly period.",
  B2_PROGRESS_BEHIND_SCHEDULE:
    "The bound source is progressing too slowly to meet the backup deadline. Inspect its measured progress.",
  B2_PROGRESS_FAILED:
    "The source progress observer reported a backup failure. Inspect the exact invocation and its private records.",
  B2_PROGRESS_STALLED:
    "The bound source did not advance useful work. Check the exact source invocation and resource counters.",
  B2_PRUNE_FAILED:
    "The prior backup's cleanup plan did not complete. Check the private pruning evidence.",
  B2_REPORT_INVALID:
    "The private maintenance report could not be read or validated. Check its permissions and schema.",
  B2_REPORT_WRITE_FAILED:
    "The private report could not be written. Check the deployed controller directory and report permissions.",
  B2_RETENTION_APPROVAL_CHANGED:
    "The approved retention policy or catalog changed after planning. Reconcile the exact maintenance transaction before retrying.",
  B2_RETENTION_BACKUP_IN_PROGRESS:
    "A backup or another maintenance transaction owns source custody. Reconcile it before retrying this operation.",
  B2_RETENTION_CATALOG_BINDING_INVALID:
    "A required private catalog graph is missing or does not match its accepted receipt. Verify the catalog bindings before retrying.",
  B2_RETENTION_CONTROL_INVALID:
    "The private maintenance control or gate could not be validated. Inspect the exact transaction and custody evidence.",
  B2_RETENTION_CONTROL_WRITE_FAILED:
    "The controller could not persist maintenance state. Check private storage and the current source gate.",
  B2_RETENTION_CREDENTIAL_INVALID:
    "The explicit retention credential is unreadable, malformed or bound to the wrong bucket. Check the private key file.",
  B2_RETENTION_CUSTODY_UNPROVED:
    "The controller could not prove exact maintenance custody or settlement. Inspect the source gate and its bound unit.",
  B2_RETENTION_EXECUTION_IN_PROGRESS:
    "A deletion transaction is already in progress. Reconcile the original transaction before requesting plan-only maintenance.",
  B2_RETENTION_LAUNCH_UNPROVED:
    "The source did not confirm the exact maintenance launch. Inspect the existing gate and unit before retrying.",
  B2_RETENTION_ORACLE_CUSTODY_UNPROVED:
    "Oracle backup custody does not permit maintenance. Resolve the scheduled claim or active Oracle cycle first.",
  B2_BACKUP_ADMISSION_BLOCKED:
    "Oracle or source custody blocks a fresh backup. Reconcile the scheduled claim and source lock before retrying.",
  B2_RETENTION_PLAN_UNPROVED:
    "The exact private plan, approval or catalog-retirement evidence could not be verified. Inspect the saved transaction before retrying.",
  B2_RETENTION_POLICY_INVALID:
    "The private retention policy is unreadable or invalid. Check the documented settings and leave execution disabled.",
  B2_RETENTION_RECONCILIATION_PENDING:
    "The exact maintenance transaction is still running or settling. Reconcile it again to obtain a final report.",
  B2_RETENTION_SOURCE_PREFLIGHT_FAILED:
    "The controller could not prepare the source maintenance request. Check the deployment, source boot and private settings.",
  B2_RETENTION_SOURCE_SETTINGS_FAILED:
    "The exact source runtime settings or scratch cleanup proof could not be installed. Check the pinned deployment and source custody.",
  B2_RETENTION_STEP_FAILED:
    "The exact maintenance reconciliation did not complete. Inspect the private transaction and source state before retrying.",
  B2_RETENTION_STATUS_UNPROVED:
    "The source maintenance invocation or useful progress could not be proved. Inspect the exact gate and unit.",
  B2_SOURCE_UNREACHABLE:
    "The source did not answer its metadata-only observation. Check the host connection.",
  B2_STATE_UNKNOWN:
    "The backup state does not describe a recognized controller phase. Inspect the private controller record.",
  B2_TUNNEL_CLOSE_FAILED: "Task tunnel closure could not be proved",
  B2_WATCHDOG_CHECK_FAILED:
    "The watchdog could not read or validate backup state and source custody. Inspect the private controller and gate records.",
  CAP_EXCEEDED:
    "The proposed deletion exceeds maxDeleteFraction. Review the private plan and bucket totals before changing the policy.",
  DAMAGED_ACCEPTED_GENERATION:
    "An accepted generation has missing or mismatched cloud objects. Keep intact fallbacks and verify the named generations.",
  IDENTITY_CHANGED:
    "A candidate's exact identity or upload age no longer matches the approved plan. Review a fresh read-only inventory.",
  NO_ACCEPTED_GENERATION:
    "No accepted recovery point can be retained. Establish and verify an accepted backup before enabling deletion.",
  PLAN_CHANGED:
    "The exact plan no longer matches the approved inventory or catalog. Review a fresh read-only plan before retrying.",
  TRANSPORT_UNCERTAIN:
    "The provider outcome is uncertain. Reconcile the same transaction and journal before retrying.",
  LEGACY_CANCELLATION_UNCLASSIFIED:
    "The prior controller did not record a specific custody failure. Reconcile the existing exact job and source gate.",
  SOURCE_BOOT_CHANGED:
    "The source boot identity changed. Reconcile the exact gate against the current boot before retrying.",
  SOURCE_UNIT_ABSENT:
    "The exact source unit is absent and settlement is unproved. Check the gate and last invocation.",
  SOURCE_UNIT_FAILED:
    "The exact source unit failed. Inspect its private journal and custody before retrying.",
  SOURCE_INVOCATION_UNPROVED:
    "The controller could not prove the exact source invocation. Inspect the current unit and gate.",
  SOURCE_STATUS_FAILED:
    "The bound source status reports failure. Inspect the exact source unit's private records.",
  SOURCE_STATUS_CANCELLATION_BLOCKED:
    "The source reports blocked cancellation. Inspect and settle the exact source invocation.",
  SOURCE_TERMINAL_STATUS_UNPROVED:
    "The source unit exit and terminal status do not prove the same completed invocation.",
  SOURCE_TERMINAL_PROCESSES_UNSETTLED:
    "The exact source invocation still has unsettled process custody. Inspect its cgroup.",
  SOURCE_TERMINAL_RESULT_MISSING:
    "The source exited without the required terminal result or native custody proof. Inspect the exact unit journal.",
  SOURCE_TERMINAL_RESULT_HASH_MISMATCH:
    "The source result hash differs from the bound terminal status. Keep the gate and inspect the private artifacts.",
  SOURCE_TERMINAL_NATIVE_CUSTODY_MISMATCH:
    "The source result and native custody receipt disagree. Keep the exact gate and inspect both.",
  SOURCE_TERMINAL_RESULT_INVALID:
    "The source terminal receipt failed validation. Compare the exact request, result and native custody proof.",
  SOURCE_OBSERVATION_UNPROVED:
    "The bound source invocation could not be observed. Check host reachability and the exact unit.",
  SOURCE_CLEAR_PROOF_MISSING:
    "The exact source gate has no matching durable clear proof. Inspect its saved settlement artifacts.",
  SOURCE_EXACT_STOP_FAILED:
    "The controller did not prove the exact source unit stopped safely. Inspect its invocation and cgroup.",
  SOURCE_GATE_CLEAR_FAILED:
    "The settled source gate could not be cleared. Check the exact gate identity and private proof.",
  SOURCE_CANCELLATION_SAMPLE_INVALID:
    "A cancellation observation does not bind the exact source invocation. Check its custody evidence.",
  SOURCE_CANCELLATION_UNSETTLED:
    "The source cancellation has unsettled process or operation custody. Keep the existing gate.",
  BRIDGE_SETTINGS_UNPROVED:
    "The verifier bridge settings do not prove the exact invocation. Inspect the private job and bridge records.",
  BRIDGE_MANAGER_UNPROVED:
    "The bridge manager did not prove the exact keeper unit. Inspect its systemd identity and cgroup.",
  BRIDGE_STATUS_UNPROVED:
    "The bridge status could not prove the exact keeper state. Inspect its private status and source custody.",
  BRIDGE_BINDING_MISMATCH:
    "The bridge, keeper and verifier identities disagree. Compare their exact private receipts.",
  BRIDGE_SOURCE_UNPROVED:
    "The bridge could not verify the source invocation. Check the bound verifier and source status.",
  BRIDGE_SOCKET_UNPROVED:
    "The bridge did not prove its task-owned socket. Check the exact keeper and its private socket.",
  BRIDGE_READINESS_UNPROVED:
    "The bridge could not prove readiness for this verifier. Inspect the exact keeper and verifier.",
  BRIDGE_TERMINAL_CLOSE_UNPROVED:
    "The bridge did not prove a terminal close for the exact verifier. Compare the private result and bridge receipts.",
  BRIDGE_CANCELLATION_CLOSE_PENDING:
    "The bridge has not finished closing after cancellation. Reconcile the exact keeper again.",
  BRIDGE_TERMINAL_PROCESSES_UNPROVED:
    "The terminal bridge still has unproved process custody. Inspect the exact keeper cgroup.",
  BRIDGE_EXACT_STOP_UNPROVED:
    "The controller could not prove the exact bridge keeper stopped. Inspect its invocation and cgroup.",
  BRIDGE_KEEPER_CANCELLED:
    "The keeper cancelled before terminal verification was proved. Inspect the exact bridge and source receipts.",
  BRIDGE_KEEPER_LEASE_EXPIRED:
    "The keeper's useful-work lease expired. Inspect the exact verifier progress and bridge state.",
  BRIDGE_KEEPER_IDENTITY_CHANGED:
    "The keeper observed an invocation identity change. Keep the existing gate and reconcile the exact jobs.",
  BRIDGE_KEEPER_PROGRESS_REGRESSED:
    "The verifier's reported useful work regressed. Inspect the exact keeper and verifier counters.",
  BRIDGE_KEEPER_PROGRESS_WRONG_PHASE:
    "The keeper observed progress from an unexpected verifier phase. Compare the bound status receipts.",
  BRIDGE_KEEPER_TUNNEL_LOST:
    "The keeper lost its verifier tunnel. Inspect the exact bridge unit and source invocation.",
  BRIDGE_KEEPER_OVERLAPPING_OPERATION:
    "The keeper observed overlapping operations. Settle the exact bridge and source custody.",
  BRIDGE_KEEPER_OBSERVATION_OR_NOTIFICATION_UNPROVED:
    "The keeper could not prove its observation or notification. Inspect the exact private bridge status.",
  SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE:
    "Scheduled Oracle claim custody is undecidable. Inspect its evidence under the shared controller lock.",
  SCHEDULED_CLAIM_CUSTODY_OVERDUE:
    "Scheduled Oracle claim custody remains overdue. Inspect the exact live owner, gates and source lock.",
  SCHEDULED_CLAIM_OWNER_LIVE:
    "The scheduled Oracle claim still has a live owner. Wait for that invocation to settle.",
  SCHEDULE_CLAIM_RECONCILIATION_REQUIRED:
    "The scheduled claim needs reconciliation before a new backup can start.",
} as const;

export type BackblazeReportReason = keyof typeof messages;

export interface BackblazeReportReasonFields {
  reason?: BackblazeReportReason;
  message?: string;
  reportWriteError?: "B2_REPORT_WRITE_FAILED";
}

export function backblazeReportReason(
  reason: unknown,
  fallback: BackblazeReportReason,
): BackblazeReportReason {
  return typeof reason === "string" && Object.hasOwn(messages, reason)
    ? reason as BackblazeReportReason
    : fallback;
}

export function backblazeReportExplanation(reason: BackblazeReportReason) {
  return { reason, message: messages[reason] };
}

export class BackblazeReportError extends Error {
  constructor(public readonly reason: BackblazeReportReason) {
    super(messages[reason]);
  }
}

export function reasonForBackblazeError(
  error: unknown,
  fallback: BackblazeReportReason,
): BackblazeReportReason {
  return error instanceof BackblazeReportError ||
      error instanceof B2CredentialError
    ? backblazeReportReason(error.reason, fallback)
    : fallback;
}

export async function withBackblazeReportReason<T>(
  fallback: BackblazeReportReason,
  operation: () => T | Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw new BackblazeReportError(reasonForBackblazeError(error, fallback));
  }
}

export function addBackblazeFailureReason<
  T extends {
    status: string;
    healthy: boolean;
  },
>(report: T, fallback: BackblazeReportReason): T & BackblazeReportReasonFields {
  if (report.healthy) return report;
  return {
    ...report,
    ...backblazeReportExplanation(
      backblazeReportReason(report.status.split(":", 1)[0], fallback),
    ),
  };
}
