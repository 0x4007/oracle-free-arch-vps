/** Shared evidence for the online backup cutover. These records never authorize
 * a resource operation and do not upgrade archive checks into a boot drill.
 */
export type OnlineBackupPhase =
  | "planned"
  | "backing-up"
  | "pair-available"
  | "source-accepted"
  | "retiring"
  | "complete"
  | "failed";

export interface OnlineCaptureIdentity {
  kind: "oci-volume-group";
  volumeGroupId: string;
  volumeGroupBackupId: string;
  captureTimeUtc: string;
  bootBackupId: string;
  rootBackupId: string;
  consistency: "crash-consistent";
}

export interface SourceContinuityEvidence {
  bootId: string;
  serviceInvocations: Record<string, string>;
  observedAtUtc: string;
}

export interface MachineRestoreProof {
  generation: string;
  indexSha256: string;
  targetIdentity: string;
  extractedAtUtc: string;
  bootedAtUtc?: string;
  status: "FILESYSTEMS_REBUILT" | "RESTORE_DRILL_PROVED";
}

/** A failed operation retains its transaction identity and resumable phase.
 * Unknown identity is blocked; transport failures are retried only after fresh
 * evidence. Exhausting a burst cools down, never authorizes a new capture.
 */
export interface OnlineBackupRetry {
  disposition: "retryable" | "blocked";
  resumePhase: Exclude<OnlineBackupPhase, "failed" | "complete">;
  attempts: number;
  firstFailureAtUtc: string;
  nextAttemptAtUtc: string;
  deadlineAtUtc: string;
}

export const ONLINE_RETRY_POLICY = {
  initialDelayMs: 15 * 60_000,
  maximumDelayMs: 60 * 60_000,
  burstDeadlineMs: 4 * 60 * 60_000,
  maximumAttempts: 6,
  cooldownMs: 24 * 60 * 60_000,
} as const;

/** Only transport/read boundaries may produce this error. Failed policy or
 * identity checks must retain their ordinary error and block mutation. */
export class RetryableObservationError extends Error {}
