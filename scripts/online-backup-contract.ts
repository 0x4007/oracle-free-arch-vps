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
