/** One explicit reconstruction authorization; provisioning alone never grants it. */
import { createHash } from "node:crypto";
import {
  assertReplacementApproval,
  type ReplacementConfig,
  replacementPlanDigest,
} from "./pi-machine-recovery.ts";

export const UNATTENDED_RECOVERY_OPERATION =
  "restore the selected independent generation on the bound replacement without further routine approvals, including console trust, RAM rescue, exact disk preparation, Pi key-agent forwarding, copied-root isolation and restored boot acceptance; exclude production and stop on uncertain writes";
export interface UnattendedRecoveryAuthorization {
  planSha256: string;
  indexSha256: string;
  sourceRevision: string;
  approvedAtUtc: string;
  expiresAtUtc: string;
  exactOperation: typeof UNATTENDED_RECOVERY_OPERATION;
}
export interface UnattendedRecoveryConfig extends ReplacementConfig {
  consolePublicKey?: string;
  unattended?: UnattendedRecoveryAuthorization;
}
const hash = (v: unknown) =>
  createHash("sha256").update(JSON.stringify(v)).digest("hex");
export function unattendedRecoveryPlan(
  config: UnattendedRecoveryConfig,
  indexSha256: string,
  sourceRevision: string,
  expiresAtUtc: string,
) {
  if (
    !/^[a-f0-9]{64}$/.test(indexSha256) ||
    !/^[a-f0-9]{40}$/.test(sourceRevision) || !config.consolePublicKey ||
    !Number.isFinite(Date.parse(expiresAtUtc))
  ) {
    throw Error("Unattended reconstruction binding is incomplete");
  }
  const body = {
    replacementPlanSha256: replacementPlanDigest(config),
    indexSha256,
    sourceRevision,
    consolePublicKeySha256: hash(config.consolePublicKey),
    expiresAtUtc,
    operation: UNATTENDED_RECOVERY_OPERATION,
  };
  return { ...body, planSha256: hash(body) };
}
export function assertUnattendedRecoveryAuthority(
  config: UnattendedRecoveryConfig,
  indexSha256: string,
  sourceRevision: string,
  now = Date.now(),
): UnattendedRecoveryAuthorization {
  assertReplacementApproval(config, replacementPlanDigest(config), now);
  const a = config.unattended;
  if (!a) throw Error("Explicit unattended reconstruction authority is absent");
  const approved = Date.parse(a.approvedAtUtc),
    expires = Date.parse(a.expiresAtUtc);
  if (
    a.exactOperation !== UNATTENDED_RECOVERY_OPERATION ||
    a.indexSha256 !== indexSha256 || a.sourceRevision !== sourceRevision ||
    !Number.isFinite(approved) || !Number.isFinite(expires) || approved > now ||
    expires <= now || expires - approved > 4 * 3600000 || expires <= approved ||
    (config.trial && expires > Date.parse(config.trial.expiresAtUtc)) ||
    a.planSha256 !==
      unattendedRecoveryPlan(
        config,
        indexSha256,
        sourceRevision,
        a.expiresAtUtc,
      ).planSha256
  ) {
    throw Error("Unattended reconstruction authority expired or changed");
  }
  return a;
}

/** Plans originate in the existing guarded stage implementations, never reports
 * supplied by an operator. Persist the derived receipt before its use; do not
 * refresh its timestamp on a retry. Existing stage validators remain mandatory. */
export function deriveRecoveryStageApproval<T extends string>(
  plan: { planSha256: string; operation: T },
  authority: UnattendedRecoveryAuthorization,
  now = Date.now(),
) {
  if (
    !/^[a-f0-9]{64}$/.test(plan.planSha256) || !plan.operation ||
    !Number.isFinite(now) ||
    !Number.isFinite(Date.parse(authority.approvedAtUtc)) ||
    !Number.isFinite(Date.parse(authority.expiresAtUtc)) ||
    now < Date.parse(authority.approvedAtUtc) ||
    now >= Date.parse(authority.expiresAtUtc)
  ) {
    throw Error("Stage is outside unattended reconstruction authority");
  }
  return {
    planSha256: plan.planSha256,
    exactOperation: plan.operation,
    approvedAtUtc: new Date(now).toISOString(),
  };
}
