import { recoverBlockedBackupV2Verifier } from "../../scripts/backup-v2-controller.ts";

const [jobId, gateId, requestSha256] = Deno.args;
try {
  if (Deno.args.length !== 3) {
    throw new Error("Expected exact recovery binding");
  }
  const report = await recoverBlockedBackupV2Verifier({
    jobId,
    gateId,
    requestSha256,
  });
  console.log(JSON.stringify({
    status: report.status,
    healthy: report.healthy,
    detail: report.detail,
  }));
  if (report.status !== "COMPLETE") Deno.exitCode = 1;
} catch {
  console.error("B2_EXACT_VERIFIER_RECOVERY_REFUSED");
  Deno.exitCode = 1;
}
