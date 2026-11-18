/** Explicit operator entry point for an inventory and private plan only. */
import { runBackblazePiController } from "./backblaze-file-backup.ts";

if (import.meta.main) {
  try {
    const report = await runBackblazePiController("plan");
    console.log(JSON.stringify(report));
    if (!report.healthy) Deno.exitCode = 1;
  } catch {
    console.error("B2_RETENTION_PLAN_REFUSED");
    Deno.exitCode = 1;
  }
}
