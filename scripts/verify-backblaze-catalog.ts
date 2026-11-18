/** Read-only operator verification of the exact accepted cloud versions. */
import { runBackblazePiController } from "./backblaze-file-backup.ts";

if (import.meta.main) {
  try {
    const report = await runBackblazePiController("verify-catalog");
    console.log(JSON.stringify(report));
    if (report.status !== "B2_RETENTION_CATALOG_VERIFIED") Deno.exitCode = 1;
  } catch {
    console.error("B2_RETENTION_CATALOG_VERIFICATION_REFUSED");
    Deno.exitCode = 1;
  }
}
