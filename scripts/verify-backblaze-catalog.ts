/** Read-only operator verification of the exact accepted cloud versions. */
import {
  backblazeOperatorExitCode,
  runBackblazePiController,
} from "./backblaze-file-backup.ts";

if (import.meta.main) {
  const report = await runBackblazePiController("verify-catalog");
  console.log(JSON.stringify(report));
  Deno.exitCode = backblazeOperatorExitCode(report, "verify-catalog");
}
