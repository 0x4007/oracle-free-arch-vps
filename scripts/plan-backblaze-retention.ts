/** Explicit operator entry point for an inventory and private plan only. */
import {
  backblazeOperatorExitCode,
  runBackblazePiController,
} from "./backblaze-file-backup.ts";

if (import.meta.main) {
  const report = await runBackblazePiController("plan");
  console.log(JSON.stringify(report));
  Deno.exitCode = backblazeOperatorExitCode(report, "plan");
}
