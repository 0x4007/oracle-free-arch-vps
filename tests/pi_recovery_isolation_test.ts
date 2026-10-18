import { recoveryIsolationPlan } from "../scripts/pi-recovery-isolation.ts";
import type { MachineRestoreInput } from "../scripts/backblaze-machine-restore.ts";
import type { RecoveryIsolationInput } from "../scripts/pi-recovery-isolation.ts";

Deno.test("copied-root isolation refuses wrong target before reading either source version", () => {
  for (const version of [1, 2]) {
    let sourceRead = false;
    const input = {
      target: { targetId: "approved-target" },
      get index() {
        sourceRead = true;
        throw Error(`source${version}`);
      },
    } as unknown as MachineRestoreInput;
    const isolation = {
      preparation: { instanceId: "different-target" },
    } as RecoveryIsolationInput;
    let failure: unknown;
    try {
      recoveryIsolationPlan(input, isolation);
    } catch (error) {
      failure = error;
    }
    if (
      !(failure instanceof Error) ||
      !failure.message.includes("accepted replacement") || sourceRead
    ) throw Error("Isolation guard order changed");
  }
});
