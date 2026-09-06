import { backupGuestControl, shellQuote } from "../scripts/backup-guest.ts";

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function fixture() {
  const commands: string[] = [];
  let inactive = false;
  const control = backupGuestControl({
    host: "codex@vps.pavlovcik.com",
    rootUuid: "a".repeat(36),
    stagingUuid: "b".repeat(36),
    activityScriptPath:
      "/home/codex/ops/weekly-backup-controller/backup-guest-activity.ts",
  }, (_command, args) => {
    const command = args.at(-1)!;
    commands.push(command);
    let stdout = "";
    if (command.includes("docker inspect")) {
      stdout = ["guacamole-trial-guacamole-1", "guacamole-trial-guacd-1"]
        .map((name, i) =>
          `"${String(i).repeat(64)}" "/${name}" true 0 "unless-stopped"`
        ).join("\n");
    } else if (command.includes("deno run")) {
      stdout = JSON.stringify({ loadedThreads: 7 });
    } else if (command.includes("/proc/sys/kernel/random/boot_id")) {
      stdout = "a".repeat(36);
    } else if (command.includes("show -p ActiveState")) {
      stdout = `ActiveState=${inactive ? "inactive" : "active"}\nInvocationID=${
        "b".repeat(32)
      }`;
    } else if (command.includes("is-active") && inactive) {
      return Promise.resolve({ code: 3, stdout: "inactive", stderr: "" });
    }
    return Promise.resolve({ code: 0, stdout, stderr: "" });
  });
  return { control, commands, fail: () => inactive = true };
}
async function refuses(run: () => Promise<unknown>) {
  let rejected = false;
  try {
    await run();
  } catch {
    rejected = true;
  }
  assert(rejected);
}

Deno.test("online guest acceptance permits active threads and has no mutation surface", async () => {
  const f = fixture();
  await f.control.acceptSource();
  const proof = await f.control.observeSource();
  assert(Object.keys(proof.serviceInvocations).length === 7);
  assert(Object.keys(f.control).sort().join() === "acceptSource,observeSource");
  assert(
    f.commands.every((command) =>
      !/\b(stop|start|restart|reboot|kill|fsfreeze)\b/.test(command)
    ),
  );
});

Deno.test("online acceptance reports an inactive service without repairing it", async () => {
  const f = fixture();
  f.fail();
  await refuses(() => f.control.acceptSource());
  await refuses(() => f.control.observeSource());
  assert(f.commands.every((command) => !/\b(start|restart)\b/.test(command)));
});

Deno.test("shell quoting retains literal metacharacters", () => {
  assert(shellQuote("a'b$(x)") === "'a'\\''b$(x)'");
});

Deno.test("SSH transport failure is retryable but a failed remote assertion is blocked", async () => {
  const { RetryableObservationError } = await import(
    "../scripts/online-backup-contract.ts"
  );
  for (const code of [255, 1]) {
    const control = backupGuestControl(
      {
        host: "codex@vps.pavlovcik.com",
        rootUuid: "a".repeat(36),
        stagingUuid: "b".repeat(36),
        activityScriptPath: "/home/codex/ops/backup-guest-activity.ts",
      },
      () => Promise.resolve({ code, stdout: "", stderr: "private diagnostic" }),
    );
    for (const observe of [control.observeSource, control.acceptSource]) {
      let failure: unknown;
      try {
        await observe();
      } catch (error) {
        failure = error;
      }
      assert(failure instanceof Error);
      assert((failure instanceof RetryableObservationError) === (code === 255));
      assert(!failure.message.includes("private diagnostic"));
    }
  }
});
