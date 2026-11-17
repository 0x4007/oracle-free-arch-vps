function assertEquals(
  actual: unknown,
  expected: unknown,
  message?: string,
): void {
  if (actual !== expected) {
    throw new Error(
      message ?? `Expected ${String(expected)}, got ${String(actual)}`,
    );
  }
}

import { backupGatePresent } from "../scripts/backup-runtime.ts";

const root = new URL("../", import.meta.url);

async function text(path: string): Promise<string> {
  return await Deno.readTextFile(new URL(path, root));
}

Deno.test("backup services capture safepi output and keep pipe status", async () => {
  for (
    const path of [
      "config/weekly-backup.service",
      "config/backblaze-file-backup.service",
      "config/weekly-backup-watchdog.service",
      "config/weekly-audit.service",
    ]
  ) {
    const unit = await text(path);
    assertEquals(unit.includes("set -o pipefail;"), true, path);
    assertEquals(unit.includes(" 2>&1 | cat'"), true, path);
  }
});

Deno.test("weekly scheduler skips at the unit boundary while a backup gate exists", async () => {
  const unit = await text("config/weekly-backup.service");
  assertEquals(
    unit.includes(
      "ConditionPathExists=!%h/ops/weekly-backup-controller/.private/backup-controller-gate.json",
    ),
    true,
  );
});

Deno.test("scheduled services route startup failures through the same scoped alert stream", async () => {
  const { tasks } = JSON.parse(await text("deno.json"));
  assertEquals(
    tasks["backup:scheduled"].endsWith(
      "--allow-net=docs.oracle.com,ntfy.pavlovcik.com scripts/alerting-backup-scheduled.ts",
    ),
    true,
  );
  assertEquals(
    tasks["backup:watchdog"].endsWith(
      "--allow-run=ssh --allow-net=ntfy.pavlovcik.com scripts/backup-watchdog.ts",
    ),
    true,
  );
  const backblaze = await text("config/backblaze-file-backup.service");
  const oracle = await text("config/weekly-backup.service");
  assertEquals(
    backblaze.includes("scripts/scheduled-backblaze-file-backup.ts"),
    true,
  );
  for (
    const [unit, stream] of [[oracle, "oracle-scheduled"], [
      backblaze,
      "backblaze-scheduled",
    ]]
  ) {
    assertEquals(unit.includes("ExecStopPost=-/bin/bash"), true);
    assertEquals(unit.includes('"$$SERVICE_RESULT" == success'), true);
    assertEquals(
      unit.includes(
        `--allow-net=ntfy.pavlovcik.com scripts/backup-mac-alert.ts ${stream}`,
      ),
      true,
    );
  }
});

Deno.test("backup gate presence blocks both current and future schemas", async () => {
  const dir = await Deno.makeTempDir({ prefix: "backup-gate-presence-" });
  try {
    await Deno.mkdir(`${dir}/.private`, { mode: 0o700 });
    const path = `${dir}/.private/backup-controller-gate.json`;
    assertEquals(await backupGatePresent(path), false);
    await Deno.writeTextFile(path, JSON.stringify({ format: "backup-v2" }), {
      mode: 0o600,
    });
    assertEquals(await backupGatePresent(path), true);
    await Deno.remove(path);
    assertEquals(await backupGatePresent(path), false);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
