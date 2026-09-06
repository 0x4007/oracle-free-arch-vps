import {
  assertBackblazeLaunchAllowed,
  type BackupControllerGate,
  validateGate,
} from "../scripts/backblaze-controller-contract.ts";
import {
  markOrphaned,
  writeActiveGate,
} from "../scripts/backblaze-controller-gate.ts";
import { withBackupLock } from "../scripts/backup-lock.ts";
import { main as runtimeMain } from "../scripts/backup-runtime.ts";
import { main as restoreMain } from "../scripts/oci-restore.ts";
import type { CommandRunner } from "../scripts/oci.ts";

const UUID = "681c4067-aec2-45d5-9afb-77ee530e3a97";

function assert(value: unknown, message?: string): asserts value {
  if (!value) throw new Error(message ?? "Assertion failed");
}

async function assertThrowsAsync(
  run: () => Promise<unknown>,
  messageIncludes?: string,
): Promise<string> {
  try {
    await run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert(
      !messageIncludes || message.includes(messageIncludes),
      `Expected error to include ${messageIncludes}, got ${message}`,
    );
    return message;
  }
  throw new Error("Expected the call to throw");
}

function assertThrowsSync(
  run: () => unknown,
  messageIncludes?: string,
): string {
  try {
    run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert(
      !messageIncludes || message.includes(messageIncludes),
      `Expected error to include ${messageIncludes}, got ${message}`,
    );
    return message;
  }
  throw new Error("Expected the call to throw");
}

/** Query-only permission probe; the default `deno test` task carries no
 * permissions, so runtime cases skip there and only execute under the
 * explicit --allow-read/--allow-write invocation. */
async function runtimePermissionsGranted(): Promise<boolean> {
  const descriptors: Deno.PermissionDescriptor[] = [
    { name: "read" },
    { name: "write" },
  ];
  for (const descriptor of descriptors) {
    try {
      if ((await Deno.permissions.query(descriptor)).state !== "granted") {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

const runtimePermitted = await runtimePermissionsGranted();

function runtimeTest(
  name: string,
  fn: () => void | Promise<void>,
): void {
  Deno.test({ name: `runtime: ${name}`, ignore: !runtimePermitted, fn });
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function gateFixture(
  overrides: Record<string, unknown> = {},
): BackupControllerGate {
  const nowMs = Date.now();
  const requestedAt = nowMs - 7_200_000;
  const createdAt = nowMs - 3_600_000;
  return validateGate({
    schemaVersion: 1,
    owner: "backblaze-direct",
    state: "active",
    jobId: `job-${UUID}`,
    periodKey: "2026-09-06",
    generation: `generation-${UUID}`,
    requestSha256: "ab".repeat(32),
    requestedAtUtc: iso(requestedAt),
    deadlineAtUtc: iso(requestedAt + 6 * 3_600_000),
    createdAtUtc: iso(createdAt),
    updatedAtUtc: iso(createdAt + 1_000),
    remoteHost: "codex@vps.pavlovcik.com",
    unitName: `arch-vps-b2-worker-${UUID}.service`,
    unitInvocationId: null,
    sourceLockPath: "/var/tmp/arch-vps-file-backup/source.lock",
    ...overrides,
  });
}

/** All runtime files live under one unique temporary directory; the previous
 * cwd is restored and the directory removed in finally. */
async function withTempWorkdir(
  fn: () => Promise<void>,
): Promise<void> {
  const original = Deno.cwd();
  const dir = await Deno.makeTempDir({ prefix: "m06-integration-" });
  let moved = false;
  try {
    Deno.chdir(dir);
    moved = true;
    await Deno.mkdir(".private", { mode: 0o700 });
    await Deno.chmod(".private", 0o700);
    await fn();
  } finally {
    if (moved) Deno.chdir(original);
    await Deno.remove(dir, { recursive: true });
  }
}

async function writePrivateJsonFile(
  path: string,
  value: unknown,
  mode: number = 0o600,
): Promise<void> {
  await Deno.writeFile(
    path,
    new TextEncoder().encode(JSON.stringify(value)),
    { mode },
  );
}

const SOURCE = {
  instanceId: "ocid1.instance.oc1..aaaa",
  bootVolumeId: "ocid1.bootvolume.oc1..aaaa",
  rootVolumeId: "ocid1.volume.oc1..aaaa",
  compartmentId: "ocid1.compartment.oc1..aaaa",
  region: "us-ashburn-1",
};
const PAIR = {
  suffix: "20260903T191507Z",
  bootId: "ocid1.bootvolumebackup.oc1..bbbb",
  rootId: "ocid1.volumebackup.oc1..bbbb",
};

function runtimeConfigFixture(
  action: "preflight" | "cycle",
): Record<string, unknown> {
  return {
    ociCliPath: "/usr/bin/oci",
    ociProfile: "DEFAULT",
    tenancyId: "ocid1.tenancy.oc1..aaaa",
    source: { ...SOURCE },
    action,
    policy: {
      source: { ...SOURCE },
      standingApproval: {
        approvedAtUtc: iso(Date.now() - 86_400_000),
        exactOperation: "weekly paired backup rotation",
        source: { ...SOURCE },
      },
      acceptedPair: { ...PAIR },
      retainPreviousPair: true,
      allowFifthSlot: true,
    },
    guest: {
      host: "codex@vps.pavlovcik.com",
      rootUuid: "aaaaaaaa-1111-1111-1111-111111111111",
      stagingUuid: "bbbbbbbb-2222-2222-2222-222222222222",
      activityScriptPath:
        "/home/codex/ops/weekly-backup-controller/backup-guest-activity.ts",
    },
  };
}

function restoreConfigFixture(
  action: "soft-stop" | "restore",
): Record<string, unknown> {
  const base = {
    action,
    ociCliPath: "/usr/bin/oci",
    ociProfile: "DEFAULT",
    region: "us-ashburn-1",
    compartmentId: SOURCE.compartmentId,
    availabilityDomains: ["AD-1"],
    subnetId: "ocid1.subnet.oc1..aaaa",
    bootVolumeBackupId: "ocid1.bootvolumebackup.oc1..bbbb",
    rootVolumeBackupId: "ocid1.volumebackup.oc1..bbbb",
    expectedBootSourceVolumeId: SOURCE.bootVolumeId,
    expectedRootSourceVolumeId: SOURCE.rootVolumeId,
    reservedPublicIpId: "ocid1.publicip.oc1..aaaa",
    instanceId: SOURCE.instanceId,
    expectedPairSuffix: PAIR.suffix,
    expectedRootUuid: "aaaaaaaa-1111-1111-1111-111111111111",
    stopWaitSeconds: 30,
  };
  if (action === "restore") {
    return {
      ...base,
      approval: {
        approved: true,
        approvedAtUtc: iso(Date.now() - 60_000),
        exactOperation:
          "restore matched arch backup pair and reassign the reserved IP",
        approvedPairSuffix: PAIR.suffix,
        approvedTargets: {
          bootVolumeBackupId: base.bootVolumeBackupId,
          rootVolumeBackupId: base.rootVolumeBackupId,
          expectedBootSourceVolumeId: base.expectedBootSourceVolumeId,
          expectedRootSourceVolumeId: base.expectedRootSourceVolumeId,
          compartmentId: base.compartmentId,
          availabilityDomains: base.availabilityDomains,
          subnetId: base.subnetId,
          reservedPublicIpId: base.reservedPublicIpId,
        },
      },
    };
  }
  return {
    ...base,
    softStopApproval: {
      approved: true,
      approvedAtUtc: iso(Date.now() - 60_000),
      exactOperation: "gracefully stop the OCI instance with SOFTSTOP",
      instanceId: base.instanceId,
    },
  };
}

function recordingRunner(): {
  runner: CommandRunner;
  calls: string[][];
} {
  const calls: string[][] = [];
  const runner: CommandRunner = (_command, args) => {
    calls.push(args);
    return Promise.resolve({
      code: 0,
      stdout: JSON.stringify({ data: {} }),
      stderr: "",
    });
  };
  return { runner, calls };
}

function stoppedRunner(): {
  runner: CommandRunner;
  calls: string[][];
} {
  const calls: string[][] = [];
  let phase = "RUNNING";
  const runner: CommandRunner = (_command, args) => {
    calls.push(args);
    const action = args.indexOf("--action");
    if (action >= 0 && args[action + 1] === "SOFTSTOP") {
      phase = "STOPPED";
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify({ data: { "lifecycle-state": "STOPPING" } }),
        stderr: "",
      });
    }
    return Promise.resolve({
      code: 0,
      stdout: JSON.stringify({
        data: { "lifecycle-state": phase },
        etag: "etag-1",
      }),
      stderr: "",
    });
  };
  return { runner, calls };
}

runtimeTest(
  "runtime.main refuses Oracle work for an active gate before any read",
  async () => {
    await withTempWorkdir(async () => {
      await writeActiveGate(gateFixture());
      let calls = 0;
      const message = await assertThrowsAsync(async () => {
        await runtimeMain(() => {
          calls++;
          return Promise.resolve({ recoveryOnly: true });
        });
      }, "gate");
      assert(/gate/.test(message));
      assert(calls === 0, "beforeCycle must never run behind an active gate");
    });
  },
);

runtimeTest(
  "runtime.main refuses Oracle work for an orphaned gate too",
  async () => {
    await withTempWorkdir(async () => {
      const gate = await writeActiveGate(gateFixture());
      await markOrphaned(gate, "TERMINAL_PROOF_MISSING");
      let calls = 0;
      await assertThrowsAsync(async () => {
        await runtimeMain(() => {
          calls++;
          return Promise.resolve({ recoveryOnly: true });
        });
      }, "gate");
      assert(calls === 0);
    });
  },
);

runtimeTest("runtime.main fails closed on malformed gate state", async () => {
  await withTempWorkdir(async () => {
    await writePrivateJsonFile(
      ".private/backup-controller-gate.json",
      { schemaVersion: 2 },
    );
    let calls = 0;
    await assertThrowsAsync(async () => {
      await runtimeMain(() => {
        calls++;
        return Promise.resolve({ recoveryOnly: true });
      });
    }, "schemaVersion must be 1");
    assert(calls === 0);
  });
});

runtimeTest(
  "runtime.main absence alone permits the preflight path",
  async () => {
    await withTempWorkdir(async () => {
      await writePrivateJsonFile(
        ".private/backup-controller.json",
        runtimeConfigFixture("preflight"),
      );
      const probe = { called: false };
      await assertThrowsAsync(async () => {
        await runtimeMain(() => {
          probe.called = true;
          return Promise.resolve({});
        });
      }, "Scheduled execution requires cycle mode");
      assert(probe.called === false);
    });
  },
);

runtimeTest(
  "runtime.main absence permits a recoveryOnly callback to run",
  async () => {
    await withTempWorkdir(async () => {
      await writePrivateJsonFile(
        ".private/backup-controller.json",
        runtimeConfigFixture("cycle"),
      );
      const probe = { called: false };
      await assertThrowsAsync(async () => {
        await runtimeMain(() => {
          probe.called = true;
          return Promise.resolve({ recoveryOnly: true });
        });
      }, "No interrupted source outage requires recovery");
      assert(
        probe.called === true,
        "The recoveryOnly callback must reach the next gate",
      );
    });
  },
);

runtimeTest(
  "oci-restore.main soft-stop is blocked by a gate before any runner call",
  async () => {
    await withTempWorkdir(async () => {
      await writePrivateJsonFile(
        ".private/restore.json",
        restoreConfigFixture("soft-stop"),
      );
      await writeActiveGate(gateFixture());
      const { runner, calls } = recordingRunner();
      await assertThrowsAsync(() => restoreMain(runner), "gate");
      assert(calls.length === 0, "No remote runner invocation may occur");
    });
  },
);

runtimeTest(
  "oci-restore.main restore is blocked by a gate before any runner call",
  async () => {
    await withTempWorkdir(async () => {
      await writePrivateJsonFile(
        ".private/restore.json",
        restoreConfigFixture("restore"),
      );
      await writeActiveGate(gateFixture());
      const { runner, calls } = recordingRunner();
      await assertThrowsAsync(() => restoreMain(runner), "gate");
      assert(calls.length === 0, "No remote runner invocation may occur");
    });
  },
);

runtimeTest(
  "oci-restore.main absence permits the guarded soft-stop dispatch",
  async () => {
    await withTempWorkdir(async () => {
      await writePrivateJsonFile(
        ".private/restore.json",
        restoreConfigFixture("soft-stop"),
      );
      const { runner, calls } = stoppedRunner();
      await restoreMain(runner);
      assert(calls.length >= 2, "The guarded dispatch must reach the runner");
    });
  },
);

runtimeTest(
  "oci-restore.main rereads config after the lock wait and refuses changed actions",
  async () => {
    await withTempWorkdir(async () => {
      await writePrivateJsonFile(
        ".private/restore.json",
        restoreConfigFixture("soft-stop"),
      );
      const { runner, calls } = recordingRunner();
      let pending!: Promise<void>;
      await withBackupLock(".private/backup-controller.lock", async () => {
        pending = restoreMain(runner);
        await new Promise((resolve) => setTimeout(resolve, 100));
        await writePrivateJsonFile(
          ".private/restore.json",
          restoreConfigFixture("restore"),
        );
      });
      await assertThrowsAsync(
        () => pending,
        "changed while waiting for the controller lock",
      );
      assert(calls.length === 0);
    });
  },
);

runtimeTest(
  "oci-restore.main reapplies the exact approval after the lock wait",
  async () => {
    await withTempWorkdir(async () => {
      await writePrivateJsonFile(
        ".private/restore.json",
        restoreConfigFixture("soft-stop"),
      );
      const { runner, calls } = recordingRunner();
      let pending!: Promise<void>;
      await withBackupLock(".private/backup-controller.lock", async () => {
        pending = restoreMain(runner);
        await new Promise((resolve) => setTimeout(resolve, 100));
        const stale = restoreConfigFixture("soft-stop");
        (stale.softStopApproval as Record<string, unknown>).approvedAtUtc = iso(
          Date.now() - 2 * 3_600_000,
        );
        await writePrivateJsonFile(".private/restore.json", stale);
      });
      await assertThrowsAsync(() => pending, "SOFTSTOP approval");
      assert(calls.length === 0);
    });
  },
);

runtimeTest(
  "launch preflight is a pure gate of complete, recovered Oracle state",
  () => {
    const acceptedAt = iso(Date.now() - 3_300_000);
    const state = {
      policy: {
        source: { ...SOURCE },
        standingApproval: {
          approvedAtUtc: iso(Date.now() - 86_400_000),
          exactOperation: "weekly paired backup rotation",
          source: { ...SOURCE },
        },
        acceptedPair: { ...PAIR },
        retainPreviousPair: true,
        allowFifthSlot: true,
      },
      cycle: {
        source: { ...SOURCE },
        previousPair: { ...PAIR },
        suffix: "20260905T050131Z",
        phase: "complete",
        createdAtUtc: iso(Date.now() - 7_200_000),
        updatedAtUtc: acceptedAt,
        sourceAcceptedAtUtc: acceptedAt,
      },
      guest: {
        rootUuid: "aaaaaaaa-1111-1111-1111-111111111111",
        stagingUuid: "bbbbbbbb-2222-2222-2222-222222222222",
        containers: [{ id: "c1", name: "guac", running: true }],
        units: [{ name: "caddy.service", active: true }],
        restored: true,
      },
    };
    assertBackblazeLaunchAllowed(state, undefined);
    const incomplete = structuredClone(state);
    (incomplete.cycle as Record<string, unknown>).phase = "planned";
    assertThrowsSync(
      () => assertBackblazeLaunchAllowed(incomplete, undefined),
      "not complete",
    );
    const claim = {
      windowId: "2026-09-06@America/New_York",
      status: "started",
      updatedAtUtc: iso(Date.now() - 60_000),
    };
    assertThrowsSync(
      () => assertBackblazeLaunchAllowed(state, claim),
      "already started",
    );
  },
);
