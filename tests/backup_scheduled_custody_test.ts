import { withBackupLock } from "../scripts/backup-lock.ts";
import {
  type RuntimeState,
  settleBackupPreparation,
} from "../scripts/backup-runtime.ts";
import { type BackupSchedule } from "../scripts/backup-schedule.ts";
import {
  approvedScheduleOf,
  assertClaimInventorySettled,
  planScheduledClaim,
  recoverScheduledClaim,
  type WindowClaim,
} from "../scripts/backup-scheduled.ts";
import {
  proveBackblazeSourceIdle,
  SOURCE_LOCK_PATH,
} from "../scripts/backblaze-file-backup.ts";
import { GATE_BACKUP_CGROUP_ROOT } from "../scripts/backblaze-controller-contract.ts";
import {
  defaultRunner,
  readPrivateJson,
  writePrivateJson,
} from "../scripts/oci.ts";
import {
  CLAIM_PATH,
  currentClaimOwner,
  ScheduledClaimCustodyError,
  type ScheduledClaimCustodyStatus,
  scheduledClaimOwnerState,
} from "../scripts/scheduled-claim-custody.ts";
import { type BackupPolicy } from "../scripts/weekly-backup.ts";

const schedule: BackupSchedule = {
  approvedAtUtc: "2026-09-05T01:51:00.000Z",
  timeZone: "America/New_York",
  weekday: 0,
  hour: 0,
  minute: 0,
  windowMinutes: 120,
};
const now = new Date("2026-11-17T21:00:00.000Z");
const startedAtUtc = "2026-11-17T20:51:03.274Z";
const cycleSuffix = "20261025T040557Z";
const source = {
  instanceId: "vps",
  bootVolumeId: "boot",
  rootVolumeId: "root",
  compartmentId: "tenancy",
  region: "home-region",
};
const policy: BackupPolicy = {
  source,
  volumeGroupId: "source-group",
  standingApproval: {
    approvedAtUtc: schedule.approvedAtUtc,
    exactOperation: "weekly paired backup rotation",
    source,
  },
  acceptedPair: { suffix: "20261018T040000Z", bootId: "b", rootId: "r" },
  retainPreviousPair: false,
  allowFifthSlot: false,
};
const predecessor: RuntimeState = {
  policy,
  cycle: {
    mode: "online",
    source,
    previousPair: policy.acceptedPair,
    suffix: cycleSuffix,
    phase: "complete",
    createdAtUtc: "2026-10-25T04:05:57.115Z",
    updatedAtUtc: "2026-10-25T05:05:08.576Z",
    sourceAcceptedAtUtc: "2026-10-25T04:45:49.960Z",
    volumeGroupBackupId: "prior-group-backup",
    volumeGroupBackupIntent: true,
  },
};
const legacy: WindowClaim = {
  windowId: "2026-11-15@America/New_York",
  periodId: "2026-11-15@America/New_York",
  previousCycleSuffix: cycleSuffix,
  status: "started",
  updatedAtUtc: startedAtUtc,
  approvedSchedule: approvedScheduleOf(schedule),
};
const owner = {
  machineId: "a".repeat(32),
  bootId: "12345678-1234-1234-1234-123456789abc",
  pid: 42,
  startTicks: "122333",
  startedAtUtc,
  journalSuffix: cycleSuffix,
};
const started = { ...legacy, owner };

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}

async function rejects(
  run: () => Promise<unknown>,
  status?: ScheduledClaimCustodyStatus,
) {
  try {
    await run();
  } catch (error) {
    if (status !== undefined) {
      assert(
        error instanceof ScheduledClaimCustodyError && error.status === status,
      );
    }
    return;
  }
  throw new Error("Expected rejection");
}

type RecoveryDeps = Parameters<typeof recoverScheduledClaim>[4];

function fixture(claim: WindowClaim = started) {
  const records = new Map<string, WindowClaim>([[CLAIM_PATH, claim]]);
  const calls: string[] = [];
  const deps: RecoveryDeps = {
    ownerState: () => Promise.resolve("dead"),
    proveIdle: () => {
      calls.push("prove");
      return Promise.resolve();
    },
    read: (path) => Promise.resolve(records.get(path)),
    write: (path, value) => {
      records.set(path, value);
      calls.push(path === CLAIM_PATH ? "settle" : "archive");
      return Promise.resolve();
    },
  };
  return {
    records,
    calls,
    deps,
    recover: (state = predecessor, at = now) =>
      recoverScheduledClaim(records.get(CLAIM_PATH), state, schedule, at, deps),
  };
}

Deno.test("an exact live owner blocks and performs no recovery writes or probes", async () => {
  const f = fixture();
  f.deps.ownerState = () => Promise.resolve("live");
  await rejects(() => f.recover(), "SCHEDULED_CLAIM_OWNER_LIVE");
  await rejects(
    () => f.recover(predecessor, new Date("2026-11-19T00:00:00Z")),
    "SCHEDULED_CLAIM_OWNER_LIVE",
  );
  assert(f.records.get(CLAIM_PATH) === started && f.calls.length === 0);
});

Deno.test("a dead owner and unchanged predecessor settle before the next due claim", async () => {
  const f = fixture();
  const released = await f.recover();
  assert(
    released?.status === "failed" &&
      released.failure?.reason === "CONTROLLER_EXITED",
  );
  assert(f.calls.join(",") === "prove,archive,settle");
  assert(Array.from(f.records.values()).includes(started));
  assert(predecessor.cycle.phase === "complete");
  const next = planScheduledClaim(schedule, now, predecessor, released);
  assert(
    next.action === "run" && next.claim.owner === undefined &&
      next.claim.failure === undefined,
  );
  const changed = structuredClone(predecessor);
  changed.cycle.updatedAtUtc = now.toISOString();
  const inconsistent = fixture();
  await rejects(
    () => inconsistent.recover(changed),
    "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE",
  );
  assert(inconsistent.calls.length === 0);
});

Deno.test("unknown ownership becomes a bounded incident and never authorizes cleanup", async () => {
  const f = fixture();
  f.deps.ownerState = () => Promise.resolve("unknown");
  await rejects(() => f.recover(), "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
  await rejects(
    () => f.recover(predecessor, new Date("2026-11-18T20:51:03.274Z")),
    "SCHEDULED_CLAIM_CUSTODY_OVERDUE",
  );
  assert(f.records.get(CLAIM_PATH) === started && f.calls.length === 0);
});

Deno.test("legacy claim uses the approved period age and exact predecessor, including a refreshed timestamp", async () => {
  const f = fixture(legacy);
  f.deps.ownerState = () =>
    Promise.reject(new Error("A legacy claim has no PID to query"));
  const released = await f.recover();
  assert(released?.failure?.reason === "LEGACY_CONTROLLER_EXITED");

  const tooYoung = fixture({
    ...legacy,
    updatedAtUtc: "2026-11-15T05:01:00.000Z",
  });
  await rejects(
    () => tooYoung.recover(predecessor, new Date("2026-11-15T17:59:59.999Z")),
    "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE",
  );
  assert(tooYoung.calls.length === 0);

  const wrongPredecessor = fixture({
    ...legacy,
    previousCycleSuffix: "20261018T040000Z",
  });
  await rejects(
    () => wrongPredecessor.recover(),
    "SCHEDULED_CLAIM_CUSTODY_OVERDUE",
  );
  assert(wrongPredecessor.calls.length === 0);
});

Deno.test("a committed runtime repairs claim completion without a fresh scheduled launch", async () => {
  const f = fixture();
  const completed = structuredClone(predecessor);
  completed.cycle = {
    ...completed.cycle,
    suffix: "20261117T205105Z",
    previousPair: { suffix: cycleSuffix, bootId: "b", rootId: "r" },
    createdAtUtc: "2026-11-17T20:51:05.000Z",
    updatedAtUtc: "2026-11-17T20:59:00.000Z",
    sourceAcceptedAtUtc: "2026-11-17T20:58:00.000Z",
  };
  const repaired = await f.recover(completed);
  assert(repaired?.status === "complete");
  assert(
    planScheduledClaim(schedule, now, completed, repaired).action === "skip",
  );
});

Deno.test("interruption at each custody transition retains the fence and retries idempotently", async () => {
  for (
    const point of [
      "proof",
      "archive-before",
      "archive-after",
      "settle-before",
      "settle-after",
    ]
  ) {
    const f = fixture();
    const write = f.deps.write;
    const prove = f.deps.proveIdle;
    f.deps.proveIdle = async (recovery) => {
      if (point === "proof") throw new Error("lost proof");
      await prove(recovery);
    };
    f.deps.write = async (path, value) => {
      const stage = path === CLAIM_PATH ? "settle" : "archive";
      if (point === stage + "-before") throw new Error("before durable write");
      await write(path, value);
      if (point === stage + "-after") throw new Error("after durable write");
    };
    await rejects(() => f.recover(), "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
    assert(
      f.records.get(CLAIM_PATH)?.status ===
        (point === "settle-after" ? "failed" : "started"),
    );
    f.deps.write = write;
    f.deps.proveIdle = prove;
    assert((await f.recover())?.status === "failed");
    assert(f.calls.filter((call) => call === "archive").length === 1);
    assert(f.calls.filter((call) => call === "settle").length === 1);
  }
});

function group(suffix: string, id: string, at: string) {
  return {
    id,
    "volume-group-id": policy.volumeGroupId,
    "compartment-id": source.compartmentId,
    "display-name": `arch-online-golden-${suffix}`,
    "lifecycle-state": "AVAILABLE",
    "time-created": at,
    type: "FULL",
  };
}

Deno.test("ambiguous, unmatched, and live OCI captures keep the claim; exact settled intent preserves the journal", async () => {
  const resume = structuredClone(predecessor);
  resume.cycle = {
    ...resume.cycle,
    suffix: "20261117T205105Z",
    previousPair: { suffix: cycleSuffix, bootId: "b", rootId: "r" },
    phase: "backing-up",
    createdAtUtc: "2026-11-17T20:51:05.000Z",
    updatedAtUtc: "2026-11-17T20:51:12.000Z",
    volumeGroupBackupId: undefined,
    volumeGroupBackupIntent: true,
  };
  const f = fixture();
  const initialJournal = JSON.stringify(resume);
  const oldGroup = group(
    cycleSuffix,
    "prior-group-backup",
    predecessor.cycle.createdAtUtc,
  );
  const newGroup = group(
    resume.cycle.suffix,
    "accepted-intent",
    resume.cycle.updatedAtUtc,
  );
  let groups = [oldGroup];
  f.deps.proveIdle = (proof) => {
    const inventory = {
      observedAtUtc: now.toISOString(),
      instance: { "lifecycle-state": "RUNNING" },
      sourceAttachmentsProved: true,
      sourceVolumeGroupProved: true,
      sourceVolumeGroup: { id: policy.volumeGroupId },
      volumeGroupBackups: groups,
    };
    assertClaimInventorySettled(inventory, { source, policy }, proof);
    return Promise.resolve();
  };
  await rejects(() => f.recover(resume), "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
  groups = [oldGroup, { ...newGroup, "lifecycle-state": "CREATING" }];
  await rejects(() => f.recover(resume), "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
  groups = [oldGroup, newGroup, { ...newGroup, id: "duplicate" }];
  await rejects(() => f.recover(resume), "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
  groups = [oldGroup, newGroup];
  await rejects(
    () => f.recover(predecessor),
    "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE",
  );
  assert(f.records.get(CLAIM_PATH) === started && f.calls.length === 0);
  const released = await f.recover(resume);
  assert(
    released?.status === "failed" && JSON.stringify(resume) === initialJournal,
  );
  const next = planScheduledClaim(schedule, now, resume, released);
  assert(next.action === "run" && next.claim.windowId === started.windowId);
});

Deno.test("a caught pre-journal failure settles the started claim before releasing ownership", async () => {
  const f = fixture();
  const refused = new Error("predecessor account check failed");
  try {
    await settleBackupPreparation(
      () => Promise.reject(refused),
      () => f.deps.write(CLAIM_PATH, { ...started, status: "failed" }),
    );
  } catch (error) {
    assert(error === refused);
  }
  assert(f.records.get(CLAIM_PATH)?.status === "failed");
});

Deno.test("owner probe distinguishes PID reuse, reboot, zombie, different host and unreadable proc", async () => {
  const stat = (startTicks: string, state = "S") =>
    `42 (name with ) spaces) ${state} ${
      new Array(18).fill("0").join(" ")
    } ${startTicks}`;
  const probe = (
    entry: string,
    machine = owner.machineId,
    boot = owner.bootId,
    code = 0,
  ) =>
    scheduledClaimOwnerState(
      owner,
      () =>
        Promise.resolve({
          code,
          stderr: "",
          stdout: `${machine}\n${boot}\n${entry}\n`,
        }),
    );
  assert(await probe(stat(owner.startTicks)) === "live");
  assert(await probe(stat("223334")) === "dead");
  assert(await probe(stat(owner.startTicks, "Z")) === "dead");
  assert(await probe("absent") === "dead");
  assert(
    await probe(
      "absent",
      owner.machineId,
      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ) === "dead",
  );
  assert(await probe("absent", "c".repeat(32)) === "unknown");
  assert(await probe("absent", owner.machineId, owner.bootId, 1) === "unknown");
  assert(await probe("invalid") === "unknown");
});

const nativeDir = "/tmp";
const nativeFiles =
  (await Deno.permissions.query({ name: "read", path: nativeDir })).state ===
    "granted" &&
  (await Deno.permissions.query({ name: "write", path: nativeDir })).state ===
    "granted";

Deno.test({
  name:
    "two controllers acquire the real kernel lock and fence an orphan after a failed claim write",
  ignore: !nativeFiles,
  async fn() {
    const dir = await Deno.makeTempDir({ prefix: "backup-claim-lock-" });
    const claimPath = `${dir}/claim.json`;
    const lockPath = `${dir}/controller.lock`;
    const sourceIntent = `${dir}/source-intent.json`;
    await writePrivateJson(claimPath, started);
    const entered = Promise.withResolvers<void>();
    const secondArrived = Promise.withResolvers<void>();
    let launches = 0;
    let repairs = 0;
    let recoveryAttempts = 0;
    const deps: RecoveryDeps = {
      ownerState: () => Promise.resolve("dead"),
      proveIdle: () => {
        recoveryAttempts++;
        return Promise.resolve();
      },
      read: async (path) => {
        try {
          return await readPrivateJson(
            path === CLAIM_PATH ? claimPath : `${dir}/archive.json`,
          );
        } catch (error) {
          if (error instanceof Deno.errors.NotFound) return undefined;
          throw error;
        }
      },
      write: async (path, value) => {
        if (path === CLAIM_PATH && recoveryAttempts === 1) {
          throw new Error("first controller exited before settling");
        }
        if (path !== CLAIM_PATH) repairs++;
        await writePrivateJson(
          path === CLAIM_PATH ? claimPath : `${dir}/archive.json`,
          value,
        );
      },
    };
    const run = () =>
      withBackupLock(lockPath, async () => {
        if (recoveryAttempts === 0) {
          entered.resolve();
          await secondArrived.promise;
        }
        const result = await recoverScheduledClaim(
          await readPrivateJson(claimPath),
          predecessor,
          schedule,
          now,
          deps,
        );
        assert(result?.status === "failed");
        try {
          await Deno.stat(sourceIntent);
          return;
        } catch (error) {
          if (!(error instanceof Deno.errors.NotFound)) throw error;
        }
        await writePrivateJson(sourceIntent, { stage: "intent" });
        launches++;
      });
    try {
      const first = rejects(run, "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
      await entered.promise;
      const second = run();
      secondArrived.resolve();
      await Promise.all([first, second]);
      await run();
      assert(recoveryAttempts === 2 && repairs === 1 && launches === 1);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "owner liveness observes the actual Linux process through the existing subprocess grant",
  ignore: (await Deno.permissions.query({ name: "run", command: "/bin/sh" }))
    .state !== "granted",
  async fn() {
    const identity = await currentClaimOwner(startedAtUtc, cycleSuffix);
    assert(identity.pid === Deno.pid);
    assert(await scheduledClaimOwnerState(identity) === "live");
  },
});

Deno.test({
  name:
    "source quiescence shell refuses process inventory gaps, escaped tar, queued units and populated cgroups",
  ignore: !nativeFiles ||
    (await Deno.permissions.query({ name: "run", command: "/bin/bash" }))
        .state !== "granted",
  async fn() {
    const dir = await Deno.makeTempDir({ prefix: "backup-source-idle-" });
    const cgroup = dir + "/sys";
    const slice = cgroup + GATE_BACKUP_CGROUP_ROOT;
    const lock = `${dir}/lock`;
    await Deno.mkdir(slice, { recursive: true });
    await Deno.writeTextFile(lock, "");
    await Deno.writeTextFile(`${cgroup}/cgroup.events`, "populated 1\n");
    await Deno.writeTextFile(`${slice}/cgroup.events`, "populated 0\n");
    const processList = "1 systemd /usr/lib/systemd/systemd\n";
    const systemctl = `${dir}/systemctl`;
    const ps = `${dir}/ps`;
    const shellFile = (path: string, command: string) =>
      Deno.writeTextFile(path, "#!/bin/sh\n" + command + "\n", { mode: 0o700 });
    const run = () =>
      proveBackblazeSourceIdle({
        root: (script) =>
          defaultRunner("/bin/bash", [
            "-c",
            `export PATH='${dir}:/usr/bin:/bin';\n` + script
              .replaceAll(SOURCE_LOCK_PATH, lock)
              .replaceAll("/sys/fs/cgroup", cgroup),
          ]),
      });
    try {
      await shellFile(systemctl, "exit 0");
      await shellFile(ps, `printf '%s' '${processList}'`);
      await run();
      await shellFile(
        ps,
        `printf '%s' '${processList}21 tar tar -C / --create\n'`,
      );
      await rejects(run);
      await shellFile(
        ps,
        `printf '%s' '${processList}22 zstd zstd -3 -T1 --check -c\n'`,
      );
      await rejects(run);
      await shellFile(ps, "exit 1");
      await rejects(run);
      await shellFile(ps, "exit 0");
      await rejects(run);
      await shellFile(ps, `printf '%s' '${processList}'`);
      await shellFile(
        systemctl,
        'if [ "$1" = list-jobs ]; then echo "7 arch-vps-b2-worker-queued.service start waiting"; fi',
      );
      await rejects(run);
      await shellFile(systemctl, "exit 0");
      await Deno.writeTextFile(`${slice}/cgroup.events`, "populated 1\n");
      await rejects(run);
      await Deno.writeTextFile(`${slice}/cgroup.events`, "populated 0\n");
      await Deno.remove(lock);
      await rejects(run);
      await rejects(() => Deno.stat(lock));
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});
