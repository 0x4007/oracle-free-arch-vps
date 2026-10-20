import {
  type BackupV2RuntimeLeaseCapabilities,
  backupV2RuntimeLeaseDirectory,
  createBackupV2RuntimeLease,
  validateBackupV2RuntimeLeaseText,
} from "../scripts/backup-v2-runtime-lease.ts";
import type { BackupV2SupervisorIdentity } from "../scripts/backup-v2-supervisor.ts";
import { GATE_BACKUP_CGROUP_ROOT } from "../scripts/backblaze-controller-contract.ts";

function equal(actual: unknown, expected: unknown) {
  if (actual !== expected) throw new Error("Mismatch");
}
async function rejects(run: () => unknown) {
  try {
    await run();
  } catch {
    return;
  }
  throw new Error("Expected rejection");
}
const unitName =
  "arch-vps-b2-v2-worker-00000000-0000-4000-8000-000000000001-00000000-0000-4000-8000-000000000002.service";
const identity: BackupV2SupervisorIdentity = {
  unitName,
  invocationId: "a".repeat(32),
  mainPid: 1234,
  mainStartTicks: "5678",
  cgroup: `${GATE_BACKUP_CGROUP_ROOT}/${unitName}`,
};
function fixture() {
  const state = {
    now: 50_000,
    kernel: 420_000_000n,
    activation: 400_000_000n,
    running: true,
    identity: { ...identity },
    writes: [] as string[],
    reads: 0,
  };
  const caps: BackupV2RuntimeLeaseCapabilities = {
    now: () => state.now,
    kernelNowUsec: () => state.kernel,
    observe: () => {
      state.reads++;
      return Promise.resolve({
        identity: state.identity,
        running: state.running,
        activeEnterUsec: state.activation,
      });
    },
    persist: (text, signal) => {
      signal.throwIfAborted();
      state.writes.push(text);
      return Promise.resolve();
    },
  };
  return { state, caps };
}
const signal = () => new AbortController().signal;

Deno.test("reload lease projects a process-relative deadline onto actual kernel activation", async () => {
  const { state, caps } = fixture(),
    persist = createBackupV2RuntimeLease(identity, caps);
  await persist(52_000, signal());
  equal(state.writes.length, 1);
  equal(
    state.writes[0].endsWith(
      "RuntimeMaxSec=22000000us\nRuntimeRandomizedExtraSec=0\n",
    ),
    true,
  );
  validateBackupV2RuntimeLeaseText(state.writes[0], identity);
  state.now += 10_000;
  state.kernel += 10_000_000n;
  await persist(62_000, signal());
  equal(
    state.writes[1].endsWith(
      "RuntimeMaxSec=32000000us\nRuntimeRandomizedExtraSec=0\n",
    ),
    true,
  );
});

Deno.test("READY barrier ignores an old inactive activation and binds the processed running activation", async () => {
  const { state, caps } = fixture();
  caps.observe = () => {
    state.reads++;
    state.now += 10;
    return Promise.resolve({
      identity,
      running: state.reads > 1,
      activeEnterUsec: state.reads > 1 ? 410_000_000n : 1n,
    });
  };
  await createBackupV2RuntimeLease(identity, caps)(50_100, signal());
  equal(state.reads, 2);
  equal(
    state.writes[0].endsWith(
      "RuntimeMaxSec=10080000us\nRuntimeRandomizedExtraSec=0\n",
    ),
    true,
  );
});

Deno.test("readiness, custody and clock failures never persist a renewal", async () => {
  for (
    const fault of [
      "readiness",
      "activation-future",
      "clock-zero",
      "deadline",
      "aborted",
      "observe",
    ] as const
  ) {
    const { state, caps } = fixture(), abort = new AbortController();
    if (fault === "readiness") {
      caps.observe = () => {
        state.now += 1000;
        return Promise.resolve({
          identity,
          running: false,
          activeEnterUsec: 1n,
        });
      };
    }
    if (fault === "activation-future") state.activation = state.kernel + 1n;
    if (fault === "clock-zero") state.kernel = 0n;
    if (fault === "deadline") {
      caps.observe = () => {
        state.now += 2000;
        return Promise.resolve({
          identity,
          running: true,
          activeEnterUsec: state.activation,
        });
      };
    }
    if (fault === "aborted") abort.abort();
    if (fault === "observe") {
      caps.observe = () => Promise.reject(new Error("unreadable"));
    }
    await rejects(() =>
      createBackupV2RuntimeLease(identity, caps)(52_000, abort.signal)
    );
    equal(state.writes.length, 0);
  }
  for (
    const field of [
      "unitName",
      "invocationId",
      "mainPid",
      "mainStartTicks",
      "cgroup",
    ] as const
  ) {
    const { state, caps } = fixture();
    if (field === "mainPid") state.identity.mainPid++;
    else state.identity[field] += "1";
    await rejects(() =>
      createBackupV2RuntimeLease(identity, caps)(52_000, signal())
    );
    equal(state.writes.length, 0);
  }
});

Deno.test("persistence failure poisons later renewals and preserves the original fixed deadline", async () => {
  const { state, caps } = fixture();
  caps.persist = () => Promise.reject(new Error("fsync failed"));
  const persist = createBackupV2RuntimeLease(identity, caps);
  await rejects(() => persist(52_000, signal()));
  const reads = state.reads;
  state.now++;
  await rejects(() => persist(52_001, signal()));
  equal(state.reads, reads);
  equal(state.writes.length, 0);
});

Deno.test("a changed activation or regressing clock cannot reuse an earlier successful lease", async () => {
  for (const fault of ["activation", "kernel", "process"] as const) {
    const { state, caps } = fixture(),
      persist = createBackupV2RuntimeLease(identity, caps);
    await persist(52_000, signal());
    if (fault === "activation") state.activation++;
    if (fault === "kernel") state.kernel--;
    if (fault === "process") state.now--;
    await rejects(() => persist(52_000, signal()));
    equal(state.writes.length, 1);
  }
});

Deno.test("stale invocation files, unsafe units, unlimited and randomized lease text fail closed", async () => {
  const { state, caps } = fixture();
  await createBackupV2RuntimeLease(identity, caps)(52_000, signal());
  await rejects(() =>
    validateBackupV2RuntimeLeaseText(state.writes[0], {
      ...identity,
      invocationId: "b".repeat(32),
    })
  );
  for (
    const text of [
      state.writes[0].replace("22000000us", "infinity"),
      state.writes[0].replace("ExtraSec=0", "ExtraSec=1"),
      state.writes[0] + "RuntimeMaxSec=infinity\n",
    ]
  ) {
    await rejects(() => validateBackupV2RuntimeLeaseText(text, identity));
  }
  for (
    const unit of [
      "../" + unitName,
      unitName + "/../other.service",
      "unrelated.service",
    ]
  ) {
    await rejects(() => backupV2RuntimeLeaseDirectory(unit));
  }
  equal(
    backupV2RuntimeLeaseDirectory(unitName),
    `/run/systemd/system/${unitName}.d`,
  );
});
