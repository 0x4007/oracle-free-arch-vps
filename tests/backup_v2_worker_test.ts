import {
  type BackupV2CapacityIO,
  backupV2CapacityRoots,
  observeBackupV2Capacity,
} from "../scripts/backup-v2-worker.ts";

function equal(actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw Error("Mismatch");
  }
}
async function rejects(work: () => Promise<unknown>) {
  try {
    await work();
  } catch {
    return;
  }
  throw Error("Expected rejection");
}
function fixture() {
  const gate = "/var/tmp/gate",
    graph = "/var/tmp/protection/new",
    old = "/var/tmp/protection/old",
    home = "/home/codex/public",
    transaction = "/var/tmp/protection/transactions/current",
    cache = "/var/tmp/job/deno-cache";
  const nodes = new Map([
    [gate, { ino: 1n, blocks: 8n, dir: true }],
    [gate + "/slot", { ino: 2n, blocks: 128n, dir: false }],
    [graph, { ino: 3n, blocks: 8n, dir: true }],
    [graph + "/page", { ino: 4n, blocks: 16n, dir: false }],
    [old, { ino: 5n, blocks: 1_000_000n, dir: false }],
    [home, { ino: 6n, blocks: 8n, dir: true }],
    [home + "/key", { ino: 7n, blocks: 8n, dir: false }],
    [transaction, { ino: 8n, blocks: 8n, dir: true }],
    [transaction + "/journal", { ino: 9n, blocks: 16n, dir: false }],
    [cache, { ino: 10n, blocks: 8n, dir: true }],
    [cache + "/compile", { ino: 11n, blocks: 16n, dir: false }],
  ]);
  const reads: string[] = [];
  const io: BackupV2CapacityIO = {
    lstat(path) {
      reads.push(path);
      const node = nodes.get(path);
      if (!node) throw new Deno.errors.NotFound();
      return Promise.resolve({
        ...node,
        dev: 1n,
        isSymbolicLink: () => false,
        isDirectory: () => node.dir,
      });
    },
    async *entries(path) {
      for (const child of nodes.keys()) {
        if (
          child.startsWith(path + "/") &&
          !child.slice(path.length + 1).includes("/")
        ) yield child.slice(path.length + 1);
      }
    },
    statfs: () => Promise.resolve({ bavail: 1000n, bsize: 4096n, ffree: 100n }),
    deleted: () =>
      Promise.resolve({
        workspaceHeldDeletedBytes: 4096,
        sourceHeldDeletedBytes: 8192,
      }),
  };
  return { gate, graph, old, home, transaction, cache, nodes, reads, io };
}

Deno.test("capacity counts only exact active roots, unique inodes and both deleted counters once", async () => {
  const f = fixture();
  f.nodes.set(f.home + "/alias", { ino: 2n, blocks: 128n, dir: false });
  const roots = [
    f.graph,
    f.home,
    f.transaction,
    f.cache,
    f.graph,
    f.gate + "/slot",
    "/var/tmp/future",
  ];
  equal(backupV2CapacityRoots(f.gate, roots), [
    f.gate,
    f.graph,
    f.home,
    f.transaction,
    f.cache,
    "/var/tmp/future",
  ]);
  const sample = await observeBackupV2Capacity(f.gate, "cgroup", roots, f.io);
  equal(sample.allocatedWorkspaceBytes, 224 * 512 + 4096 + 8192);
  equal(sample.workspaceHeldDeletedBytes, 4096 + 8192);
  equal(sample.sourceHeldDeletedBytes, 8192);
  equal(sample.availableBytes, 1000 * 4096);
  equal(f.reads.includes(f.old), false);
});

Deno.test("capacity never turns unreadable roots, vanished descendants or unknown deleted accounting into zero", async () => {
  for (
    const mode of [
      "permission",
      "child",
      "deleted",
      "filesystem",
      "device",
      "symlink",
    ] as const
  ) {
    const f = fixture(), lstat = f.io.lstat;
    if (mode === "permission" || mode === "child") {
      f.io.lstat = (path) => {
        if (path === (mode === "permission" ? f.graph : f.gate + "/slot")) {
          throw mode === "permission"
            ? new Deno.errors.PermissionDenied()
            : new Deno.errors.NotFound();
        }
        return lstat(path);
      };
    }
    if (mode === "deleted") {
      f.io.deleted = () =>
        Promise.resolve({
          workspaceHeldDeletedBytes: NaN,
          sourceHeldDeletedBytes: 0,
        });
    }
    if (mode === "filesystem") {
      f.io.statfs = () =>
        Promise.resolve({ bavail: -1n, bsize: 4096n, ffree: 100n });
    }
    if (mode === "device" || mode === "symlink") {
      f.io.lstat = async (path) => ({
        ...await lstat(path),
        ...(path === f.graph
          ? mode === "device" ? { dev: 2n } : { isSymbolicLink: () => true }
          : {}),
      });
    }
    await rejects(() =>
      observeBackupV2Capacity(f.gate, "cgroup", [f.graph], f.io)
    );
  }
});
