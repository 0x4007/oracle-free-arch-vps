import { createHash } from "node:crypto";
import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  BACKUP_V2_LIMITS,
  BACKUP_V2_PROFILE_ID,
} from "../scripts/backup-v2-profile.ts";
import { backupV2ObjectName } from "../scripts/backup-v2-contract.ts";
import {
  BACKUP_V2_PROTECTION_SOURCE_BASE,
  type BackupV2PruneInput,
  buildBackupV2Protection,
} from "../scripts/backup-v2-protection.ts";
import {
  type BackupV2Request,
  backupV2RequestSha256,
  validateBackupV2Gate,
} from "../scripts/backup-v2-runtime-contract.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import {
  BACKUP_V2_PRUNE_TRANSACTIONS,
  type BackupV2PruneFile,
  type BackupV2PruneIO,
  type BackupV2PruneRuntimeDependencies,
  createBackupV2PruneRuntime,
} from "../scripts/backup-v2-prune-runtime.ts";

function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
async function rejects(run: () => unknown) {
  let failed = false;
  try {
    await run();
  } catch {
    failed = true;
  }
  assert(failed);
}
type Info = Awaited<ReturnType<BackupV2PruneIO["lstat"]>>;
type Node = { info: Info; data: Uint8Array };
class MemoryIO implements BackupV2PruneIO {
  nodes = new Map<string, Node>();
  opened = 0;
  closed = 0;
  tick = 1;
  failSync: string | null = null;
  swapOnOpen: string | null = null;
  zeroWrite = false;
  short = 7;
  constructor() {
    this.dir(dirname(BACKUP_V2_PROTECTION_SOURCE_BASE), 0o755);
    this.dir(BACKUP_V2_PROTECTION_SOURCE_BASE);
  }
  info(isDirectory: boolean, mode: number): Info {
    return {
      isDirectory,
      isFile: !isDirectory,
      isSymlink: false,
      uid: 0,
      mode,
      nlink: isDirectory ? 2 : 1,
      dev: 1,
      ino: this.tick++,
      size: 0,
      mtime: new Date(this.tick),
      ctime: new Date(this.tick),
    };
  }
  dir(path: string, mode = 0o700) {
    this.nodes.set(path, {
      info: this.info(true, mode),
      data: new Uint8Array(),
    });
  }
  file(path: string, bytes: Uint8Array) {
    const info = this.info(false, 0o600);
    info.size = bytes.length;
    this.nodes.set(path, { info, data: bytes.slice() });
  }
  lstat(path: string) {
    const node = this.nodes.get(path);
    if (!node) throw new Deno.errors.NotFound("missing fixture");
    return Promise.resolve(structuredClone(node.info));
  }
  async realPath(path: string) {
    if ((await this.lstat(path)).isSymlink) return "/foreign";
    return path;
  }
  mkdir(path: string) {
    if (this.nodes.has(path)) throw new Deno.errors.AlreadyExists();
    assert(this.nodes.has(dirname(path)));
    this.dir(path);
    this.nodes.get(dirname(path))!.info.nlink!++;
    return Promise.resolve();
  }
  open(
    path: string,
    options: Deno.OpenOptions,
  ): Promise<BackupV2PruneFile> {
    if (this.swapOnOpen === path) {
      this.swapOnOpen = null;
      this.nodes.get(path)!.info.ino = this.tick++;
    }
    let node = this.nodes.get(path);
    if (options.createNew) {
      if (node) throw new Deno.errors.AlreadyExists();
      this.file(path, new Uint8Array());
      node = this.nodes.get(path);
    }
    if (!node) throw new Deno.errors.NotFound("missing fixture");
    const target = node;
    let offset = 0, closed = false;
    this.opened++;
    return Promise.resolve({
      stat: () => Promise.resolve(structuredClone(target.info)),
      read: (bytes) => {
        if (closed) throw Error("closed");
        if (offset >= target.data.length) return Promise.resolve(null);
        const size = Math.min(
          bytes.length,
          this.short,
          target.data.length - offset,
        );
        bytes.set(target.data.subarray(offset, offset + size));
        offset += size;
        return Promise.resolve(size);
      },
      write: (bytes) => {
        if (closed) throw Error("closed");
        if (this.zeroWrite) return Promise.resolve(0);
        const size = Math.min(bytes.length, this.short),
          start = options.append ? target.data.length : offset,
          data = new Uint8Array(Math.max(target.data.length, start + size));
        data.set(target.data);
        data.set(bytes.subarray(0, size), start);
        target.data = data;
        offset = start + size;
        target.info.size = data.length;
        target.info.mtime = target.info.ctime = new Date(++this.tick);
        return Promise.resolve(size);
      },
      sync: () =>
        this.failSync === path
          ? Promise.reject(Error("fsync failed"))
          : Promise.resolve(),
      close: () => {
        assert(!closed);
        closed = true;
        this.closed++;
      },
    });
  }
}
const id = (value: number) =>
  `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`;
const H = "a".repeat(64), utc = "2026-10-18T01:00:00.000Z";
const bytes = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value) + "\n");
const hash = (value: Uint8Array) =>
  createHash("sha256").update(value).digest("hex");
function fixture() {
  const request: BackupV2Request = {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    jobId: `job-${id(1)}`,
    captureId: `generation-${id(1)}`,
    periodKey: "2026-10-18",
    requestedAtUtc: utc,
    sourceRevision: "b".repeat(40),
    sourceConfigSha256: H,
    recipientSha256: H,
    recipientFingerprint: "A".repeat(40),
  };
  const unitName = `arch-vps-b2-v2-prune-${id(1)}-${id(2)}.service`;
  const gate = validateBackupV2Gate({
    schemaVersion: 2,
    format: "backup-v2",
    owner: GATE_OWNER,
    envelope: { request, requestSha256: backupV2RequestSha256(request) },
    gateId: id(2),
    sourceBootId: id(3),
    kind: "prune",
    unitName,
    custody: {
      unitName,
      invocationId: "c".repeat(32),
      mainPid: 100,
      mainStartTicks: "200",
      cgroup: `${GATE_BACKUP_CGROUP_ROOT}/${unitName}`,
    },
    state: "ACTIVE",
    remoteHost: GATE_REMOTE_HOST,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    createdAtUtc: utc,
    updatedAtUtc: utc,
  });
  const object = {
    fileId: "data-1",
    fileName: backupV2ObjectName(request.captureId, id(4), "data", 0, id(5)),
    contentLength: 1,
    contentSha1: "d".repeat(40),
    sha256: H,
    uploadTimestamp: 1,
    action: "upload" as const,
  };
  const root = {
    object: {
      ...object,
      fileId: "manifest-1",
      fileName: backupV2ObjectName(
        request.captureId,
        id(4),
        "manifest",
        0,
        id(6),
      ),
    },
    plaintextSha256: H,
  };
  const bundle = buildBackupV2Protection(root, [object]),
    graph =
      `${BACKUP_V2_PROTECTION_SOURCE_BASE}/${bundle.descriptor.manifestSha256}`,
    io = new MemoryIO();
  io.dir(graph);
  io.file(`${graph}/descriptor.json`, bytes(bundle.descriptor));
  io.file(`${graph}/manifest.json`, bundle.manifestBytes);
  io.file(`${graph}/page-00000000.json`, bundle.pages[0].bytes);
  const input: BackupV2PruneInput = {
    schemaVersion: 2,
    format: "backup-v2-prune",
    gate,
    transactionId: id(7),
    stage: "PLAN",
    plan: null,
    snapshot: {
      custody: {
        lockId: id(7),
        sourceBootId: gate.sourceBootId,
        sourceSettled: true,
      },
      catalog: [],
      protection: {
        acceptedRoots: [],
        activeObjects: [],
        sealedRoleManifests: [],
        unresolvedPuts: [],
      },
      receipts: [],
    },
    graphs: [bundle.descriptor],
  };
  const body = {
    schemaVersion: 2,
    format: "backup-v2-retention",
    dryRun: true,
    preconditionSha256: H,
    retainedCaptureIds: [1, 2, 3, 4].map((value) => `generation-${id(value)}`),
    obsoleteLegacyCaptureIds: [],
    candidates: [object],
  };
  const plan = bytes({ ...body, digest: H }),
    ref = { sha256: hash(plan), bytes: plan.length, digest: H },
    directory = `${BACKUP_V2_PRUNE_TRANSACTIONS}/${input.transactionId}`;
  const deps: BackupV2PruneRuntimeDependencies = {
    io,
    exactStore: {
      versionsPage: () => Promise.reject(Error("provider prohibited")),
      reconcileExact: () => Promise.reject(Error("provider prohibited")),
      removeExact: () => Promise.reject(Error("provider prohibited")),
    },
    observeFresh: () => Promise.resolve(structuredClone(input)),
    validateLegacy: () => {
      throw Error("unused fixture seam");
    },
    progress: () => Promise.resolve(),
    now: () => new Date(utc),
  };
  const intent = {
    planSha256: H,
    ordinal: 0,
    fileId: object.fileId,
    fileName: object.fileName,
    attempt: 1,
    state: "INTENT" as const,
  };
  const publish = async () => {
    const caps = await createBackupV2PruneRuntime(input, deps);
    await caps.writePlanDurable(input.transactionId, plan);
    return caps;
  };
  const execute = async () => {
    input.stage = "EXECUTE";
    input.plan = ref;
    return await createBackupV2PruneRuntime(input, deps);
  };
  return {
    input,
    deps,
    io,
    graph,
    directory,
    object,
    bundle,
    plan,
    ref,
    intent,
    publish,
    execute,
  };
}

Deno.test("prune runtime reads exact root metadata and durably creates a genuine empty transaction journal", async () => {
  const f = fixture(), caps = await f.publish();
  assert(
    isDeepStrictEqual(
      await caps.readGraphManifest(f.bundle.descriptor),
      f.bundle.manifestBytes,
    ),
  );
  assert(
    isDeepStrictEqual(
      await caps.readGraphPage(f.bundle.descriptor, f.bundle.manifest.pages[0]),
      f.bundle.pages[0].bytes,
    ),
  );
  assert(
    isDeepStrictEqual(
      await caps.readPlan(f.input.transactionId, f.ref),
      f.plan,
    ),
  );
  assert((await caps.loadJournal(f.input.transactionId)).length === 0);
  assert(
    f.io.opened === f.io.closed &&
      f.io.nodes.get(`${f.directory}/plan.json`)!.info.mode === 0o600,
  );
});
Deno.test("prune runtime rejects wrong mode owner symlink oversized metadata and inode replacement before read", async () => {
  for (const kind of ["mode", "uid", "symlink", "size", "inode"] as const) {
    const f = fixture(),
      caps = await f.publish(),
      path = `${f.graph}/descriptor.json`,
      node = f.io.nodes.get(path)!;
    if (kind === "mode") node.info.mode = 0o644;
    if (kind === "uid") node.info.uid = 1000;
    if (kind === "symlink") node.info.isSymlink = true;
    if (kind === "size") {
      node.info.size = BACKUP_V2_LIMITS.controlResponseBytes + 1;
    }
    if (kind === "inode") f.io.swapOnOpen = path;
    await rejects(() => caps.readGraphManifest(f.bundle.descriptor));
    assert(f.io.opened === f.io.closed);
  }
});
Deno.test("prune runtime binds directory identities and descriptor/manifest/page hashes without a fallback", async () => {
  const f = fixture(), caps = await f.publish();
  await caps.readGraphManifest(f.bundle.descriptor);
  f.io.nodes.get(`${f.graph}/page-00000000.json`)!.data[0] ^= 1;
  await rejects(() =>
    caps.readGraphPage(f.bundle.descriptor, f.bundle.manifest.pages[0])
  );
  const g = fixture(), other = await g.publish();
  await other.readGraphManifest(g.bundle.descriptor);
  g.io.nodes.get(g.graph)!.info.ino = 99999;
  await rejects(() =>
    other.readGraphPage(g.bundle.descriptor, g.bundle.manifest.pages[0])
  );
  const h = fixture(), missing = await h.publish();
  h.io.nodes.delete(`${h.graph}/manifest.json`);
  await rejects(() => missing.readGraphManifest(h.bundle.descriptor));
});
Deno.test("prune runtime refuses plan rewrite, missing EXECUTE evidence and cross-snapshot journal adoption", async () => {
  const f = fixture(), caps = await f.publish();
  const changed = f.plan.slice();
  changed[changed.length - 2] ^= 1;
  await rejects(() => caps.writePlanDurable(f.input.transactionId, changed));
  assert(
    isDeepStrictEqual(f.io.nodes.get(`${f.directory}/plan.json`)!.data, f.plan),
  );
  const g = fixture();
  await rejects(() => g.execute());
  const missingJournal = fixture();
  await missingJournal.publish();
  missingJournal.io.nodes.delete(`${missingJournal.directory}/journal.jsonl`);
  const retry = await createBackupV2PruneRuntime(
    missingJournal.input,
    missingJournal.deps,
  );
  await rejects(() =>
    retry.writePlanDurable(
      missingJournal.input.transactionId,
      missingJournal.plan,
    )
  );
  assert(
    !missingJournal.io.nodes.has(`${missingJournal.directory}/journal.jsonl`),
  );
  const h = fixture();
  await h.publish();
  h.input.snapshot.custody.lockId = id(99);
  const altered = await h.execute();
  await altered.readPlan(h.input.transactionId, h.ref);
  await rejects(() => altered.loadJournal(h.input.transactionId));
});
Deno.test("prune runtime persists exact journal records and replays them across distinct managed phase gates", async () => {
  const f = fixture();
  await f.publish();
  f.input.gate = { ...f.input.gate, gateId: id(8) };
  const caps = await f.execute();
  await caps.readPlan(f.input.transactionId, f.ref);
  await caps.loadJournal(f.input.transactionId);
  await caps.appendDurable(f.input.transactionId, f.intent);
  await caps.appendDurable(f.input.transactionId, {
    ...f.intent,
    state: "AMBIGUOUS",
  });
  const resumed = await createBackupV2PruneRuntime(f.input, f.deps);
  await resumed.readPlan(f.input.transactionId, f.ref);
  assert((await resumed.loadJournal(f.input.transactionId)).length === 2);
  assert(f.io.opened === f.io.closed);
});
Deno.test("prune runtime poisons uncertain writes on fsync/zero progress and never deletes partial metadata", async () => {
  const f = fixture();
  f.io.failSync = `${f.directory}/plan.json`;
  await rejects(() => f.publish());
  assert(
    f.io.nodes.has(`${f.directory}/plan.json`) && f.io.opened === f.io.closed,
  );
  const g = fixture();
  g.io.zeroWrite = true;
  await rejects(() => g.publish());
  assert(
    g.io.nodes.has(`${g.directory}/plan.json`) && g.io.opened === g.io.closed,
  );
  const h = fixture();
  await h.publish();
  const caps = await h.execute();
  await caps.readPlan(h.input.transactionId, h.ref);
  await caps.loadJournal(h.input.transactionId);
  h.io.failSync = `${h.directory}/journal.jsonl`;
  await rejects(() => caps.appendDurable(h.input.transactionId, h.intent));
  h.io.failSync = null;
  await rejects(() => caps.appendDurable(h.input.transactionId, h.intent));
  assert(
    h.io.nodes.has(`${h.directory}/journal.jsonl`) &&
      h.io.opened === h.io.closed,
  );
});
Deno.test("prune runtime rejects fresh custody/boot/lock drift and unexpected journal mutation", async () => {
  const f = fixture();
  f.deps.observeFresh = () =>
    Promise.resolve({
      ...f.input,
      gate: { ...f.input.gate, sourceBootId: id(99) },
    });
  await rejects(() => createBackupV2PruneRuntime(f.input, f.deps));
  const g = fixture();
  await g.publish();
  const caps = await g.execute();
  await caps.readPlan(g.input.transactionId, g.ref);
  await caps.loadJournal(g.input.transactionId);
  const header = g.io.nodes.get(`${g.directory}/journal.jsonl`)!;
  header.data[0] ^= 1;
  await rejects(() => caps.appendDurable(g.input.transactionId, g.intent));
  const h = fixture();
  await h.publish();
  const check = await h.execute();
  await check.readPlan(h.input.transactionId, h.ref);
  await check.loadJournal(h.input.transactionId);
  h.input.snapshot.custody.lockId = id(99);
  await rejects(() => check.appendDurable(h.input.transactionId, h.intent));
});

/** Operator-only bounded native entry. Supply a genuine ACTIVE managed PLAN
 * gate and owned fixture graph/transaction; call again after changing only the
 * owned fixture's mode/uid/symlink to prove rejection. No provider method is used. */
export async function exerciseNativePruneRuntime(
  input: BackupV2PruneInput,
  deps: BackupV2PruneRuntimeDependencies,
  plan: Uint8Array,
) {
  if (
    deps.io || input.stage !== "PLAN" || plan.length > 65536 ||
    input.graphs.length > 2
  ) throw Error("Bounded native fixture scope required");
  const caps = await createBackupV2PruneRuntime(input, deps);
  let count = 0;
  for (const descriptor of input.graphs) {
    const manifest = JSON.parse(
      new TextDecoder().decode(await caps.readGraphManifest(descriptor)),
    );
    if (manifest.pages.length > 2) throw Error("Bounded native pages required");
    for (const page of manifest.pages) {
      await caps.readGraphPage(descriptor, page);
      count++;
    }
  }
  await caps.writePlanDurable(input.transactionId, plan);
  const value = JSON.parse(new TextDecoder().decode(plan)),
    ref = { bytes: plan.length, sha256: hash(plan), digest: value.digest };
  assert(
    isDeepStrictEqual(await caps.readPlan(input.transactionId, ref), plan),
  );
  assert((await caps.loadJournal(input.transactionId)).length === 0);
  return {
    state: "NATIVE_METADATA_CALLBACKS_PROVED",
    pages: count,
    planSha256: ref.sha256,
    cloudWrites: 0,
    archivePayloadBytes: 0,
  };
}
