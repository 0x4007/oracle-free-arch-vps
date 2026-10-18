/** Concrete bounded metadata IO only. The managed bootstrap supplies actual
 * gate/boot/lock observation, exact-store credentials and lease orchestration. */
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  BACKUP_V2_PROTECTION_SOURCE_BASE,
  backupV2ProtectionPageName,
  backupV2ProtectionSourceDirectory,
  type BackupV2PruneInput,
  type BackupV2PrunePlanReference,
  parseBackupV2ProtectionManifest,
  validateBackupV2ProtectionDescriptor,
} from "./backup-v2-protection.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";
import { validateBackupV2Gate } from "./backup-v2-runtime-contract.ts";
import type { BackupV2RetentionJournalEntry } from "./backup-v2-retention.ts";
import type { BackupV2SourcePrunerCapabilities } from "./backup-v2-source-pruner.ts";
import { writeBackupV2All } from "./backup-v2-spool.ts";
import { parseBackupV2ObjectName } from "./backup-v2-contract.ts";

type FileInfo = Pick<
  Deno.FileInfo,
  | "isFile"
  | "isDirectory"
  | "isSymlink"
  | "uid"
  | "mode"
  | "nlink"
  | "dev"
  | "ino"
  | "size"
  | "mtime"
  | "ctime"
>;
export interface BackupV2PruneFile {
  stat(): Promise<FileInfo>;
  read(bytes: Uint8Array): Promise<number | null>;
  write(bytes: Uint8Array): Promise<number>;
  sync(): Promise<void>;
  close(): void;
}
/** Injection is for pure fault tests. Production defaults to actual Deno IO. */
export interface BackupV2PruneIO {
  lstat(path: string): Promise<FileInfo>;
  realPath(path: string): Promise<string>;
  mkdir(path: string, options: Deno.MkdirOptions): Promise<void>;
  open(path: string, options: Deno.OpenOptions): Promise<BackupV2PruneFile>;
}
export type BackupV2PruneRuntimeDependencies =
  & Pick<
    BackupV2SourcePrunerCapabilities,
    | "exactStore"
    | "observeFresh"
    | "validateLegacy"
    | "progress"
    | "now"
    | "signal"
  >
  & { io?: BackupV2PruneIO };
export const BACKUP_V2_PRUNE_TRANSACTIONS =
  `${BACKUP_V2_PROTECTION_SOURCE_BASE}/transactions`;
const nativeIO: BackupV2PruneIO = {
  lstat: Deno.lstat,
  realPath: Deno.realPath,
  mkdir: Deno.mkdir,
  open: Deno.open,
};
const encoder = new TextEncoder(),
  decoder = new TextDecoder("utf-8", { fatal: true });
const bytes = (value: unknown) => encoder.encode(JSON.stringify(value) + "\n");
const hash = (value: Uint8Array) =>
  createHash("sha256").update(value).digest("hex");
const canonicalHash = (value: unknown) =>
  hash(
    encoder.encode(JSON.stringify(value, (_key, item) =>
      item && typeof item === "object" && !Array.isArray(item)
        ? Object.fromEntries(
          Object.keys(item).sort().map((key) => [key, item[key]]),
        )
        : item)),
  );
function invalid(): never {
  throw new Error("Backup v2 prune filesystem identity or durability unproved");
}
function uuid(value: unknown): value is string {
  return typeof value === "string" &&
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
}
function sameIdentity(a: FileInfo, b: FileInfo) {
  return a.dev === b.dev && a.ino === b.ino && a.uid === b.uid &&
    a.mode === b.mode;
}
function sameFile(a: FileInfo, b: FileInfo) {
  return sameIdentity(a, b) && a.size === b.size &&
    a.mtime?.getTime() === b.mtime?.getTime() &&
    a.ctime?.getTime() === b.ctime?.getTime();
}
function regular(info: FileInfo) {
  if (
    !info.isFile || info.isSymlink || info.uid !== 0 || info.nlink !== 1 ||
    info.mode === null || (info.mode & 0o777) !== 0o600 ||
    !Number.isSafeInteger(info.dev) || !Number.isSafeInteger(info.ino) ||
    !Number.isSafeInteger(info.size) || info.size < 0
  ) invalid();
}
function reference(value: Uint8Array): BackupV2PrunePlanReference {
  if (!value.length || value.length > BACKUP_V2_LIMITS.journalBytes) invalid();
  const plan = JSON.parse(decoder.decode(value));
  if (
    plan.schemaVersion !== 2 || plan.format !== "backup-v2-retention" ||
    plan.dryRun !== true || !/^[a-f0-9]{64}$/.test(plan.digest)
  ) invalid();
  return { bytes: value.length, sha256: hash(value), digest: plan.digest };
}

export async function createBackupV2PruneRuntime(
  input: BackupV2PruneInput,
  deps: BackupV2PruneRuntimeDependencies,
): Promise<BackupV2SourcePrunerCapabilities> {
  const expected = structuredClone(input),
    gate = validateBackupV2Gate(expected.gate);
  if (
    expected.schemaVersion !== 2 || expected.format !== "backup-v2-prune" ||
    !uuid(expected.transactionId) || gate.kind !== "prune" ||
    gate.state !== "ACTIVE" || !gate.custody ||
    expected.snapshot.custody.sourceBootId !== gate.sourceBootId ||
    expected.snapshot.custody.sourceSettled !== true ||
    !["PLAN", "EXECUTE"].includes(expected.stage) ||
    expected.stage === "PLAN" && expected.plan !== null ||
    expected.stage === "EXECUTE" &&
      (!expected.plan || !/^[a-f0-9]{64}$/.test(expected.plan.sha256) ||
        !/^[a-f0-9]{64}$/.test(expected.plan.digest) ||
        !Number.isSafeInteger(expected.plan.bytes) ||
        expected.plan.bytes <= 0 ||
        expected.plan.bytes > BACKUP_V2_LIMITS.journalBytes)
  ) invalid();
  const io = deps.io ?? nativeIO,
    snapshotSha256 = canonicalHash(expected.snapshot);
  const transaction = expected.transactionId,
    directory = `${BACKUP_V2_PRUNE_TRANSACTIONS}/${transaction}`;
  const planPath = `${directory}/plan.json`,
    journalPath = `${directory}/journal.jsonl`;
  const directories = new Map<string, FileInfo>(),
    immutable = new Map<string, { info: FileInfo; sha256: string }>();
  let poisoned = false, writing = false;
  let planRef: BackupV2PrunePlanReference | undefined = expected.plan ??
    undefined;
  let journal: {
    info: FileInfo;
    sha256: string;
    size: number;
    data: Uint8Array;
  } | undefined;
  const active = () => {
    if (poisoned) invalid();
    deps.signal?.throwIfAborted();
  };
  const fresh = async () => {
    active();
    const observed = structuredClone(await deps.observeFresh()),
      current = validateBackupV2Gate(observed.gate);
    if (
      observed.schemaVersion !== 2 || observed.format !== "backup-v2-prune" ||
      observed.transactionId !== transaction ||
      observed.stage !== expected.stage ||
      !isDeepStrictEqual(observed.plan, expected.plan) ||
      current.kind !== "prune" || current.state !== "ACTIVE" ||
      !isDeepStrictEqual(
        { ...current, updatedAtUtc: gate.updatedAtUtc },
        gate,
      ) || observed.snapshot.custody.sourceBootId !== current.sourceBootId ||
      observed.snapshot.custody.sourceSettled !== true ||
      canonicalHash(observed.snapshot) !== snapshotSha256
    ) invalid();
    return observed;
  };
  const checkDirectory = async (
    path: string,
    strict = true,
  ): Promise<FileInfo> => {
    const info = await io.lstat(path), old = directories.get(path);
    if (
      !info.isDirectory || info.isSymlink || info.uid !== 0 ||
      info.mode === null ||
      (strict ? (info.mode & 0o777) !== 0o700 : (info.mode & 0o022) !== 0) ||
      !Number.isSafeInteger(info.dev) || !Number.isSafeInteger(info.ino) ||
      await io.realPath(path) !== path || old && !sameIdentity(old, info)
    ) invalid();
    if (!old) directories.set(path, structuredClone(info));
    return info;
  };
  const syncDirectory = async (path: string) => {
    const before = await checkDirectory(path),
      file = await io.open(path, { read: true });
    try {
      if (!sameIdentity(before, await file.stat())) invalid();
      await file.sync();
      await checkDirectory(path);
    } finally {
      file.close();
    }
  };
  const ensureDirectory = async (path: string) => {
    await checkDirectory(dirname(path));
    let created = false;
    try {
      await io.mkdir(path, { mode: 0o700 });
      created = true;
    } catch (error) {
      if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
    }
    if (created) await syncDirectory(dirname(path));
    await checkDirectory(path);
  };
  const syncFile = async (path: string, expected: FileInfo) => {
    const file = await io.open(path, { read: true });
    try {
      const before = await file.stat();
      regular(before);
      if (!sameFile(before, expected)) invalid();
      await file.sync();
      if (
        !sameFile(expected, await file.stat()) ||
        !sameFile(expected, await io.lstat(path))
      ) invalid();
      await checkDirectory(dirname(path));
    } finally {
      file.close();
    }
  };
  const read = async (path: string, maximum: number, fixed = true) => {
    active();
    await checkDirectory(dirname(path));
    const before = await io.lstat(path),
      old = fixed ? immutable.get(path) : undefined;
    regular(before);
    if (
      before.size > maximum || await io.realPath(path) !== path ||
      old && !sameFile(old.info, before)
    ) invalid();
    const file = await io.open(path, { read: true });
    try {
      const opened = await file.stat();
      regular(opened);
      if (!sameFile(before, opened)) invalid();
      const data = new Uint8Array(before.size);
      let offset = 0;
      while (offset < data.length) {
        const count = await file.read(data.subarray(offset));
        if (
          !Number.isSafeInteger(count) || !count || count < 0 ||
          count > data.length - offset
        ) invalid();
        offset += count;
      }
      if (await file.read(new Uint8Array(1)) !== null) invalid();
      const after = await file.stat(), named = await io.lstat(path);
      regular(after);
      regular(named);
      if (
        !sameFile(before, after) || !sameFile(before, named) ||
        await io.realPath(path) !== path || old && hash(data) !== old.sha256
      ) invalid();
      await checkDirectory(dirname(path));
      if (fixed && !old) {
        immutable.set(path, {
          info: structuredClone(before),
          sha256: hash(data),
        });
      }
      return { data, info: structuredClone(after) };
    } finally {
      file.close();
    }
  };
  const create = async (path: string, data: Uint8Array) => {
    await checkDirectory(dirname(path));
    let file: BackupV2PruneFile;
    try {
      file = await io.open(path, { createNew: true, write: true, mode: 0o600 });
    } catch (error) {
      if (error instanceof Deno.errors.AlreadyExists) return false;
      throw error;
    }
    try {
      const opened = await file.stat();
      regular(opened);
      if (opened.size !== 0) invalid();
      await writeBackupV2All(file, data);
      await file.sync();
      const after = await file.stat(), named = await io.lstat(path);
      regular(after);
      regular(named);
      if (
        !sameIdentity(opened, after) || !sameFile(after, named) ||
        after.size !== data.length || await io.realPath(path) !== path
      ) invalid();
      await syncDirectory(dirname(path));
    } finally {
      file.close();
    }
    return true;
  };
  const header = (plan: BackupV2PrunePlanReference) => ({
    schemaVersion: 2,
    format: "backup-v2-prune-journal",
    transactionId: transaction,
    snapshotSha256,
    plan,
  });
  const entryValue = (value: unknown): BackupV2RetentionJournalEntry => {
    if (
      !value || typeof value !== "object" || Array.isArray(value) || !planRef
    ) invalid();
    const entry = value as BackupV2RetentionJournalEntry;
    if (
      Object.keys(entry).sort().join(",") !==
        "attempt,fileId,fileName,ordinal,planSha256,state" ||
      entry.planSha256 !== planRef.digest ||
      !Number.isSafeInteger(entry.ordinal) || entry.ordinal < 0 ||
      entry.ordinal >= BACKUP_V2_LIMITS.pruneCandidates ||
      !Number.isSafeInteger(entry.attempt) || entry.attempt < 1 ||
      entry.attempt > 16 || typeof entry.fileId !== "string" || !entry.fileId ||
      entry.fileId.length > BACKUP_V2_LIMITS.descriptorBytes ||
      Array.from(entry.fileId).some((char) =>
        char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127
      ) ||
      !["INTENT", "DELETED", "ABSENT", "PRESENT", "AMBIGUOUS"].includes(
        entry.state,
      )
    ) invalid();
    parseBackupV2ObjectName(entry.fileName);
    return structuredClone(entry);
  };
  const readJournal = async () => {
    if (!planRef) invalid();
    const result = await read(
        journalPath,
        BACKUP_V2_LIMITS.journalBytes,
        false,
      ),
      text = decoder.decode(result.data);
    if (!text.endsWith("\n")) invalid();
    const lines = text.slice(0, -1).split("\n"),
      first = JSON.parse(lines.shift()!);
    if (!isDeepStrictEqual(first, header(planRef))) invalid();
    const entries = lines.map((line): BackupV2RetentionJournalEntry => {
      if (
        !line ||
        encoder.encode(line).length > BACKUP_V2_LIMITS.controlResponseBytes
      ) invalid();
      return entryValue(JSON.parse(line));
    });
    if (
      journal &&
      (!sameFile(journal.info, result.info) ||
        journal.sha256 !== hash(result.data))
    ) invalid();
    await syncFile(journalPath, result.info);
    await syncDirectory(directory);
    journal = {
      info: result.info,
      sha256: hash(result.data),
      size: result.data.length,
      data: result.data,
    };
    return { entries, state: journal };
  };
  await fresh();
  await checkDirectory(dirname(BACKUP_V2_PROTECTION_SOURCE_BASE), false);
  await checkDirectory(BACKUP_V2_PROTECTION_SOURCE_BASE);
  if (expected.stage === "PLAN") {
    await ensureDirectory(BACKUP_V2_PRUNE_TRANSACTIONS);
    await ensureDirectory(directory);
  } else {
    await checkDirectory(BACKUP_V2_PRUNE_TRANSACTIONS);
    await checkDirectory(directory);
  }
  const manifests = new Map<
    string,
    ReturnType<typeof parseBackupV2ProtectionManifest>
  >();
  const ownedTransaction = (value: string) => {
    active();
    if (value !== transaction) invalid();
  };
  return {
    exactStore: deps.exactStore,
    validateLegacy: deps.validateLegacy,
    progress: deps.progress,
    now: deps.now,
    signal: deps.signal,
    observeFresh: fresh,
    async readGraphManifest(value) {
      const descriptor = validateBackupV2ProtectionDescriptor(value),
        path = backupV2ProtectionSourceDirectory(descriptor.manifestSha256);
      await checkDirectory(path);
      const metadata = await read(
        `${path}/descriptor.json`,
        BACKUP_V2_LIMITS.controlResponseBytes,
      );
      if (
        !isDeepStrictEqual(
          validateBackupV2ProtectionDescriptor(
            JSON.parse(decoder.decode(metadata.data)),
          ),
          descriptor,
        )
      ) invalid();
      const result = await read(
        `${path}/manifest.json`,
        descriptor.manifestBytes,
      );
      const manifest = parseBackupV2ProtectionManifest(result.data, descriptor);
      manifests.set(descriptor.manifestSha256, manifest);
      return result.data;
    },
    async readGraphPage(value, page) {
      const descriptor = validateBackupV2ProtectionDescriptor(value),
        manifest = manifests.get(descriptor.manifestSha256);
      if (
        !manifest || !isDeepStrictEqual(manifest.root, descriptor.root) ||
        !isDeepStrictEqual(manifest.pages[page.pageIndex], page)
      ) invalid();
      const result = await read(
        `${backupV2ProtectionSourceDirectory(descriptor.manifestSha256)}/${
          backupV2ProtectionPageName(page.pageIndex)
        }`,
        page.bytes,
      );
      if (
        result.data.length !== page.bytes || hash(result.data) !== page.sha256
      ) invalid();
      return result.data;
    },
    async readPlan(tx, ref) {
      ownedTransaction(tx);
      if (planRef && !isDeepStrictEqual(planRef, ref)) invalid();
      const result = await read(planPath, BACKUP_V2_LIMITS.journalBytes);
      if (!isDeepStrictEqual(reference(result.data), ref)) invalid();
      planRef = ref;
      return result.data;
    },
    async writePlanDurable(tx, data) {
      ownedTransaction(tx);
      if (expected.stage !== "PLAN" || writing) invalid();
      writing = true;
      try {
        await fresh();
        const ref = reference(data);
        const newPlan = await create(planPath, data);
        const saved = await read(planPath, data.length);
        if (
          hash(saved.data) !== ref.sha256 || saved.data.length !== ref.bytes
        ) invalid();
        planRef = ref;
        await syncFile(planPath, saved.info);
        await syncDirectory(directory);
        if (newPlan) await create(journalPath, bytes(header(ref)));
        await readJournal();
      } catch (error) {
        poisoned = true;
        throw error;
      } finally {
        writing = false;
      }
    },
    async loadJournal(tx) {
      ownedTransaction(tx);
      return (await readJournal()).entries;
    },
    async appendDurable(tx, entry) {
      ownedTransaction(tx);
      if (
        expected.stage !== "EXECUTE" || writing || !journal || !planRef ||
        entry.planSha256 !== planRef.digest
      ) invalid();
      writing = true;
      try {
        await fresh();
        const prior = (await readJournal()).state;
        const encoded = bytes(entryValue(entry));
        if (prior.size + encoded.length > BACKUP_V2_LIMITS.journalBytes) {
          invalid();
        }
        const expectedHash = createHash("sha256").update(prior.data).update(
          encoded,
        ).digest("hex");
        const file = await io.open(journalPath, { write: true, append: true });
        try {
          const before = await file.stat();
          regular(before);
          if (!sameFile(before, prior.info)) invalid();
          await writeBackupV2All(file, encoded);
          await file.sync();
          const after = await file.stat(), named = await io.lstat(journalPath);
          regular(after);
          regular(named);
          if (
            !sameIdentity(before, after) ||
            after.size !== before.size + encoded.length ||
            !sameFile(after, named) ||
            await io.realPath(journalPath) !== journalPath
          ) invalid();
          await checkDirectory(directory);
          journal = undefined;
        } finally {
          file.close();
        }
        if ((await readJournal()).state.sha256 !== expectedHash) invalid();
      } catch (error) {
        poisoned = true;
        throw error;
      } finally {
        writing = false;
      }
    },
  };
}
