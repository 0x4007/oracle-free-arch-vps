import { createHash } from "node:crypto";
import {
  type BackupV2SealedSlot,
  validateBackupV2SealedSlot,
} from "./backup-v2-contract.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";

export interface BackupV2SlotWriter {
  write(bytes: Uint8Array): Promise<number>;
  sync(): Promise<void>;
  close(): void;
}
/** A narrow filesystem boundary. Production uses the guarded adapter below. */
export interface BackupV2SpoolStorage {
  create(index: 0 | 1): Promise<BackupV2SlotWriter>;
  seal(
    index: 0 | 1,
    expected: { bytes: number; sha1: string; sha256: string },
  ): Promise<BackupV2SealedSlot>;
  read(
    slot: BackupV2SealedSlot,
    consume: (bytes: Uint8Array) => void | Promise<void>,
  ): Promise<void>;
  remove(slot: BackupV2SealedSlot): Promise<void>;
  removeEmpty(index: 0 | 1): Promise<void>;
}
function invalid(): never {
  throw new Error("Backup v2 spool identity or progress is invalid");
}
function sameSlot(left: unknown, right: BackupV2SealedSlot): boolean {
  return JSON.stringify(validateBackupV2SealedSlot(left)) ===
    JSON.stringify(validateBackupV2SealedSlot(right));
}
export async function writeBackupV2All(
  writer: Pick<BackupV2SlotWriter, "write">,
  bytes: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    const count = await writer.write(bytes.subarray(offset));
    if (
      !Number.isSafeInteger(count) || count <= 0 ||
      count > bytes.length - offset
    ) invalid();
    offset += count;
  }
}
export interface BackupV2Directory {
  path: string;
  device: number;
  inode: number;
}
export async function assertBackupV2Directory(
  path: string,
  expected?: BackupV2Directory,
): Promise<BackupV2Directory> {
  const info = await Deno.lstat(path);
  if (
    !info.isDirectory || info.isSymlink || info.uid !== 0 ||
    info.mode === null || (info.mode & 0o777) !== 0o700 ||
    info.dev === null || info.ino === null || !Number.isSafeInteger(info.dev) ||
    !Number.isSafeInteger(info.ino) || await Deno.realPath(path) !== path
  ) invalid();
  const result = { path, device: info.dev, inode: info.ino };
  if (
    expected &&
    (expected.path !== path || expected.device !== info.dev ||
      expected.inode !== info.ino)
  ) invalid();
  return result;
}
export async function syncBackupV2Directory(path: string): Promise<void> {
  const directory = await Deno.open(path, { read: true });
  try {
    await directory.sync();
  } finally {
    directory.close();
  }
}
function regular(info: Deno.FileInfo): void {
  if (
    !info.isFile || info.isSymlink || info.uid !== 0 || info.mode === null ||
    (info.mode & 0o777) !== 0o600 || info.nlink !== 1 || info.dev === null ||
    info.ino === null
  ) invalid();
}

/** Exactly two named files; no existing file is replaced or silently discarded. */
export async function createBackupV2FileSpoolStorage(
  path: string,
): Promise<BackupV2SpoolStorage> {
  const directory = await assertBackupV2Directory(path);
  for await (const _entry of Deno.readDir(path)) invalid();
  const created = new Map<number, Deno.FileInfo>();
  const filename = (index: number) => `${path}/slot-${index}.cipher`;
  const check = async (index: number, expected?: BackupV2SealedSlot) => {
    await assertBackupV2Directory(path, directory);
    const file = filename(index),
      info = await Deno.lstat(file),
      original = created.get(index);
    regular(info);
    if (
      await Deno.realPath(file) !== file || !original ||
      info.dev !== original.dev || info.ino !== original.ino
    ) invalid();
    if (
      expected &&
      (expected.path !== file || expected.device !== info.dev ||
        expected.inode !== info.ino || expected.bytes !== info.size)
    ) invalid();
    return info;
  };
  const storage: BackupV2SpoolStorage = {
    async create(index) {
      await assertBackupV2Directory(path, directory);
      const handle = await Deno.open(filename(index), {
        createNew: true,
        write: true,
        mode: 0o600,
      });
      try {
        const info = await handle.stat();
        regular(info);
        created.set(index, info);
        return handle;
      } catch (error) {
        handle.close();
        throw error;
      }
    },
    async seal(index, expected) {
      const info = await check(index);
      if (info.size !== expected.bytes) invalid();
      const slot = validateBackupV2SealedSlot({
        index,
        path: filename(index),
        device: info.dev,
        inode: info.ino,
        ...expected,
        uid: 0,
        mode: 384,
        links: 1,
      });
      await storage.read(slot, () => {});
      await syncBackupV2Directory(path);
      return slot;
    },
    async read(slot, consume) {
      validateBackupV2SealedSlot(slot);
      await check(slot.index, slot);
      const handle = await Deno.open(slot.path, { read: true });
      const sha1 = createHash("sha1"), sha256 = createHash("sha256");
      let total = 0;
      try {
        const info = await handle.stat();
        regular(info);
        if (
          info.dev !== slot.device || info.ino !== slot.inode ||
          info.size !== slot.bytes
        ) invalid();
        const buffer = new Uint8Array(64 * 1024);
        while (true) {
          const count = await handle.read(buffer);
          if (count === null) break;
          if (count <= 0 || total + count > slot.bytes) invalid();
          const bytes = buffer.subarray(0, count);
          sha1.update(bytes);
          sha256.update(bytes);
          total += count;
          await consume(bytes);
        }
        if (
          total !== slot.bytes || sha1.digest("hex") !== slot.sha1 ||
          sha256.digest("hex") !== slot.sha256
        ) invalid();
        await check(slot.index, slot);
        const after = await handle.stat();
        if (
          after.dev !== slot.device || after.ino !== slot.inode ||
          after.size !== slot.bytes
        ) invalid();
      } finally {
        handle.close();
      }
    },
    async remove(slot) {
      await storage.read(slot, () => {});
      await check(slot.index, slot);
      await Deno.remove(slot.path);
      await syncBackupV2Directory(path);
      created.delete(slot.index);
    },
    async removeEmpty(index) {
      const info = await check(index);
      if (info.size !== 0) invalid();
      await Deno.remove(filename(index));
      await syncBackupV2Directory(path);
      created.delete(index);
    },
  };
  return storage;
}

/** One producer, two live slots. A failed attempt remains unusable and intact. */
export class BackupV2Spool {
  private slots: ("free" | "writing" | BackupV2SealedSlot)[] = ["free", "free"];
  private waiters: (() => void)[] = [];
  private failure: unknown;
  private reader?: ReadableStreamDefaultReader<Uint8Array>;
  private producing = false;
  constructor(
    readonly storage: BackupV2SpoolStorage,
    readonly chunkBytes: number = BACKUP_V2_LIMITS.slotBytes,
  ) {
    if (
      !Number.isSafeInteger(chunkBytes) || chunkBytes <= 0 ||
      chunkBytes > BACKUP_V2_LIMITS.slotBytes
    ) invalid();
  }
  private check(): void {
    if (this.failure !== undefined) throw this.failure;
  }
  private async acquire(): Promise<0 | 1> {
    while (true) {
      this.check();
      const index = this.slots.indexOf("free");
      if (index >= 0) {
        this.slots[index] = "writing";
        return index as 0 | 1;
      }
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
  }
  async abort(reason: unknown): Promise<void> {
    this.failure ??= reason instanceof Error
      ? reason
      : new Error("Backup v2 spool aborted");
    this.waiters.splice(0).forEach((wake) => wake());
    try {
      await this.reader?.cancel(this.failure);
    } catch { /* Preserve original failure. */ }
  }
  async read(
    slot: BackupV2SealedSlot,
    consume: (bytes: Uint8Array) => void | Promise<void>,
  ): Promise<void> {
    if (!sameSlot(this.slots[slot.index], slot)) {
      invalid();
    }
    await this.storage.read(slot, consume);
  }
  /** Caller must have durably journaled exact remote readback before reclaim. */
  async reclaim(slot: BackupV2SealedSlot): Promise<void> {
    if (!sameSlot(this.slots[slot.index], slot)) {
      invalid();
    }
    await this.storage.remove(slot);
    this.slots[slot.index] = "free";
    this.waiters.splice(0).forEach((wake) => wake());
  }
  async *sealed(
    source: ReadableStream<Uint8Array>,
  ): AsyncGenerator<BackupV2SealedSlot> {
    if (this.producing) invalid();
    this.check();
    this.producing = true;
    const reader = source.getReader();
    this.reader = reader;
    let pending: Uint8Array = new Uint8Array(), cursor = 0, done = false;
    let writer: BackupV2SlotWriter | undefined;
    try {
      while (!done) {
        const index = await this.acquire();
        writer = await this.storage.create(index);
        const sha1 = createHash("sha1"), sha256 = createHash("sha256");
        let total = 0;
        while (total < this.chunkBytes) {
          this.check();
          if (cursor === pending.length) {
            const next = await reader.read();
            this.check();
            if (next.done) {
              done = true;
              break;
            }
            if (
              !(next.value instanceof Uint8Array) || next.value.length === 0
            ) invalid();
            pending = next.value;
            cursor = 0;
          }
          const bytes = pending.subarray(
            cursor,
            cursor + Math.min(this.chunkBytes - total, pending.length - cursor),
          );
          await writeBackupV2All(writer, bytes);
          sha1.update(bytes);
          sha256.update(bytes);
          total += bytes.length;
          cursor += bytes.length;
        }
        await writer.sync();
        writer.close();
        writer = undefined;
        if (total === 0) {
          await this.storage.removeEmpty(index);
          this.slots[index] = "free";
          break;
        }
        const slot = await this.storage.seal(index, {
          bytes: total,
          sha1: sha1.digest("hex"),
          sha256: sha256.digest("hex"),
        });
        this.slots[index] = slot;
        yield slot;
      }
    } catch (error) {
      await this.abort(error);
      throw error;
    } finally {
      writer?.close();
      if (!done) {
        try {
          await reader.cancel();
        } catch { /* Caller owns native tree settlement. */ }
      }
      reader.releaseLock();
      this.reader = undefined;
      this.producing = false;
    }
  }
}
