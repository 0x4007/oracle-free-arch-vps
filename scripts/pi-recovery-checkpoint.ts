/** Small acknowledged control records over SSH; never a backup payload channel.
 * The Pi caller must hold the existing controller lock for the whole session.
 */
import { createHash } from "node:crypto";
import { type RestoreJournal, STAGES } from "./backblaze-machine-restore.ts";
import { readPrivateJson, writePrivateJson } from "./oci.ts";

export const CHECKPOINT_LIMIT = 64 * 1024;
export interface CheckpointBinding {
  requestId: string;
  instanceId: string;
  bootId: string;
  generation: string;
  indexSha256: string;
  bootDiskPath: string;
  rootDiskPath: string;
  bootDiskSerial: string;
  rootDiskSerial: string;
}
export interface RecoveryCheckpoint {
  kind: "recovery-checkpoint";
  binding: CheckpointBinding;
  journal: RestoreJournal;
  sha256: string;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${
      Object.keys(record).sort().map((key) =>
        `${JSON.stringify(key)}:${canonical(record[key])}`
      ).join(",")
    }}`;
  }
  return JSON.stringify(value);
}
function hash(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}
function assertBinding(binding: CheckpointBinding): void {
  const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
  if (
    !binding || !uuid.test(binding.requestId?.replace(/^recovery-/, "")) ||
    !binding.requestId.startsWith("recovery-") ||
    !/^ocid1\.instance\.[a-zA-Z0-9.]+$/.test(binding.instanceId) ||
    !uuid.test(binding.bootId) ||
    !/^generation-[0-9a-f-]{36}$/.test(binding.generation) ||
    !/^[0-9a-f]{64}$/.test(binding.indexSha256) ||
    ![binding.bootDiskPath, binding.rootDiskPath].every((path) =>
      /^\/dev\/disk\/by-id\/(?:virtio|scsi)-[A-Za-z0-9_.+:-]+$/.test(path)
    ) ||
    ![binding.bootDiskSerial, binding.rootDiskSerial].every((serial) =>
      typeof serial === "string" && /^[A-Za-z0-9_.+:-]+$/.test(serial)
    ) || binding.bootDiskPath === binding.rootDiskPath ||
    binding.bootDiskSerial === binding.rootDiskSerial
  ) throw Error("Checkpoint binding is invalid");
}
function assertJournal(journal: RestoreJournal, binding: CheckpointBinding) {
  if (
    !journal || journal.schemaVersion !== 2 ||
    journal.targetId !== binding.instanceId ||
    journal.architecture !== "aarch64" ||
    journal.bootDiskBytes !== 50 * 1024 ** 3 ||
    journal.rootDiskBytes !== 150 * 1024 ** 3 ||
    ![
      "generation",
      "indexSha256",
      "bootDiskPath",
      "rootDiskPath",
      "bootDiskSerial",
      "rootDiskSerial",
    ].every((key) =>
      journal[key as keyof RestoreJournal] ===
        binding[key as keyof CheckpointBinding]
    ) ||
    !Array.isArray(journal.completedStages) ||
    journal.completedStages.length < 1 ||
    journal.completedStages.length > STAGES.length ||
    !journal.completedStages.every((stage, index) => stage === STAGES[index]) ||
    !Number.isFinite(Date.parse(journal.startedAtUtc)) ||
    !Number.isFinite(Date.parse(journal.updatedAtUtc))
  ) throw Error("Checkpoint journal binding or stages differ");
}
export function makeCheckpoint(
  binding: CheckpointBinding,
  journal: RestoreJournal,
): RecoveryCheckpoint {
  assertBinding(binding);
  assertJournal(journal, binding);
  const body = { kind: "recovery-checkpoint" as const, binding, journal };
  const result = { ...body, sha256: hash(body) };
  if (
    new TextEncoder().encode(JSON.stringify(result)).length >= CHECKPOINT_LIMIT
  ) {
    throw Error("Checkpoint exceeds control-record bound");
  }
  return structuredClone(result);
}
function validateCheckpoint(
  value: RecoveryCheckpoint,
  binding: CheckpointBinding,
): RecoveryCheckpoint {
  if (
    !value || value.kind !== "recovery-checkpoint" ||
    hash(value.binding) !== hash(binding)
  ) {
    throw Error("Checkpoint request, target or RAM boot differs");
  }
  const expected = makeCheckpoint(binding, value.journal);
  if (value.sha256 !== expected.sha256) throw Error("Checkpoint hash differs");
  return expected;
}
function immutableJournal(journal: RestoreJournal): string {
  const { completedStages: _stages, updatedAtUtc: _updated, ...immutable } =
    journal;
  return hash(immutable);
}

/** A poisoned/closed channel cannot be reused after a timeout or malformed line.
 * Reads are cancelled on timeout so there is no abandoned read consuming an ack.
 */
export class CheckpointChannel {
  #reader: ReadableStreamDefaultReader<Uint8Array>;
  #writer: WritableStreamDefaultWriter<Uint8Array>;
  #pending = new Uint8Array(0);
  #closed = false;
  constructor(
    input: ReadableStream<Uint8Array>,
    output: WritableStream<Uint8Array>,
    readonly timeoutMs = 30_000,
  ) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw Error("Invalid checkpoint timeout");
    }
    this.#reader = input.getReader();
    this.#writer = output.getWriter();
  }
  async #bounded<T>(operation: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(Error("Checkpoint exchange timed out")),
            this.timeoutMs,
          );
        }),
      ]);
    } catch (error) {
      await this.close();
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
  async send(value: unknown): Promise<void> {
    if (this.#closed) throw Error("Checkpoint channel is closed");
    const bytes = new TextEncoder().encode(`${JSON.stringify(value)}\n`);
    if (bytes.length > CHECKPOINT_LIMIT) {
      throw Error("Checkpoint exceeds control-record bound");
    }
    await this.#bounded(this.#writer.write(bytes));
  }
  async receive(): Promise<unknown> {
    if (this.#closed) throw Error("Checkpoint channel is closed");
    return await this.#bounded((async () => {
      while (true) {
        const newline = this.#pending.indexOf(10);
        if (newline >= 0) {
          const line = this.#pending.slice(0, newline);
          this.#pending = this.#pending.slice(newline + 1);
          return JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(line),
          );
        }
        const { value, done } = await this.#reader.read();
        if (done) {
          throw Error("Checkpoint channel ended before acknowledgement");
        }
        if (this.#pending.length + value.length > CHECKPOINT_LIMIT) {
          throw Error("Checkpoint input exceeds control-record bound");
        }
        const joined = new Uint8Array(this.#pending.length + value.length);
        joined.set(this.#pending);
        joined.set(value, this.#pending.length);
        this.#pending = joined;
      }
    })());
  }
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await Promise.allSettled([this.#reader.cancel(), this.#writer.abort()]);
    this.#reader.releaseLock();
    this.#writer.releaseLock();
  }
}

export function remoteCheckpoint(
  channel: CheckpointChannel,
  binding: CheckpointBinding,
) {
  return async (journal: RestoreJournal): Promise<void> => {
    const checkpoint = makeCheckpoint(binding, journal);
    await channel.send(checkpoint);
    const ack = await channel.receive() as
      | { kind?: unknown; sha256?: unknown }
      | null;
    if (
      ack?.kind !== "recovery-checkpoint-ack" ||
      ack.sha256 !== checkpoint.sha256
    ) {
      await channel.close();
      throw Error("Pi durable checkpoint acknowledgement differs");
    }
  };
}

/** Call under the Pi controller lock. A repeated latest checkpoint is safe;
 * changed immutable journal content, stage regressions and skipped stages fail.
 * Disk-state resume validation remains the target restorer's responsibility.
 */
export async function persistCheckpoint(
  value: RecoveryCheckpoint,
  binding: CheckpointBinding,
  path: string,
  storage = {
    read: readPrivateJson<RecoveryCheckpoint>,
    write: writePrivateJson,
  },
): Promise<{ kind: "recovery-checkpoint-ack"; sha256: string }> {
  const current = validateCheckpoint(value, binding);
  let previous: RecoveryCheckpoint | null = null;
  try {
    previous = validateCheckpoint(await storage.read(path), binding);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  if (previous) {
    if (current.sha256 === previous.sha256) {
      return { kind: "recovery-checkpoint-ack", sha256: current.sha256 };
    }
    if (
      immutableJournal(previous.journal) !==
        immutableJournal(current.journal) ||
      current.journal.completedStages.length !==
        previous.journal.completedStages.length + 1 ||
      Date.parse(current.journal.updatedAtUtc) <
        Date.parse(previous.journal.updatedAtUtc)
    ) throw Error("Checkpoint transition is not the next bound stage");
  } else if (current.journal.completedStages.length !== 1) {
    throw Error("Pi has no durable initial checkpoint for this restore");
  }
  await storage.write(path, current);
  return { kind: "recovery-checkpoint-ack", sha256: current.sha256 };
}

export async function receiveCheckpoint(
  channel: CheckpointChannel,
  binding: CheckpointBinding,
  path: string,
): Promise<RecoveryCheckpoint> {
  const value = await channel.receive() as RecoveryCheckpoint;
  const ack = await persistCheckpoint(value, binding, path);
  await channel.send(ack);
  return value;
}
