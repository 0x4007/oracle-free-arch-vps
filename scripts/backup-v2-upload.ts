import { createHash } from "node:crypto";
import {
  BACKUP_V2_ROLES,
  type BackupV2Chunk,
  type BackupV2ObjectKind,
  backupV2ObjectName,
  type BackupV2ObjectRef,
  type BackupV2ObjectStore,
  type BackupV2PutIntent,
  type BackupV2Role,
  type BackupV2SealedSlot,
  type BackupV2TransferEpisode,
  type BackupV2TransferPhase,
  backupV2TransferWindowMs,
  validateBackupV2ObjectRef,
  validateBackupV2PutIntent,
  validateBackupV2VersionPage,
} from "./backup-v2-contract.ts";
import { assertBackupV2Budget, BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";
import { createTransferPacer } from "./backblaze-upload.ts";
import {
  assertBackupV2Directory,
  BackupV2Spool,
  syncBackupV2Directory,
  writeBackupV2All,
} from "./backup-v2-spool.ts";

export interface BackupV2UploadIdentity {
  captureId: string;
  attemptId: string;
  role: BackupV2Role;
  kind: BackupV2ObjectKind;
}
type RecordEntry =
  | { type: "begin"; identity: BackupV2UploadIdentity }
  | { type: "intent"; intent: BackupV2PutIntent }
  | { type: "candidate" | "selected"; name: string; object: BackupV2ObjectRef }
  | { type: "verify" | "reclaimed"; name: string }
  | { type: "episode"; key: string; startedAtUtc: string }
  | {
    type: "transfer";
    key: string;
    phase: BackupV2TransferPhase;
    startedAtUtc: string;
  }
  | { type: "scan" }
  | {
    type: "eof";
    identity: BackupV2UploadIdentity;
    bytes: number;
    sha256: string;
    chunks: number;
  };
interface Logical {
  intent: BackupV2PutIntent;
  names: string[];
  candidates: BackupV2ObjectRef[];
  selected?: BackupV2ObjectRef;
  verifies: number;
}
const ZERO = "00000000-0000-0000-0000-000000000000";
const keyFor = (i: BackupV2UploadIdentity, ordinal: number) =>
  `${i.captureId}/${i.attemptId}/${i.role}/${i.kind}/${ordinal}`;
const identityKey = (i: BackupV2UploadIdentity) => keyFor(i, 0);
function fail(message: string): never {
  throw new Error(`Backup v2 upload ${message}`);
}
function identity(value: BackupV2UploadIdentity): BackupV2UploadIdentity {
  backupV2ObjectName(value.captureId, value.attemptId, value.kind, 0, ZERO);
  if (!BACKUP_V2_ROLES.includes(value.role)) fail("identity is invalid");
  return {
    captureId: value.captureId,
    attemptId: value.attemptId,
    role: value.role,
    kind: value.kind,
  };
}
function match(
  object: BackupV2ObjectRef,
  intent: BackupV2PutIntent,
): BackupV2ObjectRef {
  const result = validateBackupV2ObjectRef(object);
  if (
    result.fileName !== intent.name ||
    result.contentLength !== intent.slot.bytes ||
    result.contentSha1 !== intent.slot.sha1 ||
    result.sha256 !== intent.slot.sha256
  ) fail("object binding is invalid");
  return result;
}

/** Append-only bounded metadata. Each persistence callback must append+fsync;
 * a failed write poisons the journal rather than permitting another wire PUT. */
export class BackupV2UploadJournal {
  private entries: RecordEntry[] = [];
  private logical = new Map<string, Logical>();
  private intents = new Map<string, BackupV2PutIntent>();
  private begun = new Set<string>();
  private episodes = new Map<string, string>();
  private transfers = new Map<string, string>();
  private bytes = 0;
  private puts = 0;
  private putBytes = 0;
  private logicalBytes = 0;
  private scans = 0;
  private serial = Promise.resolve();
  private poisoned: unknown;
  constructor(
    readonly captureId: string,
    private persist: (bytes: Uint8Array) => Promise<void>,
    previous: readonly RecordEntry[] = [],
    readonly close: () => void = () => {},
  ) {
    for (const record of previous) {
      const bytes = this.encode(record);
      this.apply(record);
      this.entries.push(structuredClone(record));
      this.bytes += bytes.length;
    }
    assertBackupV2Budget("journalBytes", this.bytes);
  }
  private encode(record: RecordEntry): Uint8Array {
    const bytes = new TextEncoder().encode(JSON.stringify(record) + "\n");
    if (bytes.length > 8192) fail("journal record limit exceeded");
    return bytes;
  }
  private apply(record: RecordEntry): void {
    switch (record.type) {
      case "begin": {
        const i = identity(record.identity), key = identityKey(i);
        if (i.captureId !== this.captureId || this.begun.has(key)) {
          fail("producer attempt cannot restart");
        }
        this.begun.add(key);
        break;
      }
      case "intent": {
        const i = validateBackupV2PutIntent(record.intent),
          key = keyFor(i, i.ordinal);
        if (i.captureId !== this.captureId || this.intents.has(i.name)) {
          fail("physical PUT identity was reused");
        }
        const old = this.logical.get(key);
        if (
          old &&
          (old.intent.offset !== i.offset ||
            JSON.stringify(old.intent.slot) !== JSON.stringify(i.slot) ||
            old.selected)
        ) fail("logical bytes changed or already committed");
        assertBackupV2Budget("physicalPuts", this.puts + 1);
        assertBackupV2Budget(
          "physicallyPutBytes",
          this.putBytes + i.slot.bytes,
        );
        assertBackupV2Budget("putsPerObject", (old?.names.length ?? 0) + 1);
        if (!old) {
          assertBackupV2Budget("logicalObjects", this.logical.size + 1);
          assertBackupV2Budget(
            "ciphertextBytes",
            this.logicalBytes + i.slot.bytes,
          );
          this.logicalBytes += i.slot.bytes;
          this.logical.set(key, {
            intent: i,
            names: [],
            candidates: [],
            verifies: 0,
          });
        }
        this.puts++;
        this.putBytes += i.slot.bytes;
        this.intents.set(i.name, i);
        this.logical.get(key)!.names.push(i.name);
        break;
      }
      case "candidate":
      case "selected": {
        const i = this.intents.get(record.name);
        if (!i) fail("journal intent is missing");
        const ref = match(record.object, i),
          item = this.logical.get(keyFor(i, i.ordinal))!;
        if (record.type === "selected") {
          if (
            item.verifies === 0 ||
            (item.selected &&
              JSON.stringify(item.selected) !== JSON.stringify(ref))
          ) fail("selected proof is inconsistent");
          item.selected = ref;
        } else if (!item.candidates.some((old) => old.fileId === ref.fileId)) {
          item.candidates.push(ref);
        }
        break;
      }
      case "verify": {
        const i = this.intents.get(record.name);
        if (!i) fail("verify intent is missing");
        const item = this.logical.get(keyFor(i, i.ordinal))!;
        assertBackupV2Budget("putsPerObject", item.verifies + 1);
        item.verifies++;
        break;
      }
      case "reclaimed": {
        const i = this.intents.get(record.name);
        if (!i || !this.logical.get(keyFor(i, i.ordinal))?.selected) {
          fail("reclaim lacks durable selection");
        }
        break;
      }
      case "episode":
        if (
          !this.logical.has(record.key) || this.episodes.has(record.key) ||
          !Number.isFinite(Date.parse(record.startedAtUtc))
        ) fail("retry episode is invalid");
        this.episodes.set(record.key, record.startedAtUtc);
        break;
      case "transfer": {
        const item = this.logical.get(record.key),
          key = `${record.key}/${record.phase}`;
        if (
          !item || !["PUT", "READBACK"].includes(record.phase) ||
          this.transfers.has(key) ||
          !Number.isFinite(Date.parse(record.startedAtUtc)) ||
          record.phase === "READBACK" && item.verifies < 1
        ) fail("transfer episode is invalid");
        this.transfers.set(key, record.startedAtUtc);
        break;
      }
      case "scan":
        if (++this.scans > BACKUP_V2_LIMITS.pruneCandidates) {
          fail("reconciliation page budget exceeded");
        }
        break;
      case "eof": {
        const i = identity(record.identity);
        if (
          !this.begun.has(identityKey(i)) ||
          !/^[0-9a-f]{64}$/.test(record.sha256)
        ) fail("EOF lacks producer attempt");
        const selected = [...this.logical.values()].filter((item) =>
          identityKey(item.intent) === identityKey(i)
        ).sort((a, b) => a.intent.ordinal - b.intent.ordinal);
        if (
          selected.length !== record.chunks ||
          selected.some((item, index) =>
            !item.selected || item.intent.ordinal !== index
          ) ||
          selected.reduce((sum, item) => sum + item.intent.slot.bytes, 0) !==
            record.bytes
        ) fail("EOF lacks complete selected chunks");
        break;
      }
      default:
        fail("journal record is unknown");
    }
  }
  append(record: RecordEntry): Promise<void> {
    const frozen = structuredClone(record);
    const operation = this.serial.then(async () => {
      if (this.poisoned !== undefined) throw this.poisoned;
      const bytes = this.encode(frozen);
      assertBackupV2Budget("journalBytes", this.bytes + bytes.length);
      try {
        this.apply(frozen);
        await this.persist(bytes);
        this.entries.push(frozen);
        this.bytes += bytes.length;
      } catch (error) {
        this.poisoned = error;
        throw error;
      }
    });
    this.serial = operation.catch(() => {});
    return operation;
  }
  state(i: BackupV2UploadIdentity, ordinal: number): Logical | undefined {
    if (this.poisoned !== undefined) throw this.poisoned;
    const item = this.logical.get(keyFor(i, ordinal));
    return item ? structuredClone(item) : undefined;
  }
  episode(i: BackupV2UploadIdentity, ordinal: number): string | undefined {
    return this.episodes.get(keyFor(i, ordinal));
  }
  snapshot(): readonly RecordEntry[] {
    return structuredClone(this.entries);
  }
  transfer(
    i: BackupV2UploadIdentity,
    ordinal: number,
    phase: BackupV2TransferPhase,
  ): string | undefined {
    return this.transfers.get(`${keyFor(i, ordinal)}/${phase}`);
  }
}

/** One fixed append file; no full-journal rewrite/WAL/hidden compaction copy. */
export async function openBackupV2UploadJournal(
  directory: string,
  captureId: string,
): Promise<BackupV2UploadJournal> {
  const dir = await assertBackupV2Directory(directory),
    path = `${directory}/upload-journal.ndjson`;
  let old: Deno.FileInfo | undefined;
  try {
    old = await Deno.lstat(path);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  const valid = (info: Deno.FileInfo) => {
    if (
      !info.isFile || info.isSymlink || info.uid !== 0 || info.mode === null ||
      (info.mode & 0o777) !== 0o600 || info.nlink !== 1
    ) fail("journal file is unsafe");
    assertBackupV2Budget("journalBytes", info.size);
  };
  if (old) valid(old);
  const handle = await Deno.open(
    path,
    old
      ? { read: true, append: true }
      : { read: true, append: true, createNew: true, mode: 0o600 },
  );
  try {
    await handle.lock(true);
    const bound = await handle.stat();
    valid(bound);
    if (old && (old.dev !== bound.dev || old.ino !== bound.ino)) {
      fail("journal identity changed");
    }
    const bytes = new Uint8Array(bound.size);
    let offset = 0;
    while (offset < bytes.length) {
      const n = await handle.read(bytes.subarray(offset));
      if (!n) fail("journal read stalled");
      offset += n;
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (text && !text.endsWith("\n")) {
      fail("journal has an incomplete trailing record");
    }
    const records = text
      ? text.slice(0, -1).split("\n").map((line) => {
        if (new TextEncoder().encode(line).length > 8192) {
          fail("journal record is oversized");
        }
        return JSON.parse(line) as RecordEntry;
      })
      : [];
    await handle.sync();
    await syncBackupV2Directory(directory);
    return new BackupV2UploadJournal(
      captureId,
      async (record) => {
        await assertBackupV2Directory(directory, dir);
        const current = await Deno.lstat(path);
        valid(current);
        if (current.dev !== bound.dev || current.ino !== bound.ino) {
          fail("journal path was replaced");
        }
        assertBackupV2Budget("journalBytes", current.size + record.length);
        await writeBackupV2All(handle, record);
        await handle.sync();
      },
      records,
      () => handle.close(),
    );
  } catch (error) {
    handle.close();
    throw error;
  }
}

export interface BackupV2UploadContext {
  spool: BackupV2Spool;
  journal: BackupV2UploadJournal;
  store: BackupV2ObjectStore;
  identity: BackupV2UploadIdentity;
  signal?: AbortSignal;
  classifyFailure(
    error: unknown,
  ): { retryable: boolean; mayHaveCommitted: boolean };
  /** Shared PUT + full GET readback ceiling; charge every attempt, even failures. */
  pace: (bytes: number) => Promise<void>;
  sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
  now?: () => Date;
  monotonicNow?: () => number;
  newPutId?: () => string;
  onVerified?: (chunk: BackupV2Chunk) => void | Promise<void>;
  /** Called only after the journal's retry episode is durable. The original
   * monotonic endpoints remain fixed across all subsequent attempts. */
  onRetryEpisode?: (
    episode: BackupV2UploadRetryEpisode,
  ) => void | Promise<void>;
  onTransferEpisode?: (
    episode: BackupV2TransferEpisode,
  ) => void | Promise<void>;
  onTransferComplete?: (operationId: string) => void | Promise<void>;
}
export interface BackupV2UploadRetryEpisode {
  sealedObjectIdentity: string;
  retainedBytes: number;
  startedAtMs: number;
  expiresAtMs: number;
}
export function createBackupV2UploadPacer(): (bytes: number) => Promise<void> {
  return createTransferPacer();
}
async function reconcile(
  context: BackupV2UploadContext,
  ordinal: number,
): Promise<BackupV2ObjectRef | undefined> {
  const item = context.journal.state(context.identity, ordinal);
  if (!item) return undefined;
  if (item.candidates.length) return item.candidates[0];
  for (const name of item.names) {
    let cursor: import("./backup-v2-contract.ts").BackupV2Cursor | null = null;
    const seen = new Set<string>();
    do {
      await context.journal.append({ type: "scan" });
      await context.pace(BACKUP_V2_LIMITS.listResponseBytes);
      const page = validateBackupV2VersionPage(
        await context.store.versionsPage(name, cursor, context.signal),
      );
      for (const version of page.items) {
        if (
          version.fileName !== name || version.action !== "upload" ||
          version.contentLength !== item.intent.slot.bytes ||
          version.contentSha1 !== item.intent.slot.sha1
        ) fail("physical object inventory conflicts");
        return match({
          ...version,
          action: "upload",
          sha256: item.intent.slot.sha256,
        }, { ...item.intent, name });
      }
      cursor = page.next;
      if (cursor) {
        const key = JSON.stringify(cursor);
        if (seen.has(key) || seen.size >= 32) {
          fail("pagination did not terminate");
        }
        seen.add(key);
      }
    } while (cursor);
  }
  // No intent is removed or declared absent: a delayed earlier PUT may still land.
  return undefined;
}

/** This is the sole selection/reclaim barrier for both payload and metadata. */
export async function uploadSealedBackupV2Object(
  slot: BackupV2SealedSlot,
  ordinal: number,
  offset: number,
  context: BackupV2UploadContext,
): Promise<BackupV2ObjectRef> {
  const i = identity(context.identity),
    now = context.now ?? (() => new Date()),
    mono = context.monotonicNow ?? (() => performance.now());
  const pace = context.pace,
    sleep = context.sleep ??
      ((ms: number, signal?: AbortSignal) =>
        new Promise<void>((resolve, reject) => {
          signal?.throwIfAborted();
          const timer = setTimeout(() => {
            signal?.removeEventListener("abort", aborted);
            resolve();
          }, ms);
          const aborted = () => {
            clearTimeout(timer);
            reject(signal?.reason);
          };
          signal?.addEventListener("abort", aborted, { once: true });
        }));
  await context.spool.read(slot, () => {});
  let episodeDeadline: number | undefined;
  let episodeStarted: number | undefined;
  const previousEpisode = context.journal.episode(i, ordinal);
  if (previousEpisode) {
    const remaining = Date.parse(previousEpisode) +
      BACKUP_V2_LIMITS.blockedTransportMs - now().getTime();
    if (remaining <= 0 || remaining > BACKUP_V2_LIMITS.blockedTransportMs) {
      fail("retry episode expired or clock regressed");
    }
    episodeDeadline = mono() + remaining;
    episodeStarted = episodeDeadline - BACKUP_V2_LIMITS.blockedTransportMs;
  }
  const notifyEpisode = async () => {
    if (episodeDeadline !== undefined && episodeStarted !== undefined) {
      await context.onRetryEpisode?.({
        sealedObjectIdentity: keyFor(i, ordinal),
        retainedBytes: slot.bytes,
        startedAtMs: episodeStarted,
        expiresAtMs: episodeDeadline,
      });
    }
  };
  const transferWindows = new Map<
    BackupV2TransferPhase,
    BackupV2TransferEpisode
  >();
  let currentTransfer: BackupV2TransferEpisode | undefined;
  const beginTransfer = async (phase: BackupV2TransferPhase) => {
    let episode = transferWindows.get(phase);
    if (!episode) {
      const duration = backupV2TransferWindowMs(phase),
        old = context.journal.transfer(i, ordinal, phase);
      let startedAtMs = mono();
      if (old) {
        const elapsed = now().getTime() - Date.parse(old);
        if (elapsed < 0 || elapsed >= duration) {
          fail("sealed transfer wait expired or clock regressed");
        }
        startedAtMs -= elapsed;
      } else {await context.journal.append({
          type: "transfer",
          key: keyFor(i, ordinal),
          phase,
          startedAtUtc: now().toISOString(),
        });}
      episode = {
        kind: "SEALED_TRANSFER",
        operationId: `${keyFor(i, ordinal)}/${phase}`,
        phase,
        sealedObjectIdentity: keyFor(i, ordinal),
        retainedBytes: slot.bytes,
        startedAtMs,
        expiresAtMs: startedAtMs + duration,
      };
      transferWindows.set(phase, episode);
    }
    if (mono() >= episode.expiresAtMs) fail("sealed transfer wait expired");
    currentTransfer = episode;
    await context.onTransferEpisode?.(episode);
  };
  for (
    let iteration = 0;
    iteration < BACKUP_V2_LIMITS.putsPerObject;
    iteration++
  ) {
    context.signal?.throwIfAborted();
    if (episodeDeadline !== undefined && mono() >= episodeDeadline) {
      fail("retry episode expired");
    }
    await notifyEpisode();
    if (currentTransfer) await context.onTransferEpisode?.(currentTransfer);
    let candidate: BackupV2ObjectRef | undefined;
    let wireError: unknown;
    try {
      const state = context.journal.state(i, ordinal),
        previouslySelected = state?.selected !== undefined;
      candidate = state?.selected ?? await reconcile(context, ordinal);
      if (!candidate) {
        const putId = (context.newPutId ?? (() => crypto.randomUUID()))();
        const intent = validateBackupV2PutIntent({
          ...i,
          ordinal,
          offset,
          putId,
          createdAtUtc: now().toISOString(),
          slot,
          name: backupV2ObjectName(
            i.captureId,
            i.attemptId,
            i.kind,
            ordinal,
            putId,
          ),
        });
        await context.journal.append({ type: "intent", intent });
        await beginTransfer("PUT");
        await pace(slot.bytes);
        try {
          candidate = match(
            await context.store.putFileOnce(intent, context.signal),
            intent,
          );
        } catch (error) {
          wireError = error;
          candidate = await reconcile(context, ordinal);
        }
        if (candidate) {
          await context.journal.append({
            type: "candidate",
            name: candidate.fileName,
            object: candidate,
          });
        }
      }
      if (!candidate) {
        if (wireError !== undefined) throw wireError;
        fail("PUT produced no candidate");
      }
      const selectedIntent = context.journal.state(i, ordinal)!;
      const matching = selectedIntent.names.find((name) =>
        name === candidate!.fileName
      );
      if (!matching) fail("candidate has no durable intent");
      match(candidate, { ...selectedIntent.intent, name: matching });
      await context.journal.append({ type: "verify", name: matching });
      await beginTransfer("READBACK");
      await pace(candidate.contentLength);
      await context.store.verifyExactReadback(candidate, context.signal);
      await context.journal.append({
        type: "selected",
        name: matching,
        object: candidate,
      });
      if (!previouslySelected) {
        await context.onVerified?.({ ordinal, offset, object: candidate });
      }
      await context.spool.reclaim(slot);
      await context.journal.append({ type: "reclaimed", name: matching });
      await context.onTransferComplete?.(currentTransfer!.operationId);
      return candidate;
    } catch (error) {
      if (!context.classifyFailure(error).retryable) throw error;
      if (episodeDeadline === undefined) {
        episodeStarted = mono();
        await context.journal.append({
          type: "episode",
          key: keyFor(i, ordinal),
          startedAtUtc: now().toISOString(),
        });
        episodeDeadline = episodeStarted + BACKUP_V2_LIMITS.blockedTransportMs;
      }
      await notifyEpisode();
      const delay = iteration < 2 ? 1000 * (iteration + 1) : 30 * 60_000;
      if (
        iteration + 1 >= BACKUP_V2_LIMITS.putsPerObject ||
        mono() + delay >= episodeDeadline
      ) throw error;
      await sleep(delay, context.signal);
    }
  }
  return fail("retry attempt budget exhausted");
}

/** Producer EOF alone never marks a role cloud-sealed; caller checks all native statuses. */
export async function uploadBackupV2Stream(
  source: ReadableStream<Uint8Array>,
  context: BackupV2UploadContext,
) {
  await context.journal.append({
    type: "begin",
    identity: identity(context.identity),
  });
  const controller = new AbortController();
  const signal = context.signal
    ? AbortSignal.any([context.signal, controller.signal])
    : controller.signal;
  const shared = { ...context, signal };
  const hash = createHash("sha256"), chunks: BackupV2Chunk[] = [];
  let bytes = 0, ordinal = 0, failure: unknown, tail = Promise.resolve();
  try {
    for await (const slot of context.spool.sealed(source)) {
      const index = ordinal++, offset = bytes;
      assertBackupV2Budget("logicalObjects", ordinal);
      assertBackupV2Budget("ciphertextBytes", bytes + slot.bytes);
      await context.spool.read(slot, (part) => {
        hash.update(part);
      });
      bytes += slot.bytes;
      tail = tail.then(async () => {
        if (failure !== undefined) throw failure;
        const object = await uploadSealedBackupV2Object(
          slot,
          index,
          offset,
          shared,
        );
        chunks.push({ ordinal: index, offset, object });
      }).catch(async (error) => {
        failure ??= error;
        controller.abort(error);
        await context.spool.abort(error);
      });
    }
  } catch (error) {
    failure ??= error;
    controller.abort(error);
    await context.spool.abort(error);
  }
  await tail;
  if (failure !== undefined) throw failure;
  if (chunks.length === 0) fail("ciphertext stream was empty");
  const sha256 = hash.digest("hex");
  await context.journal.append({
    type: "eof",
    identity: context.identity,
    bytes,
    sha256,
    chunks: chunks.length,
  });
  return { chunks, ciphertextBytes: bytes, ciphertextSha256: sha256 };
}
