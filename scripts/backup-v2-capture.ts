import { createHash } from "node:crypto";
import {
  assertMountGuards,
  assertRecipientPinned,
  assertStagingBootParity,
  type CaptureSettings,
  exclusionPaths,
  type FileSource,
  finalInspection,
  fsRelativeExclusions,
  gpgArgs,
  initialInspection,
  prepareRecipient,
  recordToolVersions,
  ROLE_ORDER,
  type RoleName,
  swapfileRecreation,
  swapfileStatLines,
  TAR_OPTIONS,
  validateCaptureSettings,
} from "./backblaze-capture.ts";
import { shellQuote } from "./backup-guest.ts";
import {
  type BackupV2ArchiveDescriptor,
  type BackupV2Chunk,
  type BackupV2ProducerProof,
  type BackupV2Role,
} from "./backup-v2-contract.ts";
import { type BackupV2InventorySummary } from "./backup-v2-inventory.ts";
import {
  backupV2BootSamples,
  backupV2CompatibilitySha256,
  type BackupV2ReusedRole,
  type BackupV2RoleRecoveryMetadata,
  backupV2SourceConfigSha256,
  collectBackupV2RecoveryMetadata,
  createBackupV2MetadataRunner,
  restoreBackupV2RecoveryMetadata,
  validateBackupV2ReusedRoles,
} from "./backup-v2-metadata.ts";
export type {
  BackupV2ReusedRole,
  BackupV2RoleRecoveryMetadata,
} from "./backup-v2-metadata.ts";
import { assertBackupV2Budget } from "./backup-v2-profile.ts";
import { assertBackupV2Directory } from "./backup-v2-spool.ts";
import {
  type BackupV2UploadContext,
  uploadBackupV2Stream,
} from "./backup-v2-upload.ts";
import {
  consumeNativeTarListing,
  createTarInventory,
  tarPathKey,
} from "./backup-tar-consumers.ts";

const encoder = new TextEncoder();
const digest = (text: string) =>
  createHash("sha256").update(text).digest("hex");
const DIAGNOSTIC_BYTES = 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function fail(reason: string): never {
  throw new Error(`Backup v2 capture rejected: ${reason}`);
}

export interface BackupV2CaptureProgress {
  role: BackupV2Role;
  kind: "source" | "inventory" | "verified";
  bytes: number;
  members: number;
}
export interface BackupV2CaptureChild {
  stdin: WritableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
  status: Promise<{ code: number }>;
}
/** cancel must settle the whole managed unit, including namespace descendants. */
export interface BackupV2CaptureNative {
  assertManaged(): Promise<void>;
  cancel(reason: unknown): Promise<void>;
  spawn?: (command: string, args: string[]) => BackupV2CaptureChild;
}
export interface BackupV2RoleProducerParams {
  settings: CaptureSettings;
  stage: string;
  role: BackupV2Role;
  attemptId: string;
  recovery?: Uint8Array;
  native: BackupV2CaptureNative;
  signal?: AbortSignal;
  now?: () => Date;
  progress?: (value: BackupV2CaptureProgress) => void | Promise<void>;
}
export interface BackupV2RoleProducer {
  ciphertext: ReadableStream<Uint8Array>;
  /** Real native completion, observed independently from the final PUT/readback. */
  completion: Promise<{ captureFinishedAtUtc: string }>;
  /** Release namespace only after producer and upload have both settled. */
  release(): Promise<{
    inventory: BackupV2InventorySummary | null;
    producer: BackupV2ProducerProof;
  }>;
  cancel(reason: unknown): Promise<void>;
}

/** Same stored GNU tar metadata and exclusions as v1; names have their own pipe. */
export function backupV2TarArguments(exclusions: string[], index: string) {
  return [
    ...TAR_OPTIONS,
    "--verbose",
    "--verbose",
    "--full-time",
    "--utc",
    "--quoting-style=c",
    `--index-file=${index}`,
    ...exclusions.map((path) => `--exclude=${path}`),
    "--",
    ".",
  ];
}

/** Only recognized live-root drift is tolerated; data loss is always fatal. */
export function classifyBackupV2TarDiagnostics(
  role: BackupV2Role,
  code: number,
  text: string,
): Pick<BackupV2ProducerProof, "tarExitCode" | "driftRecords" | "driftSha256"> {
  if (encoder.encode(text).length > DIAGNOSTIC_BYTES) fail("diagnostic bound");
  if (code !== 0 && code !== 1) fail("tar status");
  const drift: string[] = [];
  for (const line of text.split("\n").filter(Boolean)) {
    if (role === "root" && /^tar: .+: file changed as we read it$/.test(line)) {
      drift.push(line);
    } else if (role === "root" && /^tar: .+: socket ignored$/.test(line)) {
      // Sockets have no persistent payload; their warning is not drift proof.
    } else fail("unclassified tar diagnostic");
  }
  if (code === 1 && (role !== "root" || drift.length === 0)) {
    fail("tar exit one without recognized live drift");
  }
  return {
    tarExitCode: code,
    driftRecords: drift.length,
    driftSha256: digest(drift.map((line) => line + "\n").join("")),
  };
}

export function backupV2NamespaceScript(params: {
  source: FileSource;
  role: RoleName;
  stage: string;
  index: string;
  status: string;
  exclusions: string[];
}): string {
  const { source, role, stage, index, status, exclusions } = params;
  const quote = shellQuote;
  const lines = [
    "umask 077",
    "set -uC",
    "ulimit -f 2048 || exit 80",
    // Open before mount setup, so even setup failures settle the FIFO reader.
    `exec 3>${quote(index)} || exit 70`,
    "mount --make-rprivate / || exit 70",
    'd=""',
    'cleanup() { s=$?; if test -n "$d"; then umount "$d" || s=79; rmdir "$d" || s=79; fi; exit "$s"; }',
    "trap cleanup EXIT",
  ];
  if (source.livePath) lines.push(`cd ${quote(source.livePath)} || exit 71`);
  else {
    const options = source.filesystem === "xfs"
      ? "ro,norecovery"
      : source.filesystem === "ext4"
      ? "ro,noload"
      : "ro";
    lines.push(
      `dev=$(readlink -f /dev/disk/by-uuid/${source.uuid}) || exit 71`,
      'test -b "$dev" || exit 71',
      `test "$(blkid -s TYPE -o value "$dev")" = ${
        quote(source.filesystem)
      } || exit 72`,
      `test "$(blkid -s UUID -o value "$dev")" = ${
        quote(source.uuid)
      } || exit 72`,
      `test "$(blockdev --getsize64 "$dev")" = ${
        quote(String(source.size))
      } || exit 72`,
      'test -z "$(findmnt -rn -S "$dev")" || exit 73',
      `d=$(mktemp -d ${quote(`${stage}/mount-${role}.XXXXXX`)}) || exit 74`,
      `mount -t ${quote(source.filesystem)} -o ${
        quote(options)
      } "$dev" "$d" || exit 75`,
      'cd "$d" || exit 75',
    );
  }
  if (role === "oracle-root") lines.push(...swapfileStatLines(stage));
  if (role === "staging-boot") {
    lines.push(
      `sha256sum ./arch-vmlinuz ./arch-initrd.img > ${
        quote(`${stage}/staging-boot.sha.before`)
      } || exit 76`,
      `stat -c %s ./arch-vmlinuz ./arch-initrd.img > ${
        quote(`${stage}/staging-boot.bytes.before`)
      } || exit 76`,
    );
  }
  lines.push(
    `tar ${
      backupV2TarArguments(exclusions, "/proc/self/fd/3").map(quote).join(" ")
    }`,
    "ts=$?",
    "exec 3>&-",
  );
  if (role === "staging-boot") {
    lines.push(
      `sha256sum ./arch-vmlinuz ./arch-initrd.img > ${
        quote(`${stage}/staging-boot.sha.after`)
      } || exit 76`,
      `stat -c %s ./arch-vmlinuz ./arch-initrd.img > ${
        quote(`${stage}/staging-boot.bytes.after`)
      } || exit 76`,
      `cmp ${quote(`${stage}/staging-boot.bytes.before`)} ${
        quote(`${stage}/staging-boot.bytes.after`)
      } || exit 76`,
    );
  }
  lines.push(
    `printf '%s\\n' "$ts" > ${quote(status)} || exit 77`,
    "exec 1>&-",
    // Keep read-only mounts alive while native compression and upload finish.
    'IFS= read -r release && test "$release" = RELEASE || exit 78',
  );
  return lines.join("\n");
}

/** Every write is awaited, including short native writes; no tee or payload queue. */
export async function pumpBackupV2Capture(
  source: ReadableStream<Uint8Array>,
  sink: WritableStream<Uint8Array>,
  progress?: (bytes: number) => void | Promise<void>,
) {
  const reader = source.getReader(), writer = sink.getWriter();
  let complete = false;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      if (!(next.value instanceof Uint8Array) || !next.value.length) {
        fail("empty pipe progress");
      }
      await writer.write(next.value);
      await progress?.(next.value.length);
    }
    await writer.close();
    complete = true;
  } finally {
    if (!complete) {
      await Promise.allSettled([reader.cancel(), writer.abort()]);
    }
    reader.releaseLock();
    writer.releaseLock();
  }
}

async function boundedText(
  stream: ReadableStream<Uint8Array>,
  limit: number,
  log?: string,
) {
  const chunks: Uint8Array[] = [];
  let size = 0;
  const file = log
    ? await Deno.open(log, { createNew: true, write: true, mode: 0o600 })
    : undefined;
  try {
    for await (const bytes of stream) {
      size += bytes.length;
      if (size > limit) fail("native diagnostic bound");
      if (file) {
        let offset = 0;
        while (offset < bytes.length) {
          const count = await file.write(bytes.subarray(offset));
          if (count <= 0) fail("diagnostic write stalled");
          offset += count;
        }
      }
      chunks.push(bytes);
    }
  } finally {
    if (file) {
      try {
        await file.sync();
      } finally {
        file.close();
      }
    }
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const bytes of chunks) {
    result.set(bytes, offset);
    offset += bytes.length;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(result);
}

async function readSmall(path: string, maximum = 8192) {
  const info = await Deno.lstat(path);
  if (
    !info.isFile || info.isSymlink || info.nlink !== 1 || info.size > maximum
  ) fail("metadata file bound");
  const file = await Deno.open(path, { read: true });
  try {
    const bound = await file.stat();
    if (
      bound.dev !== info.dev || bound.ino !== info.ino ||
      bound.size !== info.size
    ) fail("metadata file replaced");
    return await boundedText(file.readable, maximum);
  } finally {
    try {
      file.close();
    } catch { /* readable may have closed its handle. */ }
  }
}

/** Requires the current managed unit; cancellation belongs to its supervisor. */
export async function createBackupV2RoleProducer(
  params: BackupV2RoleProducerParams,
): Promise<BackupV2RoleProducer> {
  validateCaptureSettings(params.settings);
  const { role, stage, attemptId, native } = params;
  if (!UUID.test(attemptId) || ![...ROLE_ORDER, "recovery"].includes(role)) {
    fail("producer identity");
  }
  if ((role === "recovery") !== (params.recovery !== undefined)) {
    fail("producer input");
  }
  if (params.recovery && params.recovery.length > 8 * 1024 * 1024) {
    fail("recovery bound");
  }
  params.signal?.throwIfAborted();
  await native.assertManaged();
  await assertBackupV2Directory(stage);
  await assertRecipientPinned(params.settings, stage);
  const now = params.now ?? (() => new Date());
  const spawn = native.spawn ??
    ((command: string, args: string[]) =>
      new Deno.Command(command, {
        args,
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
        clearEnv: true,
        env: { PATH: "/usr/bin:/bin", LC_ALL: "C", TZ: "UTC", TMPDIR: stage },
      }).spawn());
  const tasks: Promise<unknown>[] = [];
  const children: BackupV2CaptureChild[] = [];
  let failed: unknown, cancellation: Promise<void> | undefined;
  const cancel = (reason: unknown) => {
    failed ??= reason;
    return cancellation ??= native.cancel(reason);
  };
  const observe = <T>(promise: Promise<T>): Promise<T> => {
    tasks.push(promise);
    // Attach now; delayed awaiting of another pipeline branch must not leak.
    promise.catch((error) => {
      void cancel(error).catch(() => {});
    });
    return promise;
  };
  const aborted = () => {
    void cancel(params.signal?.reason).catch(() => {});
  };
  params.signal?.addEventListener("abort", aborted, { once: true });
  const start = (command: string, args: string[]) => {
    const child = spawn(command, args);
    children.push(child);
    observe(child.status.then((status) => {
      if (status.code !== 0) fail(`${command} status`);
      return status;
    }));
    return child;
  };
  let namespace: BackupV2CaptureChild | undefined;
  let indexPath: string | undefined, indexIdentity: Deno.FileInfo | undefined;
  let indexOpen: Promise<Deno.FsFile> | undefined;
  let indexOpened = false;
  let indexUnblock: Promise<void> | undefined;
  const releaseIndexOpen = async () => {
    if (indexOpen && !indexOpened && indexPath) {
      await (indexUnblock ??= (async () => {
        const writer = await Deno.open(indexPath!, { write: true });
        writer.close();
      })());
    }
  };
  const statusPath = `${stage}/producer-${role}-${attemptId}.status`;
  try {
    const zstd = start("zstd", ["-3", "-T1", "--check", "-c"]);
    const gpg = start(
      "gpg",
      gpgArgs(`${stage}/gpg-public-home`, `${stage}/recipient.asc`, "-", "-"),
    );
    const zstdError = observe(
      boundedText(
        zstd.stderr,
        DIAGNOSTIC_BYTES,
        `${stage}/producer-${role}-${attemptId}.zstd.log`,
      ),
    );
    const gpgError = observe(
      boundedText(
        gpg.stderr,
        DIAGNOSTIC_BYTES,
        `${stage}/producer-${role}-${attemptId}.gpg.log`,
      ),
    );
    observe(pumpBackupV2Capture(zstd.stdout, gpg.stdin));
    const required = role === "root"
      ? ["./etc/os-release", "./boot/Image", "./boot/initramfs-linux.img"]
      : role === "staging-boot"
      ? ["./arch-vmlinuz", "./arch-initrd.img"]
      : [];
    const inventory = createTarInventory(
      required.map((path) => encoder.encode(path)),
      false,
    );
    let members = 0, sourceBytes = 0;
    let indexTask: Promise<void> = Promise.resolve();
    let tarError: Promise<string> = Promise.resolve("");
    let input: ReadableStream<Uint8Array>;
    if (role === "recovery") {
      input = new ReadableStream({
        start(c) {
          c.enqueue(params.recovery!);
          c.close();
        },
      });
    } else {
      indexPath = `${stage}/producer-${role}-${attemptId}.fifo`;
      const made = await createBackupV2MetadataRunner(stage, native)("mkfifo", [
        "-m",
        "600",
        indexPath,
      ]);
      if (made.code !== 0) fail("inventory FIFO creation");
      indexIdentity = await Deno.lstat(indexPath);
      indexOpen = Deno.open(indexPath, { read: true });
      indexTask = observe(indexOpen.then(async (file) => {
        indexOpened = true;
        try {
          await consumeNativeTarListing(file.readable, (member) => {
            inventory.add(member);
            members++;
          });
        } finally {
          try {
            file.close();
          } catch { /* stream owns closure. */ }
        }
      }));
      const source = params.settings.sources.find((item) =>
        item.name === role
      )!;
      namespace = spawn("unshare", [
        "--mount",
        "bash",
        "-c",
        backupV2NamespaceScript({
          source,
          role: role as RoleName,
          stage,
          index: indexPath,
          status: statusPath,
          exclusions: fsRelativeExclusions(
            exclusionPaths(params.settings.exclusionsText),
          ),
        }),
      ]);
      children.push(namespace);
      observe(namespace.status.then(async (status) => {
        await releaseIndexOpen();
        if (status.code !== 0) fail("namespace status");
      }));
      tarError = observe(
        boundedText(
          namespace.stderr,
          DIAGNOSTIC_BYTES,
          `${stage}/producer-${role}-${attemptId}.tar.log`,
        ),
      );
      input = namespace.stdout;
    }
    const inputTask = observe(
      pumpBackupV2Capture(input, zstd.stdin, async (bytes) => {
        sourceBytes = assertBackupV2Budget(
          "logicalSourceBytes",
          sourceBytes + bytes,
        );
        await params.progress?.({
          role,
          kind: "source",
          bytes: sourceBytes,
          members,
        });
      }),
    );
    const completion = observe((async () => {
      await inputTask;
      const codes = await Promise.all([zstd.status, gpg.status]);
      if (codes.some((value) => value.code !== 0)) {
        fail("compression or encryption status");
      }
      return { captureFinishedAtUtc: now().toISOString() };
    })());
    let released:
      | Promise<
        {
          inventory: BackupV2InventorySummary | null;
          producer: BackupV2ProducerProof;
        }
      >
      | undefined;
    return {
      ciphertext: gpg.stdout,
      completion,
      cancel: async (reason) => {
        await cancel(reason);
        await releaseIndexOpen();
        await Promise.allSettled(tasks);
      },
      release() {
        return released ??= (async () => {
          try {
            await completion;
            if (namespace) {
              const writer = namespace.stdin.getWriter();
              try {
                await writer.write(encoder.encode("RELEASE\n"));
                await writer.close();
              } finally {
                writer.releaseLock();
              }
            }
            await Promise.all(children.map((child) => child.status));
            await indexTask;
            const text = await tarError;
            await Promise.all([zstdError, gpgError]);
            if (failed !== undefined) throw failed;
            const tarStatus = role === "recovery"
              ? "0\n"
              : await readSmall(statusPath, 16);
            if (!/^[012]\n$/.test(tarStatus)) fail("tar status record");
            const tarCode = Number(tarStatus.trim());
            const producer = {
              ...classifyBackupV2TarDiagnostics(role, tarCode, text),
              zstdExitCode: 0 as const,
              gpgExitCode: 0 as const,
            };
            const summary = role === "recovery" ? null : inventory.finish();
            if (summary) {
              for (const path of required) {
                if (
                  summary.observed.get(tarPathKey(encoder.encode(path)))
                    ?.count !== 1
                ) fail("required member missing or duplicated");
              }
              await params.progress?.({
                role,
                kind: "inventory",
                bytes: sourceBytes,
                members,
              });
            }
            return { inventory: summary?.inventory ?? null, producer };
          } catch (error) {
            await cancel(error);
            await releaseIndexOpen();
            throw error;
          } finally {
            await Promise.allSettled(tasks);
            params.signal?.removeEventListener("abort", aborted);
            if (indexPath && indexIdentity) {
              const current = await Deno.lstat(indexPath);
              if (
                current.dev !== indexIdentity.dev ||
                current.ino !== indexIdentity.ino || current.isSymlink
              ) fail("FIFO replaced");
              await Deno.remove(indexPath);
            }
          }
        })();
      },
    };
  } catch (error) {
    await cancel(error);
    await releaseIndexOpen();
    await Promise.allSettled(tasks);
    params.signal?.removeEventListener("abort", aborted);
    throw error;
  }
}

export interface BackupV2CapturedRole extends BackupV2ArchiveDescriptor {
  captureId: string;
  attemptId: string;
  sourceConfigSha256: string;
  compatibilitySha256: string;
  recipientSha256: string;
  recipientFingerprint: string;
  captureStartedAtUtc: string;
  captureFinishedAtUtc: string;
  uploadStartedAtUtc: string;
  uploadFinishedAtUtc: string;
  chunks: BackupV2Chunk[];
  inventory: BackupV2InventorySummary | null;
  producer: BackupV2ProducerProof;
}
export interface BackupV2CaptureContext
  extends Omit<BackupV2UploadContext, "identity" | "onVerified"> {
  stage: string;
  sourceConfigSha256: string;
  native: BackupV2CaptureNative;
  /** Exact source scope, aggregate workspace, reserve/inodes and current cgroup. */
  admit(role: BackupV2Role): Promise<void>;
  progress?: (value: BackupV2CaptureProgress) => void | Promise<void>;
  newAttemptId?: () => string;
  createProducer?: (
    params: BackupV2RoleProducerParams,
  ) => Promise<BackupV2RoleProducer>;
  reusedRoles?: readonly BackupV2ReusedRole[];
  onRole?: (
    value: BackupV2CapturedRole,
    recovery: BackupV2RoleRecoveryMetadata,
  ) => void | Promise<void>;
}

/** Bind real producer and upload intervals, and settle both branches on error. */
export async function uploadBackupV2RoleProducer(
  params: {
    settings: CaptureSettings;
    role: BackupV2Role;
    attemptId: string;
    captureStartedAtUtc: string;
    compatibilitySha256: string;
    producer: BackupV2RoleProducer;
  },
  context: Pick<
    BackupV2CaptureContext,
    | "spool"
    | "journal"
    | "store"
    | "pace"
    | "classifyFailure"
    | "sleep"
    | "now"
    | "monotonicNow"
    | "newPutId"
    | "signal"
    | "sourceConfigSha256"
    | "progress"
  >,
): Promise<BackupV2CapturedRole> {
  const {
    settings,
    role,
    attemptId,
    captureStartedAtUtc,
    compatibilitySha256,
    producer,
  } = params;
  const now = context.now ?? (() => new Date());
  const controller = new AbortController();
  const signal = context.signal
    ? AbortSignal.any([context.signal, controller.signal])
    : controller.signal;
  let uploadStartedAtUtc: string | undefined;
  const store = {
    putFileOnce: (
      intent: Parameters<BackupV2UploadContext["store"]["putFileOnce"]>[0],
      signal?: AbortSignal,
    ) => {
      uploadStartedAtUtc ??= now().toISOString();
      return context.store.putFileOnce(intent, signal);
    },
    verifyExactReadback: context.store.verifyExactReadback.bind(context.store),
    getExactToFile: context.store.getExactToFile.bind(context.store),
    versionsPage: context.store.versionsPage.bind(context.store),
  };
  const upload = uploadBackupV2Stream(producer.ciphertext, {
    ...context,
    store,
    signal,
    identity: { captureId: settings.generation, attemptId, role, kind: "data" },
    onVerified: async (chunk) => {
      await context.progress?.({
        role,
        kind: "verified",
        bytes: chunk.offset + chunk.object.contentLength,
        members: 0,
      });
    },
  });
  try {
    const [uploaded, completed] = await Promise.all([
      upload,
      producer.completion,
    ]);
    const proof = await producer.release();
    if (!uploadStartedAtUtc) fail("no actual upload start");
    if (captureStartedAtUtc >= completed.captureFinishedAtUtc) {
      fail("native capture clock");
    }
    return {
      role,
      format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
      captureId: settings.generation,
      attemptId,
      sourceConfigSha256: context.sourceConfigSha256,
      compatibilitySha256,
      recipientSha256: settings.recipientSha256,
      recipientFingerprint: settings.recipientFingerprint,
      captureStartedAtUtc,
      captureFinishedAtUtc: completed.captureFinishedAtUtc,
      uploadStartedAtUtc,
      uploadFinishedAtUtc: now().toISOString(),
      ...uploaded,
      ...proof,
    };
  } catch (error) {
    controller.abort(error);
    await context.spool.abort(error);
    try {
      await producer.cancel(error);
    } finally {
      await Promise.allSettled([upload, producer.completion]);
    }
    throw error;
  }
}

/** Six serial roles plus recovery; publishing/acceptance remains caller-owned. */
export async function captureBackupV2Generation(
  settings: CaptureSettings,
  context: BackupV2CaptureContext,
) {
  validateCaptureSettings(settings);
  settings = structuredClone(settings);
  if (backupV2SourceConfigSha256(settings) !== context.sourceConfigSha256) {
    fail("source configuration hash");
  }
  const now = context.now ?? (() => new Date());
  let startedAtUtc = now().toISOString();
  await context.native.assertManaged();
  await assertBackupV2Directory(context.stage);
  await context.admit("root");
  const run = createBackupV2MetadataRunner(context.stage, context.native);
  await prepareRecipient(settings, context.stage, run);
  const before = await initialInspection(settings, context.stage, run);
  const tools = await recordToolVersions(context.stage, run);
  const rootSizes = await run("stat", [
    "-c",
    "%s",
    "/boot/Image",
    "/boot/initramfs-linux.img",
  ]);
  if (rootSizes.code !== 0) fail("root boot sizes");
  const rootBytes = rootSizes.stdout.trim().split("\n").map(Number);
  const reused = validateBackupV2ReusedRoles(
    context.reusedRoles ?? [],
    settings,
    before,
    tools,
    rootBytes,
    now().toISOString(),
  );
  startedAtUtc = [
    startedAtUtc,
    ...[...reused.values()].map((entry) => entry.capture.captureStartedAtUtc),
  ].sort()[0];
  const rootMetadata = reused.get("root")?.recovery;
  const metadataBefore = rootMetadata?.role === "root"
    ? rootMetadata.initial
    : before;
  const metadataTools = rootMetadata?.role === "root"
    ? rootMetadata.tools
    : tools;
  const compatibilitySha256 = backupV2CompatibilitySha256(settings, before);
  const roles: BackupV2CapturedRole[] = [];
  const roleMetadata: BackupV2ReusedRole[] = [];
  const attempts = new Set(
    [...reused.values()].map((entry) => entry.capture.attemptId),
  );
  const capture = async (role: BackupV2Role, recovery?: Uint8Array) => {
    await context.admit(role);
    context.signal?.throwIfAborted();
    await assertRecipientPinned(settings, context.stage);
    const previous = reused.get(role);
    if (previous) {
      const metadata = previous.recovery;
      const files = metadata.role === "staging-boot"
        ? {
          "staging-boot.sha.before": metadata.beforeHashes,
          "staging-boot.sha.after": metadata.afterHashes,
          "staging-boot.bytes.before": metadata.beforeBytes,
          "staging-boot.bytes.after": metadata.afterBytes,
        }
        : metadata.role === "oracle-root"
        ? { "oracle-root.swapfile.stat": metadata.swapfileStat }
        : {};
      for (const [name, text] of Object.entries(files)) {
        const file = await Deno.open(`${context.stage}/${name}`, {
          createNew: true,
          write: true,
          mode: 0o600,
        });
        try {
          const writer = file.writable.getWriter();
          await writer.write(encoder.encode(text));
          await writer.close();
        } finally {
          try {
            file.close();
          } catch { /* writable owns closure. */ }
        }
      }
      await assertMountGuards(settings, context.stage, `guard:v2:${role}`, run);
      if (role === "staging-boot") {
        await assertStagingBootParity(context.stage, before);
      }
      roles.push(previous.capture);
      roleMetadata.push(previous);
      return;
    }
    const captureStartedAtUtc = now().toISOString();
    const attemptId = (context.newAttemptId ?? (() => crypto.randomUUID()))();
    if (attempts.has(attemptId)) fail("producer attempt was reused");
    attempts.add(attemptId);
    const producer =
      await (context.createProducer ?? createBackupV2RoleProducer)({
        settings,
        stage: context.stage,
        role,
        attemptId,
        recovery,
        native: context.native,
        signal: context.signal,
        now,
        progress: context.progress,
      });
    const result = await uploadBackupV2RoleProducer({
      settings,
      role,
      attemptId,
      captureStartedAtUtc,
      compatibilitySha256,
      producer,
    }, context);
    await assertMountGuards(settings, context.stage, `guard:v2:${role}`, run);
    if (role === "staging-boot") {
      await assertStagingBootParity(context.stage, before);
    }
    const metadata: BackupV2RoleRecoveryMetadata = role === "root"
      ? {
        role,
        initial: structuredClone(before),
        tools: structuredClone(tools),
        bootBytes: [...rootBytes],
      }
      : role === "staging-boot"
      ? {
        role,
        beforeHashes: await readSmall(
          `${context.stage}/staging-boot.sha.before`,
        ),
        afterHashes: await readSmall(`${context.stage}/staging-boot.sha.after`),
        beforeBytes: await readSmall(
          `${context.stage}/staging-boot.bytes.before`,
        ),
        afterBytes: await readSmall(
          `${context.stage}/staging-boot.bytes.after`,
        ),
      }
      : role === "oracle-root"
      ? {
        role,
        swapfileStat: await readSmall(
          `${context.stage}/oracle-root.swapfile.stat`,
        ),
      }
      : role === "recovery"
      ? {
        role,
        text: new TextDecoder("utf-8", { fatal: true }).decode(recovery!),
        sha256: createHash("sha256").update(recovery!).digest("hex"),
      }
      : { role };
    if (metadata.role !== "recovery") {
      assertBackupV2Budget(
        "metadataRecordBytes",
        encoder.encode(JSON.stringify(metadata)).length,
      );
    }
    roles.push(result);
    roleMetadata.push({ capture: result, recovery: metadata });
    await context.onRole?.(result, metadata);
  };
  for (const role of ROLE_ORDER) await capture(role);
  await assertStagingBootParity(context.stage, before);
  const layoutFinal = await finalInspection(
    settings,
    context.stage,
    before,
    run,
  );
  if (
    backupV2CompatibilitySha256(settings, {
      ...before,
      layout: layoutFinal,
    }) !== compatibilitySha256
  ) fail("final source topology");
  const rootFinal = await run("stat", [
    "-c",
    "%s",
    "/boot/Image",
    "/boot/initramfs-linux.img",
  ]);
  if (rootFinal.code !== 0 || rootFinal.stdout !== rootSizes.stdout) {
    fail("root boot sizes changed");
  }
  const samples = backupV2BootSamples(
    before.bootHashes,
    await readSmall(`${context.stage}/staging-boot.sha.after`),
    rootSizes.stdout.trim().split("\n").map(Number),
    (await readSmall(`${context.stage}/staging-boot.bytes.after`)).trim().split(
      "\n",
    ).map(Number),
  );
  const oldRecovery = reused.get("recovery")?.recovery;
  const recovery = oldRecovery?.role === "recovery"
    ? restoreBackupV2RecoveryMetadata(
      oldRecovery,
      settings,
      metadataBefore,
      roles,
      samples,
    )
    : await collectBackupV2RecoveryMetadata({
      settings,
      stage: context.stage,
      before: metadataBefore,
      layoutFinal,
      tools: metadataTools,
      archives: roles,
      swapRecreation: swapfileRecreation(
        await readSmall(`${context.stage}/oracle-root.swapfile.stat`),
      ),
      startedAtUtc,
      finishedAtUtc: now().toISOString(),
      run,
    }, samples);
  await capture("recovery", recovery.bytes);
  // Catch a boot/package/source change during metadata encryption, too.
  const lastLayout = await finalInspection(
    settings,
    context.stage,
    before,
    run,
  );
  if (
    backupV2CompatibilitySha256(settings, { ...before, layout: lastLayout }) !==
      compatibilitySha256
  ) fail("post-recovery topology");
  return {
    generation: settings.generation,
    roles,
    recovery,
    roleMetadata,
    startedAtUtc,
    finishedAtUtc: now().toISOString(),
    consistency: "live-file-copy" as const,
    sourceShutdown: false as const,
  };
}
