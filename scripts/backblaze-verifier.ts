/**
 * m08-verifier: host-neutral library that proves complete readability of all
 * seven reconstructed ciphertext archives of a validated portable
 * RecoveryIndex and restores exactly four selected boot files for SHA-256
 * comparison against the captured recovery metadata.
 *
 * SCOPE AND LIMITS: this module proves (1) that each reconstructed
 * ciphertext archive is byte-identical to the validated index descriptor
 * (owner-only 0600, one hardlink, canonical path), (2) that its GPG
 * plaintext is a complete, positive-size zstd stream and that the zstd frame
 * integrity test (`zstd -t`) passes, (3) that the six filesystem archives
 * are complete, nonempty tar members (root:
 * ./etc/os-release,./boot/Image,./boot/initramfs-linux.img; staging-boot:
 * ./arch-vmlinuz,./arch-initrd.img; every selected boot member occurs
 * exactly once; every other filesystem role has a complete successful
 * nonempty listing), and (4) that four boot files restored with
 * `tar --extract --to-stdout` are byte-identical to the four captured boot
 * hashes in the recovery metadata (root/staging kernel parity included). It
 * never extracts a directory tree, never writes paths taken from tar
 * headers or from the metadata, never touches a source filesystem, never
 * checks database consistency and never boots a machine: the returned
 * DecryptedVerification carries decryptedRestoreProved true and
 * machineBootRestoreProved false. Full filesystem extraction, database
 * consistency and machine boot verification are out of scope.
 *
 * CONTRACT: the caller holds controller/source locks and owns exclusive
 * trusted input/output directories. The input RecoveryIndex is re-validated
 * with the m04 validator and copied before any await; the m05
 * ReconstructedGeneration result is copied and bound to the exact index
 * generation/recipient/hash and to all seven ordered archive
 * role/format/bytes/sha256/path identities (each path must be the canonical
 * m05 final `<recovery-directory>/<role>.<format>`). The output directory
 * must be an EXISTING canonical absolute real directory, mode 0700, owned by
 * the process that owns the created files, and empty: a nonempty or
 * non-canonical directory fails before any side effect. The directory is
 * bound to its POSIX device+inode+uid+mode and rechecked at every
 * checkpoint; a replacement with the same owner/mode is never accepted.
 *
 * OUTPUTS: only createNew 0600 files are created inside the output
 * directory - the seven compressed plaintext finals (`<role>.<format
 * without .gpg>`, e.g. recovery.json.zst, root.tar.zst) and the four fixed
 * boot sample finals `sample.root.Image`, `sample.root.initramfs-linux.img`,
 * `sample.staging-boot.arch-vmlinuz` and
 * `sample.staging-boot.arch-initrd.img` - each written by the decrypt
 * callback into a task-owned `<name>.partial` first, verified (identity,
 * owner, size, zstd integrity, hash, listing, samples where applicable) and
 * only then published with a create-new hard link and removal of the
 * partial after both paths still address the bound inode. A failure
 * preserves every partial and completed final it created and never returns
 * a receipt; nothing is ever chmodded, re-owned, rewritten, renamed-over or
 * removed except the task-owned partial just linked.
 *
 * DECRYPT: the caller supplies the exactly-typed decryption capability
 * DecryptArchive `(ciphertextPath, destination) => Promise<
 * {integrityChecked: true}>`. The library creates and binds the destination
 * handle (0600, owner, one link), calls the callback which writes the
 * compressed plaintext to that handle and must NOT close it; a callback
 * error or a missing integrityChecked fails visibly, and the library then
 * fsyncs, re-checks handle and pathname identity, closes and continues. The
 * library never receives a private key, agent socket, passphrase or
 * credential; the production caller must provide real GPG integrity-checked
 * decryption only after authorization. Synthetic tests inject synthetic
 * output and are not live restore acceptance.
 *
 * TOOLS: installed zstd and (in production) GNU tar are invoked through
 * Deno.Command with bounded stdout/stderr collection and explicit
 * per-producer status checks (capture-style PIPESTATUS snapshots for the
 * listing pipeline); producer failures are never suppressed. The full tar
 * listing is streamed through a bounded awk summary (entry count plus
 * required-member presence and exact-once boot-member counts); no archive
 * or listing bytes are loaded into memory. Restored byte streams are
 * consumed completely into the bound sample handle while hashed.
 *
 * ERRORS: every failure throws a bounded module error ("Verifier failed
 * (<label>)"). No payload, no metadata-derived filename, no credential and
 * no raw tool output appears in error messages, return values or the
 * receipt; tool diagnostics are bounded and intentionally not propagated.
 * The receipt is produced by a pure validator (validateVerifierReceipt)
 * which rejects malformed, unknown and inconsistent 7-role/4-sample data;
 * that validation is structural and does not itself prove live
 * verification.
 */
import { createHash } from "node:crypto";
import type { Hash } from "node:crypto";

import {
  type IndexArchiveRecord,
  type RecoveryIndex,
  validateRecoveryIndex,
} from "./backblaze-index.ts";
import type {
  ReconstructedArchive,
  ReconstructedGeneration,
} from "./backblaze-recovery.ts";
import type { UploadFormat, UploadRole } from "./backblaze-upload.ts";
import { UPLOAD_ROLE_ORDER } from "./backblaze-upload.ts";
import { pipelineStatusLines } from "./backblaze-capture.ts";
import { shellQuote } from "./backup-guest.ts";

const FAIL_PREFIX = "Verifier failed (";
const READ_BUFFER_BYTES = 1024 * 1024;
/** Decompressed recovery metadata hard bound (mirrors the m04 index bound). */
const MAX_METADATA_BYTES = 8 * 1024 * 1024;
/** Bounded capture of tool stdout/stderr; never propagated into errors. */
const TOOL_STDOUT_CAP = 64 * 1024;
const TOOL_STDERR_CAP = 64 * 1024;

const GENERATION_PATTERN =
  /^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}$/;
const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Literal fixed tar members required on the root archive. */
const ROOT_REQUIRED_MEMBERS = [
  "./etc/os-release",
  "./boot/Image",
  "./boot/initramfs-linux.img",
] as const;
/** Literal fixed tar members required on the staging-boot archive. */
const STAGING_REQUIRED_MEMBERS = [
  "./arch-vmlinuz",
  "./arch-initrd.img",
] as const;
/** Selected boot members: exactly one occurrence in the complete listing. */
const ROOT_BOOT_MEMBERS = [
  "./boot/Image",
  "./boot/initramfs-linux.img",
] as const;
const STAGING_BOOT_MEMBERS = ["./arch-vmlinuz", "./arch-initrd.img"] as const;
/** Expected sha256sum emission paths for the four captured boot hashes. */
const ROOT_BOOT_HASH_PATHS = [
  "/boot/Image",
  "/boot/initramfs-linux.img",
] as const;
const STAGING_BOOT_HASH_PATHS = [
  "./arch-vmlinuz",
  "./arch-initrd.img",
] as const;

/** Ordered fixed boot sample set: role, literal member, fixed sample file
 * name and which captured hash must match it. */
const BOOT_SAMPLES: readonly {
  role: "root" | "staging-boot";
  member: string;
  file: string;
  captured: "kernel" | "initramfs";
}[] = [
  {
    role: "root",
    member: ROOT_BOOT_MEMBERS[0],
    file: "sample.root.Image",
    captured: "kernel",
  },
  {
    role: "root",
    member: ROOT_BOOT_MEMBERS[1],
    file: "sample.root.initramfs-linux.img",
    captured: "initramfs",
  },
  {
    role: "staging-boot",
    member: STAGING_BOOT_MEMBERS[0],
    file: "sample.staging-boot.arch-vmlinuz",
    captured: "kernel",
  },
  {
    role: "staging-boot",
    member: STAGING_BOOT_MEMBERS[1],
    file: "sample.staging-boot.arch-initrd.img",
    captured: "initramfs",
  },
];

/** Caller-supplied decryption capability: writes the compressed plaintext
 * to the bound handle and must not close it. */
export type DecryptArchive = (
  ciphertextPath: string,
  destination: Deno.FsFile,
) => Promise<{ integrityChecked: true }>;

/** One verified archive of the generation, in canonical index order. */
export interface ArchiveVerificationDescriptor {
  role: UploadRole;
  format: UploadFormat;
  ciphertextBytes: number;
  ciphertextSha256: string;
  /** GPG plaintext (zstd stream) length and SHA-256 on the output disk. */
  compressedBytes: number;
  compressedSha256: string;
  /** Complete documented tar entry count; absent for the recovery archive. */
  entries?: number;
}

/** One restored boot file sample, in fixed order. */
export interface BootSampleDescriptor {
  role: "root" | "staging-boot";
  member: string;
  bytes: number;
  sha256: string;
}

/** Small decrypted-restore verification receipt; never an acceptance mark. */
export interface DecryptedVerification {
  schemaVersion: 1;
  generation: string;
  indexSha256: string;
  recipientFingerprint: string;
  recipientSha256: string;
  verifiedAtUtc: string;
  archives: ArchiveVerificationDescriptor[];
  /** SHA-256 of the decompressed recovery metadata JSON. */
  metadataSha256: string;
  bootSamples: BootSampleDescriptor[];
  decryptedRestoreProved: true;
  machineBootRestoreProved: false;
}

/** Validated subset of the recovery metadata that the verifier consumes. */
export interface RecoveryMetadataView {
  generation: string;
  /** Captured root/staging kernel hash (parity enforced). */
  kernelSha256: string;
  /** Captured root/staging initramfs hash (parity enforced). */
  initramfsSha256: string;
}

interface DirectoryIdentity {
  dev: number;
  ino: number;
  uid: number;
  mode: number;
}

interface FileBinding {
  dev: number;
  ino: number;
  uid: number;
  mode: number;
}

interface FileIdentityRecord {
  dev: number;
  ino: number;
  uid: number;
  mode: number;
  nlink: number;
  size: number;
  mtime: number | null;
  ctime: number | null;
}

/** One decrypted but not yet published archive plaintext. */
interface DecryptedArchive {
  partialPath: string;
  finalPath: string;
  binding: FileBinding;
  bytes: number;
  sha256: string;
}

function fail(label: string): never {
  throw new Error(`${FAIL_PREFIX}${label})`);
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(label);
  }
  return value as Record<string, unknown>;
}

function asSafeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) fail(label);
  return value;
}

function asUtcTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !UTC_TIMESTAMP_PATTERN.test(value)) {
    fail(label);
  }
  if (!Number.isFinite(Date.parse(value))) fail(label);
  return value;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function expectedFormat(role: UploadRole): UploadFormat {
  return role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
}

/** Final compressed plaintext name for a validated role/format. */
function compressedFileName(archive: IndexArchiveRecord): string {
  const format = archive.format.replace(/\.gpg$/, "");
  return `${archive.role}.${format}`;
}

function recordFromFileInfo(info: Deno.FileInfo): FileIdentityRecord {
  return {
    dev: info.dev!,
    ino: info.ino!,
    uid: info.uid!,
    mode: (info.mode ?? 0) & 0o777,
    nlink: info.nlink!,
    size: info.size,
    mtime: info.mtime === null ? null : info.mtime.getTime(),
    ctime: info.ctime === null ? null : info.ctime.getTime(),
  };
}

function matchesRecord(
  info: Deno.FileInfo,
  record: FileIdentityRecord,
): boolean {
  if (info.dev !== record.dev || info.ino !== record.ino) return false;
  if (info.uid !== record.uid) return false;
  if (info.mode === null || (info.mode & 0o777) !== record.mode) return false;
  if (info.nlink !== record.nlink) return false;
  if (info.size !== record.size) return false;
  if (
    record.mtime !== null &&
    (info.mtime === null || info.mtime.getTime() !== record.mtime)
  ) {
    return false;
  }
  if (
    record.ctime !== null &&
    (info.ctime === null || info.ctime.getTime() !== record.ctime)
  ) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Output directory identity and state
// ---------------------------------------------------------------------------

/** Check the existing canonical owner-only output directory and return its
 * original identity. */
async function assertOutputDirectory(
  path: string,
): Promise<DirectoryIdentity> {
  if (typeof path !== "string" || !path.startsWith("/")) {
    fail("directory:absolute");
  }
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("directory:missing");
    fail("directory:check");
  }
  if (info.isSymlink || !info.isDirectory) fail("directory:not-directory");
  if (info.mode === null || (info.mode & 0o777) !== 0o700) {
    fail("directory:permissions");
  }
  if (typeof info.uid !== "number") fail("directory:identity");
  if (info.dev === null || info.ino === null) fail("directory:identity");
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail("directory:realpath");
  }
  if (real !== path) fail("directory:realpath");
  return {
    dev: info.dev,
    ino: info.ino,
    uid: info.uid,
    mode: info.mode & 0o777,
  };
}

async function assertDirectoryIdentity(
  path: string,
  expected: DirectoryIdentity,
): Promise<void> {
  const actual = await assertOutputDirectory(path);
  if (
    actual.dev !== expected.dev ||
    actual.ino !== expected.ino ||
    actual.uid !== expected.uid ||
    actual.mode !== expected.mode
  ) {
    fail("directory:identity");
  }
}

/** The output directory must contain exactly the already-published finals:
 * unknown entries, abandoned partials of a previous run and replaced
 * directories all fail before the next side effect. */
async function assertOutputState(
  directory: string,
  identity: DirectoryIdentity,
  expected: ReadonlySet<string>,
): Promise<void> {
  await assertDirectoryIdentity(directory, identity);
  let count = 0;
  try {
    for await (const entry of Deno.readDir(directory)) {
      if (!expected.has(entry.name)) fail("output:entry");
      count += 1;
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
    fail("output:read");
  }
  if (count !== expected.size) fail("output:entry");
}

/** Sync the directory through a handle bound to the original identity. */
async function syncDirectory(
  path: string,
  identity: DirectoryIdentity,
): Promise<void> {
  let directory: Deno.FsFile | null = null;
  try {
    directory = await Deno.open(path, { read: true });
    const info = await directory.stat();
    if (info.isSymlink || !info.isDirectory) fail("directory:identity");
    if (info.dev !== identity.dev || info.ino !== identity.ino) {
      fail("directory:identity");
    }
    await directory.sync();
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
    fail("directory:sync");
  } finally {
    directory?.close();
  }
}

// ---------------------------------------------------------------------------
// Ciphertext pre-verification
// ---------------------------------------------------------------------------

/** Re-hash one existing canonical owner-only 0600 nlink-1 ciphertext file
 * with bounded streamed SHA-256 and reject any drift: the pre-open lstat
 * record (including mtime/ctime where available) must still match after the
 * read, and length plus SHA-256 must equal the validated index descriptor. */
async function verifyCiphertext(
  path: string,
  owner: number,
  archive: IndexArchiveRecord,
): Promise<FileIdentityRecord> {
  let before: Deno.FileInfo;
  try {
    before = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("ciphertext:missing");
    fail("ciphertext:check");
  }
  if (before.isSymlink || !before.isFile) fail("ciphertext:identity");
  if (before.mode === null || (before.mode & 0o777) !== 0o600) {
    fail("ciphertext:permissions");
  }
  if (before.uid !== owner) fail("ciphertext:owner");
  if (before.nlink !== 1) fail("ciphertext:hardlink");
  if (before.dev === null || before.ino === null) fail("ciphertext:identity");
  if (before.size !== archive.bytes) fail("ciphertext:length");
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail("ciphertext:identity");
  }
  if (real !== path) fail("ciphertext:identity");
  let file: Deno.FsFile;
  try {
    file = await Deno.open(path, { read: true });
  } catch {
    fail("ciphertext:read");
  }
  try {
    let openInfo: Deno.FileInfo;
    try {
      openInfo = await file.stat();
    } catch {
      fail("ciphertext:read");
    }
    if (!openInfo.isFile) fail("ciphertext:identity");
    if (openInfo.dev !== before.dev || openInfo.ino !== before.ino) {
      fail("ciphertext:identity");
    }
    const hasher = createHash("sha256");
    const buffer = new Uint8Array(READ_BUFFER_BYTES);
    let total = 0;
    while (true) {
      let n: number | null;
      try {
        n = await file.read(buffer);
      } catch {
        fail("ciphertext:read");
      }
      if (n === null) break;
      if (n === 0) fail("ciphertext:read");
      total += n;
      if (total > archive.bytes) fail("ciphertext:length");
      hasher.update(buffer.subarray(0, n));
    }
    if (total !== archive.bytes) fail("ciphertext:length");
    if (hasher.digest("hex") !== archive.sha256) fail("ciphertext:hash");
    const record = recordFromFileInfo(before);
    let afterOpen: Deno.FileInfo;
    let afterPath: Deno.FileInfo;
    try {
      afterOpen = await file.stat();
      afterPath = await Deno.lstat(path);
    } catch {
      fail("ciphertext:drift");
    }
    if (!matchesRecord(afterOpen, record)) fail("ciphertext:drift");
    if (!matchesRecord(afterPath, record)) fail("ciphertext:drift");
    return record;
  } finally {
    file.close();
  }
}

/** Recheck that a ciphertext path still addresses the pre-verified record
 * immediately before its decrypt callback is invoked. */
async function assertCiphertextRecord(
  path: string,
  record: FileIdentityRecord,
): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch {
    fail("ciphertext:changed");
  }
  if (info.isSymlink || !info.isFile) fail("ciphertext:drift");
  if (!matchesRecord(info, record)) fail("ciphertext:drift");
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail("ciphertext:drift");
  }
  if (real !== path) fail("ciphertext:drift");
}

// ---------------------------------------------------------------------------
// Bounded child-process helpers
// ---------------------------------------------------------------------------

/** Read a child stream with a hard cap; on overflow the child is killed so
 * the remaining streams can close and no caller ever blocks. */
async function readBounded(
  stream: ReadableStream<Uint8Array>,
  cap: number,
  label: string,
  child: Deno.ChildProcess,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  try {
    while (true) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await reader.read();
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {
          // already exited; the bounded failure is reported below
        }
        fail(label);
      }
      const { done, value } = chunk;
      if (done) break;
      if (value.byteLength > cap - total) {
        try {
          child.kill("SIGKILL");
        } catch {
          // already exited; the bounded failure is reported below
        }
        fail(label);
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Run one bounded command and return its status plus capped stdout. Raw
 * diagnostics are bounded and never propagated to callers. */
async function runTool(
  argv: string[],
  label: string,
): Promise<{ code: number; stdout: Uint8Array }> {
  const child = new Deno.Command(argv[0], {
    args: argv.slice(1),
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const stdoutP = readBounded(
    child.stdout,
    TOOL_STDOUT_CAP,
    `${label}:stdout`,
    child,
  );
  const stderrP = readBounded(
    child.stderr,
    TOOL_STDERR_CAP,
    `${label}:stderr`,
    child,
  );
  const [stdout] = await Promise.all([stdoutP, stderrP]);
  const status = await child.status;
  return { code: status.code, stdout };
}

/** Complete zstd frame integrity test of a compressed plaintext file. */
async function assertZstdIntegrity(path: string): Promise<void> {
  const result = await runTool(["zstd", "-t", path], "zstd");
  if (result.code !== 0) fail("zstd:integrity");
}

/** Complete zstd decompression of the recovery metadata, hard-bounded to
 * MAX_METADATA_BYTES; returns the plaintext bytes. */
async function decompressMetadata(path: string): Promise<Uint8Array> {
  const child = new Deno.Command("zstd", {
    args: ["-dc", path],
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const stdoutP = readBounded(
    child.stdout,
    MAX_METADATA_BYTES,
    "metadata:size",
    child,
  );
  const stderrP = readBounded(child.stderr, TOOL_STDERR_CAP, "metadata", child);
  const [stdout] = await Promise.all([stdoutP, stderrP]);
  const status = await child.status;
  if (status.code !== 0) fail("metadata:decompress");
  return stdout;
}

/** Bounded awk summary program: entry count, required-member presence and
 * exact-once counts for every selected boot member. One pass, no buffering
 * of the listing. */
function inventoryAwkProgram(
  required: readonly string[],
  exact: readonly string[],
): string {
  const counters: [string, string][] = [
    ...required.map((member, index) =>
      [`r${index}`, member] as [string, string]
    ),
    ...exact.map((member, index) => [`e${index}`, member] as [string, string]),
  ];
  const exactCounters = new Set(exact.map((_, index) => `e${index}`));
  const lines: string[] = [];
  lines.push("{");
  lines.push("  n++");
  for (const [counter, member] of counters) {
    lines.push(`  if ($0 == ${JSON.stringify(member)}) ${counter} += 1`);
  }
  lines.push("}");
  lines.push("END {");
  lines.push('  printf "entries=%d\\n", n');
  lines.push('  if (n == 0) { print "empty archive" > "/dev/stderr"; exit 1 }');
  for (const [counter, member] of counters) {
    if (exactCounters.has(counter)) {
      lines.push(
        `  if (${counter} != 1) { print ${
          JSON.stringify(`member ${member} occurrence`)
        } > "/dev/stderr"; exit 1 }`,
      );
    } else {
      lines.push(
        `  if (${counter} < 1) { print ${
          JSON.stringify(`missing ${member}`)
        } > "/dev/stderr"; exit 1 }`,
      );
    }
  }
  lines.push("}");
  return lines.join("\n");
}

const INVENTORY_PRODUCERS = [
  { label: "inventory-zstd", variable: "iz", exitCode: 73 },
  { label: "inventory-tar", variable: "it", exitCode: 74 },
  { label: "inventory-awk", variable: "ia", exitCode: 75 },
];

/** Full zstd decompression and GNU tar listing to completion with checked
 * producer statuses; requires a nonempty archive, every required member and
 * exactly one occurrence of each selected boot member. Returns the complete
 * entry count (bounded); no listing bytes are held in memory. */
async function inventoryArchive(
  compressedPath: string,
  required: readonly string[],
  exact: readonly string[],
): Promise<number> {
  const pipeline = `zstd -dc ${
    shellQuote(compressedPath)
  } | tar -t -f - | awk ${shellQuote(inventoryAwkProgram(required, exact))}`;
  const script = pipelineStatusLines(pipeline, INVENTORY_PRODUCERS).join("\n");
  const child = new Deno.Command("bash", {
    args: ["-c", script],
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const stdoutP = readBounded(child.stdout, TOOL_STDOUT_CAP, "listing", child);
  const stderrP = readBounded(child.stderr, TOOL_STDERR_CAP, "listing", child);
  const [stdout] = await Promise.all([stdoutP, stderrP]);
  const status = await child.status;
  if (status.code !== 0) fail("listing:producer");
  const line = new TextDecoder().decode(stdout).trim();
  const match = /^entries=(\d+)$/.exec(line);
  if (match === null) fail("listing:summary");
  const entries = Number(match[1]);
  if (!Number.isSafeInteger(entries) || entries < 1) fail("listing:summary");
  return entries;
}

// ---------------------------------------------------------------------------
// Handle/path identity and partial/publication
// ---------------------------------------------------------------------------

async function bindCreatedFile(
  file: Deno.FsFile,
  owner: number,
  label: string,
): Promise<FileBinding> {
  let info: Deno.FileInfo;
  try {
    info = await file.stat();
  } catch {
    fail(label);
  }
  if (info.isSymlink || !info.isFile) fail(`${label}:identity`);
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    fail(`${label}:permissions`);
  }
  if (info.uid !== owner) fail(`${label}:owner`);
  if (info.nlink !== 1) fail(`${label}:hardlink`);
  if (info.dev === null || info.ino === null) fail(`${label}:identity`);
  return {
    dev: info.dev,
    ino: info.ino,
    uid: info.uid,
    mode: info.mode & 0o777,
  };
}

async function assertHandleBound(
  file: Deno.FsFile,
  binding: FileBinding,
  size: number,
  label: string,
): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await file.stat();
  } catch {
    fail(label);
  }
  if (info.isSymlink || !info.isFile) fail(`${label}:identity`);
  if (info.dev !== binding.dev || info.ino !== binding.ino) {
    fail(`${label}:identity`);
  }
  if (info.uid !== binding.uid) fail(`${label}:owner`);
  if (info.mode === null || (info.mode & 0o777) !== binding.mode) {
    fail(`${label}:permissions`);
  }
  if (info.nlink !== 1) fail(`${label}:hardlink`);
  if (info.size !== size) fail(`${label}:length`);
}

async function assertPathBound(
  path: string,
  binding: FileBinding,
  nlink: number,
  size: number,
  label: string,
): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch {
    fail(label);
  }
  if (info.isSymlink || !info.isFile) fail(`${label}:identity`);
  if (info.dev !== binding.dev || info.ino !== binding.ino) {
    fail(`${label}:identity`);
  }
  if (info.uid !== binding.uid) fail(`${label}:owner`);
  if (info.mode === null || (info.mode & 0o777) !== binding.mode) {
    fail(`${label}:permissions`);
  }
  if (info.nlink !== nlink) fail(`${label}:hardlink`);
  if (info.size !== size) fail(`${label}:length`);
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail(`${label}:identity`);
  }
  if (real !== path) fail(`${label}:identity`);
}

async function assertLinkedPair(
  partialPath: string,
  finalPath: string,
  binding: FileBinding,
  size: number,
  label: string,
): Promise<void> {
  let partialInfo: Deno.FileInfo;
  let finalInfo: Deno.FileInfo;
  try {
    partialInfo = await Deno.lstat(partialPath);
    finalInfo = await Deno.lstat(finalPath);
  } catch {
    fail(label);
  }
  if (
    partialInfo.isSymlink || !partialInfo.isFile ||
    finalInfo.isSymlink || !finalInfo.isFile
  ) {
    fail(label);
  }
  if (partialInfo.dev !== binding.dev || partialInfo.ino !== binding.ino) {
    fail(label);
  }
  if (finalInfo.dev !== binding.dev || finalInfo.ino !== binding.ino) {
    fail(label);
  }
  if (partialInfo.uid !== binding.uid || finalInfo.uid !== binding.uid) {
    fail(label);
  }
  if (
    partialInfo.mode === null || finalInfo.mode === null ||
    (partialInfo.mode & 0o777) !== binding.mode ||
    (finalInfo.mode & 0o777) !== binding.mode
  ) {
    fail(label);
  }
  if (partialInfo.nlink !== 2 || finalInfo.nlink !== 2) fail(label);
  if (partialInfo.size !== size || finalInfo.size !== size) fail(label);
}

/** Publish the bound partial as a create-new final: after the link both
 * paths address the original inode with two links, after the partial
 * removal the final must be that inode with exactly one link, and both
 * paths must be canonical. Returns the final identity record. */
async function publishPartial(
  partialPath: string,
  finalPath: string,
  binding: FileBinding,
  size: number,
  directory: string,
  identity: DirectoryIdentity,
): Promise<FileIdentityRecord> {
  await assertDirectoryIdentity(directory, identity);
  await assertPathBound(partialPath, binding, 1, size, "partial");
  try {
    await Deno.link(partialPath, finalPath);
  } catch (error) {
    if (error instanceof Deno.errors.AlreadyExists) fail("final:exists");
    fail("write");
  }
  await assertLinkedPair(partialPath, finalPath, binding, size, "final:link");
  await assertDirectoryIdentity(directory, identity);
  await assertLinkedPair(partialPath, finalPath, binding, size, "final:link");
  try {
    await Deno.remove(partialPath);
  } catch {
    fail("write");
  }
  let finalInfo: Deno.FileInfo;
  try {
    finalInfo = await Deno.lstat(finalPath);
  } catch {
    fail("final:changed");
  }
  if (finalInfo.isSymlink || !finalInfo.isFile) fail("final:identity");
  if (finalInfo.dev !== binding.dev || finalInfo.ino !== binding.ino) {
    fail("final:identity");
  }
  if (finalInfo.uid !== binding.uid) fail("final:owner");
  if (finalInfo.mode === null || (finalInfo.mode & 0o777) !== binding.mode) {
    fail("final:permissions");
  }
  if (finalInfo.nlink !== 1) fail("final:hardlink");
  if (finalInfo.size !== size) fail("final:length");
  let real: string;
  try {
    real = await Deno.realPath(finalPath);
  } catch {
    fail("final:identity");
  }
  if (real !== finalPath) fail("final:identity");
  return recordFromFileInfo(finalInfo);
}

/** Recheck a retained final identity record on its pathname. */
async function assertRecordedFinal(
  path: string,
  record: FileIdentityRecord,
): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch {
    fail("final:changed");
  }
  if (info.isSymlink || !info.isFile) fail("final:drift");
  if (!matchesRecord(info, record)) fail("final:drift");
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail("final:drift");
  }
  if (real !== path) fail("final:drift");
}

// ---------------------------------------------------------------------------
// Streamed writes
// ---------------------------------------------------------------------------

async function writeProgress(
  file: Deno.FsFile,
  bytes: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const remaining = bytes.subarray(offset);
    let written: number;
    try {
      written = await file.write(remaining);
    } catch {
      fail("write");
    }
    if (!Number.isSafeInteger(written) || written > remaining.byteLength) {
      fail("write:count");
    }
    if (written <= 0) fail("write:progress");
    offset += written;
  }
}

/** Stream-hash the closed partial with bounded reads; its bound identity
 * must be unchanged before and after the read. */
async function hashPartial(
  partialPath: string,
  binding: FileBinding,
  expectedSize: number,
): Promise<string> {
  let file: Deno.FsFile;
  try {
    file = await Deno.open(partialPath, { read: true });
  } catch {
    fail("partial:read");
  }
  try {
    let openInfo: Deno.FileInfo;
    try {
      openInfo = await file.stat();
    } catch {
      fail("partial:read");
    }
    if (!openInfo.isFile) fail("partial:identity");
    if (openInfo.dev !== binding.dev || openInfo.ino !== binding.ino) {
      fail("partial:identity");
    }
    const hasher = createHash("sha256");
    const buffer = new Uint8Array(READ_BUFFER_BYTES);
    let total = 0;
    while (true) {
      let n: number | null;
      try {
        n = await file.read(buffer);
      } catch {
        fail("partial:read");
      }
      if (n === null) break;
      if (n === 0) fail("partial:read");
      total += n;
      if (total > expectedSize) fail("partial:length");
      hasher.update(buffer.subarray(0, n));
    }
    if (total !== expectedSize) fail("partial:length");
    let afterPath: Deno.FileInfo;
    try {
      afterPath = await Deno.lstat(partialPath);
    } catch {
      fail("partial:drift");
    }
    if (
      afterPath.isSymlink || !afterPath.isFile ||
      afterPath.dev !== binding.dev ||
      afterPath.ino !== binding.ino ||
      afterPath.uid !== binding.uid ||
      afterPath.mode === null ||
      (afterPath.mode & 0o777) !== binding.mode ||
      afterPath.nlink !== 1 ||
      afterPath.size !== expectedSize
    ) {
      fail("partial:drift");
    }
    return hasher.digest("hex");
  } finally {
    file.close();
  }
}

// ---------------------------------------------------------------------------
// Decrypt one archive into its compressed plaintext partial
// ---------------------------------------------------------------------------

/** Decrypt one ciphertext archive into a fresh createNew 0600 partial,
 * require positive bytes and a bound handle/path/owner/size, then check
 * complete zstd integrity and stream-hash the partial. The callback may
 * fail (decrypt) or omit the integrity proof (decrypt:integrity). The
 * partial is NOT published here; the caller publishes it only after every
 * archive check passed, so a failure always preserves the partial. */
async function decryptArchivePartial(params: {
  archive: IndexArchiveRecord;
  ciphertextPath: string;
  outputDirectory: string;
  directory: DirectoryIdentity;
  decrypt: DecryptArchive;
}): Promise<DecryptedArchive> {
  const {
    archive,
    ciphertextPath,
    outputDirectory,
    directory,
    decrypt,
  } = params;
  const finalName = compressedFileName(archive);
  const finalPath = `${outputDirectory}/${finalName}`;
  const partialPath = `${finalPath}.partial`;
  let file: Deno.FsFile;
  try {
    file = await Deno.open(partialPath, {
      write: true,
      createNew: true,
      mode: 0o600,
    });
  } catch (error) {
    if (error instanceof Deno.errors.AlreadyExists) fail("partial:exists");
    fail("write");
  }
  let binding: FileBinding;
  try {
    binding = await bindCreatedFile(file, directory.uid, "partial");
  } catch (error) {
    file.close();
    throw error;
  }
  let size = 0;
  try {
    let result: { integrityChecked: boolean };
    try {
      result = await decrypt(ciphertextPath, file);
    } catch {
      fail("decrypt");
    }
    if (result === null || result.integrityChecked !== true) {
      fail("decrypt:integrity");
    }
    try {
      await file.sync();
    } catch {
      fail("write");
    }
    let openInfo: Deno.FileInfo;
    try {
      openInfo = await file.stat();
    } catch {
      fail("partial:identity");
    }
    if (
      !openInfo.isFile || openInfo.dev !== binding.dev ||
      openInfo.ino !== binding.ino
    ) {
      fail("partial:identity");
    }
    if (openInfo.uid !== binding.uid) fail("partial:owner");
    if (openInfo.mode === null || (openInfo.mode & 0o777) !== binding.mode) {
      fail("partial:permissions");
    }
    if (openInfo.nlink !== 1) fail("partial:hardlink");
    if (openInfo.size <= 0) fail("partial:length");
    size = openInfo.size;
    await assertHandleBound(file, binding, size, "partial");
    await assertPathBound(partialPath, binding, 1, size, "partial");
  } catch (error) {
    try {
      file.close();
    } catch {
      // The callback closed the handle against the contract; the bounded
      // failure below must not be masked by the cleanup close.
    }
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
    fail("partial:identity");
  }
  file.close();
  await assertZstdIntegrity(partialPath);
  const sha256 = await hashPartial(partialPath, binding, size);
  return {
    partialPath,
    finalPath,
    binding,
    bytes: size,
    sha256,
  };
}

// ---------------------------------------------------------------------------
// Restore one boot member
// ---------------------------------------------------------------------------

/** Consume the complete `tar --to-stdout` stream into the bound handle
 * while hashing; both producer statuses must be zero (never suppress
 * tar/zstd failures). The restored byte count must be positive. */
async function restoreMemberToHandle(params: {
  compressedPath: string;
  member: string;
  file: Deno.FsFile;
  hasher: Hash;
}): Promise<number> {
  const zstd = new Deno.Command("zstd", {
    args: ["-dc", params.compressedPath],
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const tar = new Deno.Command("tar", {
    args: ["--extract", "--to-stdout", "--file=-", params.member],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  let consumed = 0;
  const settled = await Promise.allSettled([
    pumpZstdToTar(zstd.stdout, tar.stdin),
    consumeTarStdout(tar.stdout, params.file, params.hasher).then((count) => {
      consumed = count;
    }),
    readBounded(zstd.stderr, TOOL_STDERR_CAP, "restore", zstd),
    readBounded(tar.stderr, TOOL_STDERR_CAP, "restore", tar),
  ]);
  const rejected = settled.find((entry) => entry.status === "rejected");
  if (rejected !== undefined) {
    try {
      zstd.kill("SIGKILL");
    } catch {
      // already exited
    }
    try {
      tar.kill("SIGKILL");
    } catch {
      // already exited
    }
    await zstd.status;
    await tar.status;
    const reason = (rejected as PromiseRejectedResult).reason;
    // Only bounded module errors may escape; a raw stream error is mapped.
    if (reason instanceof Error && reason.message.startsWith(FAIL_PREFIX)) {
      throw reason;
    }
    fail("restore");
  }
  const zstdStatus = await zstd.status;
  const tarStatus = await tar.status;
  if (
    zstdStatus.code !== 0 ||
    tarStatus.code !== 0 ||
    (settled[0] as PromiseFulfilledResult<boolean>).value === false
  ) {
    fail("restore:pipeline");
  }
  if (consumed <= 0) fail("restore:empty");
  return consumed;
}

/** Forward every zstd byte to tar and always drain the source to EOF; a
 * write failure (tar exited early) is reported as false, never as a raw
 * error, so the caller's producer-status checks are authoritative. */
async function pumpZstdToTar(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
): Promise<boolean> {
  const reader = source.getReader();
  const writer = destination.getWriter();
  let failed = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!failed) {
        try {
          await writer.write(value);
        } catch {
          failed = true;
        }
      }
    }
  } finally {
    reader.releaseLock();
    try {
      await writer.close();
    } catch {
      // destination already closed by the tar process
    }
  }
  return !failed;
}

/** Consume the complete restored stream: bounded chunks, hashed inline and
 * written with a checked progress loop; every byte is consumed. */
async function consumeTarStdout(
  source: ReadableStream<Uint8Array>,
  file: Deno.FsFile,
  hasher: Hash,
): Promise<number> {
  const reader = source.getReader();
  let total = 0;
  const buffer = new Uint8Array(READ_BUFFER_BYTES);
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      hasher.update(value);
      if (value.byteLength <= buffer.byteLength) {
        buffer.set(value);
        await writeProgress(file, buffer.subarray(0, value.byteLength));
      } else {
        await writeProgress(file, value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  return total;
}

/** Restore one literal fixed tar member into its fixed owned sample final
 * (createNew 0600) and return the exact byte count, SHA-256 and the
 * published final identity record. */
async function restoreBootSample(params: {
  compressedPath: string;
  role: "root" | "staging-boot";
  member: string;
  sampleFile: string;
  outputDirectory: string;
  directory: DirectoryIdentity;
  expectedSha256: string;
}): Promise<{
  descriptor: BootSampleDescriptor;
  record: FileIdentityRecord;
}> {
  const {
    compressedPath,
    role,
    member,
    sampleFile,
    outputDirectory,
    directory,
    expectedSha256,
  } = params;
  const partialPath = `${outputDirectory}/${sampleFile}.partial`;
  const finalPath = `${outputDirectory}/${sampleFile}`;
  let file: Deno.FsFile;
  try {
    file = await Deno.open(partialPath, {
      write: true,
      createNew: true,
      mode: 0o600,
    });
  } catch (error) {
    if (error instanceof Deno.errors.AlreadyExists) fail("partial:exists");
    fail("write");
  }
  let binding: FileBinding;
  try {
    binding = await bindCreatedFile(file, directory.uid, "partial");
  } catch (error) {
    file.close();
    throw error;
  }
  const hasher = createHash("sha256");
  let bytes: number;
  try {
    bytes = await restoreMemberToHandle({
      compressedPath,
      member,
      file,
      hasher,
    });
    try {
      await file.sync();
    } catch {
      fail("write");
    }
    await assertHandleBound(file, binding, bytes, "partial");
    await assertPathBound(partialPath, binding, 1, bytes, "partial");
  } catch (error) {
    try {
      file.close();
    } catch {
      // Already closed; the bounded failure below must not be masked.
    }
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
    fail("partial:identity");
  }
  file.close();
  const sha256 = hasher.digest("hex");
  if (sha256 !== expectedSha256) fail("sample:hash");
  const record = await publishPartial(
    partialPath,
    finalPath,
    binding,
    bytes,
    outputDirectory,
    directory,
  );
  return {
    descriptor: { role, member, bytes, sha256 },
    record,
  };
}

// ---------------------------------------------------------------------------
// Pure metadata and receipt validation
// ---------------------------------------------------------------------------

/** Parse one sha256sum emission pair: exactly two lines, each with a
 * 64-hex hash and the exact expected source path. */
function parseBootHashPair(
  text: unknown,
  label: string,
  expectedPaths: readonly string[],
): [string, string] {
  if (typeof text !== "string") fail(label);
  const lines = text.trim().split("\n").filter((line) => line.length > 0);
  if (lines.length !== 2) fail(label);
  const hashes: string[] = [];
  for (let i = 0; i < 2; i += 1) {
    const fields = lines[i].trim().split(/\s+/);
    if (fields.length !== 2) fail(label);
    const [hash, path] = fields;
    if (!SHA256_PATTERN.test(hash)) fail(label);
    if (path !== expectedPaths[i]) fail(label);
    hashes.push(hash);
  }
  return [hashes[0], hashes[1]];
}

/** Pure validator of the capture recovery metadata (the plaintext JSON of
 * the recovery archive) against the validated index: generation, recipient
 * fingerprint/publicSha256, consistency flags, the six filesystem archive
 * descriptors, the final package/boot guards and the exact four captured
 * boot hashes with root/staging parity. Unknown extra metadata fields are
 * tolerated: the metadata is produced by the capture module and may carry
 * additional recovery context; only the fields named here are bound. */
export function validateRecoveryMetadata(
  input: unknown,
  index: RecoveryIndex,
): RecoveryMetadataView {
  const record = asObject(input, "metadata:shape");
  if (record.schemaVersion !== 1) fail("metadata:version");
  const generation = record.generation;
  if (typeof generation !== "string" || generation !== index.generation) {
    fail("metadata:generation");
  }
  if (record.consistency !== "live-file-copy") fail("metadata:consistency");
  if (record.sourceShutdown !== false) fail("metadata:shutdown");
  if (record.machineBootRestoreProved !== false) fail("metadata:flags");
  const recipient = asObject(record.recipient, "metadata:recipient");
  if (
    Object.keys(recipient).length !== 2 ||
    recipient.fingerprint !== index.recipientFingerprint ||
    recipient.publicSha256 !== index.recipientSha256
  ) {
    fail("metadata:recipient");
  }
  if (!FINGERPRINT_PATTERN.test(String(recipient.fingerprint))) {
    fail("metadata:recipient");
  }
  if (!SHA256_PATTERN.test(String(recipient.publicSha256))) {
    fail("metadata:recipient");
  }
  const metadataArchives = record.archives;
  if (!Array.isArray(metadataArchives) || metadataArchives.length !== 6) {
    fail("metadata:archives");
  }
  const indexArchives = new Map<UploadRole, IndexArchiveRecord>();
  for (const archive of index.archives) {
    if (archive.role !== "recovery") {
      indexArchives.set(archive.role, archive);
    }
  }
  const matchedRoles = new Set<UploadRole>();
  for (const candidate of metadataArchives) {
    const entry = asObject(candidate, "metadata:archives");
    const role = entry.role;
    if (typeof role !== "string" || !indexArchives.has(role as UploadRole)) {
      fail("metadata:archives");
    }
    const expected = indexArchives.get(role as UploadRole)!;
    if (entry.format !== expected.format) fail("metadata:archives");
    if (asSafeInteger(entry.bytes, "metadata:bytes") !== expected.bytes) {
      fail("metadata:archives");
    }
    if (entry.sha256 !== expected.sha256) fail("metadata:archives");
    matchedRoles.add(role as UploadRole);
  }
  if (matchedRoles.size !== 6) fail("metadata:archives");
  const finalChecks = asObject(record.finalChecks, "metadata:guards");
  if (
    finalChecks.pacmanLockAbsent !== true ||
    finalChecks.packagesUnchanged !== true ||
    finalChecks.bootHashesUnchanged !== true
  ) {
    fail("metadata:guards");
  }
  const bootHashes = asObject(record.bootHashes, "metadata:boot");
  const [rootKernel, rootInitramfs] = parseBootHashPair(
    bootHashes.root,
    "metadata:boot",
    ROOT_BOOT_HASH_PATHS,
  );
  const [stagingKernel, stagingInitramfs] = parseBootHashPair(
    bootHashes.stagingBoot,
    "metadata:boot",
    STAGING_BOOT_HASH_PATHS,
  );
  if (rootKernel !== stagingKernel || rootInitramfs !== stagingInitramfs) {
    fail("metadata:boot");
  }
  return {
    generation: index.generation,
    kernelSha256: rootKernel,
    initramfsSha256: rootInitramfs,
  };
}

const RECEIPT_KEYS = new Set([
  "schemaVersion",
  "generation",
  "indexSha256",
  "recipientFingerprint",
  "recipientSha256",
  "verifiedAtUtc",
  "archives",
  "metadataSha256",
  "bootSamples",
  "decryptedRestoreProved",
  "machineBootRestoreProved",
]);

const ARCHIVE_DESCRIPTOR_KEYS = new Set([
  "role",
  "format",
  "ciphertextBytes",
  "ciphertextSha256",
  "compressedBytes",
  "compressedSha256",
  "entries",
]);

const BOOT_SAMPLE_KEYS = new Set(["role", "member", "bytes", "sha256"]);

const RECEIPT_BOOT_SAMPLES: readonly {
  role: "root" | "staging-boot";
  member: string;
}[] = BOOT_SAMPLES.map(({ role, member }) => ({ role, member }));

/** Pure structural receipt validation for the later controller: every field
 * is exactly typed, unknown or missing fields fail, the seven archive roles
 * are exactly the canonical index order with format-compatible descriptors
 * and the four boot samples are the exact fixed members with positive counts
 * and root/staging kernel plus initramfs parity. This is structural
 * validation of a verified receipt; it does not prove live verification by
 * itself. */
export function validateVerifierReceipt(
  input: unknown,
): DecryptedVerification {
  const record = asObject(input, "receipt:shape");
  for (const key of Object.keys(record)) {
    if (!RECEIPT_KEYS.has(key)) fail("receipt:keys");
  }
  if (record.schemaVersion !== 1) fail("receipt:version");
  const generation = record.generation;
  if (typeof generation !== "string" || !GENERATION_PATTERN.test(generation)) {
    fail("receipt:generation");
  }
  const indexSha256 = record.indexSha256;
  if (typeof indexSha256 !== "string" || !SHA256_PATTERN.test(indexSha256)) {
    fail("receipt:index-sha256");
  }
  const recipientFingerprint = record.recipientFingerprint;
  if (
    typeof recipientFingerprint !== "string" ||
    !FINGERPRINT_PATTERN.test(recipientFingerprint)
  ) {
    fail("receipt:recipient");
  }
  const recipientSha256 = record.recipientSha256;
  if (
    typeof recipientSha256 !== "string" ||
    !SHA256_PATTERN.test(recipientSha256)
  ) {
    fail("receipt:recipient");
  }
  const verifiedAtUtc = asUtcTimestamp(record.verifiedAtUtc, "receipt:time");
  const metadataSha256 = record.metadataSha256;
  if (
    typeof metadataSha256 !== "string" ||
    !SHA256_PATTERN.test(metadataSha256)
  ) {
    fail("receipt:metadata-sha256");
  }
  if (record.decryptedRestoreProved !== true) fail("receipt:flags");
  if (record.machineBootRestoreProved !== false) fail("receipt:flags");
  const archivesInput = record.archives;
  if (!Array.isArray(archivesInput) || archivesInput.length !== 7) {
    fail("receipt:archives");
  }
  const archives: ArchiveVerificationDescriptor[] = [];
  for (let i = 0; i < UPLOAD_ROLE_ORDER.length; i += 1) {
    const role = UPLOAD_ROLE_ORDER[i];
    const entry = asObject(archivesInput[i], "receipt:archives");
    for (const key of Object.keys(entry)) {
      if (!ARCHIVE_DESCRIPTOR_KEYS.has(key)) fail("receipt:archives");
    }
    if (entry.role !== role || entry.format !== expectedFormat(role)) {
      fail("receipt:archives");
    }
    const ciphertextBytes = asSafeInteger(
      entry.ciphertextBytes,
      "receipt:archives",
    );
    const compressedBytes = asSafeInteger(
      entry.compressedBytes,
      "receipt:archives",
    );
    if (ciphertextBytes <= 0 || compressedBytes <= 0) fail("receipt:archives");
    if (
      typeof entry.ciphertextSha256 !== "string" ||
      !SHA256_PATTERN.test(entry.ciphertextSha256)
    ) {
      fail("receipt:archives");
    }
    if (
      typeof entry.compressedSha256 !== "string" ||
      !SHA256_PATTERN.test(entry.compressedSha256)
    ) {
      fail("receipt:archives");
    }
    let entries: number | undefined;
    if (role === "recovery") {
      if ("entries" in entry) fail("receipt:archives");
    } else {
      if (!("entries" in entry)) fail("receipt:archives");
      entries = asSafeInteger(entry.entries, "receipt:archives");
      if (entries <= 0) fail("receipt:archives");
    }
    archives.push({
      role,
      format: expectedFormat(role),
      ciphertextBytes,
      ciphertextSha256: entry.ciphertextSha256 as string,
      compressedBytes,
      compressedSha256: entry.compressedSha256 as string,
      ...(entries === undefined ? {} : { entries }),
    });
  }
  const samplesInput = record.bootSamples;
  if (!Array.isArray(samplesInput) || samplesInput.length !== 4) {
    fail("receipt:samples");
  }
  const bootSamples: BootSampleDescriptor[] = [];
  for (let i = 0; i < RECEIPT_BOOT_SAMPLES.length; i += 1) {
    const expected = RECEIPT_BOOT_SAMPLES[i];
    const entry = asObject(samplesInput[i], "receipt:samples");
    for (const key of Object.keys(entry)) {
      if (!BOOT_SAMPLE_KEYS.has(key)) fail("receipt:samples");
    }
    if (entry.role !== expected.role || entry.member !== expected.member) {
      fail("receipt:samples");
    }
    const bytes = asSafeInteger(entry.bytes, "receipt:samples");
    if (bytes <= 0) fail("receipt:samples");
    if (
      typeof entry.sha256 !== "string" ||
      !SHA256_PATTERN.test(entry.sha256)
    ) {
      fail("receipt:samples");
    }
    bootSamples.push({
      role: expected.role,
      member: expected.member,
      bytes,
      sha256: entry.sha256,
    });
  }
  if (bootSamples[0].sha256 !== bootSamples[2].sha256) fail("receipt:samples");
  if (bootSamples[1].sha256 !== bootSamples[3].sha256) fail("receipt:samples");
  return {
    schemaVersion: 1,
    generation,
    indexSha256,
    recipientFingerprint,
    recipientSha256,
    verifiedAtUtc,
    archives,
    metadataSha256,
    bootSamples,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  };
}

// ---------------------------------------------------------------------------
// Input binding
// ---------------------------------------------------------------------------

function copyReconstruction(
  input: ReconstructedGeneration,
  index: RecoveryIndex,
  indexSha256: string,
): ReconstructedArchive[] {
  if (typeof input !== "object" || input === null) fail("reconstruction");
  if (input.generation !== index.generation) fail("reconstruction");
  if (input.indexSha256 !== indexSha256) fail("reconstruction");
  if (input.recipientFingerprint !== index.recipientFingerprint) {
    fail("reconstruction");
  }
  if (input.recipientSha256 !== index.recipientSha256) {
    fail("reconstruction");
  }
  if (input.ciphertextReconstructed !== true) fail("reconstruction");
  if (typeof input.recoveryDirectory !== "string") fail("reconstruction");
  if (
    !Array.isArray(input.archives) ||
    input.archives.length !== index.archives.length
  ) {
    fail("reconstruction");
  }
  const archives: ReconstructedArchive[] = [];
  for (let i = 0; i < index.archives.length; i += 1) {
    const expected = index.archives[i];
    const entry = input.archives[i];
    if (entry === null || typeof entry !== "object") fail("reconstruction");
    if (entry.role !== expected.role) fail("reconstruction");
    if (entry.format !== expected.format) fail("reconstruction");
    if (entry.bytes !== expected.bytes) fail("reconstruction");
    if (entry.sha256 !== expected.sha256) fail("reconstruction");
    const expectedPath =
      `${input.recoveryDirectory}/${expected.role}.${expected.format}`;
    if (entry.path !== expectedPath) fail("reconstruction");
    archives.push({
      role: expected.role,
      format: expected.format,
      bytes: expected.bytes,
      sha256: expected.sha256,
      chunks: expected.chunks.map((chunk) => ({ ...chunk })),
      path: expectedPath,
    });
  }
  return archives;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/** Verify the complete reconstructed generation: re-verify every ciphertext
 * first, process the recovery metadata archive next (validated metadata
 * pins the four captured boot hashes), then the six filesystem archives in
 * canonical order with complete listings and fixed-member boot restoration.
 * Returns a small still-to-be-validated receipt, or throws without any
 * receipt.
 */
export async function verifyDecryptedGeneration(
  indexInput: RecoveryIndex,
  reconstructionInput: ReconstructedGeneration,
  outputDirectory: string,
  decrypt: DecryptArchive,
): Promise<DecryptedVerification> {
  const index = validateRecoveryIndex(indexInput);
  const indexSha256 = sha256Hex(
    new TextEncoder().encode(JSON.stringify(index)),
  );
  const archives = copyReconstruction(reconstructionInput, index, indexSha256);
  const directory = await assertOutputDirectory(outputDirectory);
  await assertOutputState(outputDirectory, directory, new Set());
  const owner = directory.uid;

  // 1. Ciphertext pre-verification before any decryption: every archive must
  // be byte-identical to its index descriptor and still addressable.
  const ciphertextRecords = new Map<string, FileIdentityRecord>();
  for (const archive of archives) {
    const record = await verifyCiphertext(archive.path, owner, archive);
    ciphertextRecords.set(archive.path, record);
  }

  // 2. Recovery metadata archive first (index order: recovery is last).
  const published = new Set<string>();
  const retained = new Map<string, FileIdentityRecord>();
  const descriptors: ArchiveVerificationDescriptor[] = [];
  const samples: BootSampleDescriptor[] = [];
  const recovery = archives.find((archive) => archive.role === "recovery")!;
  let metadataView: RecoveryMetadataView | null = null;
  let metadataSha256 = "";

  await assertOutputState(outputDirectory, directory, published);
  await assertCiphertextRecord(
    recovery.path,
    ciphertextRecords.get(recovery.path)!,
  );
  const recoveryPlain = await decryptArchivePartial({
    archive: recovery,
    ciphertextPath: recovery.path,
    outputDirectory,
    directory,
    decrypt,
  });
  const metadataPlaintext = await decompressMetadata(
    recoveryPlain.partialPath,
  );
  metadataSha256 = sha256Hex(metadataPlaintext);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(metadataPlaintext));
  } catch {
    fail("metadata:json");
  }
  metadataView = validateRecoveryMetadata(parsed, index);
  retained.set(
    recoveryPlain.finalPath,
    await publishPartial(
      recoveryPlain.partialPath,
      recoveryPlain.finalPath,
      recoveryPlain.binding,
      recoveryPlain.bytes,
      outputDirectory,
      directory,
    ),
  );
  published.add(compressedFileName(recovery));
  descriptors.push({
    role: recovery.role,
    format: recovery.format,
    ciphertextBytes: recovery.bytes,
    ciphertextSha256: recovery.sha256,
    compressedBytes: recoveryPlain.bytes,
    compressedSha256: recoveryPlain.sha256,
  });

  // 3. Six filesystem archives in canonical index order.
  for (const archive of archives) {
    if (archive.role === "recovery") continue;
    await assertOutputState(outputDirectory, directory, published);
    await assertCiphertextRecord(
      archive.path,
      ciphertextRecords.get(archive.path)!,
    );
    const decrypted = await decryptArchivePartial({
      archive,
      ciphertextPath: archive.path,
      outputDirectory,
      directory,
      decrypt,
    });
    const required = archive.role === "root"
      ? ROOT_REQUIRED_MEMBERS
      : archive.role === "staging-boot"
      ? STAGING_REQUIRED_MEMBERS
      : [];
    const exact = archive.role === "root"
      ? ROOT_BOOT_MEMBERS
      : archive.role === "staging-boot"
      ? STAGING_BOOT_MEMBERS
      : [];
    const entries = await inventoryArchive(
      decrypted.partialPath,
      required,
      exact,
    );
    if (archive.role === "root" || archive.role === "staging-boot") {
      for (const sample of BOOT_SAMPLES) {
        if (sample.role !== archive.role) continue;
        const expectedSha256 = metadataView![
          sample.captured === "kernel" ? "kernelSha256" : "initramfsSha256"
        ];
        const restored = await restoreBootSample({
          compressedPath: decrypted.partialPath,
          role: sample.role,
          member: sample.member,
          sampleFile: sample.file,
          outputDirectory,
          directory,
          expectedSha256,
        });
        samples.push(restored.descriptor);
        retained.set(`${outputDirectory}/${sample.file}`, restored.record);
        published.add(sample.file);
      }
    }
    retained.set(
      decrypted.finalPath,
      await publishPartial(
        decrypted.partialPath,
        decrypted.finalPath,
        decrypted.binding,
        decrypted.bytes,
        outputDirectory,
        directory,
      ),
    );
    published.add(compressedFileName(archive));
    descriptors.push({
      role: archive.role,
      format: archive.format,
      ciphertextBytes: archive.bytes,
      ciphertextSha256: archive.sha256,
      compressedBytes: decrypted.bytes,
      compressedSha256: decrypted.sha256,
      entries,
    });
  }

  // 4. Final checkpoint: bound directory identity, exact expected entry set,
  // every retained final identity unchanged, then a bound directory sync.
  const expected = new Set<string>();
  for (const archive of archives) {
    expected.add(compressedFileName(archive));
  }
  for (const sample of BOOT_SAMPLES) expected.add(sample.file);
  await assertOutputState(outputDirectory, directory, expected);
  for (const [path, record] of retained) {
    await assertRecordedFinal(path, record);
  }
  await syncDirectory(outputDirectory, directory);

  const ordered = index.archives.map((archive) =>
    descriptors.find((descriptor) => descriptor.role === archive.role)!
  );
  return {
    schemaVersion: 1,
    generation: index.generation,
    indexSha256,
    recipientFingerprint: index.recipientFingerprint,
    recipientSha256: index.recipientSha256,
    verifiedAtUtc: new Date().toISOString(),
    archives: ordered,
    metadataSha256,
    bootSamples: samples,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  };
}
