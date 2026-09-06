/**
 * Focused m08-verifier tests: synthetic fixtures and unique temporary
 * directories only. Nothing reaches the network, no credential is read, no
 * real GPG key or source capture/upload stage file is used - the synthetic
 * `decrypt` callback writes in-memory zstd fixtures into the bound handles
 * and is NOT live restore acceptance. Runtime cases (fixtures built through
 * the installed zstd/tar tools and filesystem guards) need read, write and
 * run permissions and are explicitly ignored in the default permissionless
 * mode; the same cases must run with zero skips under
 * `deno test --allow-read --allow-write --allow-run`. A failed case
 * deliberately leaves its task-owned partial in its unique temporary
 * directory for explicit diagnosis; cleanup is best-effort and never
 * touches files it did not create.
 */
import { createHash } from "node:crypto";

import {
  type IndexArchiveRecord,
  type RecoveryIndex,
  validateRecoveryIndex,
} from "../scripts/backblaze-index.ts";
import type { ReconstructedGeneration } from "../scripts/backblaze-recovery.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
} from "../scripts/backblaze-upload.ts";
import {
  type DecryptArchive,
  type DecryptedVerification,
  validateRecoveryMetadata,
  validateVerifierReceipt,
  verifyDecryptedGeneration,
} from "../scripts/backblaze-verifier.ts";

function assert(condition: unknown, message?: string): asserts condition {
  if (!condition) throw new Error(message ?? "Assertion failed");
}

async function rejectWith(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof Error) return error;
    throw new Error("expected an Error");
  }
  throw new Error("expected a rejection");
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha1Hex(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

/** Deterministic non-repeating fixture bytes. */
function filler(seed: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = (seed + i * 31 + (i >> 8)) & 0xff;
  }
  return out;
}

const GENERATION = "generation-11111111-2222-3333-4444-555555555555";
const RECIPIENT_FINGERPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD";
const RECIPIENT_SHA256 = "ab".repeat(32);

const KERNEL_BYTES = new TextEncoder().encode("KERNEL-BYTES-".repeat(64));
const INITRAMFS_BYTES = new TextEncoder().encode("INITRAMFS-BYTES-".repeat(64));
const OS_RELEASE_BYTES = new TextEncoder().encode("NAME=Arch Linux\n");
const KERNEL_SHA256 = sha256Hex(KERNEL_BYTES);
const INITRAMFS_SHA256 = sha256Hex(INITRAMFS_BYTES);

const KERNEL_HASH_LINE =
  `${KERNEL_SHA256}  /boot/Image\n${INITRAMFS_SHA256}  /boot/initramfs-linux.img\n`;
const STAGING_HASH_LINE =
  `${KERNEL_SHA256}  ./arch-vmlinuz\n${INITRAMFS_SHA256}  ./arch-initrd.img\n`;

function formatFor(role: string): "tar.zst.gpg" | "json.zst.gpg" {
  return role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
}

// ---------------------------------------------------------------------------
// Runtime permission probe and helpers
// ---------------------------------------------------------------------------

/** Query-only permission probe; never requests a grant. Deno's default
 * `deno test` task carries no permissions, so runtime cases skip there and
 * only execute under the explicit --allow-read/--allow-write/--allow-run
 * invocation. */
async function runtimePermissionsGranted(): Promise<boolean> {
  const descriptors: Deno.PermissionDescriptor[] = [
    { name: "run", command: "bash" },
    { name: "run", command: "zstd" },
    { name: "run", command: "tar" },
    { name: "run", command: "awk" },
    { name: "read" },
    { name: "write" },
  ];
  for (const descriptor of descriptors) {
    try {
      if ((await Deno.permissions.query(descriptor)).state !== "granted") {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

const runtimePermitted = await runtimePermissionsGranted();

function runtimeTest(
  name: string,
  fn: (context: Deno.TestContext) => void | Promise<void>,
): void {
  Deno.test({ name: `runtime: ${name}`, ignore: !runtimePermitted, fn });
}

/** Unique canonical temporary directory (0700 unless a guard case lowers
 * it); macOS /var is canonicalized by the same realPath identity the module
 * requires. */
async function makeCanonicalDir(prefix: string, mode = 0o700): Promise<string> {
  const raw = await Deno.makeTempDir({ prefix });
  const dir = await Deno.realPath(raw);
  await Deno.chmod(dir, mode);
  return dir;
}

async function removeBestEffort(path: string): Promise<void> {
  try {
    await Deno.remove(path, { recursive: true });
  } catch {
    // Best effort only; never touch anything outside the case directory.
  }
}

async function modeOf(path: string): Promise<number> {
  const info = await Deno.lstat(path);
  return (info.mode ?? 0) & 0o777;
}

async function listNames(path: string): Promise<string[]> {
  const names: string[] = [];
  for await (const entry of Deno.readDir(path)) names.push(entry.name);
  return names.sort();
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await Deno.lstat(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
}

async function runStdout(
  name: string,
  args: string[],
  input?: Uint8Array,
): Promise<Uint8Array> {
  const child = new Deno.Command(name, {
    args,
    stdin: input ? "piped" : "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  if (input !== undefined) {
    const writer = child.stdin.getWriter();
    await writer.write(input);
    await writer.close();
  }
  const output = await child.output();
  return output.stdout;
}

// ---------------------------------------------------------------------------
// Synthetic fixture builder (runtime only; uses installed tar/zstd)
// ---------------------------------------------------------------------------

interface Fixture {
  index: RecoveryIndex;
  reconstruction: ReconstructedGeneration;
  /** Canonical directory holding the seven reconstructed ciphertexts. */
  recoveryDirectory: string;
  /** Canonical empty output directory. */
  outputDirectory: string;
  /** Compressed plaintext (GPG plaintext) bytes per role. */
  compressed: Map<string, Uint8Array>;
  /** Plaintext recovery metadata JSON bytes. */
  metadataBytes: Uint8Array;
  /** Ciphertext path per role. */
  pathByRole: Map<string, string>;
}

interface FixtureOptions {
  /** Root archive's compressed plaintext (default: full root tree). */
  rootCompressed?: Uint8Array;
  /** Mutate the built metadata plaintext before zstd is applied. */
  metadataMutate?: (metadata: Record<string, unknown>) => void;
  /** Mutate the built index candidate before validation. */
  indexMutate?: (index: Record<string, unknown>) => void;
  /** Customizes the root tree after the default fixture files exist. */
  customizeRoot?: (dir: string) => Promise<void>;
  /** Customizes the staging tree after the default fixture files exist. */
  customizeStaging?: (dir: string) => Promise<void>;
}

/** Compressed tar created from a directory with the installed tools:
 * `tar -cf - -C dir .` piped through `zstd -3 --check -c`. */
async function compressTree(directory: string): Promise<Uint8Array> {
  const tar = await runStdout("tar", ["-cf", "-", "-C", directory, "."]);
  return runStdout("zstd", ["-3", "--check", "-c"], tar);
}

function compressMetadata(bytes: Uint8Array): Promise<Uint8Array> {
  return runStdout("zstd", ["-3", "--check", "-c"], bytes);
}

/** Build the canonical synthetic index validated through the m04 validator,
 * with one deterministic chunk per archive. */
function syntheticIndex(): RecoveryIndex {
  const archives: IndexArchiveRecord[] = UPLOAD_ROLE_ORDER.map(
    (role, index) => {
      const bytes = filler(index * 13 + 5, 4096 + role.length * 7);
      return {
        role,
        format: formatFor(role),
        bytes: bytes.byteLength,
        sha256: sha256Hex(bytes),
        chunks: [{
          index: 0,
          name: generationChunkName(GENERATION, role, 0),
          size: bytes.byteLength,
          sha256: sha256Hex(bytes),
          sha1: sha1Hex(bytes),
          fileId: `file-${role}-0000`,
          uploadTimestamp: 1_900_000_000_000,
        }],
      };
    },
  );
  const candidate: Record<string, unknown> = {
    schemaVersion: 1,
    generation: GENERATION,
    captureStartedAtUtc: "2026-09-06T01:00:00.000Z",
    captureFinishedAtUtc: "2026-09-06T01:01:00.000Z",
    uploadStartedAtUtc: "2026-09-06T01:01:00.000Z",
    uploadFinishedAtUtc: "2026-09-06T01:02:00.000Z",
    consistency: "live-file-copy",
    sourceShutdown: false,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    recipientSha256: RECIPIENT_SHA256,
    archives,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  return validateRecoveryIndex(candidate);
}

/** Canonical recovery metadata JSON record (capture-manifest shape) bound to
 * the synthetic index; extra top-level context is included to prove it is
 * tolerated. */
function canonicalMetadata(
  index: RecoveryIndex,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    generation: GENERATION,
    startedAtUtc: "2026-09-06T01:00:00.000Z",
    finishedAtUtc: "2026-09-06T01:01:00.000Z",
    consistency: "live-file-copy",
    sourceShutdown: false,
    machineBootRestoreProved: false,
    captureMethod: "non-atomic live file copy",
    bootHashes: { root: KERNEL_HASH_LINE, stagingBoot: STAGING_HASH_LINE },
    finalChecks: {
      pacmanLockAbsent: true,
      packagesUnchanged: true,
      bootHashesUnchanged: true,
    },
    archives: index.archives
      .filter((archive) => archive.role !== "recovery")
      .map((archive) => ({
        role: archive.role,
        format: archive.format,
        bytes: archive.bytes,
        sha256: archive.sha256,
        // Capture-produced manifests also carry the local stage path; the
        // verifier must tolerate and ignore it.
        path:
          `/var/tmp/arch-vps-file-backup/${index.generation}/${archive.role}.${archive.format}`,
      })),
    recipient: {
      fingerprint: RECIPIENT_FINGERPRINT,
      publicSha256: RECIPIENT_SHA256,
    },
    extraUnboundField: "capture may add recovery context",
    ...overrides,
  };
}

async function buildFixture(
  options: FixtureOptions = {},
): Promise<Fixture> {
  const root = await makeCanonicalDir("m08-root-");
  const staging = await makeCanonicalDir("m08-staging-");
  const other = await makeCanonicalDir("m08-other-");
  const cleanup = [root, staging, other];
  try {
    await Deno.mkdir(`${root}/etc`);
    await Deno.mkdir(`${root}/boot`);
    await Deno.writeFile(`${root}/etc/os-release`, OS_RELEASE_BYTES);
    await Deno.writeFile(`${root}/boot/Image`, KERNEL_BYTES);
    await Deno.writeFile(`${root}/boot/initramfs-linux.img`, INITRAMFS_BYTES);
    await Deno.writeFile(`${staging}/arch-vmlinuz`, KERNEL_BYTES);
    await Deno.writeFile(`${staging}/arch-initrd.img`, INITRAMFS_BYTES);
    await Deno.writeFile(
      `${other}/payload`,
      new TextEncoder().encode("synthetic payload for a non-boot role\n"),
    );
    await options.customizeRoot?.(root);
    await options.customizeStaging?.(staging);
    const compressed = new Map<string, Uint8Array>([
      ["root", options.rootCompressed ?? await compressTree(root)],
      ["efi", await compressTree(other)],
      ["staging-boot", await compressTree(staging)],
      ["staging-efi", await compressTree(other)],
      ["oracle-root", await compressTree(other)],
      ["oracle-oled", await compressTree(other)],
    ]);
    const recoveryDirectory = await makeCanonicalDir("m08-recovery-");
    const outputDirectory = await makeCanonicalDir("m08-output-");
    const pathByRole = new Map<string, string>();
    const indexFixture = syntheticIndex();
    const candidate: Record<string, unknown> = {
      schemaVersion: 1,
      generation: GENERATION,
      captureStartedAtUtc: "2026-09-06T01:00:00.000Z",
      captureFinishedAtUtc: "2026-09-06T01:01:00.000Z",
      uploadStartedAtUtc: "2026-09-06T01:01:00.000Z",
      uploadFinishedAtUtc: "2026-09-06T01:02:00.000Z",
      consistency: "live-file-copy",
      sourceShutdown: false,
      recipientFingerprint: RECIPIENT_FINGERPRINT,
      recipientSha256: RECIPIENT_SHA256,
      archives: indexFixture.archives,
      uploadVerified: true,
      decryptedRestoreProved: false,
      machineBootRestoreProved: false,
    };
    options.indexMutate?.(candidate);
    const index = validateRecoveryIndex(candidate);
    for (const archive of index.archives) {
      const cipherBytes = filler(
        UPLOAD_ROLE_ORDER.indexOf(archive.role) * 13 + 5,
        4096 + archive.role.length * 7,
      );
      const path = `${recoveryDirectory}/${archive.role}.${archive.format}`;
      await Deno.writeFile(path, cipherBytes);
      await Deno.chmod(path, 0o600);
      pathByRole.set(archive.role, path);
    }
    const metadata = canonicalMetadata(index);
    options.metadataMutate?.(metadata);
    const mutable = new Map(compressed);
    const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
    mutable.set("recovery", await compressMetadata(metadataBytes));
    const indexSha256 = sha256Hex(
      new TextEncoder().encode(JSON.stringify(index)),
    );
    const reconstruction: ReconstructedGeneration = {
      generation: GENERATION,
      indexSha256,
      recipientFingerprint: RECIPIENT_FINGERPRINT,
      recipientSha256: RECIPIENT_SHA256,
      recoveryDirectory,
      archives: index.archives.map((archive) => ({
        ...archive,
        chunks: archive.chunks.map((chunk) => ({ ...chunk })),
        path: pathByRole.get(archive.role)!,
      })),
      ciphertextReconstructed: true,
      decryptedRestoreProved: false,
      machineBootRestoreProved: false,
    };
    return {
      index,
      reconstruction,
      recoveryDirectory,
      outputDirectory,
      compressed: mutable,
      metadataBytes,
      pathByRole,
    };
  } finally {
    await removeBestEffort(cleanup[0]);
    await removeBestEffort(cleanup[1]);
    await removeBestEffort(cleanup[2]);
  }
}

// ---------------------------------------------------------------------------
// Pure receipt validator cases (no permissions required)
// ---------------------------------------------------------------------------

function validReceipt(
  metadataBytes: Uint8Array,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    generation: GENERATION,
    indexSha256: "aa".repeat(32),
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    recipientSha256: RECIPIENT_SHA256,
    verifiedAtUtc: "2026-09-06T02:00:00.000Z",
    archives: UPLOAD_ROLE_ORDER.map((role, index) => ({
      role,
      format: formatFor(role),
      ciphertextBytes: 4096 + role.length * 7,
      ciphertextSha256: "ab".repeat(32),
      compressedBytes: 100 + index,
      compressedSha256: "bb".repeat(32),
      ...(role === "recovery" ? {} : { entries: 3 + index }),
    })),
    metadataSha256: sha256Hex(metadataBytes),
    bootSamples: [
      {
        role: "root",
        member: "./boot/Image",
        bytes: KERNEL_BYTES.byteLength,
        sha256: KERNEL_SHA256,
      },
      {
        role: "root",
        member: "./boot/initramfs-linux.img",
        bytes: INITRAMFS_BYTES.byteLength,
        sha256: INITRAMFS_SHA256,
      },
      {
        role: "staging-boot",
        member: "./arch-vmlinuz",
        bytes: KERNEL_BYTES.byteLength,
        sha256: KERNEL_SHA256,
      },
      {
        role: "staging-boot",
        member: "./arch-initrd.img",
        bytes: INITRAMFS_BYTES.byteLength,
        sha256: INITRAMFS_SHA256,
      },
    ],
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
    ...overrides,
  };
}

Deno.test("validateVerifierReceipt accepts the canonical receipt", () => {
  const receipt = validateVerifierReceipt(validReceipt(new Uint8Array()));
  assert(receipt.schemaVersion === 1);
  assert(receipt.generation === GENERATION);
  assert(receipt.archives.length === 7);
  assert(receipt.bootSamples.length === 4);
  assert(receipt.decryptedRestoreProved === true);
  assert(receipt.machineBootRestoreProved === false);
  const again = validateVerifierReceipt(receipt);
  assert(JSON.stringify(again) === JSON.stringify(receipt));
});

Deno.test("validateVerifierReceipt rejects unknown and missing fields", () => {
  const base = validReceipt(new Uint8Array());
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "extra top-level field",
      { ...base, unexpectedField: 1 },
      "Verifier failed (receipt:keys)",
    ],
    [
      "missing archives",
      Object.fromEntries(
        Object.entries(base).filter(([key]) => key !== "archives"),
      ),
      "Verifier failed (receipt:archives)",
    ],
    [
      "missing bootSamples",
      Object.fromEntries(
        Object.entries(base).filter(([key]) => key !== "bootSamples"),
      ),
      "Verifier failed (receipt:samples)",
    ],
    [
      "wrong version",
      { ...base, schemaVersion: 2 },
      "Verifier failed (receipt:version)",
    ],
    [
      "wrong generation",
      { ...base, generation: "not-a-generation" },
      "Verifier failed (receipt:generation)",
    ],
    [
      "wrong index hash",
      { ...base, indexSha256: "zz".repeat(32) },
      "Verifier failed (receipt:index-sha256)",
    ],
    [
      "wrong metadata hash",
      { ...base, metadataSha256: "a".repeat(63) },
      "Verifier failed (receipt:metadata-sha256)",
    ],
    ["fingerprint lowercase", {
      ...base,
      recipientFingerprint: RECIPIENT_FINGERPRINT.toLowerCase(),
    }, "Verifier failed (receipt:recipient)"],
    [
      "non-utc verified time",
      { ...base, verifiedAtUtc: "2026-09-06 02:00:00" },
      "Verifier failed (receipt:time)",
    ],
    [
      "decryptedRestoreProved false",
      { ...base, decryptedRestoreProved: false },
      "Verifier failed (receipt:flags)",
    ],
    ["machineBootRestoreProved true", {
      ...base,
      machineBootRestoreProved: true,
    }, "Verifier failed (receipt:flags)"],
  ];
  for (const [label, input, expected] of cases) {
    let caught: Error | null = null;
    try {
      validateVerifierReceipt(input);
    } catch (error) {
      caught = error as Error;
    }
    assert(caught !== null, `${label}: expected rejection`);
    assert(caught!.message === expected, `${label}: ${caught!.message}`);
  }
});

Deno.test("validateVerifierReceipt rejects inconsistent 7-role receipt data", () => {
  const base = validReceipt(new Uint8Array());
  const archivesInput = base.archives as Record<string, unknown>[];
  const cases: [string, Record<string, unknown>[], string][] = [
    [
      "six archives",
      archivesInput.slice(0, 6),
      "Verifier failed (receipt:archives)",
    ],
    [
      "eight archives",
      [...archivesInput, ...archivesInput.slice(0, 1)],
      "Verifier failed (receipt:archives)",
    ],
    [
      "roles out of canonical order",
      [...archivesInput.slice(1), archivesInput[0]],
      "Verifier failed (receipt:archives)",
    ],
    [
      "wrong role at position",
      archivesInput.map((entry, index) =>
        index === 0 ? { ...entry, role: "efi" } : entry
      ),
      "Verifier failed (receipt:archives)",
    ],
    [
      "wrong format for role",
      archivesInput.map((entry, index) =>
        index === 0 ? { ...entry, format: "json.zst.gpg" } : entry
      ),
      "Verifier failed (receipt:archives)",
    ],
    [
      "entries on the recovery archive",
      archivesInput.map((entry, index) =>
        index === 6 ? { ...entry, entries: 1 } : entry
      ),
      "Verifier failed (receipt:archives)",
    ],
    [
      "entries missing on a filesystem archive",
      archivesInput.map((entry, index) => {
        if (index === 6) return entry;
        const copy = { ...entry };
        delete copy.entries;
        return copy;
      }),
      "Verifier failed (receipt:archives)",
    ],
    [
      "zero ciphertext bytes",
      archivesInput.map((entry, index) =>
        index === 0 ? { ...entry, ciphertextBytes: 0 } : entry
      ),
      "Verifier failed (receipt:archives)",
    ],
    [
      "bad archive hash",
      archivesInput.map((entry, index) =>
        index === 0 ? { ...entry, ciphertextSha256: "zz".repeat(32) } : entry
      ),
      "Verifier failed (receipt:archives)",
    ],
    [
      "extra field on an archive descriptor",
      archivesInput.map((entry, index) =>
        index === 0 ? { ...entry, path: "/x" } : entry
      ),
      "Verifier failed (receipt:archives)",
    ],
    [
      "missing format key",
      archivesInput.map((entry, index) => {
        if (index !== 0) return entry;
        const copy = { ...entry };
        delete copy.format;
        return copy;
      }),
      "Verifier failed (receipt:archives)",
    ],
  ];
  for (const [label, archives, expected] of cases) {
    let caught: Error | null = null;
    try {
      validateVerifierReceipt({ ...base, archives });
    } catch (error) {
      caught = error as Error;
    }
    assert(caught !== null, `${label}: expected rejection`);
    assert(caught!.message === expected, `${label}: ${caught!.message}`);
  }
});

Deno.test("validateVerifierReceipt rejects inconsistent 4-sample receipt data", () => {
  const base = validReceipt(new Uint8Array());
  const samplesInput = base.bootSamples as Record<string, unknown>[];
  const cases: [string, Record<string, unknown>[], string][] = [
    [
      "three samples",
      samplesInput.slice(0, 3),
      "Verifier failed (receipt:samples)",
    ],
    [
      "five samples",
      [...samplesInput, ...samplesInput.slice(0, 1)],
      "Verifier failed (receipt:samples)",
    ],
    [
      "wrong member on root kernel sample",
      samplesInput.map((entry, index) =>
        index === 0 ? { ...entry, member: "./arch-vmlinuz" } : entry
      ),
      "Verifier failed (receipt:samples)",
    ],
    [
      "wrong role on staging initramfs sample",
      samplesInput.map((entry, index) =>
        index === 3 ? { ...entry, role: "root" } : entry
      ),
      "Verifier failed (receipt:samples)",
    ],
    [
      "zero sample bytes",
      samplesInput.map((entry, index) =>
        index === 0 ? { ...entry, bytes: 0 } : entry
      ),
      "Verifier failed (receipt:samples)",
    ],
    [
      "bad sample hash",
      samplesInput.map((entry, index) =>
        index === 0 ? { ...entry, sha256: "ff".repeat(32) } : entry
      ),
      "Verifier failed (receipt:samples)",
    ],
    [
      "broken kernel parity",
      samplesInput.map((entry, index) =>
        index === 2 ? { ...entry, sha256: "11".repeat(32) } : entry
      ),
      "Verifier failed (receipt:samples)",
    ],
    [
      "broken initramfs parity",
      samplesInput.map((entry, index) =>
        index === 1 ? { ...entry, sha256: "22".repeat(32) } : entry
      ),
      "Verifier failed (receipt:samples)",
    ],
  ];
  for (const [label, bootSamples, expected] of cases) {
    let caught: Error | null = null;
    try {
      validateVerifierReceipt({ ...base, bootSamples });
    } catch (error) {
      caught = error as Error;
    }
    assert(caught !== null, `${label}: expected rejection`);
    assert(caught!.message === expected, `${label}: ${caught!.message}`);
  }
});

// ---------------------------------------------------------------------------
// Pure metadata validator cases (no permissions required)
// ---------------------------------------------------------------------------

const pureIndex = syntheticIndex();

Deno.test("validateRecoveryMetadata accepts canonical metadata and tolerates extra fields", () => {
  const view = validateRecoveryMetadata(
    canonicalMetadata(pureIndex),
    pureIndex,
  );
  assert(view.generation === GENERATION);
  assert(view.kernelSha256 === KERNEL_SHA256);
  assert(view.initramfsSha256 === INITRAMFS_SHA256);
});

Deno.test("validateRecoveryMetadata rejects identity and consistency mismatches", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "generation mismatch",
      canonicalMetadata(pureIndex, {
        generation: "generation-99999999-9999-9999-9999-999999999999",
      }),
      "Verifier failed (metadata:generation)",
    ],
    [
      "consistency mismatch",
      canonicalMetadata(pureIndex, { consistency: "snapshot" }),
      "Verifier failed (metadata:consistency)",
    ],
    [
      "sourceShutdown true",
      canonicalMetadata(pureIndex, { sourceShutdown: true }),
      "Verifier failed (metadata:shutdown)",
    ],
    [
      "machine boot proved",
      canonicalMetadata(pureIndex, { machineBootRestoreProved: true }),
      "Verifier failed (metadata:flags)",
    ],
    [
      "recipient fingerprint mismatch",
      canonicalMetadata(pureIndex, {
        recipient: {
          fingerprint: "0000000000000000000000000000000000000000",
          publicSha256: RECIPIENT_SHA256,
        },
      }),
      "Verifier failed (metadata:recipient)",
    ],
    [
      "recipient extra key",
      canonicalMetadata(pureIndex, {
        recipient: {
          fingerprint: RECIPIENT_FINGERPRINT,
          publicSha256: RECIPIENT_SHA256,
          extra: 1,
        },
      }),
      "Verifier failed (metadata:recipient)",
    ],
    [
      "incomplete final guards",
      canonicalMetadata(pureIndex, {
        finalChecks: {
          pacmanLockAbsent: true,
          packagesUnchanged: true,
          bootHashesUnchanged: false,
        },
      }),
      "Verifier failed (metadata:guards)",
    ],
    [
      "one boot hash line",
      canonicalMetadata(pureIndex, {
        bootHashes: {
          root: `${KERNEL_SHA256}  /boot/Image\n`,
          stagingBoot: STAGING_HASH_LINE,
        },
      }),
      "Verifier failed (metadata:boot)",
    ],
    [
      "boot hash wrong source path",
      canonicalMetadata(pureIndex, {
        bootHashes: {
          root:
            `${KERNEL_SHA256}  /boot/vmlinuz\n${INITRAMFS_SHA256}  /boot/initramfs-linux.img\n`,
          stagingBoot: STAGING_HASH_LINE,
        },
      }),
      "Verifier failed (metadata:boot)",
    ],
    [
      "boot parity mismatch",
      canonicalMetadata(pureIndex, {
        bootHashes: {
          root: KERNEL_HASH_LINE,
          stagingBoot: `${
            "11".repeat(32)
          }  ./arch-vmlinuz\n${INITRAMFS_SHA256}  ./arch-initrd.img\n`,
        },
      }),
      "Verifier failed (metadata:boot)",
    ],
    [
      "five archives",
      canonicalMetadata(pureIndex, {
        archives: (canonicalMetadata(pureIndex).archives as unknown[]).slice(
          0,
          5,
        ),
      }),
      "Verifier failed (metadata:archives)",
    ],
    [
      "archive descriptor bytes mismatch",
      canonicalMetadata(pureIndex, {
        archives:
          (canonicalMetadata(pureIndex).archives as Record<string, unknown>[])
            .map((entry, index) =>
              index === 0 ? { ...entry, bytes: 999 } : entry
            ),
      }),
      "Verifier failed (metadata:archives)",
    ],
  ];
  for (const [label, input, expected] of cases) {
    let caught: Error | null = null;
    try {
      validateRecoveryMetadata(input, pureIndex);
    } catch (error) {
      caught = error as Error;
    }
    assert(caught !== null, `${label}: expected rejection`);
    assert(caught!.message === expected, `${label}: ${caught!.message}`);
  }
});

// ---------------------------------------------------------------------------
// Runtime verification cases
// ---------------------------------------------------------------------------

/** Synthetic decrypt callback writing registered compressed plaintext per
 * ciphertext path and recording every invocation. */
function syntheticDecrypt(
  compressed: Map<string, Uint8Array>,
  pathByRole: Map<string, string>,
  calls: string[] = [],
): { decrypt: DecryptArchive; calls: string[] } {
  const byPath = new Map<string, string>();
  for (const [role, path] of pathByRole) byPath.set(path, role);
  return {
    calls,
    decrypt: async (ciphertextPath: string, destination: Deno.FsFile) => {
      calls.push(ciphertextPath);
      const role = byPath.get(ciphertextPath);
      assert(role !== undefined, "unknown ciphertext path");
      const bytes = compressed.get(role)!;
      let offset = 0;
      while (offset < bytes.byteLength) {
        const written = await destination.write(bytes.subarray(offset));
        assert(written > 0, "synthetic decrypt write made no progress");
        offset += written;
      }
      return { integrityChecked: true };
    },
  };
}

runtimeTest(
  "all seven archives verify and four exact boot samples restore",
  async () => {
    const fixture = await buildFixture();
    try {
      const { decrypt, calls } = syntheticDecrypt(
        fixture.compressed,
        fixture.pathByRole,
      );
      const receipt = await verifyDecryptedGeneration(
        fixture.index,
        fixture.reconstruction,
        fixture.outputDirectory,
        decrypt,
      ) as DecryptedVerification;
      assert(calls.length === 7, "exactly seven decrypt calls expected");
      assert(receipt.schemaVersion === 1);
      assert(receipt.generation === GENERATION);
      assert(receipt.indexSha256 === fixture.reconstruction.indexSha256);
      assert(receipt.recipientFingerprint === RECIPIENT_FINGERPRINT);
      assert(receipt.recipientSha256 === RECIPIENT_SHA256);
      assert(receipt.metadataSha256 === sha256Hex(fixture.metadataBytes));
      assert(receipt.decryptedRestoreProved === true);
      assert(receipt.machineBootRestoreProved === false);
      assert(receipt.archives.length === 7);
      for (const archive of receipt.archives) {
        const line = fixture.reconstruction.archives.find(
          (candidate) => candidate.role === archive.role,
        )!;
        assert(archive.ciphertextBytes === line.bytes);
        assert(archive.ciphertextSha256 === line.sha256);
        const compressed = fixture.compressed.get(archive.role)!;
        assert(archive.compressedBytes === compressed.byteLength);
        assert(archive.compressedSha256 === sha256Hex(compressed));
        if (archive.role === "recovery") {
          assert(archive.entries === undefined);
        } else {
          assert(archive.entries !== undefined && archive.entries > 0);
        }
      }
      assert(receipt.bootSamples.length === 4);
      assert(receipt.bootSamples[0].role === "root");
      assert(receipt.bootSamples[0].member === "./boot/Image");
      assert(receipt.bootSamples[0].sha256 === KERNEL_SHA256);
      assert(receipt.bootSamples[1].member === "./boot/initramfs-linux.img");
      assert(receipt.bootSamples[1].sha256 === INITRAMFS_SHA256);
      assert(receipt.bootSamples[2].role === "staging-boot");
      assert(receipt.bootSamples[2].member === "./arch-vmlinuz");
      assert(receipt.bootSamples[2].bytes === KERNEL_BYTES.byteLength);
      assert(receipt.bootSamples[2].sha256 === KERNEL_SHA256);
      assert(receipt.bootSamples[3].member === "./arch-initrd.img");
      assert(receipt.bootSamples[3].sha256 === INITRAMFS_SHA256);
      // The receipt must pass its own pure validator unchanged.
      const validated = validateVerifierReceipt(receipt);
      assert(JSON.stringify(validated) === JSON.stringify(receipt));
      // Exactly the seven compressed finals and four sample finals, all 0600.
      const expectedNames = [
        "recovery.json.zst",
        ...UPLOAD_ROLE_ORDER.filter((role) => role !== "recovery")
          .map((role) => `${role}.tar.zst`),
        "sample.root.Image",
        "sample.root.initramfs-linux.img",
        "sample.staging-boot.arch-vmlinuz",
        "sample.staging-boot.arch-initrd.img",
      ].sort();
      assert(
        JSON.stringify(await listNames(fixture.outputDirectory)) ===
          JSON.stringify(expectedNames),
        "unexpected output directory entries",
      );
      for (const name of expectedNames) {
        assert((await modeOf(`${fixture.outputDirectory}/${name}`)) === 0o600);
      }
      // Sample byte-identity against the fixture kernel/initramfs bytes.
      const image = await Deno.readFile(
        `${fixture.outputDirectory}/sample.root.Image`,
      );
      assert(sha256Hex(image) === KERNEL_SHA256);
      assert(JSON.stringify(image) === JSON.stringify(KERNEL_BYTES));
      const initramfs = await Deno.readFile(
        `${fixture.outputDirectory}/sample.root.initramfs-linux.img`,
      );
      assert(sha256Hex(initramfs) === INITRAMFS_SHA256);
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest(
  "wrong ciphertext hash fails before any decrypt callback",
  async () => {
    const fixture = await buildFixture();
    try {
      const recoveryPath = fixture.pathByRole.get("recovery")!;
      const current = await Deno.readFile(recoveryPath);
      const drifted = new Uint8Array(current);
      drifted[0] = drifted[0]! ^ 0x01;
      await Deno.writeFile(recoveryPath, drifted);
      await Deno.chmod(recoveryPath, 0o600);
      const { decrypt, calls } = syntheticDecrypt(
        fixture.compressed,
        fixture.pathByRole,
      );
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          decrypt,
        ),
      );
      assert(
        error.message === "Verifier failed (ciphertext:hash)",
        error.message,
      );
      assert(calls.length === 0, "no decrypt callback may run");
      assert((await listNames(fixture.outputDirectory)).length === 0);
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest(
  "decrypt callback failure leaves partial, no receipt, bounded error",
  async () => {
    const fixture = await buildFixture();
    try {
      const secret = "SECRET-TOKEN-MUST-NOT-LEAK-7f2a";
      const calls: string[] = [];
      const failing: DecryptArchive = async (
        ciphertextPath: string,
        destination: Deno.FsFile,
      ) => {
        calls.push(ciphertextPath);
        await destination.write(fixture.compressed.get("recovery")!);
        throw new Error(`raw callback failure ${secret}`);
      };
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          failing,
        ),
      );
      assert(error.message === "Verifier failed (decrypt)", error.message);
      assert(
        !error.message.includes(secret),
        "no raw callback payload may leak",
      );
      assert(calls.length === 1, "only the first archive callback runs");
      assert(
        await fileExists(
          `${fixture.outputDirectory}/recovery.json.zst.partial`,
        ),
        "the failed partial must be preserved",
      );
      assert(
        !(await fileExists(`${fixture.outputDirectory}/recovery.json.zst`)),
      );
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest(
  "missing integrityChecked fails visibly and preserves the partial",
  async () => {
    const fixture = await buildFixture();
    try {
      const callback = (async (
        _ciphertextPath: string,
        destination: Deno.FsFile,
      ) => {
        await destination.write(fixture.compressed.get("recovery")!);
        return { integrityChecked: false };
      }) as unknown as DecryptArchive;
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          callback,
        ),
      );
      assert(
        error.message === "Verifier failed (decrypt:integrity)",
        error.message,
      );
      assert(
        await fileExists(
          `${fixture.outputDirectory}/recovery.json.zst.partial`,
        ),
      );
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest(
  "callback that closes the destination handle fails bounded",
  async () => {
    const fixture = await buildFixture();
    try {
      const callback = (async (
        _ciphertextPath: string,
        destination: Deno.FsFile,
      ) => {
        await destination.write(fixture.compressed.get("recovery")!);
        destination.close();
        return { integrityChecked: true };
      }) as unknown as DecryptArchive;
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          callback,
        ),
      );
      assert(error.message.startsWith("Verifier failed ("), error.message);
      assert(!error.message.includes("Bad resource ID"), error.message);
      assert(
        await fileExists(
          `${fixture.outputDirectory}/recovery.json.zst.partial`,
        ),
      );
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest(
  "corrupt zstd fails the integrity test before the final is published",
  async () => {
    const fixture = await buildFixture();
    try {
      const corrupted = new Uint8Array(fixture.compressed.get("root")!);
      corrupted[40] = corrupted[40]! ^ 0x55;
      const map = new Map(fixture.compressed);
      map.set("root", corrupted);
      const { decrypt, calls } = syntheticDecrypt(map, fixture.pathByRole);
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          decrypt,
        ),
      );
      assert(
        error.message === "Verifier failed (zstd:integrity)",
        error.message,
      );
      assert(calls.length === 2, "recovery plus root callback expected");
      assert(
        await fileExists(`${fixture.outputDirectory}/root.tar.zst.partial`),
        "root partial must be preserved",
      );
      assert(!(await fileExists(`${fixture.outputDirectory}/root.tar.zst`)));
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest("truncated zstd fails the integrity test", async () => {
  const fixture = await buildFixture();
  try {
    const full = fixture.compressed.get("root")!;
    const map = new Map(fixture.compressed);
    map.set("root", full.subarray(0, full.byteLength - 6));
    const { decrypt } = syntheticDecrypt(map, fixture.pathByRole);
    const error = await rejectWith(
      verifyDecryptedGeneration(
        fixture.index,
        fixture.reconstruction,
        fixture.outputDirectory,
        decrypt,
      ),
    );
    assert(error.message === "Verifier failed (zstd:integrity)", error.message);
  } finally {
    await removeBestEffort(fixture.recoveryDirectory);
    await removeBestEffort(fixture.outputDirectory);
  }
});

runtimeTest(
  "truncated tar inside a valid zstd stream fails the listing",
  async () => {
    const fixture = await buildFixture();
    try {
      const tree = await makeCanonicalDir("m08-trunctree-");
      try {
        await Deno.writeFile(
          `${tree}/member-a`,
          new TextEncoder().encode("truncation fixture\n"),
        );
        const tar = await runStdout("tar", ["-cf", "-", "-C", tree, "."]);
        const truncatedTar = tar.subarray(0, Math.min(40, tar.byteLength - 5));
        const map = new Map(fixture.compressed);
        map.set(
          "root",
          await runStdout("zstd", ["-3", "--check", "-c"], truncatedTar),
        );
        const { decrypt } = syntheticDecrypt(map, fixture.pathByRole);
        const error = await rejectWith(
          verifyDecryptedGeneration(
            fixture.index,
            fixture.reconstruction,
            fixture.outputDirectory,
            decrypt,
          ),
        );
        assert(
          error.message === "Verifier failed (listing:producer)",
          error.message,
        );
        assert(
          await fileExists(`${fixture.outputDirectory}/root.tar.zst.partial`),
          "root partial must be preserved",
        );
      } finally {
        await removeBestEffort(tree);
      }
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest("missing required member fails the listing", async () => {
  const fixture = await buildFixture({
    customizeRoot: async (root) => {
      await Deno.remove(`${root}/boot/Image`);
    },
  });
  try {
    const { decrypt } = syntheticDecrypt(
      fixture.compressed,
      fixture.pathByRole,
    );
    const error = await rejectWith(
      verifyDecryptedGeneration(
        fixture.index,
        fixture.reconstruction,
        fixture.outputDirectory,
        decrypt,
      ),
    );
    assert(
      error.message === "Verifier failed (listing:producer)",
      error.message,
    );
    assert(
      await fileExists(`${fixture.outputDirectory}/root.tar.zst.partial`),
      "root partial must be preserved",
    );
    assert(!(await fileExists(`${fixture.outputDirectory}/root.tar.zst`)));
  } finally {
    await removeBestEffort(fixture.recoveryDirectory);
    await removeBestEffort(fixture.outputDirectory);
  }
});

runtimeTest("duplicate selected boot member fails the listing", async () => {
  const fixture = await buildFixture();
  try {
    const tree = await makeCanonicalDir("m08-duptree-");
    try {
      await Deno.mkdir(`${tree}/boot`);
      await Deno.writeFile(`${tree}/boot/Image`, KERNEL_BYTES);
      // Two archive passes over the same tree produce two occurrences of
      // ./boot/Image in one tar stream.
      const first = await runStdout("tar", ["-cf", "-", "-C", tree, "."]);
      const second = await runStdout("tar", ["-cf", "-", "-C", tree, "."]);
      const combined = new Uint8Array(first.byteLength + second.byteLength);
      combined.set(first, 0);
      combined.set(second, first.byteLength);
      const map = new Map(fixture.compressed);
      map.set(
        "root",
        await runStdout("zstd", ["-3", "--check", "-c"], combined),
      );
      const { decrypt } = syntheticDecrypt(map, fixture.pathByRole);
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          decrypt,
        ),
      );
      assert(
        error.message === "Verifier failed (listing:producer)",
        error.message,
      );
    } finally {
      await removeBestEffort(tree);
    }
  } finally {
    await removeBestEffort(fixture.recoveryDirectory);
    await removeBestEffort(fixture.outputDirectory);
  }
});

runtimeTest(
  "metadata identity mismatch fails before any final is published",
  async () => {
    const fixture = await buildFixture({
      metadataMutate: (metadata) => {
        metadata.generation = "generation-99999999-9999-9999-9999-999999999999";
      },
    });
    try {
      const { decrypt, calls } = syntheticDecrypt(
        fixture.compressed,
        fixture.pathByRole,
      );
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          decrypt,
        ),
      );
      assert(
        error.message === "Verifier failed (metadata:generation)",
        error.message,
      );
      assert(calls.length === 1, "only the recovery archive may be decrypted");
      assert(
        await fileExists(
          `${fixture.outputDirectory}/recovery.json.zst.partial`,
        ),
        "recovery partial must be preserved",
      );
      assert(
        !(await fileExists(`${fixture.outputDirectory}/recovery.json.zst`)),
      );
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest("metadata archive descriptor mismatch fails", async () => {
  const fixture = await buildFixture({
    metadataMutate: (metadata) => {
      (metadata.archives as Record<string, unknown>[])[0].bytes = 999999;
    },
  });
  try {
    const { decrypt } = syntheticDecrypt(
      fixture.compressed,
      fixture.pathByRole,
    );
    const error = await rejectWith(
      verifyDecryptedGeneration(
        fixture.index,
        fixture.reconstruction,
        fixture.outputDirectory,
        decrypt,
      ),
    );
    assert(
      error.message === "Verifier failed (metadata:archives)",
      error.message,
    );
  } finally {
    await removeBestEffort(fixture.recoveryDirectory);
    await removeBestEffort(fixture.outputDirectory);
  }
});

runtimeTest(
  "boot sample hash mismatch fails against captured metadata",
  async () => {
    const fixture = await buildFixture({
      metadataMutate: (metadata) => {
        // Valid-hash parity but wrong value: metadata validation passes, the
        // restored sample hash must not match the captured hash.
        const bootHashes = metadata.bootHashes as Record<string, string>;
        const wrong = "11".repeat(32);
        const rootLines = bootHashes.root.split("\n");
        const stagingLines = bootHashes.stagingBoot.split("\n");
        bootHashes.root = `${wrong}  /boot/Image\n${rootLines[1]}`;
        bootHashes.stagingBoot = `${wrong}  ./arch-vmlinuz\n${stagingLines[1]}`;
      },
    });
    try {
      const { decrypt, calls } = syntheticDecrypt(
        fixture.compressed,
        fixture.pathByRole,
      );
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          decrypt,
        ),
      );
      assert(error.message === "Verifier failed (sample:hash)", error.message);
      assert(calls.length === 2, "recovery plus root callback expected");
      assert(
        await fileExists(
          `${fixture.outputDirectory}/sample.root.Image.partial`,
        ),
        "sample partial must be preserved",
      );
      assert(
        !(await fileExists(`${fixture.outputDirectory}/sample.root.Image`)),
      );
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest("oversized metadata fails the bounded decompression", async () => {
  const fixture = await buildFixture({
    metadataMutate: (metadata) => {
      metadata.bigPadding = "x".repeat(8 * 1024 * 1024 + 1024);
    },
  });
  try {
    const { decrypt } = syntheticDecrypt(
      fixture.compressed,
      fixture.pathByRole,
    );
    const error = await rejectWith(
      verifyDecryptedGeneration(
        fixture.index,
        fixture.reconstruction,
        fixture.outputDirectory,
        decrypt,
      ),
    );
    assert(error.message === "Verifier failed (metadata:size)", error.message);
  } finally {
    await removeBestEffort(fixture.recoveryDirectory);
    await removeBestEffort(fixture.outputDirectory);
  }
});

runtimeTest(
  "nonempty output directory fails before any side effect",
  async () => {
    const fixture = await buildFixture();
    try {
      await Deno.writeFile(
        `${fixture.outputDirectory}/foreign-file`,
        new TextEncoder().encode("foreign"),
      );
      const { decrypt, calls } = syntheticDecrypt(
        fixture.compressed,
        fixture.pathByRole,
      );
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          decrypt,
        ),
      );
      assert(error.message === "Verifier failed (output:entry)", error.message);
      assert(calls.length === 0);
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest("unsafe output directory is rejected unchanged", async () => {
  const fixture = await buildFixture();
  try {
    await Deno.chmod(fixture.outputDirectory, 0o755);
    const { decrypt } = syntheticDecrypt(
      fixture.compressed,
      fixture.pathByRole,
    );
    const error = await rejectWith(
      verifyDecryptedGeneration(
        fixture.index,
        fixture.reconstruction,
        fixture.outputDirectory,
        decrypt,
      ),
    );
    assert(
      error.message === "Verifier failed (directory:permissions)",
      error.message,
    );
    assert((await modeOf(fixture.outputDirectory)) === 0o755);
  } finally {
    await removeBestEffort(fixture.recoveryDirectory);
    await removeBestEffort(fixture.outputDirectory);
  }
});

runtimeTest(
  "reconstruction identity mismatch is rejected before any decryption",
  async () => {
    const fixture = await buildFixture();
    try {
      const swapped = {
        ...fixture.reconstruction,
        archives: fixture.reconstruction.archives.map((archive, index) => ({
          ...archive,
          path: index === 0 ? fixture.pathByRole.get("efi")! : archive.path,
        })),
      };
      const { decrypt, calls } = syntheticDecrypt(
        fixture.compressed,
        fixture.pathByRole,
      );
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          swapped,
          fixture.outputDirectory,
          decrypt,
        ),
      );
      assert(
        error.message === "Verifier failed (reconstruction)",
        error.message,
      );
      assert(calls.length === 0);
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest(
  "mid-run failure preserves completed finals and partials, returns no receipt",
  async () => {
    const fixture = await buildFixture({
      customizeRoot: async (root) => {
        await Deno.remove(`${root}/boot/Image`);
      },
    });
    try {
      const { decrypt, calls } = syntheticDecrypt(
        fixture.compressed,
        fixture.pathByRole,
      );
      const error = await rejectWith(
        verifyDecryptedGeneration(
          fixture.index,
          fixture.reconstruction,
          fixture.outputDirectory,
          decrypt,
        ),
      );
      assert(
        error.message === "Verifier failed (listing:producer)",
        error.message,
      );
      assert(calls.length === 2);
      assert(
        await fileExists(`${fixture.outputDirectory}/recovery.json.zst`),
        "completed recovery final must remain",
      );
      assert(
        await fileExists(`${fixture.outputDirectory}/root.tar.zst.partial`),
        "failed root partial must remain",
      );
      assert(!(await fileExists(`${fixture.outputDirectory}/root.tar.zst`)));
    } finally {
      await removeBestEffort(fixture.recoveryDirectory);
      await removeBestEffort(fixture.outputDirectory);
    }
  },
);

runtimeTest("raw tool diagnostics never appear in module errors", async () => {
  const fixture = await buildFixture({
    customizeRoot: async (root) => {
      await Deno.remove(`${root}/boot/Image`);
    },
  });
  try {
    const { decrypt } = syntheticDecrypt(
      fixture.compressed,
      fixture.pathByRole,
    );
    const error = await rejectWith(
      verifyDecryptedGeneration(
        fixture.index,
        fixture.reconstruction,
        fixture.outputDirectory,
        decrypt,
      ),
    );
    assert(
      error.message === "Verifier failed (listing:producer)",
      error.message,
    );
    assert(!error.message.includes("tar:"), "no raw tar diagnostics");
    assert(!error.message.includes("zstd"), "no zstd diagnostics");
    assert(!error.message.includes("/var/folders"), "no local paths");
    assert(!error.message.includes("missing ./boot/Image"), "no member detail");
  } finally {
    await removeBestEffort(fixture.recoveryDirectory);
    await removeBestEffort(fixture.outputDirectory);
  }
});
