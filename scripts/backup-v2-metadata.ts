import { createHash } from "node:crypto";
import {
  type CaptureCommandRunner,
  type CaptureSettings,
  collectRecoveryMetadata,
  flattenLsblk,
  type InitialState,
  type RecoveryMetadataParams,
  ROLE_ORDER,
  swapfileRecreation,
  validateCaptureSettings,
  validateSources,
} from "./backblaze-capture.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  type BackupV2SampleExpectation,
  validateBackupV2ChunkPage,
} from "./backup-v2-contract.ts";
import {
  assertBackupV2Budget,
  BACKUP_V2_PROFILE_ID,
} from "./backup-v2-profile.ts";
import { validateBackupV2InventorySummary } from "./backup-v2-inventory.ts";
import type { BackupV2CapturedRole } from "./backup-v2-capture.ts";

const encoder = new TextEncoder();
export const BACKUP_V2_RECOVERY_BYTES = 8 * 1024 * 1024;
const hash = (bytes: Uint8Array | string) =>
  createHash("sha256").update(bytes).digest("hex");

/** Small metadata commands only; overflow cancels the complete managed unit. */
export function createBackupV2MetadataRunner(
  stage: string,
  custody: {
    assertManaged(): Promise<void>;
    cancel(reason: unknown): Promise<void>;
  },
): CaptureCommandRunner {
  return async (command, args, stderrLog) => {
    await custody.assertManaged();
    const child = new Deno.Command("bash", {
      args: [
        "-c",
        'ulimit -f 2048 || exit 80; exec "$@"',
        "m05-metadata",
        command,
        ...args,
      ],
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      clearEnv: true,
      env: { PATH: "/usr/bin:/bin", LC_ALL: "C", TZ: "UTC", TMPDIR: stage },
    }).spawn();
    const collect = async (
      stream: ReadableStream<Uint8Array>,
      limit: number,
    ) => {
      let total = 0;
      const chunks: Uint8Array[] = [];
      for await (const bytes of stream) {
        total += bytes.length;
        if (total > limit) {
          throw new Error("Backup v2 metadata command output bound");
        }
        chunks.push(bytes);
      }
      const result = new Uint8Array(total);
      let offset = 0;
      for (const bytes of chunks) {
        result.set(bytes, offset);
        offset += bytes.length;
      }
      return new TextDecoder("utf-8", { fatal: true }).decode(result);
    };
    const observe = <T>(promise: Promise<T>) =>
      promise.catch(async (error) => {
        await custody.cancel(error);
        throw error;
      });
    const results = await Promise.allSettled([
      child.status,
      observe(collect(child.stdout, BACKUP_V2_RECOVERY_BYTES)),
      observe(collect(child.stderr, 1024 * 1024)),
    ]);
    for (const result of results) {
      if (result.status === "rejected") throw result.reason;
    }
    const code =
      (results[0] as PromiseFulfilledResult<Deno.CommandStatus>).value.code;
    const stdout = (results[1] as PromiseFulfilledResult<string>).value;
    const stderr = (results[2] as PromiseFulfilledResult<string>).value;
    if (code !== 0 && stderrLog) {
      try {
        await Deno.writeTextFile(stderrLog, stderr, {
          mode: 0o600,
          createNew: true,
        });
      } catch {
        /* Do not replace earlier diagnostics or mask the command failure. */
      }
    }
    return { code, stdout, stderr };
  };
}

/** Same canonical byte encoding as the existing source worker. */
export function backupV2SourceConfigSha256(settings: CaptureSettings): string {
  validateCaptureSettings(settings);
  const sources = ROLE_ORDER.map((role) => {
    const source = settings.sources.find((item) => item.name === role)!;
    return {
      name: source.name,
      uuid: source.uuid,
      filesystem: source.filesystem,
      size: source.size,
      ...(source.livePath === undefined ? {} : { livePath: source.livePath }),
    };
  });
  return hash(
    JSON.stringify({ sources, exclusionsText: settings.exclusionsText }),
  );
}

/** No elapsed-time substitute for source/boot/package compatibility. */
export function backupV2CompatibilitySha256(
  settings: CaptureSettings,
  before: InitialState,
): string {
  const topology = flattenLsblk(before.layout).map((node) => ({
    path: node.path,
    type: node.type,
    size: node.size,
    fstype: node.fstype,
    uuid: node.uuid,
    mountpoints: [...(node.mountpoints ?? [])].sort(),
  })).sort((a, b) => (a.path ?? "").localeCompare(b.path ?? ""));
  return hash(JSON.stringify({
    sourceConfigSha256: backupV2SourceConfigSha256(settings),
    recipientSha256: settings.recipientSha256,
    recipientFingerprint: settings.recipientFingerprint,
    profile: BACKUP_V2_PROFILE_ID,
    topology,
    packagesSha256: hash(before.pacman),
    bootHashes: before.bootHashes,
  }));
}

export function backupV2BootSamples(
  rootHashes: string,
  stagingHashes: string,
  rootBytes: readonly number[],
  stagingBytes: readonly number[],
): (BackupV2SampleExpectation & { bytes: number })[] {
  const parse = (text: string) =>
    text.trim().split("\n").map((line) => {
      const match = /^([0-9a-f]{64})[ \t]+[ *]?(.+)$/.exec(line);
      if (!match) throw new Error("Backup v2 boot hash is invalid");
      return { sha256: match[1], member: match[2] };
    });
  const root = parse(rootHashes), staging = parse(stagingHashes);
  if (
    root.length !== 2 || staging.length !== 2 || rootBytes.length !== 2 ||
    stagingBytes.length !== 2
  ) throw new Error("Backup v2 boot sample count is invalid");
  const all = [...root, ...staging], sizes = [...rootBytes, ...stagingBytes];
  const samples = BACKUP_V2_BOOT_SAMPLES.map((sample, index) => {
    const expected = sample.role === "root"
      ? sample.member.slice(1)
      : sample.member;
    if (
      all[index].member !== expected || !Number.isSafeInteger(sizes[index]) ||
      sizes[index] <= 0
    ) throw new Error("Backup v2 boot sample identity is invalid");
    return {
      role: sample.role,
      member: encoder.encode(sample.member),
      bytes: sizes[index],
      sha256: all[index].sha256,
    };
  });
  for (let index = 0; index < 2; index++) {
    if (
      samples[index].sha256 !== samples[index + 2].sha256 ||
      samples[index].bytes !== samples[index + 2].bytes
    ) throw new Error("Backup v2 boot samples disagree");
  }
  return samples;
}

/** Metadata is bounded independently of payload size; no local archives invented. */
export function encodeBackupV2RecoveryMetadata(value: unknown) {
  const text = JSON.stringify(value);
  if (!text || text.length > BACKUP_V2_RECOVERY_BYTES) {
    throw new Error("Backup v2 recovery metadata exceeds its bound");
  }
  const bytes = encoder.encode(text);
  if (bytes.length > BACKUP_V2_RECOVERY_BYTES) {
    throw new Error("Backup v2 recovery metadata exceeds its bound");
  }
  return { bytes, sha256: hash(bytes) };
}

export async function collectBackupV2RecoveryMetadata<Archive>(
  params: RecoveryMetadataParams<Archive>,
  bootSamples: (BackupV2SampleExpectation & { bytes: number })[],
) {
  const legacy = await collectRecoveryMetadata(params);
  const manifest = {
    ...legacy,
    schemaVersion: 2,
    format: "backup-v2-recovery",
    sourceConfigSha256: backupV2SourceConfigSha256(params.settings),
    compatibilitySha256: backupV2CompatibilitySha256(
      params.settings,
      params.before,
    ),
    bootSamples: bootSamples.map((sample) => ({
      ...sample,
      member: new TextDecoder("utf-8", { fatal: true }).decode(sample.member),
    })),
  };
  return { ...encodeBackupV2RecoveryMetadata(manifest), bootSamples, manifest };
}

export type BackupV2RoleRecoveryMetadata =
  | {
    role: "root";
    initial: InitialState;
    tools: Record<string, string>;
    bootBytes: number[];
  }
  | {
    role: "staging-boot";
    beforeHashes: string;
    afterHashes: string;
    beforeBytes: string;
    afterBytes: string;
  }
  | { role: "oracle-root"; swapfileStat: string }
  | { role: "efi" | "staging-efi" | "oracle-oled" }
  | { role: "recovery"; text: string; sha256: string };
export interface BackupV2ReusedRole {
  capture: BackupV2CapturedRole;
  recovery: BackupV2RoleRecoveryMetadata;
}

function rejected(): never {
  throw new Error("Backup v2 reused role or original metadata is invalid");
}
function canonical(value: unknown): string {
  const order = (item: unknown): unknown =>
    Array.isArray(item)
      ? item.map(order)
      : item !== null && typeof item === "object"
      ? Object.fromEntries(
        Object.entries(item).sort(([a], [b]) => a.localeCompare(b)).map((
          [key, val],
        ) => [key, order(val)]),
      )
      : item;
  return JSON.stringify(order(value));
}
function exact(value: unknown, keys: string[]) {
  if (
    !value || typeof value !== "object" || Array.isArray(value) ||
    canonical(Object.keys(value).sort()) !== canonical(keys.sort())
  ) rejected();
}
function timestamp(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    rejected();
  }
  return parsed;
}
function sizes(text: string): number[] {
  if (!/^[1-9][0-9]*\n[1-9][0-9]*\n$/.test(text)) rejected();
  const result = text.trim().split("\n").map(Number);
  if (result.some((value) => !Number.isSafeInteger(value))) rejected();
  return result;
}

/** Cloud-object readback/custody belongs to the caller; these are current-source gates. */
export function validateBackupV2ReusedRoles(
  values: readonly BackupV2ReusedRole[],
  settings: CaptureSettings,
  before: InitialState,
  tools: Record<string, string>,
  bootBytes: readonly number[],
  observedAtUtc: string,
): Map<string, BackupV2ReusedRole> {
  if (!Array.isArray(values) || values.length > 7) rejected();
  const result = new Map<string, BackupV2ReusedRole>();
  const compatibility = backupV2CompatibilitySha256(settings, before);
  for (const entry of values) {
    exact(entry, ["capture", "recovery"]);
    const role = entry.capture, metadata = entry.recovery;
    if (
      !role || !metadata || result.has(role.role) ||
      ![...ROLE_ORDER, "recovery"].includes(role.role) ||
      role.captureId !== settings.generation ||
      role.sourceConfigSha256 !== backupV2SourceConfigSha256(settings) ||
      role.compatibilitySha256 !== compatibility ||
      role.recipientSha256 !== settings.recipientSha256 ||
      role.recipientFingerprint !== settings.recipientFingerprint ||
      metadata.role !== role.role ||
      role.format !==
        (role.role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg") ||
      !/^[0-9a-f]{64}$/.test(role.ciphertextSha256)
    ) rejected();
    const start = timestamp(role.captureStartedAtUtc),
      finish = timestamp(role.captureFinishedAtUtc),
      upload = timestamp(role.uploadStartedAtUtc),
      uploaded = timestamp(role.uploadFinishedAtUtc);
    if (
      start >= finish || upload < start || uploaded < finish ||
      upload > uploaded || uploaded > timestamp(observedAtUtc)
    ) rejected();
    assertBackupV2Budget("ciphertextBytes", role.ciphertextBytes);
    assertBackupV2Budget("logicalObjects", role.chunks.length);
    if (!role.ciphertextBytes || !role.chunks.length) rejected();
    for (let index = 0; index < role.chunks.length; index += 256) {
      const first = role.chunks[index];
      validateBackupV2ChunkPage({
        schemaVersion: 2,
        captureId: role.captureId,
        attemptId: role.attemptId,
        role: role.role,
        pageIndex: index / 256,
        startOrdinal: index,
        startOffset: first.offset,
        chunks: role.chunks.slice(index, index + 256),
      });
    }
    let offset = 0;
    for (const [index, chunk] of role.chunks.entries()) {
      if (chunk.ordinal !== index || chunk.offset !== offset) rejected();
      offset += chunk.object.contentLength;
    }
    if (
      offset !== role.ciphertextBytes || role.producer.zstdExitCode !== 0 ||
      role.producer.gpgExitCode !== 0 ||
      ![0, 1].includes(role.producer.tarExitCode) ||
      !/^[0-9a-f]{64}$/.test(role.producer.driftSha256)
    ) rejected();
    assertBackupV2Budget("members", role.producer.driftRecords);
    if (
      role.producer.tarExitCode === 1 &&
      (role.role !== "root" || !role.producer.driftRecords)
    ) rejected();
    if (
      role.role === "recovery"
        ? role.inventory !== null
        : !role.inventory?.members
    ) rejected();
    if (role.inventory) validateBackupV2InventorySummary(role.inventory);
    if (metadata.role === "root") {
      exact(metadata, ["role", "initial", "tools", "bootBytes"]);
      exact(metadata.initial, ["layout", "pacman", "bootHashes"]);
      validateSources(settings.sources, metadata.initial.layout);
      if (
        backupV2CompatibilitySha256(settings, metadata.initial) !==
          compatibility ||
        canonical(metadata.tools) !== canonical(tools) ||
        metadata.initial.pacman !== before.pacman ||
        metadata.initial.bootHashes !== before.bootHashes ||
        canonical(metadata.bootBytes) !== canonical(bootBytes)
      ) rejected();
    } else if (metadata.role === "staging-boot") {
      exact(metadata, [
        "role",
        "beforeHashes",
        "afterHashes",
        "beforeBytes",
        "afterBytes",
      ]);
      backupV2BootSamples(
        before.bootHashes,
        metadata.beforeHashes,
        bootBytes,
        sizes(metadata.beforeBytes),
      );
      backupV2BootSamples(
        before.bootHashes,
        metadata.afterHashes,
        bootBytes,
        sizes(metadata.afterBytes),
      );
    } else if (metadata.role === "oracle-root") {
      exact(metadata, ["role", "swapfileStat"]);
      if (metadata.swapfileStat.length > 256) rejected();
      swapfileRecreation(metadata.swapfileStat);
    } else if (metadata.role === "recovery") {
      exact(metadata, ["role", "text", "sha256"]);
      if (
        typeof metadata.text !== "string" ||
        metadata.text.length > BACKUP_V2_RECOVERY_BYTES
      ) rejected();
      const encoded = encodeBackupV2RecoveryMetadata(JSON.parse(metadata.text));
      if (
        new TextDecoder().decode(encoded.bytes) !== metadata.text ||
        encoded.sha256 !== metadata.sha256
      ) rejected();
    } else exact(metadata, ["role"]);
    if (metadata.role !== "recovery") {
      assertBackupV2Budget(
        "metadataRecordBytes",
        encoder.encode(JSON.stringify(metadata)).length,
      );
    }
    result.set(role.role, structuredClone(entry));
  }
  if (result.has("recovery") && ROLE_ORDER.some((role) => !result.has(role))) {
    rejected();
  }
  return result;
}

/** Reuse complete original bytes only, after matching all original role descriptors. */
export function restoreBackupV2RecoveryMetadata<Archive>(
  original: Extract<BackupV2RoleRecoveryMetadata, { role: "recovery" }>,
  settings: CaptureSettings,
  before: InitialState,
  archives: Archive[],
  bootSamples: (BackupV2SampleExpectation & { bytes: number })[],
): Awaited<ReturnType<typeof collectBackupV2RecoveryMetadata<Archive>>> {
  const value = JSON.parse(original.text);
  const encoded = encodeBackupV2RecoveryMetadata(value);
  const required = [
    "startedAtUtc",
    "finishedAtUtc",
    "consistency",
    "sourceShutdown",
    "machineBootRestoreProved",
    "captureMethod",
    "sources",
    "blockLayouts",
    "mountMetadata",
    "findmnt",
    "partitionTables",
    "lvm",
    "packages",
    "bootHashes",
    "finalChecks",
    "exclusions",
    "swapRecreation",
    "procCmdline",
    "fstab",
    "tools",
    "archiveOptions",
    "archives",
    "recipient",
    "efivars",
    "bootSamples",
  ];
  if (
    encoded.sha256 !== original.sha256 ||
    new TextDecoder().decode(encoded.bytes) !== original.text ||
    required.some((key) => !(key in value)) ||
    value.consistency !== "live-file-copy" || value.sourceShutdown !== false ||
    value.machineBootRestoreProved !== false ||
    value.packages !== before.pacman ||
    value.bootHashes?.root !== before.bootHashes ||
    canonical(value.blockLayouts?.initial) !== canonical(before.layout) ||
    value.schemaVersion !== 2 || value.format !== "backup-v2-recovery" ||
    value.generation !== settings.generation ||
    value.sourceConfigSha256 !== backupV2SourceConfigSha256(settings) ||
    value.compatibilitySha256 !==
      backupV2CompatibilitySha256(settings, before) ||
    value.recipient?.fingerprint !== settings.recipientFingerprint ||
    value.recipient?.publicSha256 !== settings.recipientSha256 ||
    canonical(value.archives) !== canonical(archives) ||
    canonical(value.bootSamples) !==
      canonical(
        bootSamples.map((sample) => ({
          ...sample,
          member: new TextDecoder().decode(sample.member),
        })),
      )
  ) rejected();
  return {
    ...encoded,
    bootSamples: structuredClone(bootSamples),
    manifest: value,
  };
}
