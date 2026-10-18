import { createHash } from "node:crypto";
import {
  type CaptureCommandRunner,
  type CaptureSettings,
  collectRecoveryMetadata,
  flattenLsblk,
  type InitialState,
  type RecoveryMetadataParams,
  ROLE_ORDER,
  validateCaptureSettings,
} from "./backblaze-capture.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  type BackupV2SampleExpectation,
} from "./backup-v2-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "./backup-v2-profile.ts";

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
