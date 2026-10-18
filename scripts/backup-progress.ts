import { backupUnitCgroupPaths } from "./backblaze-controller-contract.ts";
import { STALE_AFTER_MS } from "./backblaze-file-backup.ts";
import { backupV2GateDirectory } from "./backup-v2-worker.ts";
import {
  type BackupV2Status,
  validateBackupV2Gate,
  validateBackupV2Status,
} from "./backup-v2-runtime-contract.ts";
import {
  parseBackupV2ObjectName,
  validateBackupV2ObjectRef,
  validateBackupV2PutIntent,
} from "./backup-v2-contract.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";
/** Observation only: never controls a backup or copies archive contents. */
const BACKUP = "/var/tmp/arch-vps-file-backup";
const REPORT = "/var/lib/arch-vps-backup-progress/report.json";
const RELEASES = "/var/tmp/arch-vps-file-backup-runtime/releases";
const HOUR = 3_600_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STATES = new Set([
  "REQUESTED",
  "CAPTURING",
  "CAPTURED",
  "UPLOADING",
  "UPLOAD_VERIFIED",
  "INDEXING",
  "PENDING_VERIFIER",
  "VERIFYING",
  "ACCEPTED",
  "COMPLETE",
  "FAILED",
]);

export interface ProgressSample {
  format?: "backup-v2";
  v2Status?: BackupV2Status;
  processBound?: boolean;
  observedAtUtc: string;
  jobId: string;
  generation: string;
  requestedAtUtc: string;
  invocationId: string;
  phase: string;
  unitName: string;
  cpuUsec: number | null;
  readBytes: number | null;
  writeBytes: number | null;
  archiveBytes: Record<string, number> | null;
  uploadedBytes: number | null;
  verifiedChunks: number | null;
  captureBytes: number | null;
  sourceRevision: string | null;
  resourceLimits: ResourceLimits | null;
}

type Limit = number | "max" | null;
export interface ResourceLimits {
  cgroupPath: string;
  cpuMaxRaw: string | null;
  cpuQuotaCores: Limit;
  cpuWeight: number | null;
  memoryMaxBytes: Limit;
  memoryHighBytes: Limit;
  memorySwapMaxBytes: Limit;
  ioMaxRaw: string | null;
  ioDevices:
    | Array<{
      device: string;
      rbps: Limit;
      wbps: Limit;
      riops: Limit;
      wiops: Limit;
    }>
    | null;
  networkBytesPerSecond: number | null;
  networkBudgetProvenance: "PINNED_RELEASE_CONSTANT" | "UNKNOWN";
  networkBudgetSourcePath: string | null;
}

export interface ProgressReport {
  schemaVersion: 1;
  jobId: string | null;
  observedAtUtc: string;
  state:
    | "BASELINE"
    | "PROGRESSING"
    | "STALLED"
    | "BEHIND_SCHEDULE"
    | "COMPLETE"
    | "FAILED"
    | "UNKNOWN";
  detail: string;
  sample: ProgressSample | null;
  lastProgressAtUtc: string | null;
  uploadBytesPerSecond: number | null;
  uploadFinishAtUtc: string | null;
  cycleFinishAtUtc: null;
}

function finite(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function limit(value: string | null | undefined): Limit {
  const raw = value?.trim();
  if (raw === "max") return "max";
  if (!raw || !/^\d+$/.test(raw)) return null;
  const result = Number(raw);
  return finite(result) ? result : null;
}

/** Unknown and unbounded controls stay distinct in historical samples. */
export function parseResourceLimits(
  cgroupPath: string,
  controls: Record<string, string | null>,
): ResourceLimits {
  const cpu = controls["cpu.max"]?.trim().split(/\s+/);
  const quota = limit(cpu?.[0]);
  const period = limit(cpu?.[1]);
  const weight = limit(controls["cpu.weight"]);
  const io = controls["io.max"] ?? null;
  return {
    cgroupPath,
    cpuMaxRaw: controls["cpu.max"] ?? null,
    cpuQuotaCores: cpu?.length === 2 && typeof period === "number" &&
        period > 0 && quota !== null
      ? quota === "max" ? "max" : quota / period
      : null,
    cpuWeight: typeof weight === "number" && weight >= 1 && weight <= 10_000
      ? weight
      : null,
    memoryMaxBytes: limit(controls["memory.max"]),
    memoryHighBytes: limit(controls["memory.high"]),
    memorySwapMaxBytes: limit(controls["memory.swap.max"]),
    ioMaxRaw: io,
    ioDevices: io === null ? null : io.trim().split("\n").flatMap((line) => {
      const [device, ...fields] = line.trim().split(/\s+/);
      if (!/^\d+:\d+$/.test(device)) return [];
      const caps = Object.fromEntries(fields.map((field) => field.split("=")));
      return [{
        device,
        rbps: limit(caps.rbps),
        wbps: limit(caps.wbps),
        riops: limit(caps.riops),
        wiops: limit(caps.wiops),
      }];
    }),
    networkBytesPerSecond: null,
    networkBudgetProvenance: "UNKNOWN",
    networkBudgetSourcePath: null,
  };
}

/** Parse only a pinned release's literal budget; never execute source text. */
export function parseTransferBudget(source: string | null): number | null {
  const expression = source?.match(
    /^export const TRANSFER_BYTES_PER_SECOND\s*=\s*([^;]+);/m,
  )?.[1];
  if (!expression) return null;
  const factors = expression.trim().split("*").map((factor) => factor.trim());
  if (factors.some((factor) => !/^(0|[1-9]\d*(?:_\d+)*)$/.test(factor))) {
    return null;
  }
  const budget = factors.reduce(
    (product, factor) => product * Number(factor.replaceAll("_", "")),
    1,
  );
  return finite(budget) && budget > 0 ? budget : null;
}

/** Heartbeats are deliberately absent: a responsive process may be stalled. */
export function assessProgress(
  sample: ProgressSample | null,
  prior: ProgressReport | null,
  now: Date,
): ProgressReport {
  const report: ProgressReport = {
    schemaVersion: 1,
    jobId: sample?.jobId ?? null,
    observedAtUtc: now.toISOString(),
    state: "UNKNOWN",
    detail: "No usable source evidence",
    sample,
    lastProgressAtUtc: null,
    uploadBytesPerSecond: null,
    uploadFinishAtUtc: null,
    cycleFinishAtUtc: null,
  };
  if (!sample) return report;
  if (sample.format === "backup-v2") {
    return assessBackupV2Progress(sample, prior, now, report);
  }
  if (
    sample.phase === "FAILED" || sample.phase === "ACCEPTED" ||
    sample.phase === "COMPLETE"
  ) {
    report.state = sample.phase === "FAILED" ? "FAILED" : "COMPLETE";
    report.detail = sample.phase === "ACCEPTED"
      ? "Source verification accepted; controller cleanup is separate"
      : `Source status ${sample.phase}`;
    return report;
  }
  const old = prior?.sample;
  if (
    sample.cpuUsec === null || sample.readBytes === null ||
    sample.writeBytes === null
  ) {
    report.detail =
      "Exact source cgroup counters are missing; progress is unproven";
    return report;
  }
  const currentCounters = [
    sample.cpuUsec,
    sample.readBytes,
    sample.writeBytes,
    sample.uploadedBytes,
    sample.verifiedChunks,
  ];
  if (
    currentCounters.every((value) => value === null) &&
    sample.archiveBytes === null
  ) return report;
  report.state = "BASELINE";
  report.detail = "First observation for this job or invocation";
  report.lastProgressAtUtc = sample.observedAtUtc;
  if (
    !old || old.jobId !== sample.jobId ||
    old.invocationId !== sample.invocationId
  ) return report;
  if (
    JSON.stringify(sample.resourceLimits) !== JSON.stringify(old.resourceLimits)
  ) {
    report.detail =
      "Resource limits changed; starting a new performance baseline";
    return report;
  }
  const elapsed = Date.parse(sample.observedAtUtc) -
    Date.parse(old.observedAtUtc);
  if (!(elapsed > 0)) {
    report.state = "UNKNOWN";
    report.detail = "Observation clock did not advance";
    return report;
  }
  const previousCounters = [
    old.cpuUsec,
    old.readBytes,
    old.writeBytes,
    old.uploadedBytes,
    old.verifiedChunks,
  ];
  if (
    currentCounters.some((value, i) =>
      value !== null && previousCounters[i] !== null &&
      value < previousCounters[i]!
    )
  ) {
    report.detail = "Counter reset; a new comparison baseline is required";
    return report;
  }
  const comparableCounters = currentCounters.some((value, i) =>
    value !== null && previousCounters[i] !== null
  );
  const comparableArchives = sample.archiveBytes !== null &&
    old.archiveBytes !== null;
  const changed = sample.phase !== old.phase ||
    currentCounters.some((value, i) =>
      value !== null && previousCounters[i] !== null &&
      value > previousCounters[i]!
    ) ||
    (comparableArchives &&
      Object.entries(sample.archiveBytes!).some(([name, bytes]) =>
        bytes > (old.archiveBytes![name] ?? 0)
      ));
  if (!changed && !comparableCounters && !comparableArchives) {
    report.state = "UNKNOWN";
    report.detail = "No comparable progress evidence";
    return report;
  }
  report.lastProgressAtUtc = changed
    ? sample.observedAtUtc
    : prior?.lastProgressAtUtc ?? old.observedAtUtc;
  const idle = now.getTime() - Date.parse(report.lastProgressAtUtc);
  report.state = changed
    ? "PROGRESSING"
    : idle >= HOUR
    ? "STALLED"
    : "BASELINE";
  report.detail = changed
    ? "Phase, cgroup counters, archive growth or verified chunks advanced"
    : idle >= HOUR
    ? "No observed progress for at least one hour; inspect before intervening"
    : "Waiting for one hour of comparable observations";
  if (
    sample.phase === "UPLOADING" && old.phase === sample.phase &&
    sample.uploadedBytes !== null && old.uploadedBytes !== null &&
    sample.captureBytes !== null && sample.uploadedBytes > old.uploadedBytes &&
    sample.uploadedBytes <= sample.captureBytes
  ) {
    report.uploadBytesPerSecond = (sample.uploadedBytes - old.uploadedBytes) /
      (elapsed / 1000);
    const finish = now.getTime() +
      (sample.captureBytes - sample.uploadedBytes) /
        report.uploadBytesPerSecond * 1000;
    if (Number.isFinite(finish) && finish <= 8.64e15) {
      report.uploadFinishAtUtc = new Date(finish).toISOString();
      if (finish > Date.parse(sample.requestedAtUtc) + 24 * HOUR) {
        report.state = "BEHIND_SCHEDULE";
        report.detail =
          "Upload alone is projected past 24 hours; verification still follows";
      }
    }
  }
  return report;
}

/** CPU/IO remain attribution data. Only cumulative source/compressor/readback/
 * decrypt/inventory work proves v2 progress; phase/UTC/heartbeat changes do not. */
export function assessBackupV2Progress(
  sample: ProgressSample,
  prior: ProgressReport | null,
  now: Date,
  empty?: ProgressReport,
): ProgressReport {
  const report: ProgressReport = empty ?? {
    schemaVersion: 1,
    jobId: sample.jobId,
    observedAtUtc: now.toISOString(),
    state: "UNKNOWN",
    detail: "V2 progress is unproved",
    sample,
    lastProgressAtUtc: null,
    uploadBytesPerSecond: null,
    uploadFinishAtUtc: null,
    cycleFinishAtUtc: null,
  };
  let status: BackupV2Status;
  try {
    status = validateBackupV2Status(sample.v2Status);
  } catch {
    return report;
  }
  if (
    status.envelope.request.jobId !== sample.jobId ||
    status.envelope.request.captureId !== sample.generation ||
    status.custody.invocationId !== sample.invocationId ||
    status.phase !== sample.phase ||
    Date.parse(status.updatedAtUtc) > now.getTime()
  ) return report;
  if (status.phase === "FAILED" || status.phase === "CANCELLATION_BLOCKED") {
    report.state = "FAILED";
    report.detail =
      `V2 source ${status.phase}; custody and cleanup remain separate`;
    return report;
  }
  if (["CLOUD_COMPLETE", "ACCEPTED", "CLEANED"].includes(status.phase)) {
    report.state = "BASELINE";
    report.detail = status.kind === "prune"
      ? "Source retention stage finished; controller cleanup completion remains separate"
      : "Source terminal artifact exists; accepted catalog and settlement proof remain controller-owned";
    return report;
  }
  if (
    sample.processBound !== true || sample.cpuUsec === null ||
    sample.readBytes === null || sample.writeBytes === null ||
    now.getTime() - Date.parse(status.updatedAtUtc) > STALE_AFTER_MS
  ) {
    report.detail =
      "Exact v2 source process, current status or cgroup counters are unavailable";
    return report;
  }
  report.state = "BASELINE";
  report.detail = status.kind === "prune"
    ? "First bound source retention work observation"
    : "First bound v2 work observation; capture and upload may overlap";
  report.lastProgressAtUtc = sample.observedAtUtc;
  const old = prior?.sample;
  let previous: BackupV2Status;
  try {
    previous = validateBackupV2Status(old?.v2Status);
  } catch {
    return report;
  }
  if (
    !old || !previous || old.format !== "backup-v2" ||
    old.processBound !== true || previous.gateId !== status.gateId ||
    previous.sourceBootId !== status.sourceBootId ||
    previous.envelope.requestSha256 !== status.envelope.requestSha256 ||
    JSON.stringify(previous.custody) !== JSON.stringify(status.custody)
  ) return report;
  const elapsed = Date.parse(sample.observedAtUtc) -
    Date.parse(old.observedAtUtc);
  if (
    !(elapsed > 0) ||
    status.progress.observedMonotonicMs <= previous.progress.observedMonotonicMs
  ) {
    report.state = "UNKNOWN";
    report.detail = "V2 source observation clock did not advance";
    return report;
  }
  const fields = [
    "sourceBytes",
    "compressionInputBytes",
    "verifiedChunks",
    "decryptedBytes",
    "inventoryMembers",
  ] as const;
  if (
    fields.some((key) => status.progress[key] < previous.progress[key]) ||
    sample.uploadedBytes !== null && old.uploadedBytes !== null &&
      sample.uploadedBytes < old.uploadedBytes
  ) {
    report.detail = "V2 work counters reset; a fresh baseline is required";
    return report;
  }
  const changed =
    fields.some((key) => status.progress[key] > previous.progress[key]) ||
    sample.uploadedBytes !== null && old.uploadedBytes !== null &&
      sample.uploadedBytes > old.uploadedBytes;
  report.lastProgressAtUtc = changed
    ? sample.observedAtUtc
    : prior?.lastProgressAtUtc ?? old.observedAtUtc;
  const episode = status.lease.retryEpisode,
    waiting = episode !== null &&
      episode.expiresAtMs > status.lease.observedMonotonicMs;
  report.state = changed
    ? "PROGRESSING"
    : waiting
    ? "BASELINE"
    : now.getTime() - Date.parse(report.lastProgressAtUtc) >= HOUR
    ? "STALLED"
    : "BASELINE";
  report.detail = changed
    ? status.kind === "prune"
      ? "Bound source retention inventory work advanced; controller cleanup completion remains separate"
      : "Bound v2 source/compressor/verified-byte/decrypt/inventory work advanced; capture/upload overlap has no finalized total ETA"
    : waiting
    ? "Fixed source retry episode is active; no new useful work is claimed"
    : report.state === "STALLED"
    ? "No useful v2 work advanced for at least one hour; CPU/IO or heartbeats alone do not renew progress"
    : "Waiting for comparable useful v2 work";
  if (
    sample.uploadedBytes !== null && old.uploadedBytes !== null &&
    sample.uploadedBytes > old.uploadedBytes &&
    JSON.stringify(sample.resourceLimits) === JSON.stringify(old.resourceLimits)
  ) {
    report.uploadBytesPerSecond = (sample.uploadedBytes - old.uploadedBytes) /
      (elapsed / 1000);
  }
  return report;
}

/** Readback-selected payload bytes, never attempted PUT bytes or link ceilings.
 * This bounded journal observation is not cloud verification or acceptance. */
export async function verifiedBackupV2JournalBytes(
  chunks: AsyncIterable<Uint8Array>,
  captureId: string,
): Promise<number> {
  let pending = "", bytes = 0, total = 0;
  const decoder = new TextDecoder("utf-8", { fatal: true }),
    intents = new Map<
      string,
      { bytes: number; sha1: string; sha256: string; verified: boolean }
    >(),
    selected = new Map<string, string>(),
    logical = new Set<string>(),
    transfers = new Set<string>();
  for await (const chunk of chunks) {
    if (chunk.length > 64 * 1024) {
      throw Error("V2 journal read chunk exceeded bound");
    }
    bytes += chunk.length;
    if (bytes > BACKUP_V2_LIMITS.journalBytes) {
      throw Error("V2 journal bound exceeded");
    }
    pending += decoder.decode(chunk, { stream: true });
    let end: number;
    while ((end = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, end);
      pending = pending.slice(end + 1);
      if (new TextEncoder().encode(line).length > 8192) {
        throw Error("V2 journal record bound exceeded");
      }
      const r = JSON.parse(line);
      if (r.type === "intent") {
        const i = validateBackupV2PutIntent(r.intent);
        if (
          i.captureId !== captureId ||
          intents.size >= BACKUP_V2_LIMITS.physicalPuts
        ) throw Error("V2 journal identity differs");
        logical.add(
          `${i.captureId}/${i.attemptId}/${i.role}/${i.kind}/${i.ordinal}`,
        );
        intents.set(i.name, {
          bytes: i.slot.bytes,
          sha1: i.slot.sha1,
          sha256: i.slot.sha256,
          verified: false,
        });
      } else if (r.type === "verify") {
        const i = intents.get(r.name);
        if (!i) throw Error("V2 readback intent is missing");
        i.verified = true;
      } else if (r.type === "selected") {
        const object = validateBackupV2ObjectRef(r.object),
          i = intents.get(r.name),
          name = parseBackupV2ObjectName(object.fileName);
        if (
          !i || !i.verified || object.fileName !== r.name ||
          name.captureId !== captureId ||
          object.contentLength !== i.bytes ||
          object.sha256 !== i.sha256 || object.contentSha1 !== i.sha1
        ) throw Error("V2 selected readback differs");
        if (name.kind !== "data") continue;
        const key = `${name.attemptId}/${name.kind}/${name.ordinal}`,
          value = JSON.stringify(object),
          old = selected.get(key);
        if (old !== undefined && old !== value) {
          throw Error("V2 selection conflicts");
        }
        if (old === undefined) {
          selected.set(key, value);
          total += object.contentLength;
        }
        if (
          selected.size > BACKUP_V2_LIMITS.logicalObjects || !finite(total) ||
          total > BACKUP_V2_LIMITS.ciphertextBytes
        ) throw Error("V2 selected bytes exceed bound");
      } else if (r.type === "transfer") {
        if (
          typeof r.key !== "string" || !logical.has(r.key) ||
          transfers.has(`${r.key}/${r.phase}`) ||
          !["PUT", "READBACK"].includes(r.phase) ||
          typeof r.startedAtUtc !== "string" ||
          !Number.isFinite(Date.parse(r.startedAtUtc)) ||
          Object.keys(r).sort().join(",") !== "key,phase,startedAtUtc,type"
        ) {
          throw Error("Invalid V2 transfer record");
        }
        transfers.add(`${r.key}/${r.phase}`);
      } else if (
        !["begin", "candidate", "reclaimed", "episode", "scan", "eof"].includes(
          r.type,
        )
      ) throw Error("Unknown V2 journal record");
    }
    if (new TextEncoder().encode(pending).length > 8192) {
      throw Error("V2 journal record bound exceeded");
    }
  }
  decoder.decode(); // A concurrent partial final record is not selected evidence.
  return total;
}

async function json(
  path: string,
  budget?: { remaining: number },
): Promise<Record<string, unknown> | null> {
  try {
    const info = await Deno.lstat(path);
    if (!info.isFile || info.isSymlink || info.size > 2 * 1024 * 1024) {
      return null;
    }
    if (budget) {
      if (
        info.uid !== 0 || info.nlink !== 1 || info.mode === null ||
        (info.mode & 0o777) !== 0o600
      ) return null;
      budget.remaining -= info.size;
      if (budget.remaining < 0) return null;
    }
    const value = JSON.parse(await Deno.readTextFile(path));
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? value
      : null;
  } catch {
    return null;
  }
}

/** Permit only named backup units and a fixed set of cgroup controls. */
export function isBackupCgroupControlPath(path: string): boolean {
  return /^\/sys\/fs\/cgroup\/(?:system\.slice|weekly\.slice\/weekly-backup\.slice)\/arch-vps-b2-(?:v2-)?(?:worker|verify|prune)-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?:-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})?\.service\/(cgroup\.events|cgroup\.procs|cpu\.stat|io\.stat|cpu\.max|cpu\.weight|memory\.max|memory\.high|memory\.swap\.max|io\.max)$/
    .test(path);
}

async function text(path: string): Promise<string | null> {
  try {
    // Deno treats /sys as all-access. Grant only this fixed control reader
    // rather than granting the observer unrestricted Deno permissions.
    if (
      isBackupCgroupControlPath(path) ||
      /^\/proc\/[1-9][0-9]{0,9}\/(stat|cgroup)$/.test(path) ||
      path === "/proc/sys/kernel/random/boot_id"
    ) {
      const result = await new Deno.Command("/usr/bin/cat", {
        args: ["--", path],
        clearEnv: true,
        stdout: "piped",
        stderr: "null",
      }).output();
      return result.success && result.stdout.length <= 64 * 1024
        ? new TextDecoder().decode(result.stdout)
        : null;
    }
    return null;
  } catch {
    return null;
  }
}

function total(records: unknown, field: string): number | null {
  if (
    !Array.isArray(records) ||
    records.some((item) => !item || !finite(item[field]))
  ) return null;
  const sum = records.reduce((value, item) => value + item[field], 0);
  return finite(sum) ? sum : null;
}

/** Reads only status, metadata, file sizes, and the exact job's cgroup. */
async function sampleLegacy(now: Date): Promise<ProgressSample | null> {
  let selected: Record<string, unknown> | null = null;
  let count = 0;
  try {
    for await (const entry of Deno.readDir(`${BACKUP}/jobs`)) {
      if (++count > 1024) return null;
      if (
        !entry.isDirectory || !entry.name.startsWith("job-") ||
        !UUID.test(entry.name.slice(4))
      ) continue;
      const status = await json(`${BACKUP}/jobs/${entry.name}/status.json`);
      if (
        !status || status.jobId !== entry.name ||
        status.generation !== `generation-${entry.name.slice(4)}` ||
        !STATES.has(String(status.state)) ||
        typeof status.invocationId !== "string" ||
        !/^[0-9a-f]{32}$/.test(status.invocationId) ||
        typeof status.requestedAtUtc !== "string" ||
        !Number.isFinite(Date.parse(status.requestedAtUtc)) ||
        Date.parse(status.requestedAtUtc) > now.getTime()
      ) continue;
      if (
        !selected ||
        Date.parse(status.requestedAtUtc) >
          Date.parse(String(selected.requestedAtUtc))
      ) selected = status;
    }
  } catch {
    return null;
  }
  if (!selected) return null;
  const jobId = String(selected.jobId);
  const generation = String(selected.generation);
  const phase = String(selected.state);
  const unitName = `arch-vps-b2-${
    phase === "VERIFYING" || phase === "ACCEPTED" ? "verify" : "worker"
  }-${jobId.slice(4)}.service`;
  const groups = backupUnitCgroupPaths(unitName).map((path) =>
    `/sys/fs/cgroup${path}`
  );
  let group = groups[0];
  for (const candidate of groups) {
    if (await text(`${candidate}/cgroup.events`) !== null) {
      group = candidate;
      break;
    }
  }
  const controlNames = [
    "cpu.max",
    "cpu.weight",
    "memory.max",
    "memory.high",
    "memory.swap.max",
    "io.max",
  ];
  const [cpu, io, ...values] = await Promise.all([
    text(`${group}/cpu.stat`),
    text(`${group}/io.stat`),
    ...controlNames.map((name) => text(`${group}/${name}`)),
  ]);
  const resourceLimits = parseResourceLimits(
    group,
    Object.fromEntries(
      controlNames.map((name, index) => [name, values[index]]),
    ),
  );
  const request = await json(`${BACKUP}/jobs/${jobId}/request.json`);
  const sourceRevision = typeof request?.sourceRevision === "string" &&
      /^[0-9a-f]{40}$/.test(request.sourceRevision)
    ? request.sourceRevision
    : null;
  if (sourceRevision) {
    const sourcePath =
      `${RELEASES}/${sourceRevision}/scripts/backblaze-upload.ts`;
    try {
      const info = await Deno.lstat(sourcePath);
      if (info.isFile && !info.isSymlink && info.size <= 2 * 1024 * 1024) {
        resourceLimits.networkBytesPerSecond = parseTransferBudget(
          await Deno.readTextFile(sourcePath),
        );
        resourceLimits.networkBudgetSourcePath = sourcePath;
        if (resourceLimits.networkBytesPerSecond !== null) {
          resourceLimits.networkBudgetProvenance = "PINNED_RELEASE_CONSTANT";
        }
      }
    } catch {
      // A missing release is unknown, never the newest controller's default.
    }
  }
  const usage = cpu?.match(/^usage_usec (\d+)$/m)?.[1];
  const ioSum = (field: string): number | null => {
    if (io === null) return null;
    const matches = [...io.matchAll(new RegExp(`\\b${field}=(\\d+)`, "g"))];
    const sum = matches.reduce((value, match) => value + Number(match[1]), 0);
    return finite(sum) ? sum : null;
  };
  const stage = `${BACKUP}/${generation}`;
  let archiveBytes: Record<string, number> | null = {};
  try {
    for await (const entry of Deno.readDir(stage)) {
      if (
        !entry.isFile ||
        !/^(root|efi|staging-boot|staging-efi|oracle-root|oracle-oled|recovery)\.(tar|json)\.zst(\.gpg)?(\.partial)?$/
          .test(entry.name)
      ) continue;
      const info = await Deno.lstat(`${stage}/${entry.name}`);
      if (info.isFile && !info.isSymlink && finite(info.size)) {
        archiveBytes[entry.name] = info.size;
      }
    }
  } catch {
    archiveBytes = null;
  }
  const capture = await json(`${stage}/capture-result.json`);
  const journal = await json(`${stage}/upload-journal.json`);
  const validJournal = journal?.generation === generation &&
    journal.stageDirectory === stage && Array.isArray(journal.chunks) &&
    journal.chunks.every((chunk) =>
      chunk && typeof chunk.fileId === "string" && chunk.fileId.length > 0 &&
      typeof chunk.verifiedAtUtc === "string" &&
      Number.isFinite(Date.parse(chunk.verifiedAtUtc))
    );
  return {
    observedAtUtc: now.toISOString(),
    jobId,
    generation,
    requestedAtUtc: String(selected.requestedAtUtc),
    invocationId: String(selected.invocationId),
    phase,
    unitName,
    cpuUsec: usage !== undefined && finite(Number(usage))
      ? Number(usage)
      : null,
    readBytes: ioSum("rbytes"),
    writeBytes: ioSum("wbytes"),
    archiveBytes,
    uploadedBytes: validJournal ? total(journal!.chunks, "size") : null,
    verifiedChunks: validJournal ? (journal!.chunks as unknown[]).length : null,
    captureBytes:
      capture?.generation === generation && capture.stageDirectory === stage
        ? total(capture.archives, "bytes")
        : null,
    sourceRevision,
    resourceLimits,
  };
}

export function backupV2ProcessBound(
  status: BackupV2Status,
  boot: string | null,
  processGroup: string | null,
  stat: string | null,
  members: string | null,
): boolean {
  if (
    boot?.trim() !== status.sourceBootId ||
    processGroup?.trim() !== `0::${status.custody.cgroup}` ||
    !members?.trim().split(/\s+/).includes(String(status.custody.mainPid)) ||
    !stat?.startsWith(`${status.custody.mainPid} (`)
  ) return false;
  const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
  return fields[19] === status.custody.mainStartTicks &&
    !["Z", "X"].includes(fields[0]);
}
export function validateBackupV2ProgressGate(
  value: unknown,
  directory: string,
) {
  const gate = validateBackupV2Gate(value);
  if (backupV2GateDirectory(gate) !== directory) {
    throw Error("V2 observation gate directory differs");
  }
  return gate;
}
async function journalBytes(
  directory: string,
  captureId: string,
): Promise<number | null> {
  try {
    const path = `${directory}/journal/upload-journal.ndjson`,
      before = await Deno.lstat(path);
    if (
      !before.isFile || before.isSymlink || before.uid !== 0 ||
      before.nlink !== 1 || before.mode === null ||
      (before.mode & 0o777) !== 0o600 ||
      before.size > BACKUP_V2_LIMITS.journalBytes
    ) return null;
    using file = await Deno.open(path, { read: true });
    const opened = await file.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino) return null;
    const chunks = async function* () {
      let remaining = before.size;
      while (remaining > 0) {
        const bytes = new Uint8Array(Math.min(8192, remaining)),
          count = await file.read(bytes);
        if (!count) throw Error("V2 journal read stopped");
        remaining -= count;
        yield bytes.subarray(0, count);
      }
    };
    const result = await verifiedBackupV2JournalBytes(chunks(), captureId),
      after = await Deno.lstat(path);
    return after.dev === before.dev && after.ino === before.ino &&
        after.size >= before.size
      ? result
      : null;
  } catch {
    return null;
  }
}
/** Only public bound gate/status metadata is discovered under the existing
 * backup root. Missing publication is unknown; secret runtime settings are never read. */
async function sampleV2(
  now: Date,
): Promise<{ found: boolean; sample: ProgressSample | null }> {
  let found = false, scanned = 0;
  let latest:
    | { status: BackupV2Status; directory: string; bound: boolean }
    | null = null;
  const budget = { remaining: 16 * 1024 * 1024 };
  try {
    for await (const generation of Deno.readDir(BACKUP)) {
      if (++scanned > 4096) return { found: true, sample: null };
      if (
        !generation.isDirectory || !generation.name.startsWith("generation-") ||
        !UUID.test(generation.name.slice(11))
      ) continue;
      for await (
        const gateEntry of Deno.readDir(`${BACKUP}/${generation.name}`)
      ) {
        if (++scanned > 4096) return { found: true, sample: null };
        if (
          !gateEntry.isDirectory || !gateEntry.name.startsWith("v2-") ||
          !UUID.test(gateEntry.name.slice(3))
        ) continue;
        found = true;
        for await (
          const invocation of Deno.readDir(
            `${BACKUP}/${generation.name}/${gateEntry.name}`,
          )
        ) {
          if (++scanned > 4096) return { found, sample: null };
          if (
            !invocation.isDirectory || !/^[a-f0-9]{32}$/.test(invocation.name)
          ) continue;
          const directory =
            `${BACKUP}/${generation.name}/${gateEntry.name}/${invocation.name}`;
          const gate = validateBackupV2ProgressGate(
            await json(`${directory}/gate.json`, budget),
            directory,
          );
          if (
            Date.parse(gate.envelope.request.requestedAtUtc) > now.getTime()
          ) return { found, sample: null };
          const status = validateBackupV2Status(
            await json(`${directory}/status.json`, budget),
            gate,
          );
          const ack = await json(`${directory}/gate-bound.json`, budget);
          let sameCustody = false;
          try {
            validateBackupV2Status({ ...status, custody: ack?.custody }, gate);
            sameCustody = true;
          } catch { /* unknown acknowledgement */ }
          const bound = ack !== null && Object.keys(ack).length === 4 &&
            ack.gateId === gate.gateId &&
            ack.requestSha256 === gate.envelope.requestSha256 &&
            ack.sourceBootId === gate.sourceBootId && sameCustody;
          if (
            !latest ||
            status.envelope.request.requestedAtUtc >
              latest.status.envelope.request.requestedAtUtc ||
            status.envelope.request.requestedAtUtc ===
                  latest.status.envelope.request.requestedAtUtc &&
              status.updatedAtUtc > latest.status.updatedAtUtc
          ) latest = { status, directory, bound };
        }
      }
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) {
      return { found: true, sample: null };
    }
  }
  if (!latest || budget.remaining < 0) return { found, sample: null };
  const { status, directory, bound } = latest,
    group = `/sys/fs/cgroup${status.custody.cgroup}`,
    pid = status.custody.mainPid;
  const [boot, procGroup, stat, members, cpu, io] = await Promise.all([
    text("/proc/sys/kernel/random/boot_id"),
    text(`/proc/${pid}/cgroup`),
    text(`/proc/${pid}/stat`),
    text(`${group}/cgroup.procs`),
    text(`${group}/cpu.stat`),
    text(`${group}/io.stat`),
  ]);
  const names = [
      "cpu.max",
      "cpu.weight",
      "memory.max",
      "memory.high",
      "memory.swap.max",
      "io.max",
    ],
    values = await Promise.all(names.map((name) => text(`${group}/${name}`)));
  const ioSum = (field: string): number | null => {
    if (io === null) return null;
    const sum = [...io.matchAll(new RegExp(`\\b${field}=(\\d+)`, "g"))].reduce(
      (total, value) => total + Number(value[1]),
      0,
    );
    return finite(sum) ? sum : null;
  };
  const usage = cpu?.match(/^usage_usec (\d+)$/m)?.[1];
  const uploadedBytes = await journalBytes(
    directory,
    status.envelope.request.captureId,
  );
  const [afterGroup, afterStat, afterMembers] = await Promise.all([
    text(`/proc/${pid}/cgroup`),
    text(`/proc/${pid}/stat`),
    text(`${group}/cgroup.procs`),
  ]);
  return {
    found,
    sample: {
      format: "backup-v2",
      v2Status: status,
      processBound: bound &&
        backupV2ProcessBound(status, boot, procGroup, stat, members) &&
        backupV2ProcessBound(status, boot, afterGroup, afterStat, afterMembers),
      observedAtUtc: now.toISOString(),
      jobId: status.envelope.request.jobId,
      generation: status.envelope.request.captureId,
      requestedAtUtc: status.envelope.request.requestedAtUtc,
      invocationId: status.custody.invocationId,
      phase: status.phase,
      unitName: status.custody.unitName,
      cpuUsec: usage !== undefined && finite(Number(usage))
        ? Number(usage)
        : null,
      readBytes: ioSum("rbytes"),
      writeBytes: ioSum("wbytes"),
      archiveBytes: null,
      uploadedBytes,
      verifiedChunks: status.progress.verifiedChunks,
      captureBytes: null,
      sourceRevision: status.envelope.request.sourceRevision,
      resourceLimits: parseResourceLimits(
        group,
        Object.fromEntries(names.map((name, index) => [name, values[index]])),
      ),
    },
  };
}
export async function sampleLatest(now: Date): Promise<ProgressSample | null> {
  const [legacy, v2] = await Promise.all([sampleLegacy(now), sampleV2(now)]);
  if (!v2.found) return legacy;
  if (!v2.sample) return null;
  return legacy && legacy.requestedAtUtc > v2.sample.requestedAtUtc
    ? legacy
    : v2.sample;
}

async function writeReport(report: ProgressReport): Promise<void> {
  const directory = REPORT.slice(0, REPORT.lastIndexOf("/"));
  await Deno.mkdir(directory, { recursive: true, mode: 0o700 });
  if (await Deno.realPath(directory) !== directory) {
    throw new Error("Report directory is not canonical");
  }
  const history = `${directory}/history`;
  await Deno.mkdir(history, { recursive: true, mode: 0o700 });
  if (await Deno.realPath(history) !== history) {
    throw new Error("History directory is not canonical");
  }
  const historyPath = `${history}/${report.observedAtUtc.slice(0, 10)}.jsonl`;
  try {
    const info = await Deno.lstat(historyPath);
    if (!info.isFile || info.isSymlink) {
      throw new Error("History file is not a regular file");
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  using historical = await Deno.open(historyPath, {
    create: true,
    append: true,
    write: true,
    mode: 0o600,
  });
  const line = new TextEncoder().encode(`${JSON.stringify(report)}\n`);
  let written = 0;
  while (written < line.length) {
    written += await historical.write(line.subarray(written));
  }
  await historical.sync();
  const temporary = `${directory}/.report-${crypto.randomUUID()}.tmp`;
  let removalFailure: unknown;
  try {
    using file = await Deno.open(temporary, {
      createNew: true,
      write: true,
      mode: 0o600,
    });
    const bytes = new TextEncoder().encode(
      `${JSON.stringify(report, null, 2)}\n`,
    );
    let offset = 0;
    while (offset < bytes.length) {
      offset += await file.write(bytes.subarray(offset));
    }
    await file.sync();
    await Deno.rename(temporary, REPORT);
    using parent = await Deno.open(directory, { read: true });
    await parent.sync();
  } finally {
    try {
      await Deno.remove(temporary);
    } catch (error) {
      // Deno lint forbids control flow from a finally block: record the
      // cleanup failure and raise it after the primary result settles.
      if (!(error instanceof Deno.errors.NotFound)) removalFailure = error;
    }
  }
  if (removalFailure !== undefined) throw removalFailure;
}

if (import.meta.main) {
  const began = new Date();
  const prior = await json(REPORT);
  const sample = await sampleLatest(began),
    now = sample?.format === "backup-v2" ? new Date() : began;
  if (sample?.format === "backup-v2") sample.observedAtUtc = now.toISOString();
  const report = assessProgress(
    sample,
    prior?.schemaVersion === 1 ? prior as unknown as ProgressReport : null,
    now,
  );
  await writeReport(report);
  console.log(JSON.stringify(report));
}
