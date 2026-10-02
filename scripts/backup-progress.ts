/** Observation only: never controls a backup or copies archive contents. */
const BACKUP = "/var/tmp/arch-vps-file-backup";
const REPORT = "/var/lib/arch-vps-backup-progress/report.json";
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

async function json(path: string): Promise<Record<string, unknown> | null> {
  try {
    const info = await Deno.lstat(path);
    if (!info.isFile || info.isSymlink || info.size > 2 * 1024 * 1024) {
      return null;
    }
    const value = JSON.parse(await Deno.readTextFile(path));
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? value
      : null;
  } catch {
    return null;
  }
}

async function text(path: string): Promise<string | null> {
  try {
    // Deno treats /sys as all-access. Grant only this fixed counter reader
    // rather than granting the observer unrestricted Deno permissions.
    if (
      /^\/sys\/fs\/cgroup\/system\.slice\/arch-vps-b2-(worker|verify)-[0-9a-f-]{36}\.service\/(cpu|io)\.stat$/
        .test(path)
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
export async function sampleLatest(now: Date): Promise<ProgressSample | null> {
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
  const group = `/sys/fs/cgroup/system.slice/${unitName}`;
  const cpu = await text(`${group}/cpu.stat`);
  const io = await text(`${group}/io.stat`);
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
  };
}

async function writeReport(report: ProgressReport): Promise<void> {
  const directory = REPORT.slice(0, REPORT.lastIndexOf("/"));
  await Deno.mkdir(directory, { recursive: true, mode: 0o700 });
  if (await Deno.realPath(directory) !== directory) {
    throw new Error("Report directory is not canonical");
  }
  const temporary = `${directory}/.report-${crypto.randomUUID()}.tmp`;
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
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  }
}

if (import.meta.main) {
  const now = new Date();
  const prior = await json(REPORT);
  const report = assessProgress(
    await sampleLatest(now),
    prior?.schemaVersion === 1 ? prior as unknown as ProgressReport : null,
    now,
  );
  await writeReport(report);
  console.log(JSON.stringify(report));
}
