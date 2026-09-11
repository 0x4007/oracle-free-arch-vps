/** Read-only Linux guest telemetry over the existing pinned SSH identity.
 * These are supporting measurements, never oci_computeagent or idle-policy
 * evidence. No package, guest service or provider resource is changed. */
import { type GuestPolicy, shellQuote } from "./backup-guest.ts";
import { withBackupLock } from "./backup-lock.ts";
import {
  type CommandRunner,
  defaultRunner,
  readPrivateJson,
  writePrivateJson,
} from "./oci.ts";

export interface GuestSample {
  source: "linux-proc-over-ssh";
  instanceId: string;
  observedAtUtc: string;
  bootId: string;
  rootUuid: string;
  uptimeSeconds: number;
  memoryTotalBytes: number;
  memoryAvailableBytes: number;
  memoryUsedPercent: number;
  interface: string;
  receivedBytes: number;
  transmittedBytes: number;
}

export const GUEST_OBSERVATION_COMMAND = `set -euo pipefail
printf 'BOOT '; cat /proc/sys/kernel/random/boot_id
printf 'ROOT '; findmnt -nro UUID /
printf 'UPTIME '; cat /proc/uptime
printf 'MEMORY\\n'; cat /proc/meminfo
printf 'ROUTES\\n'; cat /proc/net/route
printf 'NETWORK\\n'; cat /proc/net/dev`;

export function parseGuestSample(
  output: string,
  instanceId: string,
  rootUuid: string,
  observedAt: Date,
): GuestSample {
  if (output.length > 32 * 1024 || !Number.isFinite(observedAt.getTime())) {
    throw Error("Guest observation is outside its bound");
  }
  const field = (pattern: RegExp) => {
    const matches = [...output.matchAll(pattern)];
    if (matches.length !== 1) throw Error("Guest observation is ambiguous");
    return matches[0][1];
  };
  const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
  const bootId = field(/^BOOT (\S+)$/gm);
  if (
    !uuid.test(bootId) || !uuid.test(rootUuid) ||
    field(/^ROOT (\S+)$/gm) !== rootUuid ||
    !/^ocid1\.instance\.[A-Za-z0-9.]+$/.test(instanceId)
  ) {
    throw Error("Guest identity differs from the configured source");
  }
  const uptimeSeconds = Number(field(/^UPTIME ([\d.]+) [\d.]+$/gm));
  const memoryTotalBytes = Number(field(/^MemTotal:\s+(\d+) kB$/gm)) * 1024;
  const memoryAvailableBytes = Number(field(/^MemAvailable:\s+(\d+) kB$/gm)) *
    1024;
  if (
    ![memoryTotalBytes, memoryAvailableBytes].every(Number.isSafeInteger) ||
    memoryTotalBytes <= 0 || memoryAvailableBytes < 0 ||
    memoryAvailableBytes > memoryTotalBytes ||
    !Number.isFinite(uptimeSeconds) || uptimeSeconds <= 0
  ) {
    throw Error("Invalid guest memory or uptime");
  }
  const routes = output.split("ROUTES\n")[1]?.split("NETWORK\n")[0];
  const network = output.split("NETWORK\n")[1];
  if (!routes || !network) throw Error("Guest network data missing");
  const defaults = routes.trim().split("\n").slice(1).map((line) =>
    line.trim().split(/\s+/)
  )
    .filter((row) => row[1] === "00000000" && (parseInt(row[3], 16) & 1) === 1);
  if (defaults.length !== 1 || !/^[A-Za-z0-9_.-]+$/.test(defaults[0][0])) {
    throw Error("Guest default interface is ambiguous");
  }
  const iface = defaults[0][0];
  const rows = network.trim().split("\n").filter((line) =>
    line.trim().startsWith(iface + ":")
  );
  if (rows.length !== 1) throw Error("Guest interface counters missing");
  const counters = rows[0].split(":")[1].trim().split(/\s+/).map(Number);
  if (
    counters.length !== 16 ||
    !counters.every((n) => Number.isSafeInteger(n) && n >= 0)
  ) {
    throw Error("Invalid network counters");
  }
  return {
    source: "linux-proc-over-ssh",
    instanceId,
    observedAtUtc: observedAt.toISOString(),
    bootId,
    rootUuid,
    uptimeSeconds,
    memoryTotalBytes,
    memoryAvailableBytes,
    memoryUsedPercent: 100 * (1 - memoryAvailableBytes / memoryTotalBytes),
    interface: iface,
    receivedBytes: counters[0],
    transmittedBytes: counters[8],
  };
}

export function guestNetworkRate(current: GuestSample, previous?: GuestSample) {
  if (!previous) return { status: "baseline-required" as const };
  const seconds = current.uptimeSeconds - previous.uptimeSeconds;
  const wallSeconds =
    (Date.parse(current.observedAtUtc) - Date.parse(previous.observedAtUtc)) /
    1000;
  if (
    ![
      current.receivedBytes,
      current.transmittedBytes,
      previous.receivedBytes,
      previous.transmittedBytes,
    ]
      .every((n) => Number.isSafeInteger(n) && n >= 0) ||
    current.instanceId !== previous.instanceId ||
    current.bootId !== previous.bootId ||
    current.rootUuid !== previous.rootUuid ||
    current.interface !== previous.interface ||
    !Number.isFinite(seconds) || !Number.isFinite(wallSeconds) ||
    seconds <= 0 || seconds > 150 ||
    Math.abs(wallSeconds - seconds) > 10 ||
    current.receivedBytes < previous.receivedBytes ||
    current.transmittedBytes < previous.transmittedBytes
  ) {
    return { status: "discontinuity" as const };
  }
  return {
    status: "observed" as const,
    intervalSeconds: seconds,
    receivedBytesPerSecond: (current.receivedBytes - previous.receivedBytes) /
      seconds,
    transmittedBytesPerSecond:
      (current.transmittedBytes - previous.transmittedBytes) / seconds,
  };
}

const REPORT = ".private/reports/guest-telemetry.json";
const DIRECTORY = ".private/guest-telemetry";

export function summarizeGuestSamples(
  samples: GuestSample[],
  instanceId: string,
  start: Date,
  end: Date,
) {
  const startMs = start.getTime(), endMs = end.getTime();
  const minutes = (endMs - startMs) / 60000;
  if (
    !Number.isInteger(minutes) || minutes <= 0 || minutes > 10080 ||
    startMs % 60000 !== 0 || endMs % 60000 !== 0
  ) throw Error("Invalid guest telemetry window");
  const buckets = new Map<number, GuestSample>();
  for (const sample of samples) {
    const time = Date.parse(sample.observedAtUtc);
    if (
      sample.source !== "linux-proc-over-ssh" ||
      sample.instanceId !== instanceId ||
      !Number.isFinite(time) || time < startMs || time >= endMs ||
      !Number.isFinite(sample.memoryUsedPercent) ||
      sample.memoryUsedPercent < 0 || sample.memoryUsedPercent > 100
    ) continue;
    const bucket = Math.floor(time / 60000);
    const old = buckets.get(bucket);
    if (!old || Date.parse(old.observedAtUtc) < time) {
      buckets.set(bucket, sample);
    }
  }
  const ordered = [...buckets.values()].sort((a, b) =>
    Date.parse(a.observedAtUtc) - Date.parse(b.observedAtUtc)
  );
  const memory = ordered.map((s) => s.memoryUsedPercent).sort((a, b) => a - b);
  const networkIntervalsObserved =
    ordered.slice(1).filter((s, i) =>
      guestNetworkRate(s, ordered[i]).status === "observed"
    ).length;
  return {
    source: "linux-proc-over-ssh",
    nativeOracleAgent: false,
    idlePolicyEvidence: false,
    windowStartUtc: start.toISOString(),
    windowEndUtcExclusive: end.toISOString(),
    expectedMinutes: minutes,
    observedMinutes: buckets.size,
    missingMinutes: minutes - buckets.size,
    status: buckets.size === 0
      ? "unavailable"
      : buckets.size === minutes
      ? "complete"
      : "incomplete",
    memoryUsedPercent: memory.length
      ? {
        minimum: memory[0],
        maximum: memory.at(-1),
        percentile95: memory[Math.ceil(memory.length * 0.95) - 1],
      }
      : null,
    networkIntervalsObserved,
    expectedNetworkIntervals: minutes - 1,
    networkStatus:
      buckets.size === minutes && networkIntervalsObserved === minutes - 1
        ? "complete"
        : "incomplete",
  };
}

export async function readGuestTelemetrySummary(
  instanceId: string,
  start: Date,
  end: Date,
) {
  const samples: GuestSample[] = [];
  let malformedRecords = 0;
  try {
    for await (const entry of Deno.readDir(DIRECTORY)) {
      if (!entry.isFile || !/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(entry.name)) {
        continue;
      }
      const date = entry.name.slice(0, 10);
      if (
        date < start.toISOString().slice(0, 10) ||
        date > end.toISOString().slice(0, 10)
      ) continue;
      const path = `${DIRECTORY}/${entry.name}`;
      const stat = await Deno.stat(path);
      if (stat.size > 2 * 1024 * 1024) {
        throw Error("Guest telemetry day exceeds size bound");
      }
      for (const line of (await Deno.readTextFile(path)).split("\n")) {
        if (!line) continue;
        try {
          const value = JSON.parse(line);
          if (!value.sample || typeof value.sample !== "object") {
            throw Error("Missing sample");
          }
          samples.push(value.sample);
        } catch {
          malformedRecords++;
        }
      }
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  return {
    ...summarizeGuestSamples(samples, instanceId, start, end),
    malformedRecords,
  };
}

export async function main(
  runner: CommandRunner = defaultRunner,
): Promise<void> {
  await withBackupLock(".private/guest-telemetry.lock", async () => {
    const config = await readPrivateJson<
      { source: { instanceId: string }; guest: GuestPolicy }
    >(
      ".private/backup-controller.json",
    );
    if (config.guest.host !== "codex@vps.pavlovcik.com") {
      throw Error("Unexpected guest host");
    }
    const result = await runner("ssh", [
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      "ConnectTimeout=10",
      "-o",
      "ServerAliveInterval=10",
      "-o",
      "ServerAliveCountMax=2",
      config.guest.host,
      "bash -c " + shellQuote(GUEST_OBSERVATION_COMMAND),
    ]);
    if (result.code !== 0) {
      // Retain the last good sample; the failed service and failure record do
      // not turn the previous sample into a fresh observation.
      await writePrivateJson(".private/reports/guest-telemetry-failure.json", {
        status: "GUEST_OBSERVATION_FAILED",
        observedAtUtc: new Date().toISOString(),
      });
      throw Error("Guest telemetry SSH observation failed");
    }
    const sample = parseGuestSample(
      result.stdout,
      config.source.instanceId,
      config.guest.rootUuid,
      new Date(),
    );
    let previous: GuestSample | undefined;
    try {
      previous =
        (await readPrivateJson<{ sample: GuestSample }>(REPORT)).sample;
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    const rate = guestNetworkRate(sample, previous);
    const record = {
      status: "GUEST_TELEMETRY_OBSERVED",
      sample,
      networkRate: rate,
      nativeOracleAgent: false,
      idlePolicyEvidence: false,
    };
    await Deno.mkdir(DIRECTORY, { recursive: true, mode: 0o700 });
    const date = sample.observedAtUtc.slice(0, 10);
    using file = await Deno.open(`${DIRECTORY}/${date}.jsonl`, {
      create: true,
      append: true,
      write: true,
      mode: 0o600,
    });
    const bytes = new TextEncoder().encode(JSON.stringify(record) + "\n");
    let offset = 0;
    while (offset < bytes.length) {
      offset += await file.write(bytes.subarray(offset));
    }
    await file.sync();
    await writePrivateJson(REPORT, record);
    // Nine UTC files cover seven complete days plus partial-day boundaries.
    const cutoff = new Date(Date.parse(date) - 8 * 86400000).toISOString()
      .slice(0, 10);
    for await (const entry of Deno.readDir(DIRECTORY)) {
      if (
        entry.isFile && /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(entry.name) &&
        entry.name.slice(0, 10) < cutoff
      ) {
        await Deno.remove(`${DIRECTORY}/${entry.name}`);
      }
    }
    console.log(JSON.stringify(record));
  });
}
if (import.meta.main) await main();
