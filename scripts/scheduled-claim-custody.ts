import { type CommandRunner, defaultRunner } from "./oci.ts";

export const CLAIM_PATH = ".private/backup-scheduled-window.json";
export const LEGACY_CLAIM_MIN_AGE_MS = 13 * 60 * 60 * 1000;
export const CLAIM_INCIDENT_AGE_MS = 24 * 60 * 60 * 1000;

export type ScheduledClaimCustodyStatus =
  | "SCHEDULED_CLAIM_OWNER_LIVE"
  | "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE"
  | "SCHEDULED_CLAIM_CUSTODY_OVERDUE";

export class ScheduledClaimCustodyError extends Error {
  constructor(readonly status: ScheduledClaimCustodyStatus) {
    super(status);
  }
}

export interface ScheduledClaimOwner {
  machineId: string;
  bootId: string;
  pid: number;
  startTicks: string;
  startedAtUtc: string;
  journalSuffix: string | null;
}

type OwnerState = "live" | "dead" | "unknown";

const MACHINE_ID = /^[0-9a-f]{32}$/;
const BOOT_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const START_TICKS = /^[1-9][0-9]{0,19}$/;
export const CYCLE_SUFFIX = /^\d{8}T\d{6}Z$/;

export function validateClaimOwner(owner: ScheduledClaimOwner): void {
  if (
    !owner || typeof owner.machineId !== "string" ||
    !MACHINE_ID.test(owner.machineId) || typeof owner.bootId !== "string" ||
    !BOOT_ID.test(owner.bootId) || !Number.isSafeInteger(owner.pid) ||
    owner.pid <= 0 || typeof owner.startTicks !== "string" ||
    !START_TICKS.test(owner.startTicks) ||
    typeof owner.startedAtUtc !== "string" ||
    !Number.isFinite(Date.parse(owner.startedAtUtc)) ||
    new Date(owner.startedAtUtc).toISOString() !== owner.startedAtUtc ||
    (owner.journalSuffix !== null &&
      (typeof owner.journalSuffix !== "string" ||
        !CYCLE_SUFFIX.test(owner.journalSuffix)))
  ) throw new ScheduledClaimCustodyError("SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
}

const READ_OWNER = [
  "set -eu",
  "machine=$(/usr/bin/cat /etc/machine-id)",
  "boot=$(/usr/bin/cat /proc/sys/kernel/random/boot_id)",
  'printf "%s\n%s\n" "$machine" "$boot"',
  'if entry=$(/usr/bin/cat "/proc/$1/stat" 2>/dev/null); then',
  '  printf "%s\n" "$entry"',
  'elif [ ! -e "/proc/$1" ] && [ -r /proc/self/stat ]; then',
  '  printf "absent\n"',
  "else",
  "  exit 1",
  "fi",
].join("\n");

async function observeProcess(
  pid: number,
  run: CommandRunner,
): Promise<
  { machineId: string; bootId: string; startTicks?: string; zombie?: boolean }
> {
  // Both existing Pi entry points permit subprocesses. Keep their filesystem
  // grants unchanged and pass only a validated numeric PID to the fixed read.
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error("Invalid PID");
  const result = await run("/bin/sh", [
    "-c",
    READ_OWNER,
    "claim-owner",
    `${pid}`,
  ]);
  const [machineId, bootId, ...lines] = result.stdout.trimEnd().split("\n");
  const stat = lines.join("\n");
  if (
    result.code !== 0 || !machineId || !MACHINE_ID.test(machineId) ||
    !bootId || !BOOT_ID.test(bootId)
  ) throw new Error("Controller process observation failed");
  if (stat === "absent") return { machineId, bootId };
  const endOfComm = stat.lastIndexOf(") ");
  const fields = stat.slice(endOfComm + 2).trim().split(/\s+/);
  const startTicks = fields[19];
  if (
    !stat.startsWith(`${pid} (`) || endOfComm < 0 ||
    !fields[0] || !/^[A-Za-z]$/.test(fields[0]) ||
    !startTicks || !START_TICKS.test(startTicks)
  ) throw new Error("Controller process stat is invalid");
  return { machineId, bootId, startTicks, zombie: /^[ZXx]$/.test(fields[0]) };
}

export async function currentClaimOwner(
  startedAtUtc: string,
  journalSuffix: string | null,
  run: CommandRunner = defaultRunner,
): Promise<ScheduledClaimOwner> {
  const pid = Deno.pid;
  try {
    const { machineId, bootId, startTicks, zombie } = await observeProcess(
      pid,
      run,
    );
    if (!startTicks || zombie) {
      throw new Error("Current controller not observed");
    }
    const owner = {
      machineId,
      bootId,
      pid,
      startTicks,
      startedAtUtc,
      journalSuffix,
    };
    validateClaimOwner(owner);
    return owner;
  } catch {
    throw new ScheduledClaimCustodyError("SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");
  }
}

export async function scheduledClaimOwnerState(
  owner: ScheduledClaimOwner,
  run: CommandRunner = defaultRunner,
): Promise<OwnerState> {
  try {
    validateClaimOwner(owner);
    const observed = await observeProcess(owner.pid, run);
    if (observed.machineId !== owner.machineId) return "unknown";
    if (
      observed.bootId !== owner.bootId ||
      observed.startTicks !== owner.startTicks || observed.zombie
    ) return "dead";
    return "live";
  } catch {
    return "unknown";
  }
}
