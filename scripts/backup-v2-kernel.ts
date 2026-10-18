/** Kernel metadata crosses bounded native commands, never Deno proc/sys IO.
 * An empty cgroup cannot prove that unrecorded escaped children are absent. */
import type { BackupV2ControllerObservation } from "./backup-v2-controller.ts";
import {
  type BackupV2Gate,
  validateBackupV2Gate,
} from "./backup-v2-runtime-contract.ts";
import type { BackupV2SupervisorIdentity } from "./backup-v2-supervisor.ts";
import { GATE_BACKUP_CGROUP_ROOT } from "./backblaze-controller-contract.ts";
import { backupV2ChildEnvironment } from "./backup-v2-supervisor.ts";
import { shellQuote } from "./backup-guest.ts";

const ROOT = "/sys/fs/cgroup";
const GROUP = ROOT + GATE_BACKUP_CGROUP_ROOT;
const UUID = "[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}";
const UNIT = new RegExp(
  `^arch-vps-b2-v2-(worker|verify|prune)-(${UUID})-(${UUID})\\.service$`,
);
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_PIDS = 4096, MAX_FDS = 4096, MAX_GROUPS = 128;
const COUNTERS = new Set([
  "cgroup.procs",
  "cgroup.events",
  "cpu.stat",
  "cpu.max",
  "cpu.weight",
  "memory.current",
  "memory.high",
  "memory.max",
  "memory.swap.max",
  "memory.events",
  "io.stat",
  "io.max",
  "io.pressure",
  "pids.current",
  "pids.max",
]);
export interface BackupV2KernelCommandResult {
  code: number;
  stdout: string;
  stderr: string;
  observerPid?: number;
}
export type BackupV2KernelCommand = (
  command: string,
  args: string[],
) => Promise<BackupV2KernelCommandResult>;
export class BackupV2KernelEvidenceError extends Error {
  constructor(
    readonly kind:
      | "ABSENT"
      | "UNREADABLE"
      | "BOUNDED"
      | "MALFORMED"
      | "CUSTODY",
  ) {
    super(`Backup kernel evidence ${kind.toLowerCase()}`);
  }
}
function fail(kind: BackupV2KernelEvidenceError["kind"]): never {
  throw new BackupV2KernelEvidenceError(kind);
}
function absent(error: unknown): boolean {
  return error instanceof BackupV2KernelEvidenceError &&
    error.kind === "ABSENT";
}
let commandsInFlight = 0, unsettledFailure = false;
/** Never signals a process. On a deadline/output failure close only our pipe
 * readers and retain unknown evidence until the owned command has settled.
 * The enclosing managed unit remains responsible for tree cancellation. */
export const realBackupV2KernelCommand: BackupV2KernelCommand = async (
  command,
  args,
) => {
  if (unsettledFailure || commandsInFlight >= 16) fail("BOUNDED");
  const child = new Deno.Command(command, {
    args,
    clearEnv: true,
    env: backupV2ChildEnvironment({
      PATH: "/usr/bin:/bin",
      LC_ALL: "C",
      LANG: "C",
    }),
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  commandsInFlight++;
  const output = child.stdout.getReader(), errors = child.stderr.getReader();
  const collect = async (
    reader: ReadableStreamDefaultReader<Uint8Array>,
    maximum: number,
  ) => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.length;
      if (total > maximum) fail("BOUNDED");
      chunks.push(item.value);
    }
    const bytes = new Uint8Array(total);
    let at = 0;
    for (const item of chunks) {
      bytes.set(item, at);
      at += item.length;
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  };
  const terminal = child.status.finally(() => {
    commandsInFlight--;
    if (commandsInFlight === 0) unsettledFailure = false;
  });
  const operation = Promise.all([
    collect(output, MAX_BYTES),
    collect(errors, 8192),
    terminal,
  ]);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const [stdout, stderr, status] = await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new BackupV2KernelEvidenceError("BOUNDED")),
          2000,
        );
      }),
    ]);
    return { code: status.code, stdout, stderr, observerPid: child.pid };
  } catch (error) {
    unsettledFailure = commandsInFlight > 0;
    void output.cancel().catch(() => {});
    void errors.cancel().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
};
function bounded(run: BackupV2KernelCommand): BackupV2KernelCommand {
  const start = performance.now();
  let count = 0, total = 0;
  return async (command, args) => {
    if (++count > 256 || performance.now() - start > 4000) fail("BOUNDED");
    const result = await run(command, args);
    if (
      new TextEncoder().encode(result.stdout).length > MAX_BYTES ||
      new TextEncoder().encode(result.stderr).length > 8192
    ) fail("BOUNDED");
    total += new TextEncoder().encode(result.stdout).length +
      new TextEncoder().encode(result.stderr).length;
    if (total > 8 * MAX_BYTES || performance.now() - start > 4000) {
      fail("BOUNDED");
    }
    return result;
  };
}
function result(value: BackupV2KernelCommandResult): string {
  if (value.code !== 0) {
    if (value.stderr.includes("No such file or directory")) fail("ABSENT");
    fail("UNREADABLE");
  }
  if (new TextEncoder().encode(value.stdout).length > MAX_BYTES) {
    fail("BOUNDED");
  }
  return value.stdout;
}
function pid(value: string | number): number {
  if (!/^[1-9][0-9]{0,9}$/.test(String(value)) || Number(value) > 2147483647) {
    fail("MALFORMED");
  }
  return Number(value);
}
function group(path: string): string {
  if (!path.startsWith(GATE_BACKUP_CGROUP_ROOT + "/") || path.length > 2048) {
    fail("CUSTODY");
  }
  const parts = path.slice(GATE_BACKUP_CGROUP_ROOT.length + 1).split("/");
  if (
    !UNIT.test(parts[0]) || parts.length > 33 ||
    parts.some((part) =>
      !/^[A-Za-z0-9_.:@-]{1,247}$/.test(part) || part === "." || part === ".."
    )
  ) fail("CUSTODY");
  return path;
}
function kernelPath(path: string): void {
  if (path === "/proc/sys/kernel/random/boot_id") return;
  const process = path.match(/^\/proc\/([1-9][0-9]{0,9})\/(stat|cgroup)$/);
  if (process) {
    pid(process[1]);
    return;
  }
  const slash = path.lastIndexOf("/"),
    directory = path.slice(0, slash),
    counter = path.slice(slash + 1);
  if (!COUNTERS.has(counter)) fail("CUSTODY");
  if ([ROOT, ROOT + "/weekly.slice", GROUP].includes(directory)) return;
  if (!directory.startsWith(ROOT)) fail("CUSTODY");
  group(directory.slice(ROOT.length));
}
export async function readBackupV2KernelText(
  path: string,
  run: BackupV2KernelCommand = realBackupV2KernelCommand,
): Promise<string> {
  kernelPath(path);
  return result(await bounded(run)("/usr/bin/cat", ["--", path]));
}
function fields(
  text: string,
  expectedPid: number,
): { start: string; parent: number } {
  if (!text.startsWith(`${expectedPid} (`)) fail("CUSTODY");
  const values = text.slice(text.lastIndexOf(")") + 2).trim().split(/\s+/);
  if (
    values.length < 20 || !/^[1-9][0-9]{0,19}$/.test(values[19]) ||
    !/^[0-9]+$/.test(values[1])
  ) fail("MALFORMED");
  return { start: values[19], parent: Number(values[1]) };
}
function lines(text: string): string[] {
  return text.trim() === "" ? [] : text.trim().split("\n");
}
async function pids(
  cgroup: string,
  run: BackupV2KernelCommand,
): Promise<number[]> {
  group(cgroup);
  const root = ROOT + cgroup;
  const dirs = result(
    await run("/usr/bin/find", [
      root,
      "-maxdepth",
      "32",
      "-type",
      "d",
      "-printf",
      "%P\\0",
    ]),
  ).split("\0");
  if (dirs.pop() !== "" || dirs.length > MAX_GROUPS || dirs[0] !== "") {
    fail("BOUNDED");
  }
  const found = new Set<number>();
  for (const directory of dirs) {
    if (directory && directory.split("/").length >= 32) fail("BOUNDED");
    const path = directory ? group(cgroup + "/" + directory) : cgroup;
    const response = await run("/usr/bin/cat", [
      "--",
      ROOT + path + "/cgroup.procs",
    ]);
    for (const value of lines(result(response))) {
      const current = pid(value);
      if (current !== response.observerPid) found.add(current);
      if (found.size > MAX_PIDS) fail("BOUNDED");
    }
  }
  return [...found].sort((a, b) => a - b);
}
function stats(
  text: string,
): { key: string; blocks: number; links: number; regular: boolean }[] {
  const records = text.split("\0");
  if (records.pop() !== "") fail("MALFORMED");
  return records.map((line) => {
    const [device, inode, blocks, links, type, ...extra] = line.split(":");
    if (
      extra.length ||
      ![device, inode, blocks, links].every((value) =>
        /^[0-9]{1,20}$/.test(value)
      )
    ) fail("MALFORMED");
    const allocated = Number(BigInt(blocks) * 512n), count = Number(links);
    if (!Number.isSafeInteger(allocated) || !Number.isSafeInteger(count)) {
      fail("BOUNDED");
    }
    return {
      key: `${device}:${inode}`,
      blocks: allocated,
      links: count,
      regular: type === "regular file" || type === "regular empty file",
    };
  });
}
/** File contents are never read. stat -L observes only blocks/inodes and
 * readlink emits NUL-separated FD targets, preserving arbitrary filenames. */
export async function backupV2DeletedHandleBytes(
  directory: string,
  cgroup: string,
  command: BackupV2KernelCommand = realBackupV2KernelCommand,
): Promise<
  { workspaceHeldDeletedBytes: number; sourceHeldDeletedBytes: number }
> {
  const pattern = new RegExp(
    `^/var/tmp/arch-vps-file-backup/generation-(${UUID})/v2-(${UUID})/[a-f0-9]{32}$`,
  );
  const workspace = pattern.exec(directory);
  if (!workspace) fail("CUSTODY");
  group(cgroup);
  const owner = UNIT.exec(
    cgroup.slice(GATE_BACKUP_CGROUP_ROOT.length + 1).split("/")[0],
  );
  if (!owner || workspace[1] !== owner[2] || workspace[2] !== owner[3]) {
    fail("CUSTODY");
  }
  const run = bounded(command),
    processes = await pids(cgroup, run),
    held = new Map<string, { bytes: number; workspace: boolean }>();
  for (const current of processes) {
    const before = result(
      await run("/usr/bin/cat", ["--", `/proc/${current}/stat`]),
    );
    const start = fields(before, current).start;
    const membership = result(
      await run("/usr/bin/cat", ["--", `/proc/${current}/cgroup`]),
    ).trim();
    if (
      membership !== `0::${cgroup}` && !membership.startsWith(`0::${cgroup}/`)
    ) fail("CUSTODY");
    const descriptors = result(
      await run("/usr/bin/find", [
        `/proc/${current}/fd`,
        "-mindepth",
        "1",
        "-maxdepth",
        "1",
        "-printf",
        "%f\\0",
      ]),
    ).split("\0");
    if (
      descriptors.pop() !== "" || descriptors.length > MAX_FDS ||
      descriptors.some((fd) => !/^[0-9]{1,10}$/.test(fd))
    ) fail("BOUNDED");
    if (descriptors.length === 0) {
      if (
        fields(
          result(await run("/usr/bin/cat", ["--", `/proc/${current}/stat`])),
          current,
        ).start !== start
      ) fail("CUSTODY");
      continue;
    }
    const paths = descriptors.map((fd) => `/proc/${current}/fd/${fd}`);
    const statArgs = ["-L", "--printf=%d:%i:%b:%h:%F\\0", "--", ...paths];
    const first = stats(result(await run("/usr/bin/stat", statArgs)));
    const targets = result(
      await run("/usr/bin/readlink", ["-z", "--", ...paths]),
    ).split("\0");
    if (
      targets.pop() !== "" || targets.length !== descriptors.length ||
      first.length !== descriptors.length
    ) fail("MALFORMED");
    const after = stats(result(await run("/usr/bin/stat", statArgs)));
    if (
      after.length !== first.length ||
      fields(
          result(await run("/usr/bin/cat", ["--", `/proc/${current}/stat`])),
          current,
        ).start !== start
    ) fail("CUSTODY");
    for (let index = 0; index < first.length; index++) {
      const info = after[index];
      if (!info.regular || info.links !== 0) continue;
      if (first[index].key !== info.key || !first[index].regular) {
        fail("CUSTODY");
      }
      const workspace = targets[index].startsWith(directory + "/");
      const prior = held.get(info.key);
      if (prior && prior.bytes !== info.blocks) fail("CUSTODY");
      held.set(info.key, {
        bytes: info.blocks,
        workspace: workspace || prior?.workspace === true,
      });
    }
  }
  const after = await pids(cgroup, run);
  if (JSON.stringify(after) !== JSON.stringify(processes)) fail("CUSTODY");
  let workspaceHeldDeletedBytes = 0, sourceHeldDeletedBytes = 0;
  for (const value of held.values()) {
    if (value.workspace) workspaceHeldDeletedBytes += value.bytes;
    else sourceHeldDeletedBytes += value.bytes;
  }
  if (
    ![workspaceHeldDeletedBytes, sourceHeldDeletedBytes].every(
      Number.isSafeInteger,
    )
  ) fail("BOUNDED");
  return { workspaceHeldDeletedBytes, sourceHeldDeletedBytes };
}
function properties(text: string): Record<string, string> {
  return Object.fromEntries(
    lines(text).map((line) => {
      const index = line.indexOf("=");
      if (index < 1) fail("MALFORMED");
      return [line.slice(0, index), line.slice(index + 1)];
    }),
  );
}
async function lockFree(
  gate: BackupV2Gate,
  run: BackupV2KernelCommand,
): Promise<boolean | null> {
  try {
    const args = ["--printf=%d:%i:%u:%a:%h:%F", "--", gate.sourceLockPath];
    const before = result(await run("/usr/bin/stat", args));
    if (!/^[0-9]+:[0-9]+:0:600:1:regular (?:empty )?file$/.test(before)) {
      return null;
    }
    const value = await run("/bin/sh", [
      "-c",
      `exec 3<${shellQuote(gate.sourceLockPath)}\n/usr/bin/flock -n 3`,
    ]);
    if (before !== result(await run("/usr/bin/stat", args))) return null;
    return value.code === 0 ? true : value.code === 1 ? false : null;
  } catch {
    return null;
  }
}
/** Tree facts that need complete child/namespace custody stay null until the
 * producer publishes that exact gate-bound record. No host-wide argv scan. */
export async function observeBackupV2Kernel(
  gateInput: BackupV2Gate,
  command: BackupV2KernelCommand = realBackupV2KernelCommand,
): Promise<Omit<BackupV2ControllerObservation, "status" | "resultBytes">> {
  const gate = validateBackupV2Gate(gateInput), run = bounded(command);
  const sourceBootId = result(
    await run("/usr/bin/cat", ["--", "/proc/sys/kernel/random/boot_id"]),
  ).trim();
  if (!new RegExp(`^${UUID}$`).test(sourceBootId)) fail("MALFORMED");
  const response = await run("/usr/bin/systemctl", [
    "show",
    gate.unitName,
    "--no-pager",
    "--property=LoadState,ActiveState,SubState,Result,MainPID,ControlPID,ControlGroup,InvocationID",
  ]);
  const props = properties(response.stdout);
  if (response.code !== 0 && props.LoadState !== "not-found") {
    fail("UNREADABLE");
  }
  const unit = props.LoadState === "not-found"
    ? "ABSENT"
    : props.ActiveState === "failed"
    ? "FAILED"
    : props.ActiveState === "active" && props.SubState === "exited"
    ? "EXITED"
    : props.ActiveState === "active"
    ? "RUNNING"
    : "STARTING";
  const unknown = { sourceBootId, unit, identity: null, tree: null } as const;
  if (sourceBootId !== gate.sourceBootId || unit === "ABSENT") return unknown;
  if (!/^[0-9]+$/.test(props.MainPID) || !/^[0-9]+$/.test(props.ControlPID)) {
    fail("MALFORMED");
  }
  const mainPid = Number(props.MainPID),
    controlPid = Number(props.ControlPID),
    cgroup = `${GATE_BACKUP_CGROUP_ROOT}/${gate.unitName}`;
  let identity: BackupV2SupervisorIdentity | null = null;
  if (controlPid > 0) pid(controlPid);
  if (mainPid > 0) {
    pid(mainPid);
    const start = fields(
      result(await run("/usr/bin/cat", ["--", `/proc/${mainPid}/stat`])),
      mainPid,
    ).start;
    const membership = result(
      await run("/usr/bin/cat", ["--", `/proc/${mainPid}/cgroup`]),
    ).trim();
    if (membership !== `0::${cgroup}` || props.ControlGroup !== cgroup) {
      fail("CUSTODY");
    }
    identity = {
      unitName: gate.unitName,
      invocationId: props.InvocationID,
      mainPid,
      mainStartTicks: start,
      cgroup,
    };
    validateBackupV2Gate({ ...gate, state: "ACTIVE", custody: identity });
  } else if (
    gate.custody && props.LoadState === "loaded" &&
    props.InvocationID === gate.custody.invocationId &&
    ["EXITED", "FAILED"].includes(unit)
  ) identity = gate.custody;
  if (!identity) return unknown;
  let descendants: number | null = null, cgroupPopulated: boolean | null = null;
  try {
    descendants = (await pids(cgroup, run)).length;
    const events = result(
      await run("/usr/bin/cat", ["--", ROOT + cgroup + "/cgroup.events"]),
    );
    const values = [...events.matchAll(/^populated ([01])$/gm)];
    if (values.length === 1) cgroupPopulated = values[0][1] === "1";
    if (cgroupPopulated === true && descendants === 0) descendants = null;
  } catch (error) {
    descendants = null;
    // Only exact retained successful terminal custody permits original group
    // absence to prove an empty tree; missing/unreadable alone stays unknown.
    if (
      absent(error) && unit === "EXITED" && props.Result === "success" &&
      props.InvocationID === identity.invocationId && mainPid === 0 &&
      controlPid === 0
    ) {
      try {
        result(
          await run("/usr/bin/stat", ["--printf=%F", "--", ROOT + cgroup]),
        );
      } catch (missing) {
        if (absent(missing)) {
          descendants = 0;
          cgroupPopulated = false;
        }
      }
    }
  }
  return {
    sourceBootId,
    unit,
    identity,
    tree: {
      identity,
      observedMonotonicMs: performance.now(),
      mainPid,
      controlPid,
      cgroupPopulated,
      descendants,
      escapedProcesses: null,
      namespaceReferences: null,
      openPipelineHandles: null,
      pendingOperations: null,
      sourceLockFree: await lockFree(gate, run),
    },
  };
}
