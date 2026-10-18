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
import {
  BACKUP_V2_NATIVE_CUSTODY_FILE,
  type BackupV2NativeCustody,
  parseBackupV2NativeCustody,
  validateBackupV2NativeCustodyRecord,
} from "./backup-v2-native-custody.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";

const ROOT = "/sys/fs/cgroup";
const GROUP = ROOT + GATE_BACKUP_CGROUP_ROOT;
const UUID = "[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}";
const UNIT = new RegExp(
  `^arch-vps-b2-v2-(worker|verify|prune)-(${UUID})-(${UUID})\\.service$`,
);
const MAX_BYTES = 2 * 1024 * 1024;
const JOURNAL_PATH = new RegExp(
  `^/var/tmp/arch-vps-file-backup/generation-${UUID}/v2-${UUID}/[a-f0-9]{32}/${
    BACKUP_V2_NATIVE_CUSTODY_FILE.replaceAll(".", "\\.")
  }$`,
);
export interface BackupV2KernelObservation
  extends Omit<BackupV2ControllerObservation, "status" | "resultBytes"> {
  nativeCustodySha256: string | null;
  managerNamespaceReferences: number | null;
}
export interface BackupV2KernelRetainedTerminalProof {
  gate: BackupV2Gate;
  observation: BackupV2KernelObservation;
  resultSha256: string | null;
  exactStop: {
    unitName: string;
    invocationId: string;
    sourceBootId: string;
    completed: true;
  };
}
export interface BackupV2KernelObservationOptions {
  expectedCustodySha256?: string;
  retainedTerminalProof?: BackupV2KernelRetainedTerminalProof;
  cancellationStopProof?: BackupV2KernelCancellationStopProof;
}
export interface BackupV2KernelCancellationStopProof {
  /** Process settlement only. Cloud intents and missing exit outcomes remain
   * unchanged and must be reconciled independently before any acceptance. */
  gate: BackupV2Gate;
  observation: Pick<
    BackupV2KernelObservation,
    "sourceBootId" | "unit" | "identity" | "tree"
  >;
  exactStop: BackupV2KernelRetainedTerminalProof["exactStop"] & { code: 0 };
}
function outputLimit(command: string, args: string[]): number {
  return command === "/usr/bin/cat" && JOURNAL_PATH.test(args.at(-1) ?? "")
    ? BACKUP_V2_LIMITS.journalBytes
    : MAX_BYTES;
}
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
    collect(output, outputLimit(command, args)),
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
function bounded(
  run: BackupV2KernelCommand,
  duration = 4000,
  calls = 256,
  maximum = 8 * MAX_BYTES,
): BackupV2KernelCommand {
  const start = performance.now();
  let count = 0, total = 0;
  return async (command, args) => {
    if (++count > calls || performance.now() - start > duration) {
      fail("BOUNDED");
    }
    const result = await run(command, args);
    if (
      new TextEncoder().encode(result.stdout).length >
        outputLimit(command, args) ||
      new TextEncoder().encode(result.stderr).length > 8192
    ) fail("BOUNDED");
    total += new TextEncoder().encode(result.stdout).length +
      new TextEncoder().encode(result.stderr).length;
    if (total > maximum || performance.now() - start > duration) {
      fail("BOUNDED");
    }
    return result;
  };
}
function result(
  value: BackupV2KernelCommandResult,
  maximum = MAX_BYTES,
): string {
  if (value.code !== 0) {
    if (value.stderr.includes("No such file or directory")) fail("ABSENT");
    fail("UNREADABLE");
  }
  if (new TextEncoder().encode(value.stdout).length > maximum) {
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
  // Child exit and our bounded metadata readers can change a live census.
  // Start over with fresh facts, sharing one original time/call/byte budget;
  // exhausted or unreadable observations never become an accounting zero.
  const run = bounded(command),
    changed = new BackupV2KernelEvidenceError("CUSTODY");
  for (let attempt = 0;; attempt++) {
    let processes: number[] | undefined;
    try {
      processes = await pids(cgroup, run);
      const held = new Map<string, { bytes: number; workspace: boolean }>();
      for (const current of processes) {
        const before = result(
          await run("/usr/bin/cat", ["--", `/proc/${current}/stat`]),
        );
        const start = fields(before, current).start;
        const membership = result(
          await run("/usr/bin/cat", ["--", `/proc/${current}/cgroup`]),
        ).trim();
        if (
          membership !== `0::${cgroup}` &&
          !membership.startsWith(`0::${cgroup}/`)
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
              result(
                await run("/usr/bin/cat", ["--", `/proc/${current}/stat`]),
              ),
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
              result(
                await run("/usr/bin/cat", ["--", `/proc/${current}/stat`]),
              ),
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
      if (JSON.stringify(after) !== JSON.stringify(processes)) throw changed;
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
    } catch (error) {
      if (attempt >= 2) throw error;
      if (error !== changed && !absent(error)) {
        // readlink may report only exit 1 when its process vanishes. A fresh
        // changed PID list proves that race; ordinary permission failures stay
        // unknown rather than being ignored or repeatedly sampled as zero.
        if (
          !processes || !(error instanceof BackupV2KernelEvidenceError) ||
          error.kind !== "UNREADABLE" ||
          JSON.stringify(await pids(cgroup, run)) === JSON.stringify(processes)
        ) throw error;
      }
    }
  }
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
const digest = async (text: string) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
async function privateArtifact(
  path: string,
  run: BackupV2KernelCommand,
  maximum: number,
  contents = false,
): Promise<{ sha256: string; text: string }> {
  const parent = path.slice(0, path.lastIndexOf("/"));
  if (
    result(await run("/usr/bin/readlink", ["-e", "--", parent])).trim() !==
      parent ||
    result(await run("/usr/bin/stat", ["--printf=%u:%a:%F", "--", parent])) !==
      "0:700:directory"
  ) fail("CUSTODY");
  const args = ["--printf=%d:%i:%u:%a:%h:%s:%F", "--", path];
  const before = result(await run("/usr/bin/stat", args)),
    fields = before.split(":");
  if (
    fields.length !== 7 || fields[2] !== "0" || fields[3] !== "600" ||
    fields[4] !== "1" || !/^[0-9]+$/.test(fields[5]) || Number(fields[5]) < 1 ||
    Number(fields[5]) > maximum || fields[6] !== "regular file"
  ) fail("CUSTODY");
  const text = contents
    ? result(await run("/usr/bin/cat", ["--", path]), maximum)
    : "";
  const hash = result(await run("/usr/bin/sha256sum", ["--", path]));
  if (
    !/^[a-f0-9]{64} {2}/.test(hash) || hash.slice(66).trim() !== path ||
    before !== result(await run("/usr/bin/stat", args))
  ) fail("CUSTODY");
  const sha256 = hash.slice(0, 64);
  if (
    contents &&
    (new TextEncoder().encode(text).length !== Number(fields[5]) ||
      await digest(text) !== sha256)
  ) fail("CUSTODY");
  return { sha256, text };
}
function sameIdentity(
  a: BackupV2SupervisorIdentity,
  b: BackupV2SupervisorIdentity,
): boolean {
  return ([
    "unitName",
    "invocationId",
    "mainPid",
    "mainStartTicks",
    "cgroup",
  ] as const).every((key) => a[key] === b[key]);
}
function retained(
  gate: BackupV2Gate,
  options: BackupV2KernelObservationOptions,
): BackupV2KernelRetainedTerminalProof | null {
  const proof = options.retainedTerminalProof;
  if (!proof || !gate.custody) return null;
  validateBackupV2NativeCustodyRecord({
    type: "BOUND",
    schemaVersion: 1,
    gate: proof.gate,
  }, gate);
  const before = proof.observation, tree = before.tree, stop = proof.exactStop;
  if (
    before.sourceBootId !== gate.sourceBootId ||
    !["EXITED", "FAILED"].includes(before.unit) || !before.identity ||
    !sameIdentity(before.identity, gate.custody) || !tree ||
    !sameIdentity(tree.identity, gate.custody) || tree.mainPid !== 0 ||
    tree.controlPid !== 0 || tree.descendants !== 0 ||
    tree.cgroupPopulated !== false || tree.escapedProcesses !== 0 ||
    tree.openPipelineHandles !== 0 || tree.pendingOperations !== 0 ||
    tree.sourceLockFree !== true ||
    !Number.isSafeInteger(tree.namespaceReferences) ||
    tree.namespaceReferences! < 0 ||
    before.managerNamespaceReferences !== tree.namespaceReferences ||
    !/^[a-f0-9]{64}$/.test(before.nativeCustodySha256 ?? "") ||
    options.expectedCustodySha256 !== undefined &&
      options.expectedCustodySha256 !== before.nativeCustodySha256 ||
    proof.resultSha256 !== null && !/^[a-f0-9]{64}$/.test(proof.resultSha256) ||
    before.unit === "EXITED" && proof.resultSha256 === null ||
    stop.completed !== true || stop.unitName !== gate.unitName ||
    stop.invocationId !== gate.custody.invocationId ||
    stop.sourceBootId !== gate.sourceBootId
  ) fail("CUSTODY");
  return proof;
}
function numbers(text: string, descriptors = false): number[] {
  const values = text.split("\0");
  if (values.pop() !== "" || values.length > MAX_PIDS) fail("BOUNDED");
  return [
    ...new Set(
      values.map((value) => descriptors && value === "0" ? 0 : pid(value)),
    ),
  ];
}
function cancellation(
  gate: BackupV2Gate,
  options: BackupV2KernelObservationOptions,
): BackupV2KernelCancellationStopProof | null {
  const proof = options.cancellationStopProof;
  if (!proof) return null;
  if (options.retainedTerminalProof || !gate.custody) fail("CUSTODY");
  validateBackupV2NativeCustodyRecord({
    type: "BOUND",
    schemaVersion: 1,
    gate: proof.gate,
  }, gate);
  const before = proof.observation, tree = before.tree, stop = proof.exactStop;
  if (
    before.sourceBootId !== gate.sourceBootId ||
    !["RUNNING", "STARTING", "EXITED", "FAILED"].includes(before.unit) ||
    !before.identity || !sameIdentity(before.identity, gate.custody) || !tree ||
    !sameIdentity(tree.identity, gate.custody) ||
    ![0, gate.custody.mainPid].includes(tree.mainPid) ||
    ["RUNNING", "STARTING"].includes(before.unit) &&
      tree.mainPid !== gate.custody.mainPid ||
    stop.completed !== true || stop.code !== 0 ||
    stop.unitName !== gate.unitName ||
    stop.invocationId !== gate.custody.invocationId ||
    stop.sourceBootId !== gate.sourceBootId
  ) fail("CUSTODY");
  return proof;
}
async function namespaceId(
  path: string,
  run: BackupV2KernelCommand,
): Promise<string> {
  const value = result(
    await run("/usr/bin/stat", ["-L", "--printf=%d:%i", "--", path]),
  );
  if (!/^[0-9]{1,20}:[1-9][0-9]{0,19}$/.test(value)) fail("MALFORMED");
  return value;
}
async function namespaceCensus(
  privateIds: Set<string>,
  allPids: number[],
  run: BackupV2KernelCommand,
): Promise<{ references: number; manager: number }> {
  let references = 0, manager = 0;
  for (const current of allPids) {
    try {
      if (privateIds.has(await namespaceId(`/proc/${current}/ns/mnt`, run))) {
        references++;
      }
      const found = result(
        await run("/usr/bin/find", [
          `/proc/${current}/fd`,
          "-mindepth",
          "1",
          "-maxdepth",
          "1",
          "-type",
          "l",
          "-lname",
          "mnt:[[]*[]]",
          "-printf",
          "%f\\0",
        ]),
      );
      const fds = numbers(found, true);
      if (fds.length > MAX_FDS) fail("BOUNDED");
      for (const fd of fds) {
        if (
          privateIds.has(await namespaceId(`/proc/${current}/fd/${fd}`, run))
        ) {
          references++;
          if (current === 1) manager++;
        }
      }
    } catch (error) {
      if (!absent(error)) throw error;
    }
  }
  return { references, manager };
}
interface CustodyFacts {
  hash: string | null;
  escaped: number | null;
  namespaces: number | null;
  manager: number | null;
  handles: number | null;
  pending: number | null;
  mainGone: boolean;
}
async function custodyFacts(
  gate: BackupV2Gate,
  identity: BackupV2SupervisorIdentity,
  descendants: number | null,
  command: BackupV2KernelCommand,
  options: BackupV2KernelObservationOptions,
  proof: BackupV2KernelRetainedTerminalProof | null,
  cancelled = false,
): Promise<CustodyFacts> {
  const facts: CustodyFacts = {
    hash: null,
    escaped: null,
    namespaces: null,
    manager: null,
    handles: null,
    pending: null,
    mainGone: false,
  };
  if (!gate.custody || !sameIdentity(gate.custody, identity)) return facts;
  try {
    const directory = (await import("./backup-v2-worker.ts"))
        .backupV2GateDirectory(gate),
      path = `${directory}/${BACKUP_V2_NATIVE_CUSTODY_FILE}`;
    const artifact = await privateArtifact(
        path,
        command,
        BACKUP_V2_LIMITS.journalBytes,
        true,
      ),
      expected = options.expectedCustodySha256 ??
        proof?.observation.nativeCustodySha256;
    if (
      expected !== undefined &&
      (!/^[a-f0-9]{64}$/.test(expected ?? "") || expected !== artifact.sha256)
    ) fail("CUSTODY");
    const journal: BackupV2NativeCustody = parseBackupV2NativeCustody(
      new TextEncoder().encode(artifact.text),
      gate,
    );
    facts.hash = artifact.sha256;
    if (
      proof?.resultSha256 !== null && proof?.resultSha256 !== undefined &&
      (await privateArtifact(`${directory}/result.json`, command, MAX_BYTES))
          .sha256 !== proof.resultSha256
    ) fail("CUSTODY");
    const enumerated = await command("/usr/bin/find", [
      "/proc",
      "-mindepth",
      "1",
      "-maxdepth",
      "1",
      "-type",
      "d",
      "-regex",
      "/proc/[1-9][0-9]*",
      "-printf",
      "%f\\0",
    ]);
    const allPids = numbers(result(enumerated)).filter((current) =>
        current !== enumerated.observerPid
      ),
      present = new Set(allPids);
    const known = [{
      identity: { pid: identity.mainPid, startTicks: identity.mainStartTicks },
      exit: null,
    }, ...journal.children];
    const live = new Set<number>();
    let escaped = 0, handles = 0, complete = true;
    for (let at = 0; at < known.length; at++) {
      const entry = known[at];
      let exists = false;
      if (present.has(entry.identity.pid) || cancelled) {
        try {
          exists = fields(
            result(
              await command("/usr/bin/cat", [
                "--",
                `/proc/${entry.identity.pid}/stat`,
              ]),
            ),
            entry.identity.pid,
          ).start === entry.identity.startTicks;
        } catch (error) {
          if (!absent(error)) throw error;
        }
      }
      if (at === 0) facts.mainGone = !exists;
      if (!exists) {
        if (at !== 0 && !entry.exit && !cancelled) complete = false;
        continue;
      }
      if (entry.exit) complete = false;
      live.add(entry.identity.pid);
      const member = result(
        await command("/usr/bin/cat", [
          "--",
          `/proc/${entry.identity.pid}/cgroup`,
        ]),
      ).trim();
      if (
        member !== `0::${identity.cgroup}` &&
        !member.startsWith(`0::${identity.cgroup}/`)
      ) escaped++;
      const fds = result(
        await command("/usr/bin/find", [
          `/proc/${entry.identity.pid}/fd`,
          "-mindepth",
          "1",
          "-maxdepth",
          "1",
          "-type",
          "l",
          "(",
          "-lname",
          "pipe:[[]*[]]",
          "-o",
          "-lname",
          "socket:[[]*[]]",
          "-o",
          "-lname",
          `${directory}/*`,
          ")",
          "-printf",
          "%f\\0",
        ]),
      );
      handles += numbers(fds, true).length;
      if (
        fields(
          result(
            await command("/usr/bin/cat", [
              "--",
              `/proc/${entry.identity.pid}/stat`,
            ]),
          ),
          entry.identity.pid,
        ).start !== entry.identity.startTicks
      ) fail("CUSTODY");
    }
    let groupMembers: number[] = [];
    try {
      groupMembers = await pids(identity.cgroup, command);
    } catch (error) {
      if (!(absent(error) && descendants === 0)) throw error;
    }
    if (groupMembers.some((current) => !live.has(current))) complete = false;
    if (
      !complete || !journal.mounts.some((mount) => mount.scope === "UNIT") ||
      journal.unresolvedNamespaceLeaders.length
    ) return facts;
    facts.escaped = escaped;
    facts.handles = handles;
    if (
      facts.mainGone && live.size === 0 && descendants === 0 &&
      (cancelled || journal.children.every((child) => child.exit !== null))
    ) facts.pending = 0;
    const host = await namespaceId("/proc/1/ns/mnt", command);
    if (
      journal.mounts.some((mount) =>
        `${mount.hostDevice}:${mount.hostInode}` !== host
      )
    ) return facts;
    const privateIds = new Set(
      journal.mounts.filter((mount) =>
        `${mount.device}:${mount.inode}` !== host
      ).map((mount) => `${mount.device}:${mount.inode}`),
    );
    for (const mount of journal.mounts) {
      if (
        live.has(mount.leader.pid) &&
        await namespaceId(`/proc/${mount.leader.pid}/ns/mnt`, command) !==
          `${mount.device}:${mount.inode}`
      ) return { ...facts, namespaces: null, manager: null };
    }
    if (privateIds.size === 0) {
      if (
        journal.noPrivateMountProved ||
        cancelled && facts.mainGone && live.size === 0 && descendants === 0 &&
          journal.children.length === 0 && journal.mounts.length === 1 &&
          journal.mounts[0].scope === "UNIT"
      ) {
        facts.namespaces = 0;
        facts.manager = 0;
      }
    } else {
      const census = await namespaceCensus(privateIds, allPids, command);
      facts.namespaces = census.references;
      facts.manager = census.manager;
    }
    // Recheck the same root-owned bytes after the census; a live append can
    // never turn a partial snapshot into a complete terminal proof.
    if (
      (await privateArtifact(path, command, BACKUP_V2_LIMITS.journalBytes))
        .sha256 !== artifact.sha256
    ) fail("CUSTODY");
    return facts;
  } catch {
    return {
      ...facts,
      escaped: null,
      namespaces: null,
      manager: null,
      handles: null,
      pending: null,
    };
  }
}
/** Tree facts that need complete child/namespace custody stay null until the
 * producer publishes that exact gate-bound record. No host-wide argv scan. */
export async function observeBackupV2Kernel(
  gateInput: BackupV2Gate,
  command: BackupV2KernelCommand = realBackupV2KernelCommand,
  options: BackupV2KernelObservationOptions = {},
): Promise<BackupV2KernelObservation> {
  const gate = validateBackupV2Gate(gateInput),
    run = bounded(
      command,
      20_000,
      16_384,
      2 * BACKUP_V2_LIMITS.journalBytes + 8 * MAX_BYTES,
    ),
    proof = retained(gate, options),
    cancelled = cancellation(gate, options),
    stopped = proof !== null || cancelled !== null;
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
  const unit = props.LoadState === "not-found" ||
      stopped && props.LoadState === "loaded" &&
        props.MainPID === "0" && props.ControlPID === "0" &&
        (props.ActiveState === "inactive" && props.SubState === "dead" ||
          cancelled !== null && props.ActiveState === "failed" &&
            props.SubState === "failed" &&
            props.InvocationID === gate.custody?.invocationId)
    ? "ABSENT"
    : props.ActiveState === "failed"
    ? "FAILED"
    : props.ActiveState === "active" && props.SubState === "exited"
    ? "EXITED"
    : props.ActiveState === "active"
    ? "RUNNING"
    : "STARTING";
  const unknown = {
    sourceBootId,
    unit,
    identity: null,
    tree: null,
    nativeCustodySha256: null,
    managerNamespaceReferences: null,
  } as const;
  if (
    sourceBootId !== gate.sourceBootId || unit === "ABSENT" && !stopped ||
    stopped && props.InvocationID &&
      props.InvocationID !== gate.custody?.invocationId
  ) {
    return unknown;
  }
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
  else if (unit === "ABSENT" && stopped) identity = gate.custody;
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
      absent(error) &&
      (unit === "EXITED" && props.Result === "success" &&
          props.InvocationID === identity.invocationId ||
        unit === "ABSENT" && stopped) &&
      mainPid === 0 &&
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
  const facts = await custodyFacts(
    gate,
    identity,
    descendants,
    run,
    options,
    proof,
    cancelled !== null,
  );
  if (
    unit === "ABSENT" &&
    (!facts.mainGone || !facts.hash ||
      proof !== null && facts.hash !== proof.observation.nativeCustodySha256)
  ) return unknown;
  return {
    sourceBootId,
    unit,
    identity,
    nativeCustodySha256: facts.hash,
    managerNamespaceReferences: facts.manager,
    tree: {
      identity,
      observedMonotonicMs: performance.now(),
      mainPid,
      controlPid,
      cgroupPopulated,
      descendants,
      escapedProcesses: facts.escaped,
      namespaceReferences: facts.namespaces,
      openPipelineHandles: facts.handles,
      pendingOperations: facts.pending,
      sourceLockFree: await lockFree(gate, run),
    },
  };
}
