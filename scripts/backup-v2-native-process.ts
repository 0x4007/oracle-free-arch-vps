/** A registered PID waits for START; binary stdin is exposed only after ACK. */
import {
  type BackupV2NativeChild,
  type BackupV2NativeCustodyRecord,
  type BackupV2NativeKind,
  backupV2NativeMain,
  validateBackupV2NativeCustodyRecord,
} from "./backup-v2-native-custody.ts";
import {
  type BackupV2KernelCommand,
  readBackupV2KernelText,
  realBackupV2KernelCommand,
} from "./backup-v2-kernel.ts";
import {
  type BackupV2Gate,
  validateBackupV2Gate,
} from "./backup-v2-runtime-contract.ts";
import { backupV2ChildEnvironment } from "./backup-v2-supervisor.ts";

const encoder = new TextEncoder();
const ACK = encoder.encode("BACKUP_V2_START_ACK\n");
export const BACKUP_V2_NATIVE_START_SCRIPT =
  'IFS= read -r start && test "$start" = START || exit 78; printf "BACKUP_V2_START_ACK\\n" >&2; exec "$@"';
export interface BackupV2NativeExit {
  code: number;
  signal?: string | null;
}
export interface BackupV2RegisteredChild {
  identity: BackupV2NativeChild;
  exit(status: BackupV2NativeExit): Promise<void>;
}
export type BackupV2NativeRawChild =
  & Pick<
    Deno.ChildProcess,
    "pid" | "stdin" | "status" | "kill"
  >
  & {
    stdout: ReadableStream<Uint8Array>;
    stderr: ReadableStream<Uint8Array>;
  };
export interface BackupV2TrackedProcess extends BackupV2NativeRawChild {
  identity: BackupV2NativeChild;
}
export type BackupV2NativeSpawn = (
  kind: Exclude<BackupV2NativeKind, "main">,
  command: string,
  args: string[],
  options?: Deno.CommandOptions,
) => Promise<BackupV2TrackedProcess>;
function fail(): never {
  throw new Error("Backup v2 native process custody incomplete");
}
function startTicks(stat: string, pid: number): string {
  if (!stat.startsWith(`${pid} (`)) fail();
  const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
  if (!/^[1-9][0-9]{0,19}$/.test(fields[19] ?? "")) fail();
  return fields[19];
}
async function acknowledge(stream: ReadableStream<Uint8Array>) {
  const reader = stream.getReader();
  let matched = 0, pending = new Uint8Array(0);
  try {
    while (matched < ACK.length) {
      const next = await reader.read();
      if (next.done) fail();
      let at = 0;
      while (at < next.value.length && matched < ACK.length) {
        if (next.value[at++] !== ACK[matched++]) fail();
      }
      pending = next.value.slice(at);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
    throw error;
  }
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        if (pending.length) {
          controller.enqueue(pending);
          pending = new Uint8Array(0);
          return;
        }
        const next = await reader.read();
        if (next.done) {
          reader.releaseLock();
          controller.close();
        } else controller.enqueue(next.value);
      } catch (error) {
        reader.releaseLock();
        controller.error(error);
      }
    },
    async cancel() {
      await reader.cancel();
      reader.releaseLock();
    },
  }, { highWaterMark: 0 });
}

export function createBackupV2NativeProcessStarter(options: {
  gate: BackupV2Gate;
  /** Resolves only after this validated record and its journal are fsynced. */
  append(record: BackupV2NativeCustodyRecord): Promise<void>;
  /** Caller owns cancellation and complete managed-tree settlement. */
  cancel(reason: unknown): Promise<void>;
  run?: BackupV2KernelCommand;
  launch?: (
    command: string,
    options: Deno.CommandOptions,
  ) => BackupV2NativeRawChild;
}) {
  const gate = validateBackupV2Gate(options.gate);
  if (!gate.custody) fail();
  const run = options.run ?? realBackupV2KernelCommand;
  const launch = options.launch ??
    ((command, options) => new Deno.Command(command, options).spawn());
  const registered = new Map<number, BackupV2RegisteredChild>();
  let writes: Promise<void> = Promise.resolve();
  const append = (record: BackupV2NativeCustodyRecord) => {
    const checked = validateBackupV2NativeCustodyRecord(record, gate);
    const next = writes.then(() => options.append(checked));
    writes = next;
    next.catch(() => {});
    return next;
  };
  const observe = async (pid: number, kind: BackupV2NativeKind) => {
    if (!Number.isSafeInteger(pid) || pid < 1) fail();
    const before = startTicks(
      await readBackupV2KernelText(`/proc/${pid}/stat`, run),
      pid,
    );
    const [boot, group] = await Promise.all([
      readBackupV2KernelText("/proc/sys/kernel/random/boot_id", run),
      readBackupV2KernelText(`/proc/${pid}/cgroup`, run),
    ]);
    const match = /^0::([^\n]+)\n?$/.exec(group);
    if (
      !match || before !== startTicks(
          await readBackupV2KernelText(`/proc/${pid}/stat`, run),
          pid,
        )
    ) fail();
    return {
      pid,
      startTicks: before,
      bootId: boot.trim(),
      cgroup: match[1],
      kind,
    };
  };
  const registerChild = async (
    pid: number,
    kind: Exclude<BackupV2NativeKind, "main">,
  ): Promise<BackupV2RegisteredChild> => {
    if (registered.has(pid)) fail();
    const identity = await observe(pid, kind);
    await append({ type: "CHILD", identity });
    if (
      identity.cgroup !== gate.custody!.cgroup &&
      !identity.cgroup.startsWith(gate.custody!.cgroup + "/")
    ) fail();
    let exited = false;
    const child = {
      identity,
      async exit(status: BackupV2NativeExit) {
        if (exited) fail();
        exited = true;
        await append({
          type: "EXIT",
          identity,
          code: status.code,
          signal: status.signal ?? null,
        });
      },
    };
    registered.set(pid, child);
    return child;
  };
  const namespace = async (pid: number) => {
    const result = await run("/usr/bin/stat", [
      "-Lc",
      "%d %i",
      "--",
      `/proc/${pid}/ns/mnt`,
    ]);
    const match = /^(0|[1-9][0-9]{0,19}) ([1-9][0-9]{0,19})\n?$/.exec(
      result.stdout,
    );
    if (result.code !== 0 || !match) fail();
    return { device: match[1], inode: match[2] };
  };
  let unitNamespace: Awaited<ReturnType<typeof namespace>> | undefined;
  let hostNamespace: Awaited<ReturnType<typeof namespace>> | undefined;
  const same = (a: { device: string; inode: string }, b: typeof a) =>
    a.device === b.device && a.inode === b.inode;
  const recordNamespace = async (
    scope: "UNIT" | "PRODUCER",
    identity: BackupV2NativeChild,
  ) => {
    const host = hostNamespace ??= await namespace(1);
    const deadline = performance.now() + 5000;
    let actual = await namespace(identity.pid);
    while (
      scope === "PRODUCER" &&
      (same(actual, host) || unitNamespace && same(actual, unitNamespace))
    ) {
      if (performance.now() >= deadline) fail();
      await new Promise((resolve) => setTimeout(resolve, 20));
      actual = await namespace(identity.pid);
    }
    const current = await observe(identity.pid, identity.kind);
    if (JSON.stringify(current) !== JSON.stringify(identity)) fail();
    await append({
      type: "MOUNT",
      namespace: {
        scope,
        leader: identity,
        ...actual,
        hostDevice: host.device,
        hostInode: host.inode,
      },
    });
    return actual;
  };
  const spawn: BackupV2NativeSpawn = async (
    kind,
    command,
    args,
    childOptions = {},
  ) => {
    childOptions.signal?.throwIfAborted();
    for (const key of ["stdin", "stdout", "stderr"] as const) {
      if (childOptions[key] !== undefined && childOptions[key] !== "piped") {
        fail();
      }
    }
    const child = launch("/usr/bin/bash", {
      args: [
        "-c",
        BACKUP_V2_NATIVE_START_SCRIPT,
        "backup-v2-native",
        command,
        ...args,
      ],
      cwd: childOptions.cwd,
      signal: childOptions.signal,
      clearEnv: true,
      env: backupV2ChildEnvironment({
        PATH: "/usr/bin:/bin",
        LC_ALL: "C",
        ...childOptions.env,
      }),
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
    });
    let status: Promise<Deno.CommandStatus> = child.status;
    status.catch(() => {});
    try {
      const registration = await registerChild(child.pid, kind);
      status = child.status.then(async (status) => {
        await registration.exit(status);
        return status;
      });
      status.catch(() => {});
      childOptions.signal?.throwIfAborted();
      const writer = child.stdin.getWriter();
      try {
        await writer.write(encoder.encode("START\n"));
      } finally {
        writer.releaseLock();
      }
      let timer: ReturnType<typeof setTimeout> | undefined;
      let stderr: ReadableStream<Uint8Array>;
      try {
        stderr = await Promise.race([
          acknowledge(child.stderr),
          new Promise<never>((_, reject) => {
            timer = setTimeout(
              () => reject(new Error("Backup v2 native START ACK missing")),
              5000,
            );
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      return {
        pid: child.pid,
        identity: registration.identity,
        stdin: child.stdin,
        stdout: child.stdout,
        stderr,
        status,
        kill: (signal?: Deno.Signal) => child.kill(signal),
      };
    } catch (error) {
      await Promise.allSettled([options.cancel(error), status]);
      throw error;
    }
  };
  return {
    spawn,
    registerChild,
    async registerNamespace(child: { pid?: number }) {
      const known = child.pid === undefined
        ? undefined
        : registered.get(child.pid);
      if (!known || known.identity.kind !== "unshare") fail();
      await recordNamespace("PRODUCER", known.identity);
    },
    async registerUnitNamespace() {
      if (unitNamespace) fail();
      unitNamespace = await recordNamespace("UNIT", backupV2NativeMain(gate));
      return { privateMount: !same(unitNamespace, hostNamespace!) };
    },
    async recordNoPrivateMount() {
      if (
        !unitNamespace || !hostNamespace ||
        !same(unitNamespace, hostNamespace) ||
        [...registered.values()].some((child) =>
          child.identity.kind === "unshare"
        )
      ) fail();
      const actual = await namespace(gate.custody!.mainPid);
      if (!same(actual, hostNamespace)) fail();
      await append({ type: "NO_PRIVATE_MOUNT" });
    },
  };
}
