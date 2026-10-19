/** One finite, invocation-bound systemd lease survives manager reload. No
 * daemon-reload is issued here; the live timer still uses sd_notify. */
import {
  BACKUP_V2_MAX_NOTIFICATION_MS,
  BACKUP_V2_NOTIFY_LIBRARY,
  type BackupV2SupervisorIdentity,
} from "./backup-v2-supervisor.ts";
import {
  type BackupV2KernelCommand,
  type BackupV2KernelDiagnostic,
  backupV2KernelDiagnostic,
  backupV2KernelSettlement,
  readBackupV2KernelText,
  realBackupV2KernelCommand,
  tagBackupV2KernelFailure,
} from "./backup-v2-kernel.ts";
import { GATE_BACKUP_CGROUP_ROOT } from "./backblaze-controller-contract.ts";

/** Two files of at most one page, plus their directory, on /run tmpfs. */
export const BACKUP_V2_RUNTIME_LEASE_BYTES = 16 * 1024;
const MAX_FILE_BYTES = 4096;
const FILE = "lease-dropin.conf";
const UUID = "[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}";

export function backupV2RuntimeLeaseDirectory(unitName: string): string {
  if (
    !new RegExp(
      `^arch-vps-b2-v2-(worker|verify|prune)-${UUID}-${UUID}\\.service$`,
    ).test(unitName)
  ) throw new Error("Invalid runtime lease unit");
  return `/run/systemd/system/${unitName}.d`;
}
function validateIdentity(identity: BackupV2SupervisorIdentity): void {
  backupV2RuntimeLeaseDirectory(identity.unitName);
  if (
    !/^[a-f0-9]{32}$/.test(identity.invocationId) ||
    !Number.isSafeInteger(identity.mainPid) || identity.mainPid < 1 ||
    !/^[1-9][0-9]{0,19}$/.test(identity.mainStartTicks) ||
    identity.cgroup !== `${GATE_BACKUP_CGROUP_ROOT}/${identity.unitName}`
  ) throw new Error("Invalid runtime lease identity");
}
function header(identity: BackupV2SupervisorIdentity): string {
  validateIdentity(identity);
  return `# backup-v2-runtime-lease ${JSON.stringify(identity)}\n[Service]\n`;
}
export function validateBackupV2RuntimeLeaseText(
  text: string,
  identity: BackupV2SupervisorIdentity,
): void {
  if (
    !text.startsWith(header(identity)) ||
    !/^RuntimeMaxSec=[1-9][0-9]{0,19}us\nRuntimeRandomizedExtraSec=0\n$/
      .test(text.slice(header(identity).length))
  ) throw new Error("Runtime lease file custody unproved");
}
export interface BackupV2RuntimeLeaseObservation {
  identity: BackupV2SupervisorIdentity;
  running: boolean;
  activeEnterUsec: bigint;
}
export interface BackupV2RuntimeLeaseCapabilities {
  now(): number;
  kernelNowUsec(): bigint;
  observe(
    context?: BackupV2LeaseObservationContext,
  ): Promise<BackupV2RuntimeLeaseObservation>;
  persist(
    text: string,
    signal: AbortSignal,
    context?: BackupV2LeaseObservationContext,
  ): Promise<void>;
}
export interface BackupV2LeaseObservationContext {
  phase: "BEFORE_WRITE" | "BEFORE_COMMIT";
  signal: AbortSignal;
  budget: { deadlineMs: number; retried: boolean };
}
function checkObservationBudget(
  context: BackupV2LeaseObservationContext | undefined,
  now: number,
): void {
  if (
    context && (context.signal.aborted || !Number.isFinite(now) || now < 0 ||
      !Number.isFinite(context.budget.deadlineMs) ||
      now >= context.budget.deadlineMs)
  ) throw new Error("Runtime lease observation budget expired");
}

/** Process-relative useful-progress times are projected conservatively onto
 * CLOCK_MONOTONIC, the clock systemd uses for ActiveEnterTimestampMonotonic. */
export function createBackupV2RuntimeLease(
  identityInput: BackupV2SupervisorIdentity,
  caps: BackupV2RuntimeLeaseCapabilities,
) {
  const identity = Object.freeze({ ...identityInput });
  validateIdentity(identity);
  let activation: bigint | null = null, lastKernel = 0n, lastNow = 0;
  let poisoned = false;
  const now = () => {
    const value = caps.now();
    if (!Number.isFinite(value) || value < lastNow) {
      throw new Error("Runtime lease clock unproved");
    }
    return lastNow = value;
  };
  return async (
    deadlineMs: number,
    signal: AbortSignal,
    observationDeadlineMs?: number,
  ): Promise<void> => {
    if (poisoned) throw new Error("Runtime lease is poisoned");
    try {
      const began = now();
      if (
        observationDeadlineMs !== undefined &&
        (!Number.isFinite(observationDeadlineMs) ||
          observationDeadlineMs <= began ||
          observationDeadlineMs > began + 5000)
      ) {
        throw new Error("Runtime lease observation budget invalid");
      }
      const context: BackupV2LeaseObservationContext | undefined =
        observationDeadlineMs === undefined ? undefined : {
          phase: "BEFORE_WRITE",
          signal,
          budget: { deadlineMs: observationDeadlineMs, retried: false },
        };
      if (
        !Number.isFinite(deadlineMs) || deadlineMs <= began ||
        deadlineMs > began + BACKUP_V2_MAX_NOTIFICATION_MS
      ) throw new Error("Invalid runtime lease deadline");
      // READY must already have been sent. Never wait beyond the short initial
      // lease, or mistake the previous activation's timestamp for this one.
      for (;;) {
        signal.throwIfAborted();
        const sample = await caps.observe(context);
        checkObservationBudget(context, now());
        if (JSON.stringify(sample.identity) !== JSON.stringify(identity)) {
          throw new Error("Runtime lease invocation changed");
        }
        if (sample.running && sample.activeEnterUsec > 0n) {
          if (activation !== null && activation !== sample.activeEnterUsec) {
            throw new Error("Runtime lease activation changed");
          }
          activation = sample.activeEnterUsec;
          break;
        }
        if (activation !== null || now() - began >= 2000) {
          throw new Error("Runtime lease readiness unproved");
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      signal.throwIfAborted();
      const kernel = caps.kernelNowUsec(), observed = now();
      if (kernel <= 0n || kernel < lastKernel || activation > kernel) {
        throw new Error("Runtime lease kernel clock unproved");
      }
      lastKernel = kernel;
      const remaining = Math.floor((deadlineMs - observed) * 1000);
      if (!Number.isSafeInteger(remaining) || remaining <= 0) {
        throw new Error("Runtime lease deadline expired");
      }
      const duration = kernel + BigInt(remaining) - activation;
      const text = header(identity) +
        `RuntimeMaxSec=${duration}us\nRuntimeRandomizedExtraSec=0\n`;
      if (new TextEncoder().encode(text).length > MAX_FILE_BYTES) {
        throw new Error("Runtime lease metadata exceeded bound");
      }
      await caps.persist(text, signal, context);
      signal.throwIfAborted();
      checkObservationBudget(context, now());
      if (now() >= deadlineMs) {
        throw new Error("Runtime lease deadline expired");
      }
    } catch (error) {
      poisoned = true;
      throw error;
    }
  };
}

async function directory(path: string): Promise<void> {
  const info = await Deno.lstat(path);
  if (
    !info.isDirectory || info.isSymlink || info.uid !== 0 ||
    info.mode === null || (info.mode & 0o022) !== 0 ||
    await Deno.realPath(path) !== path
  ) throw new Error("Runtime lease directory custody unproved");
}
async function readOwned(
  path: string,
  identity: BackupV2SupervisorIdentity,
): Promise<Deno.FileInfo | null> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return null;
    throw error;
  }
  if (
    !info.isFile || info.isSymlink || info.uid !== 0 || info.nlink !== 1 ||
    info.mode === null || (info.mode & 0o077) !== 0 ||
    info.size > MAX_FILE_BYTES
  ) throw new Error("Runtime lease file custody unproved");
  using file = await Deno.open(path, { read: true });
  const actual = await file.stat();
  if (actual.dev !== info.dev || actual.ino !== info.ino) {
    throw new Error("Runtime lease file changed");
  }
  const bytes = new Uint8Array(MAX_FILE_BYTES + 1);
  let at = 0, count: number | null;
  while ((count = await file.read(bytes.subarray(at))) !== null) {
    at += count;
    if (at > MAX_FILE_BYTES) throw new Error("Runtime lease file too large");
  }
  validateBackupV2RuntimeLeaseText(
    new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, at)),
    identity,
  );
  return info;
}
export async function observeBackupV2RuntimeLease(
  identity: BackupV2SupervisorIdentity,
  context?: BackupV2LeaseObservationContext,
  run: BackupV2KernelCommand = realBackupV2KernelCommand,
  now: () => number = () => performance.now(),
): Promise<BackupV2RuntimeLeaseObservation> {
  const tagged = async <T>(
    helper: BackupV2KernelDiagnostic["helper"],
    call: () => Promise<T>,
  ): Promise<T> => {
    try {
      return await call();
    } catch (error) {
      tagBackupV2KernelFailure(error, helper, context?.phase ?? "UNKNOWN");
      throw error;
    }
  };
  const attempt = async (): Promise<BackupV2RuntimeLeaseObservation> => {
    checkObservationBudget(context, now());
    const results = await Promise.allSettled([
      tagged("UNIT_SHOW", () =>
        run("/usr/bin/systemctl", [
          "show",
          identity.unitName,
          "--no-pager",
          "--property=MainPID,InvocationID,ControlGroup,ActiveState,SubState,ActiveEnterTimestampMonotonic",
        ])),
      tagged(
        "PROC_STAT",
        () => readBackupV2KernelText(`/proc/${identity.mainPid}/stat`, run),
      ),
      tagged(
        "PROC_CGROUP",
        () => readBackupV2KernelText(`/proc/${identity.mainPid}/cgroup`, run),
      ),
    ]);
    const unit = results[0].status === "fulfilled" ? results[0].value : null;
    const stat = results[1].status === "fulfilled" ? results[1].value : null;
    const cgroup = results[2].status === "fulfilled" ? results[2].value : null;
    const fields = Object.fromEntries(
      (unit?.stdout ?? "").trim().split("\n").map((line) => {
        const at = line.indexOf("=");
        return [line.slice(0, at), line.slice(at + 1)];
      }),
    );
    const ticks = stat?.slice(stat.lastIndexOf(")") + 2).trim().split(
      /\s+/,
    )[19];
    if (
      unit && (unit.code !== 0 || fields.MainPID !== String(identity.mainPid) ||
          fields.InvocationID !== identity.invocationId ||
          fields.ControlGroup !== identity.cgroup ||
          !/^[0-9]{1,20}$/.test(fields.ActiveEnterTimestampMonotonic)) ||
      stat !== null && ticks !== identity.mainStartTicks ||
      cgroup !== null && cgroup.trim() !== `0::${identity.cgroup}`
    ) throw new Error("Runtime lease live custody unproved");
    const failures = results.filter((value) => value.status === "rejected").map(
      (value) => value.reason,
    );
    if (failures.length) {
      const first = failures[0];
      if (
        !context || context.budget.retried || failures.some((error) => {
          const detail = backupV2KernelDiagnostic(error);
          return detail?.bound !== "DEADLINE" || detail.helper === "UNKNOWN" ||
            !backupV2KernelSettlement(error);
        })
      ) throw first;
      context.signal.throwIfAborted();
      const remaining = context.budget.deadlineMs - now() - 2000;
      if (!Number.isFinite(remaining) || remaining <= 0) throw first;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const settled = await Promise.race([
        Promise.all(failures.map((error) => backupV2KernelSettlement(error)!))
          .then((values) => values.every(Boolean)),
        new Promise<false>((resolve) => {
          timer = setTimeout(() => resolve(false), remaining);
        }),
      ]).finally(() => clearTimeout(timer));
      if (
        !settled || context.signal.aborted ||
        context.budget.deadlineMs - now() <= 2000
      ) throw first;
      context.budget.retried = true;
      return await attempt();
    }
    if (!unit || !stat || !cgroup) {
      throw new Error("Runtime lease observation incomplete");
    }
    checkObservationBudget(context, now());
    return {
      identity,
      running: fields.ActiveState === "active" && fields.SubState === "running",
      activeEnterUsec: BigInt(fields.ActiveEnterTimestampMonotonic),
    };
  };
  return await attempt();
}

export function openBackupV2RuntimeLease(identity: BackupV2SupervisorIdentity) {
  const path = backupV2RuntimeLeaseDirectory(identity.unitName);
  validateIdentity(identity);
  // dlsym on libsystemd also resolves its libc dependency. A missing symbol or
  // unsupported clock fails closed; no guessed performance.now epoch is used.
  const library = Deno.dlopen(BACKUP_V2_NOTIFY_LIBRARY, {
    clock_gettime: { parameters: ["i32", "buffer"], result: "i32" },
  });
  let activation: bigint | null = null;
  const current = async (context?: BackupV2LeaseObservationContext) => {
    const sample = await observeBackupV2RuntimeLease(identity, context);
    if (sample.running && sample.activeEnterUsec > 0n) {
      if (activation !== null && sample.activeEnterUsec !== activation) {
        throw new Error("Runtime lease activation changed");
      }
      activation = sample.activeEnterUsec;
    }
    return sample;
  };
  const persist = createBackupV2RuntimeLease(identity, {
    now: () => performance.now(),
    kernelNowUsec() {
      const value = new BigInt64Array(2);
      if (
        library.symbols.clock_gettime(1, value) !== 0 || value[0] < 0n ||
        value[1] < 0n || value[1] >= 1_000_000_000n
      ) throw new Error("CLOCK_MONOTONIC unavailable");
      return value[0] * 1_000_000n + value[1] / 1000n;
    },
    observe: current,
    async persist(text, signal, context) {
      try {
        await Deno.mkdir(path, { mode: 0o700 });
      } catch (error) {
        if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
      }
      await directory(path);
      const target = `${path}/${FILE}`,
        temporary = `${target}.tmp-${identity.invocationId}`;
      const previous = await readOwned(target, identity);
      signal.throwIfAborted();
      const file = await Deno.open(temporary, {
        createNew: true,
        write: true,
        mode: 0o600,
      });
      const created = await file.stat();
      let cleanupFailure: unknown;
      try {
        const bytes = new TextEncoder().encode(text);
        let at = 0;
        while (at < bytes.length) {
          signal.throwIfAborted();
          const written = await file.write(bytes.subarray(at));
          if (written <= 0) throw new Error("Runtime lease short write");
          at += written;
        }
        await file.sync();
        file.close();
        await directory(path);
        const replacement = await readOwned(target, identity),
          live = await current(
            context ? { ...context, phase: "BEFORE_COMMIT" } : undefined,
          );
        if (
          !live.running || live.activeEnterUsec <= 0n ||
          replacement?.ino !== previous?.ino ||
          replacement?.dev !== previous?.dev
        ) throw new Error("Runtime lease custody changed before commit");
        signal.throwIfAborted();
        checkObservationBudget(context, performance.now());
        await Deno.rename(temporary, target);
        using parent = await Deno.open(path, { read: true });
        await parent.sync();
      } finally {
        try {
          file.close();
        } catch { /* Already closed before rename. */ }
        try {
          const left = await Deno.lstat(temporary);
          if (
            left.dev === created.dev && left.ino === created.ino &&
            !left.isSymlink
          ) {
            await Deno.remove(temporary);
          }
        } catch (error) {
          if (!(error instanceof Deno.errors.NotFound)) cleanupFailure = error;
        }
      }
      if (cleanupFailure !== undefined) throw cleanupFailure;
    },
  });
  return { persist, close: () => library.close() };
}

/** Caller must first prove exact unit/tree/namespace settlement. Never called
 * by the live worker, including its cancellation and failure paths. */
export async function removeBackupV2RuntimeLease(
  identity: BackupV2SupervisorIdentity,
): Promise<void> {
  validateIdentity(identity);
  const path = backupV2RuntimeLeaseDirectory(identity.unitName);
  try {
    await directory(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return;
    throw error;
  }
  for (const name of [FILE, `${FILE}.tmp-${identity.invocationId}`]) {
    const target = `${path}/${name}`,
      previous = await readOwned(target, identity);
    if (!previous) continue;
    const current = await Deno.lstat(target);
    if (
      current.ino !== previous.ino || current.dev !== previous.dev ||
      current.isSymlink
    ) {
      throw new Error("Runtime lease changed during cleanup");
    }
    await Deno.remove(target);
  }
  using parent = await Deno.open(path, { read: true });
  await parent.sync();
  // A nonrecursive removal preserves any unrelated drop-in, including one
  // arriving after the directory census.
  for await (const _entry of Deno.readDir(path)) return;
  await Deno.remove(path);
}
