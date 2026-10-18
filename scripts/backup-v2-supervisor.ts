import {
  type BackupV2LeaseWindow,
  type BackupV2Progress,
  type BackupV2TransferEpisode,
  validateBackupV2LeaseWindow,
  validateBackupV2Progress,
  validateBackupV2TransferEpisode,
} from "./backup-v2-contract.ts";
import {
  BACKUP_V2_LIMITS,
  backupV2RequiredFreeBytes,
} from "./backup-v2-profile.ts";

/** Internal service plumbing only; m08 must grant this exact FFI path, never -A. */
export const BACKUP_V2_NOTIFY_LIBRARY = "/usr/lib/libsystemd.so.0";
export const BACKUP_V2_MAX_NOTIFICATION_MS = 60_000;
export type BackupV2Notification =
  | { kind: "ready" }
  | { kind: "stopping" }
  | { kind: "extend"; usec: number };
export interface BackupV2Notifier {
  ready(): void;
  extend(usec: number): void;
  stopping(): void;
  close(): void;
}

function finite(
  value: number,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error("Invalid supervisor number");
  }
  return value;
}
function count(value: number): number {
  if (!Number.isSafeInteger(value)) {
    throw new Error("Invalid supervisor counter");
  }
  return finite(value);
}

export function encodeBackupV2Notification(
  message: BackupV2Notification,
): Uint8Array {
  let text: string;
  if (message.kind === "extend") {
    count(message.usec);
    finite(message.usec, 1, BACKUP_V2_MAX_NOTIFICATION_MS * 1000);
    text = `EXTEND_TIMEOUT_USEC=${message.usec}`;
  } else if (message.kind === "ready") text = "READY=1";
  else if (message.kind === "stopping") text = "STOPPING=1";
  else throw new Error("Invalid supervisor notification");
  if (text.length > 128 || !/^[\x20-\x7e]+$/.test(text)) {
    throw new Error("Invalid supervisor notification");
  }
  return new TextEncoder().encode(text + "\0");
}

/** Runs in the stable MainPID with NotifyAccess=main. This is not isolation
 * against a malicious root child able to forge process credentials. */
export function createBackupV2Notifier(): BackupV2Notifier {
  const socket = Deno.env.get("NOTIFY_SOCKET");
  if (!socket || !/^(\/|@)[^\0\r\n]{1,2047}$/.test(socket)) {
    throw new Error("Systemd notification socket unavailable");
  }
  const library = Deno.dlopen(BACKUP_V2_NOTIFY_LIBRARY, {
    sd_notify: { parameters: ["i32", "buffer"], result: "i32" },
  });
  let closed = false;
  const send = (message: BackupV2Notification) => {
    if (closed) throw new Error("Supervisor notifier is closed");
    if (
      library.symbols.sd_notify(0, encodeBackupV2Notification(message)) <= 0
    ) {
      throw new Error("Supervisor notification was not enqueued");
    }
  };
  return {
    ready: () => send({ kind: "ready" }),
    extend: (usec) => send({ kind: "extend", usec }),
    stopping: () => send({ kind: "stopping" }),
    close: () => {
      if (!closed) {
        closed = true;
        library.close();
      }
    },
  };
}

/** Supply this result with clearEnv:true at every child spawn. The supervisor
 * retains its own NOTIFY_SOCKET because libsystemd reads it on every call. */
export function backupV2ChildEnvironment(
  approved: Record<string, string>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(approved).filter(([name]) =>
      !/^(NOTIFY_SOCKET|WATCHDOG_PID|WATCHDOG_USEC|LISTEN_PID|LISTEN_FDS|LISTEN_FDNAMES)$/
        .test(name)
    ),
  );
}

export function backupV2SupervisorUnitProperties(
  notificationGraceMs: number,
): Record<string, string> {
  finite(notificationGraceMs, 1, BACKUP_V2_MAX_NOTIFICATION_MS);
  return {
    Type: "notify",
    NotifyAccess: "main",
    RuntimeMaxSec: `${notificationGraceMs}ms`,
    TimeoutStartSec: `${notificationGraceMs}ms`,
    TimeoutStopSec: "30s",
    KillMode: "control-group",
    SendSIGKILL: "yes",
    RemainAfterExit: "no",
    Restart: "no",
  };
}

export type BackupV2LeaseDecision =
  | { action: "renew"; absoluteDeadlineMs: number; extendUsec: number }
  | { action: "cancel"; reason: string };

/** Absolute timestamps belong to one supervisor invocation's monotonic domain.
 * Repeating the same window cannot turn its deadline into now + full grace. */
export function evaluateBackupV2Lease(
  window: BackupV2LeaseWindow,
  nowMs: number,
  notificationGraceMs: number,
  startupDeadlineMs = 0,
): BackupV2LeaseDecision {
  const checked = validateBackupV2LeaseWindow(window);
  finite(nowMs);
  finite(notificationGraceMs, 1, BACKUP_V2_MAX_NOTIFICATION_MS);
  finite(startupDeadlineMs);
  if (checked.observedMonotonicMs > nowMs) {
    throw new Error("Future lease observation");
  }
  const absoluteDeadlineMs = checked.transferEpisode?.expiresAtMs ?? Math.max(
    startupDeadlineMs,
    checked.usefulProgressExpiresAtMs,
    checked.retryEpisode?.expiresAtMs ?? 0,
  );
  const extendUsec = Math.floor(
    Math.min(notificationGraceMs, absoluteDeadlineMs - nowMs) * 1000,
  );
  return extendUsec > 0
    ? { action: "renew", absoluteDeadlineMs, extendUsec }
    : { action: "cancel", reason: "LEASE_EXPIRED" };
}

export interface BackupV2SupervisorIdentity {
  unitName: string;
  invocationId: string;
  mainPid: number;
  mainStartTicks: string;
  cgroup: string;
}
export interface BackupV2CapacityObservation {
  observedMonotonicMs: number;
  availableBytes: number;
  freeInodes: number;
  /** Includes allocated blocks still held through deleted workspace handles. */
  allocatedWorkspaceBytes: number;
  workspaceHeldDeletedBytes: number;
  sourceHeldDeletedBytes: number;
}
export interface BackupV2SupervisorObservation {
  identity: BackupV2SupervisorIdentity;
  progress: BackupV2Progress;
  capacity: BackupV2CapacityObservation;
}
export interface BackupV2SupervisorOptions {
  progressGraceMs: number;
  notificationGraceMs: number;
  /** One fixed initialization window, independent of each short notification. */
  startupGraceMs?: number;
  observationTimeoutMs: number;
  maximumObservationAgeMs: number;
  productionWriterMarginBytes: number;
  minimumFreeInodes: number;
  maximumSourceHeldDeletedBytes: number;
}
export interface BackupV2SupervisorCapabilities {
  now(): number;
  notifier: BackupV2Notifier;
  /** Bounded collector: independently check work, cgroup and filesystem/FD
   * accounting; counters are cumulative within the exact invocation. */
  observe(signal: AbortSignal): Promise<BackupV2SupervisorObservation>;
  /** Diagnostic only: failures here cannot alter the cancellation decision. */
  onFailure?(failure: BackupV2SupervisorFailure): void;
}

const failureStages = [
  "observation",
  "validation",
  "capacity",
  "notification",
  "worker",
] as const;
const failureClasses = [
  "Error",
  "TypeError",
  "RangeError",
  "DOMException",
  "BackupV2KernelEvidenceError",
  "BackupV2TransportError",
  "BackupV2CapacityGuardError",
];
const failureKinds = [
  "ABSENT",
  "UNREADABLE",
  "BOUNDED",
  "MALFORMED",
  "CUSTODY",
  "network",
  "http",
  "integrity",
  "protocol",
  "cancelled",
  "limit",
  "WORKSPACE_LIMIT",
  "FREE_SPACE",
  "FREE_INODES",
  "WORKSPACE_DELETED_ACCOUNTING",
  "SOURCE_DELETED_LIMIT",
];
const failureReasons = [
  "CANCELLED",
  "LEASE_EXPIRED",
  "OVERLAPPING_OBSERVATION",
  "IDENTITY_CHANGED",
  "NON_WORKING_PHASE",
  "PROGRESS_REGRESSED",
  "PROGRESS_WRONG_PHASE",
  "PROGRESS_TIMESTAMP_REUSED",
  "OBSERVATION_OR_NOTIFICATION_UNPROVED",
];
export interface BackupV2SupervisorFailure {
  stage: typeof failureStages[number];
  errorClass: string;
  kind: string | null;
}
class BackupV2CapacityGuardError extends Error {
  constructor(readonly kind: string) {
    super("Backup capacity guard rejected");
  }
}
/** Never retain message, stack, URLs, headers or arbitrary exception fields. */
export function classifyBackupV2Failure(error: unknown) {
  let errorClass = "UNKNOWN", kind: string | null = null;
  try {
    if (error instanceof Error) {
      const name = error.constructor.name;
      if (failureClasses.includes(name)) errorClass = name;
      const fields = error as Error & { kind?: unknown; category?: unknown };
      const value = errorClass === "BackupV2TransportError"
        ? fields.category
        : fields.kind;
      if (
        errorClass !== "UNKNOWN" && typeof value === "string" &&
        failureKinds.includes(value)
      ) kind = value;
    }
  } catch {
    return { errorClass: "UNKNOWN", kind: null };
  }
  return { errorClass, kind };
}
export function backupV2FailureEvidence(input: {
  identity: BackupV2SupervisorIdentity;
  reason: unknown;
  supervisorFailure: BackupV2SupervisorFailure | null;
  observation: BackupV2SupervisorObservation | null;
  observedAtUtc: string;
  observedMonotonicMs: number;
}) {
  const observedMonotonicMs = finite(input.observedMonotonicMs);
  const age = (sample: number) =>
    sample <= observedMonotonicMs ? observedMonotonicMs - sample : null;
  const identity = validIdentity({
    unitName: input.identity.unitName,
    invocationId: input.identity.invocationId,
    mainPid: input.identity.mainPid,
    mainStartTicks: input.identity.mainStartTicks,
    cgroup: input.identity.cgroup,
  });
  if (new Date(input.observedAtUtc).toISOString() !== input.observedAtUtc) {
    throw new Error("Invalid failure timestamp");
  }
  let observation: {
    progress: BackupV2Progress;
    capacity: BackupV2CapacityObservation;
  } | null = null;
  if (input.observation) {
    try {
      const source = input.observation.capacity;
      const capacity = {
        observedMonotonicMs: finite(source.observedMonotonicMs),
        availableBytes: count(source.availableBytes),
        freeInodes: count(source.freeInodes),
        allocatedWorkspaceBytes: count(source.allocatedWorkspaceBytes),
        workspaceHeldDeletedBytes: count(source.workspaceHeldDeletedBytes),
        sourceHeldDeletedBytes: count(source.sourceHeldDeletedBytes),
      };
      observation = {
        progress: validateBackupV2Progress(input.observation.progress),
        capacity,
      };
    } catch { /* Unknown facts remain absent, never invented as zero. */ }
  }
  const detail = input.supervisorFailure;
  const classified = detail ?? classifyBackupV2Failure(input.reason);
  return {
    schemaVersion: 1,
    format: "backup-v2-failure",
    observedAtUtc: input.observedAtUtc,
    observedMonotonicMs,
    capacityAgeMs: observation
      ? age(observation.capacity.observedMonotonicMs)
      : null,
    progressAgeMs: observation
      ? age(observation.progress.observedMonotonicMs)
      : null,
    identity,
    reason:
      typeof input.reason === "string" && failureReasons.includes(input.reason)
        ? input.reason
        : "UNCLASSIFIED_FAILURE",
    stage: detail && failureStages.includes(detail.stage)
      ? detail.stage
      : "worker",
    errorClass: failureClasses.includes(classified.errorClass)
      ? classified.errorClass
      : "UNKNOWN",
    kind: classified.kind !== null && failureKinds.includes(classified.kind)
      ? classified.kind
      : null,
    observation,
  };
}

function validIdentity(
  identity: BackupV2SupervisorIdentity,
): BackupV2SupervisorIdentity {
  if (
    !/^[a-zA-Z0-9_.:@-]{1,247}\.service$/.test(identity.unitName) ||
    !/^[a-f0-9]{32}$/.test(identity.invocationId) ||
    !/^[1-9][0-9]{0,19}$/.test(identity.mainStartTicks) ||
    !identity.cgroup.startsWith("/") ||
    !identity.cgroup.endsWith("/" + identity.unitName) ||
    identity.cgroup.length > 2048 ||
    identity.cgroup.split("/").some((part) =>
      part === ".." || /[\0\r\n]/.test(part)
    )
  ) {
    throw new Error("Invalid supervisor identity");
  }
  count(identity.mainPid);
  finite(identity.mainPid, 1);
  return Object.freeze({ ...identity });
}
function sameIdentity(
  expected: BackupV2SupervisorIdentity,
  actual: BackupV2SupervisorIdentity,
): boolean {
  const checked = validIdentity(actual);
  return (Object.keys(expected) as (keyof BackupV2SupervisorIdentity)[]).every((
    key,
  ) => checked[key] === expected[key]);
}

async function bounded<T>(
  run: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  outer?: AbortSignal,
): Promise<T> {
  finite(timeoutMs, 1, BACKUP_V2_LIMITS.blockedTransportMs);
  const controller = new AbortController();
  const abort = () => controller.abort();
  outer?.addEventListener("abort", abort, { once: true });
  if (outer?.aborted) abort();
  const timer = setTimeout(abort, timeoutMs);
  let rejectAbort: () => void = () => {};
  try {
    return await Promise.race([
      Promise.resolve().then(() => {
        controller.signal.throwIfAborted();
        return run(controller.signal);
      }),
      new Promise<never>((_, reject) => {
        rejectAbort = () =>
          reject(new Error("Supervisor operation did not settle in time"));
        controller.signal.addEventListener("abort", rejectAbort, {
          once: true,
        });
        if (controller.signal.aborted) rejectAbort();
      }),
    ]);
  } finally {
    clearTimeout(timer);
    outer?.removeEventListener("abort", abort);
    controller.signal.removeEventListener("abort", rejectAbort);
  }
}

const counters = [
  "sourceBytes",
  "compressionInputBytes",
  "verifiedChunks",
  "decryptedBytes",
  "decodedBytes",
  "inventoryMembers",
] as const;
const useful: Partial<
  Record<BackupV2Progress["phase"], readonly typeof counters[number][]>
> = {
  PREFLIGHT: ["sourceBytes", "inventoryMembers"],
  CAPTURING_AND_UPLOADING: [
    "sourceBytes",
    "compressionInputBytes",
    "verifiedChunks",
    "inventoryMembers",
  ],
  VERIFYING: [
    "verifiedChunks",
    "decryptedBytes",
    "decodedBytes",
    "inventoryMembers",
  ],
  PRUNING: ["inventoryMembers"],
};

export class BackupV2Supervisor {
  readonly identity: BackupV2SupervisorIdentity;
  readonly signal: AbortSignal;
  readonly #abort = new AbortController();
  readonly #options: BackupV2SupervisorOptions;
  readonly #caps: BackupV2SupervisorCapabilities;
  readonly #startupDeadline: number;
  #window: BackupV2LeaseWindow;
  #previous: BackupV2Progress | null = null;
  #lastNow: number;
  #busy = false;
  #ready = false;
  #serial = 0;
  #episodeSerial = -1;
  #reason: string | null = null;
  readonly #transfers = new Map<string, BackupV2TransferEpisode>();

  constructor(
    identity: BackupV2SupervisorIdentity,
    options: BackupV2SupervisorOptions,
    capabilities: BackupV2SupervisorCapabilities,
  ) {
    this.identity = validIdentity(identity);
    for (const value of Object.values(options)) finite(value);
    finite(options.notificationGraceMs, 1, BACKUP_V2_MAX_NOTIFICATION_MS);
    finite(
      options.progressGraceMs,
      options.notificationGraceMs,
      BACKUP_V2_LIMITS.blockedTransportMs,
    );
    finite(options.observationTimeoutMs, 1, options.notificationGraceMs);
    finite(options.maximumObservationAgeMs, 0, options.progressGraceMs);
    count(options.minimumFreeInodes);
    count(options.productionWriterMarginBytes);
    count(options.maximumSourceHeldDeletedBytes);
    this.#options = Object.freeze({ ...options });
    this.#caps = capabilities;
    this.#lastNow = finite(capabilities.now());
    const startupGraceMs = options.startupGraceMs ??
      options.notificationGraceMs;
    finite(
      startupGraceMs,
      options.notificationGraceMs,
      BACKUP_V2_LIMITS.blockedTransportMs,
    );
    this.#startupDeadline = this.#lastNow + startupGraceMs;
    this.#window = {
      observedMonotonicMs: this.#lastNow,
      usefulProgressAtMs: 0,
      usefulProgressExpiresAtMs: 0,
      retryEpisode: null,
    };
    this.signal = this.#abort.signal;
  }

  window(): BackupV2LeaseWindow {
    return structuredClone(this.#window);
  }
  /** Pending sealed I/O is an explicitly bounded wait, never a work counter.
   * The uploader supplies it only after its operation intent is fsynced. */
  beginTransferEpisode(value: BackupV2TransferEpisode): BackupV2LeaseWindow {
    if (this.#reason || this.#busy || !this.#previous) {
      throw new Error("Transfer episode is not eligible");
    }
    const now = this.#now(),
      episode = validateBackupV2TransferEpisode(value, now);
    if (
      episode.expiresAtMs <= now ||
      evaluateBackupV2Lease(
          this.#window,
          now,
          this.#options.notificationGraceMs,
          this.#startupDeadline,
        ).action !== "renew"
    ) throw new Error("Transfer cannot revive expired custody");
    const old = this.#transfers.get(episode.operationId),
      active = this.#window.transferEpisode;
    if (old && JSON.stringify(old) !== JSON.stringify(episode)) {
      throw new Error("Transfer window changed");
    }
    if (
      active && active.operationId !== episode.operationId &&
      !(active.sealedObjectIdentity === episode.sealedObjectIdentity &&
        active.phase === "PUT" && episode.phase === "READBACK")
    ) throw new Error("Overlapping sealed transfers");
    if (!old && this.#transfers.size >= BACKUP_V2_LIMITS.logicalObjects * 4) {
      throw new Error("Transfer episode budget exhausted");
    }
    this.#transfers.set(episode.operationId, structuredClone(episode));
    this.#window.transferEpisode = structuredClone(episode);
    this.#window.observedMonotonicMs = now;
    return this.window();
  }
  completeTransferEpisode(operationId: string): BackupV2LeaseWindow {
    if (
      !this.#transfers.has(operationId) ||
      this.#window.transferEpisode?.operationId !== operationId
    ) throw new Error("Transfer completion identity changed");
    this.#window.transferEpisode = null;
    this.#window.observedMonotonicMs = this.#now();
    return this.window();
  }

  cancel(reason = "CANCELLED"): BackupV2LeaseDecision {
    this.#reason ??= reason;
    this.#abort.abort();
    return { action: "cancel", reason: this.#reason };
  }

  /** m04/m08 may call only for a classified retryable blockage with durable
   * sealed bytes/intent retained. Repeated attempts cannot reset this episode. */
  beginRetryEpisode(
    evidence: {
      sealedObjectIdentity: string;
      retainedBytes: number;
      retryableTransport: true;
      /** Same-process durable uploader window; never shifted by later attempts. */
      startedAtMs?: number;
      expiresAtMs?: number;
    },
  ): BackupV2LeaseWindow {
    if (
      this.#reason || this.#busy || !this.#previous ||
      evidence.retryableTransport !== true ||
      typeof evidence.sealedObjectIdentity !== "string" ||
      evidence.sealedObjectIdentity.length < 1 ||
      evidence.sealedObjectIdentity.length > 1024
    ) {
      throw new Error("Retry episode is not eligible");
    }
    count(evidence.retainedBytes);
    finite(evidence.retainedBytes, 1, BACKUP_V2_LIMITS.slotBytes);
    const now = this.#now();
    if (
      (evidence.startedAtMs === undefined) !==
        (evidence.expiresAtMs === undefined)
    ) throw new Error("Incomplete retry episode window");
    const startedAtMs = evidence.startedAtMs ?? now;
    const expiresAtMs = evidence.expiresAtMs ??
      startedAtMs + BACKUP_V2_LIMITS.blockedTransportMs;
    finite(startedAtMs, 0, now);
    finite(
      expiresAtMs,
      now + Number.EPSILON,
      startedAtMs + BACKUP_V2_LIMITS.blockedTransportMs,
    );
    if (expiresAtMs <= now) throw new Error("Retry episode expired");
    if (
      evaluateBackupV2Lease(
        this.#window,
        now,
        this.#options.notificationGraceMs,
        this.#startupDeadline,
      ).action === "cancel"
    ) {
      this.cancel("LEASE_EXPIRED");
      throw new Error("Retry cannot revive an expired lease");
    }
    this.#fresh(this.#previous.observedMonotonicMs, now);
    if (!this.#window.retryEpisode) {
      if (this.#serial <= this.#episodeSerial) {
        throw new Error("Retry episode needs new useful work");
      }
      this.#episodeSerial = this.#serial;
      this.#window.retryEpisode = {
        startedAtMs,
        expiresAtMs,
      };
    } else if (
      evidence.startedAtMs !== undefined &&
      (this.#window.retryEpisode.startedAtMs !== startedAtMs ||
        this.#window.retryEpisode.expiresAtMs !== expiresAtMs)
    ) {
      throw new Error("Retry episode window changed");
    }
    this.#window.observedMonotonicMs = now;
    return this.window();
  }

  async poll(): Promise<BackupV2LeaseDecision> {
    if (this.#reason) return this.cancel();
    if (this.#busy) return this.cancel("OVERLAPPING_OBSERVATION");
    this.#busy = true;
    let stage: BackupV2SupervisorFailure["stage"] = "observation";
    try {
      const sample = await bounded(
        (signal) => this.#caps.observe(signal),
        this.#options.observationTimeoutMs,
        this.signal,
      );
      if (this.#reason) return this.cancel();
      stage = "validation";
      const now = this.#now();
      const prior = evaluateBackupV2Lease(
        this.#window,
        now,
        this.#options.notificationGraceMs,
        this.#startupDeadline,
      );
      if (prior.action === "cancel") return this.cancel(prior.reason);
      if (!sameIdentity(this.identity, sample.identity)) {
        return this.cancel("IDENTITY_CHANGED");
      }
      const progress = validateBackupV2Progress(sample.progress);
      this.#fresh(progress.observedMonotonicMs, now);
      stage = "capacity";
      this.#capacity(sample.capacity, now);
      stage = "validation";
      const fields = useful[progress.phase];
      if (!fields) return this.cancel("NON_WORKING_PHASE");
      if (this.#previous) {
        if (
          progress.observedMonotonicMs < this.#previous.observedMonotonicMs ||
          counters.some((field) =>
            (progress[field] ?? 0) < (this.#previous![field] ?? 0)
          )
        ) {
          return this.cancel("PROGRESS_REGRESSED");
        }
        const changed = counters.filter((field) =>
          (progress[field] ?? 0) > (this.#previous![field] ?? 0)
        );
        if (changed.some((field) => !fields.includes(field))) {
          return this.cancel("PROGRESS_WRONG_PHASE");
        }
        if (changed.length) {
          if (
            progress.observedMonotonicMs <= this.#previous.observedMonotonicMs
          ) return this.cancel("PROGRESS_TIMESTAMP_REUSED");
          this.#serial++;
          this.#window.usefulProgressAtMs = progress.observedMonotonicMs;
          this.#window.usefulProgressExpiresAtMs =
            progress.observedMonotonicMs + this.#options.progressGraceMs;
          if (
            !this.#window.retryEpisode ||
            progress.observedMonotonicMs > this.#window.retryEpisode.startedAtMs
          ) {
            this.#window.retryEpisode = null;
          }
        }
      }
      this.#previous = progress;
      this.#window.observedMonotonicMs = now;
      const decision = evaluateBackupV2Lease(
        this.#window,
        now,
        this.#options.notificationGraceMs,
        this.#startupDeadline,
      );
      if (decision.action === "cancel") return this.cancel(decision.reason);
      stage = "notification";
      if (!this.#ready) {
        this.#caps.notifier.ready();
        this.#ready = true;
      }
      this.#caps.notifier.extend(decision.extendUsec);
      return decision;
    } catch (error) {
      try {
        this.#caps.onFailure?.({ stage, ...classifyBackupV2Failure(error) });
      } catch { /* Diagnostic failure never changes the original decision. */ }
      return this.cancel("OBSERVATION_OR_NOTIFICATION_UNPROVED");
    } finally {
      this.#busy = false;
    }
  }

  #now(): number {
    const now = finite(this.#caps.now(), this.#lastNow);
    this.#lastNow = now;
    return now;
  }
  #fresh(observed: number, now: number): void {
    finite(
      observed,
      Math.max(0, now - this.#options.maximumObservationAgeMs),
      now,
    );
  }
  #capacity(capacity: BackupV2CapacityObservation, now: number): void {
    this.#fresh(capacity.observedMonotonicMs, now);
    for (const value of Object.values(capacity)) finite(value);
    for (
      const field of [
        "availableBytes",
        "freeInodes",
        "allocatedWorkspaceBytes",
        "workspaceHeldDeletedBytes",
        "sourceHeldDeletedBytes",
      ] as const
    ) count(capacity[field]);
    if (capacity.allocatedWorkspaceBytes > BACKUP_V2_LIMITS.workspaceBytes) {
      throw new BackupV2CapacityGuardError("WORKSPACE_LIMIT");
    }
    const required = backupV2RequiredFreeBytes(
      capacity.allocatedWorkspaceBytes,
      this.#options.productionWriterMarginBytes,
    );
    if (capacity.availableBytes < required) {
      throw new BackupV2CapacityGuardError("FREE_SPACE");
    }
    if (capacity.freeInodes < this.#options.minimumFreeInodes) {
      throw new BackupV2CapacityGuardError("FREE_INODES");
    }
    if (capacity.workspaceHeldDeletedBytes > capacity.allocatedWorkspaceBytes) {
      throw new BackupV2CapacityGuardError("WORKSPACE_DELETED_ACCOUNTING");
    }
    if (
      capacity.sourceHeldDeletedBytes >
        this.#options.maximumSourceHeldDeletedBytes
    ) throw new BackupV2CapacityGuardError("SOURCE_DELETED_LIMIT");
  }
}

export interface BackupV2TreeObservation {
  identity: BackupV2SupervisorIdentity;
  observedMonotonicMs: number;
  mainPid: number;
  controlPid: number;
  cgroupPopulated: boolean | null;
  descendants: number | null;
  escapedProcesses: number | null;
  namespaceReferences: number | null;
  openPipelineHandles: number | null;
  pendingOperations: number | null;
  sourceLockFree: boolean | null;
}
export interface BackupV2CancellationCapabilities {
  now(): number;
  observe(signal: AbortSignal): Promise<BackupV2TreeObservation | null>;
  wait?(milliseconds: number, signal: AbortSignal): Promise<void>;
  /** Reconcile the exact invocation again immediately before mutation; never
   * stop a replacement invocation sharing the unit name. */
  stop(
    identity: BackupV2SupervisorIdentity,
    signal: AbortSignal,
  ): Promise<void>;
}

/** Fresh observations only; an unknown sample never becomes settlement proof.
 * The caller must already have completed the exact stop before using this. */
export async function pollBackupV2Settlement(
  observe: (signal: AbortSignal) => Promise<boolean>,
  timeoutMs = 30_000,
  now: () => number = () => performance.now(),
  wait: (milliseconds: number, signal: AbortSignal) => Promise<void> = (
    milliseconds,
    signal,
  ) =>
    new Promise((resolve, reject) => {
      const abort = () => {
        clearTimeout(timer);
        reject(signal.reason);
      };
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", abort);
        resolve();
      }, milliseconds);
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    }),
): Promise<boolean> {
  finite(timeoutMs, 1, 30_000);
  let sampled = finite(now());
  const deadline = sampled + timeoutMs;
  const remaining = () => {
    sampled = finite(now(), sampled);
    return deadline - sampled;
  };
  for (let attempt = 0; attempt < 6; attempt++) {
    const available = remaining();
    if (available <= 0) return false;
    if (await bounded(observe, available)) return true;
    const left = remaining();
    if (attempt === 5 || left <= 0) return false;
    await bounded((signal) => wait(Math.min(250, left), signal), left);
  }
  return false;
}
export type BackupV2CancellationResult = {
  state: "SETTLED" | "CANCELLATION_BLOCKED";
  identity: BackupV2SupervisorIdentity;
};

/** External controller only: the MainPID cannot stop itself and subsequently
 * prove its own death. No gate/lock/scratch/namespace is released here. */
export async function settleBackupV2Cancellation(
  identity: BackupV2SupervisorIdentity,
  capabilities: BackupV2CancellationCapabilities,
  timeoutMs = 30_000,
): Promise<BackupV2CancellationResult> {
  const expected = validIdentity(identity);
  finite(timeoutMs, 1, 30_000);
  const started = finite(capabilities.now()), deadline = started + timeoutMs;
  let observed = started;
  const remaining = () => {
    observed = finite(capabilities.now(), observed, deadline);
    return deadline - observed;
  };
  const read = async () => {
    const proof = await bounded(
      (signal) => capabilities.observe(signal),
      remaining(),
    );
    if (proof === null) return null;
    if (!sameIdentity(expected, proof.identity)) {
      throw new Error("Cancellation identity changed");
    }
    finite(
      proof.observedMonotonicMs,
      observed,
      finite(capabilities.now(), observed, deadline),
    );
    count(proof.mainPid);
    count(proof.controlPid);
    if (proof.mainPid !== 0 && proof.mainPid !== expected.mainPid) {
      throw new Error("Cancellation MainPID changed");
    }
    return proof;
  };
  const settled = (proof: BackupV2TreeObservation) =>
    proof.mainPid === 0 && proof.controlPid === 0 &&
    proof.cgroupPopulated === false &&
    proof.descendants === 0 && proof.escapedProcesses === 0 &&
    proof.namespaceReferences === 0 &&
    proof.openPipelineHandles === 0 && proof.pendingOperations === 0 &&
    proof.sourceLockFree === true;
  try {
    const before = await read();
    if (before === null) throw new Error("Cancellation custody is unknown");
    if (!settled(before)) {
      await bounded(
        (signal) => capabilities.stop(expected, signal),
        remaining(),
      );
      if (
        !await pollBackupV2Settlement(
          async () => {
            const proof = await read();
            return proof !== null && settled(proof);
          },
          remaining(),
          capabilities.now,
          capabilities.wait,
        )
      ) {
        throw new Error("Cancellation tree is not settled");
      }
    }
    return { state: "SETTLED", identity: expected };
  } catch {
    return { state: "CANCELLATION_BLOCKED", identity: expected };
  }
}
