import type { TunnelSeam } from "./backblaze-file-backup.ts";
import {
  type BackupV2LeaseWindow,
  type BackupV2Progress,
  validateBackupV2LeaseWindow,
  validateBackupV2Progress,
} from "./backup-v2-contract.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";
import {
  BACKUP_V2_MAX_NOTIFICATION_MS,
  type BackupV2Notifier,
  type BackupV2SupervisorIdentity,
  backupV2SupervisorUnitProperties,
  evaluateBackupV2Lease,
} from "./backup-v2-supervisor.ts";

/** Structural subset of m08 runtime custody; no runtime/controller import. */
export interface BackupV2BridgeBinding {
  jobId: string;
  captureId: string;
  requestSha256: string;
  gateId: string;
  source: BackupV2SupervisorIdentity & { sourceBootId: string };
  publicHome: string;
  remoteSocket: string;
  defaultSocket: string;
}
export interface BackupV2BridgeObservation {
  keeper: BackupV2SupervisorIdentity;
  binding: BackupV2BridgeBinding;
  /** Collected in the keeper's monotonic domain, never a VPS timestamp. */
  observedMonotonicMs: number;
  gate: "OWNED" | "CANCELLED" | "TERMINAL";
  /** Independently checked cumulative work within this source invocation. */
  progress: Omit<BackupV2Progress, "observedMonotonicMs">;
  /** Source-bound waits projected once into this keeper's monotonic clock. */
  sourceWait?: Pick<BackupV2LeaseWindow, "retryEpisode" | "transferEpisode">;
}
export interface BackupV2BridgeClosure {
  keeper: BackupV2SupervisorIdentity;
  binding: BackupV2BridgeBinding;
  observedMonotonicMs: number;
  sshProcesses: number | null;
  openStdinHandles: number | null;
  remoteSocketPresent: boolean | null;
  defaultSocketUnchanged: boolean | null;
}
export interface BackupV2BridgeOptions {
  notificationGraceMs: number;
  progressGraceMs: number;
  retryGraceMs: number;
  operationTimeoutMs: number;
  maximumObservationAgeMs: number;
}
export interface BackupV2BridgeCapabilities {
  now(): number;
  /** Created by an actually proved stable-MainPID Pi launch. No guessed FFI
   * path, child impersonation, safepi bypass or wrapper modification here. */
  notifier: BackupV2Notifier;
  /** Existing realTunnelSeam with its unchanged Pi keyring identity and
   * reverse-forward/TUNNEL_READY/remote-cat/stdin-EOF protocol.
   * Child environment must strip notification credentials. No payload API. */
  tunnel: TunnelSeam;
  observe(signal: AbortSignal): Promise<BackupV2BridgeObservation>;
  /** External bounded control collector, independent of tunnel.current(). */
  observeClosure(signal: AbortSignal): Promise<BackupV2BridgeClosure>;
}
export type BackupV2BridgeReason =
  | "TERMINAL"
  | "CANCELLED"
  | "LEASE_EXPIRED"
  | "IDENTITY_CHANGED"
  | "PROGRESS_REGRESSED"
  | "PROGRESS_WRONG_PHASE"
  | "TUNNEL_LOST"
  | "OVERLAPPING_OPERATION"
  | "OBSERVATION_OR_NOTIFICATION_UNPROVED";
export interface BackupV2BridgeStatus {
  state: "NEW" | "ACTIVE" | "CLOSED" | "CANCELLATION_BLOCKED";
  keeper: BackupV2SupervisorIdentity;
  binding: BackupV2BridgeBinding;
  reason: BackupV2BridgeReason | null;
  lease: BackupV2LeaseWindow;
  pendingOperations: number;
}

/** Launch integration must prove actual MainPID, notify sender and effective
 * Pi scopes/caps; these properties alone do not establish those facts. The
 * bounded controller attempts continue to run through safepi. */
export function backupV2BridgeUnitProperties(
  notificationGraceMs: number,
): Record<string, string> {
  return {
    ...backupV2SupervisorUnitProperties(notificationGraceMs),
    RemainAfterExit: "yes",
    LimitCORE: "0",
    MemoryHigh: "320M",
    MemoryMax: "380M",
    CPUQuota: "90%",
    IOWeight: "100",
    TasksMax: "256",
    Nice: "10",
  };
}

const uuid = "[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}";
const uuidPattern = new RegExp(`^${uuid}$`);
function number(value: number, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new Error("Invalid bridge number");
  }
  return value;
}
function identity(
  value: BackupV2SupervisorIdentity,
): BackupV2SupervisorIdentity {
  if (
    !/^[a-zA-Z0-9_.:@-]{1,247}\.service$/.test(value.unitName) ||
    !/^[0-9a-f]{32}$/.test(value.invocationId) ||
    !Number.isSafeInteger(value.mainPid) || value.mainPid < 1 ||
    !/^[1-9][0-9]{0,19}$/.test(value.mainStartTicks) ||
    !value.cgroup.startsWith("/") || value.cgroup.length > 2048 ||
    !value.cgroup.endsWith(`/${value.unitName}`) ||
    value.cgroup.split("/").some((p) => p === ".." || /[\0\r\n]/.test(p))
  ) throw new Error("Invalid bridge custody");
  const { unitName, invocationId, mainPid, mainStartTicks, cgroup } = value;
  return { unitName, invocationId, mainPid, mainStartTicks, cgroup };
}
function sameIdentity(
  a: BackupV2SupervisorIdentity,
  b: BackupV2SupervisorIdentity,
) {
  identity(b);
  return ([
    "unitName",
    "invocationId",
    "mainPid",
    "mainStartTicks",
    "cgroup",
  ] as const)
    .every((key) => a[key] === b[key]);
}
function binding(value: BackupV2BridgeBinding): BackupV2BridgeBinding {
  identity(value.source);
  const id = value.jobId.slice(4);
  if (
    !value.jobId.startsWith("job-") || !uuidPattern.test(id) ||
    value.captureId !== `generation-${id}` || !uuidPattern.test(value.gateId) ||
    !/^[0-9a-f]{64}$/.test(value.requestSha256) ||
    !uuidPattern.test(value.source.sourceBootId) ||
    value.publicHome !==
      `/home/codex/.local/share/arch-vps-verifier/generation-${id}` ||
    value.remoteSocket.length > 2048 || value.defaultSocket.length > 2048 ||
    !/^\/run\/user\/[0-9]+\/gnupg\/d\.[a-zA-Z0-9]+\/S\.gpg-agent$/
      .test(value.remoteSocket) ||
    !/^\/run\/user\/[0-9]+\/(?:[^/\0\r\n]+\/)*S\.gpg-agent$/
      .test(value.defaultSocket) ||
    value.defaultSocket.split("/").some((part) =>
      part === "." || part === ".."
    ) ||
    value.remoteSocket.split("/")[3] !== value.defaultSocket.split("/")[3] ||
    value.remoteSocket === value.defaultSocket
  ) throw new Error("Invalid bridge binding or custom socket");
  const {
    jobId,
    captureId,
    requestSha256,
    gateId,
    publicHome,
    remoteSocket,
    defaultSocket,
  } = value;
  return {
    jobId,
    captureId,
    requestSha256,
    gateId,
    publicHome,
    remoteSocket,
    defaultSocket,
    source: {
      ...identity(value.source),
      sourceBootId: value.source.sourceBootId,
    },
  };
}
function sameBinding(
  a: BackupV2BridgeBinding,
  b: BackupV2BridgeBinding,
): boolean {
  const checked = binding(b);
  return sameIdentity(a.source, checked.source) &&
    a.source.sourceBootId === checked.source.sourceBootId &&
    (Object.keys(a) as (keyof BackupV2BridgeBinding)[])
      .filter((key) => key !== "source")
      .every((key) => a[key] === checked[key]);
}
const counters = [
  "sourceBytes",
  "compressionInputBytes",
  "verifiedChunks",
  "decryptedBytes",
  "decodedBytes",
  "inventoryMembers",
] as const;
const useful: Partial<Record<BackupV2Progress["phase"], readonly string[]>> = {
  PREFLIGHT: ["sourceBytes", "inventoryMembers"],
  CAPTURING_AND_UPLOADING: [
    "sourceBytes",
    "compressionInputBytes",
    "verifiedChunks",
    "inventoryMembers",
  ],
  CLOUD_COMPLETE: [],
  VERIFYING: [
    "verifiedChunks",
    "decryptedBytes",
    "decodedBytes",
    "inventoryMembers",
  ],
};

/** One managed helper owns this object and SSH stdin for the exact gate. The
 * caller persists bounded status and polls faster than its finite lease. It
 * must retain gate custody until source AND keeper settlement are proved. */
export class BackupV2BridgeKeeper {
  readonly #keeper: BackupV2SupervisorIdentity;
  readonly #binding: BackupV2BridgeBinding;
  readonly #options: BackupV2BridgeOptions;
  readonly #caps: BackupV2BridgeCapabilities;
  readonly #abort = new AbortController();
  readonly #startupDeadline: number;
  #state: BackupV2BridgeStatus["state"] = "NEW";
  #reason: BackupV2BridgeReason | null = null;
  #window: BackupV2LeaseWindow;
  #previous: BackupV2Progress | null = null;
  #now: number;
  #serial = 0;
  #episodeSerial = -1;
  #pending = 0;
  #operation: Promise<BackupV2BridgeStatus> | null = null;
  #notifierClosed = false;
  #ownsTunnel = false;

  constructor(
    keeper: BackupV2SupervisorIdentity,
    expected: BackupV2BridgeBinding,
    options: BackupV2BridgeOptions,
    capabilities: BackupV2BridgeCapabilities,
  ) {
    this.#keeper = identity(keeper);
    this.#binding = binding(expected);
    number(options.notificationGraceMs, 1, BACKUP_V2_MAX_NOTIFICATION_MS);
    number(
      options.progressGraceMs,
      options.notificationGraceMs,
      BACKUP_V2_LIMITS.blockedTransportMs,
    );
    number(options.retryGraceMs, 1, BACKUP_V2_LIMITS.blockedTransportMs);
    number(options.operationTimeoutMs, 1, options.notificationGraceMs);
    number(options.maximumObservationAgeMs, 0, options.progressGraceMs);
    this.#options = { ...options };
    this.#caps = capabilities;
    this.#now = number(capabilities.now());
    this.#startupDeadline = this.#now + options.notificationGraceMs;
    this.#window = {
      observedMonotonicMs: this.#now,
      usefulProgressAtMs: 0,
      usefulProgressExpiresAtMs: 0,
      retryEpisode: null,
    };
  }

  status(): BackupV2BridgeStatus {
    return structuredClone({
      state: this.#state,
      keeper: this.#keeper,
      binding: this.#binding,
      reason: this.#reason,
      lease: this.#window,
      pendingOperations: this.#pending,
    });
  }

  start(): Promise<BackupV2BridgeStatus> {
    return this.#run(async () => {
      if (this.#state !== "NEW") return;
      if (this.#caps.tunnel.current() !== null) {
        throw new Error("Bridge cannot adopt an existing transport");
      }
      await this.#observe();
      if (this.#reason) return;
      await this.#bounded(async (signal) => {
        this.#ownsTunnel = true;
        const handle = await this.#caps.tunnel.open(this.#binding.remoteSocket);
        // An unabortable old seam can resolve after the deadline. It remains
        // pending/blocked until its owned stdin is closed and exit is proved.
        if (signal.aborted || this.#reason) await this.#caps.tunnel.close();
        return handle;
      });
      this.#state = "ACTIVE";
      if (this.#reason) return;
      if (!this.#caps.tunnel.current()) return this.#fail("TUNNEL_LOST");
      if (!this.#live()) return;
      this.#caps.notifier.ready();
      this.#renew();
    });
  }

  poll(): Promise<BackupV2BridgeStatus> {
    return this.#run(async () => {
      if (this.#state !== "ACTIVE") return;
      if (!this.#live()) return;
      if (!this.#caps.tunnel.current()) return this.#fail("TUNNEL_LOST");
      await this.#observe();
      if (!this.#reason) this.#renew();
    });
  }

  /** One episode per useful-work serial; repeats retain the absolute expiry. */
  beginRetryEpisode(evidence: {
    sealedObjectIdentity: string;
    retainedBytes: number;
    retryableTransport: true;
  }): BackupV2BridgeStatus {
    if (
      this.#state !== "ACTIVE" || this.#reason || this.#operation ||
      !this.#previous || evidence.retryableTransport !== true ||
      !/^[\x21-\x7e]{1,1024}$/.test(evidence.sealedObjectIdentity) ||
      !Number.isSafeInteger(evidence.retainedBytes)
    ) throw new Error("Bridge retry is not eligible");
    number(evidence.retainedBytes, 1, BACKUP_V2_LIMITS.slotBytes);
    const now = this.#time();
    if (!this.#live()) throw new Error("Bridge retry cannot revive its lease");
    this.#fresh(this.#previous.observedMonotonicMs, now);
    if (!this.#window.retryEpisode) {
      if (this.#serial === 0 || this.#serial <= this.#episodeSerial) {
        throw new Error("Bridge retry needs new useful work");
      }
      this.#episodeSerial = this.#serial;
      this.#window.retryEpisode = {
        startedAtMs: now,
        expiresAtMs: now + this.#options.retryGraceMs,
      };
    }
    this.#window.observedMonotonicMs = now;
    return this.status();
  }

  async close(
    reason: BackupV2BridgeReason = "CANCELLED",
  ): Promise<BackupV2BridgeStatus> {
    this.#fail(reason);
    await this.#operation;
    if (this.#state !== "CLOSED") await this.#close();
    return this.status();
  }

  async #run(action: () => Promise<void>): Promise<BackupV2BridgeStatus> {
    if (this.#operation) return await this.close("OVERLAPPING_OPERATION");
    const operation = (async () => {
      try {
        await action();
      } catch {
        this.#fail("OBSERVATION_OR_NOTIFICATION_UNPROVED");
      }
      if (this.#reason && this.#state !== "CLOSED") await this.#close();
      return this.status();
    })();
    this.#operation = operation;
    try {
      return await operation;
    } finally {
      this.#operation = null;
    }
  }

  #fail(reason: BackupV2BridgeReason): void {
    this.#reason ??= reason;
    this.#abort.abort();
  }
  #time(): number {
    return this.#now = number(this.#caps.now(), this.#now);
  }
  #fresh(observed: number, now: number): void {
    number(
      observed,
      Math.max(0, now - this.#options.maximumObservationAgeMs),
      now,
    );
  }
  #live(): boolean {
    const decision = evaluateBackupV2Lease(
      this.#window,
      this.#time(),
      this.#options.notificationGraceMs,
      this.#startupDeadline,
    );
    if (decision.action === "cancel") this.#fail("LEASE_EXPIRED");
    return !this.#reason;
  }
  #renew(): boolean {
    const decision = evaluateBackupV2Lease(
      this.#window,
      this.#time(),
      this.#options.notificationGraceMs,
      this.#startupDeadline,
    );
    if (decision.action === "cancel") this.#fail("LEASE_EXPIRED");
    else this.#caps.notifier.extend(decision.extendUsec);
    return !this.#reason;
  }
  async #observe(): Promise<void> {
    const sample = await this.#bounded((signal) => this.#caps.observe(signal));
    const now = this.#time();
    if (!this.#live()) return;
    if (
      !sameIdentity(this.#keeper, sample.keeper) ||
      !sameBinding(this.#binding, sample.binding)
    ) {
      return this.#fail("IDENTITY_CHANGED");
    }
    this.#fresh(sample.observedMonotonicMs, now);
    if (sample.gate === "TERMINAL") return this.#fail("TERMINAL");
    if (sample.gate === "CANCELLED") return this.#fail("CANCELLED");
    if (sample.gate !== "OWNED") throw new Error("Bridge gate is unproved");
    const progress = validateBackupV2Progress({
      ...sample.progress,
      observedMonotonicMs: sample.observedMonotonicMs,
    });
    const allowed = useful[progress.phase];
    if (!allowed) return this.#fail("PROGRESS_WRONG_PHASE");
    if (this.#previous) {
      if (
        progress.observedMonotonicMs < this.#previous.observedMonotonicMs ||
        counters.some((field) =>
          (progress[field] ?? 0) < (this.#previous![field] ?? 0)
        )
      ) {
        return this.#fail("PROGRESS_REGRESSED");
      }
      const changed = counters.filter((field) =>
        (progress[field] ?? 0) > (this.#previous![field] ?? 0)
      );
      if (changed.some((field) => !allowed.includes(field))) {
        return this.#fail("PROGRESS_WRONG_PHASE");
      }
      if (changed.length) {
        if (
          progress.observedMonotonicMs === this.#previous.observedMonotonicMs
        ) throw new Error("Reused bridge progress time");
        this.#serial++;
        this.#window.usefulProgressAtMs = progress.observedMonotonicMs;
        this.#window.usefulProgressExpiresAtMs = progress.observedMonotonicMs +
          this.#options.progressGraceMs;
        if (
          !this.#window.retryEpisode ||
          progress.observedMonotonicMs > this.#window.retryEpisode.startedAtMs
        ) this.#window.retryEpisode = null;
      }
    }
    this.#previous = progress;
    this.#window.observedMonotonicMs = now;
    if (sample.sourceWait) {
      this.#window = validateBackupV2LeaseWindow({
        ...this.#window,
        retryEpisode: sample.sourceWait.retryEpisode,
        transferEpisode: sample.sourceWait.transferEpisode ?? null,
      });
    }
  }

  async #bounded<T>(
    run: (signal: AbortSignal) => Promise<T>,
    closing = false,
  ): Promise<T> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (!closing) {
      this.#abort.signal.addEventListener("abort", abort, { once: true });
    }
    if (!closing && this.#abort.signal.aborted) abort();
    const timer = setTimeout(abort, this.#options.operationTimeoutMs);
    let rejectAbort: () => void = () => {};
    this.#pending++;
    const operation = Promise.resolve().then(() => {
      controller.signal.throwIfAborted();
      return run(controller.signal);
    }).finally(() => this.#pending--);
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_, reject) => {
          rejectAbort = () =>
            reject(new Error("Bridge operation did not settle"));
          controller.signal.addEventListener("abort", rejectAbort, {
            once: true,
          });
          if (controller.signal.aborted) rejectAbort();
        }),
      ]);
    } finally {
      clearTimeout(timer);
      this.#abort.signal.removeEventListener("abort", abort);
      controller.signal.removeEventListener("abort", rejectAbort);
    }
  }

  async #close(): Promise<void> {
    this.#state = "CANCELLATION_BLOCKED";
    try {
      const closureStarted = this.#time();
      if (!this.#notifierClosed) {
        this.#notifierClosed = true;
        try {
          // STOPPING starts systemd's stop path and bypasses RemainAfterExit.
          // A successful terminal helper exits normally to retain custody.
          if (this.#reason !== "TERMINAL") this.#caps.notifier.stopping();
        } catch { /* Still close stdin. */ }
        try {
          this.#caps.notifier.close();
        } catch { /* No more renewal. */ }
      }
      if (!this.#ownsTunnel && this.#caps.tunnel.current() !== null) return;
      if (this.#ownsTunnel) {
        await this.#bounded(() => this.#caps.tunnel.close(), true);
      }
      const proof = await this.#bounded(
        (signal) => this.#caps.observeClosure(signal),
        true,
      );
      if (
        !sameIdentity(this.#keeper, proof.keeper) ||
        !sameBinding(this.#binding, proof.binding)
      ) return;
      this.#fresh(proof.observedMonotonicMs, this.#time());
      if (proof.observedMonotonicMs < closureStarted) return;
      if (
        this.#pending !== 0 || this.#caps.tunnel.current() !== null ||
        proof.sshProcesses !== 0 || proof.openStdinHandles !== 0 ||
        proof.remoteSocketPresent !== false ||
        proof.defaultSocketUnchanged !== true
      ) return;
      this.#state = "CLOSED";
    } catch {
      // Unknown transport/tree/socket facts retain custody; never clear a gate.
    }
  }
}
