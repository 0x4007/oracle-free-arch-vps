/** Real Pi bridge executable and bounded controller reconciliation. Bulk data
 * never enters this module; only the existing GPG-agent SSH protocol does. */
import type {
  PiDeps,
  RemoteRunner,
  TunnelChildFactory,
  TunnelSeam,
} from "./backblaze-file-backup.ts";
import type { BackupV2WorkerSettings } from "./backup-v2-worker.ts";
import {
  type BackupV2Gate,
  type BackupV2Status,
  validateBackupV2Gate,
  validateBackupV2Status,
} from "./backup-v2-runtime-contract.ts";
import {
  type BackupV2BridgeBinding,
  BackupV2BridgeKeeper,
  type BackupV2BridgeStatus,
  backupV2BridgeUnitProperties,
} from "./backup-v2-bridge.ts";
import {
  backupV2ChildEnvironment,
  type BackupV2Notifier,
  type BackupV2SupervisorIdentity,
  encodeBackupV2Notification,
} from "./backup-v2-supervisor.ts";
import { shellQuote } from "./backup-guest.ts";
import { DEFAULT_GATE_PATH } from "./backblaze-controller-gate.ts";
import { createHash } from "node:crypto";
import {
  type BackupV2LeaseWindow,
  validateBackupV2LeaseWindow,
} from "./backup-v2-contract.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";

const MAX = 64 * 1024;
const LIBRARY = "/lib/aarch64-linux-gnu/libsystemd.so.0";
const encoder = new TextEncoder();
const environment = () => ({
  clearEnv: true as const,
  env: backupV2ChildEnvironment({
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LC_ALL: "C",
    LANG: "C",
  }),
});
const bytes = (value: unknown) => encoder.encode(JSON.stringify(value) + "\n");

/** The first observation fixes each source episode's local expiry. Later
 * heartbeats, network delays or wall-clock corrections cannot extend it. */
export function createBackupV2BridgeWaitProjection() {
  const seen = new Map<
    string,
    { signature: string; startedAtMs: number; expiresAtMs: number }
  >();
  const hash = (value: unknown) =>
    createHash("sha256").update(JSON.stringify(value)).digest("hex");
  return (
    status: BackupV2Status,
    wallNow: Date,
    localNow: number,
  ): Pick<BackupV2LeaseWindow, "retryEpisode" | "transferEpisode"> => {
    const lease = validateBackupV2LeaseWindow(status.lease);
    const age = wallNow.getTime() - Date.parse(status.updatedAtUtc);
    if (
      !Number.isFinite(age) || age < -5000 || age > 90_000 ||
      !Number.isFinite(localNow) || localNow < 0
    ) fail();
    const project = (
      key: string,
      value: { startedAtMs: number; expiresAtMs: number },
    ) => {
      const signature = hash(value), id = hash(key), previous = seen.get(id);
      if (previous && previous.signature !== signature) fail();
      // Deduct status age and the permitted clock skew rather than crediting it.
      const elapsed = lease.observedMonotonicMs - value.startedAtMs +
        Math.max(0, age) + 5000;
      const remaining = value.expiresAtMs - lease.observedMonotonicMs -
        Math.max(0, age) - 5000;
      // Round inward: fractional clock subtraction must never widen a window.
      const expiresAtMs = Math.max(0, Math.floor(localNow + remaining));
      if (!previous && seen.size >= BACKUP_V2_LIMITS.physicalPuts * 3) fail();
      const result = previous
        ? {
          ...previous,
          expiresAtMs: Math.min(previous.expiresAtMs, expiresAtMs),
        }
        : {
          signature,
          startedAtMs: Math.max(0, Math.ceil(localNow - elapsed)),
          expiresAtMs,
        };
      result.startedAtMs = Math.min(result.startedAtMs, result.expiresAtMs);
      seen.set(id, result);
      return {
        startedAtMs: result.startedAtMs,
        expiresAtMs: result.expiresAtMs,
      };
    };
    return {
      retryEpisode: lease.retryEpisode
        ? project(`retry/${lease.retryEpisode.startedAtMs}`, lease.retryEpisode)
        : null,
      transferEpisode: lease.transferEpisode
        ? {
          ...lease.transferEpisode,
          ...project(
            `transfer/${lease.transferEpisode.operationId}`,
            lease.transferEpisode,
          ),
        }
        : null,
    };
  };
}
function fail(): never {
  throw new Error("Bridge runtime custody or transport is unproved");
}
function properties(text: string): Record<string, string> {
  return Object.fromEntries(
    text.trim().split("\n").filter(Boolean).map((line) => {
      const at = line.indexOf("=");
      if (at < 1) fail();
      return [line.slice(0, at), line.slice(at + 1)];
    }),
  );
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
function sameGate(a: BackupV2Gate, b: BackupV2Gate): boolean {
  return a.envelope.requestSha256 === b.envelope.requestSha256 &&
    a.gateId === b.gateId && a.sourceBootId === b.sourceBootId &&
    a.unitName === b.unitName && !!a.custody && !!b.custody &&
    sameIdentity(a.custody, b.custody);
}
async function hash(value: Uint8Array): Promise<string> {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", value as BufferSource),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
}
function active(input: BackupV2Gate): BackupV2Gate {
  const gate = validateBackupV2Gate(input);
  if (gate.kind !== "verify" || !gate.custody) fail();
  return gate;
}
export function backupV2BridgeRuntimePaths(input: BackupV2Gate) {
  const gate = active(input),
    directory =
      `.private/file-backup/jobs/${gate.envelope.request.jobId}/bridge-${gate.gateId}`;
  return {
    directory,
    settings: `${directory}/settings.json`,
    entry: `${directory}/entry.ts`,
    status: `${directory}/status.json`,
    close: `${directory}/close.json`,
    settled: `${directory}/settled.json`,
    unitName: `arch-vps-b2-bridge-${
      gate.envelope.request.jobId.slice(4)
    }-${gate.gateId}.service`,
  };
}
export interface BackupV2BridgeRuntimeInput {
  schemaVersion: 1;
  format: "backup-v2-bridge-runtime";
  gate: BackupV2Gate;
  binding: BackupV2BridgeBinding;
  sourceDirectory: string;
  defaultSocketIdentity: string;
}
interface SavedStatus {
  schemaVersion: 1;
  inputSha256: string;
  keeperBootId: string;
  updatedAtUtc: string;
  bridge: BackupV2BridgeStatus;
}
interface Unit {
  props: Record<string, string>;
  boot: string;
  identity: BackupV2SupervisorIdentity | null;
  empty: boolean;
}
type Pi = Pick<PiDeps, "private" | "remote" | "now">;
const defaultRunner: RemoteRunner = async (...args) =>
  (await import("./backblaze-file-backup.ts")).realRemoteRunner(...args);
async function checked(
  run: RemoteRunner,
  command: string,
  args: string[],
  input?: Uint8Array,
): Promise<string> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      run(command, args, input),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Bridge control deadline")),
          65_000,
        );
      }),
    ]);
    if (
      result.code !== 0 || encoder.encode(result.stdout).length > MAX ||
      encoder.encode(result.stderr).length > MAX
    ) fail();
    return result.stdout;
  } finally {
    clearTimeout(timer);
  }
}
/** Explicit user-manager address; the approved runner strips inherited env. */
export async function backupV2BridgeUserRunner(
  run: RemoteRunner,
): Promise<RemoteRunner> {
  const uid = (await checked(run, "/usr/bin/id", ["-u"])).trim();
  if (!/^[1-9][0-9]{0,9}$/.test(uid)) fail();
  return (_command, args, input) =>
    run("/usr/bin/env", [
      `XDG_RUNTIME_DIR=/run/user/${uid}`,
      `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus`,
      _command,
      ...args,
    ], input);
}
async function localUnit(
  run: RemoteRunner,
  name: string,
  expected?: BackupV2SupervisorIdentity,
): Promise<Unit> {
  if (!/^arch-vps-b2-bridge-[a-f0-9-]+\.service$/.test(name)) fail();
  const props = properties(
    await checked(run, "/usr/bin/systemctl", [
      "--user",
      "show",
      name,
      "--property=LoadState",
      "--property=ActiveState",
      "--property=SubState",
      "--property=Result",
      "--property=MainPID",
      "--property=ControlPID",
      "--property=InvocationID",
      "--property=ControlGroup",
    ]),
  );
  const boot =
    (await checked(run, "/usr/bin/cat", ["/proc/sys/kernel/random/boot_id"]))
      .trim();
  if (!/^[a-f0-9-]{36}$/.test(boot)) fail();
  const pid = Number(props.MainPID);
  let identity: BackupV2SupervisorIdentity | null = null;
  if (pid > 0) {
    if (
      !Number.isSafeInteger(pid) ||
      !/^[a-f0-9]{32}$/.test(props.InvocationID) ||
      !props.ControlGroup?.startsWith("/user.slice/") ||
      !props.ControlGroup.endsWith(`/${name}`)
    ) fail();
    const process = await checked(run, "/usr/bin/cat", [`/proc/${pid}/stat`]);
    if (
      (await checked(run, "/usr/bin/cat", [`/proc/${pid}/cgroup`])).trim() !==
        `0::${props.ControlGroup}`
    ) fail();
    identity = {
      unitName: name,
      invocationId: props.InvocationID,
      mainPid: pid,
      mainStartTicks:
        process.slice(process.lastIndexOf(")") + 2).trim().split(/\s+/)[19],
      cgroup: props.ControlGroup,
    };
  }
  const cgroup = expected?.cgroup ?? identity?.cgroup;
  let empty = false;
  if (cgroup) {
    if (
      !cgroup.startsWith("/user.slice/") || !cgroup.endsWith(`/${name}`) ||
      /[\0\r\n]|\/\.\.?\//.test(cgroup)
    ) fail();
    const path = `/sys/fs/cgroup${cgroup}`;
    const output = await checked(run, "/bin/sh", [
      "-c",
      `if test -d ${shellQuote(path)}; then cat ${
        shellQuote(path + "/cgroup.events")
      }; else printf 'ABSENT\\n'; fi`,
    ]);
    empty = output.trim() === "ABSENT" || /^populated 0$/m.test(output);
  }
  return { props, boot, identity, empty };
}
export function backupV2BridgeSourceProgram(
  input: BackupV2BridgeRuntimeInput,
): string {
  const gate = active(input.gate),
    id = gate.custody!,
    directory = input.sourceDirectory;
  if (
    !directory.startsWith("/var/tmp/arch-vps-file-backup/") ||
    directory.includes("..") || /[\r\n\0]/.test(directory)
  ) fail();
  return [
    "set -eu",
    `test "$(cat /proc/sys/kernel/random/boot_id)" = ${
      shellQuote(gate.sourceBootId)
    }`,
    "printf '__PROPS__\\n'",
    `systemctl show ${
      shellQuote(gate.unitName)
    } --property=LoadState --property=ActiveState --property=SubState --property=Result --property=MainPID --property=ControlPID --property=InvocationID --property=ControlGroup`,
    "printf '__PROCESS__\\n'",
    `if test -r /proc/${id.mainPid}/stat; then cat /proc/${id.mainPid}/stat; cat /proc/${id.mainPid}/cgroup; fi`,
    "printf '__CGROUP__\\n'",
    `if test -d ${shellQuote("/sys/fs/cgroup" + id.cgroup)}; then cat ${
      shellQuote("/sys/fs/cgroup" + id.cgroup + "/cgroup.events")
    }; else printf 'ABSENT\\n'; fi`,
    "printf '__STATUS__\\n'",
    `d=${shellQuote(directory)}`,
    'test "$(realpath "$d")" = "$d"',
    'test ! -L "$d" && test -d "$d"',
    'test "$(stat -c %u:%a "$d")" = 0:700',
    's="$d/status.json"',
    'test ! -L "$s" && test -f "$s"',
    'test "$(stat -c %u:%a:%h "$s")" = 0:600:1',
    'test "$(stat -c %s "$s")" -le 65536',
    'cat "$s"',
    "printf '__RESULT__\\n'",
    'r="$d/result.json"',
    'if test -f "$r" && test ! -L "$r"; then test "$(stat -c %u:%a:%h "$r")" = 0:600:1; test "$(stat -c %s "$r")" -le 65536; sha256sum "$r" | cut -d\' \' -f1; else printf "MISSING\\n"; fi',
    "printf '__SOCKETS__\\n'",
    `if test -S ${
      shellQuote(input.binding.remoteSocket)
    }; then printf 'CUSTOM_PRESENT\\n'; else printf 'CUSTOM_ABSENT\\n'; fi`,
    `if test -e ${
      shellQuote(input.binding.defaultSocket)
    }; then stat -c '%d:%i:%u:%a:%F' ${
      shellQuote(input.binding.defaultSocket)
    }; else printf 'ABSENT\\n'; fi`,
  ].join("\n");
}
export function decodeBackupV2BridgeSource(
  text: string,
  input: BackupV2BridgeRuntimeInput,
  now: Date,
): {
  status: BackupV2Status;
  terminal: boolean;
  cancelled: boolean;
  socketPresent: boolean;
  defaultIdentity: string;
} {
  const parts = text.split(
    /__(?:PROPS|PROCESS|CGROUP|STATUS|RESULT|SOCKETS)__\n/,
  );
  if (parts.length !== 7 || parts[0] !== "") fail();
  const gate = active(input.gate),
    id = gate.custody!,
    props = properties(parts[1]);
  if (props.LoadState !== "loaded" || props.InvocationID !== id.invocationId) {
    fail();
  }
  const status = validateBackupV2Status(JSON.parse(parts[4].trim()), gate);
  const empty = parts[3].trim() === "ABSENT" || /^populated 0$/m.test(parts[3]);
  const settled = ["exited", "failed"].includes(props.SubState) &&
    props.MainPID === "0" && props.ControlPID === "0" && empty;
  const age = now.getTime() - Date.parse(status.updatedAtUtc);
  if (!Number.isFinite(age) || age < -5000 || !settled && age > 90_000) fail();
  const terminal = settled;
  if (settled) {
    if (
      status.phase === "ACCEPTED" &&
      (props.Result !== "success" || parts[5].trim() !== status.resultSha256)
    ) fail();
  } else {
    const process = parts[2].trim().split("\n");
    if (
      Number(props.MainPID) !== id.mainPid ||
      props.ControlGroup !== id.cgroup || process.length !== 2 ||
      process[0].slice(process[0].lastIndexOf(")") + 2).trim().split(
          /\s+/,
        )[19] !== id.mainStartTicks ||
      process[1] !== `0::${id.cgroup}`
    ) fail();
  }
  const sockets = parts[6].trim().split("\n");
  if (
    sockets.length !== 2 ||
    !["CUSTOM_PRESENT", "CUSTOM_ABSENT"].includes(sockets[0])
  ) fail();
  return {
    status,
    terminal,
    cancelled: status.phase === "FAILED" ||
      status.phase === "CANCELLATION_BLOCKED" ||
      settled && status.phase !== "ACCEPTED",
    socketPresent: sockets[0] === "CUSTOM_PRESENT",
    defaultIdentity: sockets[1],
  };
}
function verifyInput(value: unknown): BackupV2BridgeRuntimeInput {
  if (!value || typeof value !== "object") fail();
  const input = value as BackupV2BridgeRuntimeInput,
    gate = active(input.gate),
    id = gate.custody!;
  if (
    input.schemaVersion !== 1 || input.format !== "backup-v2-bridge-runtime" ||
    input.binding.jobId !== gate.envelope.request.jobId ||
    input.binding.captureId !== gate.envelope.request.captureId ||
    input.binding.requestSha256 !== gate.envelope.requestSha256 ||
    input.binding.gateId !== gate.gateId ||
    input.binding.source.sourceBootId !== gate.sourceBootId ||
    !sameIdentity(input.binding.source, id) ||
    typeof input.defaultSocketIdentity !== "string" ||
    input.defaultSocketIdentity.length > 256
  ) fail();
  return input;
}
function statusBinding(
  input: BackupV2BridgeRuntimeInput,
  value: SavedStatus,
): void {
  verifyInput({ ...input, binding: value.bridge.binding });
  if (
    value.schemaVersion !== 1 ||
    value.bridge.binding.publicHome !== input.binding.publicHome ||
    value.bridge.binding.remoteSocket !== input.binding.remoteSocket ||
    value.bridge.binding.defaultSocket !== input.binding.defaultSocket ||
    value.bridge.keeper.unitName !==
      backupV2BridgeRuntimePaths(input.gate).unitName ||
    !Number.isSafeInteger(value.bridge.pendingOperations) ||
    value.bridge.pendingOperations < 0
  ) fail();
}
async function immutable(
  io: PiDeps["private"],
  path: string,
  content: Uint8Array,
): Promise<void> {
  const prior = await io.readBytes(path, MAX);
  if (prior) { if (await hash(prior) !== await hash(content)) fail(); }
  else await io.writeBytes(path, content);
}
export function backupV2BridgeEntrypoint(base: string, path: string): string {
  const root = new URL(base);
  if (
    root.protocol !== "file:" || !root.pathname.endsWith("/scripts/") ||
    !path.startsWith(".private/file-backup/jobs/") || path.includes("..")
  ) fail();
  return [
    `import {runBackupV2BridgeRuntime} from ${
      JSON.stringify(new URL("backup-v2-bridge-runtime.ts", root).href)
    };`,
    `import {realPrivateSeam,realRemoteSeam,realRemoteRunner,realTunnelSeam,PI_KEYRING_PATH} from ${
      JSON.stringify(new URL("backblaze-file-backup.ts", root).href)
    };`,
    `import {backupV2GateDirectory} from ${
      JSON.stringify(new URL("backup-v2-worker.ts", root).href)
    };`,
    `try { await runBackupV2BridgeRuntime(${
      JSON.stringify(path)
    },{private:realPrivateSeam(),remote:realRemoteSeam(realRemoteRunner),gateDirectory:backupV2GateDirectory,tunnel:(factory)=>realTunnelSeam(realRemoteRunner,PI_KEYRING_PATH,factory)}); } catch { Deno.exitCode=1; }`,
    "",
  ].join("\n");
}
export function backupV2BridgeRuntimeCommand(
  input: BackupV2BridgeRuntimeInput,
  cwd: string,
): string[] {
  const paths = backupV2BridgeRuntimePaths(input.gate);
  if (cwd !== "/home/pi/ops/weekly-backup-controller") fail();
  return [
    "/usr/bin/systemd-run",
    "--user",
    `--unit=${paths.unitName}`,
    ...Object.entries({
      ...backupV2BridgeUnitProperties(60_000),
      MemorySwapMax: "0",
      WorkingDirectory: cwd,
      UMask: "0077",
      Environment: `DENO_DIR=${cwd}/${paths.directory}/cache`,
      StandardOutput: "null",
      StandardError: "null",
    }).map(([key, value]) => `--property=${key}=${value}`),
    "/usr/local/bin/deno",
    "run",
    "--no-config",
    "--no-lock",
    "--cached-only",
    "--allow-read=.,.private",
    "--allow-write=.private",
    "--allow-run=ssh,gpgconf,/usr/bin/cat,/usr/bin/id,/bin/sh,/usr/bin/env,/usr/bin/systemctl",
    "--allow-env=NOTIFY_SOCKET,INVOCATION_ID",
    `--allow-ffi=${LIBRARY}`,
    paths.entry,
  ];
}

/** Native user manager adapter. Dynamic legacy imports occur only when an
 * already initialized controller invokes a method, avoiding evaluation cycles. */
export function realBackupV2BridgeRuntime(
  deps: Pi,
  runner: RemoteRunner = defaultRunner,
) {
  const source = async (input: BackupV2BridgeRuntimeInput) => {
    const result = await deps.remote.root(backupV2BridgeSourceProgram(input));
    if (result.code !== 0 || encoder.encode(result.stdout).length > MAX) fail();
    return decodeBackupV2BridgeSource(result.stdout, input, deps.now());
  };
  const context = async () => ({
    legacy: await import("./backblaze-file-backup.ts"),
    worker: await import("./backup-v2-worker.ts"),
    run: await backupV2BridgeUserRunner(runner),
  });
  async function saved(
    gate: BackupV2Gate,
  ): Promise<BackupV2BridgeRuntimeInput | undefined> {
    const value = await deps.private.read<unknown>(
      backupV2BridgeRuntimePaths(gate).settings,
    );
    if (value === undefined) return undefined;
    const input = verifyInput(value);
    if (!sameGate(input.gate, gate)) fail();
    return input;
  }
  return {
    async ensure(
      settings: BackupV2WorkerSettings,
      gateInput: BackupV2Gate,
    ): Promise<"READY" | "PENDING" | "CANCELLATION_BLOCKED"> {
      try {
        const gate = active(gateInput),
          paths = backupV2BridgeRuntimePaths(gate),
          ctx = await context();
        if (gate.state !== "ACTIVE") fail();
        ctx.worker.validateBackupV2WorkerSettings(settings);
        if (
          settings.envelope.requestSha256 !== gate.envelope.requestSha256 ||
          settings.verifierGate.gateId !== gate.gateId
        ) fail();
        let input = await saved(gate),
          unit = await localUnit(ctx.run, paths.unitName);
        if (!input) {
          if (unit.props.LoadState !== "not-found") fail();
          const publicHome =
              `${ctx.legacy.PUBLIC_HOME_BASE}/${gate.envelope.request.captureId}`,
            sockets = await deps.remote.resolveAgentSocket(publicHome);
          input = {
            schemaVersion: 1,
            format: "backup-v2-bridge-runtime",
            gate,
            binding: {
              jobId: gate.envelope.request.jobId,
              captureId: gate.envelope.request.captureId,
              requestSha256: gate.envelope.requestSha256,
              gateId: gate.gateId,
              source: { ...gate.custody!, sourceBootId: gate.sourceBootId },
              publicHome,
              remoteSocket: sockets.socket,
              defaultSocket: sockets.defaultSocket,
            },
            sourceDirectory: ctx.worker.backupV2GateDirectory(gate),
            defaultSocketIdentity: "",
          };
          const initial = await source(input);
          if (initial.terminal || initial.cancelled || initial.socketPresent) {
            fail();
          }
          input.defaultSocketIdentity = initial.defaultIdentity;
          await immutable(deps.private, paths.settings, bytes(input));
          const base =
            `file://${ctx.legacy.PI_CONTROLLER_CWD}/.private/file-backup/runtime/releases/${gate.envelope.request.sourceRevision}/scripts/`;
          await immutable(
            deps.private,
            paths.entry,
            encoder.encode(backupV2BridgeEntrypoint(base, paths.settings)),
          );
          await checked(
            ctx.run,
            "/usr/local/bin/safepi",
            backupV2BridgeRuntimeCommand(input, ctx.legacy.PI_CONTROLLER_CWD),
          );
          unit = await localUnit(ctx.run, paths.unitName);
        }
        const status = await deps.private.read<SavedStatus>(paths.status);
        if (!status) return unit.identity ? "PENDING" : "CANCELLATION_BLOCKED";
        statusBinding(input, status);
        if (
          status.inputSha256 !== await hash(bytes(input)) ||
          status.keeperBootId !== unit.boot ||
          status.bridge.keeper.unitName !== paths.unitName
        ) fail();
        const current = await source(input);
        if (current.defaultIdentity !== input.defaultSocketIdentity) fail();
        if (
          current.terminal && !current.cancelled &&
          status.bridge.state === "CLOSED" &&
          status.bridge.reason === "TERMINAL" &&
          status.bridge.pendingOperations === 0 &&
          unit.props.InvocationID === status.bridge.keeper.invocationId &&
          unit.props.MainPID === "0" && unit.props.ControlPID === "0" &&
          (await localUnit(ctx.run, paths.unitName, status.bridge.keeper))
            .empty &&
          !current.socketPresent
        ) return "READY";
        const age = deps.now().getTime() - Date.parse(status.updatedAtUtc);
        if (
          current.terminal && !current.cancelled && unit.identity &&
          sameIdentity(status.bridge.keeper, unit.identity) &&
          ["ACTIVE", "CLOSED"].includes(status.bridge.state) &&
          Number.isFinite(age) && age >= -5000 && age <= 90_000
        ) return "PENDING";
        if (
          !unit.identity ||
          !sameIdentity(status.bridge.keeper, unit.identity) ||
          status.bridge.state !== "ACTIVE" || !Number.isFinite(age) ||
          age < -5000 || age > 90_000 || current.terminal ||
          current.cancelled || !current.socketPresent
        ) fail();
        return "READY";
      } catch {
        return "CANCELLATION_BLOCKED";
      }
    },
    async close(
      gateInput: BackupV2Gate,
    ): Promise<"CLOSED" | "CANCELLATION_BLOCKED"> {
      try {
        const gate = active(gateInput),
          paths = backupV2BridgeRuntimePaths(gate),
          input = await saved(gate),
          ctx = await context();
        if (!input) fail();
        const status = await deps.private.read<SavedStatus>(paths.status);
        if (!status || status.inputSha256 !== await hash(bytes(input))) fail();
        statusBinding(input, status);
        const prior = await deps.private.read<
          {
            identity: BackupV2SupervisorIdentity;
            boot: string;
            inputSha256: string;
          }
        >(paths.settled);
        let unit = await localUnit(
          ctx.run,
          paths.unitName,
          status.bridge.keeper,
        );
        if (
          prior && prior.boot === unit.boot &&
          prior.inputSha256 === status.inputSha256 &&
          sameIdentity(prior.identity, status.bridge.keeper) &&
          unit.props.LoadState === "not-found" && unit.empty
        ) return "CLOSED";
        if (
          unit.boot !== status.keeperBootId ||
          unit.props.InvocationID !== status.bridge.keeper.invocationId
        ) fail();
        if (status.bridge.state !== "CLOSED") {
          const remote = await source(input);
          if (remote.terminal && !remote.cancelled) {
            return "CANCELLATION_BLOCKED";
          }
          await immutable(
            deps.private,
            paths.close,
            bytes({
              gateId: gate.gateId,
              requestSha256: gate.envelope.requestSha256,
              custody: gate.custody,
            }),
          );
          return "CANCELLATION_BLOCKED";
        }
        if (
          unit.props.MainPID !== "0" || unit.props.ControlPID !== "0" ||
          !unit.empty || !["exited", "failed"].includes(unit.props.SubState)
        ) fail();
        const remote = await source(input);
        if (
          !remote.terminal || remote.socketPresent ||
          remote.defaultIdentity !== input.defaultSocketIdentity
        ) fail();
        await checked(ctx.run, "/bin/sh", [
          "-c",
          `test "$(systemctl --user show ${
            shellQuote(paths.unitName)
          } --property=InvocationID --value)" = ${
            shellQuote(status.bridge.keeper.invocationId)
          } && systemctl --user stop ${shellQuote(paths.unitName)}`,
        ]);
        unit = await localUnit(ctx.run, paths.unitName, status.bridge.keeper);
        if (
          unit.props.MainPID !== "0" || unit.props.ControlPID !== "0" ||
          !unit.empty
        ) fail();
        await deps.private.write(paths.settled, {
          identity: status.bridge.keeper,
          boot: unit.boot,
          inputSha256: status.inputSha256,
        });
        return "CLOSED";
      } catch {
        return "CANCELLATION_BLOCKED";
      }
    },
  };
}

async function strictRead(path: string): Promise<Uint8Array> {
  const info = await Deno.lstat(path),
    parent = await Deno.lstat(path.slice(0, path.lastIndexOf("/")));
  if (
    !info.isFile || info.isSymlink || info.nlink !== 1 ||
    info.uid !== parent.uid || info.mode === null ||
    (info.mode & 0o777) !== 0o600 || info.size > MAX || parent.isSymlink ||
    !parent.isDirectory || parent.mode === null ||
    (parent.mode & 0o777) !== 0o700
  ) fail();
  const data = await Deno.readFile(path), after = await Deno.lstat(path);
  if (
    data.length !== info.size || after.dev !== info.dev ||
    after.ino !== info.ino || after.size !== info.size
  ) fail();
  return data;
}
function notifier(): BackupV2Notifier {
  if (!Deno.env.get("NOTIFY_SOCKET")) fail();
  const library = Deno.dlopen(LIBRARY, {
    sd_notify: { parameters: ["i32", "buffer"], result: "i32" },
  });
  const send = (message: Parameters<typeof encodeBackupV2Notification>[0]) => {
    if (
      library.symbols.sd_notify(0, encodeBackupV2Notification(message)) <= 0
    ) fail();
  };
  return {
    ready: () => send({ kind: "ready" }),
    extend: (usec) => send({ kind: "extend", usec }),
    stopping: () => send({ kind: "stopping" }),
    close: () => library.close(),
  };
}
export interface BackupV2BridgeRunnerDependencies {
  private: PiDeps["private"];
  remote: PiDeps["remote"];
  gateDirectory(gate: BackupV2Gate): string;
  tunnel(factory: TunnelChildFactory): TunnelSeam;
}
/** The generated executable calls this function directly; no interface-only
 * fallback. Own SSH stdin and its actual child statuses until proved closed. */
export async function runBackupV2BridgeRuntime(
  path: string,
  deps: BackupV2BridgeRunnerDependencies,
): Promise<void> {
  const inputBytes = await strictRead(path),
    input = verifyInput(JSON.parse(new TextDecoder().decode(inputBytes))),
    paths = backupV2BridgeRuntimePaths(input.gate);
  if (
    path !== paths.settings ||
    deps.gateDirectory(input.gate) !== input.sourceDirectory ||
    Deno.cwd() !== "/home/pi/ops/weekly-backup-controller"
  ) fail();
  const run = await backupV2BridgeUserRunner(defaultRunner),
    initial = await localUnit(run, paths.unitName),
    keeper = initial.identity;
  if (
    !keeper || keeper.mainPid !== Deno.pid ||
    keeper.invocationId !== Deno.env.get("INVOCATION_ID")
  ) fail();
  const children: { pid: number; exited: boolean }[] = [];
  const tunnel = deps.tunnel((args) => {
    const child = new Deno.Command("ssh", {
      ...environment(),
      args,
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    const record = { pid: child.pid, exited: false };
    children.push(record);
    const status = child.status.then((value) => {
      record.exited = true;
      return value;
    });
    return {
      stdin: child.stdin,
      stdout: child.stdout,
      stderr: child.stderr,
      status,
    };
  });
  const source = async () => {
    const result = await deps.remote.root(backupV2BridgeSourceProgram(input));
    if (result.code !== 0 || encoder.encode(result.stdout).length > MAX) fail();
    return decodeBackupV2BridgeSource(result.stdout, input, new Date());
  };
  const observeKeeper = async () => {
    const current = await localUnit(run, paths.unitName);
    if (
      current.boot !== initial.boot || !current.identity ||
      !sameIdentity(keeper, current.identity)
    ) fail();
    return current.identity;
  };
  const projectWait = createBackupV2BridgeWaitProjection();
  const bridge = new BackupV2BridgeKeeper(keeper, input.binding, {
    notificationGraceMs: 60_000,
    progressGraceMs: 120_000,
    retryGraceMs: 6 * 3_600_000,
    operationTimeoutMs: 45_000,
    maximumObservationAgeMs: 5000,
  }, {
    now: () => performance.now(),
    notifier: notifier(),
    tunnel,
    observe: async () => {
      const identity = await observeKeeper(),
        gate = validateBackupV2Gate(
          JSON.parse(
            new TextDecoder().decode(await strictRead(DEFAULT_GATE_PATH)),
          ),
        );
      if (!sameGate(input.gate, gate)) fail();
      const remote = await source();
      if (remote.defaultIdentity !== input.defaultSocketIdentity) fail();
      let cancelled = gate.state !== "ACTIVE" || remote.cancelled;
      try {
        const request = JSON.parse(
          new TextDecoder().decode(await strictRead(paths.close)),
        );
        if (
          request.gateId !== gate.gateId ||
          request.requestSha256 !== gate.envelope.requestSha256 ||
          !sameIdentity(request.custody, gate.custody!)
        ) fail();
        cancelled = true;
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) throw error;
      }
      const { observedMonotonicMs: _remoteClock, ...progress } =
        remote.status.progress;
      // Final output can precede MainPID exit. Await exact settlement without
      // inventing useful work or renewing from the final status heartbeat.
      if (!remote.terminal && progress.phase === "ACCEPTED") {
        progress.phase = "VERIFYING";
      }
      return {
        keeper: identity,
        binding: input.binding,
        observedMonotonicMs: performance.now(),
        gate: remote.terminal && !cancelled
          ? "TERMINAL"
          : cancelled
          ? "CANCELLED"
          : "OWNED",
        progress,
        sourceWait: projectWait(remote.status, new Date(), performance.now()),
      };
    },
    observeClosure: async () => {
      const identity = await observeKeeper(),
        remote = await source(),
        alive = children.filter((child) => !child.exited).length;
      return {
        keeper: identity,
        binding: input.binding,
        observedMonotonicMs: performance.now(),
        sshProcesses: alive,
        openStdinHandles: alive,
        remoteSocketPresent: remote.socketPresent,
        defaultSocketUnchanged:
          remote.defaultIdentity === input.defaultSocketIdentity,
      };
    },
  });
  const save = (status: BackupV2BridgeStatus) =>
    deps.private.write(paths.status, {
      schemaVersion: 1,
      inputSha256: hashValue,
      keeperBootId: initial.boot,
      updatedAtUtc: new Date().toISOString(),
      bridge: status,
    });
  const hashValue = await hash(inputBytes);
  let status = await bridge.start();
  await save(status);
  while (status.state === "ACTIVE") {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    status = await bridge.poll();
    await save(status);
  }
  if (status.state === "CANCELLATION_BLOCKED") {
    // Keep MainPID present: a clean exit would disable RuntimeMaxSec while an
    // unproved child survives. The finite manager lease kills the owned tree.
    await new Promise((resolve) => setTimeout(resolve, 120_000));
    fail();
  }
  if (status.state !== "CLOSED" || status.reason !== "TERMINAL") fail();
}
