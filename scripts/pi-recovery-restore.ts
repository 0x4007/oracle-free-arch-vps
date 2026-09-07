/**
 * Pi-owned transport for a replacement RAM-rescue restore.
 *
 * This module moves only bounded control files and checkpoint JSON over the
 * pinned SSH connection. The target runs the restore executable and fetches
 * every encrypted archive directly from Backblaze. The Pi never receives an
 * archive byte; the existing private decryption key stays in the Pi keyring.
 */
import { createHash } from "node:crypto";
import { shellQuote } from "./backup-guest.ts";
import {
  machineRestoreIndexSha256,
  type MachineRestoreInput,
  type MachineRestoreResult,
  type MachineRestoreTarget,
  STAGES,
} from "./backblaze-machine-restore.ts";
import type { B2Settings } from "./backblaze-storage.ts";
import { validateCatalogEntry } from "./backblaze-file-backup.ts";
import {
  type DiskPreparationBinding,
  type DiskPreparationPlan,
  diskPreparationPlan,
  inspectPreparationDisks,
  type PreparationApproval,
  type PreparationEvent,
  prepareReplacementDisks,
} from "./pi-recovery-disk-preparation.ts";
import {
  type CheckpointBinding,
  CheckpointChannel,
  persistCheckpoint,
  type RecoveryCheckpoint,
} from "./pi-recovery-checkpoint.ts";
import {
  recoveryControlRunner,
  recoverySshArgs,
  recoverySshRunner,
  type RecoverySshTarget,
} from "./pi-recovery-ssh.ts";
import { type CommandRunner, readPrivateJson } from "./oci.ts";
import {
  type RecoveryIsolationInput,
  type RecoveryIsolationPlan,
  validateIsolationPlanDigest,
} from "./pi-recovery-isolation.ts";
import {
  type IsolationInspection,
  validateIsolationInspection,
} from "./pi-recovery-isolation-executor.ts";

export const RECOVERY_TARGET_ROOT = "/run/uos-recovery/restore";
export const RECOVERY_TARGET_PUBLIC_HOME = "/run/uos-recovery/gnupg";
export const RECOVERY_TARGET_CHECKPOINT =
  ".private/pi-recovery-checkpoint.json";
export const RECOVERY_TARGET_SOURCE_REVISION =
  ".private/recovery-source-manifest.json";

const REQUEST_PATTERN =
  /^recovery-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const REVISION_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const OCID_INSTANCE_PATTERN = /^ocid1\.instance\.[a-zA-Z0-9.]+$/;
const MAX_CONTROL_FILE_BYTES = 512 * 1024;
const MAX_CONTROL_BYTES = 2 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES = 256 * 1024;

export interface RecoveryTargetFile {
  path: string;
  mode: "0600" | "0644" | "0755";
  sha256: string;
  /** JSON-safe control bytes; this list must never contain an archive. */
  data: number[];
}

export interface RecoveryTargetBundle {
  schemaVersion: 1;
  requestId: string;
  instanceId: string;
  sourceRevision: string;
  publicHome: typeof RECOVERY_TARGET_PUBLIC_HOME;
  files: RecoveryTargetFile[];
}

export interface RecoveryTargetControlInput {
  catalog: unknown;
  requestId: string;
  loaderBootId: string;
  rescueManifestSha256: string;
  target: MachineRestoreTarget;
  publicHome: typeof RECOVERY_TARGET_PUBLIC_HOME;
  isolation?: RecoveryIsolationInput;
}

export interface RecoveryTargetSourceBundleOptions {
  sourceRoot: string;
  sourceRevision: string;
  input: RecoveryTargetControlInput;
  b2: B2Settings;
  recipientBytes: Uint8Array;
}

export interface RecoveryTargetProcess {
  stdin: WritableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
  status: Promise<Deno.CommandStatus>;
  /** Stop only the SSH child created by this factory. */
  terminate(): void;
}

export type RecoveryTargetProcessFactory = (
  command: string,
  args: string[],
) => RecoveryTargetProcess;

export interface RecoveryTargetInstallReceipt {
  status: "RECOVERY_TARGET_RUNTIME_INSTALLED";
  requestId: string;
  instanceId: string;
  sourceRevision: string;
  files: number;
  publicHome: typeof RECOVERY_TARGET_PUBLIC_HOME;
}

const INSTALL_OPERATION =
  "install the bound restore runtime, scoped Backblaze settings and public recipient on the replacement RAM filesystem and temporarily forward the Pi GPG extra socket for this restoration";
export interface RecoveryTargetInstallApproval {
  planSha256: string;
  exactOperation: string;
  approvedAtUtc: string;
}
export function recoveryTargetInstallPlan(
  target: RecoverySshTarget,
  bundle: RecoveryTargetBundle,
) {
  assertBundle(bundle);
  if (
    target.host.phase !== "ram" ||
    target.host.instanceId !== bundle.instanceId ||
    target.host.requestId !== bundle.requestId
  ) throw Error("Installer SSH target differs from the RAM recovery bundle");
  const input = JSON.parse(
    new TextDecoder().decode(Uint8Array.from(
      bundle.files.find((file) =>
        file.path === ".private/backblaze-machine-restore.json"
      )!.data,
    )),
  );
  if (input.rescueManifestSha256 !== target.host.manifestSha256) {
    throw Error("Installer manifest differs from pinned RAM evidence");
  }
  const body = {
    requestId: bundle.requestId,
    instanceId: bundle.instanceId,
    bootId: target.host.bootId,
    sourceRevision: bundle.sourceRevision,
    files: bundle.files.map(({ path, mode, sha256 }) => ({
      path,
      mode,
      sha256,
    })),
    operation: INSTALL_OPERATION,
  };
  return { ...body, planSha256: sha256(bytesOf(JSON.stringify(body))) };
}
function assertInstallApproval(
  plan: ReturnType<typeof recoveryTargetInstallPlan>,
  approval: RecoveryTargetInstallApproval,
) {
  const age = Date.now() - Date.parse(approval?.approvedAtUtc);
  if (
    !approval || approval.planSha256 !== plan.planSha256 ||
    approval.exactOperation !== plan.operation || !Number.isFinite(age) ||
    age < 0 || age > 3600000
  ) throw Error("Current exact runtime installation approval is required");
}

export interface RecoveryTargetInstallPorts {
  process?: RecoveryTargetProcessFactory;
}

export interface RecoveryRestorePorts {
  process?: RecoveryTargetProcessFactory;
  beforeCheckpoint?: () => Promise<void>;
  inspected?: (
    plan: RecoveryIsolationPlan,
    inspection: IsolationInspection,
  ) => Promise<void>;
  progress?: (
    value: { role: string; bytes: number; expectedBytes: number },
  ) => Promise<void>;
}

export interface RecoveryRestoreResult {
  result: MachineRestoreResult;
  checkpoints: RecoveryCheckpoint[];
  stderr: string;
  isolationPlan?: RecoveryIsolationPlan;
  isolationInspection?: IsolationInspection;
}

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

function bytesOf(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function fileFromBytes(
  path: string,
  mode: RecoveryTargetFile["mode"],
  bytes: Uint8Array,
): RecoveryTargetFile {
  if (bytes.byteLength > MAX_CONTROL_FILE_BYTES) {
    throw Error(`Recovery control file is too large: ${path}`);
  }
  return { path, mode, sha256: sha256(bytes), data: [...bytes] };
}

function fileFromText(
  path: string,
  mode: RecoveryTargetFile["mode"],
  text: string,
): RecoveryTargetFile {
  return fileFromBytes(path, mode, bytesOf(text));
}

function safeSourcePath(value: string): boolean {
  return /^scripts\/[A-Za-z0-9_.-]+\.ts$/.test(value);
}

function safeTargetFilePath(value: string): boolean {
  return safeSourcePath(value) ||
    value === ".private/backblaze-machine-restore.json" ||
    value === ".private/b2-file-backup.json" ||
    value === ".private/file-backup/recipient.asc" ||
    value === RECOVERY_TARGET_SOURCE_REVISION;
}

function assertRequestIdentity(input: RecoveryTargetControlInput): void {
  if (
    !REQUEST_PATTERN.test(input.requestId) ||
    !OCID_INSTANCE_PATTERN.test(input.target.targetId) ||
    input.target.targetId !== input.target.approval.targetId ||
    input.publicHome !== RECOVERY_TARGET_PUBLIC_HOME ||
    input.target.workDirectory !== "/run/uos-recovery"
  ) throw Error("Recovery target control identity is incomplete");
  if (!SHA256_PATTERN.test(input.rescueManifestSha256)) {
    throw Error("Recovery target manifest identity is malformed");
  }
}

function assertB2Settings(value: B2Settings): void {
  for (
    const key of [
      "accessKeyId",
      "secretAccessKey",
      "bucketId",
      "bucketName",
    ] as const
  ) {
    if (typeof value?.[key] !== "string" || value[key] === "") {
      throw Error("Scoped Backblaze settings are incomplete");
    }
  }
}

function assertRecipient(bytes: Uint8Array): void {
  if (bytes.byteLength === 0 || bytes.byteLength > 64 * 1024) {
    throw Error("Public recovery recipient is outside the control bound");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (
    !text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
    text.includes("PRIVATE KEY")
  ) throw Error("Recovery recipient is not public-only ASCII armor");
}

function assertBundle(bundle: RecoveryTargetBundle): void {
  if (
    bundle.schemaVersion !== 1 || !REQUEST_PATTERN.test(bundle.requestId) ||
    !OCID_INSTANCE_PATTERN.test(bundle.instanceId) ||
    !REVISION_PATTERN.test(bundle.sourceRevision) ||
    bundle.publicHome !== RECOVERY_TARGET_PUBLIC_HOME ||
    !Array.isArray(bundle.files) || bundle.files.length === 0
  ) throw Error("Recovery target bundle is malformed");
  let total = 0;
  const paths = new Set<string>();
  for (const file of bundle.files) {
    if (
      !safeTargetFilePath(file.path) || paths.has(file.path) ||
      !["0600", "0644", "0755"].includes(file.mode) ||
      !SHA256_PATTERN.test(file.sha256) || !Array.isArray(file.data) ||
      file.data.some((byte) =>
        !Number.isInteger(byte) || byte < 0 || byte > 255
      )
    ) throw Error("Recovery target bundle file is malformed");
    const bytes = Uint8Array.from(file.data);
    if (
      bytes.byteLength > MAX_CONTROL_FILE_BYTES || sha256(bytes) !== file.sha256
    ) {
      throw Error("Recovery target bundle file hash differs");
    }
    total += bytes.byteLength;
    if (total > MAX_CONTROL_BYTES) {
      throw Error("Recovery target control bundle exceeds its bound");
    }
    paths.add(file.path);
  }
  for (
    const required of [
      ".private/backblaze-machine-restore.json",
      ".private/b2-file-backup.json",
      ".private/file-backup/recipient.asc",
      RECOVERY_TARGET_SOURCE_REVISION,
    ]
  ) {
    if (!paths.has(required)) throw Error(`Recovery bundle lacks ${required}`);
  }
}

/** Build the source dependency closure without copying any archive payload. */
export async function buildRecoveryTargetBundle(
  options: RecoveryTargetSourceBundleOptions,
): Promise<RecoveryTargetBundle> {
  assertRequestIdentity(options.input);
  assertB2Settings(options.b2);
  assertRecipient(options.recipientBytes);
  if (!REVISION_PATTERN.test(options.sourceRevision)) {
    throw Error("Recovery source revision is malformed");
  }
  const root = await Deno.realPath(options.sourceRoot);
  // This receipt is retained by the guarded Pi installer. A caller-supplied
  // revision alone must never turn arbitrary working-tree bytes into a release.
  const release = await readPrivateJson<{
    sourceRevision: string;
    hashes: Record<string, string>;
  }>(`${root}/.private/reports/pi-session-deployment.json`);
  if (release.sourceRevision !== options.sourceRevision || !release.hashes) {
    throw Error("Recovery source revision differs from the installed release");
  }
  const catalog = validateCatalogEntry(options.input.catalog);
  if (sha256(options.recipientBytes) !== catalog.index.recipientSha256) {
    throw Error(
      "Recovery public recipient differs from the selected generation",
    );
  }
  const entry = "scripts/backblaze-stream-restore.ts";
  const queue = [entry];
  const seen = new Set<string>();
  const sourceFiles: RecoveryTargetFile[] = [];
  const importPattern = /(?:from\s*|import\s*\(\s*)["'](\.[^"']+\.ts)["']/g;
  while (queue.length > 0) {
    const relative = queue.shift()!;
    if (seen.has(relative)) continue;
    if (!safeSourcePath(relative)) {
      throw Error("Recovery source path is unsafe");
    }
    seen.add(relative);
    const absolute = `${root}/${relative}`;
    const info = await Deno.lstat(absolute);
    if (!info.isFile || info.isSymlink) {
      throw Error(`Recovery source module is not a regular file: ${relative}`);
    }
    const bytes = await Deno.readFile(absolute);
    if (release.hashes[relative] !== sha256(bytes)) {
      throw Error(
        `Recovery module differs from the installed release: ${relative}`,
      );
    }
    sourceFiles.push(fileFromBytes(relative, "0644", bytes));
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    for (const match of text.matchAll(importPattern)) {
      const imported = match[1];
      const resolved = imported.replace(/^\.\//, "scripts/");
      if (!safeSourcePath(resolved)) {
        throw Error(`Recovery source import is outside scripts: ${imported}`);
      }
      if (!seen.has(resolved)) queue.push(resolved);
    }
  }
  sourceFiles.sort((a, b) => a.path.localeCompare(b.path));
  const manifest = {
    schemaVersion: 1,
    sourceRevision: options.sourceRevision,
    files: sourceFiles.map(({ path, sha256 }) => ({ path, sha256 })),
  };
  const input = structuredClone(options.input);
  const targetInput = JSON.stringify(input);
  const files = [
    ...sourceFiles,
    fileFromText(
      ".private/backblaze-machine-restore.json",
      "0600",
      `${targetInput}\n`,
    ),
    fileFromText(
      ".private/b2-file-backup.json",
      "0600",
      `${JSON.stringify(options.b2)}\n`,
    ),
    fileFromBytes(
      ".private/file-backup/recipient.asc",
      "0644",
      options.recipientBytes,
    ),
    fileFromText(
      RECOVERY_TARGET_SOURCE_REVISION,
      "0644",
      `${JSON.stringify(manifest)}\n`,
    ),
  ];
  const bundle: RecoveryTargetBundle = {
    schemaVersion: 1,
    requestId: options.input.requestId,
    instanceId: options.input.target.targetId,
    sourceRevision: options.sourceRevision,
    publicHome: RECOVERY_TARGET_PUBLIC_HOME,
    files,
  };
  assertBundle(bundle);
  return bundle;
}

/** Root-side installer. It accepts only the bounded control bundle above. */
export const recoveryTargetInstallerScript = String.raw`
const parts = []; let inputBytes = 0;
for await (const part of Deno.stdin.readable) {
  inputBytes += part.length;
  if (inputBytes > 16 * 1024 * 1024) throw new Error("Recovery control envelope exceeds its bound");
  parts.push(part);
}
const joined = new Uint8Array(inputBytes); let offset = 0;
for (const part of parts) { joined.set(part, offset); offset += part.length; }
const payload = JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(joined));
if (payload?.schemaVersion !== 1 || typeof payload.requestId !== "string" || typeof payload.instanceId !== "string" || typeof payload.sourceRevision !== "string" || payload.publicHome !== "/run/uos-recovery/gnupg" || !Array.isArray(payload.files)) throw new Error("Recovery target bundle is malformed");
const root = "/run/uos-recovery/restore";
const owner = 1000;
const group = 1000;
const paths = new Set();
const safe = (path) => /^scripts\/[A-Za-z0-9_.-]+\.ts$/.test(path) || path === ".private/backblaze-machine-restore.json" || path === ".private/b2-file-backup.json" || path === ".private/file-backup/recipient.asc" || path === ".private/recovery-source-manifest.json";
const digest = async (bytes) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
const ensureDir = async (path, mode) => {
  await Deno.mkdir(path, { recursive: true, mode });
  const info = await Deno.lstat(path);
  if (!info.isDirectory || info.isSymlink || (info.mode & 0o777) !== mode || await Deno.realPath(path) !== path) throw new Error("Unsafe recovery target directory");
  await Deno.chown(path, owner, group);
};
// Refuse a source host, stale boot or disk-backed workspace before any write.
if (Deno.build.os !== "linux" || Deno.build.arch !== "aarch64" || Deno.uid() !== 0) throw new Error("Installer requires the approved AArch64 rescue");
const accounts = (await Deno.readTextFile("/etc/passwd")).split("\n").filter(line => line.startsWith("codex:")).map(line => line.split(":"));
const groups = (await Deno.readTextFile("/etc/group")).split("\n").filter(line => line.startsWith("codex:")).map(line => line.split(":"));
if (accounts.length !== 1 || groups.length !== 1 || accounts[0][2] !== String(owner) || accounts[0][3] !== String(group) || groups[0][2] !== String(group) || accounts[0][5] !== "/home/codex" || accounts[0][6] !== "/bin/bash") throw new Error("Installer codex identity differs from the approved rescue bootstrap");
const inputFile = payload.files.filter(file => file.path === ".private/backblaze-machine-restore.json");
if (inputFile.length !== 1 || !Array.isArray(inputFile[0].data) || inputFile[0].data.length > 524288) throw new Error("Missing bounded target control input");
const restore = JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(Uint8Array.from(inputFile[0].data)));
if (restore.requestId !== payload.requestId || restore.target?.targetId !== payload.instanceId || restore.publicHome !== payload.publicHome || restore.target.workDirectory !== "/run/uos-recovery" || !/^[a-f0-9]{64}$/.test(restore.rescueManifestSha256)) throw new Error("Installer target binding differs");
const boot = (await Deno.readTextFile("/proc/sys/kernel/random/boot_id")).trim();
if (boot !== payload.expectedRamBootId || boot === restore.loaderBootId) throw new Error("Installer RAM boot differs from pinned SSH evidence");
const metadata = await fetch("http://169.254.169.254/opc/v2/instance/", {headers:{Authorization:"Bearer Oracle"}, redirect:"error", signal:AbortSignal.timeout(5000)});
const instance = metadata.ok ? await metadata.json() : null;
if (instance?.id !== payload.instanceId || instance?.freeformTags?.uosRecoveryRequest !== payload.requestId) throw new Error("Installer is not on the bound replacement");
if ((await Deno.readTextFile("/etc/uos-rescue/request-id")).trim() !== payload.requestId) throw new Error("Installer rescue request marker differs");
const manifest = "/etc/uos-rescue/manifest.json";
const info = await Deno.lstat(manifest);
if (!info.isFile || info.isSymlink || (info.mode & 0o777) !== 0o644 || await digest(await Deno.readFile(manifest)) !== restore.rescueManifestSha256) throw new Error("Installer rescue manifest differs");
const scratch = await Deno.lstat("/run/uos-recovery");
if (!scratch.isDirectory || scratch.isSymlink || (scratch.mode & 0o777) !== 0o700 || await Deno.realPath("/run/uos-recovery") !== "/run/uos-recovery") throw new Error("Installer scratch is not private");
for (const directory of ["/", "/run/uos-recovery"]) {
  const mount = await new Deno.Command("findmnt", {args:["-n","-o","FSTYPE","--target",directory],stdout:"piped",stderr:"null"}).output();
  if (!mount.success || new TextDecoder().decode(mount.stdout).trim() !== "tmpfs") throw new Error("Installer requires RAM-backed root and scratch");
}
if (!/^Filename\s+Type\s+Size\s+Used\s+Priority$/.test((await Deno.readTextFile("/proc/swaps")).trim())) throw new Error("Installer refuses active swap");
let decodedBytes = 0;
for (const file of payload.files) {
  if (!safe(file.path) || paths.has(file.path) || !Array.isArray(file.data) || file.data.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new Error("Malformed installer control file");
  const bytes = Uint8Array.from(file.data); decodedBytes += bytes.length;
  if (bytes.length > 524288 || decodedBytes > 2097152 || await digest(bytes) !== file.sha256) throw new Error("Installer control bounds or hashes differ");
  paths.add(file.path);
}
paths.clear();
const approvedBody = {requestId:payload.requestId,instanceId:payload.instanceId,bootId:payload.expectedRamBootId,sourceRevision:payload.sourceRevision,files:payload.files.map(({path,mode,sha256})=>({path,mode,sha256})),operation:"install the bound restore runtime, scoped Backblaze settings and public recipient on the replacement RAM filesystem and temporarily forward the Pi GPG extra socket for this restoration"};
const approvedDigest = await digest(new TextEncoder().encode(JSON.stringify(approvedBody)));
const assertApproval = () => {
  const approval=payload.installationApproval; const age=Date.now()-Date.parse(approval?.approvedAtUtc);
  if (!approval || approval.planSha256!==approvedDigest || approval.exactOperation!==approvedBody.operation || !Number.isFinite(age) || age<0 || age>3600000) throw new Error("Current exact installation approval is required");
};
assertApproval();
await ensureDir(root, 0o700);
await ensureDir(root + "/scripts", 0o755);
await ensureDir(root + "/.private", 0o700);
await ensureDir(root + "/.private/file-backup", 0o700);
await ensureDir(payload.publicHome, 0o700);
for (const file of payload.files) {
  assertApproval();
  if (!safe(file.path) || paths.has(file.path) || !["0600", "0644", "0755"].includes(file.mode) || !/^[0-9a-f]{64}$/.test(file.sha256) || !Array.isArray(file.data)) throw new Error("Recovery target file is malformed");
  const bytes = Uint8Array.from(file.data);
  if (bytes.length > 524288 || await digest(bytes) !== file.sha256) throw new Error("Recovery target file hash differs");
  const destination = root + "/" + file.path;
  const parent = destination.slice(0, destination.lastIndexOf("/"));
  await ensureDir(parent, file.path.startsWith(".private/") ? 0o700 : 0o755);
  const info = await Deno.lstat(destination).catch((error) => error instanceof Deno.errors.NotFound ? null : Promise.reject(error));
  if (info && (info.isSymlink || !info.isFile)) throw new Error("Recovery target destination is unsafe");
  if (info) {
    const existing = await Deno.readFile(destination);
    if (await digest(existing) !== file.sha256) throw new Error("Recovery target existing file differs");
  } else {
    const temporary = destination + ".tmp-" + crypto.randomUUID();
    await Deno.writeFile(temporary, bytes, { createNew: true, mode: parseInt(file.mode, 8) });
    await Deno.chmod(temporary, parseInt(file.mode, 8));
    await Deno.chown(temporary, owner, group);
    await Deno.rename(temporary, destination);
  }
  await Deno.chmod(destination, parseInt(file.mode, 8));
  await Deno.chown(destination, owner, group);
  paths.add(file.path);
}
for (const required of [".private/backblaze-machine-restore.json", ".private/b2-file-backup.json", ".private/file-backup/recipient.asc", ".private/recovery-source-manifest.json"]) if (!paths.has(required)) throw new Error("Recovery target bundle is incomplete");
const recipient = root + "/.private/file-backup/recipient.asc";
const recipientText = new TextDecoder("utf-8", { fatal: true }).decode(await Deno.readFile(recipient));
if (!recipientText.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----") || recipientText.includes("PRIVATE KEY")) throw new Error("Recovery recipient is not public-only");
if (await digest(await Deno.readFile(recipient)) !== restore.catalog?.index?.recipientSha256) throw new Error("Recovery recipient differs from the selected generation");
const shown = await new Deno.Command("sudo", {args:["-n","-u","codex","gpg","--no-options","--no-autostart","--no-keyring","--homedir",payload.publicHome,"--with-colons","--show-keys",recipient],stdout:"piped",stderr:"piped"}).output();
if (!shown.success || shown.stdout.length > 65536 || shown.stderr.length > 65536) throw new Error("Recovery public recipient inspection failed");
const records = new TextDecoder().decode(shown.stdout).split("\n");
if (records.filter(line => line.startsWith("pub:")).length !== 1 || records.some(line => line.startsWith("sec:") || line.startsWith("ssb:")) || records.find(line => line.startsWith("fpr:"))?.split(":")[9] !== restore.catalog.index.recipientFingerprint) throw new Error("Recovery recipient is not the selected public key");
assertApproval();
const imported = await new Deno.Command("sudo", { args: ["-n", "-u", "codex", "gpg", "--no-options", "--no-autostart", "--batch", "--no-tty", "--homedir", payload.publicHome, "--import", recipient], stdout: "piped", stderr: "piped" }).output();
if (!imported.success) throw new Error("Recovery public recipient import failed");
const privateKeys = payload.publicHome + "/private-keys-v1.d";
try { for await (const _entry of Deno.readDir(privateKeys)) throw new Error("Recovery target received a private key"); } catch (error) { if (!(error instanceof Deno.errors.NotFound)) throw error; }
const socket = await new Deno.Command("sudo", { args: ["-n", "-u", "codex", "gpgconf", "--homedir", payload.publicHome, "--create-socketdir"], stdout: "piped", stderr: "piped" }).output();
if (!socket.success) throw new Error("Recovery public GPG home setup failed");
console.log(JSON.stringify({ status: "RECOVERY_TARGET_RUNTIME_INSTALLED", requestId: payload.requestId, instanceId: payload.instanceId, sourceRevision: payload.sourceRevision, files: payload.files.length, publicHome: payload.publicHome }));
`.trim();

function defaultProcessFactory(
  command: string,
  args: string[],
): RecoveryTargetProcess {
  const child = new Deno.Command(command, {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  let finished = false;
  let stopping = false;
  let force: ReturnType<typeof setTimeout> | undefined;
  const status = child.status.then((value) => {
    finished = true;
    clearTimeout(force);
    return value;
  });
  const signal = (value: "SIGTERM" | "SIGKILL") => {
    if (finished) return;
    try {
      child.kill(value);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  };
  return {
    stdin: child.stdin,
    stdout: child.stdout,
    stderr: child.stderr,
    status,
    terminate() {
      if (finished || stopping) return;
      stopping = true;
      signal("SIGTERM");
      force = setTimeout(() => signal("SIGKILL"), 1000);
    },
  };
}

async function processDeadline<T>(
  process: RecoveryTargetProcess,
  work: Promise<T>,
  milliseconds: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          process.terminate();
          reject(Error("Recovery control operation exceeded its deadline"));
        }, milliseconds);
      }),
    ]);
  } catch (error) {
    process.terminate();
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function boundedText(
  stream: ReadableStream<Uint8Array>,
  limit: number,
): Promise<string> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of stream) {
    total += chunk.byteLength;
    if (total > limit) {
      throw Error("Recovery target control output exceeds its bound");
    }
    chunks.push(chunk);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function writeJsonStream(
  stream: WritableStream<Uint8Array>,
  value: unknown,
): Promise<void> {
  const writer = stream.getWriter();
  return (async () => {
    try {
      await writer.write(bytesOf(`${JSON.stringify(value)}\n`));
      await writer.close();
    } finally {
      writer.releaseLock();
    }
  })();
}

export function recoveryTargetInstallerArgs(
  target: RecoverySshTarget,
): string[] {
  return recoverySshArgs(target, "sudo", [
    "-n",
    "deno",
    "eval",
    recoveryTargetInstallerScript,
  ]);
}

export async function installRecoveryTargetRuntime(
  target: RecoverySshTarget,
  bundle: RecoveryTargetBundle,
  approval: RecoveryTargetInstallApproval,
  ports: RecoveryTargetInstallPorts = {},
): Promise<RecoveryTargetInstallReceipt> {
  assertBundle(bundle);
  if (
    target.host.phase !== "ram" ||
    target.host.instanceId !== bundle.instanceId ||
    target.host.requestId !== bundle.requestId
  ) {
    throw Error("Installer SSH target differs from the RAM recovery bundle");
  }
  const plan = recoveryTargetInstallPlan(target, bundle);
  assertInstallApproval(plan, approval);
  const process = (ports.process ?? defaultProcessFactory)(
    "ssh",
    recoveryTargetInstallerArgs(target),
  );
  const settled = await processDeadline(
    process,
    Promise.allSettled([
      boundedText(process.stdout, MAX_OUTPUT_BYTES),
      boundedText(process.stderr, MAX_DIAGNOSTIC_BYTES),
      process.status,
      writeJsonStream(process.stdin, {
        ...bundle,
        expectedRamBootId: target.host.bootId,
        installationApproval: approval,
      }),
    ]),
    120_000,
  );
  const status = settled[2];
  if (
    settled[0].status !== "fulfilled" || settled[1].status !== "fulfilled" ||
    status.status !== "fulfilled" || !status.value.success ||
    settled[3].status !== "fulfilled"
  ) throw Error("Recovery target runtime installation failed");
  let parsed: unknown;
  try {
    parsed = JSON.parse(settled[0].value.trim());
  } catch {
    throw Error("Recovery target installer returned malformed control output");
  }
  if (
    !parsed || typeof parsed !== "object" ||
    (parsed as Record<string, unknown>).status !==
      "RECOVERY_TARGET_RUNTIME_INSTALLED" ||
    (parsed as Record<string, unknown>).requestId !== bundle.requestId ||
    (parsed as Record<string, unknown>).instanceId !== bundle.instanceId ||
    (parsed as Record<string, unknown>).sourceRevision !== bundle.sourceRevision
  ) throw Error("Recovery target installer receipt differs");
  return parsed as RecoveryTargetInstallReceipt;
}

export function recoveryTargetRestoreArgs(
  target: RecoverySshTarget,
): string[] {
  const command = [
    "cd",
    shellQuote(RECOVERY_TARGET_ROOT),
    "&&",
    "exec",
    "sudo",
    "-n",
    "deno",
    "run",
    "--allow-read=/run/uos-recovery,/etc,/proc,/sys,/dev",
    "--allow-write=/run/uos-recovery",
    "--allow-net",
    "--allow-run=sudo,gpg,gpgconf,tar,zstd,bash,sh,sfdisk,udevadm,pvcreate,vgcfgrestore,vgchange,mkfs.ext4,mkfs.xfs,mkfs.vfat,mount,umount,fallocate,chmod,chown,mkswap,blkid,sync,mkdir,lsblk,findmnt,readlink,curl,wipefs,blockdev,cat,stat,sha256sum,uname",
    "scripts/backblaze-stream-restore.ts",
  ].join(" ");
  return recoverySshArgs(target, "bash", ["-ec", command]);
}

export function recoveryCheckpointBinding(
  input: MachineRestoreInput,
  requestId: string,
  bootId: string,
): CheckpointBinding {
  if (
    !REQUEST_PATTERN.test(requestId) || bootId === "" ||
    input.target.targetId !== input.target.approval.targetId
  ) {
    throw Error("Recovery checkpoint target binding is incomplete");
  }
  return {
    requestId,
    instanceId: input.target.targetId,
    bootId,
    generation: input.index.generation,
    indexSha256: machineRestoreIndexSha256(input.index),
    bootDiskPath: input.target.bootDiskPath,
    rootDiskPath: input.target.rootDiskPath,
    bootDiskSerial: input.target.bootDiskSerial,
    rootDiskSerial: input.target.rootDiskSerial,
  };
}

function validCheckpointBinding(binding: CheckpointBinding): void {
  if (
    !REQUEST_PATTERN.test(binding.requestId) ||
    !OCID_INSTANCE_PATTERN.test(binding.instanceId)
  ) throw Error("Recovery checkpoint binding is malformed");
}

async function closeInput(stream: WritableStream<Uint8Array>): Promise<void> {
  const writer = stream.getWriter();
  try {
    await writer.close();
  } catch {
    // The SSH process may already have exited.
  } finally {
    writer.releaseLock();
  }
}

/** Consume only checkpoints and the terminal control result. */
export async function restoreDirectFromBackblaze(
  target: RecoverySshTarget,
  binding: CheckpointBinding,
  checkpointPath: string,
  ports: RecoveryRestorePorts = {},
): Promise<RecoveryRestoreResult> {
  validCheckpointBinding(binding);
  if (
    target.host.phase !== "ram" ||
    target.host.requestId !== binding.requestId ||
    target.host.instanceId !== binding.instanceId ||
    target.host.bootId !== binding.bootId
  ) throw Error("Restore SSH target differs from the checkpoint binding");
  if (
    !checkpointPath.startsWith(".private/") || checkpointPath.includes("..")
  ) throw Error("Recovery checkpoint path is unsafe");
  const process = (ports.process ?? defaultProcessFactory)(
    "ssh",
    recoveryTargetRestoreArgs(target),
  );
  const channel = new CheckpointChannel(
    process.stdout,
    process.stdin,
    10 * 60 * 1000,
    () => process.terminate(),
  );
  const stderrPromise = boundedText(process.stderr, MAX_DIAGNOSTIC_BYTES).then(
    (text) => ({ text }),
    (error) => {
      process.terminate();
      return { error };
    },
  );
  const checkpoints: RecoveryCheckpoint[] = [];
  const archiveProgress = new Map<string, number>();
  let isolationPlan: RecoveryIsolationPlan | undefined;
  let isolationInspection: IsolationInspection | undefined;
  try {
    return await processDeadline(
      process,
      (async () => {
        let records = 0;
        while (true) {
          if (++records > 1500) {
            throw Error("Recovery control record budget exhausted");
          }
          const value = await channel.receive() as Record<string, unknown>;
          if (value?.kind === "recovery-isolation-inspection") {
            if (
              !isolationPlan || isolationInspection ||
              value.mountsReleased !== true || value.isolationApplied !== false
            ) throw Error("Unexpected copied-root inspection");
            const inspection = value.inspection as IsolationInspection;
            validateIsolationInspection(inspection, isolationPlan);
            await ports.beforeCheckpoint?.();
            await ports.inspected?.(isolationPlan, inspection);
            isolationInspection = inspection;
            continue;
          }
          if (value?.kind === "recovery-isolation-plan") {
            const plan = value.plan as RecoveryIsolationPlan;
            validateIsolationPlanDigest(plan);
            if (
              isolationPlan ||
              checkpoints.at(-1)?.journal.completedStages.length !==
                STAGES.length ||
              plan.generation !== binding.generation ||
              plan.indexSha256 !== binding.indexSha256 ||
              plan.binding.requestId !== binding.requestId ||
              plan.binding.instanceId !== binding.instanceId ||
              plan.binding.bootId !== binding.bootId ||
              plan.binding.boot.path !== binding.bootDiskPath ||
              plan.binding.root.path !== binding.rootDiskPath ||
              plan.binding.boot.serial !== binding.bootDiskSerial ||
              plan.binding.root.serial !== binding.rootDiskSerial
            ) {
              throw Error(
                "Isolation plan is not bound to the completed filesystem checkpoint",
              );
            }
            isolationPlan = plan;
            continue;
          }
          if (value?.kind === "recovery-archive-progress") {
            const recordBinding = value.binding as
              | CheckpointBinding
              | undefined;
            const journal = checkpoints.at(-1)?.journal;
            const archive = journal?.archives.find((a) =>
              a.role === value.role
            );
            const previous = archiveProgress.get(value.role as string);
            if (
              !recordBinding || !Object.keys(binding).every((key) =>
                recordBinding[key as keyof CheckpointBinding] ===
                  binding[key as keyof CheckpointBinding]
              ) ||
              !journal?.completedStages.includes("mounted") ||
              journal.completedStages.includes("archives-extracted") ||
              !archive || value.expectedBytes !== archive.bytes ||
              typeof value.bytes !== "number" ||
              !Number.isSafeInteger(value.bytes) ||
              value.bytes < 0 || value.bytes > archive.bytes ||
              (previous === undefined
                ? value.bytes !== 0
                : value.bytes <= previous)
            ) {
              throw Error("Archive progress is not bound or advancing");
            }
            archiveProgress.set(archive.role, value.bytes);
            await ports.progress?.({
              role: archive.role,
              bytes: value.bytes,
              expectedBytes: archive.bytes,
            });
            continue;
          }
          if (value?.kind === "recovery-checkpoint") {
            const checkpoint = value as unknown as RecoveryCheckpoint;
            await ports.beforeCheckpoint?.();
            const ack = await persistCheckpoint(
              checkpoint,
              binding,
              checkpointPath,
            );
            await channel.send(ack);
            if (checkpoints.at(-1)?.sha256 !== checkpoint.sha256) {
              checkpoints.push(checkpoint);
            }
            continue;
          }
          if (value?.kind !== "recovery-restore-result") {
            throw Error(
              "Recovery target returned an unexpected control record",
            );
          }
          const result = value.result as MachineRestoreResult;
          if (
            result?.status !== "FILESYSTEMS_REBUILT" ||
            result.targetId !== binding.instanceId ||
            result.generation !== binding.generation ||
            result.indexSha256 !== binding.indexSha256 ||
            result.machineBootRestoreProved !== false ||
            (isolationPlan !== undefined &&
              isolationInspection === undefined) ||
            checkpoints.at(-1)?.journal.completedStages.length !== STAGES.length
          ) {
            throw Error(
              "Recovery target restore result is not bound or accepted",
            );
          }
          // The target closes its protocol descriptors after its terminal result.
          // This channel still owns stdin; acquiring another writer here would fail.
          const status = await process.status;
          const diagnostic = await stderrPromise;
          if (!status.success || "error" in diagnostic) {
            throw Error("Recovery target restore process failed");
          }
          return {
            result,
            checkpoints,
            isolationPlan,
            isolationInspection,
            stderr: "text" in diagnostic ? diagnostic.text : "",
          };
        }
      })(),
      6 * 60 * 60 * 1000,
    );
  } finally {
    await channel.close();
  }
}

export interface RecoveryRestorationState {
  schemaVersion: 1;
  binding: CheckpointBinding;
  installPlanSha256: string;
  installed?: RecoveryTargetInstallReceipt;
  preparationPlan?: DiskPreparationPlan;
  preparationEvents: PreparationEvent[];
  prepared?: { planSha256: string; snapshotSha256: string };
  restoreIntent?: { intendedAtUtc: string };
  filesystems?: MachineRestoreResult;
  isolationPlan?: RecoveryIsolationPlan;
  isolationInspection?: IsolationInspection;
}

export interface RecoveryRestorationPorts {
  /** The caller holds the controller lock throughout this operation. Recheck
   * the gate, configuration and exact OCI attachment ownership here. */
  beforeMutation: () => Promise<void>;
  persist: (state: RecoveryRestorationState) => Promise<void>;
  report: (value: unknown) => Promise<void>;
  installationApproval: () => Promise<
    RecoveryTargetInstallApproval | undefined
  >;
  preparationApproval: () => Promise<PreparationApproval | undefined>;
}

/** Join existing target operations without a source-host dependency. A lost
 * disk-write or restore response stops at its durable intent; it never causes
 * an automatic repeat of destructive work. Boot remains a separate stage.
 */
export async function continueReplacementRestoration(
  target: RecoverySshTarget,
  preparation: DiskPreparationBinding,
  bundle: RecoveryTargetBundle,
  retained: RecoveryRestorationState | undefined,
  ports: RecoveryRestorationPorts,
): Promise<string> {
  const input = JSON.parse(new TextDecoder().decode(Uint8Array.from(
    bundle.files.find((file) =>
      file.path === ".private/backblaze-machine-restore.json"
    )?.data ?? [],
  ))) as RecoveryTargetControlInput;
  assertRequestIdentity(input);
  const catalog = validateCatalogEntry(input.catalog);
  const machine = input.target;
  if (
    input.requestId !== preparation.requestId ||
    machine.targetId !== preparation.instanceId ||
    target.host.bootId !== preparation.bootId ||
    input.loaderBootId !== preparation.loaderBootId ||
    input.rescueManifestSha256 !== preparation.rescueManifestSha256 ||
    machine.architecture !== "aarch64" ||
    machine.bootDiskPath !== preparation.boot.path ||
    machine.rootDiskPath !== preparation.root.path ||
    machine.bootDiskSerial !== preparation.boot.serial ||
    machine.rootDiskSerial !== preparation.root.serial ||
    machine.bootDiskBytes !== preparation.boot.bytes ||
    machine.rootDiskBytes !== preparation.root.bytes
  ) {
    throw Error(
      "Restore input differs from the provider-bound replacement disks",
    );
  }
  const binding: CheckpointBinding = {
    requestId: input.requestId,
    instanceId: machine.targetId,
    bootId: preparation.bootId,
    generation: catalog.index.generation,
    indexSha256: machineRestoreIndexSha256(catalog.index),
    bootDiskPath: machine.bootDiskPath,
    rootDiskPath: machine.rootDiskPath,
    bootDiskSerial: machine.bootDiskSerial,
    rootDiskSerial: machine.rootDiskSerial,
  };
  const plan = recoveryTargetInstallPlan(target, bundle);
  const state: RecoveryRestorationState = retained ?? {
    schemaVersion: 1,
    binding,
    installPlanSha256: plan.planSha256,
    preparationEvents: [],
  };
  if (
    state.schemaVersion !== 1 ||
    JSON.stringify(state.binding) !== JSON.stringify(binding) ||
    state.installPlanSha256 !== plan.planSha256 ||
    !Array.isArray(state.preparationEvents) ||
    state.preparationEvents.length > 6
  ) throw Error("Retained restoration belongs to a different approved input");
  const save = () => ports.persist(structuredClone(state));
  await save();
  if (state.filesystems) {
    await ports.report({
      status: state.isolationPlan
        ? "COPIED_ROOT_ISOLATION_PLANNED"
        : "FILESYSTEMS_REBUILT",
      isolationPlan: state.isolationPlan,
      isolationInspection: state.isolationInspection,
      isolationApplied: false,
      bootAccepted: false,
      applicationAccepted: false,
    });
    return "FILESYSTEMS_REBUILT";
  }
  if (state.restoreIntent) {
    await ports.report({
      status: "RESTORE_RECONCILIATION_REQUIRED",
      binding,
      bootAccepted: false,
      applicationAccepted: false,
    });
    return "RESTORE_RECONCILIATION_REQUIRED";
  }
  const installation = await ports.installationApproval();
  if (!installation) {
    await ports.report({
      status: "RESTORE_INSTALLATION_APPROVAL_REQUIRED",
      plan,
    });
    return "RESTORE_INSTALLATION_APPROVAL_REQUIRED";
  }
  assertInstallApproval(plan, installation);
  await ports.beforeMutation();
  if (!state.installed) {
    state.installed = await installRecoveryTargetRuntime(
      target,
      bundle,
      installation,
    );
    await save();
  }
  const ssh = recoverySshRunner(target);
  const privileged: CommandRunner = (command, args) =>
    ssh("sudo", ["-n", command, ...args]);
  if (!state.prepared) {
    if (state.preparationEvents.length > 0) {
      await ports.report({
        status: "DISK_PREPARATION_RECONCILIATION_REQUIRED",
        binding,
      });
      return "DISK_PREPARATION_RECONCILIATION_REQUIRED";
    }
    const snapshot = await inspectPreparationDisks(preparation, privileged);
    const diskPlan = diskPreparationPlan(preparation, snapshot);
    if (
      state.preparationPlan &&
      state.preparationPlan.planSha256 !== diskPlan.planSha256
    ) {
      throw Error(
        "Preparation snapshot changed; retained plan requires reconciliation",
      );
    }
    state.preparationPlan = diskPlan;
    await save();
    const approval = await ports.preparationApproval();
    if (!approval) {
      await ports.report({
        status: "DISK_PREPARATION_APPROVAL_REQUIRED",
        plan: diskPlan,
      });
      return "DISK_PREPARATION_APPROVAL_REQUIRED";
    }
    const prepared = await prepareReplacementDisks(
      diskPlan,
      approval,
      async (event) => {
        await ports.beforeMutation();
        const fresh = await ports.preparationApproval();
        if (JSON.stringify(fresh) !== JSON.stringify(approval)) {
          throw Error("Disk preparation authority changed");
        }
        state.preparationEvents.push(event);
        await save();
      },
      privileged,
    );
    state.prepared = {
      planSha256: prepared.planSha256,
      snapshotSha256: prepared.snapshotSha256,
    };
    await save();
  }
  await ports.beforeMutation();
  const freshInstallation = await ports.installationApproval();
  assertInstallApproval(plan, freshInstallation!);
  const socket = await ssh("gpgconf", [
    "--homedir",
    RECOVERY_TARGET_PUBLIC_HOME,
    "--list-dirs",
    "agent-socket",
  ]);
  if (socket.code !== 0) {
    throw Error("Replacement public GPG socket is unavailable");
  }
  const tunnel = await openRecoveryGpgTunnel(target, socket.stdout.trim());
  try {
    await ports.beforeMutation();
    state.restoreIntent = { intendedAtUtc: new Date().toISOString() };
    await save();
    const restored = await restoreDirectFromBackblaze(
      target,
      binding,
      RECOVERY_TARGET_CHECKPOINT,
      {
        beforeCheckpoint: ports.beforeMutation,
        inspected: async (isolationPlan, isolationInspection) => {
          state.isolationPlan = isolationPlan;
          state.isolationInspection = isolationInspection;
          await save();
        },
        progress: (value) =>
          ports.report({
            status: "ARCHIVE_EXTRACTION_PROGRESS",
            ...value,
            filesystemsAccepted: false,
            bootAccepted: false,
            applicationAccepted: false,
          }),
      },
    );
    state.filesystems = restored.result;
    state.isolationPlan = restored.isolationPlan;
    state.isolationInspection = restored.isolationInspection;
    await save();
  } finally {
    await tunnel.close();
  }
  await ports.report({
    status: state.isolationPlan
      ? "COPIED_ROOT_ISOLATION_PLANNED"
      : "FILESYSTEMS_REBUILT",
    isolationPlan: state.isolationPlan,
    isolationInspection: state.isolationInspection,
    isolationApplied: false,
    bootAccepted: false,
    applicationAccepted: false,
  });
  return "FILESYSTEMS_REBUILT";
}

export interface GpgTunnelChild {
  stdin: WritableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
  status: Promise<Deno.CommandStatus>;
  /** Stop only the SSH child created by this factory. */
  terminate(): void;
}

export type GpgTunnelChildFactory = (args: string[]) => GpgTunnelChild;

export interface GpgTunnelHandle {
  close(): Promise<void>;
}

function defaultGpgTunnelChild(args: string[]): GpgTunnelChild {
  return defaultProcessFactory("ssh", args);
}

function gpgTunnelArgs(
  target: RecoverySshTarget,
  remoteSocket: string,
  localSocket: string,
): string[] {
  if (
    !/^\/run\/[A-Za-z0-9_./-]+\/S\.gpg-agent$/.test(remoteSocket) ||
    remoteSocket.split("/").includes("..") ||
    !/^\/[A-Za-z0-9_./-]+$/.test(localSocket) ||
    localSocket.split("/").includes("..") ||
    localSocket.includes("\0") || localSocket.includes("\n") ||
    remoteSocket.includes("\0") || remoteSocket.includes("\n")
  ) throw Error("GPG tunnel socket path is unsafe");
  const command = `trap ${
    shellQuote(`rm -f -- ${shellQuote(remoteSocket)}`)
  } EXIT; printf 'TUNNEL_READY\\n'; cat`;
  const args = recoverySshArgs(target, "bash", ["-ec", command]);
  const destination = args.findIndex((value) =>
    value === `codex@${target.address}`
  );
  if (destination < 0) throw Error("Recovery SSH destination is missing");
  args.splice(
    destination,
    0,
    "-o",
    "ExitOnForwardFailure=yes",
    "-R",
    `${remoteSocket}:${localSocket}`,
  );
  return args;
}

/** Open a target-specific reverse tunnel to the Pi's existing extra socket. */
export async function openRecoveryGpgTunnel(
  target: RecoverySshTarget,
  remoteSocket: string,
  keyringPath = ".private/file-backup/gnupg",
  runner: CommandRunner = recoveryControlRunner,
  childFactory: GpgTunnelChildFactory = defaultGpgTunnelChild,
): Promise<GpgTunnelHandle> {
  if (!keyringPath || keyringPath.includes("\0")) {
    throw Error("Pi GPG keyring path is unsafe");
  }
  const keyring = await Deno.lstat(keyringPath);
  if (
    !keyring.isDirectory || keyring.isSymlink || (keyring.mode! & 0o077) !== 0
  ) throw Error("Existing Pi keyring is not private");
  const remote = recoverySshRunner(target);
  const custom = await remote("gpgconf", [
    "--homedir",
    RECOVERY_TARGET_PUBLIC_HOME,
    "--list-dirs",
    "agent-socket",
  ]);
  const normal = await remote("gpgconf", ["--list-dirs", "agent-socket"]);
  if (
    custom.code !== 0 || normal.code !== 0 ||
    custom.stdout.trim() !== remoteSocket ||
    remoteSocket === normal.stdout.trim()
  ) throw Error("Target public-home GPG socket is not proved");
  const launch = await runner("gpgconf", [
    "--homedir",
    keyringPath,
    "--launch",
    "gpg-agent",
  ]);
  if (launch.code !== 0) throw Error("Pi GPG agent launch failed");
  const extra = await runner("gpgconf", [
    "--homedir",
    keyringPath,
    "--list-dirs",
    "agent-extra-socket",
  ]);
  const standard = await runner("gpgconf", [
    "--homedir",
    keyringPath,
    "--list-dirs",
    "agent-socket",
  ]);
  const localSocket = extra.stdout.trim().split("\n").at(-1) ?? "";
  const defaultSocket = standard.stdout.trim().split("\n").at(-1) ?? "";
  if (
    extra.code !== 0 || standard.code !== 0 || !localSocket || !defaultSocket ||
    localSocket === defaultSocket
  ) throw Error("Pi GPG extra socket is not proved");
  const child = childFactory(gpgTunnelArgs(target, remoteSocket, localSocket));
  const ready = (async () => {
    let text = "";
    for await (const chunk of child.stdout) {
      text += new TextDecoder().decode(chunk);
      if (text.includes("TUNNEL_READY")) return;
      if (text.length > 64 * 1024) {
        throw Error("GPG tunnel output exceeds bound");
      }
    }
    throw Error("GPG tunnel closed before readiness");
  })();
  const diagnostic = boundedText(child.stderr, MAX_DIAGNOSTIC_BYTES).then(
    (text) => ({ text }),
    (error) => {
      child.terminate();
      return { error };
    },
  );
  try {
    await processDeadline(child, ready, 30_000);
  } catch (error) {
    child.terminate();
    throw error;
  }
  let closed = false;
  return {
    async close() {
      if (closed) return;
      closed = true;
      await processDeadline(
        child,
        (async () => {
          await closeInput(child.stdin);
          const status = await child.status;
          const result = await diagnostic;
          if (!status.success || "error" in result) {
            throw Error(
              "Recovery GPG tunnel closed with an error",
            );
          }
        })(),
        10_000,
      );
    },
  };
}
