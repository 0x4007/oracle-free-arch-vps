import { shellQuote } from "./backup-guest.ts";
import { writePrivateJson } from "./oci.ts";

/**
 * m02-capture: source-side live filesystem capture for the encrypted
 * Backblaze file backup of the Arch VPS.
 *
 * This module never uploads, never holds a private decryption key, never
 * starts a GPG agent and never writes to a source filesystem. It produces
 * one public-recipient encrypted archive per role plus an encrypted
 * recovery bundle under a fixed root-only staging root. The caller owns
 * exclusive source locks, upload journal and acceptance; this capture is a
 * non-atomic live file copy (consistency "live-file-copy",
 * sourceShutdown false) and makes no machine-boot restoration claims.
 *
 * Tools used are the standard host tools (GNU tar, zstd, GnuPG, util-linux,
 * coreutils); no package is installed or required besides the documented
 * ones. Every producer status is checked and raw diagnostics are written to
 * owner-only files inside the owned stage — never to console output.
 */

export type Filesystem = "ext4" | "xfs" | "vfat";

export interface FileSource {
  name: string;
  uuid: string;
  filesystem: Filesystem;
  size: number;
  livePath?: "/" | "/efi";
}

export interface CaptureSettings {
  sources: FileSource[];
  generation: string;
  recipientFile: string;
  recipientSha256: string;
  recipientFingerprint: string;
  exclusionsText: string;
}

export interface CapturedArchive {
  role: string;
  path: string;
  bytes: number;
  sha256: string;
  format: "tar.zst.gpg" | "json.zst.gpg";
}

export interface CaptureResult {
  generation: string;
  stageDirectory: string;
  archives: CapturedArchive[];
  startedAtUtc: string;
  finishedAtUtc: string;
  consistency: "live-file-copy";
  sourceShutdown: false;
}

export interface LsblkNode {
  name?: string;
  path?: string;
  size?: number;
  type?: string;
  fstype?: string | null;
  uuid?: string | null;
  /** One MOUNTPOINTS entry per mount; real lsblk reports an unmounted node
   * as `[null]`, so null entries are valid "unmounted" markers. */
  mountpoints?: (string | null)[] | null;
  children?: LsblkNode[];
}

export type RoleName =
  | "root"
  | "efi"
  | "staging-boot"
  | "staging-efi"
  | "oracle-root"
  | "oracle-oled";

/** Exact required six-role schema. Cold roles have no livePath. */
interface RoleSpec {
  filesystem: Filesystem;
  livePath?: "/" | "/efi";
}

const ROLE_SPECS: Record<RoleName, RoleSpec> = {
  root: { filesystem: "ext4", livePath: "/" },
  efi: { filesystem: "vfat", livePath: "/efi" },
  "staging-boot": { filesystem: "xfs" },
  "staging-efi": { filesystem: "vfat" },
  "oracle-root": { filesystem: "xfs" },
  "oracle-oled": { filesystem: "xfs" },
};

export const ROLE_ORDER: RoleName[] = [
  "root",
  "efi",
  "staging-boot",
  "staging-efi",
  "oracle-root",
  "oracle-oled",
];

/** Approved minimum exclusion set; the same list is applied to every role. */
export const REQUIRED_EXCLUSIONS: readonly string[] = [
  "/home/codex/repos",
  "/.swapfile",
  "/tmp",
  "/var/tmp",
  "/run",
  "/proc",
  "/sys",
  "/dev",
];

const PROTECTED_EXCLUSIONS = [
  "/",
  "/boot",
  "/efi",
  "/etc",
  "/usr",
  "/var/lib",
  "/home",
  "/home/codex",
  "/home/codex/.codex",
  "/home/codex/.config",
  "/mnt",
];

const GENERATION_PATTERN =
  /^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const UUID_PATTERN = /^[0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)+$/;
const ABSOLUTE_PATH_PATTERN = /^\/[A-Za-z0-9/_.-]+$/;
/** Canonical literal absolute exclusion form: exactly one leading slash,
 * literal segments separated by single slashes, no empty or dot segments and
 * no trailing slash (rejects /\., //, /etc/, /a//b aliases). */
const EXCLUSION_PATH_PATTERN = /^\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;

const STAGE_ROOT = "/var/tmp/arch-vps-file-backup";
const GIB = 1024 ** 3;
const MIB = 1024 ** 2;
const SPACE_RESERVE = 5 * GIB;
const SPACE_MARGIN = 512 * MIB;
const SPACE_MIN_FREE = SPACE_RESERVE + SPACE_MARGIN;
const RECIPIENT_MAX_BYTES = 64 * 1024;
const MAX_SFDUMP_BYTES = 1024 * 1024;
const MAX_VG_BYTES = 1024 * 1024;
const MAX_EFIVAR_BYTES = 64 * 1024;
const MAX_EFIVARS = 512;

const TAR_OPTIONS = [
  "--format=pax",
  "--create",
  "--file=-",
  "--numeric-owner",
  "--acls",
  "--xattrs",
  "--xattrs-include=*",
  "--sparse",
  "--one-file-system",
  "--anchored",
  "--no-wildcards",
] as const;

const GPG_BASE_ARGS = [
  "--no-options",
  "--no-autostart",
  "--no-keyring",
  "--no-encrypt-to",
  "--batch",
  "--no-tty",
] as const;

const TAR_OPTION_TEXT = TAR_OPTIONS.join(" ");
const ZSTD_OPTION_TEXT = "-3 -T1 --check";
const GPG_OPTION_TEXT = `${
  GPG_BASE_ARGS.join(" ")
} --compress-algo none --cipher-algo AES256`;

const FAIL_PREFIX = "Capture failed (";
const EXCLUSIONS_FILE = "exclusions.txt";

function fail(label: string, exit?: number): never {
  const code = exit === undefined ? "" : `, exit ${exit}`;
  throw new Error(`${FAIL_PREFIX}${label}${code})`);
}

export function flattenLsblk(blockdevices: LsblkNode[]): LsblkNode[] {
  const out: LsblkNode[] = [];
  const walk = (nodes: LsblkNode[]): void => {
    for (const node of nodes) {
      out.push(node);
      if (node.children) walk(node.children);
    }
  };
  walk(blockdevices);
  return out;
}

/** Strict six-role identity: exactly one of each role, correct type and
 * live binding, unique names and UUIDs of hex/dash syntax. */
export function validateSourceShapes(sources: FileSource[]): void {
  const names = sources.map((source) => source.name);
  if (new Set(names).size !== names.length) {
    throw new Error("Source names must be unique");
  }
  const expected = new Set<string>(Object.keys(ROLE_SPECS));
  if (
    names.length !== expected.size || names.some((name) => !expected.has(name))
  ) {
    throw new Error("Persistent filesystem coverage changed");
  }
  const uuids = new Set<string>();
  for (const source of sources) {
    if (!UUID_PATTERN.test(source.uuid) || uuids.has(source.uuid)) {
      throw new Error("Invalid source binding");
    }
    uuids.add(source.uuid);
    const spec = ROLE_SPECS[source.name as RoleName];
    if (
      source.filesystem !== spec.filesystem || source.livePath !== spec.livePath
    ) {
      throw new Error("Invalid source binding");
    }
    if (!Number.isSafeInteger(source.size) || source.size <= 0) {
      throw new Error("Invalid source binding");
    }
  }
}

/** No ext4/xfs/vfat filesystem may be mounted outside / and /efi. Null
 * mountpoint entries (real lsblk shape for unmounted nodes) mean unmounted;
 * anything that is not a string or an unexpected actual path is rejected. */
export function assertLiveMountTargets(blockdevices: LsblkNode[]): void {
  const persistent = new Set<Filesystem>(["ext4", "xfs", "vfat"]);
  for (const node of flattenLsblk(blockdevices)) {
    if (!node.fstype || !persistent.has(node.fstype as Filesystem)) continue;
    const mountpoints = node.mountpoints ?? [];
    if (!Array.isArray(mountpoints)) {
      throw new Error("Persistent filesystem mountpoint data is malformed");
    }
    for (const mountpoint of mountpoints) {
      if (mountpoint === null) continue; // lsblk reports unmounted as [null]
      if (typeof mountpoint !== "string") {
        throw new Error("Persistent filesystem mountpoint data is malformed");
      }
      if (mountpoint !== "/" && mountpoint !== "/efi") {
        throw new Error("Persistent filesystem mounted outside / or /efi");
      }
    }
  }
}

/** Validate every source UUID, type and exact byte size against a recursive
 * lsblk layout; ignore LVM2_member and swap containers; reject any extra
 * persistent filesystem. */
export function validateSources(
  sources: FileSource[],
  blockdevices: LsblkNode[],
): void {
  validateSourceShapes(sources);
  assertLiveMountTargets(blockdevices);
  const filesystems = flattenLsblk(blockdevices).filter((node) =>
    node.fstype !== null && node.fstype !== undefined &&
    node.fstype !== "LVM2_member" && node.fstype !== "swap"
  );
  if (filesystems.length !== sources.length) {
    throw new Error("Persistent filesystem coverage changed");
  }
  for (const source of sources) {
    const matches = filesystems.filter((node) => node.uuid === source.uuid);
    if (
      matches.length !== 1 || matches[0].fstype !== source.filesystem ||
      matches[0].size !== source.size
    ) {
      throw new Error("Filesystem identity or size changed");
    }
  }
}

/** True when the path is equal to a protected root or is an ancestor of one
 * (e.g. "/var" is an ancestor of the protected "/var/lib" and would exclude
 * the whole protected tree). */
function isProtectedRootOrAncestor(path: string): boolean {
  return PROTECTED_EXCLUSIONS.some((root) =>
    path === root || root.startsWith(`${path}/`)
  );
}

/** Parse approved exclusions: canonical explicit safe absolute paths only,
 * no globs, no empty/dot/".." segments, no repeated or trailing slash, no
 * critical broad roots or ancestors of one, and the required exclusion set. */
export function exclusionPaths(text: string): string[] {
  const paths = text.split("\n").map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  for (const path of paths) {
    if (
      !EXCLUSION_PATH_PATTERN.test(path) ||
      path.split("/").some((segment) => segment === "." || segment === "..") ||
      isProtectedRootOrAncestor(path)
    ) {
      throw new Error(
        "Exclusions must be explicit, noncritical absolute paths",
      );
    }
  }
  const unique = [...new Set(paths)];
  for (const required of REQUIRED_EXCLUSIONS) {
    if (!unique.includes(required)) {
      throw new Error(`Required exclusion is missing: ${required}`);
    }
  }
  return unique;
}

/** Convert absolute exclusions to anchored literal filesystem-relative
 * members ("./path"), identical for tar and du on every role. */
export function fsRelativeExclusions(paths: string[]): string[] {
  const relative = paths.map((path) => "./" + path.replace(/^\/+/, ""));
  return [...new Set(relative)];
}

export function validateGeneration(generation: string): void {
  if (!GENERATION_PATTERN.test(generation)) {
    throw new Error("Generation must be canonical lowercase generation-UUID");
  }
}

/** Pure settings validation; captureGeneration runs this before any command
 * or filesystem side effect. */
export function validateCaptureSettings(settings: CaptureSettings): void {
  validateGeneration(settings.generation);
  if (!/^[0-9a-f]{64}$/.test(settings.recipientSha256)) {
    throw new Error("Recipient SHA256 must be 64 lowercase hex characters");
  }
  if (!/^[0-9A-F]{40}$/.test(settings.recipientFingerprint)) {
    throw new Error(
      "Recipient fingerprint must be 40 uppercase hex characters",
    );
  }
  if (!ABSOLUTE_PATH_PATTERN.test(settings.recipientFile)) {
    throw new Error("Recipient file must be an explicit absolute path");
  }
  validateSourceShapes(settings.sources);
  exclusionPaths(settings.exclusionsText);
}

interface RunOutput {
  code: number;
  stdout: string;
  stderr: string;
}

async function runCommand(
  command: string,
  args: string[],
  stderrLog?: string,
): Promise<RunOutput> {
  const child = new Deno.Command(command, {
    args,
    stdout: "piped",
    stderr: "piped",
  });
  const output = await child.output();
  const result: RunOutput = {
    code: output.code,
    stdout: new TextDecoder().decode(output.stdout),
    stderr: new TextDecoder().decode(output.stderr),
  };
  if (output.code !== 0 && stderrLog) {
    try {
      await writePrivateText(stderrLog, result.stderr);
    } catch {
      // Diagnostics must never mask the original failure.
    }
  }
  return result;
}

function runBash(
  script: string,
  stderrLog?: string,
): Promise<RunOutput> {
  return runCommand("bash", ["-c", script], stderrLog);
}

function requireOk(result: RunOutput, label: string): void {
  if (result.code !== 0) fail(label, result.code);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return [...new Uint8Array(digest)].map((byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

/** SHA-256 of a staged file through a checked sha256sum subprocess. The
 * process streams the file itself and only its one-line digest crosses the
 * pipe, so archive-sized data is never loaded into Deno; the returned digest
 * must be exactly 64 lowercase hex digits. */
export async function sha256File(
  path: string,
  label: string,
  stderrLog?: string,
): Promise<string> {
  const result = await runCommand("sha256sum", [path], stderrLog);
  if (result.code !== 0) fail(label, result.code);
  const digest = result.stdout.trim().split(/\s+/)[0] ?? "";
  if (!/^[0-9a-f]{64}$/.test(digest)) fail(label);
  return digest;
}

/** Write owner-only text atomically (0600, fsync, rename, directory sync). */
async function writePrivateText(path: string, text: string): Promise<void> {
  const slash = path.lastIndexOf("/");
  const directory = slash > 0 ? path.slice(0, slash) : ".";
  const temporary = `${directory}/.${
    path.slice(slash + 1)
  }.${crypto.randomUUID()}.tmp`;
  try {
    const file = await Deno.open(temporary, {
      write: true,
      createNew: true,
      mode: 0o600,
    });
    try {
      const bytes = new TextEncoder().encode(text);
      let offset = 0;
      while (offset < bytes.length) {
        offset += await file.write(bytes.subarray(offset));
      }
      await file.sync();
    } finally {
      file.close();
    }
    await Deno.chmod(temporary, 0o600);
    await Deno.rename(temporary, path);
    await syncDirectory(directory);
  } catch (error) {
    try {
      await Deno.remove(temporary);
    } catch (cleanup) {
      if (!(cleanup instanceof Deno.errors.NotFound)) throw cleanup;
    }
    throw error;
  }
}

async function syncDirectory(path: string): Promise<void> {
  const directory = await Deno.open(path, { read: true });
  try {
    await directory.sync();
  } finally {
    directory.close();
  }
}

async function fsyncFile(path: string): Promise<void> {
  const file = await Deno.open(path, { write: true });
  try {
    await file.sync();
  } finally {
    file.close();
  }
}

/** Commit an owned partial file: fsync, rename, force 0600, sync directory. */
async function commitFile(partial: string, final: string): Promise<void> {
  await fsyncFile(partial);
  await Deno.rename(partial, final);
  await Deno.chmod(final, 0o600);
  const slash = final.lastIndexOf("/");
  await syncDirectory(slash > 0 ? final.slice(0, slash) : ".");
}

async function ensureStageRoot(): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(STAGE_ROOT);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      await Deno.mkdir(STAGE_ROOT, { mode: 0o700 });
      info = await Deno.lstat(STAGE_ROOT);
    } else {
      throw error;
    }
  }
  if (info.isSymlink || !info.isDirectory || info.uid !== 0) {
    fail("stage:prepare");
  }
  if (info.mode !== null && (info.mode & 0o777) !== 0o700) {
    await Deno.chmod(STAGE_ROOT, 0o700);
  }
  if (await Deno.realPath(STAGE_ROOT) !== STAGE_ROOT) fail("stage:prepare");
}

/** Create the generation directory exclusively; the caller owns resume. */
async function createGenerationDir(stage: string): Promise<void> {
  try {
    await Deno.mkdir(stage, { mode: 0o700 });
  } catch (error) {
    if (error instanceof Deno.errors.AlreadyExists) {
      throw new Error("Generation stage already exists; caller owns resume");
    }
    throw error;
  }
  await Deno.chmod(stage, 0o700);
  if (await Deno.realPath(stage) !== stage) fail("stage:generation");
}

function logPath(stage: string, label: string): string {
  return `${stage}/${label.replaceAll(":", "-")}.stderr.log`;
}

function gpgArgs(
  homedir: string,
  recipient: string,
  output: string,
  input: string,
): string[] {
  return [
    ...GPG_BASE_ARGS,
    "--homedir",
    homedir,
    "--recipient-file",
    recipient,
    "--compress-algo",
    "none",
    "--cipher-algo",
    "AES256",
    "--output",
    output,
    "--encrypt",
    input,
  ];
}

const PUBLIC_KEY_ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PUBLIC_KEY_ARMOR_END = "-----END PGP PUBLIC KEY BLOCK-----";

/** Strict input-form check for our locally generated public ASCII export:
 * exactly one PGP PUBLIC KEY BLOCK that starts the content and ends it, no
 * other armored block (SECRET/PRIVATE/SIGNATURE/...), no binary or non-ASCII
 * bytes, and a non-empty armored body. This is a narrow lexical gate only;
 * key identity and trust stay with the pinned SHA-256 and the gpg
 * fingerprint check. No key parsing framework is used. */
export function isPublicKeyArmorForm(content: string): boolean {
  for (const char of content) {
    const code = char.charCodeAt(0);
    if (code !== 0x0a && code !== 0x0d && (code < 0x20 || code > 0x7e)) {
      return false;
    }
  }
  const block = content.split("\n").map((line) =>
    line.endsWith("\r") ? line.slice(0, -1) : line
  ).filter((line) => line !== "");
  if (block.length < 3) return false;
  if (block[0] !== PUBLIC_KEY_ARMOR_BEGIN) return false;
  if (block[block.length - 1] !== PUBLIC_KEY_ARMOR_END) return false;
  const begins = block.filter((line) => line === PUBLIC_KEY_ARMOR_BEGIN).length;
  const ends = block.filter((line) => line === PUBLIC_KEY_ARMOR_END).length;
  if (begins !== 1 || ends !== 1) return false;
  for (const line of block.slice(1, -1)) {
    if (
      /^-----BEGIN PGP [A-Z ]+ BLOCK-----$/.test(line) ||
      /^-----END PGP [A-Z ]+ BLOCK-----$/.test(line)
    ) {
      return false;
    }
  }
  return true;
}

/** Copy the pinned public recipient into the owned stage and prove exactly
 * one public key with the expected fingerprint and no secret material. The
 * source must be one ASCII PGP PUBLIC KEY BLOCK. */
async function prepareRecipient(
  settings: CaptureSettings,
  stage: string,
): Promise<void> {
  const info = await Deno.stat(settings.recipientFile);
  if (!info.isFile || info.size > RECIPIENT_MAX_BYTES) fail("recipient:read");
  const content = await Deno.readTextFile(settings.recipientFile);
  if (!isPublicKeyArmorForm(content)) {
    fail("recipient:armor");
  }
  if (
    (await sha256Hex(new TextEncoder().encode(content))) !==
      settings.recipientSha256
  ) {
    fail("recipient:hash");
  }
  const publicPath = `${stage}/recipient.asc`;
  await writePrivateText(publicPath, content);
  const publicHome = `${stage}/gpg-public-home`;
  await Deno.mkdir(publicHome, { mode: 0o700 });
  await Deno.chmod(publicHome, 0o700);
  const result = await runCommand("gpg", [
    "--no-options",
    "--no-autostart",
    "--no-keyring",
    "--homedir",
    publicHome,
    "--with-colons",
    "--show-keys",
    publicPath,
  ], logPath(stage, "recipient-key"));
  requireOk(result, "recipient:key");
  const records = result.stdout.split("\n");
  const publicKeys = records.filter((line) => line.startsWith("pub:"));
  const secretRecords = records.filter((line) =>
    line.startsWith("sec:") || line.startsWith("ssb:")
  );
  const fingerprints = records.filter((line) => line.startsWith("fpr:"))
    .map((line) => line.split(":")[9] ?? "");
  if (
    publicKeys.length !== 1 || fingerprints.length === 0 ||
    fingerprints[0] !== settings.recipientFingerprint ||
    secretRecords.length > 0
  ) {
    fail("recipient:key");
  }
}

/** The copied public file hash is pinned again before every encryption. */
async function assertRecipientPinned(
  settings: CaptureSettings,
  stage: string,
): Promise<void> {
  const bytes = await Deno.readFile(`${stage}/recipient.asc`);
  if ((await sha256Hex(bytes)) !== settings.recipientSha256) {
    fail("recipient:pin");
  }
}

async function assertMountGuards(
  settings: CaptureSettings,
  stage: string,
  label: string,
): Promise<void> {
  const root = settings.sources.find((source) => source.name === "root")!;
  const efi = settings.sources.find((source) => source.name === "efi")!;
  const script = [
    "set -u",
    `test "$(findmnt -nro UUID /)" = ${
      shellQuote(root.uuid)
    } || { echo 'root UUID mismatch' >&2; exit 81; }`,
    `test "$(findmnt -nro FSTYPE /)" = ${
      shellQuote(root.filesystem)
    } || { echo 'root FSTYPE mismatch' >&2; exit 81; }`,
    "mountpoint -q / || { echo 'root is not a mountpoint' >&2; exit 81; }",
    `test "$(findmnt -nro UUID /efi)" = ${
      shellQuote(efi.uuid)
    } || { echo 'efi UUID mismatch' >&2; exit 81; }`,
    `test "$(findmnt -nro FSTYPE /efi)" = ${
      shellQuote(efi.filesystem)
    } || { echo 'efi FSTYPE mismatch' >&2; exit 81; }`,
    "mountpoint -q /efi || { echo 'efi is not a mountpoint' >&2; exit 81; }",
  ].join("\n");
  const result = await runBash(script, logPath(stage, label));
  requireOk(result, label);
}

async function requireNoPacmanLock(label: string): Promise<void> {
  const result = await runCommand("bash", [
    "-c",
    "test ! -e /var/lib/pacman/db.lck",
  ]);
  requireOk(result, label);
}

async function lsblkLayout(label: string, stage: string): Promise<LsblkNode[]> {
  const result = await runCommand("lsblk", [
    "-J",
    "-b",
    "-o",
    "NAME,PATH,SIZE,TYPE,FSTYPE,UUID,MOUNTPOINTS",
  ], logPath(stage, label));
  requireOk(result, label);
  try {
    const parsed = JSON.parse(result.stdout) as { blockdevices?: LsblkNode[] };
    if (!Array.isArray(parsed.blockdevices)) fail(label);
    return parsed.blockdevices;
  } catch (error) {
    if (error instanceof SyntaxError) fail(label);
    throw error;
  }
}

interface InitialState {
  layout: LsblkNode[];
  pacman: string;
  bootHashes: string;
}

async function initialInspection(
  settings: CaptureSettings,
  stage: string,
): Promise<InitialState> {
  await requireNoPacmanLock("pacman-lock:initial");
  const layout = await lsblkLayout("layout:initial", stage);
  validateSources(settings.sources, layout);
  const pacman = await runCommand(
    "pacman",
    ["-Q"],
    logPath(stage, "packages-before"),
  );
  requireOk(pacman, "packages:before");
  const bootHashes = await runCommand("sha256sum", [
    "/boot/Image",
    "/boot/initramfs-linux.img",
  ], logPath(stage, "boot-before"));
  requireOk(bootHashes, "boot:before");
  await assertMountGuards(settings, stage, "guard:initial");
  return {
    layout,
    pacman: pacman.stdout,
    bootHashes: bootHashes.stdout,
  };
}

async function recordToolVersions(
  stage: string,
): Promise<Record<string, string>> {
  const tools: Record<string, string> = {};
  for (const name of ["tar", "zstd", "gpg", "sfdisk", "vgcfgbackup"]) {
    const result = await runCommand(
      name,
      ["--version"],
      logPath(stage, `tools-${name}`),
    );
    requireOk(result, `tools:${name}`);
    tools[name] = result.stdout.split("\n")[0] ?? "";
  }
  return tools;
}

/** AWK program for the bounded streaming inventory summary: every line of
 * the tar listing is one record, required members are collected inside the
 * record action, and END prints the entry count and fails on an empty
 * archive or any missing required member. */
export function inventoryAwk(requiredMembers: string[]): string {
  const checks = requiredMembers.map((member, index) =>
    `if ($0 == ${JSON.stringify(member)}) r${index} = 1`
  );
  const missing = requiredMembers.map((member, index) =>
    `  if (r${index} != 1) { print ${
      JSON.stringify(`missing ${member}`)
    } > "/dev/stderr"; exit 1 }`
  );
  return [
    "{",
    "  n++",
    ...checks.map((check) => `  ${check}`),
    "}",
    "END {",
    '  printf "entries=%d\\n", n',
    '  if (n == 0) { print "empty archive" > "/dev/stderr"; exit 1 }',
    ...missing,
    "}",
  ].join("\n");
}

/** Exact generated inventory pipeline used by the capture script (and by the
 * synthetic tests with a fixture instead of the staged archive). */
export function inventoryPipeline(
  partial: string,
  requiredMembers: string[],
): string {
  return `zstd -dc ${shellQuote(partial)} | tar -t -f - | awk ${
    shellQuote(inventoryAwk(requiredMembers))
  }`;
}

export interface PipelineProducer {
  /** Short diagnostic label, e.g. "tar" or "awk". */
  label: string;
  /** Shell variable that receives this producer's status from the snapshot. */
  variable: string;
  /** Capture exit code used when this producer fails. */
  exitCode: number;
}

const TAR_ZSTD_PRODUCERS: PipelineProducer[] = [
  { label: "tar", variable: "ts", exitCode: 60 },
  { label: "zstd", variable: "zs", exitCode: 61 },
];
const INVENTORY_PRODUCERS: PipelineProducer[] = [
  { label: "zstd", variable: "s0", exitCode: 63 },
  { label: "tar", variable: "s1", exitCode: 63 },
  { label: "awk", variable: "s2", exitCode: 63 },
];

/** Bash lines that run one pipeline, snapshot the whole PIPESTATUS array in
 * one assignment immediately afterwards and then check each producer
 * separately. Any read of ${PIPESTATUS[...]} after the first assignment is a
 * bug: the array is reset by that assignment and an unset element aborts the
 * script under set -u. */
export function pipelineStatusLines(
  pipeline: string,
  producers: PipelineProducer[],
): string[] {
  for (const producer of producers) {
    if (
      !/^[A-Za-z0-9-]+$/.test(producer.label) ||
      !/^[A-Za-z_][A-Za-z0-9_]*$/.test(producer.variable)
    ) {
      fail("script:generate");
    }
  }
  const lines = [
    pipeline,
    `ps=("\${PIPESTATUS[@]}")`,
  ];
  producers.forEach((producer, index) => {
    lines.push(`${producer.variable}=\${ps[${index}]}`);
  });
  for (const producer of producers) {
    lines.push(
      `test "$${producer.variable}" -eq 0 || { printf '${producer.label} producer exit %s\\n' "$${producer.variable}" >&2; exit ${producer.exitCode}; }`,
    );
  }
  return lines;
}

/** Generated bash lines that record the excluded oracle-root fallback
 * /.swapfile (size, octal mode, uid, gid) from inside the private read-only
 * mount, before the tar exclusion, into a small owner-only stage record that
 * the recovery metadata consumes. */
export function swapfileStatLines(stage: string): string[] {
  const record = shellQuote(`${stage}/oracle-root.swapfile.stat`);
  return [
    "if test -e ./.swapfile; then",
    `  s=$(stat -c '%s %a %u %g' ./.swapfile) || { echo 'oracle-root swapfile stat failed' >&2; exit 76; }`,
    `  printf 'present %s\\n' "$s" > ${record}`,
    "else",
    `  printf 'absent\\n' > ${record}`,
    "fi",
  ];
}

/** One bash child that measures selected bytes, verifies free space, runs
 * the tar pipeline, proves zstd integrity, streams the inventory summary and
 * (for cold roles) mounts the device read-only in a private mount namespace
 * with a full temporary-mountpoint trap. Producer statuses are checked one
 * by one; nothing is silenced. */
function captureScript(params: {
  stage: string;
  role: string;
  source: FileSource;
  relativeExclusions: string[];
  requiredMembers: string[];
  cold: boolean;
}): string {
  const { stage, role, source, relativeExclusions, requiredMembers, cold } =
    params;
  const partial = `${stage}/${role}.tar.zst.partial`;
  const duFile = `${stage}/${role}.du.txt`;
  const lines: string[] = ["umask 077", "set -u", "set -o pipefail"];
  if (cold) {
    lines.push(
      "mount --make-rprivate / || { echo 'mount namespace is not rprivate' >&2; exit 70; }",
    );
    lines.push(
      `dev=$(readlink -f /dev/disk/by-uuid/${source.uuid}) || { echo 'by-uuid device absent' >&2; exit 71; }`,
    );
    lines.push(
      `test -e "$dev" || { echo 'by-uuid device absent' >&2; exit 71; }`,
    );
    lines.push(
      `test "$(blkid -s TYPE -o value "$dev")" = ${
        shellQuote(source.filesystem)
      } || { echo 'device filesystem mismatch' >&2; exit 72; }`,
    );
    lines.push(
      'test -z "$(findmnt -rn -S "$dev")" || { echo \'device already mounted\' >&2; exit 73; }',
    );
    lines.push(
      "d=$(mktemp -d /run/arch-file-capture.XXXXXX) || { echo 'mountpoint creation failed' >&2; exit 74; }",
    );
    lines.push(
      'trap \'umount "$d" 2>/dev/null || true; rmdir "$d" 2>/dev/null || true\' EXIT',
    );
    const mountOptions = source.filesystem === "xfs" ? "ro,norecovery" : "ro";
    lines.push(
      `mount -o ${mountOptions} "$dev" "$d" || { echo 'read-only mount failed' >&2; exit 75; }`,
    );
    lines.push('cd "$d"');
  } else {
    lines.push(`cd ${shellQuote(source.livePath!)}`);
  }
  if (role === "oracle-root") {
    lines.push(...swapfileStatLines(stage));
  }
  const duExcludes = relativeExclusions.map((exclude) =>
    `--exclude=${shellQuote(exclude)}`
  );
  lines.push(
    `du -sx -B1 ${duExcludes.join(" ")} -- . > ${
      shellQuote(duFile)
    } || exit 64`,
  );
  lines.push(`sel=$(cut -f1 ${shellQuote(duFile)})`);
  lines.push(
    `test -n "$sel" || { echo 'du produced no measurement' >&2; exit 64; }`,
  );
  lines.push(`avail=$(df -B1 --output=avail ${shellQuote(stage)} | tail -n 1)`);
  lines.push(
    `test $((avail - 2 * sel)) -ge ${SPACE_MIN_FREE} || { printf 'staging space insufficient selected=%s avail=%s\\n' "$sel" "$avail" >&2; exit 65; }`,
  );
  if (role === "staging-boot") {
    lines.push(
      `sha256sum ./arch-vmlinuz ./arch-initrd.img > ${
        shellQuote(`${stage}/staging-boot.sha.before`)
      }`,
    );
  }
  const tarArgs = [
    ...TAR_OPTIONS,
    ...relativeExclusions.map((exclude) => `--exclude=${exclude}`),
    "--",
    ".",
  ];
  lines.push(`args=(${tarArgs.map(shellQuote).join(" ")})`);
  lines.push(
    ...pipelineStatusLines(
      `tar "\${args[@]}" | zstd -3 -T1 --check -c > ${shellQuote(partial)}`,
      TAR_ZSTD_PRODUCERS,
    ),
  );
  lines.push(
    `zstd -t ${
      shellQuote(partial)
    } >/dev/null || { echo 'zstd integrity check failed' >&2; exit 62; }`,
  );
  lines.push(
    ...pipelineStatusLines(
      inventoryPipeline(partial, requiredMembers),
      INVENTORY_PRODUCERS,
    ),
  );
  if (role === "staging-boot") {
    lines.push(
      `sha256sum ./arch-vmlinuz ./arch-initrd.img > ${
        shellQuote(`${stage}/staging-boot.sha.after`)
      }`,
    );
  }
  return lines.join("\n");
}

async function stagingAvail(stage: string, label: string): Promise<number> {
  const result = await runBash(
    `df -B1 --output=avail ${shellQuote(stage)} | tail -n 1`,
    logPath(stage, label),
  );
  requireOk(result, label);
  const avail = Number(result.stdout.trim());
  if (!Number.isSafeInteger(avail) || avail <= 0) fail(label);
  return avail;
}

async function assertStagingBootParity(
  stage: string,
  before: InitialState,
): Promise<void> {
  const hashes = (text: string): string[] =>
    text.trim().split("\n").map((line) => line.trim().split(/\s+/)[0] ?? "");
  const root = hashes(before.bootHashes);
  const stagedBefore = hashes(
    await Deno.readTextFile(`${stage}/staging-boot.sha.before`),
  );
  const stagedAfter = hashes(
    await Deno.readTextFile(`${stage}/staging-boot.sha.after`),
  );
  if (
    root.length !== 2 || stagedBefore.length !== 2 || stagedAfter.length !== 2
  ) {
    fail("staging-boot:hash");
  }
  const equal = root.every((hash, index) =>
    hash === stagedBefore[index] && hash === stagedAfter[index]
  );
  if (!equal) fail("staging-boot:hash");
}

/** Capture one role: measure, space-check, tar|zstd, verify, inventory,
 * commit, re-check space, encrypt to the pinned recipient, commit and drop
 * the task-owned compressed plaintext. */
async function captureRole(
  settings: CaptureSettings,
  stage: string,
  role: RoleName,
  source: FileSource,
  relativeExclusions: string[],
  before: InitialState,
): Promise<CapturedArchive> {
  const requiredMembers = role === "root"
    ? ["./etc/os-release", "./boot/Image", "./boot/initramfs-linux.img"]
    : role === "staging-boot"
    ? ["./arch-vmlinuz", "./arch-initrd.img"]
    : [];
  const cold = ROLE_SPECS[role].livePath === undefined;
  const label = `capture:${role}`;
  const script = captureScript({
    stage,
    role,
    source,
    relativeExclusions,
    requiredMembers,
    cold,
  });
  const result = cold
    ? await runCommand(
      "unshare",
      ["--mount", "bash", "-c", script],
      logPath(stage, label),
    )
    : await runBash(script, logPath(stage, label));
  requireOk(result, label);
  if (role === "staging-boot") await assertStagingBootParity(stage, before);
  const partial = `${stage}/${role}.tar.zst.partial`;
  const plaintext = `${stage}/${role}.tar.zst`;
  await commitFile(partial, plaintext);
  const size = (await Deno.stat(plaintext)).size;
  const avail = await stagingAvail(stage, `space:${role}`);
  if (avail - size < SPACE_MIN_FREE) fail(`space:${role}`);
  await assertRecipientPinned(settings, stage);
  const cipherPartial = `${stage}/${role}.tar.zst.gpg.partial`;
  const encrypt = await runCommand(
    "gpg",
    gpgArgs(
      `${stage}/gpg-public-home`,
      `${stage}/recipient.asc`,
      cipherPartial,
      plaintext,
    ),
    logPath(stage, `encrypt-${role}`),
  );
  requireOk(encrypt, `encrypt:${role}`);
  const ciphertext = `${stage}/${role}.tar.zst.gpg`;
  await commitFile(cipherPartial, ciphertext);
  await Deno.remove(plaintext);
  const bytes = (await Deno.stat(ciphertext)).size;
  const sha256 = await sha256File(
    ciphertext,
    `hash:${role}`,
    logPath(stage, `hash-${role}`),
  );
  return { role, path: ciphertext, bytes, sha256, format: "tar.zst.gpg" };
}

async function finalInspection(
  settings: CaptureSettings,
  stage: string,
  before: InitialState,
): Promise<LsblkNode[]> {
  await requireNoPacmanLock("pacman-lock:final");
  const layout = await lsblkLayout("layout:final", stage);
  validateSources(settings.sources, layout);
  const pacman = await runCommand(
    "pacman",
    ["-Q"],
    logPath(stage, "packages-after"),
  );
  requireOk(pacman, "packages:after");
  if (pacman.stdout !== before.pacman) fail("packages:after");
  const bootHashes = await runCommand("sha256sum", [
    "/boot/Image",
    "/boot/initramfs-linux.img",
  ], logPath(stage, "boot-after"));
  requireOk(bootHashes, "boot:after");
  if (bootHashes.stdout !== before.bootHashes) fail("boot:after");
  await assertMountGuards(settings, stage, "guard:final");
  return layout;
}

function diskPathFor(
  blockdevices: LsblkNode[],
  uuid: string,
): string | undefined {
  const walk = (
    nodes: LsblkNode[],
    ancestors: LsblkNode[],
  ): string | undefined => {
    for (const node of nodes) {
      if (node.uuid === uuid) {
        const disk = [...ancestors, node].reverse().find((candidate) =>
          candidate.type === "disk"
        );
        return disk?.path?.startsWith("/dev/") ? disk.path : undefined;
      }
      const found = node.children
        ? walk(node.children, [...ancestors, node])
        : undefined;
      if (found) return found;
    }
    return undefined;
  };
  return walk(blockdevices, []);
}

function findmntJson(text: string): unknown {
  try {
    const parsed = JSON.parse(text) as { filesystems?: unknown };
    if (!Array.isArray(parsed.filesystems)) fail("recovery:findmnt");
    return parsed;
  } catch (error) {
    if (error instanceof SyntaxError) fail("recovery:findmnt");
    throw error;
  }
}

async function collectEfivars(stage: string): Promise<unknown> {
  const script = `set -u
if test ! -d /sys/firmware/efi/efivars; then
  echo UNAVAILABLE
  exit 0
fi
n=0
for f in /sys/firmware/efi/efivars/*; do
  test -e "$f" || continue
  b=\${f##*/}
  case "$b" in
    BootOrder-*|BootCurrent-*|BootNext-*|Boot[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]-*)
      test "$n" -lt ${MAX_EFIVARS} || { echo 'too many efivars' >&2; exit 68; }
      s=$(stat -c %s "$f")
      test "$s" -le ${MAX_EFIVAR_BYTES} || { echo 'efivar too large' >&2; exit 69; }
      enc=$(base64 -w 0 "$f") || exit 70
      printf '%s\\t%s\\n' "$b" "$enc"
      n=$((n + 1))
    ;;
  esac
done`;
  const result = await runBash(script, logPath(stage, "recovery-efivars"));
  requireOk(result, "recovery:efivars");
  if (result.stdout.trim() === "UNAVAILABLE") return { available: false };
  const variables = result.stdout.trim().split("\n").filter(Boolean).map(
    (line) => {
      const tab = line.indexOf("\t");
      return { name: line.slice(0, tab), base64: line.slice(tab + 1) };
    },
  );
  return { available: true, variables };
}

function mountMetadata(
  settings: CaptureSettings,
  rootOptions: string,
  efiOptions: string,
): unknown[] {
  return settings.sources.map((source) => {
    const mounted = source.livePath === "/"
      ? rootOptions
      : source.livePath === "/efi"
      ? efiOptions
      : source.filesystem === "xfs"
      ? "ro,norecovery"
      : "ro";
    return {
      name: source.name,
      filesystem: source.filesystem,
      live: source.livePath !== undefined,
      mountOptions: mounted,
      posixOwnershipStored: source.filesystem !== "vfat",
      note: source.filesystem === "vfat"
        ? "VFAT does not store POSIX ownership or mode; values in the archive are synthesized"
        : undefined,
    };
  });
}

export interface SwapfileRecreation {
  present: boolean;
  path?: "/.swapfile";
  bytes?: number;
  /** Octal-mode value as collected by stat. */
  mode?: number;
  uid?: number;
  gid?: number;
  note: string;
}

/** Parse the small owner-only oracle-root swapfile stat record that the
 * capture shell wrote inside the private read-only mount; absent is an
 * explicit state and any malformed record fails closed. */
export function swapfileRecreation(record: string): SwapfileRecreation {
  const trimmed = record.trim();
  if (trimmed === "absent") {
    return {
      present: false,
      note: "oracle-root fallback /.swapfile was absent before exclusion",
    };
  }
  const match = /^present ([0-9]+) ([0-7]+) ([0-9]+) ([0-9]+)$/.exec(trimmed);
  if (!match) fail("swapfile:record");
  const bytes = Number(match[1]);
  const uid = Number(match[3]);
  const gid = Number(match[4]);
  if (
    !Number.isSafeInteger(bytes) || !Number.isSafeInteger(uid) ||
    !Number.isSafeInteger(gid)
  ) {
    fail("swapfile:record");
  }
  return {
    present: true,
    path: "/.swapfile",
    bytes,
    mode: parseInt(match[2], 8),
    uid,
    gid,
    note: "recreate with identical size before fallback boot",
  };
}

async function buildRecoveryBundle(params: {
  settings: CaptureSettings;
  stage: string;
  before: InitialState;
  layoutFinal: LsblkNode[];
  tools: Record<string, string>;
  archives: CapturedArchive[];
  swapRecreation: SwapfileRecreation;
  startedAtUtc: string;
  finishedAtUtc: string;
}): Promise<CapturedArchive> {
  const {
    settings,
    stage,
    before,
    layoutFinal,
    tools,
    archives,
    swapRecreation,
    startedAtUtc,
    finishedAtUtc,
  } = params;
  const findmnt = await runCommand("findmnt", [
    "-J",
    "-o",
    "TARGET,SOURCE,FSTYPE,OPTIONS,UUID",
  ], logPath(stage, "recovery-findmnt"));
  requireOk(findmnt, "recovery:findmnt");
  const mountOptions = async (path: string): Promise<string> => {
    const result = await runCommand(
      "findmnt",
      ["-nro", "OPTIONS", path],
      logPath(stage, "recovery-mount-options"),
    );
    requireOk(result, "recovery:mount-options");
    return result.stdout.trim();
  };
  const rootOptions = await mountOptions("/");
  const efiOptions = await mountOptions("/efi");
  const partitionTables: { disk: string; dump: string }[] = [];
  const seenDisks = new Set<string>();
  const diskSourceNames = ["root", "staging-boot"] as const;
  for (const name of diskSourceNames) {
    const source = settings.sources.find((candidate) =>
      candidate.name === name
    )!;
    const disk = diskPathFor(before.layout, source.uuid);
    if (!disk) fail("recovery:partition-table");
    if (seenDisks.has(disk)) continue;
    seenDisks.add(disk);
    const dump = await runCommand(
      "sfdisk",
      ["--dump", disk],
      logPath(stage, "recovery-sfdisk"),
    );
    requireOk(dump, "recovery:partition-table");
    if (dump.stdout.length > MAX_SFDUMP_BYTES) fail("recovery:partition-table");
    partitionTables.push({ disk, dump: dump.stdout });
  }
  const vgFile = `${stage}/lvm-ocivolume.vg`;
  const lvmResult = await runCommand("vgcfgbackup", [
    "--file",
    vgFile,
    "ocivolume",
  ], logPath(stage, "recovery-lvm"));
  requireOk(lvmResult, "recovery:lvm");
  await Deno.chmod(vgFile, 0o600);
  const vgInfo = await Deno.stat(vgFile);
  if (!vgInfo.isFile || vgInfo.size > MAX_VG_BYTES) fail("recovery:lvm");
  const lvmBytes = await Deno.readFile(vgFile);
  const lvm = {
    volumeGroup: "ocivolume",
    file: vgFile,
    bytes: lvmBytes.length,
    sha256: await sha256Hex(lvmBytes),
    text: new TextDecoder().decode(lvmBytes),
  };
  const cmdline = await runCommand(
    "cat",
    ["/proc/cmdline"],
    logPath(stage, "recovery-cmdline"),
  );
  requireOk(cmdline, "recovery:cmdline");
  const fstab = await runCommand(
    "cat",
    ["/etc/fstab"],
    logPath(stage, "recovery-fstab"),
  );
  requireOk(fstab, "recovery:fstab");
  const efivars = await collectEfivars(stage);
  const exclusions = exclusionPaths(settings.exclusionsText);
  const relativeExclusions = fsRelativeExclusions(exclusions);
  const stagingBootHashes = await Deno.readTextFile(
    `${stage}/staging-boot.sha.after`,
  );
  const manifest = {
    schemaVersion: 1,
    generation: settings.generation,
    startedAtUtc,
    finishedAtUtc,
    consistency: "live-file-copy" as const,
    sourceShutdown: false,
    machineBootRestoreProved: false,
    captureMethod:
      "non-atomic live file copy; no quiescing, outage or error suppression",
    sources: settings.sources,
    blockLayouts: { initial: before.layout, final: layoutFinal },
    mountMetadata: mountMetadata(settings, rootOptions, efiOptions),
    findmnt: findmntJson(findmnt.stdout),
    partitionTables,
    lvm,
    packages: before.pacman,
    bootHashes: { root: before.bootHashes, stagingBoot: stagingBootHashes },
    finalChecks: {
      pacmanLockAbsent: true,
      packagesUnchanged: true,
      bootHashesUnchanged: true,
    },
    exclusions: {
      absolute: exclusions,
      filesystemRelative: relativeExclusions,
    },
    swapRecreation,
    procCmdline: cmdline.stdout,
    fstab: fstab.stdout,
    tools,
    archiveOptions: {
      tar: TAR_OPTION_TEXT,
      zstd: ZSTD_OPTION_TEXT,
      gpg: GPG_OPTION_TEXT,
    },
    archives,
    recipient: {
      fingerprint: settings.recipientFingerprint,
      publicSha256: settings.recipientSha256,
    },
    efivars,
  };
  await writePrivateJson(`${stage}/manifest.json`, manifest);
  const compressedPartial = `${stage}/recovery.json.zst.partial`;
  const compress = await runBash(
    `umask 077
zstd -3 -T1 --check -c < ${shellQuote(`${stage}/manifest.json`)} > ${
      shellQuote(compressedPartial)
    }`,
    logPath(stage, "recovery-compress"),
  );
  requireOk(compress, "recovery:compress");
  const testCompressed = await runCommand(
    "zstd",
    ["-t", compressedPartial],
    logPath(stage, "recovery-compress"),
  );
  requireOk(testCompressed, "recovery:compress");
  const compressed = `${stage}/recovery.json.zst`;
  await commitFile(compressedPartial, compressed);
  const compressedSize = (await Deno.stat(compressed)).size;
  const avail = await stagingAvail(stage, "space:recovery");
  if (avail - compressedSize < SPACE_MIN_FREE) fail("space:recovery");
  await assertRecipientPinned(settings, stage);
  const cipherPartial = `${stage}/recovery.json.zst.gpg.partial`;
  const encrypt = await runCommand(
    "gpg",
    gpgArgs(
      `${stage}/gpg-public-home`,
      `${stage}/recipient.asc`,
      cipherPartial,
      compressed,
    ),
    logPath(stage, "recovery-encrypt"),
  );
  requireOk(encrypt, "recovery:encrypt");
  const ciphertext = `${stage}/recovery.json.zst.gpg`;
  await commitFile(cipherPartial, ciphertext);
  await Deno.remove(compressed);
  await Deno.remove(`${stage}/manifest.json`);
  const bytes = (await Deno.stat(ciphertext)).size;
  const sha256 = await sha256File(
    ciphertext,
    "hash:recovery",
    logPath(stage, "hash-recovery"),
  );
  return {
    role: "recovery",
    path: ciphertext,
    bytes,
    sha256,
    format: "json.zst.gpg",
  };
}

export async function captureGeneration(
  settings: CaptureSettings,
  progress?: (role: string) => Promise<void>,
): Promise<CaptureResult> {
  validateCaptureSettings(settings);
  const startedAtUtc = new Date().toISOString();
  let stage: string | undefined;
  let currentOp = "environment";
  try {
    const platform = await runCommand("uname", ["-s"]);
    if (platform.code !== 0) fail("environment", platform.code);
    if (platform.stdout.trim() !== "Linux") fail("environment");
    const uid = await runCommand("id", ["-u"]);
    if (uid.code !== 0) fail("environment", uid.code);
    if (uid.stdout.trim() !== "0") fail("environment");
    currentOp = "stage:prepare";
    await ensureStageRoot();
    stage = `${STAGE_ROOT}/${settings.generation}`;
    await createGenerationDir(stage);
    currentOp = "recipient";
    await prepareRecipient(settings, stage);
    currentOp = "inspect:initial";
    const before = await initialInspection(settings, stage);
    const tools = await recordToolVersions(stage);
    const exclusions = exclusionPaths(settings.exclusionsText);
    const relativeExclusions = fsRelativeExclusions(exclusions);
    await writePrivateText(
      `${stage}/${EXCLUSIONS_FILE}`,
      exclusions.join("\n") + "\n",
    );
    const archives: CapturedArchive[] = [];
    for (const role of ROLE_ORDER) {
      const source = settings.sources.find((candidate) =>
        candidate.name === role
      )!;
      currentOp = `capture:${role}`;
      const archive = await captureRole(
        settings,
        stage,
        role,
        source,
        relativeExclusions,
        before,
      );
      archives.push(archive);
      currentOp = `guard:${role}`;
      await assertMountGuards(settings, stage, `guard:${role}`);
      await progress?.(role);
    }
    currentOp = "inspect:final";
    const layoutFinal = await finalInspection(settings, stage, before);
    currentOp = "swapfile:record";
    const swapRecreation = swapfileRecreation(
      await Deno.readTextFile(`${stage}/oracle-root.swapfile.stat`),
    );
    currentOp = "recovery";
    const finishedAtUtc = new Date().toISOString();
    const recovery = await buildRecoveryBundle({
      settings,
      stage,
      before,
      layoutFinal,
      tools,
      archives,
      swapRecreation,
      startedAtUtc,
      finishedAtUtc,
    });
    archives.push(recovery);
    await progress?.("recovery");
    return {
      generation: settings.generation,
      stageDirectory: stage,
      archives,
      startedAtUtc,
      finishedAtUtc,
      consistency: "live-file-copy",
      sourceShutdown: false,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.startsWith(FAIL_PREFIX) ||
        message === "Generation stage already exists; caller owns resume"
      ? error
      : new Error(`${FAIL_PREFIX}${currentOp})`);
    if (stage) {
      try {
        await writePrivateText(
          `${stage}/capture-error.txt`,
          `operation=${currentOp}\nerror=${
            normalized instanceof Error
              ? normalized.message
              : String(normalized)
          }\n`,
        );
      } catch {
        // The original failure must reach the caller.
      }
    }
    throw normalized;
  }
}
