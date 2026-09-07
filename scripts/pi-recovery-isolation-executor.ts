/** Target-only draft for copied-root inspection and exact-approved writes.
 * Only inspection is connected; writes remain unwired. This does not establish
 * complete first-boot isolation: copied user
 * agents, shell startup and desktop autostart still require disposition before
 * any boot. No cloud resource, production service, archive transfer or reboot
 * is performed here. */
import { createHash } from "node:crypto";
import { type CommandRunner, defaultRunner } from "./oci.ts";
import { assertAcceptedRescueBoot } from "./pi-recovery-rescue.ts";
import {
  type RecoveryIsolationPlan,
  validateIsolationPlanDigest,
} from "./pi-recovery-isolation.ts";

const BASE = "/run/uos-recovery/isolation";
const ROOT = BASE + "/root";
const STAGE = BASE + "/stage";
const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const OPERATION =
  "apply the inspected copied-root isolation files and masks, replace its SSH host key, and select its isolated default target without rebooting";
interface FileState {
  path: string;
  sha256?: string;
  symlink?: string;
  absent?: true;
  mode?: number;
  uid?: number;
  gid?: number;
}
export interface IsolationInspection {
  planSha256: string;
  rootDevice: string;
  stagingDevice: string;
  owner: { uid: number; gid: number };
  grubSha256: string;
  masks: string[];
  files: FileState[];
  startup: FileState[];
  startupIsolationVerified: false;
  inspectionSha256: string;
}
export interface IsolationExecutionApproval {
  planSha256: string;
  inspectionSha256: string;
  exactOperation: typeof OPERATION;
  approvedAtUtc: string;
}
export function validateIsolationInspection(
  inspection: IsolationInspection,
  plan: RecoveryIsolationPlan,
): void {
  const { inspectionSha256, ...body } = inspection;
  if (
    inspection.planSha256 !== plan.planSha256 ||
    inspection.startupIsolationVerified !== false ||
    !Array.isArray(inspection.startup) || inspection.startup.length > 128 ||
    !/^[0-9a-f]{64}$/.test(inspectionSha256) ||
    hash(body) !== inspectionSha256 ||
    new TextEncoder().encode(JSON.stringify(inspection)).length > 48 * 1024
  ) throw Error("Copied-root inspection is not bound to its plan");
}
export type IsolationExchange = (event: {
  kind: "copied-root-isolation";
  phase: "write-intent" | "files-applied";
  planSha256: string;
  inspectionSha256: string;
}) => Promise<void>;

async function command(
  runner: CommandRunner,
  name: string,
  args: string[],
): Promise<string> {
  const result = await runner(name, args);
  if (result.code !== 0 || result.stdout.length > 1024 * 1024) {
    throw Error(`Isolation command failed: ${name}`);
  }
  return result.stdout.trim();
}
async function runtime(plan: RecoveryIsolationPlan, runner: CommandRunner) {
  validateIsolationPlanDigest(plan);
  if (
    Deno.build.os !== "linux" || Deno.build.arch !== "aarch64" ||
    Deno.uid() !== 0
  ) throw Error("Isolation requires the replacement RAM runtime");
  const b = plan.binding;
  if (
    b.instanceId === b.sourceInstanceId ||
    b.boot.volumeId === b.sourceBootVolumeId ||
    b.root.volumeId === b.sourceRootVolumeId
  ) throw Error("Isolation refuses source resources");
  const accepted = await assertAcceptedRescueBoot({
    targetId: b.instanceId,
    workDirectory: "/run/uos-recovery",
  }, {
    requestId: b.requestId,
    loaderBootId: b.loaderBootId,
    manifestSha256: b.rescueManifestSha256,
  }, runner);
  if (accepted.bootId !== b.bootId) throw Error("Isolation RAM boot changed");
  const instance = JSON.parse(
    await command(runner, "curl", [
      "--fail",
      "--silent",
      "--show-error",
      "--max-time",
      "5",
      "-H",
      "Authorization: Bearer Oracle",
      "http://169.254.169.254/opc/v2/instance/",
    ]),
  );
  if (
    instance.id !== b.instanceId ||
    instance.freeformTags?.uosRecoveryRequest !== b.requestId
  ) throw Error("Isolation instance changed");
}
async function below(
  root: string,
  relative: string,
  createParents = false,
  parentOwner?: { uid: number; gid: number },
): Promise<string> {
  if (
    !/^[A-Za-z0-9_.@/-]+$/.test(relative) || relative.startsWith("/") ||
    relative.split("/").some((p) => !p || p === "." || p === "..")
  ) throw Error("Unsafe copied-root path");
  if (await Deno.realPath(root) !== root) {
    throw Error("Copied-root mount path is a symlink");
  }
  const components = relative.split("/");
  let parent = root;
  for (const component of components.slice(0, -1)) {
    parent += "/" + component;
    if (createParents) {
      let created = false;
      await Deno.mkdir(parent, { mode: 0o755 }).then(() => {
        created = true;
      }).catch((error) => {
        if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
      });
      if (created && parentOwner && parent.startsWith(root + "/home/codex/")) {
        await Deno.chown(parent, parentOwner.uid, parentOwner.gid);
      }
    }
    let resolved: string;
    try {
      resolved = await Deno.realPath(parent);
    } catch (error) {
      if (!createParents && error instanceof Deno.errors.NotFound) {
        return root + "/" + relative;
      }
      throw error;
    }
    if (
      !resolved.startsWith(root + "/") || !(await Deno.stat(parent)).isDirectory
    ) throw Error("Copied-root parent escapes its filesystem");
  }
  return root + "/" + relative;
}
async function regular(root: string, relative: string): Promise<string> {
  const path = await below(root, relative);
  const info = await Deno.lstat(path);
  if (
    !info.isFile || info.isSymlink ||
    !(await Deno.realPath(path)).startsWith(root + "/")
  ) throw Error("Expected regular copied-root file");
  return path;
}
async function fileHash(path: string): Promise<string> {
  const digest = createHash("sha256");
  const buffer = new Uint8Array(1024 * 1024);
  using file = await Deno.open(path, { read: true });
  while (true) {
    const n = await file.read(buffer);
    if (n === null) break;
    if (n === 0) throw Error("Copied-root hash read stalled");
    digest.update(buffer.subarray(0, n));
  }
  return digest.digest("hex");
}
async function snapshotFile(relative: string): Promise<FileState> {
  const path = await below(ROOT, relative);
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      return { path: relative, absent: true };
    }
    throw error;
  }
  if (info.isSymlink) {
    return { path: relative, symlink: await Deno.readLink(path) };
  }
  if (!info.isFile || info.size > 1024 * 1024) {
    throw Error("Managed isolation destination is not a bounded file");
  }
  return {
    path: relative,
    sha256: await fileHash(path),
    mode: info.mode! & 0o777,
    uid: info.uid!,
    gid: info.gid!,
  };
}
async function diskPartitions(
  plan: RecoveryIsolationPlan,
  runner: CommandRunner,
  requireUnmounted = false,
) {
  const tree = JSON.parse(
    await command(runner, "lsblk", [
      "--json",
      "--tree",
      "--paths",
      "--bytes",
      "--output",
      "PATH,TYPE,SIZE,RO,FSTYPE,UUID,MOUNTPOINTS",
    ]),
  );
  type Node = {
    path: string;
    type: string;
    size: number;
    ro: boolean;
    fstype: string | null;
    uuid: string | null;
    mountpoints?: (string | null)[];
    children?: Node[];
  };
  const disks = (tree.blockdevices as Node[]).filter((node) =>
    node.type === "disk"
  );
  if (disks.length !== 2) {
    throw Error("Isolation requires exactly the two replacement disks");
  }
  const unmounted = (node: Node): void => {
    if (node.mountpoints?.some(Boolean)) {
      throw Error("Isolation refuses an already mounted replacement disk");
    }
    for (const child of node.children ?? []) unmounted(child);
  };
  if (requireUnmounted) { for (const disk of disks) unmounted(disk); }
  const found: Record<string, string> = {};
  for (const role of ["boot", "root"] as const) {
    const expected = plan.binding[role];
    const resolved = await command(runner, "readlink", ["-f", expected.path]);
    const matches = disks.filter((node) =>
      node.path === resolved && node.size === expected.bytes && !node.ro
    );
    if (matches.length !== 1) {
      throw Error("Isolation disk path or capacity changed");
    }
    const serials = (await command(runner, "udevadm", [
      "info",
      "--query=property",
      "--name=" + resolved,
    ])).split("\n").filter((line) => line.startsWith("ID_SCSI_SERIAL="));
    if (
      serials.length !== 1 || serials[0] !== "ID_SCSI_SERIAL=" + expected.serial
    ) throw Error("Isolation disk serial changed");
    const uuid = role === "root" ? plan.rootUuid : plan.stagingUuid;
    const filesystem = role === "root" ? "ext4" : "xfs";
    const parts = (matches[0].children ?? []).filter((node) =>
      node.type === "part" && node.uuid === uuid &&
      node.fstype === filesystem && !node.ro
    );
    if (parts.length !== 1) {
      throw Error("Isolation filesystem is not on its bound disk");
    }
    found[role] = parts[0].path;
  }
  return { rootDevice: found.root, stagingDevice: found.boot };
}

/** Retain hashes and link targets only, never copied startup file contents.
 * This is a bounded inventory for disposition, not an execution-policy proof.
 * Do not follow directory links into arbitrary copied or host filesystems. */
async function inspectCopiedStartup(): Promise<FileState[]> {
  const paths = new Set([
    "etc/profile",
    "etc/bash.bashrc",
    "etc/bash.bash_logout",
    "etc/ssh/sshrc",
    "etc/pam.d/sshd",
    "etc/pam.d/system-login",
    "home/codex/.profile",
    "home/codex/.bash_profile",
    "home/codex/.bash_login",
    "home/codex/.bashrc",
    "home/codex/.bash_logout",
    "home/codex/.zshenv",
    "home/codex/.zprofile",
    "home/codex/.zshrc",
    "home/codex/.zlogin",
    "home/codex/.ssh/rc",
    "home/codex/.xinitrc",
    "home/codex/.xsession",
  ]);
  let entries = 0;
  const visit = async (relative: string, depth: number): Promise<void> => {
    if (depth > 6) {
      throw Error("Copied startup directory depth exceeds its bound");
    }
    const path = await below(ROOT, relative);
    const info = await Deno.lstat(path).catch((error) => {
      if (error instanceof Deno.errors.NotFound) return null;
      throw error;
    });
    if (!info) {
      paths.add(relative);
      return;
    }
    if (!info.isDirectory || info.isSymlink) {
      paths.add(relative);
      return;
    }
    for await (const entry of Deno.readDir(path)) {
      if (++entries > 128) {
        throw Error("Copied startup inventory exceeds its bound");
      }
      await visit(relative + "/" + entry.name, depth + 1);
    }
  };
  for (
    const directory of [
      "etc/profile.d",
      "etc/zsh",
      "etc/systemd/system",
      "etc/systemd/user",
      "home/codex/.config/systemd/user",
      "etc/xdg/autostart",
      "home/codex/.config/autostart",
    ]
  ) await visit(directory, 0);
  if (paths.size > 128) {
    throw Error("Copied startup inventory exceeds its bound");
  }
  const result: FileState[] = [];
  for (const path of [...paths].sort()) result.push(await snapshotFile(path));
  return result;
}

/** The caller first mounts only the bound copies read-only at ROOT and STAGE.
 * This inspection neither remounts them nor accepts uninspected write targets. */
export async function inspectCopiedRootIsolation(
  plan: RecoveryIsolationPlan,
  runner: CommandRunner = defaultRunner,
): Promise<IsolationInspection> {
  await runtime(plan, runner);
  const devices = await diskPartitions(plan, runner);
  for (
    const [path, uuid, device, type] of [[
      ROOT,
      plan.rootUuid,
      devices.rootDevice,
      "ext4",
    ], [STAGE, plan.stagingUuid, devices.stagingDevice, "xfs"]]
  ) {
    const mounts = JSON.parse(
      await command(runner, "findmnt", [
        "--json",
        "--target",
        path,
        "--output",
        "TARGET,SOURCE,UUID,FSTYPE,OPTIONS",
      ]),
    ).filesystems;
    if (
      !Array.isArray(mounts) || mounts.length !== 1 ||
      mounts[0].target !== path || mounts[0].source !== device ||
      mounts[0].uuid !== uuid || mounts[0].fstype !== type ||
      !mounts[0].options?.split(",").includes("ro")
    ) throw Error("Isolation copy is not its bound read-only mount");
  }
  for (
    const [root, path, expected] of [
      [ROOT, "boot/Image", plan.kernelSha256],
      [ROOT, "boot/initramfs-linux.img", plan.initramfsSha256],
      [STAGE, "arch-vmlinuz", plan.kernelSha256],
      [STAGE, "arch-initrd.img", plan.initramfsSha256],
    ]
  ) {
    if (await fileHash(await regular(root, path)) !== expected) {
      throw Error("Copied boot files differ from the accepted backup");
    }
  }
  const grubPath = await regular(STAGE, "grub2/grub.cfg");
  if ((await Deno.stat(grubPath)).size > 65536) {
    throw Error("Copied GRUB configuration exceeds its bound");
  }
  const grub = await Deno.readTextFile(grubPath);
  if (
    !/^set default=0$/m.test(grub) ||
    grub.split("\n").find((line) => line.startsWith("menuentry ")) !==
      'menuentry "Arch Linux ARM" {' ||
    /^\s*set\s+fallback/m.test(grub) ||
    !grub.includes("root=UUID=" + plan.rootUuid) ||
    !grub.includes("Oracle Linux (fallback)")
  ) throw Error("Copied boot chain needs separate repair before isolation");
  const releasePath = await below(ROOT, "etc/os-release");
  const releaseInfo = await Deno.lstat(releasePath);
  let releaseRelative = "etc/os-release";
  if (releaseInfo.isSymlink) {
    const target = await Deno.readLink(releasePath);
    if (!["../usr/lib/os-release", "/usr/lib/os-release"].includes(target)) {
      throw Error(
        "Copied os-release link is not the standard local release file",
      );
    }
    releaseRelative = "usr/lib/os-release";
  }
  const osPath = await regular(ROOT, releaseRelative);
  if (
    (await Deno.stat(osPath)).size > 65536 ||
    !/^ID=(?:arch|"arch")$/m.test(await Deno.readTextFile(osPath))
  ) throw Error("Copied root is not Arch");
  await regular(ROOT, "usr/bin/nft");
  const home = await below(ROOT, "home/codex");
  const owner = await Deno.lstat(home);
  if (!owner.isDirectory || owner.isSymlink || !owner.uid || !owner.gid) {
    throw Error("Copied codex home identity is unavailable");
  }
  const masks = new Set(plan.masks);
  for (
    const [directory, prefix] of [
      ["usr/lib/systemd/system", "etc/systemd/system"],
      ["etc/systemd/system", "etc/systemd/system"],
      ["usr/lib/systemd/user", "etc/systemd/user"],
      ["etc/systemd/user", "etc/systemd/user"],
      ["home/codex/.config/systemd/user", "home/codex/.config/systemd/user"],
    ]
  ) {
    const path = await below(ROOT, directory);
    try {
      if (!(await Deno.realPath(path)).startsWith(ROOT + "/")) {
        throw Error("Copied timer directory escapes root");
      }
      for await (const entry of Deno.readDir(path)) {
        if (entry.name.endsWith(".timer")) masks.add(prefix + "/" + entry.name);
        if (masks.size > 512) {
          throw Error("Copied timer inventory exceeds its bound");
        }
      }
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  }
  const paths = [
    ...new Set([
      ...Object.keys(plan.files),
      ...masks,
      "etc/systemd/system/default.target",
      "etc/ssh/ssh_host_ed25519_key",
      "etc/ssh/ssh_host_ed25519_key.pub",
    ]),
  ].sort();
  const files: FileState[] = [];
  for (const path of paths) files.push(await snapshotFile(path));
  const body = {
    planSha256: plan.planSha256,
    ...devices,
    owner: { uid: owner.uid!, gid: owner.gid! },
    grubSha256: await fileHash(grubPath),
    masks: [...masks].sort(),
    files,
    startup: await inspectCopiedStartup(),
    startupIsolationVerified: false as const,
  };
  const result = { ...body, inspectionSha256: hash(body) };
  if (new TextEncoder().encode(JSON.stringify(result)).length > 48 * 1024) {
    throw Error("Isolation inspection exceeds its control bound");
  }
  return result;
}

export const ISOLATION_EXECUTION_OPERATION = OPERATION;
export interface IsolationExecutionReceipt {
  status: "COPIED_ROOT_ISOLATION_APPLIED";
  planSha256: string;
  inspectionSha256: string;
  restoredManifestSha256: string;
  hostPublicKey: string;
  mountsReleased: true;
  bootAccepted: false;
  applicationAccepted: false;
}
export function validateIsolationExecutionApproval(
  plan: RecoveryIsolationPlan,
  inspection: IsolationInspection,
  approval: IsolationExecutionApproval | undefined,
  now = Date.now(),
) {
  const age = now - Date.parse(approval?.approvedAtUtc ?? "");
  if (
    !approval || approval.planSha256 !== plan.planSha256 ||
    approval.inspectionSha256 !== inspection.inspectionSha256 ||
    approval.exactOperation !== OPERATION || !Number.isFinite(age) || age < 0 ||
    age > 3600000
  ) throw Error("Current exact copied-root isolation approval is required");
}
const approvalMatches = validateIsolationExecutionApproval;
async function writeCopy(
  relative: string,
  bytes: Uint8Array,
  mode: number,
  owner: { uid: number; gid: number },
) {
  const destination = await below(ROOT, relative, true, owner);
  const info = await Deno.lstat(destination).catch((error) => {
    if (error instanceof Deno.errors.NotFound) return null;
    throw error;
  });
  if (info && !info.isFile) {
    throw Error("Copied-root file destination changed type");
  }
  const temporary = destination + ".uos-isolation-" + crypto.randomUUID();
  using file = await Deno.open(temporary, {
    createNew: true,
    write: true,
    mode,
  });
  let offset = 0;
  while (offset < bytes.length) {
    const written = await file.write(bytes.subarray(offset));
    if (written === 0) throw Error("Copied-root write stalled");
    offset += written;
  }
  await Deno.chmod(temporary, mode);
  await Deno.chown(temporary, owner.uid, owner.gid);
  await file.sync();
  await Deno.rename(temporary, destination);
}
async function writeLink(relative: string, target: string) {
  const destination = await below(ROOT, relative, true);
  const info = await Deno.lstat(destination).catch((error) => {
    if (error instanceof Deno.errors.NotFound) return null;
    throw error;
  });
  if (info && !info.isFile && !info.isSymlink) {
    throw Error("Copied-root mask destination changed type");
  }
  const temporary = destination + ".uos-isolation-" + crypto.randomUUID();
  await Deno.symlink(target, temporary);
  await Deno.rename(temporary, destination);
}
async function applyInspectedIsolation(
  plan: RecoveryIsolationPlan,
  inspection: IsolationInspection,
  approval: IsolationExecutionApproval,
  exchange: IsolationExchange,
  runner: CommandRunner,
): Promise<string> {
  approvalMatches(plan, inspection, approval);
  if (
    (await inspectCopiedRootIsolation(plan, runner)).inspectionSha256 !==
      inspection.inspectionSha256
  ) throw Error("Copied-root inspection changed before approval");
  await exchange({
    kind: "copied-root-isolation",
    phase: "write-intent",
    planSha256: plan.planSha256,
    inspectionSha256: inspection.inspectionSha256,
  });
  approvalMatches(plan, inspection, approval);
  if (
    (await inspectCopiedRootIsolation(plan, runner)).inspectionSha256 !==
      inspection.inspectionSha256
  ) throw Error("Copied-root inspection changed during approval exchange");
  const keyDirectory = BASE + "/host-" + inspection.inspectionSha256;
  await Deno.mkdir(keyDirectory, { mode: 0o700 });
  const key = keyDirectory + "/ssh_host_ed25519_key";
  await command(runner, "ssh-keygen", [
    "-q",
    "-t",
    "ed25519",
    "-N",
    "",
    "-f",
    key,
  ]);
  const publicKey = (await Deno.readTextFile(key + ".pub")).trim();
  if (!/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?$/.test(publicKey)) {
    throw Error("Replacement host public key is malformed");
  }
  approvalMatches(plan, inspection, approval);
  await command(runner, "mount", ["-o", "remount,rw", ROOT]);
  for (const [relative, text] of Object.entries(plan.files)) {
    approvalMatches(plan, inspection, approval);
    const user = relative.startsWith("home/codex/");
    await writeCopy(
      relative,
      new TextEncoder().encode(text),
      relative.endsWith("authorized_keys") ? 0o600 : 0o644,
      user ? inspection.owner : { uid: 0, gid: 0 },
    );
  }
  approvalMatches(plan, inspection, approval);
  await writeCopy(
    "etc/ssh/ssh_host_ed25519_key",
    await Deno.readFile(key),
    0o600,
    { uid: 0, gid: 0 },
  );
  approvalMatches(plan, inspection, approval);
  await writeCopy(
    "etc/ssh/ssh_host_ed25519_key.pub",
    new TextEncoder().encode(publicKey + "\n"),
    0o644,
    { uid: 0, gid: 0 },
  );
  for (const relative of inspection.masks) {
    approvalMatches(plan, inspection, approval);
    await writeLink(relative, "/dev/null");
  }
  approvalMatches(plan, inspection, approval);
  await writeLink(
    "etc/systemd/system/default.target",
    "/etc/systemd/system/arch-drill.target",
  );
  const sshDirectory = await below(ROOT, "home/codex/.ssh");
  approvalMatches(plan, inspection, approval);
  await Deno.chmod(sshDirectory, 0o700);
  approvalMatches(plan, inspection, approval);
  await Deno.chown(sshDirectory, inspection.owner.uid, inspection.owner.gid);
  for (const [relative, text] of Object.entries(plan.files)) {
    if (await Deno.readTextFile(await regular(ROOT, relative)) !== text) {
      throw Error("Applied isolation file differs");
    }
  }
  for (const relative of inspection.masks) {
    if (await Deno.readLink(await below(ROOT, relative)) !== "/dev/null") {
      throw Error("Applied isolation mask differs");
    }
  }
  if (
    await Deno.readLink(
      await below(ROOT, "etc/systemd/system/default.target"),
    ) !== "/etc/systemd/system/arch-drill.target"
  ) throw Error("Isolated default target differs");
  const installedPublic = await command(runner, "ssh-keygen", [
    "-y",
    "-f",
    await regular(ROOT, "etc/ssh/ssh_host_ed25519_key"),
  ]);
  if (installedPublic !== publicKey.split(/\s+/).slice(0, 2).join(" ")) {
    throw Error("Copied private host key does not match its public key");
  }
  if (
    await fileHash(await regular(ROOT, "etc/uos-rescue/manifest.json")) !==
      plan.restoredManifestSha256
  ) throw Error("Restored manifest differs");
  await command(runner, "sync", []);
  await command(runner, "mount", ["-o", "remount,ro", ROOT]);
  await exchange({
    kind: "copied-root-isolation",
    phase: "files-applied",
    planSha256: plan.planSha256,
    inspectionSha256: inspection.inspectionSha256,
  });
  return publicKey;
}

/** Mount only the serial/UUID-bound reconstructed copies. Missing approval
 * returns their inspection without writes to either copied filesystem. An
 * interrupted apply must be reconciled by the caller before another invocation. */
export async function executeCopiedRootIsolation(
  plan: RecoveryIsolationPlan,
  authorize: (
    inspection: IsolationInspection,
  ) => Promise<IsolationExecutionApproval | undefined>,
  exchange: IsolationExchange,
  runner: CommandRunner = defaultRunner,
): Promise<
  { inspection: IsolationInspection; receipt?: IsolationExecutionReceipt }
> {
  await runtime(plan, runner);
  const devices = await diskPartitions(plan, runner, true);
  await command(runner, "bash", [
    "-ec",
    'own=$(readlink /proc/self/ns/mnt); for ns in /proc/[0-9]*/ns/mnt; do observed=$(readlink "$ns") || continue; test "$observed" = "$own"; done',
  ]);
  await Deno.mkdir(BASE, { mode: 0o700 }).catch((error) => {
    if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
  });
  const baseInfo = await Deno.lstat(BASE);
  if (
    !baseInfo.isDirectory || baseInfo.isSymlink ||
    (baseInfo.mode! & 0o777) !== 0o700 || await Deno.realPath(BASE) !== BASE
  ) throw Error("Isolation RAM directory is unsafe");
  for (const path of [ROOT, STAGE]) {
    await Deno.mkdir(path, { mode: 0o700 }).catch((error) => {
      if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
    });
    if (await Deno.realPath(path) !== path) {
      throw Error("Isolation mount directory is a symlink");
    }
    for await (const _entry of Deno.readDir(path)) {
      throw Error("Isolation mount directory is not empty");
    }
  }
  const mounted: string[] = [];
  let result: {
    inspection: IsolationInspection;
    receipt?: IsolationExecutionReceipt;
  } | undefined;
  let releaseError: Error | undefined;
  try {
    await command(runner, "mount", [
      "-o",
      "ro,noload",
      devices.rootDevice,
      ROOT,
    ]);
    mounted.push(ROOT);
    await command(runner, "mount", [
      "-o",
      "ro,norecovery,nouuid",
      devices.stagingDevice,
      STAGE,
    ]);
    mounted.push(STAGE);
    const inspection = await inspectCopiedRootIsolation(plan, runner);
    const approval = await authorize(inspection);
    result = { inspection };
    if (approval) {
      const hostPublicKey = await applyInspectedIsolation(
        plan,
        inspection,
        approval,
        exchange,
        runner,
      );
      result.receipt = {
        status: "COPIED_ROOT_ISOLATION_APPLIED",
        planSha256: plan.planSha256,
        inspectionSha256: inspection.inspectionSha256,
        restoredManifestSha256: plan.restoredManifestSha256,
        hostPublicKey,
        mountsReleased: true,
        bootAccepted: false,
        applicationAccepted: false,
      };
    }
  } finally {
    const errors: unknown[] = [];
    for (const path of mounted.reverse()) {
      try {
        await command(runner, "umount", [path]);
      } catch (error) {
        errors.push(error);
      }
    }
    if (errors.length) {
      releaseError = Error(
        "Owned isolation mounts could not all be released; preserve the recovery intent",
      );
    }
  }
  if (releaseError) throw releaseError;
  await diskPartitions(plan, runner, true);
  return result!;
}

/** Target-side entry point for the second, explicitly approved isolation
 * stage. The Pi sends only the bounded plan, inspection and approval; the
 * replacement performs the mounts and writes locally. */
if (import.meta.main) {
  try {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for await (const chunk of Deno.stdin.readable) {
      total += chunk.byteLength;
      if (total > 128 * 1024) {
        throw Error("Isolation control input is too large");
      }
      chunks.push(chunk);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const payload = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    if (!payload || typeof payload !== "object") {
      throw Error("Isolation control input is malformed");
    }
    const result = await executeCopiedRootIsolation(
      payload.plan,
      (inspection) => {
        validateIsolationInspection(inspection, payload.plan);
        if (JSON.stringify(inspection) !== JSON.stringify(payload.inspection)) {
          return Promise.reject(
            Error("Current copied-root inspection differs from the Pi receipt"),
          );
        }
        return Promise.resolve(payload.approval);
      },
      async (event) => {
        await Deno.stdout.write(
          new TextEncoder().encode(
            JSON.stringify({ kind: "recovery-isolation-event", event }) + "\n",
          ),
        );
      },
    );
    await Deno.stdout.write(
      new TextEncoder().encode(
        JSON.stringify({ kind: "recovery-isolation-result", result }) + "\n",
      ),
    );
  } catch (error) {
    console.error(
      error instanceof Error ? error.message : "Isolation execution failed",
    );
    Deno.exitCode = 1;
  }
}
