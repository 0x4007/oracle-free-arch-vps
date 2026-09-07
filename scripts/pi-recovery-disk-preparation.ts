/** Approved clearing of the replacement's platform-image signatures in RAM.
 * No source disk is accepted. The controller must revalidate OCI attachments
 * and durably acknowledge every intent before this target can write a disk.
 */
import { createHash } from "node:crypto";
import { assertRamRescueRuntime } from "./pi-recovery-rescue.ts";
import { type CommandRunner, defaultRunner } from "./oci.ts";

export interface PreparationDisk {
  volumeId: string;
  path: string;
  serial: string;
  bytes: number;
}
export interface DiskPreparationBinding {
  requestId: string;
  instanceId: string;
  bootId: string;
  sourceInstanceId: string;
  sourceBootVolumeId: string;
  sourceRootVolumeId: string;
  boot: PreparationDisk;
  root: PreparationDisk;
}
interface BlockNode {
  path: string;
  type: string;
  size: number;
  ro: boolean;
  serial?: string | null;
  uuid?: string | null;
  fstype?: string | null;
  "maj:min": string;
  mountpoints?: (string | null)[] | null;
  children?: BlockNode[];
}
export interface PreparationSnapshot {
  disks: { role: "boot" | "root"; nodes: BlockNode[]; signatures: unknown[] }[];
  sha256: string;
}
export interface DiskPreparationPlan {
  binding: DiskPreparationBinding;
  snapshot: PreparationSnapshot;
  operation:
    "clear filesystem and partition-table signatures from only the bound replacement boot and root disks";
  planSha256: string;
}
export interface PreparationApproval {
  planSha256: string;
  exactOperation: DiskPreparationPlan["operation"];
  approvedAtUtc: string;
}
export interface PreparationEvent {
  kind: "disk-preparation";
  planSha256: string;
  instanceId: string;
  bootId: string;
  phase:
    | "ready"
    | "boot-clear-intent"
    | "boot-cleared"
    | "root-clear-intent"
    | "root-cleared"
    | "complete";
  snapshotSha256: string;
}
/** Return only after fresh provider/ownership checks and durable Pi persistence.
 * A failed exchange must throw; a pending exchange cannot authorize a write.
 */
export type PreparationExchange = (event: PreparationEvent) => Promise<void>;
const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const operation =
  "clear filesystem and partition-table signatures from only the bound replacement boot and root disks" as const;
function assertBinding(binding: DiskPreparationBinding) {
  const ocid = (value: string, kind: string) =>
    new RegExp(`^ocid1\\.${kind}\\.[a-zA-Z0-9.]+$`).test(value);
  if (
    !binding || !ocid(binding.instanceId, "instance") ||
    !ocid(binding.sourceInstanceId, "instance") ||
    binding.instanceId === binding.sourceInstanceId ||
    !ocid(binding.boot.volumeId, "bootvolume") ||
    !ocid(binding.root.volumeId, "volume") ||
    !ocid(binding.sourceBootVolumeId, "bootvolume") ||
    !ocid(binding.sourceRootVolumeId, "volume") ||
    binding.boot.volumeId === binding.sourceBootVolumeId ||
    binding.root.volumeId === binding.sourceRootVolumeId ||
    binding.boot.bytes !== 50 * 1024 ** 3 ||
    binding.root.bytes !== 150 * 1024 ** 3 ||
    binding.boot.path === binding.root.path ||
    binding.boot.serial === binding.root.serial ||
    ![binding.boot, binding.root].every((disk) =>
      /^\/dev\/disk\/by-id\/(?:scsi|virtio)-[A-Za-z0-9_.+:-]+$/.test(
        disk.path,
      ) &&
      /^[A-Za-z0-9_.+:-]+$/.test(disk.serial)
    )
  ) {
    throw Error(
      "Disk preparation is not bound to distinct replacement resources",
    );
  }
}
async function run(runner: CommandRunner, command: string, args: string[]) {
  const result = await runner(command, args);
  if (result.code !== 0 || result.stdout.length > 1024 * 1024) {
    throw Error(`Disk preparation evidence or operation failed: ${command}`);
  }
  return result.stdout.trim();
}
function flatten(nodes: BlockNode[]): BlockNode[] {
  const output: BlockNode[] = [];
  const visit = (node: BlockNode) => {
    if (output.length >= 64 || !node || typeof node !== "object") {
      throw Error("Unexpected block tree");
    }
    output.push(node);
    for (const child of node.children ?? []) visit(child);
  };
  for (const node of nodes) visit(node);
  return output;
}

/** Read-only. Only a RAM guest with exactly the two serial-bound whole disks
 * and no mounts, writable holders or alternate mount namespaces can pass.
 */
export async function inspectPreparationDisks(
  binding: DiskPreparationBinding,
  runner: CommandRunner = defaultRunner,
): Promise<PreparationSnapshot> {
  assertBinding(binding);
  const runtime = await assertRamRescueRuntime(
    { targetId: binding.instanceId, workDirectory: "/run/uos-recovery" },
    binding.requestId,
    runner,
  );
  if (runtime.bootId !== binding.bootId) {
    throw Error("Disk preparation RAM boot changed");
  }
  const identity = JSON.parse(
    await run(runner, "curl", [
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
    identity.id !== binding.instanceId ||
    identity.freeformTags?.uosRecoveryRequest !== binding.requestId
  ) throw Error("Disk preparation instance identity differs");
  const tree = JSON.parse(
    await run(runner, "lsblk", [
      "--json",
      "--bytes",
      "--output",
      "PATH,TYPE,SIZE,RO,SERIAL,UUID,FSTYPE,MAJ:MIN,MOUNTPOINTS",
    ]),
  );
  if (!Array.isArray(tree.blockdevices)) {
    throw Error("Block inventory is unavailable");
  }
  const all = flatten(tree.blockdevices);
  const physical = all.filter((node) => node.type === "disk");
  if (physical.length !== 2) {
    throw Error("Replacement must have exactly two physical disks");
  }
  const mounts = JSON.parse(
    await run(runner, "findmnt", ["--json", "--output", "MAJ:MIN"]),
  );
  const mountIds = new Set<string>();
  const collectMounts = (entries: Record<string, unknown>[], depth = 0) => {
    if (!Array.isArray(entries) || depth > 64) {
      throw Error("Mount evidence is malformed");
    }
    for (const entry of entries) {
      if (!entry || typeof entry["maj:min"] !== "string") {
        throw Error("Mount device identity is absent");
      }
      mountIds.add(entry["maj:min"]);
      if (entry.children) {
        collectMounts(entry.children as Record<string, unknown>[], depth + 1);
      }
    }
  };
  collectMounts(mounts.filesystems);
  const disks: PreparationSnapshot["disks"] = [];
  for (const role of ["boot", "root"] as const) {
    const disk = binding[role];
    const resolved = await run(runner, "readlink", ["-f", disk.path]);
    const found = physical.filter((node) => node.path === resolved);
    if (found.length !== 1 || found[0].size !== disk.bytes) {
      throw Error("Replacement disk path or size differs");
    }
    const top = found[0];
    if (/^\/dev\/sd[a-z]+$/.test(top.path)) {
      const serials = (await run(runner, "udevadm", [
        "info",
        "--query=property",
        "--name=" + top.path,
      ])).split("\n").filter((line) => line.startsWith("ID_SCSI_SERIAL="));
      if (serials.length !== 1) {
        throw Error("Full SCSI hardware serial is unavailable");
      }
      top.serial = serials[0].slice("ID_SCSI_SERIAL=".length);
    }
    if (top.serial !== disk.serial) {
      throw Error("Replacement hardware serial differs");
    }
    const nodes = flatten([top]);
    for (const node of nodes) {
      if (
        !/^\/dev\/(?:sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+)(?:p?[0-9]+)?$/.test(
          node.path,
        ) ||
        !["disk", "part"].includes(node.type) || node.ro !== false ||
        typeof node["maj:min"] !== "string" || mountIds.has(node["maj:min"]) ||
        (node.mountpoints ?? []).some((value) => value !== null && value !== "")
      ) {
        throw Error(
          "Replacement disk has mounted, read-only or mapped children",
        );
      }
    }
    await run(runner, "bash", [
      "-ec",
      'for device in "$@"; do name=${device##*/}; test -d "/sys/class/block/$name/holders"; for holder in /sys/class/block/"$name"/holders/*; do test ! -e "$holder"; done; done; own=$(readlink /proc/self/ns/mnt); for ns in /proc/[0-9]*/ns/mnt; do observed=$(readlink "$ns") || continue; test "$observed" = "$own"; done',
      "preparation-read-only",
      ...nodes.map((node) => node.path),
    ]);
    const signatures = [];
    for (const node of nodes) {
      const value = JSON.parse(
        await run(runner, "wipefs", [
          "--json",
          "--output",
          "TYPE,UUID,OFFSET",
          node.path,
        ]),
      );
      if (!Array.isArray(value.signatures)) {
        throw Error("Disk signature evidence is absent");
      }
      signatures.push(value.signatures);
    }
    disks.push({ role, nodes, signatures });
  }
  if (disks[0].nodes[0].path === disks[1].nodes[0].path) {
    throw Error("Replacement disk aliases collide");
  }
  return { disks, sha256: hash(disks) };
}

export function diskPreparationPlan(
  binding: DiskPreparationBinding,
  snapshot: PreparationSnapshot,
): DiskPreparationPlan {
  assertBinding(binding);
  if (snapshot.sha256 !== hash(snapshot.disks) || snapshot.disks.length !== 2) {
    throw Error("Preparation snapshot digest differs");
  }
  const body = { binding, snapshot, operation };
  return structuredClone({ ...body, planSha256: hash(body) });
}
function assertApproval(
  plan: DiskPreparationPlan,
  approval: PreparationApproval,
  now: number,
) {
  if (
    diskPreparationPlan(plan.binding, plan.snapshot).planSha256 !==
      plan.planSha256 ||
    !approval || approval.planSha256 !== plan.planSha256 ||
    approval.exactOperation !== operation ||
    !Number.isFinite(Date.parse(approval.approvedAtUtc)) ||
    Date.parse(approval.approvedAtUtc) > now ||
    now - Date.parse(approval.approvedAtUtc) > 3600000
  ) throw Error("Current exact disk-clearing approval is required");
}
function pristine(snapshot: PreparationSnapshot, role: "boot" | "root") {
  const disk = snapshot.disks.find((entry) => entry.role === role);
  return !!disk && disk.nodes.length === 1 && !disk.nodes[0].fstype &&
    !disk.nodes[0].uuid &&
    disk.signatures.length === 1 && Array.isArray(disk.signatures[0]) &&
    disk.signatures[0].length === 0;
}

/** Deliberately has no implicit resume: an interrupted wipe requires a fresh
 * read-only plan and exact approval. Already restored disks must not be fed
 * back into this entry point. Booting is never part of preparation acceptance.
 */
export async function prepareReplacementDisks(
  plan: DiskPreparationPlan,
  approval: PreparationApproval,
  exchange: PreparationExchange,
  runner: CommandRunner = defaultRunner,
  now = () => Date.now(),
) {
  assertApproval(plan, approval, now());
  if (typeof exchange !== "function") {
    throw Error("Durable Pi preparation exchange is required");
  }
  let current = await inspectPreparationDisks(plan.binding, runner);
  if (current.sha256 !== plan.snapshot.sha256) {
    throw Error("Disk preparation inventory changed since approval");
  }
  const acknowledge = (phase: PreparationEvent["phase"]) =>
    exchange({
      kind: "disk-preparation",
      planSha256: plan.planSha256,
      instanceId: plan.binding.instanceId,
      bootId: plan.binding.bootId,
      phase,
      snapshotSha256: current.sha256,
    });
  await acknowledge("ready");
  for (const role of ["boot", "root"] as const) {
    assertApproval(plan, approval, now());
    const before = await inspectPreparationDisks(plan.binding, runner);
    if (before.sha256 !== current.sha256) {
      throw Error("Replacement disk changed before clearing");
    }
    await acknowledge(
      role === "boot" ? "boot-clear-intent" : "root-clear-intent",
    );
    // Recheck after the controller round trip, not only before it.
    assertApproval(plan, approval, now());
    if (
      (await inspectPreparationDisks(plan.binding, runner)).sha256 !==
        current.sha256
    ) throw Error("Replacement disk changed during approval exchange");
    await run(runner, "wipefs", ["--all", plan.binding[role].path]);
    await run(runner, "blockdev", ["--rereadpt", plan.binding[role].path]);
    await run(runner, "udevadm", ["settle", "--timeout=10"]);
    await run(runner, "sync", []);
    const after = await inspectPreparationDisks(plan.binding, runner);
    const other = role === "boot" ? "root" : "boot";
    if (
      !pristine(after, role) ||
      hash(after.disks.find((entry) => entry.role === other)) !==
        hash(current.disks.find((entry) => entry.role === other))
    ) {
      throw Error(
        "Disk clearing did not produce the exact expected pristine result",
      );
    }
    current = after;
    await acknowledge(role === "boot" ? "boot-cleared" : "root-cleared");
  }
  await acknowledge("complete");
  return {
    status: "REPLACEMENT_DISKS_PRISTINE" as const,
    planSha256: plan.planSha256,
    snapshotSha256: current.sha256,
    restoreAccepted: false,
    bootAccepted: false,
  };
}
