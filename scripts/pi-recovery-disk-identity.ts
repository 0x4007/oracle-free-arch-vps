/** Provider-to-loader disk binding before kexec. Oracle's consistent paths
 * exist on the platform image; the RAM rescue uses retained SCSI serials.
 * The Pi owns authenticated OCI reads and a host-key-verified SSH runner.
 */
import { createHash } from "node:crypto";
import type { CommandRunner, JsonRecord } from "./oci.ts";
import type {
  DiskPreparationBinding,
  PreparationDisk,
} from "./pi-recovery-disk-preparation.ts";

export interface LoaderIdentityRequest {
  requestId: string;
  instanceId: string;
  bootVolumeId: string;
  rootVolumeId: string;
  sourceInstanceId: string;
  sourceBootVolumeId: string;
  sourceRootVolumeId: string;
}
export interface LoaderProviderEvidence {
  instance: JsonRecord;
  bootVolume: JsonRecord;
  rootVolume: JsonRecord;
  bootAttachments: JsonRecord[];
  rootAttachments: JsonRecord[];
}
export interface LoaderDiskIdentity {
  request: LoaderIdentityRequest;
  loaderBootId: string;
  bootAttachmentId: string;
  rootAttachmentId: string;
  boot: PreparationDisk;
  root: PreparationDisk;
  observedAtUtc: string;
  identitySha256: string;
}
const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
function providerBinding(
  request: LoaderIdentityRequest,
  evidence: LoaderProviderEvidence,
) {
  const instance = evidence.instance;
  const boot = evidence.bootAttachments.filter((a) =>
    a["lifecycle-state"] !== "DETACHED"
  );
  const root = evidence.rootAttachments.filter((a) =>
    a["lifecycle-state"] !== "DETACHED"
  );
  if (
    !/^recovery-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(
      request.requestId,
    ) ||
    !/^ocid1\.instance\.[a-zA-Z0-9.]+$/.test(request.instanceId) ||
    request.instanceId === request.sourceInstanceId ||
    request.bootVolumeId === request.sourceBootVolumeId ||
    request.rootVolumeId === request.sourceRootVolumeId ||
    instance.id !== request.instanceId ||
    instance["lifecycle-state"] !== "RUNNING" ||
    (instance["freeform-tags"] as JsonRecord | undefined)
        ?.uosRecoveryRequest !== request.requestId ||
    (instance["launch-options"] as JsonRecord | undefined)
        ?.["is-consistent-volume-naming-enabled"] !== true ||
    boot.length !== 1 || root.length !== 1 ||
    [boot[0], root[0]].some((a) =>
      a["lifecycle-state"] !== "ATTACHED" ||
      a["instance-id"] !== request.instanceId || typeof a.id !== "string"
    ) ||
    boot[0]["boot-volume-id"] !== request.bootVolumeId ||
    root[0]["volume-id"] !== request.rootVolumeId ||
    root[0]["attachment-type"] !== "paravirtualized" ||
    root[0].device !== "/dev/oracleoci/oraclevdb" ||
    root[0]["is-read-only"] !== false ||
    evidence.bootVolume.id !== request.bootVolumeId ||
    evidence.rootVolume.id !== request.rootVolumeId ||
    evidence.bootVolume["size-in-gbs"] !== 50 ||
    evidence.rootVolume["size-in-gbs"] !== 150 ||
    [evidence.bootVolume, evidence.rootVolume].some((v) =>
      v["lifecycle-state"] !== "AVAILABLE" ||
      v["compartment-id"] !== instance["compartment-id"] ||
      v["availability-domain"] !== instance["availability-domain"]
    )
  ) {
    throw Error(
      "Loader disks do not match the replacement's Oracle attachments",
    );
  }
  return {
    bootAttachmentId: boot[0].id as string,
    rootAttachmentId: root[0].id as string,
  };
}
async function read(runner: CommandRunner, command: string, args: string[]) {
  const result = await runner(command, args);
  if (result.code !== 0 || result.stdout.length > 1024 * 1024) {
    throw Error("Loader identity evidence is unavailable");
  }
  return result.stdout.trim();
}

/** Revalidate retained attachment identities after the loader has left. Guest
 * serial/RAM checks remain separate and use the same immutable receipt. */
export function assertRetainedProviderBinding(
  receipt: LoaderDiskIdentity,
  evidence: LoaderProviderEvidence,
): void {
  const { identitySha256, ...body } = receipt;
  if (hash(body) !== identitySha256) {
    throw Error("Loader identity receipt changed");
  }
  const attached = providerBinding(receipt.request, evidence);
  if (
    attached.bootAttachmentId !== receipt.bootAttachmentId ||
    attached.rootAttachmentId !== receipt.rootAttachmentId
  ) throw Error("Replacement attachments changed after loader acceptance");
}
interface Node {
  path: string;
  type: string;
  size: number;
  "maj:min": string;
  mountpoints?: (string | null)[];
  children?: Node[];
}
function flat(nodes: Node[]): Node[] {
  const result: Node[] = [];
  const visit = (node: Node) => {
    if (result.length >= 64) throw Error("Unexpected loader block tree");
    result.push(node);
    for (const child of node.children ?? []) visit(child);
  };
  for (const node of nodes) visit(node);
  return result;
}

/** No mutations. The provider is reread after SSH collection, refusing an
 * attachment replacement even when the new volume has the same capacity.
 */
export async function captureLoaderDiskIdentity(
  request: LoaderIdentityRequest,
  readProvider: () => Promise<LoaderProviderEvidence>,
  runner: CommandRunner,
): Promise<LoaderDiskIdentity> {
  const original = providerBinding(request, await readProvider());
  if (
    await read(runner, "uname", ["-m"]) !== "aarch64" ||
    await read(runner, "bash", [
        "-ec",
        '. /etc/os-release; printf "%s:%s" "$ID" "$VERSION_ID"',
      ]) !== "ubuntu:24.04"
  ) throw Error("Disk identity requires the approved Ubuntu AArch64 loader");
  const identity = JSON.parse(
    await read(runner, "curl", [
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
    identity.id !== request.instanceId ||
    identity.freeformTags?.uosRecoveryRequest !== request.requestId
  ) throw Error("Loader instance identity differs");
  const loaderBootId = await read(runner, "cat", [
    "/proc/sys/kernel/random/boot_id",
  ]);
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(loaderBootId)) {
    throw Error("Loader boot identity is malformed");
  }
  const tree = JSON.parse(
    await read(runner, "lsblk", [
      "--json",
      "--tree",
      "--bytes",
      "--output",
      "PATH,TYPE,SIZE,MAJ:MIN,MOUNTPOINTS",
    ]),
  );
  if (!Array.isArray(tree.blockdevices)) {
    throw Error("Loader block evidence is absent");
  }
  if (
    tree.blockdevices.some((node: Node) =>
      !["disk", "loop"].includes(node.type)
    )
  ) {
    throw Error("Loader inventory lacks partition trees");
  }
  const disks = flat(tree.blockdevices).filter((node) => node.type === "disk");
  if (disks.length !== 2) {
    throw Error("Loader must expose exactly the replacement pair");
  }
  const mount = JSON.parse(
    await read(runner, "findmnt", [
      "--json",
      "--output",
      "MAJ:MIN",
      "--target",
      "/",
    ]),
  );
  if (
    !Array.isArray(mount.filesystems) || mount.filesystems.length !== 1 ||
    typeof mount.filesystems[0]["maj:min"] !== "string"
  ) throw Error("Loader root mount is unavailable");
  const captured: PreparationDisk[] = [];
  for (
    const [index, device, volumeId, bytes] of [
      [0, "/dev/oracleoci/oraclevda", request.bootVolumeId, 50 * 1024 ** 3],
      [1, "/dev/oracleoci/oraclevdb", request.rootVolumeId, 150 * 1024 ** 3],
    ] as const
  ) {
    const resolved = await read(runner, "readlink", ["-f", device]);
    const matches = disks.filter((node) =>
      node.path === resolved && node.size === bytes
    );
    if (matches.length !== 1 || !/^\/dev\/sd[a-z]+$/.test(resolved)) {
      throw Error(
        "Oracle consistent device path does not match the expected SCSI disk",
      );
    }
    const nodes = flat(matches);
    if (
      index === 0 &&
      !nodes.some((node) => node["maj:min"] === mount.filesystems[0]["maj:min"])
    ) {
      throw Error(
        "Platform root filesystem is not on the provider boot volume",
      );
    }
    if (
      index === 1 &&
      nodes.some((node) => (node.mountpoints ?? []).some(Boolean))
    ) throw Error("Replacement root volume is already mounted");
    const properties = (await read(runner, "udevadm", [
      "info",
      "--query=property",
      "--name=" + resolved,
    ])).split("\n");
    const serials = properties.filter((line) =>
      line.startsWith("ID_SCSI_SERIAL=")
    );
    const links = properties.filter((line) => line.startsWith("DEVLINKS="));
    if (serials.length !== 1 || links.length !== 1) {
      throw Error("Loader SCSI identity or aliases are unavailable");
    }
    const serial = serials[0].slice("ID_SCSI_SERIAL=".length);
    const path =
      links[0].slice("DEVLINKS=".length).split(/\s+/).filter((value) =>
        /^\/dev\/disk\/by-id\/scsi-[A-Za-z0-9_.+:-]+$/.test(value)
      ).sort()[0];
    if (
      !/^[A-Za-z0-9_.+:-]+$/.test(serial) || !path ||
      await read(runner, "readlink", ["-f", path]) !== resolved
    ) throw Error("Loader stable disk alias is not bound to its full serial");
    captured.push({ volumeId, path, serial, bytes });
  }
  if (
    captured[0].serial === captured[1].serial ||
    captured[0].path === captured[1].path
  ) throw Error("Loader disk identities collide");
  if (
    await read(runner, "cat", ["/proc/sys/kernel/random/boot_id"]) !==
      loaderBootId ||
    hash(providerBinding(request, await readProvider())) !== hash(original)
  ) throw Error("Loader boot or Oracle attachment changed during observation");
  const body = {
    request: structuredClone(request),
    loaderBootId,
    ...original,
    boot: captured[0],
    root: captured[1],
    observedAtUtc: new Date().toISOString(),
  };
  return { ...body, identitySha256: hash(body) };
}

/** The caller must separately establish console/SSH trust and RAM acceptance.
 * Reusing the loader boot ID is never evidence of a completed kexec handoff.
 */
export function preparationBindingFromLoader(
  receipt: LoaderDiskIdentity,
  ramBootId: string,
  rescueManifestSha256: string,
): DiskPreparationBinding {
  const { identitySha256, ...body } = receipt;
  if (
    hash(body) !== identitySha256 || ramBootId === receipt.loaderBootId ||
    !/^[0-9a-f]{64}$/.test(rescueManifestSha256) ||
    !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(ramBootId)
  ) throw Error("Loader receipt changed or RAM boot is not new");
  const { bootVolumeId: _boot, rootVolumeId: _root, ...request } =
    receipt.request;
  return {
    ...request,
    bootId: ramBootId,
    loaderBootId: receipt.loaderBootId,
    rescueManifestSha256,
    boot: structuredClone(receipt.boot),
    root: structuredClone(receipt.root),
  };
}
