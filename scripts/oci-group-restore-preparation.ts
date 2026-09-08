/**
 * Source-owned Pi/helper copied-volume preparation for the volume-group
 * restore cycle's pre-boot isolation gate.
 *
 * The read-only OCI proofs (isolated network and exact restored-volume
 * identities) never mask duplicate jobs on the restored copies. This module is
 * the required `GroupRestorePreBootIsolationAdapter`: it binds a complete,
 * explicitly bound private runtime configuration to the exact restored
 * boot/root targets, proves the temporary OCI helper identity and its
 * management network read-only, attaches the exact restored copies to that
 * helper, generates the guarded offline preparation command (the same
 * consistency and masking rules as the historical offline preparation
 * procedure, bound to the reviewed volume-group restore plan), executes it
 * over a pinned-host-key SSH channel, verifies the returned preparation
 * marker, and detaches the copies again. It runs strictly between the
 * isolation proofs and the first clone create, so a preparation failure or an
 * unbound configuration prevents the restored guest from ever booting.
 *
 * The helper writes only the exact attached copies: its metadata identity,
 * the exact attachment records and the unique copied filesystem identities are
 * re-proved on the helper before any copied path is mounted or changed, and
 * the boot bytes, GRUB recovery entry and Arch default are retained. No source
 * volume identity ever appears in an attachment, and no bulk payload traverses
 * Mac, Pi or the home network: the Pi only sends the guarded command over SSH
 * while the disk traffic stays between the OCI helper and its attached
 * volumes.
 */
import { shellQuote } from "./backup-guest.ts";
import {
  copiedRootIsolationFiles,
  type DrillGuestBundle,
  drillGuestFilesDigest,
} from "./drill-offline-preparation.ts";
import { controllerCidr } from "./isolated-drill.ts";
import {
  type CommandResult,
  type CommandRunner,
  dataArray,
  dataObject,
  type JsonRecord,
  redactOcid,
  stringField,
} from "./oci.ts";
import {
  BOOT_MEMBER_SIZE_GB,
  groupRestoreCliArgs,
  type GroupRestorePlan,
  groupRestorePlanDigest,
  type GroupRestoreRunner,
  ROOT_MEMBER_SIZE_GB,
  validateGroupRestorePlan,
} from "./oci-group-restore-drill.ts";
import type {
  GroupRestorePreBootIsolationAdapter,
  GroupRestorePreBootIsolationTargets,
} from "./oci-group-restore-executor.ts";

/** Exact temporary helper instance the restored copies are attached to. */
export interface GroupRestoreHelperConfig {
  instanceId: string;
  displayName: string;
  imageId: string;
}

/** Pinned non-root SSH channel from the Pi to the helper. StrictHostKeyChecking
 * stays on and the host key is pinned via `knownHostsFile`; the helper never
 * exposes the production network. */
export interface GroupRestoreHelperSshConfig {
  host: string;
  port: number;
  user: string;
  identityFile: string;
  knownHostsFile: string;
  connectTimeoutSeconds: number;
}

/** Reviewed static identities of the restored copies, bound into the private
 * runtime configuration so the guarded command refuses changed content. */
export interface GroupRestoreCopiedIdentityConfig {
  rootUuid: string;
  stagingUuid: string;
  rootPartitionStartSector: number;
  kernelSha256: string;
  initramfsSha256: string;
  grubSha256: string;
}

/** Complete private runtime configuration for the preparation adapter. Every
 * value must be explicitly bound to the reviewed helper, the reviewed SSH
 * transport and the reviewed copied-volume identities; no default exists, and
 * a missing, placeholder or mismatching value fails closed before any
 * provider call. */
export interface GroupRestorePreparationConfig {
  /** SHA-256 of the exact reviewed volume-group restore plan. This explicit
   * binding prevents a preparation configuration from being reused with a
   * different plan that happens to share filesystem bytes. */
  planSha256: string;
  helper: GroupRestoreHelperConfig;
  ssh: GroupRestoreHelperSshConfig;
  copied: GroupRestoreCopiedIdentityConfig;
  /** SHA-256 of the reviewed isolation files (`drillGuestFilesDigest` of the
   * same files and masks the guard applies); the command refuses changed
   * files. */
  offlineFilesSha256: string;
}

/** Read-only OCI evidence of the exact helper and its attachments, reconciled
 * by the adapter immediately before the guarded command is generated. */
export interface GroupRestorePreparationEvidence {
  helper: JsonRecord;
  bootAttachment: JsonRecord;
  rootAttachment: JsonRecord;
  bootVolumeId: string;
  rootVolumeId: string;
  rootUuid: string;
  stagingUuid: string;
  rootPartitionStartSector: number;
  kernelSha256: string;
  initramfsSha256: string;
  grubSha256: string;
}

export const GROUP_RESTORE_DETACH_POLL_INTERVAL_MS = 10_000;
export const GROUP_RESTORE_DETACH_POLL_BUDGET_MS = 120_000;

const UUID_PATTERN =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ROOT_DEVICE_PATTERN = /^\/dev\/oracleoci\/oraclevd[b-z]$/;

function assertBound(value: string, label: string): string {
  if (
    value === undefined || value === "" || value.includes("<") ||
    value.includes("OCID>") || value.includes("$")
  ) {
    throw new Error(`${label} is not bound`);
  }
  return value;
}

function preparationForbiddenIds(plan: GroupRestorePlan): string[] {
  return [
    plan.source.instanceId,
    plan.source.bootVolumeId,
    plan.source.rootVolumeId,
    plan.volumeGroupId,
    plan.volumeGroupBackupId,
    plan.bootMemberBackupId,
    plan.rootMemberBackupId,
    plan.productionSubnetId,
    plan.productionVcnId,
    plan.productionReservedIpId,
    plan.isolatedSubnetId,
    plan.isolatedVcnId,
  ];
}

/** The exact isolation files and masks this cycle applies to the restored
 * copies, bound to the reviewed group-restore plan and its controller CIDR. */
export async function groupRestorePreparationBundle(
  plan: GroupRestorePlan,
): Promise<DrillGuestBundle> {
  return {
    planSha256: await groupRestorePlanDigest(plan),
    ...copiedRootIsolationFiles(plan.controllerIpv4),
  };
}

/** Fail-closed check that the private runtime configuration is complete and
 * explicitly bound to the reviewed plan and its reviewed isolation files.
 * Every identity must be concrete, distinct from every protected plan
 * identity, and the copied files digest must equal the reviewed value. */
export async function validateGroupRestorePreparationConfig(
  config: GroupRestorePreparationConfig,
  plan: GroupRestorePlan,
  bundle?: DrillGuestBundle,
): Promise<void> {
  validateGroupRestorePlan(plan);
  const resolved = bundle ?? await groupRestorePreparationBundle(plan);
  if (!SHA256_PATTERN.test(config.planSha256)) {
    throw new Error("planSha256 is not 64 hex digits");
  }
  const expectedPlanSha256 = await groupRestorePlanDigest(plan);
  if (config.planSha256 !== expectedPlanSha256) {
    throw new Error(
      "Preparation configuration is not bound to the reviewed restore plan",
    );
  }
  assertBound(config.helper.instanceId, "helper.instanceId");
  assertBound(config.helper.displayName, "helper.displayName");
  assertBound(config.helper.imageId, "helper.imageId");
  if (
    config.helper.instanceId === plan.source.instanceId ||
    preparationForbiddenIds(plan).includes(config.helper.instanceId)
  ) {
    throw new Error(
      "Preparation helper cannot be the production source or a protected plan identity",
    );
  }
  assertBound(config.ssh.host, "ssh.host");
  controllerCidr(config.ssh.host);
  if (config.ssh.host === plan.controllerIpv4) {
    throw new Error("Preparation SSH host cannot be the reviewed controller");
  }
  if (
    !Number.isInteger(config.ssh.port) || config.ssh.port < 1 ||
    config.ssh.port > 65535
  ) {
    throw new Error("Preparation SSH port must be a bound TCP port");
  }
  assertBound(config.ssh.user, "ssh.user");
  if (
    config.ssh.user === "root" || /\s/.test(config.ssh.user) ||
    config.ssh.user.startsWith("-")
  ) {
    throw new Error("Preparation SSH user must be a bound non-root login user");
  }
  assertBound(config.ssh.identityFile, "ssh.identityFile");
  assertBound(config.ssh.knownHostsFile, "ssh.knownHostsFile");
  if (
    !Number.isInteger(config.ssh.connectTimeoutSeconds) ||
    config.ssh.connectTimeoutSeconds < 1 ||
    config.ssh.connectTimeoutSeconds > 60
  ) {
    throw new Error("Preparation SSH connect timeout must be 1-60 seconds");
  }
  if (!UUID_PATTERN.test(config.copied.rootUuid)) {
    throw new Error("Copied root UUID is not a UUID");
  }
  if (!UUID_PATTERN.test(config.copied.stagingUuid)) {
    throw new Error("Copied staging UUID is not a UUID");
  }
  if (
    !Number.isInteger(config.copied.rootPartitionStartSector) ||
    config.copied.rootPartitionStartSector <= 0
  ) {
    throw new Error(
      "Copied root partition start sector must be a positive integer",
    );
  }
  for (
    const [value, label] of [
      [config.copied.kernelSha256, "copied.kernelSha256"],
      [config.copied.initramfsSha256, "copied.initramfsSha256"],
      [config.copied.grubSha256, "copied.grubSha256"],
    ] as const
  ) {
    if (!SHA256_PATTERN.test(value)) {
      throw new Error(`${label} is not 64 hex digits`);
    }
  }
  if (!SHA256_PATTERN.test(config.offlineFilesSha256)) {
    throw new Error("offlineFilesSha256 is not 64 hex digits");
  }
  const digest = await drillGuestFilesDigest(resolved);
  if (digest !== config.offlineFilesSha256) {
    throw new Error(
      "Preparation isolation files differ from the reviewed private configuration",
    );
  }
}

/** The exact restored copies the gate receives: two distinct volumes, never a
 * protected source, group, backup, production or isolated-plan identity. */
export function validateGroupRestorePreparationTargets(
  plan: GroupRestorePlan,
  targets: GroupRestorePreBootIsolationTargets,
): void {
  validateGroupRestorePlan(plan);
  if (
    !targets.bootVolumeId || !targets.rootVolumeId ||
    targets.bootVolumeId === targets.rootVolumeId
  ) {
    throw new Error(
      "Preparation targets are not two distinct restored volumes",
    );
  }
  if (
    preparationForbiddenIds(plan).some((id) =>
      id === targets.bootVolumeId || id === targets.rootVolumeId
    )
  ) {
    throw new Error("Preparation targets reference a protected identity");
  }
}

/** Read-only proof that the live helper is exactly the reviewed temporary
 * instance: running, in the reviewed compartment and availability domain, with
 * the reviewed display name and image, and never the production source. */
export function validateGroupRestoreHelperIdentity(
  config: GroupRestorePreparationConfig,
  plan: GroupRestorePlan,
  helper: JsonRecord,
): void {
  if (
    helper.id !== config.helper.instanceId ||
    helper["lifecycle-state"] !== "RUNNING" ||
    helper["compartment-id"] !== plan.source.compartmentId ||
    helper["availability-domain"] !== plan.availabilityDomain ||
    helper["display-name"] !== config.helper.displayName ||
    helper["image-id"] !== config.helper.imageId ||
    helper.id === plan.source.instanceId
  ) {
    throw new Error(
      "Preparation helper identity differs from the reviewed configuration",
    );
  }
}

/** Read-only proof that the SSH host is the helper's exact one public IP, on a
 * management subnet whose VCN is resolved from the subnet resource (OCI VNIC
 * responses expose `subnet-id`, not a reliable `vcn-id`) and is neither the
 * production network nor the isolated drill network. */
export function validateGroupRestoreHelperNetwork(
  config: GroupRestorePreparationConfig,
  plan: GroupRestorePlan,
  vnic: JsonRecord,
  subnet: JsonRecord,
  expectedVnicId?: string,
): void {
  const subnetId = stringField(vnic, "subnet-id");
  const subnetVcnId = stringField(subnet, "vcn-id");
  const vnicVcnId = vnic["vcn-id"];
  if (expectedVnicId !== undefined && vnic.id !== expectedVnicId) {
    throw new Error(
      "Preparation helper VNIC identity differs from its attachment",
    );
  }
  if (
    vnic["lifecycle-state"] !== "AVAILABLE" ||
    vnic["compartment-id"] !== plan.source.compartmentId ||
    vnic["availability-domain"] !== plan.availabilityDomain ||
    vnic["public-ip"] !== config.ssh.host ||
    subnet.id !== subnetId ||
    subnet["lifecycle-state"] !== "AVAILABLE" ||
    subnet["compartment-id"] !== plan.source.compartmentId ||
    subnetId === plan.productionSubnetId ||
    subnetVcnId === plan.productionVcnId ||
    subnetId === plan.isolatedSubnetId ||
    subnetVcnId === plan.isolatedVcnId ||
    (vnicVcnId !== undefined && vnicVcnId !== subnetVcnId)
  ) {
    throw new Error(
      "Preparation SSH host is not bound to the reviewed helper management network",
    );
  }
}

/** Exact attachment proof: both restored volumes are attached to the reviewed
 * helper as paravirtualized data disks through the data-volume attachment API
 * with the OCI device identity rules for copied whole disks, and their
 * identity fields match the reviewed copied-volume configuration. */
export function validateGroupRestorePreparationEvidence(
  config: GroupRestorePreparationConfig,
  plan: GroupRestorePlan,
  evidence: GroupRestorePreparationEvidence,
): void {
  if (
    stringField(evidence.helper, "id") !== config.helper.instanceId ||
    evidence.bootVolumeId === evidence.rootVolumeId
  ) {
    throw new Error("Preparation evidence is not bound to the helper");
  }
  const bootAttachment = evidence.bootAttachment;
  const rootAttachment = evidence.rootAttachment;
  if (
    bootAttachment["instance-id"] !== config.helper.instanceId ||
    bootAttachment["volume-id"] !== evidence.bootVolumeId ||
    bootAttachment["lifecycle-state"] !== "ATTACHED" ||
    bootAttachment["attachment-type"] !== "paravirtualized" ||
    rootAttachment["instance-id"] !== config.helper.instanceId ||
    rootAttachment["volume-id"] !== evidence.rootVolumeId ||
    rootAttachment["lifecycle-state"] !== "ATTACHED" ||
    rootAttachment["attachment-type"] !== "paravirtualized"
  ) {
    throw new Error(
      "Restored copy is not attached to the reviewed helper as one paravirtualized data volume",
    );
  }
  const bootDevice = evidence.bootAttachment.device;
  const rootDevice = evidence.rootAttachment.device;
  if (
    typeof bootDevice !== "string" || !ROOT_DEVICE_PATTERN.test(bootDevice) ||
    typeof rootDevice !== "string" || !ROOT_DEVICE_PATTERN.test(rootDevice) ||
    bootDevice === rootDevice
  ) {
    throw new Error(
      "Restored copy device identities are not the reviewed OCI whole-disk paths",
    );
  }
  if (
    evidence.rootUuid !== config.copied.rootUuid ||
    evidence.stagingUuid !== config.copied.stagingUuid ||
    evidence.rootPartitionStartSector !==
      config.copied.rootPartitionStartSector ||
    evidence.kernelSha256 !== config.copied.kernelSha256 ||
    evidence.initramfsSha256 !== config.copied.initramfsSha256 ||
    evidence.grubSha256 !== config.copied.grubSha256 ||
    preparationForbiddenIds(plan).some((id) =>
      id === evidence.bootVolumeId || id === evidence.rootVolumeId
    )
  ) {
    throw new Error(
      "Preparation copied-volume identities differ from the reviewed configuration",
    );
  }
}

/** Generated guarded offline preparation command for the exact restored
 * copies. The helper re-proves its own metadata identity, the whole-disk
 * attachment paths, filesystem identities, the reviewed root partition start
 * sector and the reviewed boot bytes before writing only the copies, then
 * masks duplicate jobs/timers, installs the isolation files and the drill
 * default target, and prints the typed preparation marker. No source volume is
 * reachable: the helper can only see its own attachments. */
export async function groupRestorePreparationCommand(
  plan: GroupRestorePlan,
  config: GroupRestorePreparationConfig,
  evidence: GroupRestorePreparationEvidence,
  bundle: DrillGuestBundle,
): Promise<string> {
  await validateGroupRestorePreparationConfig(config, plan, bundle);
  validateGroupRestorePreparationEvidence(config, plan, evidence);
  const payload = btoa(
    Array.from(
      new TextEncoder().encode(
        JSON.stringify({
          plan,
          evidence,
          bundle,
          preparationPlanSha256: config.planSha256,
        }),
      ),
      (byte) => String.fromCharCode(byte),
    ).join(""),
  );
  const script =
    `import base64,hashlib,json,os,pathlib,re,stat,subprocess,urllib.request
p=json.loads(base64.b64decode('${payload}'))
e=p['evidence']; b=p['bundle']
assert p['preparationPlanSha256']==b['planSha256'], 'Preparation plan binding changed'
request=urllib.request.Request('http://169.254.169.254/opc/v2/instance/',headers={'Authorization':'Bearer Oracle'})
with urllib.request.urlopen(request,timeout=10) as response: identity=json.load(response)
assert identity['id']==e['helper']['id'] and identity['id']!=p['plan']['source']['instanceId'], 'Wrong helper instance'
def run(*args): return subprocess.check_output(args,text=True).strip()
def disk(attachment,uuid,fstype,size):
 args=['lsblk','--json','--tree','--paths','--bytes','--output','PATH,TYPE,UUID,FSTYPE,SIZE,MOUNTPOINTS']
 assert isinstance(attachment.get('device'),str) and re.fullmatch(r'/dev/oracleoci/oraclevd[b-z]',attachment['device']), 'Copied attachment device is not an OCI data-volume path'
 args.append(os.path.realpath(attachment['device']))
 tree=json.loads(run(*args))['blockdevices']
 def has_mounts(item):
  return any(item.get('mountpoints') or []) or any(has_mounts(child) for child in item.get('children',[]))
 assert len(tree)==1 and tree[0]['type']=='disk' and int(tree[0]['size'])==size, 'Unexpected disk size or type'
 assert stat.S_ISBLK(os.stat(tree[0]['path']).st_mode), 'Attachment is not a block device'
 def unmounted(item):
  assert not any(item.get('mountpoints') or []), 'A copied device is already mounted'
  for child in item.get('children',[]): unmounted(child)
 unmounted(tree[0])
 children=tree[0].get('children',[])
 candidates=[child for child in children if child.get('uuid')==uuid and child.get('fstype')==fstype]
 assert len(candidates)==1, 'Copied partition identity is not unique'
 candidates[0]['diskPath']=tree[0]['path']
 return candidates[0]
root=disk(e['rootAttachment'],e['rootUuid'],'ext4',${ROOT_MEMBER_SIZE_GB}*1024**3)
stage=disk(e['bootAttachment'],e['stagingUuid'],'xfs',${BOOT_MEMBER_SIZE_GB}*1024**3)
assert int((pathlib.Path('/sys/class/block')/pathlib.Path(root['path']).name/'start').read_text())==e['rootPartitionStartSector'], 'Root partition start changed'
base=pathlib.Path('/mnt/arch-drill')
base.mkdir(mode=0o700,exist_ok=True)
assert not base.is_symlink() and not any(base.iterdir()), 'Preparation mount directory is not empty'
r=base/'root';s=base/'stage';r.mkdir();s.mkdir()
mounted=[]
try:
 subprocess.run(['mount','-o','ro,noload',root['path'],str(r)],check=True);mounted.append(r)
 subprocess.run(['mount','-o','ro,norecovery,nouuid',stage['path'],str(s)],check=True);mounted.append(s)
 def digest(path):
  h=hashlib.sha256()
  with path.open('rb') as stream:
   for chunk in iter(lambda:stream.read(1048576),b''): h.update(chunk)
  return h.hexdigest()
 for first,second,expected in [('boot/Image','arch-vmlinuz',e['kernelSha256']),('boot/initramfs-linux.img','arch-initrd.img',e['initramfsSha256'])]:
  assert digest(r/first)==digest(s/second)==expected, 'Backup boot bytes differ from reviewed source'
 assert digest(s/'grub2/grub.cfg')==e['grubSha256'], 'GRUB differs from the reviewed boot configuration'
 grub=(s/'grub2/grub.cfg').read_text()
 assert grub.splitlines()[0]=='set default=0', 'Arch is not the default boot entry'
 assert [line for line in grub.splitlines() if line.startswith('menuentry ')][0]=='menuentry "Arch Linux ARM" {', 'First boot entry is not Arch'
 assert 'set fallback' not in grub, 'Automatic recovery boot is not isolated'
 assert 'root=UUID='+e['rootUuid'] in grub and 'Oracle Linux (fallback)' in grub, 'Boot contract missing'
 assert 'ID=arch' in (r/'etc/os-release').read_text(), 'Copied root is not Arch'
 assert (r/'usr/bin/nft').is_file(), 'Copied nftables executable missing'
 subprocess.run(['mount','-o','remount,rw',str(r)],check=True)
 def target(name):
  path=r/name
  assert not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts
  assert path.parent.resolve().is_relative_to(r.resolve()), 'Copied path escapes root'
  path.parent.mkdir(parents=True,exist_ok=True)
  return path
 # Basic target can activate timers. Mask every copied timer before first boot.
 masks=set(b['masks'])
 for directory,prefix in [('usr/lib/systemd/system','etc/systemd/system'),('etc/systemd/system','etc/systemd/system'),('usr/lib/systemd/user','etc/systemd/user'),('etc/systemd/user','etc/systemd/user'),('home/codex/.config/systemd/user','home/codex/.config/systemd/user')]:
  for timer in (r/directory).glob('*.timer'): masks.add(prefix+'/'+timer.name)
 for name,content in b['files'].items():
  path=target(name)
  assert not path.is_symlink(), 'Unexpected symlink for managed file'
  temporary=path.with_name(path.name+'.arch-drill-new')
  with temporary.open('x') as output: output.write(content);output.flush();os.fsync(output.fileno())
  os.chmod(temporary,0o644);os.replace(temporary,path)
 for name in sorted(masks):
  path=target(name)
  if path.is_symlink() or path.exists(): path.unlink()
  path.symlink_to('/dev/null')
 default=target('etc/systemd/system/default.target')
 if default.is_symlink() or default.exists(): default.unlink()
 default.symlink_to('/etc/systemd/system/arch-drill.target')
 # Match existing user ownership for the restored desktop drop-ins.
 owner=os.stat(r/'home/codex')
 for directory in [r/'home/codex/.config/systemd/user/vncserver.service.d',r/'home/codex/.config/systemd/user/codex-remote-daemon.service.d']:
  os.chown(directory,owner.st_uid,owner.st_gid)
  os.chown(directory/'backup-recovery.conf',owner.st_uid,owner.st_gid)
 for name,content in b['files'].items(): assert target(name).read_text()==content
 for name in masks: assert os.readlink(target(name))=='/dev/null'
 marker=target('etc/arch-drill-prepared.json')
 marker.write_text(json.dumps({'planSha256':b['planSha256'],'bootVolumeId':e['bootVolumeId'],'rootVolumeId':e['rootVolumeId'],'masks':sorted(masks)}))
 os.chmod(marker,0o600)
 os.sync()
 subprocess.run(['mount','-o','remount,ro',str(r)],check=True)
 print(json.dumps({'status':'OFFLINE_FILES_PREPARED','planSha256':b['planSha256'],'bootVolumeId':e['bootVolumeId'],'rootVolumeId':e['rootVolumeId'],'helperInstanceId':e['helper']['id'],'firstBootProved':False,'bootDevicePath':stage['diskPath'],'rootDevicePath':root['diskPath']}))
finally:
 for path in reversed(mounted): subprocess.run(['umount',str(path)],check=True)
 for path in [s,r]: path.rmdir()
 base.rmdir()
`;
  return "sudo -n python3 -c " + shellQuote(script);
}

/** Parse the guarded command's typed marker line. Only an exact marker with
 * the reviewed plan, helper and both restored volume identities admits the
 * launch; anything else fails closed. */
export function groupRestorePreparationMarker(
  stdout: string,
  bundle: DrillGuestBundle,
  targets: GroupRestorePreBootIsolationTargets,
  helperInstanceId: string,
): JsonRecord {
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let marker: JsonRecord;
    try {
      marker = JSON.parse(trimmed) as JsonRecord;
    } catch {
      continue;
    }
    if (
      marker.status === "OFFLINE_FILES_PREPARED" &&
      marker.planSha256 === bundle.planSha256 &&
      marker.bootVolumeId === targets.bootVolumeId &&
      marker.rootVolumeId === targets.rootVolumeId &&
      marker.helperInstanceId === helperInstanceId &&
      marker.firstBootProved === false
    ) {
      return marker;
    }
  }
  throw new Error(
    "Copied-volume preparation marker is missing, malformed or unbound",
  );
}

export interface GroupRestorePreparationAdapterOptions {
  /** SSH execution surface; the Pi orchestrator supplies the pinned non-root
   * channel, tests inject a capturing runner. */
  ssh: CommandRunner;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

/** Injectable real Pi/helper adapter: read-only helper and management-network
 * proof, exact restore attachment, the guarded copied-volume preparation over
 * pinned SSH, marker verification and clean detach, all before the first clone
 * create. Any ambiguity, mismatch or preparation failure throws, so the
 * restored guest can never boot unprepared or beside production. */
export function groupRestorePreparationAdapter(
  config: GroupRestorePreparationConfig,
  plan: GroupRestorePlan,
  runner: GroupRestoreRunner,
  options: GroupRestorePreparationAdapterOptions,
): GroupRestorePreBootIsolationAdapter {
  const now = options.now ?? Date.now;
  const sleep = options.sleep ??
    ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const call = async (argv: string[]): Promise<JsonRecord> => {
    const result = await runner.run(
      runner.ociCliPath,
      [...groupRestoreCliArgs(runner, argv), "--output", "json"],
    );
    if (result.code !== 0) {
      throw new Error(
        `OCI preparation request failed (${result.code}): ${
          redactOcid(result.stderr)
        }`,
      );
    }
    try {
      return result.stdout.trim() ? JSON.parse(result.stdout) as JsonRecord : {
        data: [],
      };
    } catch {
      throw new Error("OCI preparation response was not JSON");
    }
  };

  const isTerminalAttachment = (row: JsonRecord): boolean =>
    row["lifecycle-state"] === "DETACHED" ||
    row["lifecycle-state"] === "TERMINATED";

  const listAttachments = async (
    _kind: "boot" | "root",
  ): Promise<JsonRecord[]> =>
    dataArray(
      await call(
        [
          "compute",
          "volume-attachment",
          "list",
          "--compartment-id",
          plan.source.compartmentId,
          "--instance-id",
          config.helper.instanceId,
          "--all",
        ],
      ),
    );

  const attachmentVolumeId = (row: JsonRecord): string =>
    stringField(row, "volume-id");

  const ensureAttached = async (
    kind: "boot" | "root",
    volumeId: string,
    onAttachAttempt: () => void,
  ): Promise<string> => {
    const rows = (await listAttachments(kind)).filter((row) =>
      !isTerminalAttachment(row)
    );
    // The helper must never hold a production source volume attachment: the
    // guarded command and the device resolution may only ever see the exact
    // restored copies.
    if (
      rows.some((row) =>
        [plan.source.bootVolumeId, plan.source.rootVolumeId].includes(
          attachmentVolumeId(row),
        )
      )
    ) {
      throw new Error(
        "Preparation helper holds a production source volume attachment",
      );
    }
    const matching = rows.filter((row) => attachmentVolumeId(row) === volumeId);
    // A target attachment that predates this invocation is not adapter-owned.
    // Never adopt or detach it: an operator must reconcile that state first.
    if (matching.length !== 0) {
      throw new Error(
        "Copied-volume target is already attached; refusing to adopt it",
      );
    }
    // Persist ownership in the caller before the provider request. If the
    // response is lost after OCI accepts it, cleanup can reconcile the exact
    // target and detach it; a pre-existing target was rejected above.
    onAttachAttempt();
    await call(
      kind === "boot"
        ? [
          "compute",
          "volume-attachment",
          "attach",
          "--instance-id",
          config.helper.instanceId,
          "--volume-id",
          volumeId,
          "--type",
          "paravirtualized",
        ]
        : [
          "compute",
          "volume-attachment",
          "attach",
          "--instance-id",
          config.helper.instanceId,
          "--volume-id",
          volumeId,
          "--type",
          "paravirtualized",
        ],
    );
    const started = now();
    while (now() - started < GROUP_RESTORE_DETACH_POLL_BUDGET_MS) {
      const current = (await listAttachments(kind)).filter((row) =>
        attachmentVolumeId(row) === volumeId && !isTerminalAttachment(row)
      );
      if (
        current.length === 1 && current[0]!["lifecycle-state"] === "ATTACHED"
      ) {
        return stringField(current[0], "id");
      }
      if (
        current.length === 1 && current[0]!["lifecycle-state"] === "ATTACHING"
      ) {
        await sleep(GROUP_RESTORE_DETACH_POLL_INTERVAL_MS);
        continue;
      }
      if (current.length !== 0) {
        throw new Error(
          "Copied-volume attachment entered an unexpected state",
        );
      }
      await sleep(GROUP_RESTORE_DETACH_POLL_INTERVAL_MS);
    }
    throw new Error(
      `Copied ${kind} volume did not reach ATTACHED within the bounded budget`,
    );
  };

  const detachBy = async (
    kind: "boot" | "root",
    attachmentId: string,
  ): Promise<void> => {
    await call(
      [
        "compute",
        "volume-attachment",
        "detach",
        "--volume-attachment-id",
        attachmentId,
        "--force",
      ],
    );
    const started = now();
    while (now() - started < GROUP_RESTORE_DETACH_POLL_BUDGET_MS) {
      const live = (await listAttachments(kind)).filter((row) =>
        String(row.id) === attachmentId &&
        !isTerminalAttachment(row)
      );
      if (live.length === 0) return;
      await sleep(GROUP_RESTORE_DETACH_POLL_INTERVAL_MS);
    }
    throw new Error(
      "Copied-volume attachment did not detach within the bounded budget",
    );
  };

  const detachByVolume = async (
    kind: "boot" | "root",
    volumeId: string,
  ): Promise<void> => {
    const matching = (await listAttachments(kind)).filter((row) =>
      attachmentVolumeId(row) === volumeId && !isTerminalAttachment(row)
    );
    if (matching.length === 0) return;
    if (matching.length !== 1) {
      throw new Error(
        "Copied-volume attachment state is ambiguous before detach",
      );
    }
    await detachBy(kind, stringField(matching[0], "id"));
  };

  return {
    prepareCopiedVolumes: async (targets) => {
      const bundle = await groupRestorePreparationBundle(plan);
      await validateGroupRestorePreparationConfig(config, plan, bundle);
      validateGroupRestorePreparationTargets(plan, targets);
      const helper = dataObject(
        await call([
          "compute",
          "instance",
          "get",
          "--instance-id",
          config.helper.instanceId,
        ]),
      );
      validateGroupRestoreHelperIdentity(config, plan, helper);
      const vnicAttachments = dataArray(
        await call([
          "compute",
          "vnic-attachment",
          "list",
          "--compartment-id",
          plan.source.compartmentId,
          "--instance-id",
          config.helper.instanceId,
          "--all",
        ]),
      ).filter((row) => row["lifecycle-state"] === "ATTACHED");
      if (vnicAttachments.length !== 1) {
        throw new Error(
          "Preparation helper must hold exactly one attached management VNIC",
        );
      }
      if (vnicAttachments[0]!["instance-id"] !== config.helper.instanceId) {
        throw new Error(
          "Preparation helper VNIC attachment is bound to another instance",
        );
      }
      const helperVnicId = stringField(vnicAttachments[0], "vnic-id");
      const vnic = dataObject(
        await call([
          "network",
          "vnic",
          "get",
          "--vnic-id",
          helperVnicId,
        ]),
      );
      const helperSubnet = dataObject(
        await call([
          "network",
          "subnet",
          "get",
          "--subnet-id",
          stringField(vnic, "subnet-id"),
        ]),
      );
      validateGroupRestoreHelperNetwork(
        config,
        plan,
        vnic,
        helperSubnet,
        helperVnicId,
      );
      let bootAttachmentId: string | undefined;
      let rootAttachmentId: string | undefined;
      let bootAttachAttempted = false;
      let rootAttachAttempted = false;
      let operationFailed = false;
      let operationError: unknown;
      try {
        bootAttachmentId = await ensureAttached(
          "boot",
          targets.bootVolumeId,
          () => {
            bootAttachAttempted = true;
          },
        );
        rootAttachmentId = await ensureAttached(
          "root",
          targets.rootVolumeId,
          () => {
            rootAttachAttempted = true;
          },
        );
        const bootAttachment = dataObject(
          await call([
            "compute",
            "volume-attachment",
            "get",
            "--volume-attachment-id",
            bootAttachmentId,
          ]),
        );
        const rootAttachment = dataObject(
          await call([
            "compute",
            "volume-attachment",
            "get",
            "--volume-attachment-id",
            rootAttachmentId,
          ]),
        );
        const evidence: GroupRestorePreparationEvidence = {
          helper,
          bootAttachment,
          rootAttachment,
          bootVolumeId: targets.bootVolumeId,
          rootVolumeId: targets.rootVolumeId,
          rootUuid: config.copied.rootUuid,
          stagingUuid: config.copied.stagingUuid,
          rootPartitionStartSector: config.copied.rootPartitionStartSector,
          kernelSha256: config.copied.kernelSha256,
          initramfsSha256: config.copied.initramfsSha256,
          grubSha256: config.copied.grubSha256,
        };
        validateGroupRestorePreparationEvidence(config, plan, evidence);
        const command = await groupRestorePreparationCommand(
          plan,
          config,
          evidence,
          bundle,
        );
        const connection = config.ssh.user + "@" + config.ssh.host;
        const sshResult: CommandResult = await options.ssh("ssh", [
          "-o",
          "BatchMode=yes",
          "-o",
          "StrictHostKeyChecking=yes",
          "-o",
          "IdentitiesOnly=yes",
          "-o",
          `UserKnownHostsFile=${config.ssh.knownHostsFile}`,
          "-o",
          `ConnectTimeout=${config.ssh.connectTimeoutSeconds}`,
          "-p",
          String(config.ssh.port),
          "-i",
          config.ssh.identityFile,
          connection,
          command,
        ]);
        if (sshResult.code !== 0) {
          throw new Error(
            `Copied-volume preparation failed on the helper (${sshResult.code}): ${
              redactOcid(sshResult.stderr || sshResult.stdout)
            }`,
          );
        }
        groupRestorePreparationMarker(
          sshResult.stdout,
          bundle,
          targets,
          config.helper.instanceId,
        );
      } catch (error) {
        operationFailed = true;
        operationError = error;
      }
      // The copies must never stay attached after preparation (success or
      // failure). Attempt both detaches independently so a root detach error
      // cannot strand the boot copy. A detach failure always fails closed.
      const detachErrors: unknown[] = [];
      const attemptDetach = async (
        kind: "boot" | "root",
        attempted: boolean,
        attachmentId: string | undefined,
        volumeId: string,
      ): Promise<void> => {
        if (!attempted) return;
        try {
          if (attachmentId !== undefined) {
            await detachBy(kind, attachmentId);
          } else {
            await detachByVolume(kind, volumeId);
          }
        } catch (error) {
          detachErrors.push(error);
        }
      };
      await attemptDetach(
        "root",
        rootAttachAttempted,
        rootAttachmentId,
        targets.rootVolumeId,
      );
      await attemptDetach(
        "boot",
        bootAttachAttempted,
        bootAttachmentId,
        targets.bootVolumeId,
      );
      if (detachErrors.length !== 0) {
        const errors = operationFailed && operationError !== undefined
          ? [operationError, ...detachErrors]
          : detachErrors;
        throw new AggregateError(
          errors,
          "Copied-volume preparation cleanup failed; launch is refused",
        );
      }
      if (operationFailed) {
        throw operationError;
      }
    },
  };
}
