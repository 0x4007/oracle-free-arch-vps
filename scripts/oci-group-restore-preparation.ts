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
  type GroupRestoreLifetime,
  type GroupRestorePlan,
  groupRestorePlanDigest,
  type GroupRestoreRunner,
  ROOT_MEMBER_SIZE_GB,
  validateGroupRestorePlan,
} from "./oci-group-restore-drill.ts";
import {
  groupRestoreDeletePollBudgetMs,
  type GroupRestorePreBootIsolationAdapter,
  type GroupRestorePreBootIsolationTargets,
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

/** One copied-volume attachment of the preparation adapter, identified by the
 * exact reviewed helper/plan/kind/volume binding. */
export type GroupRestoreAttachKind = "boot" | "root";

/** Exact-key binding of one durable attachment intent. */
export interface GroupRestoreAttachIntentKey {
  planSha256: string;
  helperInstanceId: string;
  kind: GroupRestoreAttachKind;
  volumeId: string;
}

/** Durable, plan-bound attachment intent for one exact copied volume. The
 * helper instance, volume id and kind are persisted before every OCI attach
 * and after every attachment-state transition, so a later invocation can
 * reconcile an exact match: adopt a live ATTACHING/ATTACHED target, prove the
 * helper released the copies before a detach when preparation may have run,
 * and re-attach only after a fresh reconciliation shows the prior attachment
 * absent or completed. A record that reached `detachedAtUtc` remains as a
 * small audit record; an unresolved record is only superseded after it has
 * been reconciled, never silently. */
export interface GroupRestoreAttachIntent {
  schemaVersion: 1;
  planSha256: string;
  helperInstanceId: string;
  kind: GroupRestoreAttachKind;
  volumeId: string;
  /** UTC instant the intent was durably written before the attach call. */
  attachRequestedAtUtc: string;
  /** Exact OCI attachment id once a fresh list observed the row. */
  attachmentId?: string;
  /** Latest observed non-terminal attachment state. */
  attachmentState?: "ATTACHING" | "ATTACHED";
  /** True once the guarded preparation command was invoked. */
  preparationStarted?: boolean;
  /** UTC instant a fresh read-only helper probe proved the copies released
   * (or the validated typed marker attested the same) before a detach. */
  releaseProvedAtUtc?: string;
  /** UTC instant the exact attachment was proved absent/terminal. */
  detachedAtUtc?: string;
}

/** Small state-store callback for durable attachment intents. The file-backed
 * run wrapper supplies the implementation over the existing private state
 * directory; tests inject an in-memory one. Reads must fail closed on
 * malformed or mismatching state and return undefined only for genuine
 * absence. */
export interface GroupRestoreAttachIntentStore {
  read(
    key: GroupRestoreAttachIntentKey,
  ): Promise<GroupRestoreAttachIntent | undefined>;
  write(intent: GroupRestoreAttachIntent): Promise<void>;
}

const ATTACH_INTENT_RECORD_NAMES = [
  "schemaVersion",
  "planSha256",
  "helperInstanceId",
  "kind",
  "volumeId",
  "attachRequestedAtUtc",
  "attachmentId",
  "attachmentState",
  "preparationStarted",
  "releaseProvedAtUtc",
  "detachedAtUtc",
] as const;

function definedEntries(record: Record<string, unknown>): [string, unknown][] {
  return Object.entries(record).filter(([, value]) => value !== undefined);
}

function intentTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || value === "") {
    throw new Error(`${label} is not a bound timestamp`);
  }
  if (!Number.isFinite(Date.parse(value))) {
    throw new Error(`${label} is not a valid timestamp`);
  }
  return value;
}

/** Strict parse of one durable intent record from the state store. Every
 * field is checked; a malformed record throws instead of being treated as
 * absent so a resumed create can never overwrite or adopt unknown state. */
export function parseGroupRestoreAttachIntent(
  record: unknown,
): GroupRestoreAttachIntent {
  if (typeof record !== "object" || record === null || Array.isArray(record)) {
    throw new Error("Durable attachment intent is not an object");
  }
  const entries = definedEntries(record as Record<string, unknown>);
  const keys = entries.map(([key]) => key);
  const expected = [...ATTACH_INTENT_RECORD_NAMES];
  const required = [
    "schemaVersion",
    "planSha256",
    "helperInstanceId",
    "kind",
    "volumeId",
    "attachRequestedAtUtc",
  ] as const;
  if (
    keys.some((key) => !expected.includes(key as typeof expected[number])) ||
    required.some((key) => !keys.includes(key))
  ) {
    throw new Error("Durable attachment intent has missing or unknown fields");
  }
  const fields = Object.fromEntries(entries);
  if (fields.schemaVersion !== 1) {
    throw new Error("Durable attachment intent schema is unsupported");
  }
  if (
    typeof fields.planSha256 !== "string" ||
    !SHA256_PATTERN.test(fields.planSha256)
  ) {
    throw new Error("Durable attachment intent plan digest is malformed");
  }
  if (
    typeof fields.helperInstanceId !== "string" ||
    fields.helperInstanceId === ""
  ) {
    throw new Error("Durable attachment intent helper identity is malformed");
  }
  if (fields.kind !== "boot" && fields.kind !== "root") {
    throw new Error("Durable attachment intent kind is malformed");
  }
  if (typeof fields.volumeId !== "string" || fields.volumeId === "") {
    throw new Error("Durable attachment intent volume identity is malformed");
  }
  const intent: GroupRestoreAttachIntent = {
    schemaVersion: 1,
    planSha256: fields.planSha256 as string,
    helperInstanceId: fields.helperInstanceId as string,
    kind: fields.kind as GroupRestoreAttachKind,
    volumeId: fields.volumeId as string,
    attachRequestedAtUtc: intentTimestamp(
      fields.attachRequestedAtUtc,
      "Durable attachment intent request timestamp",
    ),
  };
  if (fields.attachmentId !== undefined) {
    if (
      typeof fields.attachmentId !== "string" || fields.attachmentId === ""
    ) {
      throw new Error("Durable attachment intent attachment id is malformed");
    }
    intent.attachmentId = fields.attachmentId as string;
  }
  if (fields.attachmentState !== undefined) {
    if (
      fields.attachmentState !== "ATTACHING" &&
      fields.attachmentState !== "ATTACHED"
    ) {
      throw new Error("Durable attachment intent state is malformed");
    }
    intent.attachmentState = fields.attachmentState as "ATTACHING" | "ATTACHED";
  }
  if (fields.preparationStarted !== undefined) {
    if (typeof fields.preparationStarted !== "boolean") {
      throw new Error(
        "Durable attachment intent preparation flag is malformed",
      );
    }
    intent.preparationStarted = fields.preparationStarted as boolean;
  }
  if (fields.releaseProvedAtUtc !== undefined) {
    intent.releaseProvedAtUtc = intentTimestamp(
      fields.releaseProvedAtUtc,
      "Durable attachment intent release timestamp",
    );
  }
  if (fields.detachedAtUtc !== undefined) {
    intent.detachedAtUtc = intentTimestamp(
      fields.detachedAtUtc,
      "Durable attachment intent detach timestamp",
    );
  }
  return intent;
}

export function sameGroupRestoreAttachIntentKey(
  intent: GroupRestoreAttachIntent,
  key: GroupRestoreAttachIntentKey,
): boolean {
  return intent.planSha256 === key.planSha256 &&
    intent.helperInstanceId === key.helperInstanceId &&
    intent.kind === key.kind && intent.volumeId === key.volumeId;
}

const UUID_PATTERN =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ROOT_DEVICE_PATTERN = /^\/dev\/oracleoci\/oraclevd[b-z]$/;

/** Fail-closed signature of an OCI copied-root device conflict: the exact
 * requested device was refused because it is already in use on the instance.
 * Only this narrow signature admits the bounded conflict recovery; any other
 * provider error (including a lost attach response) is never treated as a
 * conflict, so a recovery cannot fire on uncertainty. */
const COPY_DEVICE_CONFLICT_PATTERN =
  /device[^]*?(?:in use|already|conflict|busy|occupied)/i;

function isCopiedDeviceConflictError(stderr: string): boolean {
  return COPY_DEVICE_CONFLICT_PATTERN.test(stderr);
}

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
    (bootDevice !== null &&
      (typeof bootDevice !== "string" ||
        !ROOT_DEVICE_PATTERN.test(bootDevice))) ||
    typeof rootDevice !== "string" || !ROOT_DEVICE_PATTERN.test(rootDevice) ||
    (typeof bootDevice === "string" && bootDevice === rootDevice)
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

/** Generated guarded offline preparation Python body for the exact restored
 * copies. The helper re-proves its own metadata identity, the whole-disk
 * attachment paths, filesystem identities, the reviewed root partition start
 * sector and the reviewed boot bytes before writing only the copies, then
 * masks duplicate jobs/timers, installs the isolation files and the drill
 * default target, and prints the typed preparation marker. No source volume is
 * reachable: the helper can only see its own attachments. A per-plan advisory
 * lock serializes helper invocations before marker reconciliation. Before
 * creating the exclusive active marker it reconciles the exact plan-bound
 * marker of a prior run: a regular non-symlink file carrying a strictly valid
 * RELEASED token with every owned preparation path absent and unmounted may be
 * removed for a retry, while a symlink, directory, ACTIVE, malformed or
 * ambiguous marker or any present/mounted preparation path fails closed. The
 * body is exposed separately so the deterministic syntax-validation path and
 * tests can obtain the exact script that is sent to the helper. */
export function groupRestorePreparationScriptBody(
  plan: GroupRestorePlan,
  config: GroupRestorePreparationConfig,
  evidence: GroupRestorePreparationEvidence,
  bundle: DrillGuestBundle,
): string {
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
  return `
import atexit,base64,fcntl,hashlib,json,os,pathlib,re,stat,subprocess,urllib.request
p=json.loads(base64.b64decode('${payload}'))
e=p['evidence']; b=p['bundle']
assert p['preparationPlanSha256']==b['planSha256'], 'Preparation plan binding changed'
lock=pathlib.Path('/run/arch-drill-preparation-'+b['planSha256']+'.lock')
lock_fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
os.fchmod(lock_fd,0o600)
fcntl.flock(lock_fd,fcntl.LOCK_EX)
active=pathlib.Path('/run/arch-drill-preparation-'+b['planSha256']+'.active')
def reclaim_released_marker(marker):
 info=os.lstat(marker)
 assert stat.S_ISREG(info.st_mode),'Preparation marker is not a regular file'
 handle=os.open(marker,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  assert (os.fstat(handle).st_dev,os.fstat(handle).st_ino)==(info.st_dev,info.st_ino),'Preparation marker changed while reconciling'
  token=os.read(handle,65536).decode()
  assert re.fullmatch(r'RELEASED [1-9][0-9]*',token),'Preparation marker is not a strictly released token'
  paths=[pathlib.Path('/mnt/arch-drill/root'),pathlib.Path('/mnt/arch-drill/stage'),pathlib.Path('/mnt/arch-drill')]
  assert all(not path.is_mount() and not path.exists() for path in paths),'Copied preparation path is still present or mounted'
  current=os.lstat(marker)
  assert (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino),'Preparation marker changed while reconciling'
  os.unlink(marker)
 finally:
  os.close(handle)
try:
 reclaim_released_marker(active)
except FileNotFoundError:
 pass
with active.open('x') as marker_file:
 marker_file.write('ACTIVE '+str(os.getpid()))
os.chmod(active,0o600)
def release_marker():
 paths=[pathlib.Path('/mnt/arch-drill/root'),pathlib.Path('/mnt/arch-drill/stage'),pathlib.Path('/mnt/arch-drill')]
 try:
  if all(not path.is_mount() and not path.exists() for path in paths):
   active.write_text('RELEASED '+str(os.getpid()))
   os.chmod(active,0o600)
 except Exception: pass
atexit.register(release_marker)
request=urllib.request.Request('http://169.254.169.254/opc/v2/instance/',headers={'Authorization':'Bearer Oracle'})
with urllib.request.urlopen(request,timeout=10) as response: identity=json.load(response)
assert identity['id']==e['helper']['id'] and identity['id']!=p['plan']['source']['instanceId'], 'Wrong helper instance'
def run(*args): return subprocess.check_output(args,text=True).strip()
def disk(attachment,uuid,fstype,size):
 args=['lsblk','--json','--tree','--paths','--bytes','--output','PATH,TYPE,UUID,FSTYPE,SIZE,MOUNTPOINTS']
 if attachment.get('device') is not None:
  assert isinstance(attachment['device'],str) and re.fullmatch(r'/dev/oracleoci/oraclevd[b-z]',attachment['device']), 'Copied attachment device is not an OCI data-volume path'
  args.append(os.path.realpath(attachment['device']))
 else:
  assert attachment is e['bootAttachment'], 'Only the boot copy may use automatic device discovery'
 tree=json.loads(run(*args))['blockdevices']
 def has_mounts(item):
  return any(item.get('mountpoints') or []) or any(has_mounts(child) for child in item.get('children',[]))
 if attachment.get('device') is None:
  tree=[item for item in tree if item['type']=='disk' and not has_mounts(item) and any(child.get('uuid')==uuid and child.get('fstype')==fstype for child in item.get('children',[]))]
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
marker=None
try:
 # A crash-consistent online snapshot can have pending ext4 journal work. A
 # plain read-only mount replays that journal on this copied disk; noload
 # would leave the copy unrecovered and remounting it read-write would not
 # replay the journal.
 subprocess.run(['mount','-o','ro',root['path'],str(r)],check=True)
 subprocess.run(['umount',str(r)],check=True)
 subprocess.run(['mount','-o','rw',root['path'],str(r)],check=True);mounted.append(r)
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
 marker={'status':'OFFLINE_FILES_PREPARED','planSha256':b['planSha256'],'bootVolumeId':e['bootVolumeId'],'rootVolumeId':e['rootVolumeId'],'helperInstanceId':e['helper']['id'],'firstBootProved':False,'bootDevicePath':stage['diskPath'],'rootDevicePath':root['diskPath']}
finally:
 cleanup_errors=[]
 for path in reversed(mounted):
  try: subprocess.run(['umount',str(path)],check=True)
  except Exception as error: cleanup_errors.append(error)
 for path in [s,r]:
  try: path.rmdir()
  except Exception as error: cleanup_errors.append(error)
 try: base.rmdir()
 except Exception as error: cleanup_errors.append(error)
 if cleanup_errors: raise RuntimeError('Copied-volume cleanup did not release every guest mount') from cleanup_errors[0]
assert marker is not None, 'Preparation marker was not produced'
print(json.dumps(marker))
`;
}

/** Generated guarded offline preparation command for the exact restored
 * copies: the preparation body over passwordless sudo on the helper. */
export async function groupRestorePreparationCommand(
  plan: GroupRestorePlan,
  config: GroupRestorePreparationConfig,
  evidence: GroupRestorePreparationEvidence,
  bundle: DrillGuestBundle,
): Promise<string> {
  await validateGroupRestorePreparationConfig(config, plan, bundle);
  validateGroupRestorePreparationEvidence(config, plan, evidence);
  return "sudo -n python3 -c " +
    shellQuote(
      groupRestorePreparationScriptBody(plan, config, evidence, bundle),
    );
}

/** Read-only helper-side release proof Python body. The preparation command
 * creates the per-plan active marker before any metadata or disk check, then
 * changes its content to a positive RELEASED token only after every owned
 * mount and directory has been released. This proves that a lost SSH response
 * cannot still have a writer using the copied disks. Exposed separately so
 * the deterministic syntax-validation path and tests obtain the exact body. */
export function groupRestorePreparationReleaseScriptBody(
  config: GroupRestorePreparationConfig,
): string {
  return `
import pathlib
active=pathlib.Path('/run/arch-drill-preparation-${config.planSha256}.active')
assert active.exists() and not active.is_symlink(), 'Preparation completion marker is missing or ambiguous'
assert active.read_text().startswith('RELEASED '), 'Preparation is still active or did not positively complete'
for path in [pathlib.Path('/mnt/arch-drill/root'),pathlib.Path('/mnt/arch-drill/stage'),pathlib.Path('/mnt/arch-drill')]:
 assert not path.is_mount() and not path.exists(), 'Copied preparation path is still present or mounted'
print('ARCH_DRILL_PREPARATION_RELEASED ${config.planSha256}')
`;
}

/** Read-only helper-side release proof used before a failure-path OCI
 * detach: the release body over passwordless sudo on the helper. */
export function groupRestorePreparationReleaseCommand(
  config: GroupRestorePreparationConfig,
): string {
  return "sudo -n python3 -c " +
    shellQuote(groupRestorePreparationReleaseScriptBody(config));
}

/** Stdin-capable command runner for the deterministic local Python syntax
 * validation. The adapter's SSH transport never carries script text over this
 * path: validation supplies each exact body to the local runner, which may
 * materialize it privately before invoking the parser, and makes no cloud
 * call. */
export type GroupRestorePythonSyntaxRunner = (
  command: string,
  args: string[],
  stdin: string,
) => Promise<CommandResult>;

/** Deterministic fail-closed syntax validation of the exact generated
 * preparation and release bodies: each body is handed to the supplied runner
 * for `python3 -m py_compile` and any non-zero exit refuses the plan before
 * the guarded command is ever sent to the helper. */
export async function validateGroupRestorePreparationPythonScripts(
  preparationBody: string,
  releaseBody: string,
  python: GroupRestorePythonSyntaxRunner,
): Promise<void> {
  const bodies: Array<[string, string]> = [
    ["copied-volume preparation", preparationBody],
    ["helper release proof", releaseBody],
  ];
  for (const [label, body] of bodies) {
    const result = await python("python3", ["-m", "py_compile"], body);
    if (result.code !== 0) {
      const detail = (result.stderr || result.stdout).trim();
      throw new Error(
        `Generated ${label} Python body failed syntax validation: ${
          detail || `python3 exited with status ${result.code}`
        }`,
      );
    }
  }
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
  /** Durable attachment-intent store supplied by the file-backed run wrapper
   * (under the existing private state directory), or an in-memory store in
   * tests. Every attach intent and attachment-state transition is persisted
   * through this callback before/after the provider or helper transition it
   * attests. */
  attachState: GroupRestoreAttachIntentStore;
  /** Durable drill window observed by the run wrapper; attach and detach
   * polling budgets are derived from the remaining time and stay finite even
   * when no lifetime is supplied. */
  lifetime?: () => Promise<GroupRestoreLifetime | undefined>;
  /** Local stdio Python syntax runner. When supplied, the exact generated
   * preparation and release bodies are sent to `python3 -m py_compile`
   * before the guarded command is sent to the helper, so a syntax defect
   * fails closed locally instead of mid-drill after OCI resources exist. */
  python?: GroupRestorePythonSyntaxRunner;
}

/** Injectable real Pi/helper adapter: read-only helper and management-network
 * proof, exact restore attachment, the guarded copied-volume preparation over
 * pinned SSH, marker verification and clean detach, all before the first clone
 * create. Every attach is covered by a durable, plan-bound intent: a later
 * invocation adopts only an exact helper/plan/kind/volume match, refuses
 * pre-existing or ambiguous attachments without a matching intent, proves the
 * helper released the copies before a detach when preparation may have run,
 * and marks the intent released only after the detach is proved. Any
 * ambiguity, mismatch or preparation failure throws, so the restored guest
 * can never boot unprepared or beside production. */
export function groupRestorePreparationAdapter(
  config: GroupRestorePreparationConfig,
  plan: GroupRestorePlan,
  runner: GroupRestoreRunner,
  options: GroupRestorePreparationAdapterOptions,
): GroupRestorePreBootIsolationAdapter {
  const now = options.now ?? Date.now;
  const sleep = options.sleep ??
    ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const nowIso = (): string => new Date(now()).toISOString();
  const sshArgs = (command: string): string[] => [
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
    config.ssh.user + "@" + config.ssh.host,
    command,
  ];
  const proveHelperReleased = async (): Promise<void> => {
    const result = await options.ssh(
      "ssh",
      sshArgs(groupRestorePreparationReleaseCommand(config)),
    );
    const expected = `ARCH_DRILL_PREPARATION_RELEASED ${config.planSha256}`;
    if (
      result.code !== 0 ||
      !result.stdout.split("\n").some((line) => line.trim() === expected)
    ) {
      throw new Error(
        "Could not prove the helper released copied disks; preserving attachments",
      );
    }
  };
  /** Raw OCI CLI invocation with the exact disciplined runner surface; the
   * attach path needs the provider result to classify a device conflict, so
   * this does not throw for a non-zero exit. */
  const runCli = (argv: string[]): Promise<CommandResult> =>
    runner.run(
      runner.ociCliPath,
      [...groupRestoreCliArgs(runner, argv), "--output", "json"],
    );
  const call = async (argv: string[]): Promise<JsonRecord> => {
    const result = await runCli(argv);
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

  /** Fresh exact attachment/device inventory for copied-root device
   * resolution: the explicit OCI device of every current non-terminal
   * attachment (including a boot copy auto-assigned without an explicit
   * request) plus the provider's available-device list. A device that is
   * occupied by any live attachment can never be chosen for the copied root,
   * so an unexpected boot auto-assignment cannot collide with it. */
  const deviceInventory = async (): Promise<{
    occupied: Set<string>;
    available: string[];
  }> => {
    const occupied = new Set<string>();
    for (const row of await listAttachments("root")) {
      if (isTerminalAttachment(row)) continue;
      const device = row.device;
      if (typeof device === "string" && device !== "") occupied.add(device);
    }
    const devices = dataArray(
      await call([
        "compute",
        "device",
        "list-instance",
        "--instance-id",
        config.helper.instanceId,
        "--is-available",
        "true",
        "--all",
      ]),
    );
    const available = devices
      .filter((row) => row["is-available"] === true)
      .map((row) => row.name)
      .filter((name): name is string =>
        typeof name === "string" && ROOT_DEVICE_PATTERN.test(name)
      )
      .sort();
    return { occupied, available };
  };

  /** Next available copied-root device candidate from a fresh inventory. An
   * empty provider list fails closed; a candidate that is occupied by a
   * current attachment or equals the `excluded` device (the one that just
   * conflicted) is never returned. */
  const rootDeviceCandidate = async (
    excluded?: string,
  ): Promise<string | undefined> => {
    const { occupied, available } = await deviceInventory();
    if (available.length === 0) {
      throw new Error(
        "OCI did not report an available consistent device path for the copied root",
      );
    }
    return available.find(
      (name) => !occupied.has(name) && name !== excluded,
    );
  };

  const intentKey = (
    kind: GroupRestoreAttachKind,
    volumeId: string,
  ): GroupRestoreAttachIntentKey => ({
    planSha256: config.planSha256,
    helperInstanceId: config.helper.instanceId,
    kind,
    volumeId,
  });

  const readIntent = async (
    kind: GroupRestoreAttachKind,
    volumeId: string,
  ): Promise<GroupRestoreAttachIntent | undefined> => {
    const record = await options.attachState.read(intentKey(kind, volumeId));
    if (record === undefined) return undefined;
    const intent = parseGroupRestoreAttachIntent(record);
    if (
      intent.planSha256 !== config.planSha256 ||
      intent.helperInstanceId !== config.helper.instanceId ||
      intent.kind !== kind || intent.volumeId !== volumeId
    ) {
      throw new Error(
        "Durable attachment intent is not bound to the reviewed preparation",
      );
    }
    return intent;
  };

  const writeIntent = async (
    intent: GroupRestoreAttachIntent,
  ): Promise<void> => {
    await options.attachState.write(parseGroupRestoreAttachIntent(intent));
  };

  /** Bounded polling window derived from the durable drill window, exactly
   * like the executor's delete polling; it stays finite (capped by the plan
   * window and the short fallback budget) when no lifetime is supplied. */
  const pollBudget = async (started: number): Promise<number> =>
    groupRestoreDeletePollBudgetMs(plan, await options.lifetime?.(), started);

  /** Poll one exact copied-volume attachment to ATTACHED, persisting every
   * observed state transition into the durable intent before it is trusted.
   * A single matching row in ATTACHING is recorded and re-polled; an
   * unexpected state, ambiguity or budget exhaustion fails closed and leaves
   * the durable intent for the next invocation's exact reconciliation. */
  const waitAttached = async (
    kind: GroupRestoreAttachKind,
    volumeId: string,
    base: GroupRestoreAttachIntent,
    knownId?: string,
  ): Promise<string> => {
    const started = now();
    for (;;) {
      const current = (await listAttachments(kind)).filter((row) =>
        attachmentVolumeId(row) === volumeId && !isTerminalAttachment(row)
      );
      if (current.length === 1) {
        const row = current[0]!;
        const attachmentId = stringField(row, "id");
        const state = row["lifecycle-state"];
        if (knownId !== undefined && attachmentId !== knownId) {
          throw new Error(
            "Copied-volume attachment identity changed while waiting",
          );
        }
        if (state === "ATTACHED") {
          await writeIntent({
            ...base,
            attachmentId,
            attachmentState: "ATTACHED",
          });
          return attachmentId;
        }
        if (state === "ATTACHING") {
          await writeIntent({
            ...base,
            attachmentId,
            attachmentState: "ATTACHING",
          });
        } else {
          throw new Error(
            "Copied-volume attachment entered an unexpected state",
          );
        }
      } else if (current.length > 1) {
        throw new Error("Copied-volume attachment state is ambiguous");
      }
      if (now() - started >= await pollBudget(started)) {
        throw new Error(
          `Copied ${kind} volume did not reach ATTACHED within the bounded budget`,
        );
      }
      await sleep(GROUP_RESTORE_DETACH_POLL_INTERVAL_MS);
    }
  };

  /** The helper must never hold a production source volume attachment: the
   * guarded command and the device resolution may only ever see the exact
   * restored copies. Re-checked on every fresh attachment snapshot, including
   * the device-conflict reconcile. */
  const assertNoSourceAttachment = (rows: JsonRecord[]): void => {
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
  };

  const ensureAttached = async (
    kind: GroupRestoreAttachKind,
    volumeId: string,
    onAttachAttempt: () => void,
  ): Promise<string> => {
    const rows = (await listAttachments(kind)).filter((row) =>
      !isTerminalAttachment(row)
    );
    assertNoSourceAttachment(rows);
    const matching = rows.filter((row) => attachmentVolumeId(row) === volumeId);
    if (matching.length > 1) {
      throw new Error("Copied-volume attachment state is ambiguous");
    }
    const durable = await readIntent(kind, volumeId);
    if (durable === undefined) {
      // A target attachment that predates this invocation has no matching
      // durable intent: it is not adapter-owned and must never be adopted or
      // detached. An operator has to reconcile that state first.
      if (matching.length !== 0) {
        throw new Error(
          "Copied-volume target is already attached; refusing to adopt it",
        );
      }
    } else if (durable.detachedAtUtc !== undefined) {
      // A completed/released record: reconcile it before retrying. A live
      // attachment again is no longer covered by the completed intent and is
      // refused; an absent attachment means the retry may proceed.
      if (matching.length !== 0) {
        throw new Error(
          "Completed attachment intent is live again; refusing to adopt it",
        );
      }
    } else if (matching.length === 1) {
      // An unresolved durable intent matches exactly one live attachment:
      // adopt it (never a second attach). A recorded id mismatch or an
      // unexpected state fails closed.
      const row = matching[0]!;
      const attachmentId = stringField(row, "id");
      if (
        durable.attachmentId !== undefined &&
        durable.attachmentId !== attachmentId
      ) {
        throw new Error(
          "Durable attachment intent differs from the live attachment",
        );
      }
      const state = row["lifecycle-state"];
      if (state === "ATTACHED") {
        onAttachAttempt();
        await writeIntent({
          ...durable,
          attachmentId,
          attachmentState: "ATTACHED",
        });
        return attachmentId;
      }
      if (state === "ATTACHING") {
        onAttachAttempt();
        return await waitAttached(kind, volumeId, durable, attachmentId);
      }
      throw new Error("Copied-volume attachment entered an unexpected state");
    }
    // Fresh attach (or a reconciled retry after an absent/completed target):
    // the durable intent is written BEFORE the provider request so a lost
    // response can only ever be reconciled to the exact live attachment,
    // never re-issued as a duplicate attach.
    onAttachAttempt();
    const device = kind === "root" ? await rootDeviceCandidate() : undefined;
    if (kind === "root" && device === undefined) {
      throw new Error(
        "Every OCI-available device path for the copied root is occupied by a current attachment",
      );
    }
    const base: GroupRestoreAttachIntent = {
      schemaVersion: 1,
      planSha256: config.planSha256,
      helperInstanceId: config.helper.instanceId,
      kind,
      volumeId,
      attachRequestedAtUtc: nowIso(),
    };
    await writeIntent(base);
    const attachArgs = (candidate: string | undefined): string[] => [
      "compute",
      "volume-attachment",
      "attach",
      "--instance-id",
      config.helper.instanceId,
      "--volume-id",
      volumeId,
      "--type",
      "paravirtualized",
      ...(candidate === undefined ? [] : ["--device", candidate]),
    ];
    const attachResult = await runCli(attachArgs(device));
    if (attachResult.code === 0) {
      return await waitAttached(kind, volumeId, base);
    }
    if (
      kind !== "root" || device === undefined ||
      !isCopiedDeviceConflictError(attachResult.stderr)
    ) {
      throw new Error(
        `OCI preparation request failed (${attachResult.code}): ${
          redactOcid(attachResult.stderr)
        }`,
      );
    }
    // Bounded fail-closed device-conflict recovery for the copied root: the
    // exact target's live attachment is reconciled FIRST, because OCI may
    // have accepted the attach even though the response reported the
    // conflict. A matching live target is adopted (or waited on); after an
    // uncertain acceptance it is never attached a second time.
    const conflict = attachResult;
    const live = (await listAttachments(kind)).filter((row) =>
      !isTerminalAttachment(row)
    );
    assertNoSourceAttachment(live);
    const reconciled = live.filter((row) =>
      attachmentVolumeId(row) === volumeId
    );
    if (reconciled.length === 1) {
      const row = reconciled[0]!;
      const attachmentId = stringField(row, "id");
      if (
        base.attachmentId !== undefined && base.attachmentId !== attachmentId
      ) {
        throw new Error(
          "Copied-volume attachment identity changed after a device conflict",
        );
      }
      const state = row["lifecycle-state"];
      if (state === "ATTACHED") {
        await writeIntent({
          ...base,
          attachmentId,
          attachmentState: "ATTACHED",
        });
        return attachmentId;
      }
      if (state === "ATTACHING") {
        return await waitAttached(kind, volumeId, base, attachmentId);
      }
      throw new Error("Copied-volume attachment entered an unexpected state");
    }
    if (reconciled.length > 1) {
      throw new Error("Copied-volume attachment state is ambiguous");
    }
    // A fresh reconcile proves the target absent: only a fresh available
    // device list with a distinct next candidate may admit the single
    // bounded retry; otherwise the durable intent is preserved and the run
    // fails closed.
    const next = await rootDeviceCandidate(device);
    if (next === undefined) {
      throw new Error(
        `OCI copied-root device conflict (${conflict.code}): ${
          redactOcid(conflict.stderr)
        }; no distinct next OCI device path is available, preserving the durable intent`,
      );
    }
    const retry: GroupRestoreAttachIntent = {
      schemaVersion: 1,
      planSha256: config.planSha256,
      helperInstanceId: config.helper.instanceId,
      kind,
      volumeId,
      attachRequestedAtUtc: nowIso(),
    };
    await writeIntent(retry);
    const retryResult = await runCli(attachArgs(next));
    if (retryResult.code !== 0) {
      throw new AggregateError(
        [
          new Error(
            `OCI copied-root device conflict: ${redactOcid(conflict.stderr)}`,
          ),
          new Error(
            `OCI copied-root device-conflict retry failed (${retryResult.code}): ${
              redactOcid(retryResult.stderr)
            }`,
          ),
        ],
        "Copied root device conflict retry failed; the durable intent is preserved and launch is refused",
      );
    }
    return await waitAttached(kind, volumeId, retry);
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
    for (;;) {
      const live = (await listAttachments(kind)).filter((row) =>
        String(row.id) === attachmentId &&
        !isTerminalAttachment(row)
      );
      if (live.length === 0) return;
      if (now() - started >= await pollBudget(started)) {
        throw new Error(
          "Copied-volume attachment did not detach within the bounded budget",
        );
      }
      await sleep(GROUP_RESTORE_DETACH_POLL_INTERVAL_MS);
    }
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
      let preparationStarted = false;
      let preparationSucceeded = false;
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
        if (options.python !== undefined) {
          // Fail closed locally before the guarded command can reach the
          // helper: both generated bodies must parse on the exact stdio
          // runner. No cloud call is made by this check.
          await validateGroupRestorePreparationPythonScripts(
            groupRestorePreparationScriptBody(plan, config, evidence, bundle),
            groupRestorePreparationReleaseScriptBody(config),
            options.python,
          );
        }
        // Persist the preparation intent before the helper command so a lost
        // SSH response is never detached without a fresh release proof.
        const bootIntent = await readIntent("boot", targets.bootVolumeId);
        if (bootIntent !== undefined) {
          await writeIntent({ ...bootIntent, preparationStarted: true });
        }
        const rootIntent = await readIntent("root", targets.rootVolumeId);
        if (rootIntent !== undefined) {
          await writeIntent({ ...rootIntent, preparationStarted: true });
        }
        preparationStarted = true;
        const sshResult: CommandResult = await options.ssh(
          "ssh",
          sshArgs(command),
        );
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
        // The typed marker attests the helper-side release (the command
        // exits nonzero on any leftover mount): no extra probe is needed for
        // attachments this invocation prepared successfully.
        preparationSucceeded = true;
      } catch (error) {
        operationFailed = true;
        operationError = error;
      }
      // A failed SSH operation may still be running on the helper after the
      // client lost its response. Do not detach a copied disk until a fresh,
      // read-only helper probe proves the per-plan marker and all mount paths
      // are gone. If proof is unavailable, preserve the attachments for
      // manual reconciliation rather than risking an unclean detach.
      if (operationFailed && preparationStarted && !preparationSucceeded) {
        try {
          await proveHelperReleased();
          // The read-only proof is durable before any detach may run, so the
          // per-detach reconciliation below never probes twice.
          for (
            const [kind, volumeId] of [
              ["boot", targets.bootVolumeId],
              ["root", targets.rootVolumeId],
            ] as const
          ) {
            const intent = await readIntent(kind, volumeId);
            if (
              intent !== undefined && intent.releaseProvedAtUtc === undefined
            ) {
              await writeIntent({
                ...intent,
                releaseProvedAtUtc: nowIso(),
              });
            }
          }
        } catch (error) {
          throw new AggregateError(
            operationError === undefined ? [error] : [operationError, error],
            "Copied-volume preparation cleanup blocked; helper release was not proved and attachments were preserved",
          );
        }
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
          // Preparation may have run in this invocation or in a prior one
          // that crashed: the durable intent decides whether a fresh read-only
          // helper release proof must precede this detach.
          const intent = await readIntent(kind, volumeId);
          let releaseProved = preparationSucceeded ||
            intent?.releaseProvedAtUtc !== undefined;
          if (
            intent?.preparationStarted === true &&
            intent.releaseProvedAtUtc === undefined && !releaseProved
          ) {
            await proveHelperReleased();
            await writeIntent({
              ...intent,
              releaseProvedAtUtc: nowIso(),
            });
            releaseProved = true;
          }
          if (attachmentId !== undefined) {
            await detachBy(kind, attachmentId);
          } else {
            await detachByVolume(kind, volumeId);
          }
          // Mark the intent released only after the exact detach is proved;
          // a completed record may remain as a small durable audit record.
          const settled = await readIntent(kind, volumeId);
          if (settled !== undefined) {
            await writeIntent({
              ...settled,
              detachedAtUtc: nowIso(),
              releaseProvedAtUtc: releaseProved
                ? settled.releaseProvedAtUtc ?? nowIso()
                : undefined,
            });
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
