/**
 * m02-b2-machine-restore: reconstruct the six decrypted filesystem archives
 * from one accepted v1 Backblaze generation onto the one explicitly approved
 * empty aarch64 drill target.
 *
 * The caller supplies verified archive identities plus the matching recovery
 * metadata and index. Archives can be local `.tar.zst` files or a verified
 * streaming extractor, so a RAM-rescue target needs no archive scratch disk.
 * This module then performs the target-only destructive work in
 * bounded, journaled stages.  It never opens a source block device, talks to
 * B2, reads credentials, configures NVRAM, masks clone services, or claims a
 * boot drill.  A successful result is `FILESYSTEMS_REBUILT` only.
 *
 * The executable reads `.private/backblaze-machine-restore.json`, following
 * the repository's existing private JSON convention.  No command-line flag,
 * environment variable, or secret is part of the interface.
 */
import { createHash } from "node:crypto";

import { type CommandRunner, defaultRunner } from "./oci.ts";
import {
  type IndexArchiveRecord,
  type RecoveryIndex,
  validateRecoveryIndex,
} from "./backblaze-index.ts";
import type { UploadRole } from "./backblaze-upload.ts";
import { validateRecoveryMetadata } from "./backblaze-verifier.ts";

const CONFIG_PATH = ".private/backblaze-machine-restore.json";
const JOURNAL_NAME = "backblaze-machine-restore.journal.json";
const EXPECTED_BOOT_BYTES = 50 * 1024 ** 3;
const EXPECTED_ROOT_BYTES = 150 * 1024 ** 3;
const EXPECTED_ARCHIVE_ROLES: readonly RestoreArchiveRole[] = [
  "root",
  "efi",
  "staging-boot",
  "staging-efi",
  "oracle-root",
  "oracle-oled",
];
export const STAGES = [
  "preflight-verified",
  "partition-tables-written",
  "filesystems-created",
  "lvm-restored",
  "mounted",
  "archives-extracted",
  "swap-recreated",
  "filesystem-rebuilt",
] as const;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SHA256_ANY_PATTERN = /^[0-9a-f]{64}$/i;
const UUID_PATTERN = /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+$/;
const ABSOLUTE_PATH_PATTERN = /^\/[A-Za-z0-9_.@+:-]+(?:\/[A-Za-z0-9_.@+:-]+)*$/;
/** Stable by-id paths must resolve to the separately approved hardware serials. */
const TARGET_PATH_PATTERN =
  /^\/dev\/disk\/by-id\/(?:virtio|scsi)-[A-Za-z0-9_.+:-]+$/;
const SAFE_NAME_PATTERN = /^[A-Za-z0-9_.+-]+$/;
const MAX_JOURNAL_BYTES = 1024 * 1024;

type RestoreArchiveRole = Exclude<UploadRole, "recovery">;
export type RestoreStage = (typeof STAGES)[number];

/** The exact target identity and write boundary settled by the primary. */
export interface MachineRestoreTarget {
  targetId: string;
  architecture: string;
  bootDiskPath: string;
  rootDiskPath: string;
  bootDiskBytes: number;
  rootDiskBytes: number;
  bootDiskSerial: string;
  rootDiskSerial: string;
  /** Existing owner-only rescue scratch directory. */
  workDirectory: string;
  approval: {
    targetId: string;
    bootDiskPath: string;
    rootDiskPath: string;
    bootDiskSerial: string;
    rootDiskSerial: string;
    approvedAtUtc: string;
  };
}

/** One filesystem archive's identities from the accepted verifier receipt. */
export interface DecryptedRestoreArchive {
  role: RestoreArchiveRole;
  /** Local `.tar.zst` path; omitted when a verified stream extractor is supplied. */
  path?: string;
  bytes: number;
  sha256: string;
  /** Ciphertext size/hash bound to the selected RecoveryIndex archive. */
  ciphertextBytes: number;
  ciphertextSha256: string;
  /** The upstream verifier's proof is retained in the input for auditability. */
  verifierChecked?: true;
}

/** The six source filesystem records captured in recovery metadata. */
export interface MachineSourceRecord {
  name: RestoreArchiveRole;
  uuid: string;
  filesystem: "ext4" | "xfs" | "vfat";
  size: number;
  livePath?: "/" | "/efi";
}

export interface MachineBlockNode {
  name?: string;
  path?: string;
  size?: number;
  type?: string;
  fstype?: string | null;
  uuid?: string | null;
  serial?: string;
  partn?: number;
  mountpoints?: (string | null)[] | null;
  children?: MachineBlockNode[];
}

export interface MachinePartitionTable {
  disk: string;
  dump: string;
}

export interface MachineLvmMetadata {
  volumeGroup: string;
  file?: string | null;
  bytes?: number | null;
  sha256?: string | null;
  text: string;
}

export interface MachineMetadataArchive {
  role: RestoreArchiveRole;
  path: string;
  bytes: number;
  sha256: string;
  format: "tar.zst.gpg";
}

/**
 * Recovery metadata is intentionally typed only for the fields needed to
 * rebuild the machine.  Additional capture fields remain allowed so the v1
 * archive stays forward-compatible without weakening the fields we bind.
 */
export interface MachineRecoveryMetadata {
  schemaVersion: 1;
  generation: string;
  consistency: "live-file-copy";
  sourceShutdown: false;
  machineBootRestoreProved: false;
  sources: readonly MachineSourceRecord[];
  blockLayouts: {
    final: readonly MachineBlockNode[];
    initial?: readonly MachineBlockNode[];
  };
  partitionTables: readonly MachinePartitionTable[];
  lvm: MachineLvmMetadata;
  archives: readonly MachineMetadataArchive[];
  recipient: { fingerprint: string; publicSha256: string };
  finalChecks: {
    pacmanLockAbsent: true;
    packagesUnchanged: true;
    bootHashesUnchanged: true;
  };
  bootHashes: { root: string; stagingBoot: string };
  swapRecreation: {
    present: true;
    path: "/.swapfile";
    bytes: 4294967296;
    mode: number;
    uid: number;
    gid: number;
  };
  fstab: string;
  procCmdline: string;
  [key: string]: unknown;
}

/** Concrete m02 input.  `archives` are the six decrypted `.tar.zst` paths. */
export interface MachineRestoreInput {
  index: RecoveryIndex;
  /** SHA-256 of JSON.stringify(validateRecoveryIndex(index)). */
  indexSha256: string;
  metadata: MachineRecoveryMetadata;
  archives: readonly DecryptedRestoreArchive[];
  target: MachineRestoreTarget;
}

export interface MachineRestoreResult {
  status: "FILESYSTEMS_REBUILT";
  generation: string;
  indexSha256: string;
  targetId: string;
  journalPath: string;
  stages: readonly RestoreStage[];
  restoredRoles: readonly RestoreArchiveRole[];
  targetDisks: {
    boot: string;
    root: string;
  };
  mountsReleased: true;
  decryptedRestoreProved: true;
  machineBootRestoreProved: false;
}

interface LayoutFilesystem {
  role: RestoreArchiveRole;
  filesystem: "ext4" | "xfs" | "vfat";
  uuid: string;
  size: number;
  device: string;
}

interface RestoreLayout {
  bootDisk: {
    originalPath: string;
    targetPath: string;
    dump: string;
    partitions: { efi: string; stagingBoot: string; lvm: string };
  };
  rootDisk: {
    originalPath: string;
    targetPath: string;
    dump: string;
    partitions: { efi: string; root: string };
  };
  filesystems: readonly LayoutFilesystem[];
  volumeGroup: string;
  pvUuid: string;
  lvmText: string;
  swap: MachineRecoveryMetadata["swapRecreation"];
}

interface TargetNode extends MachineBlockNode {
  path: string;
  size: number;
  type: string;
  serial: string;
}

interface TargetSnapshot {
  nodes: readonly MachineBlockNode[];
  boot: TargetNode;
  root: TargetNode;
  mountedSources: readonly string[];
  mountedTargets: readonly string[];
  mountedEntries: readonly MachineMountEntry[];
}

export interface MachineMountEntry {
  target: string;
  source: string;
  uuid?: string;
  fstype?: string;
}

export interface RestoreJournal {
  schemaVersion: 2;
  targetId: string;
  architecture: "aarch64";
  bootDiskPath: string;
  rootDiskPath: string;
  bootDiskSerial: string;
  rootDiskSerial: string;
  bootDiskBytes: typeof EXPECTED_BOOT_BYTES;
  rootDiskBytes: typeof EXPECTED_ROOT_BYTES;
  approval: MachineRestoreTarget["approval"];
  generation: string;
  indexSha256: string;
  startedAtUtc: string;
  updatedAtUtc: string;
  completedStages: RestoreStage[];
  lvmTextSha256: string;
  partitionDumpSha256: { boot: string; root: string };
  archives: readonly Pick<
    DecryptedRestoreArchive,
    "role" | "bytes" | "sha256" | "ciphertextBytes" | "ciphertextSha256"
  >[];
}

interface ParsedJson {
  [key: string]: unknown;
}

const FAIL_PREFIX = "Machine restore failed (";

function fail(label: string): never {
  throw new Error(`${FAIL_PREFIX}${label})`);
}

function isRecord(value: unknown): value is ParsedJson {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asSafeInteger(value: unknown, label: string, min = 0): number {
  if (
    typeof value !== "number" || !Number.isSafeInteger(value) || value < min
  ) {
    fail(label);
  }
  return value;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Exported so the primary can bind the same canonical index identity. */
export function machineRestoreIndexSha256(indexInput: RecoveryIndex): string {
  const index = validateRecoveryIndex(indexInput);
  return sha256Hex(new TextEncoder().encode(JSON.stringify(index)));
}

function isUtcTimestamp(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) &&
    Number.isFinite(Date.parse(value));
}

function assertAbsolutePath(
  value: unknown,
  label: string,
): asserts value is string {
  if (typeof value !== "string" || !ABSOLUTE_PATH_PATTERN.test(value)) {
    fail(label);
  }
}

function assertTargetShape(target: MachineRestoreTarget): void {
  if (!isRecord(target)) fail("target:shape");
  if (
    typeof target.targetId !== "string" ||
    !SAFE_NAME_PATTERN.test(target.targetId) ||
    target.architecture !== "aarch64"
  ) {
    fail("target:identity");
  }
  if (
    target.bootDiskBytes !== EXPECTED_BOOT_BYTES ||
    target.rootDiskBytes !== EXPECTED_ROOT_BYTES
  ) fail("target:capacity");
  if (
    !TARGET_PATH_PATTERN.test(target.bootDiskPath) ||
    !TARGET_PATH_PATTERN.test(target.rootDiskPath) ||
    target.bootDiskPath === target.rootDiskPath
  ) fail("target:path");
  assertAbsolutePath(target.workDirectory, "target:work-directory");
  if (
    target.workDirectory === target.bootDiskPath ||
    target.workDirectory === target.rootDiskPath
  ) fail("target:work-directory");
  if (
    typeof target.bootDiskSerial !== "string" ||
    typeof target.rootDiskSerial !== "string" ||
    !SAFE_NAME_PATTERN.test(target.bootDiskSerial) ||
    !SAFE_NAME_PATTERN.test(target.rootDiskSerial) ||
    target.bootDiskSerial === target.rootDiskSerial
  ) fail("target:serial");
  const approval = target.approval;
  if (
    !isRecord(approval) ||
    approval.targetId !== target.targetId ||
    approval.bootDiskPath !== target.bootDiskPath ||
    approval.rootDiskPath !== target.rootDiskPath ||
    approval.bootDiskSerial !== target.bootDiskSerial ||
    approval.rootDiskSerial !== target.rootDiskSerial ||
    typeof approval.approvedAtUtc !== "string" ||
    !isUtcTimestamp(approval.approvedAtUtc)
  ) fail("target:approval");
}

function sourceRecordMap(
  metadata: MachineRecoveryMetadata,
): Map<RestoreArchiveRole, MachineSourceRecord> {
  if (!Array.isArray(metadata.sources) || metadata.sources.length !== 6) {
    fail("metadata:sources");
  }
  const map = new Map<RestoreArchiveRole, MachineSourceRecord>();
  for (const source of metadata.sources) {
    if (
      !isRecord(source) ||
      !EXPECTED_ARCHIVE_ROLES.includes(source.name as RestoreArchiveRole)
    ) {
      fail("metadata:sources");
    }
    const role = source.name as RestoreArchiveRole;
    if (map.has(role)) fail("metadata:sources");
    if (!UUID_PATTERN.test(String(source.uuid))) fail("metadata:sources");
    if (!new Set(["ext4", "xfs", "vfat"]).has(String(source.filesystem))) {
      fail("metadata:sources");
    }
    const size = asSafeInteger(source.size, "metadata:sources", 1);
    const livePath = source.livePath === "/" || source.livePath === "/efi"
      ? source.livePath
      : undefined;
    map.set(role, {
      name: role,
      uuid: String(source.uuid),
      filesystem: source.filesystem as MachineSourceRecord["filesystem"],
      size,
      ...(livePath === undefined ? {} : { livePath }),
    });
  }
  if (map.size !== EXPECTED_ARCHIVE_ROLES.length) fail("metadata:sources");
  const expectedFilesystems: Record<RestoreArchiveRole, string> = {
    root: "ext4",
    efi: "vfat",
    "staging-boot": "xfs",
    "staging-efi": "vfat",
    "oracle-root": "xfs",
    "oracle-oled": "xfs",
  };
  for (const role of EXPECTED_ARCHIVE_ROLES) {
    if (map.get(role)!.filesystem !== expectedFilesystems[role]) {
      fail("metadata:sources");
    }
  }
  return map;
}

function finalBlockMap(
  metadata: MachineRecoveryMetadata,
): Map<string, MachineBlockNode> {
  const final = metadata.blockLayouts?.final;
  if (!Array.isArray(final) || final.length !== 2) {
    fail("metadata:block-layout");
  }
  const map = new Map<string, MachineBlockNode>();
  for (const node of flattenNodes(final)) {
    if (!isRecord(node) || typeof node.path !== "string") {
      fail("metadata:block-layout");
    }
    if (map.has(node.path)) fail("metadata:block-layout");
    map.set(node.path, node as MachineBlockNode);
  }
  return map;
}

function diskSizeFromDump(dump: string, label: string): number {
  const sector = /(?:^|\n)sector-size:\s*(\d+)\s*(?:\n|$)/.exec(dump);
  const last = /(?:^|\n)last-lba:\s*(\d+)\s*(?:\n|$)/.exec(dump);
  if (!sector || !last) fail(label);
  const sectorBytes = Number(sector[1]);
  const lastLba = Number(last[1]);
  if (
    !Number.isSafeInteger(sectorBytes) || !Number.isSafeInteger(lastLba) ||
    sectorBytes <= 0
  ) {
    fail(label);
  }
  const size = (lastLba + 1) * sectorBytes;
  if (!Number.isSafeInteger(size) || size <= 0) fail(label);
  return size;
}

function replacePathToken(
  text: string,
  original: string,
  replacement: string,
): string {
  return text.split(original).join(replacement);
}

/**
 * Rewrite a captured sfdisk dump for one approved target. Partition paths use
 * the stable `/dev/disk/by-id/...-partN` form required by the target contract;
 * no `/dev/sda`/`/dev/sdb` ordering survives the rewrite.
 */
export function rewriteSfdiskDump(
  dumpInput: string,
  originalDisk: string,
  targetDisk: string,
): string {
  assertAbsolutePath(originalDisk, "partition:source-path");
  if (!TARGET_PATH_PATTERN.test(targetDisk)) fail("partition:target-path");
  if (
    originalDisk === targetDisk ||
    !dumpInput.includes(`device: ${originalDisk}`)
  ) {
    fail("partition:source-binding");
  }
  let dump = dumpInput;
  const partitionPattern = new RegExp(
    `${originalDisk.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\d+)\\s*:`,
    "g",
  );
  dump = dump.replace(
    partitionPattern,
    (_match, number: string) => `${targetDisk}-part${number} :`,
  );
  dump = replacePathToken(dump, originalDisk, targetDisk);
  if (!dump.includes(`device: ${targetDisk}`) || dump.includes(originalDisk)) {
    fail("partition:source-leak");
  }
  return dump;
}

function validateLvmText(
  metadata: MachineRecoveryMetadata,
  sourceBlocks: Map<string, MachineBlockNode>,
): { volumeGroup: string; pvUuid: string; text: string } {
  const lvm = metadata.lvm;
  if (
    !isRecord(lvm) || typeof lvm.volumeGroup !== "string" ||
    !SAFE_NAME_PATTERN.test(lvm.volumeGroup)
  ) {
    fail("metadata:lvm");
  }
  if (
    typeof lvm.text !== "string" || lvm.text.length === 0 ||
    lvm.text.length > MAX_JOURNAL_BYTES
  ) {
    fail("metadata:lvm");
  }
  const pv =
    /physical_volumes\s*\{[\s\S]*?id\s*=\s*"([A-Za-z0-9-]+)"[\s\S]*?device\s*=\s*"([^"]+)"/
      .exec(lvm.text);
  if (!pv || !UUID_PATTERN.test(pv[1]) || !ABSOLUTE_PATH_PATTERN.test(pv[2])) {
    fail("metadata:lvm");
  }
  const sourcePv = sourceBlocks.get(pv[2]);
  if (
    !sourcePv || sourcePv.uuid === null || sourcePv.uuid === undefined ||
    sourcePv.uuid !== pv[1]
  ) {
    fail("metadata:lvm-pv");
  }
  const logicalText = /logical_volumes\s*\{([\s\S]*)\}/.exec(lvm.text)?.[1] ??
    "";
  const lvNames = [...logicalText.matchAll(/^\s*([A-Za-z0-9_.+-]+)\s*\{/gm)]
    .map((match) => match[1]);
  if (!lvNames.includes("root") || !lvNames.includes("oled")) {
    fail("metadata:lvm-lvs");
  }
  return { volumeGroup: lvm.volumeGroup, pvUuid: pv[1], text: lvm.text };
}

/**
 * Validate v1 metadata and construct the target mapping without invoking a
 * command. This pure function is also the reviewable proof that `/dev/sda`
 * and `/dev/sdb` are selected by recorded capacity, not by enumeration order.
 */
export function buildRestoreLayout(
  indexInput: RecoveryIndex,
  metadata: MachineRecoveryMetadata,
  target: MachineRestoreTarget,
): RestoreLayout {
  assertTargetShape(target);
  const index = validateRecoveryIndex(indexInput);
  try {
    validateRecoveryMetadata(metadata, index);
  } catch {
    fail("metadata:binding");
  }
  if (
    metadata.generation !== index.generation ||
    metadata.schemaVersion !== 1 ||
    metadata.consistency !== "live-file-copy" ||
    metadata.sourceShutdown !== false ||
    metadata.machineBootRestoreProved !== false
  ) fail("metadata:binding");
  const sources = sourceRecordMap(metadata);
  const blocks = finalBlockMap(metadata);
  if (
    !Array.isArray(metadata.partitionTables) ||
    metadata.partitionTables.length !== 2
  ) {
    fail("metadata:partitions");
  }
  const tables = metadata.partitionTables.map((table) => {
    if (
      !isRecord(table) || typeof table.disk !== "string" ||
      typeof table.dump !== "string"
    ) {
      fail("metadata:partitions");
    }
    const diskNode = blocks.get(table.disk);
    if (
      !diskNode || diskNode.type !== "disk" || typeof diskNode.size !== "number"
    ) {
      fail("metadata:partitions");
    }
    const dumpSize = diskSizeFromDump(table.dump, "metadata:partitions");
    if (dumpSize > diskNode.size) fail("metadata:partitions");
    return { disk: table.disk, dump: table.dump, size: diskNode.size };
  });
  const bootTable = tables.find((table) => table.size === EXPECTED_BOOT_BYTES);
  const rootTable = tables.find((table) => table.size === EXPECTED_ROOT_BYTES);
  if (!bootTable || !rootTable || bootTable.disk === rootTable.disk) {
    fail("metadata:partitions-size");
  }
  const bootDump = rewriteSfdiskDump(
    bootTable.dump,
    bootTable.disk,
    target.bootDiskPath,
  );
  const rootDump = rewriteSfdiskDump(
    rootTable.dump,
    rootTable.disk,
    target.rootDiskPath,
  );
  const bootPart3 = `${target.bootDiskPath}-part3`;
  const lvm = validateLvmText(metadata, blocks);
  const lvmText = replacePathToken(
    lvm.text,
    /device = "([^"]+)"/.exec(lvm.text)![1],
    bootPart3,
  );
  if (lvmText.includes(bootTable.disk) || lvmText.includes(rootTable.disk)) {
    fail("metadata:lvm-source-leak");
  }
  const root = sources.get("root")!;
  const efi = sources.get("efi")!;
  const stagingBoot = sources.get("staging-boot")!;
  const stagingEfi = sources.get("staging-efi")!;
  const oracleRoot = sources.get("oracle-root")!;
  const oracleOled = sources.get("oracle-oled")!;
  const filesystems: LayoutFilesystem[] = [
    {
      role: "root",
      filesystem: root.filesystem,
      uuid: root.uuid,
      size: root.size,
      device: `${target.rootDiskPath}-part2`,
    },
    {
      role: "efi",
      filesystem: efi.filesystem,
      uuid: efi.uuid,
      size: efi.size,
      device: `${target.rootDiskPath}-part1`,
    },
    {
      role: "staging-boot",
      filesystem: stagingBoot.filesystem,
      uuid: stagingBoot.uuid,
      size: stagingBoot.size,
      device: `${target.bootDiskPath}-part2`,
    },
    {
      role: "staging-efi",
      filesystem: stagingEfi.filesystem,
      uuid: stagingEfi.uuid,
      size: stagingEfi.size,
      device: `${target.bootDiskPath}-part1`,
    },
    {
      role: "oracle-root",
      filesystem: oracleRoot.filesystem,
      uuid: oracleRoot.uuid,
      size: oracleRoot.size,
      device: `/dev/mapper/${lvm.volumeGroup}-root`,
    },
    {
      role: "oracle-oled",
      filesystem: oracleOled.filesystem,
      uuid: oracleOled.uuid,
      size: oracleOled.size,
      device: `/dev/mapper/${lvm.volumeGroup}-oled`,
    },
  ];
  for (const fs of filesystems) {
    if (
      !UUID_PATTERN.test(fs.uuid) || !Number.isSafeInteger(fs.size) ||
      fs.size <= 0
    ) {
      fail("metadata:filesystem");
    }
  }
  const swap = metadata.swapRecreation;
  if (
    !isRecord(swap) || swap.present !== true || swap.path !== "/.swapfile" ||
    swap.bytes !== 4294967296 || !Number.isSafeInteger(swap.mode) ||
    !Number.isSafeInteger(swap.uid) || !Number.isSafeInteger(swap.gid)
  ) fail("metadata:swap");
  return {
    bootDisk: {
      originalPath: bootTable.disk,
      targetPath: target.bootDiskPath,
      dump: bootDump,
      partitions: {
        efi: `${target.bootDiskPath}-part1`,
        stagingBoot: `${target.bootDiskPath}-part2`,
        lvm: bootPart3,
      },
    },
    rootDisk: {
      originalPath: rootTable.disk,
      targetPath: target.rootDiskPath,
      dump: rootDump,
      partitions: {
        efi: `${target.rootDiskPath}-part1`,
        root: `${target.rootDiskPath}-part2`,
      },
    },
    filesystems,
    volumeGroup: lvm.volumeGroup,
    pvUuid: lvm.pvUuid,
    lvmText,
    swap: swap as MachineRecoveryMetadata["swapRecreation"],
  };
}

function archiveMap(
  index: RecoveryIndex,
  metadata: MachineRecoveryMetadata,
  archives: readonly DecryptedRestoreArchive[],
): Map<RestoreArchiveRole, DecryptedRestoreArchive> {
  if (!Array.isArray(archives) || archives.length !== 6) fail("archives:shape");
  const metadataByRole = new Map<RestoreArchiveRole, MachineMetadataArchive>();
  for (const item of metadata.archives) {
    if (
      !isRecord(item) ||
      !EXPECTED_ARCHIVE_ROLES.includes(item.role as RestoreArchiveRole)
    ) {
      fail("metadata:archives");
    }
    metadataByRole.set(
      item.role as RestoreArchiveRole,
      item as MachineMetadataArchive,
    );
  }
  if (metadataByRole.size !== 6) fail("metadata:archives");
  const indexByRole = new Map<RestoreArchiveRole, IndexArchiveRecord>();
  for (const item of index.archives) {
    if (item.role !== "recovery") indexByRole.set(item.role, item);
  }
  const out = new Map<RestoreArchiveRole, DecryptedRestoreArchive>();
  for (const archive of archives) {
    if (
      !isRecord(archive) ||
      !EXPECTED_ARCHIVE_ROLES.includes(archive.role as RestoreArchiveRole)
    ) {
      fail("archives:shape");
    }
    const role = archive.role as RestoreArchiveRole;
    if (out.has(role)) fail("archives:shape");
    if (archive.path !== undefined) {
      assertAbsolutePath(archive.path, "archives:path");
      if (!archive.path.endsWith(".tar.zst")) fail("archives:format");
    }
    const expected = indexByRole.get(role);
    const metadataArchive = metadataByRole.get(role);
    if (!expected || !metadataArchive) fail("archives:binding");
    const plaintextBytes = archive.bytes;
    const plaintextSha256 = archive.sha256;
    const ciphertextBytes = archive.ciphertextBytes;
    const ciphertextSha256 = archive.ciphertextSha256;
    if (
      typeof ciphertextBytes !== "number" ||
      !Number.isSafeInteger(ciphertextBytes) ||
      ciphertextBytes !== expected.bytes ||
      ciphertextBytes !== metadataArchive.bytes ||
      ciphertextSha256 !== expected.sha256 ||
      ciphertextSha256 !== metadataArchive.sha256 ||
      typeof ciphertextSha256 !== "string" ||
      !SHA256_ANY_PATTERN.test(ciphertextSha256) ||
      typeof plaintextBytes !== "number" ||
      !Number.isSafeInteger(plaintextBytes) || plaintextBytes <= 0 ||
      typeof plaintextSha256 !== "string" ||
      !SHA256_ANY_PATTERN.test(plaintextSha256)
    ) fail("archives:binding");
    out.set(role, {
      role,
      path: archive.path,
      bytes: plaintextBytes,
      sha256: plaintextSha256.toLowerCase(),
      ciphertextBytes,
      ciphertextSha256: ciphertextSha256.toLowerCase(),
      ...(archive.verifierChecked === true
        ? { verifierChecked: true as const }
        : {}),
    });
  }
  if (out.size !== EXPECTED_ARCHIVE_ROLES.length) fail("archives:shape");
  return out;
}

function flattenNodes(nodes: readonly MachineBlockNode[]): MachineBlockNode[] {
  const out: MachineBlockNode[] = [];
  const visit = (entries: readonly MachineBlockNode[]): void => {
    for (const node of entries) {
      out.push(node);
      if (Array.isArray(node.children)) visit(node.children);
    }
  };
  visit(nodes);
  return out;
}

function mountpointValues(node: MachineBlockNode): string[] {
  return (node.mountpoints ?? []).filter((value): value is string =>
    typeof value === "string" && value.length > 0
  );
}

function parseJson(stdout: string, label: string): ParsedJson {
  try {
    const value: unknown = JSON.parse(stdout);
    if (!isRecord(value)) fail(label);
    return value;
  } catch {
    fail(label);
  }
}

function collectMountEntries(
  value: unknown,
  out: MachineMountEntry[] = [],
): MachineMountEntry[] {
  if (Array.isArray(value)) {
    for (const item of value) collectMountEntries(item, out);
  } else if (isRecord(value)) {
    if (typeof value.target === "string" && typeof value.source === "string") {
      out.push({
        target: value.target,
        source: value.source,
        uuid: typeof value.uuid === "string" ? value.uuid : undefined,
        fstype: typeof value.fstype === "string" ? value.fstype : undefined,
      });
    }
    for (const item of Object.values(value)) {
      collectMountEntries(item, out);
    }
  }
  return out;
}

/** Keep target mount evidence separate from the rescue guest's own mounts. */
export function scopeTargetMountEntries(
  entries: readonly MachineMountEntry[],
  workDirectory: string,
): MachineMountEntry[] {
  const prefix = `${workDirectory}/mounts/`;
  return entries.filter((entry) => entry.target.startsWith(prefix));
}

async function checked(
  runner: CommandRunner,
  command: string,
  args: string[],
  label: string,
): Promise<{ stdout: string; stderr: string }> {
  let result;
  try {
    result = await runner(command, args);
  } catch {
    fail(`${label}:invoke`);
  }
  if (result.code !== 0) fail(`${label}:exit`);
  return { stdout: result.stdout, stderr: result.stderr };
}

async function snapshot(
  runner: CommandRunner,
  metadata: MachineRecoveryMetadata,
  target: MachineRestoreTarget,
  allowMounted: boolean,
): Promise<TargetSnapshot> {
  const listing = await checked(
    runner,
    "lsblk",
    [
      "--json",
      "--bytes",
      "--output",
      "NAME,PATH,SIZE,TYPE,FSTYPE,UUID,MOUNTPOINTS,SERIAL,PARTN,PKNAME",
    ],
    "target:lsblk",
  );
  const json = parseJson(listing.stdout, "target:lsblk-json");
  const rawNodes = json.blockdevices;
  if (!Array.isArray(rawNodes)) fail("target:lsblk-shape");
  const nodes = rawNodes.filter(isRecord) as MachineBlockNode[];
  const flat = flattenNodes(nodes);
  // Alpine's lsblk can omit SCSI serials. Read the device's actual page-80
  // serial from udev, rather than its shorter page-83 device identifier.
  for (const node of flat) {
    if (node.type !== "disk" || typeof node.path !== "string") continue;
    if (!/^\/dev\/sd[a-z]+$/.test(node.path)) continue;
    const properties = await checked(
      runner,
      "udevadm",
      ["info", "--query=property", "--name=" + node.path],
      "target:scsi-serial",
    );
    const serials = properties.stdout.split("\n")
      .filter((line) => line.startsWith("ID_SCSI_SERIAL="));
    if (serials.length !== 1) fail("target:scsi-serial");
    node.serial = serials[0].slice("ID_SCSI_SERIAL=".length);
  }
  const serialNodes = flat.filter((node): node is TargetNode =>
    typeof node.serial === "string" && typeof node.path === "string" &&
    typeof node.size === "number" && typeof node.type === "string"
  );
  const boots = serialNodes.filter((node) =>
    node.serial === target.bootDiskSerial && node.type === "disk"
  );
  const roots = serialNodes.filter((node) =>
    node.serial === target.rootDiskSerial && node.type === "disk"
  );
  if (boots.length !== 1 || roots.length !== 1) fail("target:serial");
  const [boot] = boots;
  const [root] = roots;
  if (boot.size !== EXPECTED_BOOT_BYTES || root.size !== EXPECTED_ROOT_BYTES) {
    fail("target:capacity");
  }
  if (
    boot.path === root.path || boot.path === undefined ||
    root.path === undefined
  ) fail("target:identity");
  for (
    const [configuredPath, selected] of [[
      target.bootDiskPath,
      boot,
    ], [target.rootDiskPath, root]] as const
  ) {
    const resolved = (await checked(
      runner,
      "readlink",
      ["-f", configuredPath],
      "target:resolve",
    )).stdout.trim();
    if (
      resolved.length === 0 ||
      (selected.path !== resolved && selected.path !== configuredPath)
    ) {
      fail("target:path-binding");
    }
  }
  const metadataUuids = new Set(
    metadata.sources.map((source) => source.uuid.toLowerCase()),
  );
  const targetNodes = new Set<MachineBlockNode>([
    boot,
    root,
    ...flattenNodes(boot.children ?? []),
    ...flattenNodes(root.children ?? []),
  ]);
  for (const node of flat) {
    if (
      typeof node.uuid === "string" &&
      metadataUuids.has(node.uuid.toLowerCase())
    ) {
      if (!targetNodes.has(node)) fail("target:source-present");
    }
  }
  for (const node of targetNodes) {
    if (
      mountpointValues(node).some((path) =>
        !path.startsWith(`${target.workDirectory}/mounts/`)
      )
    ) {
      fail("target:mounted-outside-restore");
    }
  }
  for (const disk of [boot, root]) {
    if (!allowMounted && mountpointValues(disk).length > 0) {
      fail("target:mounted");
    }
    if (!allowMounted && (disk.children ?? []).length > 0) {
      // A journal-free run must start with two empty whole disks.
      fail("target:not-empty");
    }
    if (!allowMounted) {
      for (const child of flattenNodes(disk.children ?? [])) {
        if (mountpointValues(child).length > 0) fail("target:mounted");
      }
    }
  }
  const findmnt = await checked(
    runner,
    "findmnt",
    ["--json", "--output", "TARGET,SOURCE,FSTYPE,UUID"],
    "target:findmnt",
  );
  const mountJson = parseJson(findmnt.stdout, "target:findmnt-json");
  const mountEntries = collectMountEntries(mountJson);
  const mountedEntries = scopeTargetMountEntries(
    mountEntries,
    target.workDirectory,
  );
  const mountedSources = mountedEntries.map((entry) => entry.source);
  const foreignEntries = mountEntries.filter((entry) =>
    !mountedEntries.includes(entry)
  );
  for (const { source } of foreignEntries) {
    if (
      (!allowMounted && metadataUuids.has(source.toLowerCase())) ||
      (!allowMounted &&
        (source.includes(target.bootDiskPath) ||
          source.includes(target.rootDiskPath)))
    ) {
      fail("target:mounted-source");
    }
  }
  if (!allowMounted && mountedEntries.length > 0) fail("target:mounted-source");
  return {
    nodes: flat,
    boot,
    root,
    mountedSources,
    mountedTargets: mountedEntries.map((entry) => entry.target),
    mountedEntries,
  };
}

async function assertPristineTarget(
  runner: CommandRunner,
  target: MachineRestoreTarget,
  snapshotValue: TargetSnapshot,
): Promise<void> {
  for (const disk of [snapshotValue.boot, snapshotValue.root]) {
    if ((disk.children ?? []).length > 0) fail("target:not-empty");
    if (
      (typeof disk.fstype === "string" && disk.fstype.length > 0) ||
      (typeof disk.uuid === "string" && disk.uuid.length > 0)
    ) {
      fail("target:signature");
    }
  }
  for (const diskPath of [target.bootDiskPath, target.rootDiskPath]) {
    const result = await checked(
      runner,
      "wipefs",
      ["--noheadings", "--output", "TYPE", diskPath],
      "target:wipefs",
    );
    if (result.stdout.trim().length > 0) fail("target:signature");
  }
}

function hasPartition(node: TargetNode, part: number): boolean {
  return (node.children ?? []).some((child) =>
    child.type === "part" &&
    ((child as Record<string, unknown>).partn === part ||
      child.name?.endsWith(String(part)))
  );
}

function assertPartitionShape(
  s: TargetSnapshot,
  requireFilesystems: boolean,
  requireLvm = true,
): void {
  if (
    !hasPartition(s.boot, 1) || !hasPartition(s.boot, 2) ||
    !hasPartition(s.boot, 3)
  ) fail("target:partitions");
  if (!hasPartition(s.root, 1) || !hasPartition(s.root, 2)) {
    fail("target:partitions");
  }
  if (!requireFilesystems) return;
  const fsByUuid = new Set(
    flattenNodes([s.boot, s.root]).map((node) => node.fstype).filter((
      value,
    ): value is string => typeof value === "string"),
  );
  if (
    !["vfat", "xfs", "ext4", ...(requireLvm ? ["LVM2_member"] : [])].every((
      value,
    ) => fsByUuid.has(value))
  ) {
    fail("target:filesystems");
  }
}

async function assertWorkDirectory(path: string): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch {
    fail("work-directory:missing");
  }
  if (
    info.isSymlink || !info.isDirectory || info.mode === null ||
    (info.mode & 0o777) !== 0o700
  ) {
    fail("work-directory:unsafe");
  }
  try {
    if (await Deno.realPath(path) !== path) fail("work-directory:realpath");
  } catch {
    fail("work-directory:realpath");
  }
}

async function readFileSha256(
  path: string,
): Promise<{ bytes: number; sha256: string }> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch {
    fail("archive:missing");
  }
  if (info.isSymlink || !info.isFile || info.size <= 0) {
    fail("archive:identity");
  }
  const file = await Deno.open(path, { read: true });
  const hash = createHash("sha256");
  let bytes = 0;
  const buffer = new Uint8Array(1024 * 1024);
  try {
    while (true) {
      const count = await file.read(buffer);
      if (count === null) break;
      if (count <= 0) fail("archive:read");
      bytes += count;
      if (!Number.isSafeInteger(bytes)) fail("archive:size");
      hash.update(buffer.subarray(0, count));
    }
  } finally {
    file.close();
  }
  return { bytes, sha256: hash.digest("hex") };
}

async function writeOwnedText(path: string, text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = sha256Hex(bytes);
  try {
    const existing = await Deno.readTextFile(path);
    if (existing !== text) fail("work-file:conflict");
    const info = await Deno.lstat(path);
    if (
      info.isSymlink || !info.isFile || info.mode === null ||
      (info.mode & 0o777) !== 0o600
    ) fail("work-file:identity");
    return digest;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
  }
  const file = await Deno.open(path, {
    write: true,
    createNew: true,
    mode: 0o600,
  });
  try {
    let offset = 0;
    while (offset < bytes.length) {
      offset += await file.write(bytes.subarray(offset));
    }
    await file.sync();
  } finally {
    file.close();
  }
  return digest;
}

async function saveJournal(
  path: string,
  journal: RestoreJournal,
): Promise<void> {
  const bytes = new TextEncoder().encode(
    `${JSON.stringify(journal, null, 2)}\n`,
  );
  if (bytes.byteLength > MAX_JOURNAL_BYTES) fail("journal:size");
  const parent = path.slice(0, path.lastIndexOf("/"));
  const temporary = `${path}.${crypto.randomUUID()}.partial`;
  let file: Deno.FsFile | undefined;
  try {
    file = await Deno.open(temporary, {
      write: true,
      createNew: true,
      mode: 0o600,
    });
    let offset = 0;
    while (offset < bytes.length) {
      offset += await file.write(bytes.subarray(offset));
    }
    await file.sync();
    file.close();
    file = undefined;
    await Deno.rename(temporary, path);
    using directory = await Deno.open(parent, { read: true });
    await directory.sync();
  } catch {
    try {
      file?.close();
    } catch {
      // Preserve the bounded journal error.
    }
    try {
      await Deno.remove(temporary);
    } catch {
      // Only the task-owned temporary path is eligible for cleanup.
    }
    fail("journal:write");
  }
}

async function loadJournal(path: string): Promise<RestoreJournal | null> {
  let text: string;
  try {
    text = await Deno.readTextFile(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return null;
    fail("journal:read");
  }
  if (text.length > MAX_JOURNAL_BYTES) fail("journal:size");
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    fail("journal:json");
  }
  if (
    !isRecord(value) || value.schemaVersion !== 2 ||
    !Array.isArray(value.completedStages)
  ) fail("journal:shape");
  const stages = value.completedStages;
  for (let i = 0; i < stages.length; i += 1) {
    if (stages[i] !== STAGES[i]) fail("journal:stages");
  }
  if (stages.length === 0) fail("journal:stages");
  const journal = value as unknown as RestoreJournal;
  if (
    typeof journal.targetId !== "string" ||
    !SAFE_NAME_PATTERN.test(journal.targetId) ||
    journal.architecture !== "aarch64" ||
    !TARGET_PATH_PATTERN.test(journal.bootDiskPath) ||
    !TARGET_PATH_PATTERN.test(journal.rootDiskPath) ||
    journal.bootDiskBytes !== EXPECTED_BOOT_BYTES ||
    journal.rootDiskBytes !== EXPECTED_ROOT_BYTES ||
    typeof journal.generation !== "string" ||
    !SHA256_PATTERN.test(journal.indexSha256) ||
    !Array.isArray(journal.archives) || journal.archives.length !== 6 ||
    !SHA256_PATTERN.test(journal.lvmTextSha256) ||
    !SHA256_PATTERN.test(journal.partitionDumpSha256.boot) ||
    !SHA256_PATTERN.test(journal.partitionDumpSha256.root)
  ) fail("journal:binding");
  if (
    !isRecord(journal.approval) ||
    journal.approval.targetId !== journal.targetId ||
    typeof journal.approval.bootDiskPath !== "string" ||
    typeof journal.approval.rootDiskPath !== "string" ||
    typeof journal.approval.approvedAtUtc !== "string"
  ) fail("journal:binding");
  return journal;
}

function newJournal(
  input: MachineRestoreInput,
  archiveMapValue: Map<RestoreArchiveRole, DecryptedRestoreArchive>,
  layout: RestoreLayout,
  indexSha256: string,
): RestoreJournal {
  return {
    schemaVersion: 2,
    targetId: input.target.targetId,
    bootDiskSerial: input.target.bootDiskSerial,
    rootDiskSerial: input.target.rootDiskSerial,
    architecture: "aarch64",
    bootDiskPath: input.target.bootDiskPath,
    rootDiskPath: input.target.rootDiskPath,
    bootDiskBytes: EXPECTED_BOOT_BYTES,
    rootDiskBytes: EXPECTED_ROOT_BYTES,
    approval: { ...input.target.approval },
    generation: input.index.generation,
    indexSha256,
    startedAtUtc: new Date().toISOString(),
    updatedAtUtc: new Date().toISOString(),
    completedStages: ["preflight-verified"],
    lvmTextSha256: sha256Hex(new TextEncoder().encode(layout.lvmText)),
    partitionDumpSha256: {
      boot: sha256Hex(new TextEncoder().encode(layout.bootDisk.dump)),
      root: sha256Hex(new TextEncoder().encode(layout.rootDisk.dump)),
    },
    archives: EXPECTED_ARCHIVE_ROLES.map((role) => {
      const archive = archiveMapValue.get(role)!;
      return {
        role,
        bytes: archive.bytes,
        sha256: archive.sha256,
        ciphertextBytes: archive.ciphertextBytes,
        ciphertextSha256: archive.ciphertextSha256,
      };
    }),
  };
}

function journalHas(journal: RestoreJournal, stage: RestoreStage): boolean {
  return journal.completedStages.includes(stage);
}

async function markStage(
  path: string,
  journal: RestoreJournal,
  stage: RestoreStage,
  checkpoint?: RestoreCheckpoint,
): Promise<void> {
  const expectedIndex = journal.completedStages.length;
  if (STAGES[expectedIndex] !== stage) fail("journal:transition");
  journal.completedStages.push(stage);
  journal.updatedAtUtc = new Date().toISOString();
  await saveJournal(path, journal);
  await checkpoint?.(structuredClone(journal));
}

function expectedMounts(
  workDirectory: string,
): Record<RestoreArchiveRole, string> {
  return {
    root: `${workDirectory}/mounts/root`,
    efi: `${workDirectory}/mounts/root/efi`,
    "staging-boot": `${workDirectory}/mounts/staging-boot`,
    "staging-efi": `${workDirectory}/mounts/staging-boot/efi`,
    "oracle-root": `${workDirectory}/mounts/oracle-root`,
    "oracle-oled": `${workDirectory}/mounts/oracle-oled`,
  };
}

async function ensureMountDirectories(
  workDirectory: string,
): Promise<Record<RestoreArchiveRole, string>> {
  const mounts = expectedMounts(workDirectory);
  const directories = new Set(Object.values(mounts));
  for (const directory of directories) {
    await Deno.mkdir(directory, { recursive: true, mode: 0o700 });
  }
  return mounts;
}

function tarExtractionArgs(archivePath: string, mountPath: string): string[] {
  return [
    "--extract",
    "--file",
    archivePath,
    "--directory",
    mountPath,
    "--use-compress-program=zstd",
    "--numeric-owner",
    "--same-owner",
    "--same-permissions",
    "--acls",
    "--xattrs",
    "--xattrs-include=*",
    "--sparse",
    "--keep-directory-symlink",
  ];
}

/** Sources and node paths must first be canonicalized by the live caller. */
export function validateRestoreMountBindings(
  entries: readonly MachineMountEntry[],
  sources: readonly MachineSourceRecord[],
  nodes: readonly MachineBlockNode[],
  workDirectory: string,
): void {
  const mounts = expectedMounts(workDirectory);
  if (entries.length !== sources.length) fail("mount:unexpected-count");
  for (const source of sources) {
    const matches = entries.filter((entry) =>
      entry.target === mounts[source.name]
    );
    const devices = nodes.filter((node) =>
      node.uuid?.toLowerCase() === source.uuid.toLowerCase()
    );
    if (
      matches.length !== 1 || devices.length !== 1 ||
      matches[0].uuid?.toLowerCase() !== source.uuid.toLowerCase() ||
      matches[0].fstype !== source.filesystem ||
      devices[0].fstype !== source.filesystem ||
      !devices[0].path || matches[0].source !== devices[0].path
    ) fail("mount:filesystem-binding");
  }
}

async function assertMountedFilesystems(
  current: TargetSnapshot,
  metadata: MachineRecoveryMetadata,
  workDirectory: string,
): Promise<void> {
  const nodes = flattenNodes([current.boot, current.root]);
  const canonicalNodes = await Promise.all(
    nodes.map(async (node) => ({
      ...node,
      path: node.path ? await Deno.realPath(node.path) : undefined,
    })),
  );
  const entries = await Promise.all(
    current.mountedEntries.map(async (entry) => ({
      ...entry,
      source: await Deno.realPath(entry.source),
    })),
  );
  validateRestoreMountBindings(
    entries,
    metadata.sources,
    canonicalNodes,
    workDirectory,
  );
}

/** Exported pure command mapping for focused tests and the primary runbook. */
export function restoreTarArgs(
  archivePath: string,
  mountPath: string,
): readonly string[] {
  if (archivePath !== "-") assertAbsolutePath(archivePath, "archive:path");
  assertAbsolutePath(mountPath, "archive:mount");
  return tarExtractionArgs(archivePath, mountPath);
}

async function runSfdisk(
  runner: CommandRunner,
  targetPath: string,
  dumpPath: string,
  label: string,
): Promise<void> {
  // CommandRunner has no stdin channel.  Positional parameters keep both
  // paths data-only while bash supplies the dump on sfdisk stdin.
  await checked(
    runner,
    "bash",
    [
      "-o",
      "pipefail",
      "-c",
      'sfdisk --no-reread --force -- "$1" < "$2"',
      "machine-restore",
      targetPath,
      dumpPath,
    ],
    label,
  );
}

async function guardBeforeWrite(
  runner: CommandRunner,
  metadata: MachineRecoveryMetadata,
  target: MachineRestoreTarget,
  label: string,
): Promise<TargetSnapshot> {
  return await snapshot(runner, metadata, target, true).then((current) => {
    if (
      current.boot.serial !== target.bootDiskSerial ||
      current.root.serial !== target.rootDiskSerial
    ) fail(`${label}:identity`);
    if (
      current.boot.size !== EXPECTED_BOOT_BYTES ||
      current.root.size !== EXPECTED_ROOT_BYTES
    ) fail(`${label}:capacity`);
    return current;
  });
}

async function formatFilesystem(
  runner: CommandRunner,
  metadata: MachineRecoveryMetadata,
  target: MachineRestoreTarget,
  fs: LayoutFilesystem,
): Promise<void> {
  await guardBeforeWrite(runner, metadata, target, `format:${fs.role}`);
  if (fs.filesystem === "ext4") {
    await checked(
      runner,
      "mkfs.ext4",
      ["-F", "-U", fs.uuid, fs.device],
      `format:${fs.role}`,
    );
  } else if (fs.filesystem === "xfs") {
    await checked(runner, "mkfs.xfs", [
      "-f",
      "-m",
      // Keep the retained GRUB 2.06 and Oracle fallback kernel able to read
      // these filesystems; current mkfs.xfs enables incompatible features.
      `uuid=${fs.uuid},crc=1,finobt=1,rmapbt=0,reflink=1,bigtime=0,inobtcount=0,metadir=0`,
      "-i",
      "nrext64=0,exchange=0",
      "-n",
      "parent=0",
      fs.device,
    ], `format:${fs.role}`);
  } else {
    const fatId = fs.uuid.replaceAll("-", "");
    if (!/^[0-9A-Fa-f]{8}$/.test(fatId)) fail(`format:${fs.role}:uuid`);
    await checked(runner, "mkfs.vfat", [
      "-F",
      "32",
      "-i",
      fatId.toUpperCase(),
      fs.device,
    ], `format:${fs.role}`);
  }
}

async function recreateSwap(
  runner: CommandRunner,
  metadata: MachineRecoveryMetadata,
  target: MachineRestoreTarget,
  rootMount: string,
  swap: RestoreLayout["swap"],
): Promise<void> {
  const path = `${rootMount}${swap.path}`;
  const current = await guardBeforeWrite(runner, metadata, target, "swap");
  await assertMountedFilesystems(current, metadata, target.workDirectory);
  try {
    const existing = await Deno.lstat(path);
    if (
      !existing.isFile || existing.isSymlink || existing.size !== swap.bytes ||
      existing.mode === null || (existing.mode & 0o777) !== swap.mode ||
      existing.uid !== swap.uid || existing.gid !== swap.gid
    ) {
      fail("swap:conflict");
    }
    const signature = await runner("blkid", [
      "-p",
      "-s",
      "TYPE",
      "-o",
      "value",
      path,
    ]);
    if (signature.code === 0 && signature.stdout.trim() === "swap") return;
    if (signature.code !== 2 || signature.stdout.trim()) fail("swap:signature");
    // A journal-bound, correctly owned allocation may have stopped before mkswap.
    await checked(
      runner,
      "mkswap",
      ["-U", "random", path],
      "swap:resume-mkswap",
    );
    const verified = await checked(runner, "blkid", [
      "-p",
      "-s",
      "TYPE",
      "-o",
      "value",
      path,
    ], "swap:verify");
    if (verified.stdout.trim() !== "swap") fail("swap:signature");
    return;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
    if (!(error instanceof Deno.errors.NotFound)) fail("swap:inspect");
  }
  await guardBeforeWrite(runner, metadata, target, "swap");
  await checked(
    runner,
    "fallocate",
    ["-l", String(swap.bytes), path],
    "swap:fallocate",
  );
  await checked(runner, "chmod", ["0600", path], "swap:chmod");
  await checked(
    runner,
    "chown",
    [`${swap.uid}:${swap.gid}`, path],
    "swap:chown",
  );
  await checked(runner, "mkswap", ["-U", "random", path], "swap:mkswap");
  const verified = await checked(runner, "blkid", [
    "-p",
    "-s",
    "TYPE",
    "-o",
    "value",
    path,
  ], "swap:verify");
  if (verified.stdout.trim() !== "swap") fail("swap:signature");
}

async function mountOne(
  runner: CommandRunner,
  metadata: MachineRecoveryMetadata,
  target: MachineRestoreTarget,
  device: string,
  mountPath: string,
  label: string,
): Promise<void> {
  await guardBeforeWrite(runner, metadata, target, label);
  // Parent mounts can hide directories created on the rescue filesystem.
  await Deno.mkdir(mountPath, { recursive: true, mode: 0o700 });
  await checked(runner, "mount", [device, mountPath], label);
}

async function unmountAll(
  runner: CommandRunner,
  mounts: Record<RestoreArchiveRole, string>,
): Promise<void> {
  const order = [
    mounts["oracle-oled"],
    mounts["oracle-root"],
    mounts["staging-efi"],
    mounts["staging-boot"],
    mounts.efi,
    mounts.root,
  ];
  for (const mountPath of order) {
    await checked(runner, "umount", [mountPath], "mount:release");
  }
}

async function extractArchives(
  runner: CommandRunner,
  metadata: MachineRecoveryMetadata,
  target: MachineRestoreTarget,
  archives: Map<RestoreArchiveRole, DecryptedRestoreArchive>,
  mounts: Record<RestoreArchiveRole, string>,
  streamArchive?: MachineArchiveExtractor,
): Promise<void> {
  for (const role of EXPECTED_ARCHIVE_ROLES) {
    const archive = archives.get(role)!;
    if (!streamArchive) {
      const result = await readFileSha256(archive.path!);
      if (result.bytes !== archive.bytes || result.sha256 !== archive.sha256) {
        fail(`archive:${role}:hash`);
      }
    }
    const current = await guardBeforeWrite(
      runner,
      metadata,
      target,
      `extract:${role}`,
    );
    await assertMountedFilesystems(current, metadata, target.workDirectory);
    if (streamArchive) {
      await streamArchive(archive, mounts[role]);
    } else {await checked(
        runner,
        "tar",
        tarExtractionArgs(archive.path!, mounts[role]),
        `extract:${role}`,
      );}
  }
  // These volatile trees are excluded from capture, including their parent
  // directories. Recreate mount points before the restored system boots.
  const current = await guardBeforeWrite(
    runner,
    metadata,
    target,
    "extract:runtime-directories",
  );
  await assertMountedFilesystems(current, metadata, target.workDirectory);
  await checked(runner, "mkdir", [
    "-p",
    ...["dev", "proc", "sys", "run", "tmp", "mnt", "var/tmp"].map((path) =>
      `${mounts.root}/${path}`
    ),
  ], "extract:runtime-directories");
  await checked(runner, "chmod", [
    "1777",
    `${mounts.root}/tmp`,
    `${mounts.root}/var/tmp`,
  ], "extract:temporary-permissions");
}

function assertResumeBinding(
  journal: RestoreJournal,
  input: MachineRestoreInput,
  archives: Map<RestoreArchiveRole, DecryptedRestoreArchive>,
  layout: RestoreLayout,
  indexSha256: string,
): void {
  if (
    journal.generation !== input.index.generation ||
    journal.indexSha256 !== indexSha256 ||
    journal.targetId !== input.target.targetId ||
    journal.bootDiskSerial !== input.target.bootDiskSerial ||
    journal.rootDiskSerial !== input.target.rootDiskSerial ||
    journal.approval.bootDiskSerial !== input.target.bootDiskSerial ||
    journal.approval.rootDiskSerial !== input.target.rootDiskSerial ||
    journal.bootDiskPath !== input.target.bootDiskPath ||
    journal.rootDiskPath !== input.target.rootDiskPath ||
    journal.approval.bootDiskPath !== input.target.bootDiskPath ||
    journal.approval.rootDiskPath !== input.target.rootDiskPath ||
    journal.approval.approvedAtUtc !== input.target.approval.approvedAtUtc
  ) fail("journal:binding");
  if (
    journal.lvmTextSha256 !==
      sha256Hex(new TextEncoder().encode(layout.lvmText)) ||
    journal.partitionDumpSha256.boot !==
      sha256Hex(new TextEncoder().encode(layout.bootDisk.dump)) ||
    journal.partitionDumpSha256.root !==
      sha256Hex(new TextEncoder().encode(layout.rootDisk.dump))
  ) fail("journal:binding");
  if (journal.archives.length !== 6) fail("journal:archives");
  for (const item of journal.archives) {
    const archive = archives.get(item.role);
    if (
      !archive || archive.bytes !== item.bytes ||
      archive.sha256 !== item.sha256 ||
      archive.ciphertextBytes !== item.ciphertextBytes ||
      archive.ciphertextSha256 !== item.ciphertextSha256
    ) fail("journal:archives");
  }
}

async function verifyJournalStage(
  stage: RestoreStage,
  runner: CommandRunner,
  metadata: MachineRecoveryMetadata,
  target: MachineRestoreTarget,
): Promise<void> {
  const current = await snapshot(
    runner,
    metadata,
    target,
    stage !== "preflight-verified",
  );
  if (stage === "preflight-verified") {
    if (
      (current.boot.children ?? []).length > 0 ||
      (current.root.children ?? []).length > 0
    ) fail("journal:unknown-partial");
  } else if (stage === "partition-tables-written") {
    assertPartitionShape(current, false);
  } else if (
    stage === "filesystems-created" || stage === "lvm-restored" ||
    stage === "filesystem-rebuilt"
  ) {
    assertPartitionShape(current, true, stage !== "filesystems-created");
    if (current.mountedSources.length > 0) fail("journal:mounted-partial");
  } else {
    // A mounted stage is resumable only while all of the expected target
    // mountpoints are still visible; a half-mounted or vanished target is
    // deliberately treated as unknown partial state.
    await assertMountedFilesystems(current, metadata, target.workDirectory);
  }
}

function assertMachineMetadataInput(metadata: MachineRecoveryMetadata): void {
  if (!isRecord(metadata)) fail("metadata:shape");
  if (metadata.schemaVersion !== 1 || typeof metadata.generation !== "string") {
    fail("metadata:shape");
  }
  if (
    !isRecord(metadata.recipient) ||
    typeof metadata.recipient.fingerprint !== "string" ||
    typeof metadata.recipient.publicSha256 !== "string"
  ) fail("metadata:recipient");
  if (
    !isRecord(metadata.finalChecks) ||
    metadata.finalChecks.pacmanLockAbsent !== true ||
    metadata.finalChecks.packagesUnchanged !== true ||
    metadata.finalChecks.bootHashesUnchanged !== true
  ) fail("metadata:guards");
  if (
    !isRecord(metadata.bootHashes) ||
    typeof metadata.bootHashes.root !== "string" ||
    typeof metadata.bootHashes.stagingBoot !== "string"
  ) fail("metadata:boot");
  if (
    typeof metadata.fstab !== "string" ||
    typeof metadata.procCmdline !== "string"
  ) fail("metadata:boot-config");
}

/**
 * Rebuild one accepted generation on the explicit target. All destructive
 * commands are preceded by a fresh target identity/mount/source guard. A
 * journal-free non-empty target, or a journal whose disk state does not match
 * its last completed stage, fails before the next write.
 */
/** The extractor must verify ciphertext, plaintext and pipeline completion. */
export type MachineArchiveExtractor = (
  archive: DecryptedRestoreArchive,
  mountPath: string,
) => Promise<void>;

/** Await durable off-target storage before proceeding to the next stage. */
export type RestoreCheckpoint = (journal: RestoreJournal) => Promise<void>;

export async function restoreMachine(
  input: MachineRestoreInput,
  runner: CommandRunner = defaultRunner,
  streamArchive?: MachineArchiveExtractor,
  checkpoint?: RestoreCheckpoint,
): Promise<MachineRestoreResult> {
  assertTargetShape(input.target);
  assertMachineMetadataInput(input.metadata);
  const index = validateRecoveryIndex(input.index);
  const indexSha256 = machineRestoreIndexSha256(index);
  if (
    !SHA256_PATTERN.test(input.indexSha256) || input.indexSha256 !== indexSha256
  ) fail("index:binding");
  if (input.metadata.generation !== index.generation) {
    fail("metadata:generation");
  }
  const archives = archiveMap(index, input.metadata, input.archives);
  if (
    !streamArchive && [...archives.values()].some((archive) => !archive.path)
  ) {
    fail("archives:extractor-required");
  }
  const layout = buildRestoreLayout(index, input.metadata, input.target);
  await assertWorkDirectory(input.target.workDirectory);
  const journalPath = `${input.target.workDirectory}/${JOURNAL_NAME}`;
  const mounts = await ensureMountDirectories(input.target.workDirectory);
  let journal = await loadJournal(journalPath);
  if (journal !== null) {
    await assertResumeBinding(journal, input, archives, layout, indexSha256);
    await verifyJournalStage(
      journal.completedStages[journal.completedStages.length - 1],
      runner,
      input.metadata,
      input.target,
    );
  } else {
    // This first inventory is the only state in which formatting is allowed
    // without a prior journal: both serial-bound whole disks must be empty.
    const initial = await snapshot(runner, input.metadata, input.target, false);
    await assertPristineTarget(runner, input.target, initial);
    journal = newJournal({ ...input, index }, archives, layout, indexSha256);
    await saveJournal(journalPath, journal);
  }
  await checkpoint?.(structuredClone(journal));

  if (!journalHas(journal, "partition-tables-written")) {
    const bootDumpPath = `${input.target.workDirectory}/sfdisk-boot.txt`;
    const rootDumpPath = `${input.target.workDirectory}/sfdisk-root.txt`;
    await writeOwnedText(bootDumpPath, layout.bootDisk.dump);
    await writeOwnedText(rootDumpPath, layout.rootDisk.dump);
    await guardBeforeWrite(
      runner,
      input.metadata,
      input.target,
      "partition:boot",
    );
    await runSfdisk(
      runner,
      input.target.bootDiskPath,
      bootDumpPath,
      "partition:boot",
    );
    await checked(runner, "udevadm", ["settle"], "partition:settle");
    await guardBeforeWrite(
      runner,
      input.metadata,
      input.target,
      "partition:root",
    );
    await runSfdisk(
      runner,
      input.target.rootDiskPath,
      rootDumpPath,
      "partition:root",
    );
    await checked(runner, "udevadm", ["settle"], "partition:settle");
    const afterPartitions = await guardBeforeWrite(
      runner,
      input.metadata,
      input.target,
      "partition:verify",
    );
    assertPartitionShape(afterPartitions, false);
    await markStage(
      journalPath,
      journal,
      "partition-tables-written",
      checkpoint,
    );
  }

  if (!journalHas(journal, "filesystems-created")) {
    for (
      const role of ["efi", "staging-efi", "root", "staging-boot"] as const
    ) {
      await formatFilesystem(
        runner,
        input.metadata,
        input.target,
        layout.filesystems.find((fs) => fs.role === role)!,
      );
    }
    await markStage(journalPath, journal, "filesystems-created", checkpoint);
  }

  if (!journalHas(journal, "lvm-restored")) {
    const lvmPath = `${input.target.workDirectory}/lvm-restore.vg`;
    await writeOwnedText(lvmPath, layout.lvmText);
    await guardBeforeWrite(
      runner,
      input.metadata,
      input.target,
      "lvm:pvcreate",
    );
    await checked(runner, "pvcreate", [
      "--yes",
      "--force",
      "--uuid",
      layout.pvUuid,
      "--restorefile",
      lvmPath,
      layout.bootDisk.partitions.lvm,
    ], "lvm:pvcreate");
    await guardBeforeWrite(runner, input.metadata, input.target, "lvm:restore");
    await checked(runner, "vgcfgrestore", [
      "--force",
      "--file",
      lvmPath,
      layout.volumeGroup,
    ], "lvm:restore");
    await guardBeforeWrite(
      runner,
      input.metadata,
      input.target,
      "lvm:activate",
    );
    await checked(
      runner,
      "vgchange",
      ["--activate", "y", layout.volumeGroup],
      "lvm:activate",
    );
    for (const role of ["oracle-root", "oracle-oled"] as const) {
      await formatFilesystem(
        runner,
        input.metadata,
        input.target,
        layout.filesystems.find((fs) => fs.role === role)!,
      );
    }
    const afterLvm = await guardBeforeWrite(
      runner,
      input.metadata,
      input.target,
      "lvm:verify",
    );
    assertPartitionShape(afterLvm, true);
    await markStage(journalPath, journal, "lvm-restored", checkpoint);
  }

  if (!journalHas(journal, "mounted")) {
    await mountOne(
      runner,
      input.metadata,
      input.target,
      layout.rootDisk.partitions.root,
      mounts.root,
      "mount:root",
    );
    await mountOne(
      runner,
      input.metadata,
      input.target,
      layout.rootDisk.partitions.efi,
      mounts.efi,
      "mount:efi",
    );
    await mountOne(
      runner,
      input.metadata,
      input.target,
      layout.bootDisk.partitions.stagingBoot,
      mounts["staging-boot"],
      "mount:staging-boot",
    );
    await mountOne(
      runner,
      input.metadata,
      input.target,
      layout.bootDisk.partitions.efi,
      mounts["staging-efi"],
      "mount:staging-efi",
    );
    await mountOne(
      runner,
      input.metadata,
      input.target,
      `/dev/mapper/${layout.volumeGroup}-root`,
      mounts["oracle-root"],
      "mount:oracle-root",
    );
    await mountOne(
      runner,
      input.metadata,
      input.target,
      `/dev/mapper/${layout.volumeGroup}-oled`,
      mounts["oracle-oled"],
      "mount:oracle-oled",
    );
    await markStage(journalPath, journal, "mounted", checkpoint);
  }

  if (!journalHas(journal, "archives-extracted")) {
    await extractArchives(
      runner,
      input.metadata,
      input.target,
      archives,
      mounts,
      streamArchive,
    );
    await checked(runner, "sync", [], "extract:sync");
    await markStage(journalPath, journal, "archives-extracted", checkpoint);
  }

  if (!journalHas(journal, "swap-recreated")) {
    await recreateSwap(
      runner,
      input.metadata,
      input.target,
      mounts["oracle-root"],
      layout.swap,
    );
    await checked(runner, "sync", [], "swap:sync");
    await markStage(journalPath, journal, "swap-recreated", checkpoint);
  }

  if (!journalHas(journal, "filesystem-rebuilt")) {
    await unmountAll(runner, mounts);
    const released = await snapshot(
      runner,
      input.metadata,
      input.target,
      true,
    );
    if (released.mountedSources.length > 0) fail("mount:release");
    await markStage(journalPath, journal, "filesystem-rebuilt", checkpoint);
  }
  return {
    status: "FILESYSTEMS_REBUILT",
    generation: input.index.generation,
    indexSha256,
    targetId: input.target.targetId,
    journalPath,
    stages: [...journal.completedStages],
    restoredRoles: [...EXPECTED_ARCHIVE_ROLES],
    targetDisks: {
      boot: input.target.bootDiskPath,
      root: input.target.rootDiskPath,
    },
    mountsReleased: true,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  };
}

async function readConfig(path = CONFIG_PATH): Promise<MachineRestoreInput> {
  let text: string;
  try {
    text = await Deno.readTextFile(path);
  } catch {
    fail("config:read");
  }
  try {
    return JSON.parse(text) as MachineRestoreInput;
  } catch {
    fail("config:json");
  }
}

export async function main(
  runner: CommandRunner = defaultRunner,
): Promise<MachineRestoreResult> {
  return await restoreMachine(await readConfig(), runner);
}

if (import.meta.main) {
  try {
    const result = await main();
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(
      error instanceof Error ? error.message : "Machine restore failed",
    );
    Deno.exitCode = 1;
  }
}
