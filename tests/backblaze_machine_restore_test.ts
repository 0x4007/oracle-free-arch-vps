/** Focused m02 tests.  They use synthetic v1 metadata and a command runner
 * that records calls; no OCI, B2, SSH, source filesystem, disk or credential
 * is touched.  The target-refusal case deliberately proves that an invalid
 * target fails before the runner is called. */
import { createHash } from "node:crypto";

import {
  buildRestoreLayout,
  type MachineMetadataArchive,
  type MachineRecoveryMetadata,
  machineRestoreBootHashes,
  machineRestoreIndexSha256,
  type MachineRestoreInput,
  type MachineRestoreTarget,
  type MachineRestoreV2Source,
  type MachineSourceRecord,
  restoreMachine,
  restoreTarArgs,
  rewriteSfdiskDump,
  scopeTargetMountEntries,
  validateMachineRestoreSource,
  validateRestoreMountBindings,
} from "../scripts/backblaze-machine-restore.ts";
import {
  type IndexArchiveRecord,
  type RecoveryIndex,
  validateRecoveryIndex,
} from "../scripts/backblaze-index.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
} from "../scripts/backblaze-upload.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ObjectKind,
  backupV2ObjectName,
  validateBackupV2Receipt,
  validateBackupV2Root,
} from "../scripts/backup-v2-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";

function assert(value: unknown, message?: string): asserts value {
  if (!value) throw new Error(message ?? "Assertion failed");
}

async function rejects(
  promise: Promise<unknown>,
  fragment?: string,
): Promise<void> {
  try {
    await promise;
  } catch (error) {
    if (fragment) {
      assert(error instanceof Error && error.message.includes(fragment));
    }
    return;
  }
  throw new Error("expected rejection");
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha1(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

const GENERATION = "generation-681c4067-aec2-45d5-9afb-77ee530e3a97";
const FINGERPRINT = "A09D9D4303E01A5EDF2A3B681672E156BF36E91C";
const RECIPIENT_SHA = "5b".repeat(32);
const TARGET: MachineRestoreTarget = {
  targetId: "uos-restore-20260906",
  bootDiskSerial: "uos-restore-20260906-stage",
  rootDiskSerial: "uos-restore-20260906-root",
  architecture: "aarch64",
  bootDiskPath: "/dev/disk/by-id/virtio-uos-restore-20260906-stage",
  rootDiskPath: "/dev/disk/by-id/virtio-uos-restore-20260906-root",
  bootDiskBytes: 50 * 1024 ** 3,
  rootDiskBytes: 150 * 1024 ** 3,
  workDirectory: "/tmp/uos-restore-20260906",
  approval: {
    targetId: "uos-restore-20260906",
    bootDiskSerial: "uos-restore-20260906-stage",
    rootDiskSerial: "uos-restore-20260906-root",
    bootDiskPath: "/dev/disk/by-id/virtio-uos-restore-20260906-stage",
    rootDiskPath: "/dev/disk/by-id/virtio-uos-restore-20260906-root",
    approvedAtUtc: "2026-09-06T14:00:00.000Z",
  },
};

function archiveBytes(seed: number): Uint8Array {
  return new Uint8Array([seed, seed + 1, seed + 2, seed + 3]);
}

function makeIndex(): RecoveryIndex {
  const archives: IndexArchiveRecord[] = UPLOAD_ROLE_ORDER.map((role, i) => {
    const bytes = archiveBytes(i + 1);
    return {
      role,
      format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
      bytes: bytes.byteLength,
      sha256: sha256(bytes),
      chunks: [{
        index: 0,
        name: generationChunkName(GENERATION, role, 0),
        size: bytes.byteLength,
        sha256: sha256(bytes),
        sha1: sha1(bytes),
        fileId: `file-${role}`,
        uploadTimestamp: 1_800_000_000_000 + i,
      }],
    };
  });
  return validateRecoveryIndex({
    schemaVersion: 1,
    generation: GENERATION,
    captureStartedAtUtc: "2026-09-06T01:00:00.000Z",
    captureFinishedAtUtc: "2026-09-06T01:01:00.000Z",
    uploadStartedAtUtc: "2026-09-06T01:01:00.000Z",
    uploadFinishedAtUtc: "2026-09-06T01:02:00.000Z",
    consistency: "live-file-copy",
    sourceShutdown: false,
    recipientFingerprint: FINGERPRINT,
    recipientSha256: RECIPIENT_SHA,
    archives,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  });
}

function bootDump(): string {
  return [
    "label: gpt",
    "label-id: 11111111-2222-3333-4444-555555555555",
    "device: /dev/sda",
    "unit: sectors",
    "first-lba: 34",
    "last-lba: 97727250",
    "sector-size: 512",
    "",
    "/dev/sda1 : start= 2048, size= 204800, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=AAAA-BBBB",
    "/dev/sda2 : start= 206848, size= 4194304, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=CCCC-DDDD",
    "/dev/sda3 : start= 4401152, size= 93325312, type=E6D6D379-F507-44C2-A23C-238F2A3DF928, uuid=EEEE-FFFF",
    "",
  ].join("\n");
}

function rootDump(): string {
  return [
    "label: gpt",
    "label-id: 66666666-7777-8888-9999-AAAAAAAAAAAA",
    "device: /dev/sdb",
    "unit: sectors",
    "first-lba: 34",
    "last-lba: 314572766",
    "sector-size: 512",
    "",
    "/dev/sdb1 : start= 2048, size= 1048576, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=1111-2222",
    "/dev/sdb2 : start= 1050624, size= 313522143, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=3333-4444",
    "",
  ].join("\n");
}

function metadata(index: RecoveryIndex): MachineRecoveryMetadata {
  const sizes = {
    root: 160_523_337_216,
    efi: 536_870_912,
    "staging-boot": 2_147_483_648,
    "staging-efi": 104_857_600,
    "oracle-root": 31_675_383_808,
    "oracle-oled": 16_106_127_360,
  } as const;
  const filesystems = {
    root: "ext4",
    efi: "vfat",
    "staging-boot": "xfs",
    "staging-efi": "vfat",
    "oracle-root": "xfs",
    "oracle-oled": "xfs",
  } as const;
  const uuids = {
    root: "e61e7a3e-996d-418a-831b-09f09e827e0a",
    efi: "CB1C-8B9A",
    "staging-boot": "88d3ee9a-b987-45cc-a3ce-75aebba9bccd",
    "staging-efi": "7049-BB0F",
    "oracle-root": "e88e4336-832e-412f-a155-50bf9bd7451b",
    "oracle-oled": "2ca3994a-8c94-41cb-9f1c-16a43132bfde",
  } as const;
  const sources: MachineSourceRecord[] = Object.keys(sizes).map((name) => ({
    name: name as MachineSourceRecord["name"],
    uuid: uuids[name as keyof typeof uuids],
    filesystem: filesystems[name as keyof typeof filesystems],
    size: sizes[name as keyof typeof sizes],
    ...(name === "root"
      ? { livePath: "/" as const }
      : name === "efi"
      ? { livePath: "/efi" as const }
      : {}),
  }));
  const indexArchives = index.archives.filter((archive) =>
    archive.role !== "recovery"
  );
  return {
    schemaVersion: 1,
    generation: GENERATION,
    consistency: "live-file-copy",
    sourceShutdown: false,
    machineBootRestoreProved: false,
    sources,
    blockLayouts: {
      final: [
        {
          name: "sda",
          path: "/dev/sda",
          size: 50 * 1024 ** 3,
          type: "disk",
          children: [{ path: "/dev/sda1", type: "part", uuid: "7049-BB0F" }, {
            path: "/dev/sda2",
            type: "part",
            uuid: "88d3ee9a-b987-45cc-a3ce-75aebba9bccd",
          }, {
            path: "/dev/sda3",
            type: "part",
            uuid: "CSr4LO-TvpE-bN5n-wguZ-FsJT-ESp0-kI1xjr",
            fstype: "LVM2_member",
          }],
        },
        {
          name: "sdb",
          path: "/dev/sdb",
          size: 150 * 1024 ** 3,
          type: "disk",
          children: [{ path: "/dev/sdb1", type: "part", uuid: "CB1C-8B9A" }, {
            path: "/dev/sdb2",
            type: "part",
            uuid: "e61e7a3e-996d-418a-831b-09f09e827e0a",
          }],
        },
      ],
    },
    partitionTables: [{ disk: "/dev/sda", dump: bootDump() }, {
      disk: "/dev/sdb",
      dump: rootDump(),
    }],
    lvm: {
      volumeGroup: "ocivolume",
      text:
        `contents = "Text Format Volume Group"\nphysical_volumes {\n\tpv0 {\n\t\tid = "CSr4LO-TvpE-bN5n-wguZ-FsJT-ESp0-kI1xjr"\n\t\tdevice = "/dev/sda3"\n\t}\n}\nlogical_volumes {\n\toled {\n\t\tid = "iKxxV3-UvE8-NfAZ-civ3-LysH-GLEh-63hzVU"\n\t}\n\troot {\n\t\tid = "LgeOsS-ROHs-U3S6-N01n-Mk8S-u0sg-fyYRsr"\n\t}\n}\n`,
    },
    archives: indexArchives.map((archive) => ({
      role: archive.role as MachineMetadataArchive["role"],
      path: `/var/tmp/${archive.role}.tar.zst.gpg`,
      bytes: archive.bytes,
      sha256: archive.sha256,
      format: "tar.zst.gpg" as const,
    })),
    recipient: { fingerprint: FINGERPRINT, publicSha256: RECIPIENT_SHA },
    finalChecks: {
      pacmanLockAbsent: true,
      packagesUnchanged: true,
      bootHashesUnchanged: true,
    },
    bootHashes: {
      root: `${"aa".repeat(32)}  /boot/Image\n${
        "bb".repeat(32)
      }  /boot/initramfs-linux.img\n`,
      stagingBoot: `${"aa".repeat(32)}  ./arch-vmlinuz\n${
        "bb".repeat(32)
      }  ./arch-initrd.img\n`,
    },
    swapRecreation: {
      present: true,
      path: "/.swapfile",
      bytes: 4294967296,
      mode: 0o600,
      uid: 0,
      gid: 0,
    },
    fstab: "UUID=e61e7a3e-996d-418a-831b-09f09e827e0a / ext4 defaults 0 1\n",
    procCmdline: "root=UUID=e61e7a3e-996d-418a-831b-09f09e827e0a rw\n",
  };
}

function v2Input() {
  const legacy = makeIndex(),
    config = "cc".repeat(32),
    attempt = "00000000-0000-4000-8000-000000000001",
    put = "00000000-0000-4000-8000-000000000002";
  const reference = (
    kind: BackupV2ObjectKind,
    ordinal: number,
    body = "fixture",
  ) => {
    const data = new TextEncoder().encode(body);
    return {
      object: {
        fileId: `fixture-${kind}-${ordinal}`,
        fileName: backupV2ObjectName(GENERATION, attempt, kind, ordinal, put),
        contentLength: data.length,
        contentSha1: sha1(data),
        sha256: sha256(data),
        uploadTimestamp: 1,
        action: "upload" as const,
      },
      plaintextSha256: sha256(data),
    };
  };
  const root = validateBackupV2Root({
    schemaVersion: 2 as const,
    format: "backup-v2" as const,
    profile: BACKUP_V2_PROFILE_ID,
    captureId: GENERATION,
    periodKey: "2026-10-18",
    sourceRevision: "c".repeat(40),
    sourceConfigSha256: config,
    recipientSha256: RECIPIENT_SHA,
    recipientFingerprint: FINGERPRINT,
    metadata: [],
    roles: BACKUP_V2_ROLES.map((role, index) => ({
      role,
      attemptId: attempt,
      manifest: reference("manifest", index),
      captureStartedAtUtc: "2026-10-18T04:00:00.000Z",
      captureFinishedAtUtc: "2026-10-18T04:01:00.000Z",
    })),
  });
  const meta: MachineRecoveryMetadata = {
    ...metadata(legacy),
    schemaVersion: 2,
    format: "backup-v2-recovery",
    sourceConfigSha256: config,
    archives: legacy.archives.filter((item) => item.role !== "recovery").map((
      item,
    ) => ({
      role: item.role as MachineMetadataArchive["role"],
      format: "tar.zst.gpg",
      ciphertextBytes: item.bytes,
      ciphertextSha256: item.sha256,
    })),
  };
  const receipt = validateBackupV2Receipt({
    schemaVersion: 2,
    format: "backup-v2",
    captureId: GENERATION,
    root: reference("manifest", 99, JSON.stringify(root)),
    verifiedAtUtc: "2026-10-18T04:02:00.000Z",
    recipientSha256: RECIPIENT_SHA,
    recipientFingerprint: FINGERPRINT,
    verifierRevision: "c".repeat(40),
    configurationSha256: config,
    tools: { tar: "1.35", zstd: "1.5.7", gpg: "2.4" },
    archives: legacy.archives.map((item) => ({
      role: item.role,
      format: item.format,
      ciphertextBytes: item.bytes,
      ciphertextSha256: item.sha256,
      compressedBytes: item.bytes,
      compressedSha256: item.sha256,
      inventory: item.role === "recovery" ? null : {
        encoding: "backup-v2-inventory-1",
        members: 1,
        pathBytes: 2,
        encodedBytes: 10,
        sha256: "a".repeat(64),
      },
      inputComplete: true,
      integrityChecked: true,
      decompressionComplete: true,
      gpgExitCode: 0,
      zstdExitCode: 0,
      tarExitCode: 0,
    })),
    bootSamples: BACKUP_V2_BOOT_SAMPLES.map((sample, index) => ({
      ...sample,
      bytes: 1,
      sha256: (index % 2 === 0 ? "aa" : "bb").repeat(32),
    })),
    metadataSha256: sha256(new TextEncoder().encode(JSON.stringify(meta))),
    sourceIndependent: true,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  });
  const source: MachineRestoreV2Source = {
    schemaVersion: 2,
    format: "backup-v2",
    generation: GENERATION,
    root,
    reference: receipt.root,
    receipt,
    receiptReference: reference("receipt", 0, JSON.stringify(receipt)),
  };
  return {
    source,
    metadata: meta,
    legacy,
    archives: receipt.archives.filter((item) => item.role !== "recovery").map((
      item,
    ) => ({
      role: item.role as MachineMetadataArchive["role"],
      bytes: item.compressedBytes,
      sha256: item.compressedSha256,
      ciphertextBytes: item.ciphertextBytes,
      ciphertextSha256: item.ciphertextSha256,
      verifierChecked: true as const,
    })),
  };
}

Deno.test("v2 machine source uses real root anchor and preserves the shared serial-bound layout", () => {
  const input = v2Input();
  assert(validateMachineRestoreSource(input.source).schemaVersion === 2);
  assert(
    machineRestoreIndexSha256(input.source) ===
      input.source.reference.plaintextSha256,
  );
  assert(
    JSON.stringify(buildRestoreLayout(input.source, input.metadata, TARGET)) ===
      JSON.stringify(
        buildRestoreLayout(input.legacy, metadata(input.legacy), TARGET),
      ),
  );
  assert(
    machineRestoreBootHashes(input.source, input.metadata).kernelSha256 ===
      "aa".repeat(32),
  );
  assert(!("archives" in input.source));
});

Deno.test("v2 machine source rejects root, metadata and compressed proof drift before commands", async () => {
  const input = v2Input();
  let calls = 0;
  const run = () => {
    calls++;
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const changedRoot = structuredClone(input.source);
  changedRoot.root.sourceRevision = "d".repeat(40);
  await rejects(
    restoreMachine(
      {
        index: changedRoot,
        indexSha256: input.source.reference.plaintextSha256,
        metadata: input.metadata,
        archives: input.archives,
        target: TARGET,
      },
      run,
      () => Promise.resolve(),
    ),
    "source:v2-binding",
  );
  const changedMetadata = structuredClone(input.metadata);
  changedMetadata.fstab = "tampered";
  await rejects(
    restoreMachine(
      {
        index: input.source,
        indexSha256: input.source.reference.plaintextSha256,
        metadata: changedMetadata,
        archives: input.archives,
        target: TARGET,
      },
      run,
      () => Promise.resolve(),
    ),
    "metadata:binding",
  );
  const changedArchives = structuredClone(input.archives);
  changedArchives[0].sha256 = "00".repeat(32);
  await rejects(
    restoreMachine(
      {
        index: input.source,
        indexSha256: input.source.reference.plaintextSha256,
        metadata: input.metadata,
        archives: changedArchives,
        target: TARGET,
      },
      run,
      () => Promise.resolve(),
    ),
    "archives:binding",
  );
  assert(calls === 0);
});

Deno.test("v2 wrong target remains refused before machine commands or filesystem work", async () => {
  const input = v2Input();
  let calls = 0;
  await rejects(
    restoreMachine({
      index: input.source,
      indexSha256: input.source.reference.plaintextSha256,
      metadata: input.metadata,
      archives: input.archives,
      target: { ...TARGET, rootDiskPath: TARGET.bootDiskPath },
    }, () => {
      calls++;
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }),
    "target",
  );
  assert(calls === 0);
});

Deno.test("m02 refuses a wrong target before any command", async () => {
  const index = makeIndex();
  const input = {
    index,
    indexSha256: machineRestoreIndexSha256(index),
    metadata: metadata(index),
    archives: [],
    target: {
      ...TARGET,
      rootDiskPath: "/dev/unsafe/uos-restore-20260906-root",
    },
  } as unknown as MachineRestoreInput;
  let calls = 0;
  await rejects(
    restoreMachine(input, () => {
      calls += 1;
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }),
    "target:path",
  );
  assert(calls === 0, "runner was called before target refusal");
});

Deno.test("m02 accepts approved scsi-by-id paths with exact serial guards", () => {
  const index = makeIndex();
  const target: MachineRestoreTarget = {
    ...TARGET,
    bootDiskPath:
      "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_uos-restore-20260906-stage",
    rootDiskPath:
      "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_uos-restore-20260906-root",
    approval: {
      ...TARGET.approval,
      bootDiskPath:
        "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_uos-restore-20260906-stage",
      rootDiskPath:
        "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_uos-restore-20260906-root",
    },
  };
  const layout = buildRestoreLayout(index, metadata(index), target);
  assert(layout.bootDisk.targetPath === target.bootDiskPath);
  assert(layout.rootDisk.targetPath === target.rootDiskPath);
});

Deno.test("m02 maps recorded disk sizes and rewrites source paths", () => {
  const index = makeIndex();
  const layout = buildRestoreLayout(index, metadata(index), TARGET);
  assert(layout.bootDisk.originalPath === "/dev/sda");
  assert(layout.rootDisk.originalPath === "/dev/sdb");
  assert(layout.bootDisk.dump.includes(`${TARGET.bootDiskPath}-part3`));
  assert(layout.rootDisk.dump.includes(`${TARGET.rootDiskPath}-part2`));
  assert(!layout.bootDisk.dump.includes("/dev/sda"));
  assert(!layout.rootDisk.dump.includes("/dev/sdb"));
  assert(
    layout.filesystems.find((item) => item.role === "root")?.device ===
      `${TARGET.rootDiskPath}-part2`,
  );
  assert(
    layout.filesystems.find((item) => item.role === "oracle-root")?.device ===
      "/dev/mapper/ocivolume-root",
  );
  assert(layout.lvmText.includes(`${TARGET.bootDiskPath}-part3`));
  assert(!layout.lvmText.includes("/dev/sda3"));
});

Deno.test("m02 tar command preserves numeric owners ACL xattrs sparse and hardlinks", () => {
  const args = restoreTarArgs("/tmp/root.tar.zst", "/tmp/mount");
  for (
    const expected of [
      "--numeric-owner",
      "--same-owner",
      "--same-permissions",
      "--acls",
      "--xattrs",
      "--xattrs-include=*",
      "--sparse",
      "--use-compress-program=zstd",
    ]
  ) {
    assert(args.includes(expected), expected);
  }
  const rewritten = rewriteSfdiskDump(
    bootDump(),
    "/dev/sda",
    TARGET.bootDiskPath,
  );
  assert(!rewritten.includes("/dev/sda"));
  assert(rewritten.includes(`${TARGET.bootDiskPath}-part1`));
});

Deno.test("m02 scopes findmnt evidence to target mounts", () => {
  const workDirectory = "/run/uos-restore-20260906";
  const entries = scopeTargetMountEntries([
    { target: "/", source: "/dev/vda2" },
    { target: "/proc", source: "proc" },
    {
      target: `${workDirectory}/mounts/root`,
      source: "/dev/target-root-part2",
    },
    {
      target: `${workDirectory}/mounts/staging-boot`,
      source: "/dev/target-stage-part2",
    },
  ], workDirectory);
  assert(entries.length === 2);
  assert(
    entries.every((entry) =>
      entry.target.startsWith(`${workDirectory}/mounts/`)
    ),
  );
});

Deno.test("restore mount bindings reject a nested-path substitute or a different device", () => {
  const sources = metadata(makeIndex()).sources;
  const work = "/run/uos-restore-20260906";
  const relative: Record<string, string> = {
    root: "root",
    efi: "root/efi",
    "staging-boot": "staging-boot",
    "staging-efi": "staging-boot/efi",
    "oracle-root": "oracle-root",
    "oracle-oled": "oracle-oled",
  };
  const nodes = sources.map((source) => ({
    uuid: source.uuid,
    fstype: source.filesystem,
    path: `/dev/${source.name}`,
  }));
  const entries = sources.map((source) => ({
    target: `${work}/mounts/${relative[source.name]}`,
    source: `/dev/${source.name}`,
    uuid: source.uuid,
    fstype: source.filesystem,
  }));
  validateRestoreMountBindings(entries, sources, nodes, work);
  for (
    const changed of [
      entries.map((entry) =>
        entry.source === "/dev/root"
          ? { ...entry, target: `${work}/mounts/root/efi/child` }
          : entry
      ),
      entries.map((entry) =>
        entry.source === "/dev/root"
          ? { ...entry, source: "/dev/unrelated" }
          : entry
      ),
      entries.map((entry) =>
        entry.source === "/dev/root" ? { ...entry, uuid: "wrong-uuid" } : entry
      ),
    ]
  ) {
    let refused = false;
    try {
      validateRestoreMountBindings(changed, sources, nodes, work);
    } catch {
      refused = true;
    }
    assert(refused);
  }
});

Deno.test({
  name: "SCSI target uses full hardware serial and refuses a substituted disk",
  ignore:
    (await Deno.permissions.query({ name: "read" })).state !== "granted" ||
    (await Deno.permissions.query({ name: "write" })).state !== "granted",
  fn: async () => {
    const index = makeIndex();
    const workDirectory = await Deno.realPath(await Deno.makeTempDir());
    await Deno.chmod(workDirectory, 0o700);
    try {
      const input: MachineRestoreInput = {
        index,
        indexSha256: machineRestoreIndexSha256(index),
        metadata: metadata(index),
        target: { ...TARGET, workDirectory },
        archives: index.archives.filter((a) => a.role !== "recovery").map((
          a,
        ) => ({
          role: a.role as Exclude<typeof a.role, "recovery">,
          path: `/recovery/${a.role}.tar.zst`,
          bytes: 4,
          sha256: "ab".repeat(32),
          ciphertextBytes: a.bytes,
          ciphertextSha256: a.sha256,
        })),
      };
      for (const substituted of [false, true]) {
        let resolves = 0;
        await rejects(
          restoreMachine(input, (command, args) => {
            if (command === "lsblk") {
              return Promise.resolve({
                code: 0,
                stderr: "",
                stdout: JSON.stringify({
                  blockdevices: [
                    {
                      path: "/dev/sda",
                      type: "disk",
                      size: TARGET.bootDiskBytes,
                      serial: null,
                    },
                    {
                      path: "/dev/sdb",
                      type: "disk",
                      size: TARGET.rootDiskBytes,
                      serial: null,
                    },
                  ],
                }),
              });
            }
            if (command === "udevadm") {
              return Promise.resolve({
                code: 0,
                stderr: "",
                stdout: "ID_SERIAL_SHORT=short-id\nID_SERIAL=" +
                  (args.at(-1) === "--name=/dev/sda"
                    ? "uos-restore-20260906-stage"
                    : substituted
                    ? "another-disk"
                    : "uos-restore-20260906-root") +
                  "\n",
              });
            }
            if (command === "readlink") {
              resolves++;
              return Promise.resolve({ code: 1, stdout: "", stderr: "" });
            }
            throw new Error("Unexpected command before serial acceptance");
          }),
          substituted ? "target:serial" : "target:resolve:exit",
        );
        assert(resolves === (substituted ? 0 : 1));
      }
    } finally {
      await Deno.remove(workDirectory, { recursive: true });
    }
  },
});

Deno.test("restore accepts a new explicitly bound target and rejects stale approval", async () => {
  const index = makeIndex();
  const binding = {
    targetId: "replacement-20260907",
    bootDiskPath: "/dev/disk/by-id/scsi-new-boot",
    rootDiskPath: "/dev/disk/by-id/scsi-new-root",
    bootDiskSerial: "new-boot-hardware-serial",
    rootDiskSerial: "new-root-hardware-serial",
  };
  const target = {
    ...TARGET,
    ...binding,
    approval: { ...TARGET.approval, ...binding },
  };
  const layout = buildRestoreLayout(index, metadata(index), target);
  assert(layout.bootDisk.targetPath === binding.bootDiskPath);
  for (
    const changed of [
      { ...target, approval: TARGET.approval },
      { ...target, bootDiskSerial: "substituted" },
      { ...target, targetId: "different-target" },
    ]
  ) {
    let calls = 0;
    await rejects(
      restoreMachine({
        index,
        indexSha256: machineRestoreIndexSha256(index),
        metadata: metadata(index),
        archives: [],
        target: changed,
      }, () => {
        calls++;
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }),
      "target:approval",
    );
    assert(calls === 0);
  }
});

Deno.test({
  name: "failed initial Pi checkpoint prevents all disk mutations",
  ignore:
    (await Deno.permissions.query({ name: "read" })).state !== "granted" ||
    (await Deno.permissions.query({ name: "write" })).state !== "granted",
  fn: async () => {
    const index = makeIndex();
    const workDirectory = await Deno.realPath(await Deno.makeTempDir());
    await Deno.chmod(workDirectory, 0o700);
    let checkpoints = 0;
    const commands: string[] = [];
    try {
      await rejects(
        restoreMachine({
          index,
          indexSha256: machineRestoreIndexSha256(index),
          metadata: metadata(index),
          target: { ...TARGET, workDirectory },
          archives: index.archives.filter((a) => a.role !== "recovery").map((
            a,
          ) => ({
            role: a.role as Exclude<typeof a.role, "recovery">,
            bytes: 4,
            sha256: "ab".repeat(32),
            ciphertextBytes: a.bytes,
            ciphertextSha256: a.sha256,
            verifierChecked: true,
          })),
        }, (command, args) => {
          commands.push(command);
          let stdout = "";
          if (command === "lsblk") {
            stdout = JSON.stringify({
              blockdevices: [
                {
                  path: "/dev/vda",
                  type: "disk",
                  size: TARGET.bootDiskBytes,
                  serial: TARGET.bootDiskSerial,
                },
                {
                  path: "/dev/vdb",
                  type: "disk",
                  size: TARGET.rootDiskBytes,
                  serial: TARGET.rootDiskSerial,
                },
              ],
            });
          } else if (command === "readlink") {
            stdout = args.at(-1) === TARGET.bootDiskPath
              ? "/dev/vda"
              : "/dev/vdb";
          } else if (command === "findmnt") {
            stdout = JSON.stringify({ filesystems: [] });
          } else if (command !== "wipefs" || args[0] !== "--noheadings") {
            throw Error(
              "Unexpected disk mutation before durable Pi checkpoint",
            );
          }
          return Promise.resolve({ code: 0, stdout, stderr: "" });
        }, () => {
          throw Error("Archive extraction must not start");
        }, (journal) => {
          checkpoints++;
          assert(journal.completedStages.join() === "preflight-verified");
          throw Error("Pi persistence failed");
        }),
        "Pi persistence failed",
      );
      assert(checkpoints === 1);
      assert(commands.length === 6);
    } finally {
      await Deno.remove(workDirectory, { recursive: true });
    }
  },
});
