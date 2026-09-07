import {
  captureLoaderDiskIdentity,
  type LoaderIdentityRequest,
  type LoaderProviderEvidence,
  preparationBindingFromLoader,
} from "../scripts/pi-recovery-disk-identity.ts";
import type { CommandRunner } from "../scripts/oci.ts";
function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
async function rejects(work: Promise<unknown>, fragment: string) {
  try {
    await work;
  } catch (error) {
    assert(String(error).includes(fragment));
    return;
  }
  throw Error("Expected refusal");
}
const request: LoaderIdentityRequest = {
  requestId: "recovery-681c4067-aec2-45d5-9afb-77ee530e3a97",
  instanceId: "ocid1.instance.example.target",
  bootVolumeId: "ocid1.bootvolume.example.target",
  rootVolumeId: "ocid1.volume.example.target",
  sourceInstanceId: "ocid1.instance.example.source",
  sourceBootVolumeId: "ocid1.bootvolume.example.source",
  sourceRootVolumeId: "ocid1.volume.example.source",
};
const bootId = "681c4067-aec2-45d5-9afb-77ee530e3a97";
const ramBootId = "781c4067-aec2-45d5-9afb-77ee530e3a97";
function fixture() {
  const shared = {
    "compartment-id": "compartment",
    "availability-domain": "AD",
    "lifecycle-state": "AVAILABLE",
  };
  const provider: LoaderProviderEvidence = {
    instance: {
      ...shared,
      id: request.instanceId,
      "lifecycle-state": "RUNNING",
      "freeform-tags": { uosRecoveryRequest: request.requestId },
      "launch-options": { "is-consistent-volume-naming-enabled": true },
    },
    bootVolume: { ...shared, id: request.bootVolumeId, "size-in-gbs": 50 },
    rootVolume: { ...shared, id: request.rootVolumeId, "size-in-gbs": 150 },
    bootAttachments: [{
      id: "ocid1.bootvolumeattachment.example.target",
      "instance-id": request.instanceId,
      "boot-volume-id": request.bootVolumeId,
      "lifecycle-state": "ATTACHED",
    }],
    rootAttachments: [{
      id: "ocid1.volumeattachment.example.target",
      "instance-id": request.instanceId,
      "volume-id": request.rootVolumeId,
      "lifecycle-state": "ATTACHED",
      "attachment-type": "paravirtualized",
      device: "/dev/oracleoci/oraclevdb",
      "is-read-only": false,
    }],
  };
  const state = {
    providerReads: 0,
    flatOutput: false,
    swapPaths: false,
    rootOnWrongDisk: false,
    collide: false,
    wrongGuest: false,
    reboot: false,
    bootReads: 0,
    attachmentChange: false,
  };
  const readProvider = () => {
    state.providerReads++;
    const copy = structuredClone(provider);
    if (state.attachmentChange && state.providerReads > 1) {
      copy.rootAttachments[0].id = "ocid1.volumeattachment.example.changed";
    }
    return Promise.resolve(copy);
  };
  const runner: CommandRunner = (command, args) => {
    let value: unknown;
    if (command === "uname") value = "aarch64";
    else if (command === "bash") value = "ubuntu:24.04";
    else if (command === "curl") {
      value = {
        id: state.wrongGuest ? request.sourceInstanceId : request.instanceId,
        freeformTags: { uosRecoveryRequest: request.requestId },
      };
    } else if (command === "cat") {
      state.bootReads++;
      value = state.reboot && state.bootReads > 1 ? ramBootId : bootId;
    } // Deliberately reversed device order and names: boot is sdb, not sda.
    else if (command === "lsblk") {
      value = {
        blockdevices: [{
          path: "/dev/sda",
          type: "disk",
          size: 150 * 1024 ** 3,
          "maj:min": "8:0",
          mountpoints: [],
        }, {
          path: "/dev/sdb",
          type: "disk",
          size: 50 * 1024 ** 3,
          "maj:min": "8:16",
          mountpoints: [],
          children: [{
            path: "/dev/sdb1",
            type: "part",
            size: 49 * 1024 ** 3,
            "maj:min": "8:17",
            mountpoints: ["/"],
          }],
        }],
      };
      if (state.flatOutput || !args.includes("--tree")) {
        const data = value as { blockdevices: Record<string, unknown>[] };
        data.blockdevices = data.blockdevices.flatMap((
          { children, ...disk },
        ) => [disk, ...((children ?? []) as Record<string, unknown>[])]);
      }
    } else if (command === "findmnt") {
      value = {
        filesystems: [{ "maj:min": state.rootOnWrongDisk ? "8:0" : "8:17" }],
      };
    } else if (command === "readlink") {
      const path = args.at(-1);
      const boot = path === "/dev/oracleoci/oraclevda" ||
        path === "/dev/disk/by-id/scsi-platform";
      value = boot !== state.swapPaths ? "/dev/sdb" : "/dev/sda";
    } else if (command === "udevadm") {
      const boot = args.at(-1) === "--name=/dev/sdb";
      value = `ID_SCSI_SERIAL=${
        state.collide
          ? "same"
          : boot
          ? "platform-full-hardware-serial"
          : "root-full-hardware-serial"
      }\nDEVLINKS=/dev/disk/by-id/scsi-${boot ? "platform" : "root"}\n`;
    } else throw Error("Unexpected read-only command");
    return Promise.resolve({
      code: 0,
      stdout: typeof value === "string" ? value : JSON.stringify(value),
      stderr: "",
    });
  };
  return { provider, state, readProvider, runner };
}
Deno.test("loader binds OCI consistent paths to full serials despite reversed Linux ordering", async () => {
  const f = fixture();
  const receipt = await captureLoaderDiskIdentity(
    request,
    f.readProvider,
    f.runner,
  );
  assert(
    receipt.boot.volumeId === request.bootVolumeId &&
      receipt.boot.path === "/dev/disk/by-id/scsi-platform" &&
      receipt.boot.serial === "platform-full-hardware-serial",
  );
  assert(
    receipt.root.serial === "root-full-hardware-serial" &&
      f.state.providerReads === 2,
  );
  const binding = preparationBindingFromLoader(
    receipt,
    ramBootId,
    "ab".repeat(32),
  );
  assert(
    binding.bootId === ramBootId &&
      binding.sourceInstanceId === request.sourceInstanceId &&
      binding.boot.serial === receipt.boot.serial,
  );
});
Deno.test("provider mapping refuses wrong attachment, naming mode, read-only volume and production IDs", async () => {
  for (
    const mutation of [
      (p: LoaderProviderEvidence) =>
        p.rootAttachments[0].device = "/dev/oracleoci/oraclevdc",
      (p: LoaderProviderEvidence) =>
        p.rootAttachments[0]["volume-id"] = request.sourceRootVolumeId,
      (p: LoaderProviderEvidence) =>
        p.rootAttachments[0]["is-read-only"] = true,
      (p: LoaderProviderEvidence) =>
        p.instance["launch-options"] = {
          "is-consistent-volume-naming-enabled": false,
        },
      (p: LoaderProviderEvidence) =>
        p.bootAttachments.push({ ...p.bootAttachments[0], id: "extra" }),
    ]
  ) {
    const f = fixture();
    mutation(f.provider);
    await rejects(
      captureLoaderDiskIdentity(request, f.readProvider, () => {
        throw Error("must not SSH");
      }),
      "Oracle attachments",
    );
  }
  const f = fixture();
  await rejects(
    captureLoaderDiskIdentity(
      { ...request, instanceId: request.sourceInstanceId },
      f.readProvider,
      f.runner,
    ),
    "Oracle attachments",
  );
});
Deno.test("loader identity refuses guest mismatch, swapped aliases, wrong root mount and serial collisions", async () => {
  for (
    const [key, fragment] of [
      ["wrongGuest", "instance identity"],
      ["swapPaths", "consistent device"],
      ["rootOnWrongDisk", "root filesystem"],
      ["collide", "identities collide"],
    ] as const
  ) {
    const f = fixture();
    f.state[key] = true;
    await rejects(
      captureLoaderDiskIdentity(request, f.readProvider, f.runner),
      fragment,
    );
  }
});
Deno.test("attachment changes or reboot during collection invalidate the receipt", async () => {
  for (const key of ["attachmentChange", "reboot"] as const) {
    const f = fixture();
    f.state[key] = true;
    await rejects(
      captureLoaderDiskIdentity(request, f.readProvider, f.runner),
      "changed during observation",
    );
  }
});
Deno.test("flat lsblk output cannot silently discard loader partitions", async () => {
  const f = fixture();
  f.state.flatOutput = true;
  await rejects(
    captureLoaderDiskIdentity(request, f.readProvider, f.runner),
    "partition trees",
  );
});
Deno.test("receipt substitution and unchanged loader boot cannot authorize RAM disk preparation", async () => {
  const f = fixture();
  const receipt = await captureLoaderDiskIdentity(
    request,
    f.readProvider,
    f.runner,
  );
  for (
    const [value, boot] of [[receipt, bootId], [{
      ...receipt,
      boot: { ...receipt.boot, serial: "substitute" },
    }, ramBootId]] as const
  ) {
    let refused = false;
    try {
      preparationBindingFromLoader(value, boot, "ab".repeat(32));
    } catch {
      refused = true;
    }
    assert(refused);
  }
});
