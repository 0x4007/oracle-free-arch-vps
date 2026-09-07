import {
  type DiskPreparationBinding,
  diskPreparationPlan,
  inspectPreparationDisks,
  type PreparationEvent,
  prepareReplacementDisks,
} from "../scripts/pi-recovery-disk-preparation.ts";
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
const binding: DiskPreparationBinding = {
  requestId: "recovery-681c4067-aec2-45d5-9afb-77ee530e3a97",
  instanceId: "ocid1.instance.example.replacement",
  bootId: "681c4067-aec2-45d5-9afb-77ee530e3a97",
  loaderBootId: "781c4067-aec2-45d5-9afb-77ee530e3a97",
  rescueManifestSha256: "ab".repeat(32),
  sourceInstanceId: "ocid1.instance.example.production",
  sourceBootVolumeId: "ocid1.bootvolume.example.production",
  sourceRootVolumeId: "ocid1.volume.example.production",
  boot: {
    volumeId: "ocid1.bootvolume.example.replacement",
    path: "/dev/disk/by-id/scsi-platform",
    serial: "platform-full-serial",
    bytes: 50 * 1024 ** 3,
  },
  root: {
    volumeId: "ocid1.volume.example.replacement",
    path: "/dev/disk/by-id/scsi-root",
    serial: "root-full-serial",
    bytes: 150 * 1024 ** 3,
  },
};
const now = Date.parse("2026-09-07T02:00:00.000Z");
function fixture() {
  const state = {
    cleared: { boot: false, root: false },
    extraDisk: false,
    flatOutput: false,
    mounted: false,
    mountedById: false,
    held: false,
    wrongSerial: false,
    wrongBoot: false,
    wrongInstance: false,
    dirtyAfterClear: false,
    readOnly: false,
    mutations: [] as string[],
    readGuard: "",
  };
  const nodes = () =>
    ["boot", "root"].map((role, index) => {
      const disk = binding[role as "boot" | "root"];
      const path = index === 0 ? "/dev/sda" : "/dev/sdb";
      const child = role === "boot" &&
        (!state.cleared.boot || state.dirtyAfterClear);
      return {
        path,
        type: "disk",
        size: disk.bytes,
        ro: state.readOnly,
        serial: "short",
        "maj:min": index === 0 ? "8:0" : "8:16",
        mountpoints: [],
        fstype: null,
        uuid: null,
        children: child
          ? [{
            path: "/dev/sda1",
            type: "part",
            size: 49 * 1024 ** 3,
            ro: false,
            "maj:min": "8:1",
            mountpoints: state.mounted ? ["/other"] : [],
            fstype: "ext4",
            uuid: "platform-uuid",
          }]
          : [],
      };
    });
  const runner: CommandRunner = (command, args) => {
    const line = [command, ...args].join(" ");
    let value: unknown;
    if (line === "uname -m") value = "aarch64";
    else if (line === "stat --format=%F:%a /etc/uos-rescue/manifest.json") {
      value = "regular file:644";
    } else if (command === "sha256sum") {
      value = binding.rescueManifestSha256 + "  /etc/uos-rescue/manifest.json";
    } else if (line === "stat --format=%F:%a /run/uos-recovery") {
      value = "directory:700";
    } else if (line === "cat /proc/cmdline") value = "ip=dhcp";
    else if (line === "cat /proc/swaps") {
      value = "Filename Type Size Used Priority";
    } else if (line === "cat /etc/uos-rescue/request-id") {
      value = binding.requestId;
    } else if (line === "cat /proc/sys/kernel/random/boot_id") {
      value = state.wrongBoot
        ? "781c4067-aec2-45d5-9afb-77ee530e3a97"
        : binding.bootId;
    } else if (command === "findmnt" && args.includes("TARGET,FSTYPE")) {
      value = { filesystems: [{ target: args.at(-1), fstype: "tmpfs" }] };
    } else if (command === "findmnt") {
      value = {
        filesystems: state.mountedById
          ? [{ "maj:min": "8:1" }]
          : [{ "maj:min": "0:22" }],
      };
    } else if (command === "curl") {
      value = {
        id: state.wrongInstance ? binding.sourceInstanceId : binding.instanceId,
        freeformTags: { uosRecoveryRequest: binding.requestId },
      };
    } else if (command === "lsblk") {
      value = {
        blockdevices: state.extraDisk
          ? [...nodes(), { path: "/dev/sdc", type: "disk", size: 1 }]
          : nodes(),
      };
      if (state.flatOutput || !args.includes("--tree")) {
        const data = value as { blockdevices: Record<string, unknown>[] };
        data.blockdevices = data.blockdevices.flatMap((
          { children, ...disk },
        ) => [disk, ...((children ?? []) as Record<string, unknown>[])]);
      }
    } else if (command === "readlink") {
      value = args.at(-1) === binding.boot.path ? "/dev/sda" : "/dev/sdb";
    } else if (command === "udevadm" && args[0] === "info") {
      value = "ID_SCSI_SERIAL=" +
        (state.wrongSerial
          ? "different"
          : args.at(-1) === "--name=/dev/sda"
          ? binding.boot.serial
          : binding.root.serial);
    } else if (command === "bash") {
      state.readGuard = args[1];
      if (state.held) {
        return Promise.resolve({ code: 1, stdout: "", stderr: "held" });
      }
      value = "";
    } else if (command === "wipefs" && args[0] === "--json") {
      value = {
        signatures: args.at(-1)?.startsWith("/dev/sda") &&
            (!state.cleared.boot || state.dirtyAfterClear)
          ? [{
            type: args.at(-1) === "/dev/sda" ? "gpt" : "ext4",
            uuid: "platform-uuid",
            offset: "0x200",
          }]
          : [],
      };
    } else if (command === "wipefs" && args[0] === "--all") {
      const role = args.at(-1) === binding.boot.path ? "boot" : "root";
      state.mutations.push(role);
      state.cleared[role] = true;
      value = "";
    } else if (
      command === "blockdev" || command === "sync" ||
      command === "udevadm" && args[0] === "settle"
    ) value = "";
    else throw Error("Unexpected command: " + line);
    return Promise.resolve({
      code: 0,
      stdout: typeof value === "string" ? value : JSON.stringify(value),
      stderr: "",
    });
  };
  return { state, runner };
}
async function prepared() {
  const f = fixture();
  const plan = diskPreparationPlan(
    binding,
    await inspectPreparationDisks(binding, f.runner),
  );
  const approval = {
    planSha256: plan.planSha256,
    exactOperation: plan.operation,
    approvedAtUtc: new Date(now).toISOString(),
  };
  return { ...f, plan, approval };
}
Deno.test("preparation binds source exclusion and exact two replacement disks", async () => {
  const f = fixture();
  for (
    const changed of [
      { ...binding, instanceId: binding.sourceInstanceId },
      {
        ...binding,
        boot: { ...binding.boot, volumeId: binding.sourceBootVolumeId },
      },
      {
        ...binding,
        root: { ...binding.root, volumeId: binding.sourceRootVolumeId },
      },
      { ...binding, root: { ...binding.root, path: binding.boot.path } },
    ]
  ) {
    await rejects(
      inspectPreparationDisks(changed, f.runner),
      "distinct replacement",
    );
  }
  assert(f.state.mutations.length === 0);
});
Deno.test("preparation refuses mounts, major/minor mount aliases, holders, serial drift and additional disks", async () => {
  for (
    const key of [
      "mounted",
      "mountedById",
      "held",
      "wrongSerial",
      "extraDisk",
      "readOnly",
      "wrongBoot",
      "wrongInstance",
    ] as const
  ) {
    const f = fixture();
    f.state[key] = true;
    await rejects(
      inspectPreparationDisks(binding, f.runner),
      key === "wrongBoot"
        ? "RAM boot"
        : key === "wrongInstance"
        ? "instance identity"
        : key === "extraDisk"
        ? "exactly two"
        : key === "wrongSerial"
        ? "serial"
        : key === "held"
        ? "bash"
        : "mounted",
    );
    assert(f.state.mutations.length === 0);
  }
});
Deno.test("preparation rejects expired or altered approval before commands", async () => {
  const f = await prepared();
  for (
    const approval of [
      { ...f.approval, planSha256: "0".repeat(64) },
      { ...f.approval, approvedAtUtc: new Date(now - 3600001).toISOString() },
      { ...f.approval, approvedAtUtc: new Date(now + 1).toISOString() },
    ]
  ) {
    await rejects(
      prepareReplacementDisks(f.plan, approval, async () => {}, () => {
        throw Error("must not run");
      }, () => now),
      "exact disk-clearing",
    );
  }
});
Deno.test("flat lsblk output cannot bypass partition mount and holder checks", async () => {
  const f = fixture();
  f.state.flatOutput = true;
  f.state.mounted = true;
  await rejects(inspectPreparationDisks(binding, f.runner), "partition trees");
  assert(f.state.mutations.length === 0);
});
Deno.test("each disk clear requires acknowledged intent and verified pristine result", async () => {
  const f = await prepared();
  const phases: string[] = [];
  const result = await prepareReplacementDisks(
    f.plan,
    f.approval,
    (event) => {
      phases.push(event.phase);
      if (event.phase === "boot-clear-intent") {
        assert(
          f.state.mutations.length === 0,
        );
      }
      if (event.phase === "root-clear-intent") {
        assert(
          f.state.mutations.join() === "boot",
        );
      }
      return Promise.resolve();
    },
    f.runner,
    () => now,
  );
  assert(
    phases.join() ===
      "ready,boot-clear-intent,boot-cleared,root-clear-intent,root-cleared,complete",
  );
  assert(f.state.mutations.join() === "boot,root");
  assert(
    result.status === "REPLACEMENT_DISKS_PRISTINE" && !result.restoreAccepted &&
      !result.bootAccepted,
  );
});
Deno.test("failed Pi persistence before wipe cannot clear a disk", async () => {
  for (const phase of ["ready", "boot-clear-intent"] as const) {
    const f = await prepared();
    await rejects(
      prepareReplacementDisks(
        f.plan,
        f.approval,
        (event) => {
          if (event.phase === phase) throw Error("Pi fsync failed");
          return Promise.resolve();
        },
        f.runner,
        () => now,
      ),
      "Pi fsync failed",
    );
    assert(f.state.mutations.length === 0);
  }
});
Deno.test("failed post-boot-clear checkpoint prevents touching root", async () => {
  const f = await prepared();
  await rejects(
    prepareReplacementDisks(
      f.plan,
      f.approval,
      (event) => {
        if (event.phase === "boot-cleared") throw Error("Pi lost");
        return Promise.resolve();
      },
      f.runner,
      () => now,
    ),
    "Pi lost",
  );
  assert(f.state.mutations.join() === "boot");
});
Deno.test("disk change or approval expiry during Pi exchange prevents wipe", async () => {
  for (const expire of [false, true]) {
    const f = await prepared();
    let clock = now;
    await rejects(
      prepareReplacementDisks(
        f.plan,
        f.approval,
        (event: PreparationEvent) => {
          if (event.phase === "boot-clear-intent") {
            if (expire) clock = now + 3600001;
            else f.state.extraDisk = true;
          }
          return Promise.resolve();
        },
        f.runner,
        () => clock,
      ),
      expire ? "exact disk-clearing" : "exactly two",
    );
    assert(f.state.mutations.length === 0);
  }
});
Deno.test("incomplete clearing fails before the second disk", async () => {
  const f = await prepared();
  f.state.dirtyAfterClear = true;
  await rejects(
    prepareReplacementDisks(
      f.plan,
      f.approval,
      async () => {},
      f.runner,
      () => now,
    ),
    "pristine result",
  );
  assert(f.state.mutations.join() === "boot");
});
Deno.test("an interrupted preparation does not silently resume from old approval", async () => {
  const f = await prepared();
  f.state.cleared.boot = true;
  await rejects(
    prepareReplacementDisks(
      f.plan,
      f.approval,
      async () => {},
      f.runner,
      () => now,
    ),
    "inventory changed",
  );
  assert(f.state.mutations.length === 0);
});
Deno.test({
  name: "holder and mount-namespace guard passes actual shell syntax checking",
  ignore:
    (await Deno.permissions.query({ name: "run", command: "bash" })).state !==
      "granted",
  fn: async () => {
    const f = fixture();
    await inspectPreparationDisks(binding, f.runner);
    const child = new Deno.Command("bash", {
      args: ["-n"],
      stdin: "piped",
      stdout: "null",
      stderr: "piped",
    }).spawn();
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(f.state.readGuard));
    await writer.close();
    writer.releaseLock();
    assert((await child.output()).success);
  },
});
