import { buildRescueCloudInit } from "../scripts/pi-recovery-bootstrap.ts";
import type { ReplacementConfig } from "../scripts/pi-machine-recovery.ts";
import {
  type RecoverySession,
  type SessionPorts,
  stepRecoverySession,
  validateSessionBootstrap,
} from "../scripts/pi-recovery-session.ts";
import { rescueBootPlan } from "../scripts/pi-recovery-rescue.ts";
import type {
  LoaderIdentityRequest,
  LoaderProviderEvidence,
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
function diskFixture() {
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

function sessionFixture() {
  const disk = diskFixture();
  const f = {
    now: Date.parse("2026-09-07T03:00:00Z"),
    approved: false,
    failIntent: false,
    lostReboot: false,
    reboots: 0,
    failProvider: false,
    saved: {
      schemaVersion: 1,
      requestId: request.requestId,
      replacementPlanSha256: "a".repeat(64),
      instanceId: request.instanceId,
      manifestSha256: "b".repeat(64),
      startedAtUtc: "2026-09-07T02:59:00Z",
    } as RecoverySession,
  };
  const ports: SessionPorts = {
    now: () => f.now,
    persist: (state) => {
      if (f.failIntent && state.rebootIntent) {
        return Promise.reject(Error("intent persistence failed"));
      }
      f.saved = structuredClone(state);
      return Promise.resolve();
    },
    report: () => Promise.resolve(),
    capture: (plan, state) =>
      Promise.resolve({
        ...state,
        host: {
          requestId: request.requestId,
          instanceId: request.instanceId,
          phase: plan.expected.phase,
          bootId: plan.expected.phase === "ram" ? ramBootId : bootId,
          manifestSha256: plan.expected.manifestSha256 ?? null,
          publicKey: "synthetic port fixture",
          fingerprint: "synthetic",
          consoleHistoryId: "ocid1.consolehistory.example",
          consoleCapturedAtUtc: new Date(f.now).toISOString(),
        },
      }),
    target: (state) =>
      Promise.resolve({
        host: state.host!,
        address: "203.0.113.3",
        knownHostsPath: "/synthetic",
      }),
    provider: () => {
      if (f.failProvider) throw Error("attachment unavailable");
      return disk.readProvider();
    },
    beforeMutation: () => Promise.resolve(),
    rebootApproval: () =>
      Promise.resolve(
        f.approved
          ? {
            approvedAtUtc: new Date(f.now).toISOString(),
            planSha256: rescueBootPlan(f.saved.stagedBoot!).planSha256,
            exactOperation: rescueBootPlan(f.saved.stagedBoot!).operation,
          }
          : undefined,
      ),
    ssh: (target) => async (command, args) => {
      if (command === "sudo" && args[1] === "cat") {
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify({
            status: "RAM_RESCUE_STAGED",
            requestId: request.requestId,
            instanceId: request.instanceId,
            sourceBootId: bootId,
            kernelSha256: "c".repeat(64),
            initramfsSha256: "d".repeat(64),
            rebooted: false,
            disksPrepared: false,
          }),
        };
      }
      if (command === "sudo" && args[1] === "bash") {
        assert(
          f.saved.rebootIntent?.planSha256 ===
            rescueBootPlan(f.saved.stagedBoot!).planSha256,
        );
        f.reboots++;
        if (f.lostReboot) throw Error("lost SSH response");
        return { code: 0, stdout: "", stderr: "" };
      }
      if (target.host.phase === "ram") {
        const facts: Record<string, string> = {
          "uname -m": "aarch64",
          "stat --format=%F:%a /run/uos-recovery": "directory:700",
          "cat /proc/cmdline": "ip=dhcp",
          "findmnt --json --output TARGET,FSTYPE --target /": JSON.stringify({
            filesystems: [{ target: "/", fstype: "tmpfs" }],
          }),
          "findmnt --json --output TARGET,FSTYPE --target /run/uos-recovery":
            JSON.stringify({
              filesystems: [{ target: "/run", fstype: "tmpfs" }],
            }),
          "cat /proc/swaps": "Filename Type Size Used Priority",
          "cat /etc/uos-rescue/request-id": request.requestId,
          "cat /proc/sys/kernel/random/boot_id": ramBootId,
          "stat --format=%F:%a /etc/uos-rescue/manifest.json":
            "regular file:644",
          "sha256sum /etc/uos-rescue/manifest.json": "b".repeat(64) +
            "  /etc/uos-rescue/manifest.json",
        };
        const key = [command, ...args].join(" ");
        assert(key in facts);
        return { code: 0, stdout: facts[key], stderr: "" };
      }
      return await disk.runner(command, args);
    },
  };
  const step = () =>
    stepRecoverySession(
      structuredClone(f.saved),
      request,
      "ocid1.compartment.example",
      ports,
    );
  return { f, ports, step };
}
Deno.test("session produces exact reboot plan and never reboots without approval", async () => {
  const { f, step } = sessionFixture();
  assert(await step() === "RESCUE_REBOOT_APPROVAL_REQUIRED");
  assert(
    f.reboots === 0 && f.saved.loaderIdentity?.loaderBootId === bootId &&
      !f.saved.rebootIntent,
  );
});
Deno.test("session joins durable reboot intent to a new accepted RAM boot", async () => {
  const { f, step } = sessionFixture();
  f.approved = true;
  assert(await step() === "RESCUE_REBOOT_REQUESTED" && f.reboots === 1);
  assert(await step() === "RAM_RESCUE_ACCEPTED" && f.reboots === 1);
  assert(f.saved.ramAccepted?.bootId === ramBootId);
});
Deno.test("lost reboot response resumes observation without repeating reboot", async () => {
  const { f, step } = sessionFixture();
  f.approved = true;
  f.lostReboot = true;
  await rejects(step(), "lost SSH response");
  assert(f.reboots === 1 && f.saved.rebootIntent);
  assert(await step() === "RAM_RESCUE_ACCEPTED" && f.reboots === 1);
});
Deno.test("failed durable intent prevents reboot", async () => {
  const { f, step } = sessionFixture();
  f.approved = true;
  f.failIntent = true;
  await rejects(step(), "intent persistence failed");
  assert(f.reboots === 0 && !f.saved.rebootIntent);
});
Deno.test("source target and changed saved reboot digest refuse", async () => {
  const { f, ports, step } = sessionFixture();
  await rejects(
    stepRecoverySession(
      f.saved,
      { ...request, sourceInstanceId: request.instanceId },
      "ocid1.compartment.example",
      ports,
    ),
    "binding differs",
  );
  f.approved = true;
  await step();
  f.saved.rebootIntent!.planSha256 = "e".repeat(64);
  await rejects(step(), "matching staged identity");
  assert(f.reboots === 1);
});

Deno.test({
  name: "session bootstrap rejects altered cloud-init before provisioning",
  ignore: (await Deno.permissions.query({ name: "read" })).state !== "granted",
  fn: async () => {
    const bytes = new Uint8Array(51);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, 11);
    bytes.set(new TextEncoder().encode("ssh-ed25519"), 4);
    view.setUint32(15, 32);
    bytes.fill(1, 19);
    const input = {
      requestId: request.requestId,
      sshPublicKey: "ssh-ed25519 " + btoa(String.fromCharCode(...bytes)),
    };
    const cloudInit = await buildRescueCloudInit(input);
    const config = {
      requestId: request.requestId,
      cloudInit,
    } as ReplacementConfig;
    assert(
      (await validateSessionBootstrap(config)).sshPublicKey ===
        input.sshPublicKey,
    );
    await rejects(
      validateSessionBootstrap({
        ...config,
        cloudInit: cloudInit.replace(
          '"disable_root": true',
          '"disable_root": false',
        ),
      }),
      "bootstrap differs",
    );
    await rejects(
      validateSessionBootstrap({ ...config, cloudInit: "echo unsafe" }),
      "malformed",
    );
  },
});
Deno.test("gate change after durable intent prevents the SSH reboot", async () => {
  const { f, ports, step } = sessionFixture();
  f.approved = true;
  ports.beforeMutation = () =>
    f.saved.rebootIntent
      ? Promise.reject(Error("gate changed"))
      : Promise.resolve();
  await rejects(step(), "gate changed");
  assert(f.reboots === 0 && f.saved.rebootIntent);
});
