import { createHash } from "node:crypto";
import {
  checkRestoredApplications,
  recoveryIsolationArgs,
  requestRestoredBoot,
  RESTORED_BOOT_OPERATION,
  restoredBootPlan,
} from "../scripts/pi-recovery-acceptance.ts";
import type { CheckpointBinding } from "../scripts/pi-recovery-checkpoint.ts";
import type {
  IsolationExecutionReceipt,
  IsolationInspection,
} from "../scripts/pi-recovery-isolation-executor.ts";
import type { RecoveryIsolationPlan } from "../scripts/pi-recovery-isolation.ts";
import { recoveryTargetRestoreArgs } from "../scripts/pi-recovery-restore.ts";
import type { RecoverySshTarget } from "../scripts/pi-recovery-ssh.ts";

const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const validPublicKey =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const validFingerprint = "SHA256:kmYcvdi2GkPeWxB6XLjrZB8JHsy2Hm8luHMFp9GMvqk";
function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
async function rejects(work: Promise<unknown>, text: string) {
  try {
    await work;
  } catch (error) {
    assert(String(error).includes(text));
    return;
  }
  throw Error("Expected refusal");
}

const binding: CheckpointBinding = {
  requestId: "recovery-681c4067-aec2-45d5-9afb-77ee530e3a97",
  instanceId: "ocid1.instance.example.target",
  bootId: "781c4067-aec2-45d5-9afb-77ee530e3a97",
  generation: "generation-1",
  indexSha256: "a".repeat(64),
  bootDiskPath: "/dev/disk/by-id/scsi-platform",
  rootDiskPath: "/dev/disk/by-id/scsi-root",
  bootDiskSerial: "platform-serial",
  rootDiskSerial: "root-serial",
};
const planBody = {
  schemaVersion: 1 as const,
  binding: {
    requestId: binding.requestId,
    instanceId: binding.instanceId,
    sourceInstanceId: "ocid1.instance.example.source",
    sourceBootVolumeId: "ocid1.bootvolume.example.source",
    sourceRootVolumeId: "ocid1.volume.example.source",
    bootId: binding.bootId,
    loaderBootId: "681c4067-aec2-45d5-9afb-77ee530e3a97",
    rescueManifestSha256: "b".repeat(64),
    boot: {
      volumeId: "ocid1.bootvolume.example.target",
      sourceVolumeId: "ocid1.bootvolume.example.source",
      path: binding.bootDiskPath,
      serial: binding.bootDiskSerial,
      bytes: 50 * 1024 ** 3,
    },
    root: {
      volumeId: "ocid1.volume.example.target",
      sourceVolumeId: "ocid1.volume.example.source",
      path: binding.rootDiskPath,
      serial: binding.rootDiskSerial,
      bytes: 150 * 1024 ** 3,
    },
  },
  generation: binding.generation,
  indexSha256: binding.indexSha256,
  rootUuid: "root-uuid-1",
  stagingUuid: "stage-uuid-1",
  kernelSha256: "c".repeat(64),
  initramfsSha256: "d".repeat(64),
  controllerIpv4: "203.0.113.3",
  files: {},
  masks: [],
  restoredManifestSha256: "e".repeat(64),
  prerequisites: {
    inspectMountedCopies: true as const,
    maskAllCopiedTimers: true as const,
    replaceCopiedSshHostKeys: true as const,
    selectIsolatedDefaultTarget: true as const,
    preserveOracleFallback: true as const,
    disableAutomaticFallback: true as const,
  },
  operation:
    "isolate only the reconstructed replacement root before its first restored boot" as const,
};
const isolationPlan = {
  ...planBody,
  planSha256: hash(planBody),
} as RecoveryIsolationPlan;
const inspectionBody = {
  planSha256: isolationPlan.planSha256,
  rootDevice: "/dev/sdb1",
  stagingDevice: "/dev/sda1",
  owner: { uid: 1000, gid: 1000 },
  grubSha256: "f".repeat(64),
  masks: [],
  files: [],
  startup: [],
  startupIsolationVerified: false as const,
};
const inspection: IsolationInspection = {
  ...inspectionBody,
  inspectionSha256: hash(inspectionBody),
};
const receipt: IsolationExecutionReceipt = {
  status: "COPIED_ROOT_ISOLATION_APPLIED",
  planSha256: isolationPlan.planSha256,
  inspectionSha256: inspection.inspectionSha256,
  restoredManifestSha256: isolationPlan.restoredManifestSha256,
  hostPublicKey: "ssh-ed25519 " + "A".repeat(43),
  mountsReleased: true,
  bootAccepted: false,
  applicationAccepted: false,
};

Deno.test("restored boot plan binds the applied isolation receipt", () => {
  const plan = restoredBootPlan(binding, isolationPlan, inspection, receipt);
  assert(plan.operation === RESTORED_BOOT_OPERATION);
  assert(plan.binding.bootId === binding.bootId);
  assert(plan.planSha256.length === 64);
});

Deno.test("restored boot refuses a missing exact approval", async () => {
  const plan = restoredBootPlan(binding, isolationPlan, inspection, receipt);
  const target = {
    host: {
      requestId: binding.requestId,
      instanceId: binding.instanceId,
      phase: "ram",
      bootId: binding.bootId,
      manifestSha256: "b".repeat(64),
      publicKey: validPublicKey,
      fingerprint: validFingerprint,
      consoleHistoryId: "ocid1.consolehistory.example",
      consoleCapturedAtUtc: "2026-09-07T04:00:00.000Z",
    },
    address: "203.0.113.3",
    knownHostsPath:
      `/tmp/recovery-known-hosts/${binding.requestId}-ram-${binding.bootId}`,
  } as RecoverySshTarget;
  await rejects(requestRestoredBoot(target, plan, undefined), "approval");
});

Deno.test("application acceptance refuses a RAM host before SSH", async () => {
  const target = {
    host: {
      requestId: binding.requestId,
      instanceId: binding.instanceId,
      phase: "ram",
      bootId: binding.bootId,
      manifestSha256: "b".repeat(64),
      publicKey: validPublicKey,
      fingerprint: validFingerprint,
      consoleHistoryId: "ocid1.consolehistory.example",
      consoleCapturedAtUtc: "2026-09-07T04:00:00.000Z",
    },
    address: "203.0.113.3",
    knownHostsPath:
      `/tmp/recovery-known-hosts/${binding.requestId}-ram-${binding.bootId}`,
  } as RecoverySshTarget;
  await rejects(
    checkRestoredApplications(target, "b".repeat(64)),
    "Restored SSH host",
  );
});

Deno.test("isolation SSH runtime allows every inspection command", () => {
  const target = {
    host: {
      requestId: binding.requestId,
      instanceId: binding.instanceId,
      phase: "ram",
      bootId: binding.bootId,
      manifestSha256: "b".repeat(64),
      publicKey: validPublicKey,
      fingerprint: validFingerprint,
      consoleHistoryId: "ocid1.consolehistory.example",
      consoleCapturedAtUtc: "2026-09-07T04:00:00.000Z",
    },
    address: "203.0.113.3",
    knownHostsPath:
      `/tmp/recovery-known-hosts/${binding.requestId}-ram-${binding.bootId}`,
  } as RecoverySshTarget;
  const command = recoveryIsolationArgs(target).join(" ");
  const restoreCommand = recoveryTargetRestoreArgs(target).join(" ");
  assert(command.includes("--allow-sys=uid"));
  assert(restoreCommand.includes("--allow-sys=uid"));
  assert(command.includes("--allow-run=") && command.includes(",uname"));
});

Deno.test("isolation launcher permits ln without widening write access", () => {
  const target = {
    host: {
      requestId: binding.requestId,
      instanceId: binding.instanceId,
      phase: "ram",
      bootId: binding.bootId,
      manifestSha256: "b".repeat(64),
      publicKey: validPublicKey,
      fingerprint: validFingerprint,
      consoleHistoryId: "ocid1.consolehistory.example",
      consoleCapturedAtUtc: "2026-09-07T04:00:00.000Z",
    },
    address: "203.0.113.3",
    knownHostsPath:
      `/tmp/recovery-known-hosts/${binding.requestId}-ram-${binding.bootId}`,
  } as RecoverySshTarget;
  const command = recoveryIsolationArgs(target).join(" ");
  const write = command.match(/--allow-write=([^ ]+)/)?.[1];
  const run = command.match(/--allow-run=([^ ]+)/)?.[1] ?? "";
  assert(write === "/run/uos-recovery");
  assert(run.split(",").includes("ln"));
});

Deno.test("application acceptance requires live Docker and Xvnc evidence", async () => {
  const target = {
    host: {
      requestId: binding.requestId,
      instanceId: binding.instanceId,
      phase: "restored",
      bootId: "881c4067-aec2-45d5-9afb-77ee530e3a97",
      manifestSha256: isolationPlan.restoredManifestSha256,
      publicKey: validPublicKey,
      fingerprint: validFingerprint,
      consoleHistoryId: "ocid1.consolehistory.example",
      consoleCapturedAtUtc: "2026-09-07T04:00:00.000Z",
    },
    address: "203.0.113.3",
    knownHostsPath:
      `/tmp/recovery-known-hosts/${binding.requestId}-restored-881c4067-aec2-45d5-9afb-77ee530e3a97`,
  } as RecoverySshTarget;
  let script = "";
  const acceptance = await checkRestoredApplications(
    target,
    isolationPlan.restoredManifestSha256,
    (_command, args) => {
      script = args.join(" ");
      return Promise.resolve({
        code: 0,
        stdout: "RESTORED_APPLICATIONS_ACCEPTED\n",
        stderr: "",
      });
    },
  );
  assert(script.includes("systemctl is-active --quiet docker.service"));
  assert(script.includes("pgrep -x Xvnc"));
  // The restored root keeps the codex identity without docker-group access, so
  // container inspection must use the already granted non-interactive sudo.
  assert(script.includes("sudo -n docker inspect --format"));
  assert(!script.includes('test "$(docker inspect'));
  assert(script.includes("http://127.0.0.1:8080/guacamole/"));
  assert(!script.includes("codex-remote-daemon.service"));
  assert(acceptance.activeProcesses[0] === "Xvnc");
});

Deno.test("restored reboot reports an explicit command failure", async () => {
  const plan = restoredBootPlan(binding, isolationPlan, inspection, receipt);
  const target = {
    host: {
      requestId: binding.requestId,
      instanceId: binding.instanceId,
      phase: "ram",
      bootId: binding.bootId,
      manifestSha256: "b".repeat(64),
      publicKey: validPublicKey,
      fingerprint: validFingerprint,
      consoleHistoryId: "ocid1.consolehistory.example",
      consoleCapturedAtUtc: "2026-09-07T04:00:00.000Z",
    },
    address: "203.0.113.3",
    knownHostsPath:
      `/tmp/recovery-known-hosts/${binding.requestId}-ram-${binding.bootId}`,
  } as RecoverySshTarget;
  const stream = (value: string) =>
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(value));
        controller.close();
      },
    });
  await rejects(
    requestRestoredBoot(
      target,
      plan,
      {
        planSha256: plan.planSha256,
        exactOperation: RESTORED_BOOT_OPERATION,
        approvedAtUtc: new Date().toISOString(),
      },
      {
        process: () => ({
          stdin: new WritableStream<Uint8Array>(),
          stdout: stream("UOS_RESTORED_BOOT_REQUESTED\n"),
          stderr: stream("sudo: reboot: command not found\n"),
          status: Promise.resolve({
            success: false,
            code: 1,
            signal: null,
          }),
          terminate() {},
        }),
      },
    ),
    "command failed",
  );
});

const RELEASE_SOURCE_URL = new URL(
  "../scripts/pi-recovery-isolation-executor.ts",
  import.meta.url,
);
const READ_RELEASE_SOURCE = (await Deno.permissions.query({
  name: "read",
  path: RELEASE_SOURCE_URL.pathname,
})).state === "granted";
Deno.test({
  name: "copied-root release ID guard admits exact Arch Linux ARM IDs only",
  ignore: !READ_RELEASE_SOURCE,
  fn: async () => {
    // Extract the real inline predicate from the executor source: the regex
    // literal immediately preceding the Os release .test() call. Never
    // duplicate an independent regex that could diverge from production.
    const source = await Deno.readTextFile(RELEASE_SOURCE_URL);
    const argument = source.indexOf("await Deno.readTextFile(osPath)");
    const member = source.lastIndexOf(".test(", argument);
    const open = source.lastIndexOf("!/", member);
    const close = source.lastIndexOf("/m", member);
    if (argument < 0 || member < 0 || open < 0 || close <= open + 2) {
      throw Error("Copied-root release ID guard is absent");
    }
    const id = new RegExp(source.slice(open + 2, close), "m");
    for (const os of [
      "ID=arch\n",
      'ID="arch"\n',
      "ID=archarm\n",
      'ID="archarm"\n',
    ]) {
      assert(id.test(os));
    }
    for (const os of [
      "ID=ubuntu\n",
      "ID=archarm-extra\n",
      'NAME="Arch Linux ARM"\n',
      "ID_LIKE=arch\n",
    ]) {
      assert(!id.test(os));
    }
  },
});

Deno.test({
  name: "isolation links go through the injected runner argv with guards",
  ignore: !READ_RELEASE_SOURCE,
  fn: async () => {
    // Source-bound regression: extract the production writeLink and its apply
    // call sites so the runner argv, destination/type/rename guards and the
    // bound link target literals cannot diverge from the shipped module.
    const source = await Deno.readTextFile(RELEASE_SOURCE_URL);
    const linkStart = source.indexOf("async function writeLink");
    const applyStart = source.indexOf("async function applyInspectedIsolation");
    if (linkStart < 0 || applyStart <= linkStart) {
      throw Error("Copied-root writeLink is absent");
    }
    const body = source.slice(linkStart, applyStart).replaceAll(/\s+/g, " ");
    assert(
      body.includes(
        "async function writeLink( relative: string, target: string, runner: CommandRunner, )",
      ),
    );
    // The injected runner receives an argv array; no shell interpolation can
    // reinterpret the bound link target or the temporary name.
    assert(
      body.includes(
        'await command(runner, "ln", ["-s", "--", target, temporary])',
      ),
    );
    assert(!body.includes("Deno.symlink"));
    assert(!body.includes(".join("));
    assert(!body.includes("bash") && !body.includes("sh -c"));
    // Destination, type-change, unique temporary and atomic rename guards stay.
    assert(
      body.includes("const destination = await below(ROOT, relative, true)"),
    );
    assert(
      body.includes("if (info && !info.isFile && !info.isSymlink)"),
    );
    assert(body.includes("Copied-root mask destination changed type"));
    assert(
      body.includes('destination + ".uos-isolation-" + crypto.randomUUID()'),
    );
    assert(body.includes("await Deno.rename(temporary, destination)"));
    // Every apply call site threads the runner and uses only the two bound
    // link target literals.
    const apply = source.slice(
      applyStart,
      source.indexOf("/** Mount only the serial/UUID-bound"),
    );
    const calls = [...apply.matchAll(/writeLink\(([\s\S]*?)\)/g)].map((match) =>
      match[1].replaceAll(/\s+/g, " ").trim()
    );
    assert(calls.length === 2);
    for (const call of calls) {
      assert(call.endsWith("runner") || call.endsWith("runner,"));
    }
    const quoted = calls.flatMap((call) =>
      [...call.matchAll(/"([^"]*)"/g)].map((match) => match[1])
    );
    assert(quoted.length === 3);
    assert(quoted.includes("/dev/null"));
    assert(quoted.includes("etc/systemd/system/default.target"));
    assert(quoted.includes("/etc/systemd/system/arch-drill.target"));
  },
});
