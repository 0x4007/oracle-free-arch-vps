import {
  buildRescueCloudInit,
  rescueAssemblerScript,
  rescueKernelCommandLine,
  rescueOverlayFiles,
} from "../scripts/pi-recovery-bootstrap.ts";
import {
  approvedRescueBootScript,
  assertRamRescueRuntime,
  type RescueBootBinding,
  rescueBootPlan,
} from "../scripts/pi-recovery-rescue.ts";
import type { CommandRunner } from "../scripts/oci.ts";
function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
function refuses(run: () => unknown) {
  let failed = false;
  try {
    run();
  } catch {
    failed = true;
  }
  assert(failed);
}
async function rejects(run: () => Promise<unknown>, fragment: string) {
  try {
    await run();
  } catch (e) {
    assert(String(e).includes(fragment));
    return;
  }
  throw Error("Expected refusal");
}
const requestId = "recovery-681c4067-aec2-45d5-9afb-77ee530e3a97";
const bytes = new Uint8Array(51);
const view = new DataView(bytes.buffer);
view.setUint32(0, 11);
bytes.set(new TextEncoder().encode("ssh-ed25519"), 4);
view.setUint32(15, 32);
bytes.fill(1, 19);
const sshPublicKey = "ssh-ed25519 " + btoa(String.fromCharCode(...bytes)) +
  " synthetic-test-key";
const input = { requestId, sshPublicKey };
const target = {
  targetId: "ocid1.instance.example",
  workDirectory: "/run/uos-recovery",
};
const binding: RescueBootBinding = {
  requestId,
  instanceId: target.targetId,
  bootVolumeId: "ocid1.bootvolume.example",
  rootVolumeId: "ocid1.volume.example",
  sourceBootId: "781c4067-aec2-45d5-9afb-77ee530e3a97",
  kernelSha256: "a".repeat(64),
  initramfsSha256: "b".repeat(64),
};
Deno.test("rescue reboot approval binds resource identities, boot identity and staged bytes", () => {
  const plan = rescueBootPlan(binding);
  const now = Date.now();
  const approval = {
    approvedAtUtc: new Date(now).toISOString(),
    planSha256: plan.planSha256,
    exactOperation: plan.operation,
  };
  const script = approvedRescueBootScript(binding, approval, now);
  assert(script.includes("systemctl --no-block kexec"));
  assert(
    !script.includes("kexec --exec") && !script.includes("--reuse-cmdline"),
  );
  for (
    const field of [
      "requestId",
      "instanceId",
      "bootVolumeId",
      "rootVolumeId",
      "sourceBootId",
      "kernelSha256",
      "initramfsSha256",
    ] as const
  ) {
    refuses(() =>
      approvedRescueBootScript(
        { ...binding, [field]: binding[field] + "changed" },
        approval,
        now,
      )
    );
  }
  refuses(() =>
    approvedRescueBootScript(binding, {
      ...approval,
      approvedAtUtc: new Date(now - 3600001).toISOString(),
    }, now)
  );
  refuses(() =>
    approvedRescueBootScript(binding, {
      ...approval,
      approvedAtUtc: new Date(now + 1).toISOString(),
    }, now)
  );
  refuses(() =>
    approvedRescueBootScript(binding, {
      ...approval,
      exactOperation: "provision",
    }, now)
  );
});
Deno.test("bootstrap rejects private keys, malformed public keys and injected identity", () => {
  for (
    const key of [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "ssh-ed25519 AAAA",
      sshPublicKey + "\ncommand=evil",
    ]
  ) refuses(() => rescueOverlayFiles({ ...input, sshPublicKey: key }));
  refuses(() =>
    rescueOverlayFiles({ ...input, requestId: requestId + ";reboot" })
  );
});
Deno.test("RAM command line cannot inherit source root or a home overlay URL", () => {
  const words = rescueKernelCommandLine().split(" ");
  assert(
    !words.some((v) =>
      /^(root|resume|cryptroot|nbd)=/.test(v) || v === "--reuse-cmdline"
    ),
  );
  assert(words.includes("apkovl=/uos-rescue.apkovl.tar.gz"));
  assert(
    words.some((v) =>
      v.startsWith("alpine_repo=https://dl-cdn.alpinelinux.org/")
    ),
  );
});
Deno.test("rescue account requires RAM and non-root public-key SSH", () => {
  const files = rescueOverlayFiles(input);
  const get = (path: string) => files.find((f) => f.path === path)!.content;
  assert(get("etc/ssh/sshd_config").includes("PermitRootLogin no\n"));
  assert(get("etc/ssh/sshd_config").includes("PasswordAuthentication no\n"));
  assert(get("etc/ssh/sshd_config").includes("AllowUsers codex\n"));
  assert(get("etc/conf.d/sshd").includes("uos-rescue-account"));
  assert(!get("etc/init.d/uos-rescue-account").includes("chown -R"));
  assert(
    get("etc/init.d/uos-rescue-account").indexOf("= tmpfs") <
      get("etc/init.d/uos-rescue-account").indexOf("adduser"),
  );
  assert(
    files.every((f) =>
      !f.path.startsWith("/") && !f.path.split("/").includes("..")
    ),
  );
});
Deno.test("assembler verifies signed archive before unpacking and never reboots or wipes", () => {
  const script = rescueAssemblerScript(input);
  assert(script.indexOf("sha256sum -c") < script.indexOf("tar -xzf"));
  assert(script.indexOf("gpgv --homedir") < script.indexOf("tar -xzf"));
  assert(script.includes("lib/modloop-virt"));
  assert(script.includes("cpio --quiet -o --format=newc"));
  assert(!/^\s*(?:sudo )?(?:kexec|reboot|wipefs|sfdisk)\b/m.test(script));
  assert(script.includes("rebooted:false,disksPrepared:false"));
});
const allowedRead =
  (await Deno.permissions.query({ name: "read" })).state === "granted";
Deno.test({
  name: "generated cloud-init fits existing private provisioning interface",
  ignore: !allowedRead,
  fn: async () => {
    const text = await buildRescueCloudInit(input);
    assert(text.startsWith("#cloud-config\n"));
    assert(new TextEncoder().encode(text).length <= 32000);
    const config = JSON.parse(text.slice("#cloud-config\n".length));
    assert(config.disable_root === true && config.ssh_pwauth === false);
    assert(config.users.length === 1 && config.users[0].name === "codex");
    assert(
      config.runcmd.length === 1 &&
        config.runcmd[0][0] === "/usr/local/sbin/uos-prepare-ram-rescue",
    );
  },
});
const allowedRun =
  (await Deno.permissions.query({ name: "run", command: "bash" })).state ===
    "granted";
Deno.test({
  name: "generated assembler and account scripts pass actual shell parsing",
  ignore: !allowedRun,
  fn: async () => {
    for (
      const script of [
        rescueAssemblerScript(input),
        rescueOverlayFiles(input).find((f) =>
          f.path === "etc/init.d/uos-rescue-account"
        )!.content,
        rescueOverlayFiles(input).find((f) =>
          f.path === "etc/init.d/uos-rescue-network"
        )!.content,
        approvedRescueBootScript(binding, {
          approvedAtUtc: new Date().toISOString(),
          planSha256: rescueBootPlan(binding).planSha256,
          exactOperation: rescueBootPlan(binding).operation,
        }),
      ]
    ) {
      const child = new Deno.Command("bash", {
        args: ["-n"],
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
      }).spawn();
      const output = child.output();
      const writer = child.stdin.getWriter();
      await writer.write(new TextEncoder().encode(script));
      await writer.close();
      const result = await output;
      if (!result.success) throw Error(new TextDecoder().decode(result.stderr));
    }
  },
});
function runtime(change: Record<string, string> = {}): CommandRunner {
  const facts: Record<string, string> = {
    "uname -m": "aarch64",
    "stat --format=%F:%a /run/uos-recovery": "directory:700",
    "cat /proc/cmdline": rescueKernelCommandLine(),
    "findmnt --json --output TARGET,FSTYPE --target /": JSON.stringify({
      filesystems: [{ target: "/", fstype: "tmpfs" }],
    }),
    "findmnt --json --output TARGET,FSTYPE --target /run/uos-recovery": JSON
      .stringify({ filesystems: [{ target: "/run", fstype: "tmpfs" }] }),
    "cat /proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n",
    "cat /etc/uos-rescue/request-id": requestId,
    "cat /proc/sys/kernel/random/boot_id":
      "781c4067-aec2-45d5-9afb-77ee530e3a97",
    ...change,
  };
  return (command, args) => {
    const key = [command, ...args].join(" ");
    assert(key in facts);
    return Promise.resolve({ code: 0, stdout: facts[key], stderr: "" });
  };
}
Deno.test("RAM runtime provides its boot ID only after every read-only check", async () => {
  const result = await assertRamRescueRuntime(target, requestId, runtime());
  assert(
    result.ramRuntimeProved &&
      result.bootId === "781c4067-aec2-45d5-9afb-77ee530e3a97",
  );
});
Deno.test("running from a platform disk or disk-backed scratch refuses", async () => {
  for (const path of ["/", "/run/uos-recovery"]) {
    await rejects(() =>
      assertRamRescueRuntime(
        target,
        requestId,
        runtime({
          ["findmnt --json --output TARGET,FSTYPE --target " + path]: JSON
            .stringify({ filesystems: [{ target: path, fstype: "ext4" }] }),
        }),
      ), "tmpfs");
  }
});
Deno.test("symlink or public scratch refuses before metadata download", async () => {
  for (
    const value of ["symbolic link:777", "directory:755", "regular file:700"]
  ) {
    await rejects(() =>
      assertRamRescueRuntime(
        target,
        requestId,
        runtime({
          "stat --format=%F:%a /run/uos-recovery": value,
        }),
      ), "private directory");
  }
});
Deno.test("swap and inherited root/resume arguments refuse", async () => {
  await rejects(
    () =>
      assertRamRescueRuntime(
        target,
        requestId,
        runtime({
          "cat /proc/swaps":
            "Filename Type Size Used Priority\n/dev/sda2 partition 4096 0 -2",
        }),
      ),
    "no active swap",
  );
  for (
    const arg of [
      "root=/dev/sda2",
      "resume=UUID=foo",
      "cryptroot=foo",
      "nbd=server",
    ]
  ) {
    await rejects(() =>
      assertRamRescueRuntime(
        target,
        requestId,
        runtime({ "cat /proc/cmdline": "ip=dhcp " + arg }),
      ), "inherited");
  }
});
Deno.test("wrong architecture, request marker and malformed mount evidence refuse", async () => {
  await rejects(
    () =>
      assertRamRescueRuntime(
        target,
        requestId,
        runtime({ "uname -m": "armv7l" }),
      ),
    "architecture",
  );
  await rejects(
    () =>
      assertRamRescueRuntime(
        target,
        requestId,
        runtime({ "cat /etc/uos-rescue/request-id": "different" }),
      ),
    "marker",
  );
  await rejects(
    () =>
      assertRamRescueRuntime(
        target,
        requestId,
        runtime({ "findmnt --json --output TARGET,FSTYPE --target /": "{}" }),
      ),
    "tmpfs",
  );
});
Deno.test("wrong scratch path refuses before commands", async () => {
  await rejects(
    () =>
      assertRamRescueRuntime(
        { ...target, workDirectory: "/home/pi/restore" },
        requestId,
        () => {
          throw Error("must not run");
        },
      ),
    "binding",
  );
});
