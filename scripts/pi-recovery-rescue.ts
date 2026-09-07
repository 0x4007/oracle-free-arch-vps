/** Read-only RAM-rescue acceptance before any Backblaze archive request.
 * These checks do not clear disks, fix mounts, or approve a reboot. */
import type { MachineRestoreTarget } from "./backblaze-machine-restore.ts";
import { type CommandRunner, defaultRunner } from "./oci.ts";

async function read(
  runner: CommandRunner,
  command: string,
  args: string[],
): Promise<string> {
  const result = await runner(command, args);
  if (result.code !== 0 || result.stdout.length > 1024 * 1024) {
    throw Error("RAM rescue evidence is unavailable");
  }
  return result.stdout.trim();
}

function tmpfsMount(text: string, root: boolean): void {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw Error("Malformed RAM mount evidence");
  }
  if (
    !Array.isArray(value?.filesystems) || value.filesystems.length !== 1 ||
    value.filesystems[0].fstype !== "tmpfs" ||
    root && value.filesystems[0].target !== "/"
  ) {
    throw Error("Recovery runtime and scratch must be on tmpfs");
  }
}

export async function assertRamRescueRuntime(
  target: Pick<MachineRestoreTarget, "targetId" | "workDirectory">,
  requestId: string,
  runner: CommandRunner = defaultRunner,
): Promise<{ bootId: string; requestId: string; ramRuntimeProved: true }> {
  if (
    !/^ocid1\.instance\.[a-zA-Z0-9.]+$/.test(target.targetId) ||
    !/^recovery-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(requestId) ||
    target.workDirectory !== "/run/uos-recovery"
  ) {
    throw Error("RAM rescue target binding is incomplete");
  }
  if (await read(runner, "uname", ["-m"]) !== "aarch64") {
    throw Error("RAM rescue architecture differs");
  }
  if (
    await read(runner, "stat", ["--format=%F:%a", target.workDirectory]) !==
      "directory:700"
  ) {
    throw Error("RAM rescue scratch must be a real private directory");
  }
  const commandLine = await read(runner, "cat", ["/proc/cmdline"]);
  if (
    commandLine.split(/\s+/).some((word) =>
      /^(root|resume|cryptroot|nbd)=/.test(word)
    )
  ) {
    throw Error("Rescue inherited a disk-root or resume argument");
  }
  tmpfsMount(
    await read(runner, "findmnt", [
      "--json",
      "--output",
      "TARGET,FSTYPE",
      "--target",
      "/",
    ]),
    true,
  );
  tmpfsMount(
    await read(runner, "findmnt", [
      "--json",
      "--output",
      "TARGET,FSTYPE",
      "--target",
      target.workDirectory,
    ]),
    false,
  );
  const swaps = await read(runner, "cat", ["/proc/swaps"]);
  if (!/^Filename\s+Type\s+Size\s+Used\s+Priority$/.test(swaps)) {
    throw Error("RAM rescue must have no active swap");
  }
  if (await read(runner, "cat", ["/etc/uos-rescue/request-id"]) !== requestId) {
    throw Error("RAM rescue request marker differs");
  }
  const bootId = await read(runner, "cat", ["/proc/sys/kernel/random/boot_id"]);
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(bootId)) {
    throw Error("RAM rescue boot identity is malformed");
  }
  return { bootId, requestId, ramRuntimeProved: true };
}

import { createHash } from "node:crypto";
import {
  RESCUE_DIRECTORY,
  rescueKernelCommandLine,
} from "./pi-recovery-bootstrap.ts";
import { shellQuote } from "./backup-guest.ts";

export interface RescueBootBinding {
  requestId: string;
  instanceId: string;
  bootVolumeId: string;
  rootVolumeId: string;
  sourceBootId: string;
  kernelSha256: string;
  initramfsSha256: string;
}
const BOOT_OPERATION =
  "gracefully reboot the bound replacement loader into the staged Alpine RAM rescue with kexec";
export function rescueBootPlan(binding: RescueBootBinding) {
  if (
    !/^recovery-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(
      binding.requestId,
    ) ||
    !/^ocid1\.instance\.[a-zA-Z0-9.]+$/.test(binding.instanceId) ||
    !/^ocid1\.bootvolume\.[a-zA-Z0-9.]+$/.test(binding.bootVolumeId) ||
    !/^ocid1\.volume\.[a-zA-Z0-9.]+$/.test(binding.rootVolumeId) ||
    !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(
      binding.sourceBootId,
    ) ||
    ![binding.kernelSha256, binding.initramfsSha256].every((v) =>
      /^[a-f0-9]{64}$/.test(v)
    )
  ) {
    throw Error("Rescue reboot binding is incomplete");
  }
  const plan = {
    requestId: binding.requestId,
    instanceId: binding.instanceId,
    bootVolumeId: binding.bootVolumeId,
    rootVolumeId: binding.rootVolumeId,
    sourceBootId: binding.sourceBootId,
    kernelSha256: binding.kernelSha256,
    initramfsSha256: binding.initramfsSha256,
    directory: RESCUE_DIRECTORY,
    commandLine: rescueKernelCommandLine(),
    operation: BOOT_OPERATION,
  };
  return {
    ...plan,
    planSha256: createHash("sha256").update(JSON.stringify(plan)).digest("hex"),
  };
}

/** Produce a separately approved reboot command for SSH as codex + sudo.
 * This builder does not execute it. The Pi must persist the reboot intent first,
 * verify the target host key from OCI console evidence, and prove a new RAM boot
 * afterward; a scheduled shutdown or SSH disconnect is not acceptance.
 */
export function approvedRescueBootScript(binding: RescueBootBinding, approval: {
  approvedAtUtc: string;
  planSha256: string;
  exactOperation: string;
}, now = Date.now()): string {
  const plan = rescueBootPlan(binding);
  const approvedAt = Date.parse(approval?.approvedAtUtc);
  if (
    !approval || approval.planSha256 !== plan.planSha256 ||
    approval.exactOperation !== BOOT_OPERATION ||
    !Number.isFinite(approvedAt) || approvedAt > now ||
    now - approvedAt > 3600000
  ) {
    throw Error("Current exact rescue reboot approval is required");
  }
  return `#!/bin/bash
set -euo pipefail
test "$(id -u)" = 0
test "$(uname -m)" = aarch64
rescue_now=$(date -u +%s)
test "$rescue_now" -ge ${Math.floor(approvedAt / 1000)}
test "$rescue_now" -le ${Math.floor((approvedAt + 3600000) / 1000)}
test "$(cat /proc/sys/kernel/random/boot_id)" = ${shellQuote(plan.sourceBootId)}
test "$(findmnt -n -o FSTYPE --target ${RESCUE_DIRECTORY})" = tmpfs
curl --fail --silent --show-error --max-time 10 -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/ | jq -e --arg instance ${
    shellQuote(plan.instanceId)
  } --arg request ${
    shellQuote(plan.requestId)
  } '.id == $instance and .freeformTags.uosRecoveryRequest == $request' >/dev/null
test "$(cat ${RESCUE_DIRECTORY}/kernel-command-line)" = ${
    shellQuote(plan.commandLine)
  }
printf '%s  %s\\n' '${plan.kernelSha256}' '${RESCUE_DIRECTORY}/vmlinuz-rescue' '${plan.initramfsSha256}' '${RESCUE_DIRECTORY}/initramfs-rescue' | sha256sum -c -
# Prevent the distribution's optional kexec-load service replacing this image.
grep -qx 'LOAD_KEXEC=false' /etc/default/kexec
kexec --load '${RESCUE_DIRECTORY}/vmlinuz-rescue' --initrd='${RESCUE_DIRECTORY}/initramfs-rescue' --command-line=${
    shellQuote(plan.commandLine)
  }
test "$(cat /sys/kernel/kexec_loaded)" = 1
sync
systemctl --no-block kexec
`;
}
