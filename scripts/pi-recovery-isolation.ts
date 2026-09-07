/** Portable copied-root isolation plan. This module does not mount, write,
 * restart or approve anything. Only bounded configuration reaches the Pi. */
import { createHash } from "node:crypto";
import { copiedRootIsolationFiles } from "./drill-offline-preparation.ts";
import {
  buildRestoreLayout,
  machineRestoreIndexSha256,
  type MachineRestoreInput,
} from "./backblaze-machine-restore.ts";
import { validateRecoveryMetadata } from "./backblaze-verifier.ts";
import type { DiskPreparationBinding } from "./pi-recovery-disk-preparation.ts";
import { rescueManifestSha256 } from "./pi-recovery-bootstrap.ts";
import { hostKeyConsoleCommand } from "./pi-recovery-ssh.ts";

const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
export interface RecoveryIsolationInput {
  preparation: DiskPreparationBinding;
  controllerIpv4: string;
  sshPublicKey: string;
}
export interface RecoveryIsolationPlan {
  schemaVersion: 1;
  binding: DiskPreparationBinding;
  generation: string;
  indexSha256: string;
  rootUuid: string;
  stagingUuid: string;
  kernelSha256: string;
  initramfsSha256: string;
  controllerIpv4: string;
  files: Record<string, string>;
  masks: string[];
  restoredManifestSha256: string;
  prerequisites: {
    inspectMountedCopies: true;
    maskAllCopiedTimers: true;
    replaceCopiedSshHostKeys: true;
    selectIsolatedDefaultTarget: true;
    preserveOracleFallback: true;
    disableAutomaticFallback: true;
  };
  operation:
    "isolate only the reconstructed replacement root before its first restored boot";
  planSha256: string;
}

/** Called on the replacement after validated direct metadata retrieval. The
 * archive metadata itself stays there; the returned plan contains no archive,
 * private key, credential, or copied application data. */
export function recoveryIsolationPlan(
  input: MachineRestoreInput,
  isolation: RecoveryIsolationInput,
): RecoveryIsolationPlan {
  const binding = isolation.preparation;
  if (
    binding.instanceId !== input.target.targetId ||
    binding.instanceId === binding.sourceInstanceId ||
    binding.boot.volumeId === binding.sourceBootVolumeId ||
    binding.root.volumeId === binding.sourceRootVolumeId ||
    binding.boot.path !== input.target.bootDiskPath ||
    binding.root.path !== input.target.rootDiskPath ||
    binding.boot.serial !== input.target.bootDiskSerial ||
    binding.root.serial !== input.target.rootDiskSerial ||
    binding.boot.bytes !== input.target.bootDiskBytes ||
    binding.root.bytes !== input.target.rootDiskBytes ||
    binding.bootId === binding.loaderBootId ||
    rescueManifestSha256({
        requestId: binding.requestId,
        sshPublicKey: isolation.sshPublicKey,
      }) !== binding.rescueManifestSha256
  ) throw Error("Copied-root isolation differs from the accepted replacement");
  const layout = buildRestoreLayout(input.index, input.metadata, input.target);
  const boot = validateRecoveryMetadata(input.metadata, input.index);
  const rules = copiedRootIsolationFiles(isolation.controllerIpv4);
  const rootUuid = layout.filesystems.find((fs) => fs.role === "root")!.uuid;
  const stagingUuid =
    layout.filesystems.find((fs) => fs.role === "staging-boot")!.uuid;
  const manifest = JSON.stringify({
    schemaVersion: 1,
    requestId: binding.requestId,
    instanceId: binding.instanceId,
    phase: "restored",
    generation: input.index.generation,
    indexSha256: machineRestoreIndexSha256(input.index),
    ramBootId: binding.bootId,
    rescueManifestSha256: binding.rescueManifestSha256,
    rootUuid,
    stagingUuid,
    controllerIpv4: isolation.controllerIpv4,
  }) + "\n";
  const restoredManifestSha256 = createHash("sha256").update(manifest).digest(
    "hex",
  );
  const files = {
    ...rules.files,
    "etc/uos-rescue/manifest.json": manifest,
    "etc/uos-rescue/request-id": binding.requestId + "\n",
    "etc/uos-rescue/announce-host.sh": "#!/bin/sh\nset -eu\n" +
      hostKeyConsoleCommand(binding.requestId, "restored") + "\n",
    "etc/systemd/system/arch-drill-firewall.service.d/recovery-host.conf":
      "[Service]\nExecStartPost=/bin/sh /etc/uos-rescue/announce-host.sh\n",
    "home/codex/.ssh/authorized_keys": isolation.sshPublicKey.trim() + "\n",
    "etc/ssh/sshd_config":
      "Port 22\nAddressFamily inet\nHostKey /etc/ssh/ssh_host_ed25519_key\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys\nAllowUsers codex\nUsePAM yes\nAllowAgentForwarding no\nAllowTcpForwarding local\nX11Forwarding no\nPermitTunnel no\n",
  };
  const body = {
    schemaVersion: 1 as const,
    binding: structuredClone(binding),
    generation: input.index.generation,
    indexSha256: machineRestoreIndexSha256(input.index),
    rootUuid,
    stagingUuid,
    kernelSha256: boot.kernelSha256,
    initramfsSha256: boot.initramfsSha256,
    controllerIpv4: isolation.controllerIpv4,
    files,
    masks: rules.masks,
    restoredManifestSha256,
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
  const result = { ...body, planSha256: hash(body) };
  if (new TextEncoder().encode(JSON.stringify(result)).length > 48 * 1024) {
    throw Error("Copied-root isolation plan exceeds the control bound");
  }
  return result;
}

export function validateIsolationPlanDigest(plan: RecoveryIsolationPlan): void {
  const { planSha256, ...body } = plan;
  if (
    plan.schemaVersion !== 1 ||
    plan.operation !==
      "isolate only the reconstructed replacement root before its first restored boot" ||
    !/^[0-9a-f]{64}$/.test(planSha256) || hash(body) !== planSha256
  ) throw Error("Copied-root isolation plan digest differs");
}
