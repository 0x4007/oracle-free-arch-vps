/** Post-restore acceptance for a replacement machine.
 *
 * The Pi sends only bounded control records. Isolation writes and the restored
 * boot each have a separate exact approval; SSH/application checks are
 * read-only evidence after the target's own disk boot.
 */
import { createHash } from "node:crypto";
import type { CommandRunner } from "./oci.ts";
import {
  defaultProcessFactory,
  type RecoveryTargetProcess,
  type RecoveryTargetProcessFactory,
} from "./pi-recovery-restore.ts";
import {
  type IsolationExecutionApproval,
  type IsolationExecutionReceipt,
  type IsolationInspection,
  validateIsolationExecutionApproval,
  validateIsolationInspection,
} from "./pi-recovery-isolation-executor.ts";
import {
  type RecoveryIsolationPlan,
  validateIsolationPlanDigest,
} from "./pi-recovery-isolation.ts";
import {
  recoveryControlRunner,
  recoverySshArgs,
  type RecoverySshTarget,
  type VerifiedRecoveryHost,
} from "./pi-recovery-ssh.ts";
import type { CheckpointBinding } from "./pi-recovery-checkpoint.ts";

const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
export const RESTORED_BOOT_OPERATION =
  "boot the isolated replacement from its reconstructed disks after direct Backblaze restoration";
export { validateIsolationExecutionApproval };
export const APPLICATION_ACCEPTANCE_OPERATION =
  "check SSH, mounts, recovery identity and required restored applications on the replacement";

export interface RestoredBootApproval {
  planSha256: string;
  exactOperation: string;
  approvedAtUtc: string;
}
export interface RestoredBootPlan {
  schemaVersion: 1;
  binding: CheckpointBinding;
  isolationPlanSha256: string;
  inspectionSha256: string;
  isolationHostPublicKey: string;
  operation: typeof RESTORED_BOOT_OPERATION;
  planSha256: string;
}
export interface IsolationApplyPorts {
  process?: RecoveryTargetProcessFactory;
  beforeMutation?: () => Promise<void>;
  event?: (value: unknown) => Promise<void>;
}
export interface RestoredBootPorts {
  process?: RecoveryTargetProcessFactory;
  beforeMutation?: () => Promise<void>;
}
export interface RestoredApplicationAcceptance {
  status: "RESTORED_APPLICATIONS_ACCEPTED";
  host: VerifiedRecoveryHost;
  manifestSha256: string;
  architecture: "aarch64";
  rootFilesystem: string;
  requiredPaths: string[];
  activeServices: string[];
  activeProcesses: string[];
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
export function validateRestoredBootApproval(
  plan: RestoredBootPlan,
  approval: RestoredBootApproval | undefined,
  now = Date.now(),
) {
  const age = now - Date.parse(approval?.approvedAtUtc ?? "");
  if (
    !approval || approval.planSha256 !== plan.planSha256 ||
    approval.exactOperation !== RESTORED_BOOT_OPERATION ||
    !Number.isFinite(age) || age < 0 || age > 3600000
  ) throw Error("Current exact restored-boot approval is required");
}

export function restoredBootPlan(
  binding: CheckpointBinding,
  isolationPlan: RecoveryIsolationPlan,
  inspection: IsolationInspection,
  receipt: IsolationExecutionReceipt,
): RestoredBootPlan {
  validateIsolationPlanDigest(isolationPlan);
  validateIsolationInspection(inspection, isolationPlan);
  if (
    receipt.status !== "COPIED_ROOT_ISOLATION_APPLIED" ||
    receipt.planSha256 !== isolationPlan.planSha256 ||
    receipt.inspectionSha256 !== inspection.inspectionSha256 ||
    receipt.mountsReleased !== true ||
    receipt.bootAccepted !== false || receipt.applicationAccepted !== false ||
    !/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?$/.test(
      receipt.hostPublicKey,
    )
  ) throw Error("Isolation receipt is not ready for restored boot");
  if (
    binding.instanceId !== isolationPlan.binding.instanceId ||
    binding.bootId !== isolationPlan.binding.bootId ||
    binding.generation !== isolationPlan.generation
  ) throw Error("Restored boot binding differs from isolation");
  const body = {
    schemaVersion: 1 as const,
    binding: structuredClone(binding),
    isolationPlanSha256: isolationPlan.planSha256,
    inspectionSha256: inspection.inspectionSha256,
    isolationHostPublicKey: receipt.hostPublicKey,
    operation: RESTORED_BOOT_OPERATION as typeof RESTORED_BOOT_OPERATION,
  };
  return { ...body, planSha256: hash(body) };
}

export function recoveryIsolationArgs(target: RecoverySshTarget): string[] {
  const command = [
    "cd",
    " /run/uos-recovery/restore",
    "&&",
    "exec",
    "sudo",
    "-n",
    "deno",
    "run",
    "--allow-read=/run/uos-recovery,/etc,/proc,/sys,/dev",
    "--allow-write=/run/uos-recovery",
    "--allow-sys=uid",
    "--allow-run=curl,lsblk,readlink,udevadm,findmnt,mount,umount,ssh-keygen,sha256sum,sync,bash,sh,cat,stat,uname",
    "scripts/pi-recovery-isolation-executor.ts",
  ].join(" ");
  return recoverySshArgs(target, "bash", ["-ec", command]);
}

async function bounded(stream: ReadableStream<Uint8Array>, limit: number) {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.byteLength;
    if (size > limit) {
      throw Error("Recovery acceptance output exceeds its bound");
    }
    chunks.push(chunk);
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(result);
}

async function deadline<T>(
  process: RecoveryTargetProcess,
  work: Promise<T>,
  milliseconds: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          process.terminate();
          reject(Error("Recovery acceptance exceeded its deadline"));
        }, milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function applyCopiedRootIsolation(
  target: RecoverySshTarget,
  plan: RecoveryIsolationPlan,
  inspection: IsolationInspection,
  approval: IsolationExecutionApproval | undefined,
  ports: IsolationApplyPorts = {},
): Promise<IsolationExecutionReceipt> {
  validateIsolationPlanDigest(plan);
  validateIsolationInspection(inspection, plan);
  if (
    target.host.phase !== "ram" ||
    target.host.instanceId !== plan.binding.instanceId
  ) {
    throw Error("Isolation SSH target differs from the accepted RAM binding");
  }
  if (!approval) {
    throw Error("Current exact copied-root isolation approval is required");
  }
  validateIsolationExecutionApproval(plan, inspection, approval);
  await ports.beforeMutation?.();
  const process = (ports.process ?? defaultProcessFactory)(
    "ssh",
    recoveryIsolationArgs(target),
  );
  const output = await deadline(
    process,
    Promise.all([
      bounded(process.stdout, 256 * 1024),
      bounded(process.stderr, 64 * 1024),
      process.status,
      (async () => {
        const writer = process.stdin.getWriter();
        try {
          await writer.write(
            bytes(JSON.stringify({ plan, inspection, approval })),
          );
          await writer.close();
        } finally {
          writer.releaseLock();
        }
      })(),
    ]),
    10 * 60 * 1000,
  );
  const lines = output[0].trim().split("\n").filter(Boolean).map((line) =>
    JSON.parse(line)
  );
  for (const line of lines) {
    if (line?.kind === "recovery-isolation-event") {
      await ports.event?.(line.event);
    }
  }
  const final = lines.find((line) =>
    line?.kind === "recovery-isolation-result"
  );
  const receipt = final?.result?.receipt as
    | IsolationExecutionReceipt
    | undefined;
  if (
    output[2].code !== 0 || !receipt ||
    receipt.status !== "COPIED_ROOT_ISOLATION_APPLIED" ||
    receipt.planSha256 !== plan.planSha256 ||
    receipt.inspectionSha256 !== inspection.inspectionSha256 ||
    receipt.mountsReleased !== true
  ) throw Error("Copied-root isolation did not complete successfully");
  return receipt;
}

function bootArgs(target: RecoverySshTarget): string[] {
  const command =
    "printf 'UOS_RESTORED_BOOT_REQUESTED\\n'; sync; sudo -n reboot";
  return recoverySshArgs(target, "sh", ["-ec", command]);
}

export async function requestRestoredBoot(
  target: RecoverySshTarget,
  plan: RestoredBootPlan,
  approval: RestoredBootApproval | undefined,
  ports: RestoredBootPorts = {},
): Promise<"RESTORED_BOOT_REQUESTED"> {
  const { planSha256, ...body } = plan;
  if (hash(body) !== planSha256 || plan.operation !== RESTORED_BOOT_OPERATION) {
    throw Error("Restored boot plan digest differs");
  }
  validateRestoredBootApproval(plan, approval);
  if (
    target.host.phase !== "ram" || target.host.bootId !== plan.binding.bootId
  ) {
    throw Error("Restored boot requires the accepted RAM host");
  }
  await ports.beforeMutation?.();
  const process = (ports.process ?? defaultProcessFactory)(
    "ssh",
    bootArgs(target),
  );
  const input = process.stdin.getWriter();
  await input.close();
  input.releaseLock();
  const [stdout, stderr, status] = await deadline(
    process,
    Promise.all([
      bounded(process.stdout, 16 * 1024),
      bounded(process.stderr, 64 * 1024),
      process.status,
    ]),
    60_000,
  );
  const marker = stdout.split("\n").some((line) =>
    line.trim() === "UOS_RESTORED_BOOT_REQUESTED"
  );
  const explicitFailure =
    /(?:command not found|permission denied|not permitted|sudo:.*(?:failed|unknown|cannot))/i
      .test(stderr);
  if (status.code !== 0 && explicitFailure) {
    process.terminate();
    throw Error("Restored boot command failed");
  }
  if (!marker || status.code !== 0) {
    process.terminate();
    throw Error(
      marker
        ? "Restored boot response uncertain; inspect the retained intent"
        : "Restored boot request response was uncertain; inspect the retained intent",
    );
  }
  process.terminate();
  return "RESTORED_BOOT_REQUESTED";
}

const ACCEPTANCE_COMMAND = `set -eu
test "$(uname -m)" = aarch64
test "$(findmnt -n -o FSTYPE --target /)" = ext4
test -f /etc/uos-rescue/manifest.json
test "$(sha256sum /etc/uos-rescue/manifest.json | cut -d' ' -f1)" = "$1"
systemctl is-active --quiet sshd.service
systemctl is-active --quiet arch-drill-firewall.service
systemctl is-active --quiet docker.service
pgrep -x Xvnc >/dev/null
for container in guacamole-trial-guacamole-1 guacamole-trial-guacd-1; do
  test "$(docker inspect --format '{{.State.Running}}' "$container")" = true
done
page="$(curl --fail --silent --show-error --max-time 15 http://127.0.0.1:8080/guacamole/)"
case "$page" in *guacamole*) ;; *) exit 1 ;; esac
case "$page" in *ng-app*) ;; *) exit 1 ;; esac
for path in /usr/bin/docker /usr/local/bin/deno /usr/bin/Xvnc; do test -x "$path"; done
printf '%s\\n' RESTORED_APPLICATIONS_ACCEPTED`;

export async function checkRestoredApplications(
  target: RecoverySshTarget,
  manifestSha256: string,
  runner: CommandRunner = recoveryControlRunner,
): Promise<RestoredApplicationAcceptance> {
  if (
    target.host.phase !== "restored" ||
    target.host.manifestSha256 !== manifestSha256
  ) {
    throw Error("Restored SSH host is not bound to the accepted manifest");
  }
  const result = await runner(
    "ssh",
    recoverySshArgs(target, "bash", [
      "-ec",
      ACCEPTANCE_COMMAND,
      "--",
      manifestSha256,
    ]),
  );
  if (
    result.code !== 0 ||
    result.stdout.trim() !== "RESTORED_APPLICATIONS_ACCEPTED"
  ) {
    throw Error("Restored SSH/application acceptance failed");
  }
  return {
    status: "RESTORED_APPLICATIONS_ACCEPTED",
    host: target.host,
    manifestSha256,
    architecture: "aarch64",
    rootFilesystem: "ext4",
    requiredPaths: [
      "/usr/bin/docker",
      "/usr/local/bin/deno",
      "/usr/bin/Xvnc",
    ],
    activeServices: [
      "sshd.service",
      "arch-drill-firewall.service",
      "docker.service",
    ],
    activeProcesses: ["Xvnc"],
  };
}
