/** Pi entry point for replacement provisioning and the loader-to-RAM handoff.
 * Payload downloads execute only on the replacement. This journal never treats
 * a reboot command, disconnect, or RAM acceptance as a restored application.
 */
import { createHash } from "node:crypto";
import { withBackupLock } from "./backup-lock.ts";
import { backupControllerEvidence } from "./backup-controller-evidence.ts";
import {
  assertOracleMutationAllowed,
  readGate,
} from "./backblaze-controller-gate.ts";
import type { BackupInventoryConfig } from "./oci-backup-inventory.ts";
import {
  type CommandRunner,
  dataArray,
  dataObject,
  readPrivateJson,
  runJson,
  writePrivateJson,
} from "./oci.ts";
import {
  type ReplacementConfig,
  replacementPlanDigest,
  type ReplacementState,
  runReplacement,
} from "./pi-machine-recovery.ts";
import {
  buildRescueCloudInit,
  RESCUE_DIRECTORY,
  rescueManifestSha256,
} from "./pi-recovery-bootstrap.ts";
import {
  type ConsoleCaptureApproval,
  type ConsoleCapturePlan,
  consoleCapturePlan,
  type ConsoleCaptureState,
  ConsoleConnectionRequiredError,
  recoveryConsolePorts,
  stepConsoleCapture,
} from "./pi-recovery-console.ts";
import {
  assertRetainedProviderBinding,
  captureLoaderDiskIdentity,
  type LoaderDiskIdentity,
  type LoaderIdentityRequest,
  type LoaderProviderEvidence,
  preparationBindingFromLoader,
} from "./pi-recovery-disk-identity.ts";
import {
  approvedRescueBootScript,
  assertAcceptedRescueBoot,
  type RescueBootBinding,
  rescueBootPlan,
} from "./pi-recovery-rescue.ts";
import {
  recoveryControlRunner,
  recoverySshRunner,
  type RecoverySshTarget,
  retainRecoveryHost,
} from "./pi-recovery-ssh.ts";
import {
  buildRecoveryTargetBundle,
  continueReplacementRestoration,
  type RecoveryRestorationState,
  type RecoveryTargetControlInput,
  type RecoveryTargetInstallApproval,
} from "./pi-recovery-restore.ts";
import type { PreparationApproval } from "./pi-recovery-disk-preparation.ts";
import type { B2Settings } from "./backblaze-storage.ts";
import { validateCatalogEntry } from "./backblaze-file-backup.ts";
import {
  type ConsoleConnectionApproval,
  consoleConnectionPlan,
  type ConsoleConnectionState,
  stepConsoleConnection,
} from "./pi-recovery-console-connection.ts";

const CONFIG = ".private/pi-machine-recovery.json";
const STATE = ".private/pi-recovery-session.json";
const REPORT = ".private/reports/pi-recovery-session.json";
type RebootApproval = Parameters<typeof approvedRescueBootScript>[1];
interface SessionConfig extends ReplacementConfig {
  /** Existing RSA public key; no private key or new credential is generated. */
  consolePublicKey?: string;
  sessionApprovals?: {
    consoleConnection?: ConsoleConnectionApproval;
    loaderConsole?: ConsoleCaptureApproval;
    ramConsole?: ConsoleCaptureApproval;
    rescueReboot?: RebootApproval;
    restoreInstallation?: RecoveryTargetInstallApproval;
    diskPreparation?: PreparationApproval;
  };
}
export interface RecoverySession {
  schemaVersion: 1;
  requestId: string;
  replacementPlanSha256: string;
  instanceId: string;
  manifestSha256: string;
  startedAtUtc: string;
  loaderConsole?: ConsoleCaptureState;
  loaderIdentity?: LoaderDiskIdentity;
  stagedBoot?: RescueBootBinding;
  rebootIntent?: { planSha256: string; intendedAtUtc: string };
  ramConsole?: ConsoleCaptureState;
  ramAccepted?: { bootId: string; acceptedAtUtc: string };
  consoleConnection?: ConsoleConnectionState;
}
export interface SessionPorts {
  now: () => number;
  persist: (state: RecoverySession) => Promise<void>;
  report: (value: unknown) => Promise<void>;
  capture: (
    plan: ConsoleCapturePlan,
    state: ConsoleCaptureState,
    phase: "loader" | "ram",
  ) => Promise<ConsoleCaptureState | undefined>;
  target: (state: ConsoleCaptureState) => Promise<RecoverySshTarget>;
  ssh: (target: RecoverySshTarget) => CommandRunner;
  provider: () => Promise<LoaderProviderEvidence>;
  beforeMutation: () => Promise<void>;
  rebootApproval: () => Promise<RebootApproval | undefined>;
}
const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");

/** One bounded handoff step. A durable reboot intent is never automatically
 * replayed; later calls observe console evidence for the next boot instead.
 */
export async function stepRecoverySession(
  state: RecoverySession,
  request: LoaderIdentityRequest,
  compartmentId: string,
  ports: SessionPorts,
): Promise<string> {
  if (
    state.schemaVersion !== 1 || state.requestId !== request.requestId ||
    state.instanceId !== request.instanceId ||
    !/^[0-9a-f]{64}$/.test(state.manifestSha256) ||
    !/^[0-9a-f]{64}$/.test(state.replacementPlanSha256) ||
    !Number.isFinite(Date.parse(state.startedAtUtc)) ||
    request.instanceId === request.sourceInstanceId
  ) {
    throw Error("Recovery session binding differs");
  }
  const save = () => ports.persist(structuredClone(state));
  const phase = state.rebootIntent ? "ram" : "loader";
  if (
    phase === "ram" &&
    (!state.loaderIdentity || !state.stagedBoot ||
      state.rebootIntent!.planSha256 !==
        rescueBootPlan(state.stagedBoot).planSha256)
  ) {
    throw Error("Recovery reboot intent has no matching staged identity");
  }
  const plan = consoleCapturePlan({
    requestId: request.requestId,
    instanceId: request.instanceId,
    phase,
    notBeforeUtc: state.rebootIntent?.intendedAtUtc ?? state.startedAtUtc,
    ...(phase === "ram"
      ? {
        previousBootId: state.loaderIdentity!.loaderBootId,
        manifestSha256: state.manifestSha256,
      }
      : {}),
  }, compartmentId);
  const field = phase === "ram" ? "ramConsole" : "loaderConsole";
  if (!state[field]) {
    state[field] = { planSha256: plan.planSha256, attempts: [] };
    await save();
  }
  const captured = await ports.capture(plan, state[field]!, phase);
  if (!captured) {
    await ports.report({ status: "CONSOLE_APPROVAL_REQUIRED", phase, plan });
    return "CONSOLE_APPROVAL_REQUIRED";
  }
  state[field] = captured;
  await save();
  if (!captured.host) return "CONSOLE_PENDING";
  const target = await ports.target(captured);
  const runner = ports.ssh(target);
  if (phase === "ram") {
    // Revalidate the retained disk receipt before deriving any destructive plan.
    preparationBindingFromLoader(
      state.loaderIdentity!,
      captured.host.bootId,
      state.manifestSha256,
    );
    const accepted = await assertAcceptedRescueBoot({
      targetId: request.instanceId,
      workDirectory: "/run/uos-recovery",
    }, {
      requestId: request.requestId,
      loaderBootId: state.loaderIdentity!.loaderBootId,
      manifestSha256: state.manifestSha256,
    }, runner);
    if (accepted.bootId !== captured.host.bootId) {
      throw Error("RAM SSH boot differs from console evidence");
    }
    state.ramAccepted = {
      bootId: accepted.bootId,
      acceptedAtUtc: new Date(ports.now()).toISOString(),
    };
    await save();
    await ports.report({
      status: "RAM_RESCUE_ACCEPTED",
      restoreAccepted: false,
      applicationAccepted: false,
    });
    return "RAM_RESCUE_ACCEPTED";
  }
  const identity = await captureLoaderDiskIdentity(
    request,
    ports.provider,
    runner,
  );
  if (identity.loaderBootId !== captured.host.bootId) {
    throw Error("Loader SSH boot differs from console evidence");
  }
  if (state.loaderIdentity) {
    const stable = (v: LoaderDiskIdentity) => {
      const { observedAtUtc: _time, identitySha256: _hash, ...body } = v;
      return hash(body);
    };
    if (stable(identity) !== stable(state.loaderIdentity)) {
      throw Error("Retained loader disk identity changed");
    }
  } else {
    state.loaderIdentity = identity;
    await save();
  }
  const receiptResult = await runner("sudo", [
    "-n",
    "cat",
    `${RESCUE_DIRECTORY}/receipt.json`,
  ]);
  if (receiptResult.code !== 0) return "RESCUE_STAGING_PENDING";
  const receipt = JSON.parse(receiptResult.stdout);
  if (
    receipt.status !== "RAM_RESCUE_STAGED" ||
    receipt.requestId !== request.requestId ||
    receipt.instanceId !== request.instanceId ||
    receipt.sourceBootId !== identity.loaderBootId ||
    receipt.rebooted !== false || receipt.disksPrepared !== false
  ) {
    throw Error("Staged rescue receipt differs from the loader");
  }
  const binding: RescueBootBinding = {
    requestId: request.requestId,
    instanceId: request.instanceId,
    bootVolumeId: request.bootVolumeId,
    rootVolumeId: request.rootVolumeId,
    sourceBootId: identity.loaderBootId,
    kernelSha256: receipt.kernelSha256,
    initramfsSha256: receipt.initramfsSha256,
  };
  const rebootPlan = rescueBootPlan(binding);
  if (state.stagedBoot && hash(state.stagedBoot) !== hash(binding)) {
    throw Error("Staged rescue bytes changed");
  }
  state.stagedBoot = binding;
  await save();
  await ports.report({
    status: "RESCUE_REBOOT_APPROVAL_REQUIRED",
    plan: rebootPlan,
  });
  const approval = await ports.rebootApproval();
  if (!approval) return "RESCUE_REBOOT_APPROVAL_REQUIRED";
  await ports.beforeMutation();
  // Repeat authenticated attachment/guest checks immediately before intent.
  const latest = await captureLoaderDiskIdentity(
    request,
    ports.provider,
    runner,
  );
  if (
    latest.loaderBootId !== identity.loaderBootId ||
    latest.bootAttachmentId !== identity.bootAttachmentId ||
    latest.rootAttachmentId !== identity.rootAttachmentId ||
    hash(latest.boot) !== hash(identity.boot) ||
    hash(latest.root) !== hash(identity.root)
  ) throw Error("Loader changed before reboot");
  const script = approvedRescueBootScript(binding, approval, ports.now());
  state.rebootIntent = {
    planSha256: rebootPlan.planSha256,
    intendedAtUtc: new Date(ports.now()).toISOString(),
  };
  await save();
  await ports.beforeMutation();
  approvedRescueBootScript(
    binding,
    (await ports.rebootApproval())!,
    ports.now(),
  );
  // Lost SSH response leaves the durable intent; never retry the reboot blindly.
  const result = await runner("sudo", ["-n", "bash", "-ec", script]);
  if (result.code !== 0) {
    throw Error(
      "Rescue reboot response uncertain; inspect the retained intent and next boot",
    );
  }
  return "RESCUE_REBOOT_REQUESTED";
}

/** Reject an incompatible bootstrap before allowing the provisioner to run. */
export async function validateSessionBootstrap(config: ReplacementConfig) {
  if (!config.cloudInit.startsWith("#cloud-config\n")) {
    throw Error("Replacement rescue cloud-init is malformed");
  }
  const cloud = JSON.parse(config.cloudInit.slice("#cloud-config\n".length));
  const input = {
    requestId: config.requestId,
    sshPublicKey: cloud.users?.[0]?.ssh_authorized_keys?.[0],
  };
  if (await buildRescueCloudInit(input) !== config.cloudInit) {
    throw Error(
      "Replacement bootstrap differs from the approved rescue implementation",
    );
  }
  return input;
}

export async function runRecoverySession(
  runner: CommandRunner = recoveryControlRunner,
): Promise<void> {
  const initial = await readPrivateJson<SessionConfig>(CONFIG);
  if (initial.action === "provision") await validateSessionBootstrap(initial);
  // Provisioner repeats the bootstrap preflight under its own lock immediately
  // before each cloud mutation, as well as capacity and eligibility checks.
  await runReplacement(runner, undefined, validateSessionBootstrap);
  await withBackupLock(".private/backup-controller.lock", async () => {
    const config = await readPrivateJson<SessionConfig>(CONFIG);
    if (config.action === "plan") return;
    const controller = await readPrivateJson<BackupInventoryConfig>(
      ".private/backup-controller.json",
    );
    const replacement = await readPrivateJson<ReplacementState>(
      ".private/pi-machine-recovery-state.json",
    );
    const digest = replacementPlanDigest(config);
    if (
      replacement.requestId !== config.requestId ||
      replacement.planSha256 !== digest || !replacement.instanceId ||
      !replacement.bootVolumeId || !replacement.rootVolumeId ||
      !replacement.privateIpId
    ) throw Error("Provisioning is not complete for this session");
    const publicInput = await validateSessionBootstrap(config);
    const request: LoaderIdentityRequest = {
      requestId: config.requestId,
      instanceId: replacement.instanceId,
      bootVolumeId: replacement.bootVolumeId,
      rootVolumeId: replacement.rootVolumeId,
      sourceInstanceId: controller.source.instanceId,
      sourceBootVolumeId: controller.source.bootVolumeId,
      sourceRootVolumeId: controller.source.rootVolumeId,
    };
    const json = (args: string[]) =>
      runJson(controller.ociCliPath, [
        "--profile",
        controller.ociProfile,
        "--region",
        controller.source.region,
        "--no-retry",
        "--connection-timeout",
        "10",
        "--read-timeout",
        "60",
        ...args,
      ], runner);
    const provider = async (): Promise<LoaderProviderEvidence> => ({
      instance: dataObject(
        await json([
          "compute",
          "instance",
          "get",
          "--instance-id",
          request.instanceId,
        ]),
      ),
      bootVolume: dataObject(
        await json([
          "bv",
          "boot-volume",
          "get",
          "--boot-volume-id",
          request.bootVolumeId,
        ]),
      ),
      rootVolume: dataObject(
        await json([
          "bv",
          "volume",
          "get",
          "--volume-id",
          request.rootVolumeId,
        ]),
      ),
      bootAttachments: dataArray(
        await json([
          "compute",
          "boot-volume-attachment",
          "list",
          "--compartment-id",
          config.compartmentId,
          "--availability-domain",
          config.availabilityDomain,
          "--instance-id",
          request.instanceId,
          "--all",
        ]),
      ),
      rootAttachments: dataArray(
        await json([
          "compute",
          "volume-attachment",
          "list",
          "--compartment-id",
          config.compartmentId,
          "--instance-id",
          request.instanceId,
          "--all",
        ]),
      ),
    });
    const beforeMutation = async () => {
      assertOracleMutationAllowed(await readGate());
      await backupControllerEvidence(controller, runner)
        .assertNoOtherController();
      const current = await readPrivateJson<SessionConfig>(CONFIG);
      if (
        current.action !== "provision" ||
        replacementPlanDigest(current) !== digest
      ) throw Error("Recovery authority or configuration changed");
    };
    await beforeMutation();
    let state: RecoverySession;
    try {
      state = await readPrivateJson<RecoverySession>(STATE);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
      state = {
        schemaVersion: 1,
        requestId: config.requestId,
        replacementPlanSha256: digest,
        instanceId: request.instanceId,
        manifestSha256: rescueManifestSha256(publicInput),
        startedAtUtc: new Date().toISOString(),
      };
      await writePrivateJson(STATE, state);
    }
    if (
      state.replacementPlanSha256 !== digest ||
      state.manifestSha256 !== rescueManifestSha256(publicInput)
    ) throw Error("Recovery session belongs to another bootstrap or plan");
    const persist = (value: RecoverySession) => writePrivateJson(STATE, value);
    const approvals = async () => {
      const current = await readPrivateJson<SessionConfig>(CONFIG);
      if (
        current.action !== "provision" ||
        replacementPlanDigest(current) !== digest
      ) throw Error("Recovery approval configuration changed");
      return current.sessionApprovals;
    };
    let acceptedTarget: RecoverySshTarget | undefined;
    let status = await stepRecoverySession(
      state,
      request,
      config.compartmentId,
      {
        now: () => Date.now(),
        persist,
        report: (value) => writePrivateJson(REPORT, value),
        provider,
        beforeMutation,
        rebootApproval: async () => (await approvals())?.rescueReboot,
        ssh: recoverySshRunner,
        target: async (capture) => {
          const address = dataObject(
            await json([
              "network",
              "public-ip",
              "get",
              "--public-ip-id",
              config.reservedPublicIpId,
            ]),
          );
          if (
            address["private-ip-id"] !== replacement.privateIpId ||
            address["lifecycle-state"] !== "ASSIGNED" ||
            typeof address["ip-address"] !== "string"
          ) throw Error("Replacement public address changed");
          const privateIp = dataObject(
            await json([
              "network",
              "private-ip",
              "get",
              "--private-ip-id",
              replacement.privateIpId!,
            ]),
          );
          const attachments = dataArray(
            await json([
              "compute",
              "vnic-attachment",
              "list",
              "--compartment-id",
              config.compartmentId,
              "--instance-id",
              request.instanceId,
              "--all",
            ]),
          );
          if (
            !attachments.some((a) =>
              a["lifecycle-state"] === "ATTACHED" &&
              a["instance-id"] === request.instanceId &&
              a["vnic-id"] === privateIp["vnic-id"]
            )
          ) throw Error("Public address is not attached to the replacement");
          acceptedTarget = await retainRecoveryHost(
            capture.host!,
            address["ip-address"],
          );
          return acceptedTarget;
        },
        capture: async (plan, captureState, phase) => {
          const key = phase === "loader" ? "loaderConsole" : "ramConsole";
          const approval = (await approvals())?.[key];
          if (
            !approval && !captureState.host &&
            captureState.attempts.length === 0
          ) return undefined;
          const getApproval = async () => {
            const value = (await approvals())?.[key];
            if (!value) throw Error("Exact console approval is absent");
            return value;
          };
          const ports = recoveryConsolePorts(
            controller,
            plan,
            async (value) => {
              state[key] = value;
              await persist(state);
            },
            getApproval,
            runner,
          );
          // Existing captures can be read after approval expiry; CREATE rechecks.
          try {
            return (await stepConsoleCapture(
              plan,
              approval!,
              captureState,
              ports,
            )).state;
          } catch (error) {
            if (error instanceof ConsoleConnectionRequiredError) {
              const current = await readPrivateJson<SessionConfig>(CONFIG);
              if (!current.consolePublicKey) {
                await writePrivateJson(REPORT, {
                  status: "CONSOLE_PUBLIC_KEY_REQUIRED",
                  requestId: request.requestId,
                  instanceId: request.instanceId,
                  requiredKeyType: "existing RSA public key",
                  setupAccepted: false,
                });
                throw error;
              }
              const publicKey = current.consolePublicKey;
              const connectionPlan = consoleConnectionPlan(
                request.requestId,
                request.instanceId,
                config.compartmentId,
                publicKey,
              );
              state.consoleConnection ??= {
                planSha256: connectionPlan.planSha256,
              };
              await persist(state);
              const connectionStatus = await stepConsoleConnection(
                connectionPlan,
                publicKey,
                state.consoleConnection,
                {
                  json,
                  now: () => Date.now(),
                  persist: async (value) => {
                    state.consoleConnection = value;
                    await persist(state);
                  },
                  approval: async () => (await approvals())?.consoleConnection,
                  beforeMutation: async () => {
                    await beforeMutation();
                    const fresh = await readPrivateJson<SessionConfig>(CONFIG);
                    if (
                      consoleConnectionPlan(
                        request.requestId,
                        request.instanceId,
                        config.compartmentId,
                        fresh.consolePublicKey!,
                      ).planSha256 !== connectionPlan.planSha256
                    ) {
                      throw Error("Console public-key authority changed");
                    }
                    const instance = dataObject(
                      await json([
                        "compute",
                        "instance",
                        "get",
                        "--instance-id",
                        request.instanceId,
                      ]),
                    );
                    if (
                      instance.id !== request.instanceId ||
                      instance["lifecycle-state"] !== "RUNNING" ||
                      instance["compartment-id"] !== config.compartmentId ||
                      (instance["freeform-tags"] as
                          | Record<string, unknown>
                          | undefined)?.uosRecoveryRequest !==
                        request.requestId ||
                      request.instanceId === controller.source.instanceId
                    ) {
                      throw Error(
                        "Console connection target is not the running replacement",
                      );
                    }
                  },
                },
              );
              await writePrivateJson(REPORT, {
                status: connectionStatus,
                plan: connectionPlan,
                setupAccepted: connectionStatus === "CONSOLE_CONNECTION_ACTIVE",
                restoreAccepted: false,
                applicationAccepted: false,
              });
              if (connectionStatus === "CONSOLE_CONNECTION_ACTIVE") {
                return (await stepConsoleCapture(
                  plan,
                  approval!,
                  captureState,
                  ports,
                )).state;
              }
            }
            throw error;
          }
        },
      },
    );
    if (status === "RAM_RESCUE_ACCEPTED") {
      if (!acceptedTarget || !state.loaderIdentity || !state.ramAccepted) {
        throw Error("Accepted RAM target is unavailable for restoration");
      }
      const inputPath = ".private/backblaze-machine-restore.json";
      let input: RecoveryTargetControlInput | undefined;
      try {
        input = await readPrivateJson<RecoveryTargetControlInput>(inputPath);
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) throw error;
      }
      if (!input) {
        status = "RESTORE_CONFIGURATION_REQUIRED";
        await writePrivateJson(REPORT, {
          status,
          restoreAccepted: false,
          applicationAccepted: false,
        });
      } else {
        if (
          validateCatalogEntry(input.catalog).index.generation !==
            config.generation
        ) {
          throw Error(
            "Restoration generation differs from the replacement plan",
          );
        }
        const inputDigest = hash(input);
        const preparation = preparationBindingFromLoader(
          state.loaderIdentity,
          state.ramAccepted.bootId,
          state.manifestSha256,
        );
        const connection = await recoverySshRunner(acceptedTarget)("bash", [
          "-ec",
          "printf '%s\\n' \"$SSH_CONNECTION\"",
        ]);
        const connectionFields = connection.stdout.trim().split(/\s+/);
        if (connection.code !== 0 || connectionFields.length !== 4) {
          throw Error(
            "Pi SSH peer address is unavailable for copied-root isolation",
          );
        }
        const release = await readPrivateJson<{ sourceRevision: string }>(
          ".private/reports/pi-session-deployment.json",
        );
        const bundle = await buildRecoveryTargetBundle({
          sourceRoot: Deno.cwd(),
          sourceRevision: release.sourceRevision,
          input: {
            ...input,
            isolation: {
              preparation,
              controllerIpv4: connectionFields[0],
              sshPublicKey: publicInput.sshPublicKey,
            },
          },
          b2: await readPrivateJson<B2Settings>(".private/b2-file-backup.json"),
          recipientBytes: await Deno.readFile(
            ".private/file-backup/recipient.asc",
          ),
        });
        const restorationPath = ".private/pi-recovery-restoration.json";
        let retained: RecoveryRestorationState | undefined;
        try {
          retained = await readPrivateJson<RecoveryRestorationState>(
            restorationPath,
          );
        } catch (error) {
          if (!(error instanceof Deno.errors.NotFound)) throw error;
        }
        status = await continueReplacementRestoration(
          acceptedTarget,
          preparation,
          bundle,
          retained,
          {
            beforeMutation: async () => {
              await beforeMutation();
              if (hash(await readPrivateJson(inputPath)) !== inputDigest) {
                throw Error("Restoration input or approval changed");
              }
              assertRetainedProviderBinding(
                state.loaderIdentity!,
                await provider(),
              );
            },
            persist: (value) => writePrivateJson(restorationPath, value),
            report: (value) => writePrivateJson(REPORT, value),
            installationApproval: async () =>
              (await approvals())?.restoreInstallation,
            preparationApproval: async () =>
              (await approvals())?.diskPreparation,
          },
        );
      }
    }
    console.log(
      JSON.stringify({
        status,
        restoreAccepted: false,
        applicationAccepted: false,
      }),
    );
  });
}
if (import.meta.main) {
  try {
    await runRecoverySession();
  } catch {
    console.error(
      "Pi recovery session stopped; inspect its private report and journal before resuming",
    );
    Deno.exitCode = 1;
  }
}
