import {
  type BackupInventoryConfig,
  readBackupInventory,
} from "./oci-backup-inventory.ts";
import { backupControllerEvidence } from "./backup-controller-evidence.ts";
import {
  type CommandRunner,
  dataArray,
  dataObject,
  defaultRunner,
  readPrivateJson,
  redactOcid,
  runJson,
  stringField,
  writePrivateJson,
} from "./oci.ts";
import { type BackupJournal, type BackupPolicy } from "./weekly-backup.ts";
import type { GuestJournal } from "./backup-guest.ts";
import { validateBackupPair } from "./oci-restore.ts";
import {
  controllerCidr,
  drillHourlyCostUsd,
  type DrillPlan,
  drillPlanDigest,
} from "./isolated-drill.ts";

interface AcceptedRuntime {
  policy: BackupPolicy;
  cycle: BackupJournal;
  guest?: GuestJournal;
}
export function acceptedDrillPair(state: AcceptedRuntime, now = new Date()) {
  const { cycle, policy } = state;
  if (
    cycle.phase !== "complete" || !cycle.bootId || !cycle.rootId ||
    !cycle.sourceAcceptedAtUtc || !state.guest?.restored ||
    !policy.retainPreviousPair || cycle.suffix === policy.acceptedPair.suffix ||
    JSON.stringify(cycle.source) !== JSON.stringify(policy.source) ||
    !Number.isFinite(Date.parse(cycle.createdAtUtc)) ||
    !Number.isFinite(Date.parse(cycle.sourceAcceptedAtUtc)) ||
    Date.parse(cycle.sourceAcceptedAtUtc) > now.getTime() ||
    Date.parse(cycle.sourceAcceptedAtUtc) < Date.parse(cycle.createdAtUtc)
  ) {
    throw new Error(
      "A fresh paired backup and accepted source recovery are required before preparing the drill",
    );
  }
  return { suffix: cycle.suffix, bootId: cycle.bootId, rootId: cycle.rootId };
}

/** Read-only plan preparation on the approved Pi. Creation and cleanup are
 * separate stages. This does not manufacture an approval or a restore result.
 */
export async function prepareDrill(
  runner: CommandRunner = defaultRunner,
): Promise<void> {
  const state = await readPrivateJson<AcceptedRuntime>(
    ".private/backup-runtime.json",
  );
  const pair = acceptedDrillPair(state);
  const config = await readPrivateJson<BackupInventoryConfig>(
    ".private/backup-controller.json",
  );
  if (
    config.ociCliPath !== "/home/pi/.venvs/oci/bin/oci" ||
    JSON.stringify(config.source) !== JSON.stringify(state.policy.source)
  ) {
    throw new Error(
      "Prepare the exact source plan on the approved Pi controller",
    );
  }
  const evidence = backupControllerEvidence(config, runner);
  await evidence.assertNoOtherController();
  const inventory = await readBackupInventory(config, runner);
  if (
    inventory.totals.instances !== 1 || inventory.totals.ocpus !== 2 ||
    inventory.totals.memoryGb !== 12 || inventory.totals.liveVolumeGb !== 200 ||
    inventory.totals.publicIps !== 1 || !inventory.sourceAttachmentsProved
  ) throw new Error("Production footprint changed before drill preparation");
  const boot = inventory.bootBackups.find((item) => item.id === pair.bootId);
  const root = inventory.rootBackups.find((item) => item.id === pair.rootId);
  if (!boot || !root) throw new Error("Fresh pair is absent from OCI");
  validateBackupPair(
    boot,
    root,
    pair.suffix,
    config.source.bootVolumeId,
    config.source.rootVolumeId,
    config.source.compartmentId,
  );
  for (const backup of [boot, root]) {
    const created = Date.parse(stringField(backup, "time-created"));
    if (
      !Number.isFinite(created) ||
      created < Date.parse(state.cycle.createdAtUtc) - 1000 ||
      created > Date.parse(state.cycle.sourceAcceptedAtUtc!)
    ) throw new Error("Backup postdates the recorded source acceptance");
  }
  const call = (args: string[]) =>
    runJson(config.ociCliPath, [
      "--profile",
      config.ociProfile,
      "--region",
      config.source.region,
      "--no-retry",
      "--connection-timeout",
      "10",
      "--read-timeout",
      "60",
      ...args,
    ], runner);
  const attachments = dataArray(
    await call([
      "compute",
      "vnic-attachment",
      "list",
      "--compartment-id",
      config.source.compartmentId,
      "--instance-id",
      config.source.instanceId,
      "--all",
    ]),
  ).filter((item) => item["lifecycle-state"] === "ATTACHED");
  if (attachments.length !== 1) {
    throw new Error(
      "Production VNIC inventory is not the reviewed single-interface source",
    );
  }
  const vnic = dataObject(
    await call([
      "network",
      "vnic",
      "get",
      "--vnic-id",
      stringField(attachments[0], "vnic-id"),
    ]),
  );
  const subnet = dataObject(
    await call([
      "network",
      "subnet",
      "get",
      "--subnet-id",
      stringField(vnic, "subnet-id"),
    ]),
  );
  const reserved = inventory.publicIps.filter((item) =>
    item.lifetime === "RESERVED" && item["ip-address"] === vnic["public-ip"]
  );
  if (reserved.length !== 1) {
    throw new Error("Production reserved IP binding is not proved");
  }
  const observed = await runner("ssh", [
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ConnectTimeout=10",
    "codex@vps.pavlovcik.com",
    'printf "%s\\n" "$SSH_CONNECTION"',
  ]);
  if (observed.code !== 0) {
    throw new Error("Pi SSH source address could not be observed");
  }
  const connection = observed.stdout.trim().split(/\s+/);
  if (connection.length !== 4 || connection[3] !== "22") {
    throw new Error("Unexpected controller SSH source evidence");
  }
  controllerCidr(connection[0]);
  const now = new Date();
  const plan: DrillPlan = {
    source: config.source,
    pair,
    sourceAcceptedAtUtc: state.cycle.sourceAcceptedAtUtc!,
    availabilityDomain: stringField(inventory.instance, "availability-domain"),
    productionReservedIpId: stringField(reserved[0], "id"),
    productionSubnetId: stringField(subnet, "id"),
    productionVcnId: stringField(subnet, "vcn-id"),
    controllerIpv4: connection[0],
    suffix: now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z"),
    maxDurationHours: 4,
    spendingCapUsd: 0.5,
  };
  const report = {
    status: "DRAFT_REQUIRES_APPROVAL",
    preparedAtUtc: now.toISOString(),
    plan,
    planSha256: await drillPlanDigest(plan),
    projectedTotals: {
      instances: 2,
      ocpus: 4,
      memoryGb: 24,
      liveVolumeGb: 400,
      backups: inventory.totals.backups,
      publicIps: 2,
    },
    estimatedAdditionalHourlyUsd: drillHourlyCostUsd(),
    estimatedFourHourUsd: 4 * drillHourlyCostUsd(),
    pendingEvidence: [
      "current trial credit balance and pricing",
      "complete first-boot isolation",
      "exact creation approval",
      "exact cleanup approval after resource IDs exist",
    ],
    resourcesToCreate: [
      "isolated VCN",
      "SSH-only security list",
      "custom DHCP options",
      "internet gateway",
      "isolated route table",
      "isolated subnet",
      "50 GB boot volume from fresh backup",
      "150 GB root volume from fresh backup",
      "2 OCPU / 12 GB A1 clone with ephemeral public IP",
    ],
    productionIpOrDnsMutation: false,
  };
  await writePrivateJson(".private/isolated-drill-plan.json", report);
  console.log(JSON.stringify({
    status: report.status,
    planSha256: report.planSha256,
    projectedTotals: report.projectedTotals,
    estimatedFourHourUsd: report.estimatedFourHourUsd,
    approvalRecorded: false,
  }));
}
if (import.meta.main) {
  try {
    await prepareDrill();
  } catch (error) {
    console.error(
      redactOcid(error instanceof Error ? error.message : String(error)),
    );
    Deno.exitCode = 1;
  }
}
