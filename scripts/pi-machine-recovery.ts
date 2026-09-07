/** Pi-owned replacement provisioning. This controller never downloads B2
 * archives, deletes an existing resource, stops production, or moves an assigned
 * public IP. Recovery is separate from normal weekly capture. */
import { createHash } from "node:crypto";
import { withBackupLock } from "./backup-lock.ts";
import {
  assertOracleMutationAllowed,
  readGate,
} from "./backblaze-controller-gate.ts";
import { backupControllerEvidence } from "./backup-controller-evidence.ts";
import type { BackupInventoryConfig } from "./oci-backup-inventory.ts";
import {
  type CommandRunner,
  dataArray,
  dataObject,
  defaultRunner,
  type JsonRecord,
  numberField,
  readPrivateJson,
  runJson,
  stringField,
  writePrivateJson,
} from "./oci.ts";

const CONFIG = ".private/pi-machine-recovery.json";
const STATE = ".private/pi-machine-recovery-state.json";
const REPORT = ".private/reports/pi-machine-recovery-plan.json";
const TAG = "uosRecoveryRequest";
const OPERATION =
  "provision one 2 OCPU 12 GB replacement with 50 GB boot and 150 GB root and assign its existing unassigned reserved IP for direct Backblaze recovery";
/** Trial provisioning is a distinct exact approval operation: an ordinary
 * replacement approval never authorizes trial capacity and vice versa. */
export const TRIAL_OPERATION =
  "provision one trial-funded 2 OCPU 12 GB replacement alongside the running production 2 OCPU 12 GB instance with 50 GB boot and 150 GB root and assign its existing unassigned reserved IP for direct Backblaze recovery";

export function assertReplacementApproval(
  config: ReplacementConfig,
  digest: string,
  now = Date.now(),
): void {
  validateReplacementConfig(config);
  if (
    config.action !== "provision" || replacementPlanDigest(config) !== digest
  ) {
    throw Error("Replacement plan changed");
  }
  const approval = config.approval;
  const age = now - Date.parse(approval?.approvedAtUtc ?? "");
  if (
    !approval || approval.exactOperation !==
      (config.trial !== undefined ? TRIAL_OPERATION : OPERATION) ||
    approval.planSha256 !== digest ||
    !Number.isFinite(age) || age < 0 || age > 3600000
  ) {
    throw Error("Current exact replacement approval is required");
  }
  if (config.trial !== undefined) {
    const approvedAt = Date.parse(approval.approvedAtUtc);
    const expires = Date.parse(config.trial.expiresAtUtc);
    if (
      !Number.isFinite(approvedAt) || !Number.isFinite(expires) ||
      expires <= now || expires - approvedAt > 4 * 3600000
    ) {
      throw Error(
        "Trial replacement is authorized only while its expiry is future and within four hours of approval",
      );
    }
  }
}

export interface ReplacementTrial {
  /** Trial-funded spend bound; never described as a remaining credit balance. */
  spendingCapUsd: number;
  expiresAtUtc: string;
}
export interface ProductionBinding {
  instanceId: string;
  bootVolumeId: string;
  rootVolumeId: string;
}
export interface ReplacementConfig {
  action: "plan" | "provision";
  requestId: string;
  generation: string;
  tenancyId: string;
  region: string;
  compartmentId: string;
  availabilityDomain: string;
  subnetId: string;
  reservedPublicIpId: string;
  platformImageId: string;
  /** Public bootstrap configuration; no keys, credentials or archives. */
  cloudInit: string;
  /** Optional bounded trial-funded capacity; absent keeps the free-only plan. */
  trial?: ReplacementTrial;
  approval?: {
    approvedAtUtc: string;
    exactOperation: string;
    planSha256: string;
  };
}
export interface ReplacementState {
  requestId: string;
  planSha256: string;
  rootVolumeId?: string;
  instanceId?: string;
  bootVolumeId?: string;
  privateIpId?: string;
  /** Persist before the CREATE call; reconcile tagged resources after a crash. */
  pending?: "root" | "instance";
  updatedAtUtc: string;
}
export interface ReplacementInventory {
  bootVolumes: JsonRecord[];
  rootVolumes: JsonRecord[];
  instances: JsonRecord[];
  backupMembers: number;
  publicIps: number;
  objectStorageBytes: number;
}
const alive = (item: JsonRecord) => item["lifecycle-state"] !== "TERMINATED";
function quantity(item: JsonRecord, field: string): number {
  const value = numberField(item, field);
  if (!Number.isFinite(value) || value < 0) {
    throw Error("Invalid resource quantity");
  }
  return value;
}
const sum = (items: JsonRecord[], field: string) =>
  items.reduce((total, item) => total + quantity(item, field), 0);

export function replacementPlanDigest(config: ReplacementConfig): string {
  const plan: Record<string, unknown> = {
    requestId: config.requestId,
    generation: config.generation,
    tenancyId: config.tenancyId,
    region: config.region,
    compartmentId: config.compartmentId,
    availabilityDomain: config.availabilityDomain,
    subnetId: config.subnetId,
    reservedPublicIpId: config.reservedPublicIpId,
    platformImageId: config.platformImageId,
    cloudInit: config.cloudInit,
    ocpus: 2,
    memoryGb: 12,
    bootGb: 50,
    rootGb: 150,
    consistentVolumeNaming: true,
    rootDevice: "/dev/oracleoci/oraclevdb",
  };
  // Optional trial funding becomes part of the reviewed plan; its absence
  // keeps the original free-only digest byte-identical.
  if (config.trial !== undefined) plan["trial"] = config.trial;
  return createHash("sha256").update(JSON.stringify(plan)).digest("hex");
}
export function validateReplacementConfig(config: ReplacementConfig): void {
  if (
    !["plan", "provision"].includes(config.action) ||
    !/^recovery-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      .test(config.requestId) ||
    !/^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      .test(config.generation) ||
    !config.availabilityDomain ||
    !config.region || !config.tenancyId?.startsWith("ocid1.tenancy.") ||
    new TextEncoder().encode(config.cloudInit).length > 32000 ||
    !config.cloudInit.startsWith("#cloud-config\n")
  ) throw Error("Replacement configuration is incomplete");
  for (
    const [field, kind] of [
      ["subnetId", "subnet"],
      ["reservedPublicIpId", "publicip"],
      ["platformImageId", "image"],
    ] as const
  ) {
    if (!config[field].startsWith(`ocid1.${kind}.`)) {
      throw Error("Replacement resource identity is malformed");
    }
  }
  if (!/^ocid1\.(?:compartment|tenancy)\./.test(config.compartmentId)) {
    throw Error("Replacement compartment identity is malformed");
  }
  const trial = config.trial as ReplacementTrial | null | undefined;
  if (trial !== undefined) {
    if (
      trial === null || typeof trial.spendingCapUsd !== "number" ||
      !Number.isFinite(trial.spendingCapUsd) || trial.spendingCapUsd <= 0 ||
      trial.spendingCapUsd > 300 || typeof trial.expiresAtUtc !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(
        trial.expiresAtUtc,
      ) || !Number.isFinite(Date.parse(trial.expiresAtUtc))
    ) throw Error("Replacement trial spending bound or expiry is invalid");
  }
}
/** Recognized production identity comes only from the trusted controller
 * source; the trial configuration never names a production resource. */
function productionBinding(
  controller: BackupInventoryConfig,
): ProductionBinding {
  return {
    instanceId: controller.source.instanceId,
    bootVolumeId: controller.source.bootVolumeId,
    rootVolumeId: controller.source.rootVolumeId,
  };
}

/** Exact distinct production instance/boot/root must be present, running with
 * the trusted 2 OCPU/12 GB shape and the exact 50/150 GB disks. Malformed or
 * overlapping identities throw; a missing, changed or stopped production
 * footprint returns undefined so the trial assessment fails closed. */
function resolveProduction(
  production: ProductionBinding,
  boot: JsonRecord[],
  root: JsonRecord[],
  instances: JsonRecord[],
  state?: ReplacementState,
): { boot: JsonRecord; root: JsonRecord; instance: JsonRecord } | undefined {
  const ids = [
    production.instanceId,
    production.bootVolumeId,
    production.rootVolumeId,
  ];
  if (ids.some((id) => !id)) {
    throw Error("Production identity is missing from the controller source");
  }
  if (new Set(ids).size !== ids.length) {
    throw Error("Production identities are not distinct");
  }
  const replacementIds = [
    state?.instanceId,
    state?.bootVolumeId,
    state?.rootVolumeId,
  ].filter((id): id is string => Boolean(id));
  if (replacementIds.some((id) => ids.includes(id))) {
    throw Error("Production binding overlaps the replacement identity");
  }
  const exact = (items: JsonRecord[], id: string) =>
    items.filter((item) => item.id === id).length === 1
      ? items.find((item) => item.id === id)!
      : undefined;
  const instance = exact(instances, production.instanceId);
  const bootVolume = exact(boot, production.bootVolumeId);
  const rootVolume = exact(root, production.rootVolumeId);
  if (!instance || !bootVolume || !rootVolume) return undefined;
  const shape = dataObject({ data: instance["shape-config"] });
  if (
    instance["lifecycle-state"] !== "RUNNING" ||
    instance.shape !== "VM.Standard.A1.Flex" ||
    quantity(shape, "ocpus") !== 2 ||
    quantity(shape, "memory-in-gbs") !== 12 ||
    bootVolume["size-in-gbs"] !== 50 || rootVolume["size-in-gbs"] !== 150
  ) {
    return undefined;
  }
  return { boot: bootVolume, root: rootVolume, instance };
}

/** Count peak final use without treating orphaned production volumes as free.
 * Without a production binding the assessment stays exactly free-only and
 * rejects coexistence; with the binding the trial envelope applies only while
 * the exact production footprint is present and running. */
export function assessReplacementCapacity(
  inventory: ReplacementInventory,
  state?: ReplacementState,
  production?: ProductionBinding,
) {
  const boot = inventory.bootVolumes.filter(alive);
  const root = inventory.rootVolumes.filter(alive);
  const instances = inventory.instances.filter(alive);
  for (const items of [boot, root, instances]) {
    const ids = items.map((item) => stringField(item, "id"));
    if (ids.some((id) => !id) || new Set(ids).size !== ids.length) {
      throw Error("Resource identities are incomplete or duplicated");
    }
  }
  for (
    const field of ["backupMembers", "publicIps", "objectStorageBytes"] as const
  ) {
    if (!Number.isSafeInteger(inventory[field]) || inventory[field] < 0) {
      throw Error("Invalid inventory total");
    }
  }
  const ownRoot = root.find((v) => v.id === state?.rootVolumeId);
  const ownBoot = boot.find((v) => v.id === state?.bootVolumeId);
  const ownInstance = instances.find((v) => v.id === state?.instanceId);
  const shape = (item: JsonRecord) =>
    dataObject({ data: item["shape-config"] });
  const liveVolumeGb = sum([...boot, ...root], "size-in-gbs");
  const ocpus = instances.reduce(
    (n, v) => n + quantity(shape(v), "ocpus"),
    0,
  );
  const memoryGb = instances.reduce(
    (n, v) => n + quantity(shape(v), "memory-in-gbs"),
    0,
  );
  const productionProved = production
    ? resolveProduction(production, boot, root, instances, state)
    : undefined;
  const recognized = new Set([
    ...[
      state?.bootVolumeId,
      state?.rootVolumeId,
      state?.instanceId,
    ].filter((id): id is string => Boolean(id)),
    ...(production
      ? [
        production.bootVolumeId,
        production.rootVolumeId,
        production.instanceId,
      ]
      : []),
  ]);
  const peak = {
    liveVolumeGb: liveVolumeGb + (ownRoot ? 0 : 150) + (ownBoot ? 0 : 50),
    ocpus: ocpus + (ownInstance ? 0 : 2),
    memoryGb: memoryGb + (ownInstance ? 0 : 12),
    backupMembers: inventory.backupMembers,
    publicIps: inventory.publicIps,
    objectStorageBytes: inventory.objectStorageBytes,
  };
  // The ordinary free-only plan keeps the original per-family ownership
  // predicates; the recognized reconciliation set is used only for the trial
  // coexistence branch, where the exact production footprint is trusted too.
  const unowned = production
    ? boot.some((v) => !recognized.has(stringField(v, "id"))) ||
      root.some((v) => !recognized.has(stringField(v, "id"))) ||
      instances.some((v) => !recognized.has(stringField(v, "id")))
    : boot.some((v) => v.id !== state?.bootVolumeId) ||
      root.some((v) => v.id !== state?.rootVolumeId) ||
      instances.some((v) => v.id !== state?.instanceId);
  const missing = Boolean(
    state?.rootVolumeId && !ownRoot ||
      state?.bootVolumeId && !ownBoot || state?.instanceId && !ownInstance,
  );
  const withinCaps = production
    ? peak.liveVolumeGb <= 400 && peak.ocpus <= 4 && peak.memoryGb <= 24 &&
      peak.publicIps <= 2 && peak.backupMembers <= 5 &&
      peak.objectStorageBytes <= 20_000_000_000
    : peak.liveVolumeGb <= 200 && peak.ocpus <= 2 && peak.memoryGb <= 12 &&
      peak.backupMembers <= 5 &&
      peak.objectStorageBytes <= 20_000_000_000;
  return {
    current: { liveVolumeGb, ocpus, memoryGb },
    peak,
    ready: (!production || productionProved !== undefined) && !unowned &&
      !missing && withinCaps,
  };
}

async function inventory(
  controller: BackupInventoryConfig,
  runner: CommandRunner,
  fetchDocument?: () => Promise<string>,
): Promise<ReplacementInventory> {
  const call = (args: string[]) =>
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
  const regions = dataArray(await call(["iam", "region-subscription", "list"]));
  if (
    regions.length !== 1 || regions[0]["is-home-region"] !== true ||
    regions[0]["region-name"] !== controller.source.region
  ) throw Error("Replacement must remain in the sole tenancy home region");
  const proof = await backupControllerEvidence(
    controller,
    runner,
    fetchDocument,
  ).verify();
  if (
    !proof.accountAndLimitsProved || !proof.objectStorageComplete ||
    !proof.objectStorageWithinLimit || proof.objectStorageBytes === undefined
  ) throw Error("Free eligibility is not proved");
  const surfaces = proof.freeResourceSurface;
  if (!surfaces?.freeResourceSurfaceProved) {
    throw Error("Free resource settings are not proved");
  }
  const compartments = [
    controller.tenancyId,
    ...dataArray(
      await call([
        "iam",
        "compartment",
        "list",
        "--compartment-id",
        controller.tenancyId,
        "--compartment-id-in-subtree",
        "true",
        "--access-level",
        "ANY",
        "--all",
      ]),
    ).filter((v) => v["lifecycle-state"] === "ACTIVE").map((v) =>
      stringField(v, "id")
    ),
  ];
  const instances: JsonRecord[] = [];
  const domains = dataArray(
    await call([
      "iam",
      "availability-domain",
      "list",
      "--compartment-id",
      controller.tenancyId,
    ]),
  );
  if (!domains.length) throw Error("Availability domain inventory is empty");
  let backupMembers = 0;
  const publicIpIds = new Set<string>();
  for (const compartmentId of new Set(compartments)) {
    instances.push(
      ...dataArray(
        await call([
          "compute",
          "instance",
          "list",
          "--compartment-id",
          compartmentId,
          "--all",
        ]),
      ).filter(alive),
    );
    for (const family of ["backup", "boot-volume-backup"]) {
      backupMembers += dataArray(
        await call([
          "bv",
          family,
          "list",
          "--compartment-id",
          compartmentId,
          "--all",
        ]),
      ).filter(alive).length;
    }
    const addresses = dataArray(
      await call([
        "network",
        "public-ip",
        "list",
        "--compartment-id",
        compartmentId,
        "--scope",
        "REGION",
        "--all",
      ]),
    );
    for (const domain of domains) {
      addresses.push(...dataArray(
        await call([
          "network",
          "public-ip",
          "list",
          "--compartment-id",
          compartmentId,
          "--scope",
          "AVAILABILITY_DOMAIN",
          "--availability-domain",
          stringField(domain, "name"),
          "--all",
        ]),
      ));
    }
    for (const address of addresses.filter(alive)) {
      publicIpIds.add(stringField(address, "id"));
    }
  }
  return {
    bootVolumes: surfaces.activeBootVolumes,
    rootVolumes: surfaces.activeBlockVolumes,
    instances,
    backupMembers,
    publicIps: publicIpIds.size,
    objectStorageBytes: proof.objectStorageBytes,
  };
}

/** Confirm the current Organizations subscription and USD promotion through
 * the same bounded call interface before any trial cloud mutation. The
 * promotion amount is a spending bound, never a remaining credit balance;
 * reported usage and resource totals are the primary's separate checks. */
export async function proveTrialFunding(
  controller: BackupInventoryConfig,
  config: ReplacementConfig,
  runner: CommandRunner = defaultRunner,
): Promise<void> {
  if (config.trial === undefined || config.trial === null) {
    throw Error("Trial funding proof requires trial configuration");
  }
  // Capture the guarded spending bound once: the promotion check below runs
  // inside a callback, where the `config.trial` guard narrowing does not apply.
  const spendingCapUsd = config.trial.spendingCapUsd;
  const call = (args: string[]) =>
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
  const collection = dataObject(
    await call([
      "organizations",
      "subscription",
      "list",
      "--compartment-id",
      controller.tenancyId,
      "--all",
    ]),
  );
  if (!Array.isArray(collection.items) || collection.items.length !== 1) {
    throw Error("A single current Organizations subscription is required");
  }
  const summary = collection.items[0] as JsonRecord;
  const subscription = dataObject(
    await call([
      "organizations",
      "subscription",
      "get",
      "--subscription-id",
      stringField(summary, "id"),
    ]),
  );
  if (
    subscription.id !== summary.id ||
    subscription["compartment-id"] !== controller.tenancyId ||
    subscription["lifecycle-state"] !== "ACTIVE" ||
    subscription["subscription-tier"] !== "FREE_AND_TRIAL" ||
    subscription["payment-model"] !== "FREE_TRIAL"
  ) {
    throw Error(
      "Current subscription is not the ACTIVE Free Trial account",
    );
  }
  const trialExpiry = Date.parse(config.trial.expiresAtUtc);
  const subscriptionEnd = Date.parse(
    stringField(subscription, "end-date"),
  );
  if (
    !Number.isFinite(trialExpiry) || !Number.isFinite(subscriptionEnd) ||
    subscriptionEnd <= trialExpiry
  ) {
    throw Error("Trial replacement would outlive the current subscription");
  }
  const promotions = Array.isArray(subscription.promotion)
    ? subscription.promotion
    : [];
  if (
    !promotions.some((promotion: JsonRecord) => {
      if (promotion["status"] !== "ACTIVE") return false;
      if (promotion["currency-unit"] !== "USD") return false;
      const amount = numberField(promotion, "amount");
      return Number.isFinite(amount) && amount >= spendingCapUsd;
    })
  ) {
    throw Error(
      "The ACTIVE USD promotion does not cover the requested trial spending bound",
    );
  }
}

export async function runReplacement(
  runner: CommandRunner = defaultRunner,
  fetchDocument?: () => Promise<string>,
  validateBootstrap?: (config: ReplacementConfig) => Promise<unknown>,
): Promise<void> {
  const controller = await readPrivateJson<BackupInventoryConfig>(
    ".private/backup-controller.json",
  );
  const config = await readPrivateJson<ReplacementConfig>(CONFIG);
  validateReplacementConfig(config);
  if (
    config.tenancyId !== controller.tenancyId ||
    config.region !== controller.source.region
  ) {
    throw Error("Replacement account or region differs from the controller");
  }
  const digest = replacementPlanDigest(config);
  const production = config.trial !== undefined
    ? productionBinding(controller)
    : undefined;
  const call = (args: string[]) =>
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
  await withBackupLock(".private/backup-controller.lock", async () => {
    assertOracleMutationAllowed(await readGate());
    await backupControllerEvidence(controller, runner)
      .assertNoOtherController();
    let state: ReplacementState;
    try {
      state = await readPrivateJson<ReplacementState>(STATE);
    } catch (e) {
      if (!(e instanceof Deno.errors.NotFound)) throw e;
      state = {
        requestId: config.requestId,
        planSha256: digest,
        updatedAtUtc: new Date().toISOString(),
      };
    }
    if (state.requestId !== config.requestId || state.planSha256 !== digest) {
      throw Error("Replacement journal belongs to another approved plan");
    }
    const save = async () => {
      state.updatedAtUtc = new Date().toISOString();
      await writePrivateJson(STATE, state);
    };
    let resources = await inventory(controller, runner, fetchDocument);
    const reconcile = async () => {
      // Never infer ownership from a name alone. The request tag and
      // exact specification must agree before adopting a lost CREATE response.
      const tagged = (items: JsonRecord[]) =>
        items.filter((v) =>
          dataObject({ data: v["freeform-tags"] ?? {} })[TAG] ===
            config.requestId
        );
      const roots = tagged(resources.rootVolumes);
      const instances = tagged(resources.instances);
      if (
        state.rootVolumeId && !roots.some((v) => v.id === state.rootVolumeId) ||
        state.instanceId && !instances.some((v) => v.id === state.instanceId)
      ) {
        throw Error(
          "Recorded replacement identity is missing or no longer owned",
        );
      }
      if (roots.length > 1 || instances.length > 1) {
        throw Error("Replacement creation identity is ambiguous");
      }
      if (roots[0]) {
        if (
          roots[0]["size-in-gbs"] !== 150 ||
          roots[0]["compartment-id"] !== config.compartmentId ||
          roots[0]["availability-domain"] !== config.availabilityDomain ||
          roots[0]["vpus-per-gb"] !== 10 ||
          state.rootVolumeId && state.rootVolumeId !== roots[0].id
        ) throw Error("Replacement root specification drift");
        state.rootVolumeId = stringField(roots[0], "id");
      }
      if (instances[0]) {
        const instance = instances[0];
        if (instance["lifecycle-state"] !== "RUNNING") {
          throw Error(
            "Replacement is not running; reconcile this request before continuing",
          );
        }
        const shape = dataObject({ data: instance["shape-config"] });
        if (
          instance.shape !== "VM.Standard.A1.Flex" || shape.ocpus !== 2 ||
          shape["memory-in-gbs"] !== 12 ||
          instance["image-id"] !== config.platformImageId ||
          (instance["launch-options"] as JsonRecord | undefined)
              ?.["is-consistent-volume-naming-enabled"] !== true ||
          instance["compartment-id"] !== config.compartmentId ||
          instance["availability-domain"] !== config.availabilityDomain ||
          state.instanceId && state.instanceId !== instance.id
        ) throw Error("Replacement instance specification drift");
        state.instanceId = stringField(instance, "id");
        const attachments = dataArray(
          await call([
            "compute",
            "boot-volume-attachment",
            "list",
            "--compartment-id",
            config.compartmentId,
            "--availability-domain",
            config.availabilityDomain,
            "--instance-id",
            state.instanceId,
            "--all",
          ]),
        ).filter((v) => v["lifecycle-state"] === "ATTACHED");
        if (
          attachments.length !== 1 ||
          attachments[0]["instance-id"] !== state.instanceId
        ) {
          throw Error("Replacement boot attachment is not yet proved");
        }
        const attachedBoot = stringField(attachments[0], "boot-volume-id");
        if (state.bootVolumeId && state.bootVolumeId !== attachedBoot) {
          throw Error("Recorded boot attachment changed");
        }
        state.bootVolumeId = attachedBoot;
        const boot = resources.bootVolumes.find((v) =>
          v.id === state.bootVolumeId
        );
        if (
          !boot || boot["size-in-gbs"] !== 50 ||
          boot["lifecycle-state"] !== "AVAILABLE" ||
          boot["compartment-id"] !== config.compartmentId ||
          boot["availability-domain"] !== config.availabilityDomain ||
          boot["image-id"] !== config.platformImageId
        ) throw Error("Replacement boot specification drift");
        const rootsAttached = dataArray(
          await call([
            "compute",
            "volume-attachment",
            "list",
            "--compartment-id",
            config.compartmentId,
            "--instance-id",
            state.instanceId,
            "--all",
          ]),
        ).filter((v) => v["lifecycle-state"] !== "DETACHED");
        if (
          rootsAttached.length !== 1 ||
          rootsAttached[0]["lifecycle-state"] !== "ATTACHED" ||
          rootsAttached[0]["volume-id"] !== state.rootVolumeId ||
          rootsAttached[0]["instance-id"] !== state.instanceId ||
          rootsAttached[0]["attachment-type"] !== "paravirtualized" ||
          rootsAttached[0].device !== "/dev/oracleoci/oraclevdb"
        ) {
          throw Error("Replacement root attachment is not proved");
        }
        const vnics = dataArray(
          await call([
            "compute",
            "vnic-attachment",
            "list",
            "--compartment-id",
            config.compartmentId,
            "--instance-id",
            state.instanceId,
            "--all",
          ]),
        ).filter((v) => v["lifecycle-state"] !== "DETACHED");
        if (
          vnics.length !== 1 || vnics[0]["lifecycle-state"] !== "ATTACHED" ||
          vnics[0]["instance-id"] !== state.instanceId
        ) throw Error("Replacement VNIC is not proved");
        const vnicId = stringField(vnics[0], "vnic-id");
        const vnic = dataObject(
          await call(["network", "vnic", "get", "--vnic-id", vnicId]),
        );
        if (
          vnic["subnet-id"] !== config.subnetId || vnic["is-primary"] !== true
        ) {
          throw Error("Replacement VNIC scope changed");
        }
        const privateIps = dataArray(
          await call([
            "network",
            "private-ip",
            "list",
            "--vnic-id",
            vnicId,
            "--all",
          ]),
        )
          .filter((v) => v["is-primary"] === true && v["vnic-id"] === vnicId);
        if (
          privateIps.length !== 1 ||
          state.privateIpId && state.privateIpId !== privateIps[0].id
        ) {
          throw Error("Replacement primary IP is not proved");
        }
        state.privateIpId = stringField(privateIps[0], "id");
      }
    };
    await reconcile();
    if (config.trial !== undefined && config.action === "provision") {
      // The initial trial capacity assessment runs under the same explicit
      // trial authority that gates every pre-mutation reassessment.
      assertReplacementApproval(config, digest);
      await proveTrialFunding(controller, config, runner);
    }
    const capacity = assessReplacementCapacity(resources, state, production);
    await writePrivateJson(REPORT, {
      observedAtUtc: new Date().toISOString(),
      planSha256: digest,
      ...capacity,
      ...(config.trial !== undefined ? { trial: config.trial } : {}),
      status: capacity.ready
        ? "REPLACEMENT_CAPACITY_READY"
        : "REPLACEMENT_CAPACITY_BLOCKED",
      provisioned: false,
    });
    if (config.action === "plan") {
      console.log(
        JSON.stringify({
          status: capacity.ready
            ? "REPLACEMENT_CAPACITY_READY"
            : "REPLACEMENT_CAPACITY_BLOCKED",
          ...capacity,
        }),
      );
      return;
    }
    if (!capacity.ready) {
      throw Error(
        config.trial !== undefined
          ? "Replacement would exceed trial capacity or touch unrecognized resources"
          : "Replacement would exceed free capacity or touch unowned resources",
      );
    }
    const preMutation = async () => {
      assertOracleMutationAllowed(await readGate());
      await backupControllerEvidence(controller, runner)
        .assertNoOtherController();
      const currentConfig = await readPrivateJson<ReplacementConfig>(CONFIG);
      assertReplacementApproval(currentConfig, digest);
      if (currentConfig.trial !== undefined) {
        await proveTrialFunding(controller, currentConfig, runner);
      }
      await validateBootstrap?.(currentConfig);
      const image = dataObject(
        await call([
          "compute",
          "image",
          "get",
          "--image-id",
          config.platformImageId,
        ]),
      );
      if (
        image["compartment-id"] !== null ||
        image["lifecycle-state"] !== "AVAILABLE" ||
        image["operating-system"] !== "Canonical Ubuntu" ||
        image["operating-system-version"] !== "24.04"
      ) throw Error("A current Oracle Ubuntu 24.04 platform image is required");
      const compatible = dataObject(
        await call([
          "compute",
          "image-shape-compatibility-entry",
          "get",
          "--image-id",
          config.platformImageId,
          "--shape-name",
          "VM.Standard.A1.Flex",
        ]),
      );
      if (
        compatible.shape !== "VM.Standard.A1.Flex" ||
        compatible["image-id"] !== config.platformImageId
      ) {
        throw Error("Platform image does not support the replacement shape");
      }
      for (
        const [field, value, min, max] of [
          ["ocpu-constraints", 2, "min", "max"],
          ["memory-constraints", 12, "min-in-gbs", "max-in-gbs"],
        ] as const
      ) {
        if (compatible[field] === null) continue;
        const bounds = dataObject({ data: compatible[field] });
        if (quantity(bounds, min) > value || quantity(bounds, max) < value) {
          throw Error(
            "Platform image resource constraints exclude the replacement",
          );
        }
      }
      const subnet = dataObject(
        await call([
          "network",
          "subnet",
          "get",
          "--subnet-id",
          config.subnetId,
        ]),
      );
      if (
        subnet.id !== config.subnetId ||
        subnet["compartment-id"] !== config.compartmentId ||
        subnet["lifecycle-state"] !== "AVAILABLE" ||
        subnet["prohibit-public-ip-on-vnic"] !== false ||
        subnet["availability-domain"] !== null &&
          subnet["availability-domain"] !== config.availabilityDomain
      ) {
        throw Error("Replacement subnet scope or public access is not proved");
      }
      const reserved = dataObject(
        await call([
          "network",
          "public-ip",
          "get",
          "--public-ip-id",
          config.reservedPublicIpId,
        ]),
      );
      if (
        reserved.lifetime !== "RESERVED" ||
        reserved["private-ip-id"] !== null &&
          reserved["private-ip-id"] !== state.privateIpId
      ) {
        throw Error(
          "Reserved address is assigned; never move a production address",
        );
      }
      resources = await inventory(controller, runner, fetchDocument);
      await reconcile();
      if (!assessReplacementCapacity(resources, state, production).ready) {
        throw Error("Fresh replacement capacity or ownership check failed");
      }
      assertReplacementApproval(
        await readPrivateJson<ReplacementConfig>(CONFIG),
        digest,
      );
      assertOracleMutationAllowed(await readGate());
      await backupControllerEvidence(controller, runner)
        .assertNoOtherController();
    };
    if (
      state.pending &&
      !(state.pending === "root" ? state.rootVolumeId : state.instanceId)
    ) {
      throw Error(
        "An earlier CREATE has no conclusive resource identity; do not repeat it",
      );
    }
    const tags = JSON.stringify({ [TAG]: config.requestId });
    if (!state.rootVolumeId) {
      await preMutation();
      if (state.rootVolumeId) {
        await save();
        throw Error(
          "A matching root appeared during preflight; resume its recorded identity",
        );
      }
      state.pending = "root";
      await save();
      const root = dataObject(
        await call([
          "bv",
          "volume",
          "create",
          "--compartment-id",
          config.compartmentId,
          "--availability-domain",
          config.availabilityDomain,
          "--size-in-gbs",
          "150",
          "--vpus-per-gb",
          "10",
          "--display-name",
          config.requestId + "-root",
          "--freeform-tags",
          tags,
          "--opc-retry-token",
          config.requestId.slice(9),
        ]),
      );
      state.rootVolumeId = stringField(root, "id");
      delete state.pending;
      await save();
    }
    if (!state.instanceId) {
      const root = dataObject(
        await call(["bv", "volume", "get", "--volume-id", state.rootVolumeId]),
      );
      if (root["lifecycle-state"] !== "AVAILABLE") {
        throw Error(
          "Replacement root is still provisioning; resume this same request later",
        );
      }
      await preMutation();
      if (state.instanceId) {
        await save();
        throw Error(
          "A matching instance appeared during preflight; resume its recorded identity",
        );
      }
      state.pending = "instance";
      await save();
      const created = dataObject(
        await call([
          "compute",
          "instance",
          "launch",
          "--compartment-id",
          config.compartmentId,
          "--availability-domain",
          config.availabilityDomain,
          "--subnet-id",
          config.subnetId,
          "--shape",
          "VM.Standard.A1.Flex",
          "--shape-config",
          JSON.stringify({ ocpus: 2, memoryInGBs: 12 }),
          "--launch-options",
          JSON.stringify({ isConsistentVolumeNamingEnabled: true }),
          "--source-details",
          JSON.stringify({
            sourceType: "image",
            imageId: config.platformImageId,
            bootVolumeSizeInGBs: 50,
          }),
          "--launch-volume-attachments",
          JSON.stringify([{
            type: "paravirtualized",
            volumeId: state.rootVolumeId,
            device: "/dev/oracleoci/oraclevdb",
          }]),
          "--assign-public-ip",
          "false",
          "--display-name",
          config.requestId,
          "--freeform-tags",
          tags,
          "--metadata",
          JSON.stringify({
            "user_data": btoa(
              String.fromCharCode(
                ...new TextEncoder().encode(config.cloudInit),
              ),
            ),
          }),
          "--opc-retry-token",
          config.requestId.slice(9),
        ]),
      );
      state.instanceId = stringField(created, "id");
      delete state.pending;
      await save();
    }
    await save();
    if (state.privateIpId) {
      let reservedResponse = await call([
        "network",
        "public-ip",
        "get",
        "--public-ip-id",
        config.reservedPublicIpId,
      ]);
      let reserved = dataObject(reservedResponse);
      if (reserved.lifetime !== "RESERVED") {
        throw Error("Replacement address is not reserved");
      }
      if (reserved["private-ip-id"] === null) {
        await preMutation();
        reservedResponse = await call([
          "network",
          "public-ip",
          "get",
          "--public-ip-id",
          config.reservedPublicIpId,
        ]);
        reserved = dataObject(reservedResponse);
        if (reserved.lifetime !== "RESERVED") {
          throw Error("Replacement address changed");
        }
      }
      if (reserved["private-ip-id"] === null) {
        // A lost response is reconciled by rereading this same reserved IP on
        // resume. This never allocates an address or detaches another owner.
        await call([
          "network",
          "public-ip",
          "update",
          "--public-ip-id",
          config.reservedPublicIpId,
          "--private-ip-id",
          state.privateIpId,
          "--if-match",
          stringField(reservedResponse, "etag"),
        ]);
      } else if (reserved["private-ip-id"] !== state.privateIpId) {
        throw Error("Reserved address ownership changed");
      }
      const assigned = dataObject(
        await call([
          "network",
          "public-ip",
          "get",
          "--public-ip-id",
          config.reservedPublicIpId,
        ]),
      );
      if (
        assigned["private-ip-id"] !== state.privateIpId ||
        assigned["lifecycle-state"] !== "ASSIGNED"
      ) {
        throw Error("Replacement public address assignment is not yet proved");
      }
      await save();
    }
    console.log(
      JSON.stringify({
        status: state.privateIpId
          ? "REPLACEMENT_CONTROL_PLANE_PROVED"
          : "REPLACEMENT_PROVISIONING",
        bootAccepted: false,
        restoreAccepted: false,
      }),
    );
  });
}
if (import.meta.main) {
  try {
    await runReplacement();
  } catch {
    console.error(
      "Pi replacement recovery stopped; preserve its private plan and journal",
    );
    Deno.exitCode = 1;
  }
}
