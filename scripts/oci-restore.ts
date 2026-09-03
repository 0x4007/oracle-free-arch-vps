import {
  type CommandRunner,
  dataArray,
  dataObject,
  defaultRunner,
  type JsonRecord,
  numberField,
  readPrivateJson,
  redactOcid,
  runJson,
  stringField,
  writePrivateJson,
} from "./oci.ts";

const CONFIG_PATH = ".private/restore.json";
const STATE_PATH = ".private/restore-state.json";
const APPROVAL_OPERATION =
  "restore matched arch backup pair and reassign the reserved IP";
const SOFT_STOP_APPROVAL_OPERATION =
  "gracefully stop the OCI instance with SOFTSTOP";
const TERMINAL_VOLUME_STATES = new Set(["TERMINATED"]);
const TERMINAL_INSTANCE_STATES = new Set(["TERMINATED"]);
const APPROVAL_MAX_AGE_MS = 60 * 60 * 1000;

type RestoreAction =
  | "inventory"
  | "soft-stop"
  | "wait-for-stopped"
  | "plan"
  | "restore"
  | "verify";

interface RestoreConfig {
  action: RestoreAction;
  ociCliPath: string;
  ociProfile: string;
  region: string;
  compartmentId: string;
  availabilityDomains: string[];
  subnetId: string;
  bootVolumeBackupId: string;
  rootVolumeBackupId: string;
  expectedBootSourceVolumeId: string;
  expectedRootSourceVolumeId: string;
  reservedPublicIpId: string;
  instanceId: string;
  expectedPairSuffix: string;
  expectedRootUuid: string;
  stopWaitSeconds: number;
  approval: {
    approved: boolean;
    approvedAtUtc: string;
    exactOperation: string;
    approvedPairSuffix: string;
    approvedTargets: {
      bootVolumeBackupId: string;
      rootVolumeBackupId: string;
      expectedBootSourceVolumeId: string;
      expectedRootSourceVolumeId: string;
      compartmentId: string;
      availabilityDomains: string[];
      subnetId: string;
      reservedPublicIpId: string;
    };
  };
  softStopApproval?: {
    approved: boolean;
    approvedAtUtc: string;
    exactOperation: string;
    instanceId: string;
  };
}

interface RestoreState {
  pairSuffix: string;
  availabilityDomain?: string;
  bootVolumeId?: string;
  rootVolumeId?: string;
  instanceId?: string;
  vnicId?: string;
  privateIpId?: string;
  rootAttached?: boolean;
  reservedIpAssigned?: boolean;
  updatedAtUtc: string;
}

function assertPrivateValue(value: string, name: string): void {
  if (!value || value.startsWith("<") || value.includes("_OCID>")) {
    throw new Error(`${name} is not configured in ${CONFIG_PATH}`);
  }
}

export function validateConfig(config: RestoreConfig): void {
  const actions: RestoreAction[] = [
    "inventory",
    "soft-stop",
    "wait-for-stopped",
    "plan",
    "restore",
    "verify",
  ];
  if (!actions.includes(config.action)) {
    throw new Error("Unsupported restore action");
  }
  assertPrivateValue(config.ociCliPath, "ociCliPath");
  assertPrivateValue(config.compartmentId, "compartmentId");
  assertPrivateValue(config.region, "region");
  if (config.availabilityDomains.length === 0) {
    throw new Error("No availability domain is configured");
  }
  for (const domain of config.availabilityDomains) {
    assertPrivateValue(domain, "availabilityDomain");
  }
  assertPrivateValue(config.bootVolumeBackupId, "bootVolumeBackupId");
  assertPrivateValue(config.rootVolumeBackupId, "rootVolumeBackupId");
  assertPrivateValue(
    config.expectedBootSourceVolumeId,
    "expectedBootSourceVolumeId",
  );
  assertPrivateValue(
    config.expectedRootSourceVolumeId,
    "expectedRootSourceVolumeId",
  );
  assertPrivateValue(config.expectedPairSuffix, "expectedPairSuffix");
  assertPrivateValue(config.expectedRootUuid, "expectedRootUuid");
  if (config.action === "restore") {
    assertPrivateValue(config.subnetId, "subnetId");
    assertPrivateValue(config.reservedPublicIpId, "reservedPublicIpId");
    const approvedAt = Date.parse(config.approval.approvedAtUtc);
    const approvalAge = Date.now() - approvedAt;
    const expectedTargets = {
      bootVolumeBackupId: config.bootVolumeBackupId,
      rootVolumeBackupId: config.rootVolumeBackupId,
      expectedBootSourceVolumeId: config.expectedBootSourceVolumeId,
      expectedRootSourceVolumeId: config.expectedRootSourceVolumeId,
      compartmentId: config.compartmentId,
      availabilityDomains: config.availabilityDomains,
      subnetId: config.subnetId,
      reservedPublicIpId: config.reservedPublicIpId,
    };
    if (
      !config.approval.approved ||
      config.approval.exactOperation !== APPROVAL_OPERATION ||
      config.approval.approvedPairSuffix !== config.expectedPairSuffix ||
      Number.isNaN(approvedAt) ||
      approvalAge < -5 * 60 * 1000 ||
      approvalAge > APPROVAL_MAX_AGE_MS ||
      JSON.stringify(config.approval.approvedTargets) !==
        JSON.stringify(expectedTargets)
    ) {
      throw new Error(
        "The exact restore approval is absent or does not match the selected pair",
      );
    }
  }
  if (config.action === "soft-stop") {
    assertPrivateValue(config.instanceId, "instanceId");
    const approval = config.softStopApproval;
    const approvedAt = Date.parse(approval?.approvedAtUtc ?? "");
    const approvalAge = Date.now() - approvedAt;
    if (
      !approval?.approved ||
      approval.exactOperation !== SOFT_STOP_APPROVAL_OPERATION ||
      approval.instanceId !== config.instanceId ||
      Number.isNaN(approvedAt) ||
      approvalAge < -5 * 60 * 1000 ||
      approvalAge > APPROVAL_MAX_AGE_MS
    ) {
      throw new Error(
        "Current exact SOFTSTOP approval is absent or does not match the instance",
      );
    }
  }
}

export function pairSuffix(name: string): string | undefined {
  return /([0-9]{8}T[0-9]{6}Z)$/.exec(name)?.[1];
}

export function validateBackupPair(
  boot: JsonRecord,
  root: JsonRecord,
  expectedSuffix: string,
  expectedBootSourceVolumeId?: string,
  expectedRootSourceVolumeId?: string,
  expectedCompartmentId?: string,
): void {
  if (stringField(boot, "lifecycle-state") !== "AVAILABLE") {
    throw new Error("The staging backup is not AVAILABLE");
  }
  if (stringField(root, "lifecycle-state") !== "AVAILABLE") {
    throw new Error("The root backup is not AVAILABLE");
  }
  if (numberField(boot, "size-in-gbs") !== 50) {
    throw new Error("The staging backup source is not 50 GB");
  }
  if (numberField(root, "size-in-gbs") !== 150) {
    throw new Error("The root backup source is not 150 GB");
  }
  if (
    stringField(boot, "type") !== "FULL" || stringField(root, "type") !== "FULL"
  ) {
    throw new Error("Both selected recovery backups must be FULL");
  }
  const bootSuffix = pairSuffix(stringField(boot, "display-name"));
  const rootSuffix = pairSuffix(stringField(root, "display-name"));
  if (
    stringField(boot, "display-name") !==
      `arch-stage-golden-${expectedSuffix}` ||
    stringField(root, "display-name") !==
      `arch-root-golden-${expectedSuffix}` ||
    bootSuffix !== expectedSuffix || rootSuffix !== expectedSuffix
  ) {
    throw new Error("Backup names do not have the approved shared suffix");
  }
  if (
    expectedBootSourceVolumeId &&
    boot["boot-volume-id"] !== expectedBootSourceVolumeId
  ) {
    throw new Error(
      "The staging backup source does not match the private plan",
    );
  }
  if (
    expectedRootSourceVolumeId &&
    root["volume-id"] !== expectedRootSourceVolumeId
  ) {
    throw new Error("The root backup source does not match the private plan");
  }
  if (
    expectedCompartmentId &&
    (boot["compartment-id"] !== expectedCompartmentId ||
      root["compartment-id"] !== expectedCompartmentId)
  ) {
    throw new Error(
      "The selected backup pair is outside the planned compartment",
    );
  }
}

export function activeVolumeTotal(volumes: JsonRecord[]): number {
  return volumes.reduce((total, volume) => {
    const state = stringField(volume, "lifecycle-state");
    return TERMINAL_VOLUME_STATES.has(state)
      ? total
      : total + numberField(volume, "size-in-gbs");
  }, 0);
}

function ociArgs(config: RestoreConfig, args: string[]): string[] {
  return [
    "--profile",
    config.ociProfile || "DEFAULT",
    "--region",
    config.region,
    ...args,
  ];
}

async function loadConfig(): Promise<RestoreConfig> {
  return await readPrivateJson<RestoreConfig>(CONFIG_PATH);
}

async function loadState(): Promise<RestoreState> {
  try {
    return await readPrivateJson<RestoreState>(STATE_PATH);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      return { pairSuffix: "", updatedAtUtc: new Date().toISOString() };
    }
    throw error;
  }
}

async function saveState(state: RestoreState): Promise<void> {
  state.updatedAtUtc = new Date().toISOString();
  await writePrivateJson(STATE_PATH, state);
}

export function validateRestoreStateBinding(
  state: { pairSuffix: string; availabilityDomain?: string },
  expectedPairSuffix: string,
  approvedAvailabilityDomains: string[],
): void {
  if (state.pairSuffix && state.pairSuffix !== expectedPairSuffix) {
    throw new Error("Private restore state belongs to another backup pair");
  }
  if (
    state.availabilityDomain &&
    !approvedAvailabilityDomains.includes(state.availabilityDomain)
  ) {
    throw new Error(
      "Private restore state uses an unapproved availability domain",
    );
  }
}

function validateRestoredVolume(
  volume: JsonRecord,
  expectedName: string,
  expectedSizeGb: number,
  expectedBackupId: string,
  expectedCompartmentId: string,
  expectedAvailabilityDomain: string | undefined,
): void {
  const source = volume["source-details"];
  if (
    stringField(volume, "display-name") !== expectedName ||
    numberField(volume, "size-in-gbs") !== expectedSizeGb ||
    numberField(volume, "vpus-per-gb") !== 10 ||
    volume["compartment-id"] !== expectedCompartmentId ||
    (expectedAvailabilityDomain &&
      volume["availability-domain"] !== expectedAvailabilityDomain) ||
    !source ||
    typeof source !== "object" ||
    (source as JsonRecord).id !== expectedBackupId ||
    TERMINAL_VOLUME_STATES.has(stringField(volume, "lifecycle-state"))
  ) {
    throw new Error(
      "Recorded restore volume does not match the approved target",
    );
  }
}

async function verifyRootAttachment(
  config: RestoreConfig,
  state: RestoreState,
  runner: CommandRunner,
): Promise<void> {
  if (!state.instanceId || !state.rootVolumeId) {
    throw new Error(
      "Root attachment cannot be checked before restore state is complete",
    );
  }
  const attachments = dataArray(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "compute",
        "volume-attachment",
        "list",
        "--compartment-id",
        config.compartmentId,
        "--instance-id",
        state.instanceId,
        "--volume-id",
        state.rootVolumeId,
        "--all",
      ]),
      runner,
    ),
  );
  const accepted = attachments.filter((attachment) =>
    attachment["instance-id"] === state.instanceId &&
    attachment["volume-id"] === state.rootVolumeId &&
    attachment["lifecycle-state"] === "ATTACHED" &&
    String(attachment["attachment-type"]).toLowerCase() === "paravirtualized"
  );
  if (accepted.length !== 1) {
    throw new Error(
      "The approved Arch root volume is not attached exactly once by paravirtualized transport",
    );
  }
}

async function readInventory(config: RestoreConfig, runner: CommandRunner) {
  const bootBackup = dataObject(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "bv",
        "boot-volume-backup",
        "get",
        "--boot-volume-backup-id",
        config.bootVolumeBackupId,
      ]),
      runner,
    ),
  );
  const rootBackup = dataObject(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "bv",
        "backup",
        "get",
        "--volume-backup-id",
        config.rootVolumeBackupId,
      ]),
      runner,
    ),
  );
  validateBackupPair(
    bootBackup,
    rootBackup,
    config.expectedPairSuffix,
    config.expectedBootSourceVolumeId,
    config.expectedRootSourceVolumeId,
    config.compartmentId,
  );

  const blockVolumes = dataArray(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "bv",
        "volume",
        "list",
        "--compartment-id",
        config.compartmentId,
        "--all",
      ]),
      runner,
    ),
  );
  const bootVolumes: JsonRecord[] = [];
  for (const domain of config.availabilityDomains) {
    bootVolumes.push(...dataArray(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "bv",
          "boot-volume",
          "list",
          "--compartment-id",
          config.compartmentId,
          "--availability-domain",
          domain,
          "--all",
        ]),
        runner,
      ),
    ));
  }
  const liveVolumeGb = activeVolumeTotal([...bootVolumes, ...blockVolumes]);
  const instances = dataArray(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "compute",
        "instance",
        "list",
        "--compartment-id",
        config.compartmentId,
        "--all",
      ]),
      runner,
    ),
  );
  const activeInstances = instances.filter((item) =>
    !TERMINAL_INSTANCE_STATES.has(
      stringField(item, "lifecycle-state"),
    )
  );
  return {
    bootBackup,
    rootBackup,
    liveVolumeGb,
    activeBootVolumes:
      bootVolumes.filter((item) =>
        !TERMINAL_VOLUME_STATES.has(stringField(item, "lifecycle-state"))
      ).length,
    activeBlockVolumes:
      blockVolumes.filter((item) =>
        !TERMINAL_VOLUME_STATES.has(stringField(item, "lifecycle-state"))
      ).length,
    activeInstances: activeInstances.length,
    bootVolumes,
    blockVolumes,
    instances: activeInstances,
  };
}

async function reconcileRestoreState(
  config: RestoreConfig,
  state: RestoreState,
  runner: CommandRunner,
): Promise<void> {
  validateRestoreStateBinding(
    state,
    config.expectedPairSuffix,
    config.availabilityDomains,
  );
  if (state.bootVolumeId) {
    const boot = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "bv",
          "boot-volume",
          "get",
          "--boot-volume-id",
          state.bootVolumeId,
        ]),
        runner,
      ),
    );
    validateRestoredVolume(
      boot,
      `arch-stage-restore-${config.expectedPairSuffix}`,
      50,
      config.bootVolumeBackupId,
      config.compartmentId,
      state.availabilityDomain,
    );
  }
  if (state.rootVolumeId) {
    const root = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "bv",
          "volume",
          "get",
          "--volume-id",
          state.rootVolumeId,
        ]),
        runner,
      ),
    );
    validateRestoredVolume(
      root,
      `arch-root-restore-${config.expectedPairSuffix}`,
      150,
      config.rootVolumeBackupId,
      config.compartmentId,
      state.availabilityDomain,
    );
  }
  if (state.instanceId) {
    const instance = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "compute",
          "instance",
          "get",
          "--instance-id",
          state.instanceId,
        ]),
        runner,
      ),
    );
    if (
      instance["display-name"] !== "arch" ||
      instance.shape !== "VM.Standard.A1.Flex" ||
      instance["compartment-id"] !== config.compartmentId ||
      (state.availabilityDomain &&
        instance["availability-domain"] !== state.availabilityDomain) ||
      typeof instance["shape-config"] !== "object" ||
      (instance["shape-config"] as JsonRecord).ocpus !== 2 ||
      (instance["shape-config"] as JsonRecord)["memory-in-gbs"] !== 12 ||
      TERMINAL_INSTANCE_STATES.has(
        stringField(instance, "lifecycle-state"),
      )
    ) {
      throw new Error(
        "Recorded restore instance does not match the private state",
      );
    }
  }
}

async function capacityDomain(
  config: RestoreConfig,
  runner: CommandRunner,
): Promise<string> {
  const shapeRequest = JSON.stringify([{
    instanceShape: "VM.Standard.A1.Flex",
    instanceShapeConfig: { ocpus: 2, memoryInGBs: 12 },
  }]);
  for (const domain of config.availabilityDomains) {
    const report = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "compute",
          "compute-capacity-report",
          "create",
          "--compartment-id",
          config.compartmentId,
          "--availability-domain",
          domain,
          "--shape-availabilities",
          shapeRequest,
        ]),
        runner,
      ),
    );
    const entries = report["shape-availabilities"];
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new Error(`Capacity report for ${domain} contains no shape result`);
    }
    const statuses = entries.map((entry) =>
      typeof entry === "object" && entry !== null
        ? (entry as JsonRecord)["availability-status"]
        : undefined
    );
    const available = entries.some((entry) =>
      typeof entry === "object" && entry !== null &&
      (entry as JsonRecord)["availability-status"] === "AVAILABLE" &&
      numberField(entry as JsonRecord, "available-count") > 0
    );
    if (available) return domain;
    if (statuses.every((status) => status === "OUT_OF_HOST_CAPACITY")) continue;
    throw new Error(
      `Capacity report for ${domain} returned a non-retryable status`,
    );
  }
  throw new Error(
    "No configured availability domain reports A1 capacity; no volume was restored",
  );
}

async function waitForStopped(
  config: RestoreConfig,
  runner: CommandRunner,
): Promise<void> {
  assertPrivateValue(config.instanceId, "instanceId");
  const deadline = Date.now() + Math.max(1, config.stopWaitSeconds) * 1000;
  let lastState = "UNKNOWN";
  while (Date.now() < deadline) {
    const instance = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "compute",
          "instance",
          "get",
          "--instance-id",
          config.instanceId,
        ]),
        runner,
      ),
    );
    lastState = stringField(instance, "lifecycle-state");
    if (lastState === "STOPPED") {
      console.log(JSON.stringify({ status: "STOPPED" }));
      return;
    }
    if (lastState !== "RUNNING" && lastState !== "STOPPING") {
      console.log(JSON.stringify({
        status: "UNEXPECTED_LIFECYCLE_STATE",
        lifecycleState: lastState,
      }));
      Deno.exitCode = 4;
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10_000));
  }
  console.log(JSON.stringify({
    status: lastState === "RUNNING"
      ? "CONTROL_PLANE_STOP_REQUIRED"
      : "STOPPED_NOT_OBSERVED",
    lifecycleState: lastState,
    instruction:
      "Use an approved SOFTSTOP while the guest is running. Never automatically invoke STOP or RESET.",
  }));
  Deno.exitCode = 3;
}

type SoftStopStatus =
  | "STOPPED"
  | "SOFTSTOP_TIMEOUT"
  | "SOFTSTOP_FAILED"
  | "UNEXPECTED_LIFECYCLE_STATE";

export function classifySoftStopResult(
  commandFailed: boolean,
  timedOut: boolean,
  lifecycleState: string,
): SoftStopStatus {
  if (lifecycleState === "STOPPED") return "STOPPED";
  if (commandFailed) return "SOFTSTOP_FAILED";
  if (timedOut) return "SOFTSTOP_TIMEOUT";
  return "UNEXPECTED_LIFECYCLE_STATE";
}

async function instanceMetadata(
  config: RestoreConfig,
  runner: CommandRunner,
): Promise<{ data: JsonRecord; etag: string }> {
  const response = await runJson(
    config.ociCliPath,
    ociArgs(config, [
      "compute",
      "instance",
      "get",
      "--instance-id",
      config.instanceId,
    ]),
    runner,
  );
  return { data: dataObject(response), etag: stringField(response, "etag") };
}

async function softStop(
  config: RestoreConfig,
  runner: CommandRunner,
): Promise<void> {
  const beforeResponse = await instanceMetadata(config, runner);
  const before = beforeResponse.data;
  const beforeState = stringField(before, "lifecycle-state");
  if (beforeState !== "RUNNING") {
    console.log(JSON.stringify({
      status: "UNEXPECTED_LIFECYCLE_STATE",
      lifecycleState: beforeState,
      mutationPerformed: false,
    }));
    Deno.exitCode = 3;
    return;
  }
  let commandFailed = false;
  let errorMessage: string | undefined;
  try {
    const result = await runner(
      config.ociCliPath,
      ociArgs(config, [
        "compute",
        "instance",
        "action",
        "--instance-id",
        config.instanceId,
        "--action",
        "SOFTSTOP",
        "--if-match",
        beforeResponse.etag,
        "--output",
        "json",
      ]),
    );
    commandFailed = result.code !== 0;
    if (commandFailed) {
      errorMessage = redactOcid(result.stderr.trim() || result.stdout.trim());
    }
  } catch (error) {
    commandFailed = true;
    errorMessage = redactOcid(
      error instanceof Error ? error.message : String(error),
    );
  }
  const deadline = Date.now() + 1_200_000;
  let afterState = "UNKNOWN";
  let readFailed = false;
  while (!commandFailed && Date.now() < deadline) {
    try {
      afterState = stringField(
        (await instanceMetadata(config, runner)).data,
        "lifecycle-state",
      );
    } catch (error) {
      readFailed = true;
      errorMessage = redactOcid(
        error instanceof Error ? error.message : String(error),
      );
      break;
    }
    if (afterState === "STOPPED") break;
    if (afterState !== "RUNNING" && afterState !== "STOPPING") break;
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  if (commandFailed) {
    try {
      afterState = stringField(
        (await instanceMetadata(config, runner)).data,
        "lifecycle-state",
      );
    } catch {
      // Keep UNKNOWN when the required best-effort reread also fails.
    }
  }
  if (
    !commandFailed && !readFailed && afterState !== "STOPPED" &&
    Date.now() >= deadline
  ) {
    try {
      afterState = stringField(
        (await instanceMetadata(config, runner)).data,
        "lifecycle-state",
      );
    } catch (error) {
      readFailed = true;
      errorMessage = redactOcid(
        error instanceof Error ? error.message : String(error),
      );
    }
  }
  const timedOut = !commandFailed && !readFailed && afterState !== "STOPPED" &&
    Date.now() >= deadline;
  const status = classifySoftStopResult(
    commandFailed || readFailed,
    timedOut,
    afterState,
  );
  console.log(JSON.stringify({
    status,
    lifecycleState: afterState,
    mutationAttempted: true,
    error: errorMessage,
    instruction: status === "STOPPED"
      ? "The instance reached STOPPED."
      : "Reread OCI state and investigate. Do not automatically issue STOP or RESET.",
  }));
  if (status !== "STOPPED") {
    Deno.exitCode = status === "SOFTSTOP_TIMEOUT" ? 3 : 4;
  }
}

async function restore(
  config: RestoreConfig,
  runner: CommandRunner,
): Promise<void> {
  const inventory = await readInventory(config, runner);
  const state = await loadState();
  validateRestoreStateBinding(
    state,
    config.expectedPairSuffix,
    config.availabilityDomains,
  );
  await reconcileRestoreState(config, state, runner);
  const recordedVolumeIds = new Set(
    [state.bootVolumeId, state.rootVolumeId].filter((value): value is string =>
      Boolean(value)
    ),
  );
  const unexpectedVolumes = [
    ...inventory.bootVolumes,
    ...inventory.blockVolumes,
  ]
    .filter((item) =>
      !TERMINAL_VOLUME_STATES.has(stringField(item, "lifecycle-state"))
    )
    .filter((item) => !recordedVolumeIds.has(stringField(item, "id")));
  const unexpectedVolumeGb = activeVolumeTotal(unexpectedVolumes);
  if (unexpectedVolumeGb !== 0) {
    throw new Error(
      `Restore refused: ${unexpectedVolumeGb} GB of unrecorded live boot/block storage remains`,
    );
  }
  if (inventory.liveVolumeGb > 200) {
    throw new Error(
      `Restore refused: ${inventory.liveVolumeGb} GB exceeds the hard live-storage ceiling`,
    );
  }
  const unexpectedInstances = inventory.instances.filter((item) =>
    item.id !== state.instanceId
  );
  if (unexpectedInstances.length !== 0) {
    throw new Error(
      `Restore refused: ${unexpectedInstances.length} unrecorded non-terminated instance(s) remain`,
    );
  }
  const reservedIp = dataObject(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "network",
        "public-ip",
        "get",
        "--public-ip-id",
        config.reservedPublicIpId,
      ]),
      runner,
    ),
  );
  const assignedToRecordedPrivateIp = state.reservedIpAssigned &&
    reservedIp["private-ip-id"] === state.privateIpId;
  if (
    reservedIp.lifetime !== "RESERVED" ||
    (reservedIp["private-ip-id"] !== null && !assignedToRecordedPrivateIp)
  ) {
    throw new Error(
      "Restore refused: the planned reserved IP is not unassigned",
    );
  }
  state.pairSuffix = config.expectedPairSuffix;

  if (!state.availabilityDomain) {
    state.availabilityDomain = await capacityDomain(config, runner);
    await saveState(state);
  }
  const suffix = config.expectedPairSuffix;
  if (!state.bootVolumeId) {
    const result = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "bv",
          "boot-volume",
          "create",
          "--availability-domain",
          state.availabilityDomain,
          "--compartment-id",
          config.compartmentId,
          "--boot-volume-backup-id",
          config.bootVolumeBackupId,
          "--display-name",
          `arch-stage-restore-${suffix}`,
          "--vpus-per-gb",
          "10",
          "--wait-for-state",
          "AVAILABLE",
        ]),
        runner,
      ),
    );
    state.bootVolumeId = stringField(result, "id");
    await saveState(state);
  }
  if (!state.rootVolumeId) {
    const result = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "bv",
          "volume",
          "create",
          "--availability-domain",
          state.availabilityDomain,
          "--compartment-id",
          config.compartmentId,
          "--volume-backup-id",
          config.rootVolumeBackupId,
          "--display-name",
          `arch-root-restore-${suffix}`,
          "--vpus-per-gb",
          "10",
          "--wait-for-state",
          "AVAILABLE",
        ]),
        runner,
      ),
    );
    state.rootVolumeId = stringField(result, "id");
    await saveState(state);
  }
  if (!state.instanceId) {
    const result = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "compute",
          "instance",
          "launch",
          "--availability-domain",
          state.availabilityDomain,
          "--compartment-id",
          config.compartmentId,
          "--subnet-id",
          config.subnetId,
          "--shape",
          "VM.Standard.A1.Flex",
          "--shape-config",
          JSON.stringify({ ocpus: 2, memoryInGBs: 12 }),
          "--source-boot-volume-id",
          state.bootVolumeId,
          "--launch-volume-attachments",
          JSON.stringify([{
            type: "paravirtualized",
            volumeId: state.rootVolumeId,
          }]),
          "--display-name",
          "arch",
          "--assign-public-ip",
          "false",
          "--launch-options",
          JSON.stringify({
            networkType: "PARAVIRTUALIZED",
            remoteDataVolumeType: "PARAVIRTUALIZED",
            firmware: "UEFI_64",
            isConsistentVolumeNamingEnabled: false,
            isPvEncryptionInTransitEnabled: false,
          }),
          "--wait-for-state",
          "RUNNING",
        ]),
        runner,
      ),
    );
    state.instanceId = stringField(result, "id");
    await saveState(state);
  }
  await verifyRootAttachment(config, state, runner);
  state.rootAttached = true;
  await saveState(state);

  const attachments = dataArray(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "compute",
        "vnic-attachment",
        "list",
        "--compartment-id",
        config.compartmentId,
        "--instance-id",
        state.instanceId,
      ]),
      runner,
    ),
  );
  const primary =
    attachments.find((entry) => entry["lifecycle-state"] === "ATTACHED") ??
      attachments[0];
  if (!primary) {
    throw new Error("No VNIC attachment was found for the restored instance");
  }
  state.vnicId = stringField(primary, "vnic-id");
  const privateIps = dataArray(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "network",
        "private-ip",
        "list",
        "--vnic-id",
        state.vnicId,
      ]),
      runner,
    ),
  );
  const primaryIp = privateIps.find((entry) => entry["is-primary"] === true) ??
    privateIps[0];
  if (!primaryIp) throw new Error("No primary private IP was found");
  state.privateIpId = stringField(primaryIp, "id");
  await saveState(state);
  if (!state.reservedIpAssigned) {
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "network",
        "public-ip",
        "update",
        "--public-ip-id",
        config.reservedPublicIpId,
        "--private-ip-id",
        state.privateIpId,
        "--wait-for-state",
        "ASSIGNED",
      ]),
      runner,
    );
    state.reservedIpAssigned = true;
    await saveState(state);
  }
  console.log(JSON.stringify(
    {
      status: "CONTROL_PLANE_RESTORE_COMPLETE",
      pairSuffix: suffix,
      next:
        "Run guest UUID, GRUB, kernel parity, SSH, service, DNS, and backup acceptance before production use.",
    },
    null,
    2,
  ));
}

async function verify(
  config: RestoreConfig,
  runner: CommandRunner,
): Promise<void> {
  const state = await loadState();
  if (!state.instanceId || !state.bootVolumeId || !state.rootVolumeId) {
    throw new Error("Restore state is incomplete");
  }
  await reconcileRestoreState(config, state, runner);
  await verifyRootAttachment(config, state, runner);
  const instance = dataObject(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "compute",
        "instance",
        "get",
        "--instance-id",
        state.instanceId,
      ]),
      runner,
    ),
  );
  const boot = dataObject(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "bv",
        "boot-volume",
        "get",
        "--boot-volume-id",
        state.bootVolumeId,
      ]),
      runner,
    ),
  );
  const root = dataObject(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "bv",
        "volume",
        "get",
        "--volume-id",
        state.rootVolumeId,
      ]),
      runner,
    ),
  );
  console.log(JSON.stringify(
    {
      status: "METADATA_PROVED",
      instanceState: instance["lifecycle-state"],
      bootVolumeState: boot["lifecycle-state"],
      bootVolumeGb: boot["size-in-gbs"],
      rootVolumeState: root["lifecycle-state"],
      rootVolumeGb: root["size-in-gbs"],
      pairSuffix: state.pairSuffix,
      expectedRootUuid: config.expectedRootUuid,
      restoreDrillProved: false,
      next: "Complete the live guest checks in 05-ACCEPTANCE.md.",
    },
    null,
    2,
  ));
}

export async function main(
  runner: CommandRunner = defaultRunner,
): Promise<void> {
  const config = await loadConfig();
  validateConfig(config);
  if (config.action === "wait-for-stopped") {
    return await waitForStopped(config, runner);
  }
  if (config.action === "soft-stop") return await softStop(config, runner);
  if (config.action === "restore") return await restore(config, runner);
  if (config.action === "verify") return await verify(config, runner);
  const inventory = await readInventory(config, runner);
  console.log(JSON.stringify(
    {
      action: config.action,
      pairSuffix: config.expectedPairSuffix,
      backupPair: "AVAILABLE_50_GB_PLUS_150_GB",
      liveVolumeGb: inventory.liveVolumeGb,
      activeBootVolumes: inventory.activeBootVolumes,
      activeBlockVolumes: inventory.activeBlockVolumes,
      activeInstances: inventory.activeInstances,
      restoreCapacityReady: inventory.liveVolumeGb === 0,
      mutationPerformed: false,
    },
    null,
    2,
  ));
}

if (import.meta.main) await main();
