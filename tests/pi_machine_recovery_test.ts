import {
  assertReplacementApproval,
  assessReplacementCapacity,
  type ProductionBinding,
  proveTrialFunding,
  type ReplacementConfig,
  type ReplacementInventory,
  replacementPlanDigest,
  type ReplacementState,
  runReplacement,
  TRIAL_OPERATION,
  validateReplacementConfig,
} from "../scripts/pi-machine-recovery.ts";
import type { CommandRunner, JsonRecord } from "../scripts/oci.ts";

const terms =
  "first 1,500 OCPU hours and 9,000 GB hours per month for free; equivalent to 2 OCPUs and 12 GB of memory; total of 200 GB of Block Volume storage, and five volume backups; amounts apply to both boot volumes and block volumes combined; 20 GB of combined Standard tier, Infrequent Access tier, and Archive tier data";
const OPERATION_TEXT =
  "provision one 2 OCPU 12 GB replacement with 50 GB boot and 150 GB root and assign its existing unassigned reserved IP for direct Backblaze recovery";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw Error(message);
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
const config: ReplacementConfig = {
  action: "plan",
  requestId: "recovery-681c4067-aec2-45d5-9afb-77ee530e3a97",
  generation: "generation-681c4067-aec2-45d5-9afb-77ee530e3a97",
  tenancyId: "ocid1.tenancy.example",
  region: "home",
  compartmentId: "ocid1.tenancy.example",
  availabilityDomain: "example-domain",
  subnetId: "ocid1.subnet.example",
  reservedPublicIpId: "ocid1.publicip.example",
  platformImageId: "ocid1.image.example",
  cloudInit: "#cloud-config\n{}\n",
};
/** Both provision mutations share the same OCI CLI contract: the unsupported
 * --opc-retry-token option is never sent, while the global --no-retry policy
 * and the exact-request ownership tag remain on the call. */
function assertMutationContract(args: string[]): void {
  assert(!args.includes("--opc-retry-token"));
  assert(args.includes("--no-retry"));
  const tagIndex = args.indexOf("--freeform-tags");
  assert(tagIndex !== -1);
  assert(
    JSON.parse(args[tagIndex + 1]).uosRecoveryRequest === config.requestId,
  );
}
function empty(): ReplacementInventory {
  return {
    bootVolumes: [],
    rootVolumes: [],
    instances: [],
    backupMembers: 3,
    publicIps: 1,
    objectStorageBytes: 0,
  };
}
function owned(): { inventory: ReplacementInventory; state: ReplacementState } {
  return {
    state: {
      requestId: config.requestId,
      planSha256: replacementPlanDigest(config),
      rootVolumeId: "root",
      bootVolumeId: "boot",
      instanceId: "instance",
      updatedAtUtc: new Date().toISOString(),
    },
    inventory: {
      ...empty(),
      bootVolumes: [{ id: "boot", "size-in-gbs": 50 }],
      rootVolumes: [{ id: "root", "size-in-gbs": 150 }],
      instances: [{
        id: "instance",
        "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
      }],
    },
  };
}
/** Exact running 2 OCPU/12 GB production footprint with the 50/150 GB disks. */
function running(): ReplacementInventory {
  return {
    ...empty(),
    bootVolumes: [{ id: "boot", "size-in-gbs": 50 }],
    rootVolumes: [{ id: "root", "size-in-gbs": 150 }],
    instances: [{
      id: "instance",
      shape: "VM.Standard.A1.Flex",
      "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
      "lifecycle-state": "RUNNING",
    }],
  };
}
function productionBinding(): ProductionBinding {
  return {
    instanceId: "instance",
    bootVolumeId: "boot",
    rootVolumeId: "root",
  };
}
const fundingNow = Date.parse("2026-09-07T01:00:00Z");
const fundingController = {
  ociCliPath: "oci",
  ociProfile: "DEFAULT",
  tenancyId: "ocid1.tenancy.example",
  source: {
    compartmentId: "ocid1.tenancy.example",
    region: "home",
    instanceId: "production-instance",
    bootVolumeId: "production-boot",
    rootVolumeId: "production-root",
  },
};
function fundingConfig(): ReplacementConfig {
  return {
    ...config,
    action: "provision",
    trial: {
      spendingCapUsd: 300,
      expiresAtUtc: new Date(fundingNow + 3600000).toISOString(),
    },
  };
}
function verifiedSubscription(): JsonRecord {
  return {
    id: "subscription-id",
    "compartment-id": fundingController.tenancyId,
    "lifecycle-state": "ACTIVE",
    "subscription-tier": "FREE_AND_TRIAL",
    "payment-model": "FREE_TRIAL",
    "end-date": new Date(fundingNow + 30 * 24 * 3600000).toISOString(),
    promotion: [{ status: "ACTIVE", amount: 300, "currency-unit": "USD" }],
  };
}
function fundingRunner(
  list: unknown = undefined,
  get: JsonRecord = verifiedSubscription(),
  calls: string[] = [],
): CommandRunner {
  return (command, args) => {
    assert(command === "oci");
    const line = args.join(" ");
    calls.push(line);
    let data: unknown;
    if (line.includes("organizations subscription list")) {
      data = list === undefined ? { items: [{ id: "subscription-id" }] } : list;
    } else if (line.includes("organizations subscription get")) {
      data = get;
    } else throw Error("Unexpected provider operation: " + line);
    return Promise.resolve({
      code: 0,
      stdout: JSON.stringify({ data }),
      stderr: "",
    });
  };
}
async function fundingRefuses(list: unknown, get: JsonRecord): Promise<void> {
  let refused = false;
  try {
    await proveTrialFunding(
      fundingController,
      fundingConfig(),
      fundingRunner(list, get),
    );
  } catch {
    refused = true;
  }
  assert(refused);
}
Deno.test("production footprint blocks a second replacement", () => {
  const result = assessReplacementCapacity(owned().inventory);
  assert(
    !result.ready && result.peak.liveVolumeGb === 400 &&
      result.peak.ocpus === 4,
  );
});
Deno.test("post-loss empty tenancy reserves only the final 50/150 GB pair", () => {
  const result = assessReplacementCapacity(empty());
  assert(
    result.ready && result.peak.liveVolumeGb === 200 &&
      result.peak.ocpus === 2 && result.peak.memoryGb === 12,
  );
});
Deno.test("orphaned disks remain occupied after compute loss", () => {
  const { inventory } = owned();
  inventory.instances = [];
  assert(!assessReplacementCapacity(inventory).ready);
});
Deno.test("reconciled own resources are counted once", () => {
  const { inventory, state } = owned();
  const result = assessReplacementCapacity(inventory, state);
  assert(result.ready && result.peak.liveVolumeGb === 200);
});
Deno.test("missing recorded resources cannot silently authorize recreation", () => {
  const { state } = owned();
  assert(!assessReplacementCapacity(empty(), state).ready);
});
Deno.test("foreign small resources block even below numeric allowances", () => {
  const inventory = empty();
  inventory.rootVolumes.push({ id: "foreign", "size-in-gbs": 0 });
  assert(!assessReplacementCapacity(inventory).ready);
});
Deno.test("negative nonfinite duplicate and missing inventory values are refused", () => {
  for (const value of [-1, NaN, Infinity]) {
    const inventory = empty();
    inventory.rootVolumes.push({ id: "root", "size-in-gbs": value });
    refuses(() => assessReplacementCapacity(inventory));
  }
  const { inventory, state } = owned();
  inventory.rootVolumes.push({ ...inventory.rootVolumes[0] });
  refuses(() => assessReplacementCapacity(inventory, state));
  for (const value of [-1, NaN, Infinity, 0.5]) {
    refuses(() => assessReplacementCapacity({ ...empty(), publicIps: value }));
  }
});
Deno.test("backup and Object Storage overages block", () => {
  assert(!assessReplacementCapacity({ ...empty(), backupMembers: 6 }).ready);
  assert(
    !assessReplacementCapacity({
      ...empty(),
      objectStorageBytes: 20_000_000_001,
    }).ready,
  );
});
Deno.test("exact plan binds generation target and bootstrap bytes but not action", () => {
  const digest = replacementPlanDigest(config);
  assert(digest === replacementPlanDigest({ ...config, action: "provision" }));
  for (
    const field of [
      "generation",
      "subnetId",
      "compartmentId",
      "availabilityDomain",
      "reservedPublicIpId",
      "platformImageId",
      "cloudInit",
      "requestId",
    ] as const
  ) {
    assert(
      digest !==
        replacementPlanDigest({
          ...config,
          [field]: config[field] + "changed",
        }),
    );
  }
});
Deno.test("configuration accepts tenancy root and refuses malformed identities", () => {
  validateReplacementConfig(config);
  validateReplacementConfig({
    ...config,
    compartmentId: "ocid1.compartment.example",
  });
  refuses(() =>
    validateReplacementConfig({
      ...config,
      requestId: "recovery-" + "-".repeat(36),
    })
  );
  refuses(() =>
    validateReplacementConfig({
      ...config,
      compartmentId: "ocid1.instance.example",
    })
  );
  refuses(() =>
    validateReplacementConfig({
      ...config,
      cloudInit: "#cloud-config\n" + "a".repeat(32000),
    })
  );
});

Deno.test("missing expired future revoked and changed approvals are refused", () => {
  const now = Date.parse("2026-09-07T01:00:00Z");
  const digest = replacementPlanDigest(config);
  const approved: ReplacementConfig = {
    ...config,
    action: "provision",
    approval: {
      approvedAtUtc: new Date(now).toISOString(),
      planSha256: digest,
      exactOperation:
        "provision one 2 OCPU 12 GB replacement with 50 GB boot and 150 GB root and assign its existing unassigned reserved IP for direct Backblaze recovery",
    },
  };
  assertReplacementApproval(approved, digest, now);
  refuses(() =>
    assertReplacementApproval({ ...approved, approval: undefined }, digest, now)
  );
  refuses(() =>
    assertReplacementApproval({ ...approved, action: "plan" }, digest, now)
  );
  refuses(() =>
    assertReplacementApproval(
      { ...approved, cloudInit: approved.cloudInit + "# change" },
      digest,
      now,
    )
  );
  for (const delta of [-3600001, 1]) {
    refuses(() =>
      assertReplacementApproval(
        {
          ...approved,
          approval: {
            ...approved.approval!,
            approvedAtUtc: new Date(now + delta).toISOString(),
          },
        },
        digest,
        now,
      )
    );
  }
});

// Real controller and durable journal with a provider-shaped, credential-free
// runner. No test subprocess, network call or real resource is permitted.
Deno.test({
  name: "controller reconciles lost CREATE and rechecks capacity before launch",
  ignore:
    (await Deno.permissions.query({ name: "read" })).state !== "granted" ||
    (await Deno.permissions.query({ name: "write" })).state !== "granted",
  permissions: { read: true, write: true },
  fn: async () => {
    const previous = Deno.cwd();
    const directory = await Deno.makeTempDir();
    try {
      Deno.chdir(directory);
      await Deno.mkdir(".private", { mode: 0o700 });
      const approved = {
        ...config,
        action: "provision",
        approval: {
          approvedAtUtc: new Date().toISOString(),
          exactOperation:
            "provision one 2 OCPU 12 GB replacement with 50 GB boot and 150 GB root and assign its existing unassigned reserved IP for direct Backblaze recovery",
          planSha256: replacementPlanDigest(config),
        },
      };
      await Deno.writeTextFile(
        ".private/pi-machine-recovery.json",
        JSON.stringify(approved),
      );
      await Deno.writeTextFile(
        ".private/backup-controller.json",
        JSON.stringify({
          ociCliPath: "oci",
          ociProfile: "DEFAULT",
          tenancyId: config.compartmentId,
          source: {
            compartmentId: config.compartmentId,
            region: "home",
            instanceId: "lost",
            bootVolumeId: "lost-boot",
            rootVolumeId: "lost-root",
          },
        }),
      );
      await Deno.chmod(".private/backup-controller.json", 0o600);
      await Deno.chmod(".private/pi-machine-recovery.json", 0o600);
      let root: JsonRecord | undefined;
      let compatibleLoader = false;
      let loseResponse = true;
      let foreign = false;
      let creates = 0;
      let launches = 0;
      let eligibilityReads = 0;
      let assignedIp: string | null = null;
      let assignments = 0;
      const runner: CommandRunner = (command, args) => {
        if (command === "ps") {
          return Promise.resolve({
            code: 0,
            stdout: `${Deno.pid} 1 deno controller\n1 0 init init`,
            stderr: "",
          });
        }
        assert(command === "oci");
        const line = args.join(" ");
        let data: unknown;
        if (line.includes("iam region-subscription list")) {
          data = [{ "is-home-region": true, "region-name": "home" }];
        } else if (line.includes("organizations subscription list")) {
          data = { items: [{ id: "subscription" }] };
        } else if (line.includes("organizations subscription get")) {
          eligibilityReads++;
          data = {
            "compartment-id": config.compartmentId,
            "lifecycle-state": "ACTIVE",
            "subscription-tier": "FREE_AND_TRIAL",
            "payment-model": "FREE_TRIAL",
          };
        } else if (line.includes("iam compartment list")) {
          data = [];
        } else if (line.includes("iam availability-domain list")) {
          data = [{ name: config.availabilityDomain }];
        } else if (line.includes("os ns get")) {
          data = "namespace";
        } else if (line.includes("os bucket list")) data = [];
        else if (line.includes("compute image get")) {
          data = {
            "compartment-id": null,
            "lifecycle-state": "AVAILABLE",
            "operating-system": "Canonical Ubuntu",
            "operating-system-version": compatibleLoader ? "24.04" : "22.04",
          };
        } else if (
          line.includes("compute image-shape-compatibility-entry get")
        ) {
          data = {
            shape: "VM.Standard.A1.Flex",
            "image-id": config.platformImageId,
            "ocpu-constraints": { min: 1, max: 80 },
            "memory-constraints": { "min-in-gbs": 1, "max-in-gbs": 512 },
          };
        } else if (line.includes("network subnet get")) {
          data = {
            id: config.subnetId,
            "compartment-id": config.compartmentId,
            "lifecycle-state": "AVAILABLE",
            "prohibit-public-ip-on-vnic": false,
            "availability-domain": null,
          };
        } else if (line.includes("network public-ip get")) {
          data = {
            lifetime: "RESERVED",
            "private-ip-id": assignedIp,
            "lifecycle-state": assignedIp ? "ASSIGNED" : "AVAILABLE",
          };
        } else if (line.includes("network public-ip update")) {
          assert(args.includes("--if-match") && args.includes("etag-example"));
          assignedIp = "private-ip";
          assignments++;
          data = {};
        } else if (line.includes("bv volume create")) {
          creates++;
          assert(eligibilityReads >= 2);
          assertMutationContract(args);
          root = {
            id: "ocid1.volume.example",
            "size-in-gbs": 150,
            "vpus-per-gb": 10,
            "is-auto-tune-enabled": false,
            "autotune-policies": [],
            "block-volume-replicas": null,
            "compartment-id": config.compartmentId,
            "availability-domain": config.availabilityDomain,
            "freeform-tags": { uosRecoveryRequest: config.requestId },
            "lifecycle-state": "AVAILABLE",
          };
          if (loseResponse) {
            loseResponse = false;
            return Promise.reject(Error("lost CREATE response"));
          }
          data = root;
        } else if (line.includes("bv volume get")) {
          data = root;
        } else if (line.includes("bv volume list")) {
          data = root
            ? [
              root,
              ...(foreign
                ? [{ ...root, id: "foreign", "freeform-tags": {} }]
                : []),
            ]
            : [];
        } else if (line.includes("compute instance launch")) {
          launches++;
          assert(eligibilityReads >= 4);
          assertMutationContract(args);
          assert(
            JSON.parse(args[args.indexOf("--launch-options") + 1])
              .isConsistentVolumeNamingEnabled === true,
          );
          assert(
            JSON.parse(args[args.indexOf("--launch-options") + 1])
              .networkType === "PARAVIRTUALIZED",
          );
          assert(
            JSON.parse(args[args.indexOf("--launch-volume-attachments") + 1])[0]
              .device === "/dev/oracleoci/oraclevdb",
          );
          data = { id: "ocid1.instance.example" };
        } else if (line.includes("compute instance list")) {
          data = launches
            ? [{
              id: "ocid1.instance.example",
              shape: "VM.Standard.A1.Flex",
              "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
              "image-id": config.platformImageId,
              "launch-options": { "is-consistent-volume-naming-enabled": true },
              "compartment-id": config.compartmentId,
              "availability-domain": config.availabilityDomain,
              "freeform-tags": { uosRecoveryRequest: config.requestId },
              "lifecycle-state": "RUNNING",
            }]
            : [];
        } else if (line.includes("bv boot-volume list")) {
          data = launches
            ? [{
              ...root,
              id: "boot",
              "size-in-gbs": 50,
              "image-id": config.platformImageId,
              "boot-volume-replicas": null,
            }]
            : [];
        } else if (line.includes("compute boot-volume-attachment list")) {
          data = [{
            "instance-id": "ocid1.instance.example",
            "boot-volume-id": "boot",
            "lifecycle-state": "ATTACHED",
          }];
        } else if (line.includes("compute volume-attachment list")) {
          data = [{
            "volume-id": root!.id,
            "instance-id": "ocid1.instance.example",
            "lifecycle-state": "ATTACHED",
            "attachment-type": "paravirtualized",
            device: "/dev/oracleoci/oraclevdb",
          }];
        } else if (line.includes("compute vnic-attachment list")) {
          data = [{
            "vnic-id": "vnic",
            "instance-id": "ocid1.instance.example",
            "lifecycle-state": "ATTACHED",
          }];
        } else if (line.includes("network vnic get")) {
          data = { "subnet-id": config.subnetId, "is-primary": true };
        } else if (line.includes("network private-ip list")) {
          data = [{ id: "private-ip", "vnic-id": "vnic", "is-primary": true }];
        } else if (
          [
            "compute image list",
            "bv boot-volume list",
            "compute instance list",
            "bv backup list",
            "bv boot-volume-backup list",
            "network public-ip list",
          ].some((part) => line.includes(part))
        ) data = [];
        else throw Error("Unexpected provider operation: " + line);
        return Promise.resolve({
          code: 0,
          stdout: JSON.stringify({ data, etag: "etag-example" }),
          stderr: "",
        });
      };
      const run = () => runReplacement(runner, () => Promise.resolve(terms));
      let failure = "";
      try {
        await run();
      } catch (error) {
        failure = String(error);
      }
      assert(
        failure.includes("Ubuntu 24.04") && Number(creates) === 0 &&
          Number(launches) === 0,
      );
      compatibleLoader = true;
      try {
        await run();
      } catch (error) {
        failure = String(error);
      }
      assert(
        failure.includes("lost CREATE response") && creates === 1 &&
          launches === 0,
        failure,
      );
      const journal = JSON.parse(
        await Deno.readTextFile(".private/pi-machine-recovery-state.json"),
      );
      assert(journal.pending === "root" && !journal.rootVolumeId);
      foreign = true;
      try {
        await run();
      } catch (error) {
        failure = String(error);
      }
      assert(
        failure.includes("exceed free capacity") && creates === 1 &&
          launches === 0,
      );
      foreign = false;
      await run();
      assert(creates === 1 && Number(launches) === 1);
      const final = JSON.parse(
        await Deno.readTextFile(".private/pi-machine-recovery-state.json"),
      );
      assert(
        final.rootVolumeId === root!.id &&
          final.instanceId === "ocid1.instance.example" && !final.pending,
      );
      await run();
      await run();
      assert(assignments === 1 && creates === 1 && Number(launches) === 1);
      approved.approval.approvedAtUtc = new Date(Date.now() - 3600001)
        .toISOString();
      await Deno.writeTextFile(
        ".private/pi-machine-recovery.json",
        JSON.stringify(approved),
      );
      await run(); // Read-only reconciliation must not renew creation authority.
      assert(assignments === 1 && creates === 1 && Number(launches) === 1);
      assignedIp = null;
      let expired = false;
      try {
        await run();
      } catch (error) {
        expired = String(error).includes("exact replacement approval");
      }
      assert(expired && assignments === 1);
    } finally {
      Deno.chdir(previous);
      await Deno.remove(directory, { recursive: true });
    }
  },
});

Deno.test("trial coexistence accepts exactly 400 GB 4 OCPU 24 GB while normal still refuses", () => {
  const trial = assessReplacementCapacity(
    running(),
    undefined,
    productionBinding(),
  );
  assert(
    trial.ready && trial.peak.liveVolumeGb === 400 &&
      trial.peak.ocpus === 4 && trial.peak.memoryGb === 24,
  );
  const normal = assessReplacementCapacity(running());
  assert(
    !normal.ready && normal.peak.liveVolumeGb === 400 &&
      normal.peak.ocpus === 4 && normal.peak.memoryGb === 24,
  );
});

Deno.test("trial fails closed on absent stopped or wrong-shaped production source", () => {
  const absent = assessReplacementCapacity(
    empty(),
    undefined,
    productionBinding(),
  );
  assert(!absent.ready);
  const stopped = running();
  stopped.instances[0]["lifecycle-state"] = "STOPPED";
  assert(
    !assessReplacementCapacity(stopped, undefined, productionBinding()).ready,
  );
  const shape = running();
  shape.instances[0].shape = "VM.Standard.E4.Flex";
  assert(
    !assessReplacementCapacity(shape, undefined, productionBinding()).ready,
  );
  const ocpus = running();
  ocpus.instances[0]["shape-config"] = { ocpus: 4, "memory-in-gbs": 12 };
  assert(
    !assessReplacementCapacity(ocpus, undefined, productionBinding()).ready,
  );
  const memory = running();
  memory.instances[0]["shape-config"] = { ocpus: 2, "memory-in-gbs": 24 };
  assert(
    !assessReplacementCapacity(memory, undefined, productionBinding()).ready,
  );
  const boot = running();
  boot.bootVolumes[0]["size-in-gbs"] = 60;
  assert(
    !assessReplacementCapacity(boot, undefined, productionBinding()).ready,
  );
  const root = running();
  root.rootVolumes[0]["size-in-gbs"] = 200;
  assert(
    !assessReplacementCapacity(root, undefined, productionBinding()).ready,
  );
});

Deno.test("missing or overlapping production identities are refused", () => {
  refuses(() =>
    assessReplacementCapacity(running(), undefined, {
      ...productionBinding(),
      instanceId: "",
    })
  );
  refuses(() =>
    assessReplacementCapacity(running(), undefined, {
      instanceId: "boot",
      bootVolumeId: "boot",
      rootVolumeId: "root",
    })
  );
  const { state } = owned();
  refuses(() =>
    assessReplacementCapacity(running(), state, productionBinding())
  );
});

Deno.test("foreign zero-size volume still blocks trial coexistence", () => {
  const inventory = running();
  inventory.rootVolumes.push({ id: "foreign", "size-in-gbs": 0 });
  assert(
    !assessReplacementCapacity(inventory, undefined, productionBinding()).ready,
  );
  assert(!assessReplacementCapacity(inventory).ready);
});

Deno.test("trial caps bind the coexistence and refuse any numeric overage", () => {
  const production = productionBinding();
  const second = running();
  second.instances.push({
    id: "instance2",
    shape: "VM.Standard.A1.Flex",
    "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
    "lifecycle-state": "RUNNING",
  });
  const stateSecond: ReplacementState = {
    requestId: config.requestId,
    planSha256: replacementPlanDigest(config),
    instanceId: "instance2",
    updatedAtUtc: new Date().toISOString(),
  };
  const boundary = assessReplacementCapacity(second, stateSecond, production);
  assert(
    boundary.ready && boundary.peak.liveVolumeGb === 400 &&
      boundary.peak.ocpus === 4 && boundary.peak.memoryGb === 24,
  );
  const extraBoot = running();
  extraBoot.bootVolumes.push({ id: "boot2", "size-in-gbs": 51 });
  const stateBoot: ReplacementState = {
    requestId: config.requestId,
    planSha256: replacementPlanDigest(config),
    bootVolumeId: "boot2",
    updatedAtUtc: new Date().toISOString(),
  };
  assert(!assessReplacementCapacity(extraBoot, stateBoot, production).ready);
  const third = running();
  third.instances.push(
    {
      id: "instance2",
      shape: "VM.Standard.A1.Flex",
      "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
      "lifecycle-state": "RUNNING",
    },
    {
      id: "instance3",
      shape: "VM.Standard.A1.Flex",
      "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
      "lifecycle-state": "RUNNING",
    },
  );
  const stateThird: ReplacementState = {
    requestId: config.requestId,
    planSha256: replacementPlanDigest(config),
    instanceId: "instance3",
    updatedAtUtc: new Date().toISOString(),
  };
  assert(!assessReplacementCapacity(third, stateThird, production).ready);
  assert(
    !assessReplacementCapacity(
      { ...running(), publicIps: 3 },
      undefined,
      production,
    ).ready,
  );
});

Deno.test("distinct trial operation and approval digest drive approval", () => {
  const now = Date.parse("2026-09-07T01:00:00Z");
  const trialFields = {
    spendingCapUsd: 300,
    expiresAtUtc: new Date(now + 3600000).toISOString(),
  };
  const trial: ReplacementConfig = {
    ...config,
    action: "provision",
    trial: trialFields,
  };
  const trialDigest = replacementPlanDigest(trial);
  assert(trialDigest !== replacementPlanDigest(config));
  assert(
    trialDigest !== replacementPlanDigest({
      ...trial,
      trial: { ...trialFields, spendingCapUsd: 250 },
    }),
  );
  assert(
    trialDigest !== replacementPlanDigest({
      ...trial,
      trial: {
        ...trialFields,
        expiresAtUtc: new Date(now + 7200000).toISOString(),
      },
    }),
  );
  const approved: ReplacementConfig = {
    ...trial,
    approval: {
      approvedAtUtc: new Date(now).toISOString(),
      planSha256: trialDigest,
      exactOperation: TRIAL_OPERATION,
    },
  };
  assertReplacementApproval(approved, trialDigest, now);
  refuses(() =>
    assertReplacementApproval(
      {
        ...approved,
        approval: { ...approved.approval!, exactOperation: OPERATION_TEXT },
      },
      trialDigest,
      now,
    )
  );
  refuses(() =>
    assertReplacementApproval(
      {
        ...approved,
        approval: {
          ...approved.approval!,
          planSha256: replacementPlanDigest(config),
        },
      },
      trialDigest,
      now,
    )
  );
  const normal: ReplacementConfig = {
    ...config,
    action: "provision",
    approval: {
      approvedAtUtc: new Date(now).toISOString(),
      planSha256: replacementPlanDigest(config),
      exactOperation: OPERATION_TEXT,
    },
  };
  assertReplacementApproval(normal, replacementPlanDigest(config), now);
  refuses(() =>
    assertReplacementApproval(
      {
        ...normal,
        approval: { ...normal.approval!, exactOperation: TRIAL_OPERATION },
      },
      replacementPlanDigest(config),
      now,
    )
  );
});

Deno.test("trial cap and expiry validation plus the four hour approval bound", () => {
  const now = Date.parse("2026-09-07T01:00:00Z");
  const expiry = new Date(now + 3600000).toISOString();
  validateReplacementConfig({
    ...config,
    trial: { spendingCapUsd: 300, expiresAtUtc: expiry },
  });
  for (const spendingCapUsd of [0, -1, NaN, Infinity, 300.01]) {
    refuses(() =>
      validateReplacementConfig({
        ...config,
        trial: { spendingCapUsd, expiresAtUtc: expiry },
      })
    );
  }
  for (
    const expiresAtUtc of [
      "2026-09-07",
      "2026-09-07T01:00:00",
      "2026-13-07T01:00:00Z",
      "later",
    ]
  ) {
    refuses(() =>
      validateReplacementConfig({
        ...config,
        trial: { spendingCapUsd: 300, expiresAtUtc },
      })
    );
  }
  const trialFields = { spendingCapUsd: 300, expiresAtUtc: expiry };
  const trial: ReplacementConfig = {
    ...config,
    action: "provision",
    trial: trialFields,
  };
  const digest = replacementPlanDigest(trial);
  const approved: ReplacementConfig = {
    ...trial,
    approval: {
      approvedAtUtc: new Date(now).toISOString(),
      planSha256: digest,
      exactOperation: TRIAL_OPERATION,
    },
  };
  assertReplacementApproval(approved, digest, now);
  const withExpiry = (expiresAtUtc: string) => {
    const next: ReplacementConfig = {
      ...trial,
      trial: { ...trialFields, expiresAtUtc },
    };
    const nextDigest = replacementPlanDigest(next);
    return {
      config: {
        ...next,
        approval: {
          approvedAtUtc: new Date(now).toISOString(),
          planSha256: nextDigest,
          exactOperation: TRIAL_OPERATION,
        },
      },
      digest: nextDigest,
    };
  };
  const past = withExpiry(new Date(now - 1000).toISOString());
  refuses(() => assertReplacementApproval(past.config, past.digest, now));
  const over = withExpiry(new Date(now + 4 * 3600000 + 1000).toISOString());
  refuses(() => assertReplacementApproval(over.config, over.digest, now));
  const exact = withExpiry(new Date(now + 4 * 3600000).toISOString());
  assertReplacementApproval(exact.config, exact.digest, now);
});

Deno.test(
  "durable trial authority keeps a stale valid approval usable but still refuses expired, over-lifetime, malformed or future trial authority",
  () => {
    const now = Date.parse("2026-09-07T01:00:00Z");
    // Two hours old: beyond the one-hour window an agent-selected freshness
    // check must not revoke the owner's standing trial authorization.
    const approvedAtUtc = new Date(now - 2 * 3600000).toISOString();
    const trialFields = {
      spendingCapUsd: 300,
      expiresAtUtc: new Date(now + 2 * 3600000).toISOString(),
    };
    const trial: ReplacementConfig = {
      ...config,
      action: "provision",
      trial: trialFields,
    };
    const digest = replacementPlanDigest(trial);
    const approved: ReplacementConfig = {
      ...trial,
      approval: {
        approvedAtUtc,
        planSha256: digest,
        exactOperation: TRIAL_OPERATION,
      },
    };
    assertReplacementApproval(approved, digest, now);
    // The exact plan digest and target still bind into the durable authority.
    refuses(() =>
      assertReplacementApproval(
        {
          ...approved,
          approval: { ...approved.approval!, planSha256: "stale-digest" },
        },
        digest,
        now,
      )
    );
    refuses(() =>
      assertReplacementApproval(
        {
          ...approved,
          approval: { ...approved.approval!, exactOperation: OPERATION_TEXT },
        },
        digest,
        now,
      )
    );
    // Expired trial coverage still fails closed.
    const expired: ReplacementConfig = {
      ...approved,
      trial: {
        ...trialFields,
        expiresAtUtc: new Date(now - 1000).toISOString(),
      },
    };
    refuses(() =>
      assertReplacementApproval(expired, replacementPlanDigest(expired), now)
    );
    // A stale approval cannot stretch the trial lifetime beyond its bound.
    const over: ReplacementConfig = {
      ...approved,
      trial: {
        ...trialFields,
        expiresAtUtc: new Date(now + 3 * 3600000).toISOString(),
      },
    };
    refuses(() =>
      assertReplacementApproval(over, replacementPlanDigest(over), now)
    );
    // Malformed and future approval timestamps remain refused.
    refuses(() =>
      assertReplacementApproval(
        {
          ...approved,
          approval: { ...approved.approval!, approvedAtUtc: "not-a-date" },
        },
        digest,
        now,
      )
    );
    refuses(() =>
      assertReplacementApproval(
        {
          ...approved,
          approval: {
            ...approved.approval!,
            approvedAtUtc: new Date(now + 1000).toISOString(),
          },
        },
        digest,
        now,
      )
    );
    // The ordinary free-only path never uses trial authority and still needs
    // a fresh exact approval.
    const normal: ReplacementConfig = {
      ...config,
      action: "provision",
      approval: {
        approvedAtUtc,
        planSha256: replacementPlanDigest(config),
        exactOperation: OPERATION_TEXT,
      },
    };
    refuses(() =>
      assertReplacementApproval(normal, replacementPlanDigest(config), now)
    );
  },
);

Deno.test("proveTrialFunding accepts the verified ACTIVE USD promotion with only two calls", async () => {
  const calls: string[] = [];
  const runner = fundingRunner(undefined, verifiedSubscription(), calls);
  await proveTrialFunding(fundingController, fundingConfig(), runner);
  assert(calls.length === 2);
  assert(calls[0].includes("organizations subscription list"));
  assert(calls[1].includes("organizations subscription get --subscription-id"));
  assert(!calls[0].includes("promotion"));
  assert(!calls[1].includes("promotion"));
});

Deno.test("proveTrialFunding refuses a wrong account or subscription state", async () => {
  const base = verifiedSubscription();
  for (
    const get of [
      { ...base, id: "another-subscription" },
      { ...base, "compartment-id": "ocid1.tenancy.other" },
      { ...base, "lifecycle-state": "INACTIVE" },
      { ...base, "subscription-tier": "FREE" },
      { ...base, "payment-model": "PAY_AS_YOU_GO" },
    ]
  ) {
    await fundingRefuses(undefined, get);
  }
});

Deno.test("proveTrialFunding refuses a missing or earlier end-date", async () => {
  const base = verifiedSubscription();
  const missing = { ...base };
  delete missing["end-date"];
  for (
    const get of [
      missing,
      { ...base, "end-date": new Date(fundingNow + 3600000).toISOString() },
      { ...base, "end-date": new Date(fundingNow + 1000).toISOString() },
      { ...base, "end-date": "not-a-date" },
    ]
  ) {
    await fundingRefuses(undefined, get);
  }
});

Deno.test("proveTrialFunding refuses inactive non-USD too-small or malformed promotions", async () => {
  const base = verifiedSubscription();
  for (
    const get of [
      {
        ...base,
        promotion: [{ status: "EXPIRED", amount: 300, "currency-unit": "USD" }],
      },
      {
        ...base,
        promotion: [{ status: "ACTIVE", amount: 300, "currency-unit": "EUR" }],
      },
      {
        ...base,
        promotion: [{ status: "ACTIVE", amount: 299, "currency-unit": "USD" }],
      },
      { ...base, promotion: [{ status: "ACTIVE", "currency-unit": "USD" }] },
      { ...base, promotion: "none" },
      { ...base, promotion: null },
    ]
  ) {
    await fundingRefuses(undefined, get);
  }
});

Deno.test("proveTrialFunding refuses a missing duplicate or malformed subscription collection", async () => {
  for (
    const list of [
      { items: [] },
      { items: [{ id: "a" }, { id: "b" }] },
      { items: "one" },
      { no: "items" },
      null,
      [{ id: "subscription-id" }],
    ]
  ) {
    await fundingRefuses(list, verifiedSubscription());
  }
});
