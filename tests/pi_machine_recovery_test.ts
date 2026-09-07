import {
  assertReplacementApproval,
  assessReplacementCapacity,
  type ReplacementConfig,
  type ReplacementInventory,
  replacementPlanDigest,
  type ReplacementState,
  runReplacement,
  validateReplacementConfig,
} from "../scripts/pi-machine-recovery.ts";
import type { CommandRunner, JsonRecord } from "../scripts/oci.ts";

const terms =
  "first 1,500 OCPU hours and 9,000 GB hours per month for free; equivalent to 2 OCPUs and 12 GB of memory; total of 200 GB of Block Volume storage, and five volume backups; amounts apply to both boot volumes and block volumes combined; 20 GB of combined Standard tier, Infrequent Access tier, and Archive tier data";

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
          data = { "compartment-id": null, "lifecycle-state": "AVAILABLE" };
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
          data = { id: "ocid1.instance.example" };
        } else if (line.includes("compute instance list")) {
          data = launches
            ? [{
              id: "ocid1.instance.example",
              shape: "VM.Standard.A1.Flex",
              "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
              "image-id": config.platformImageId,
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
    } finally {
      Deno.chdir(previous);
      await Deno.remove(directory, { recursive: true });
    }
  },
});
