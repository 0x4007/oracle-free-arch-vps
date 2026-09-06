import {
  proveFreeVolumeSettings,
  proveNoBillableCustomImages,
  readFreeResourceSurfaceEvidence,
} from "../scripts/oci-backup-inventory.ts";
import type { CommandResult } from "../scripts/oci.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

const compliantBootVolume = {
  id: "boot",
  "lifecycle-state": "AVAILABLE",
  "vpus-per-gb": 10,
  "is-auto-tune-enabled": false,
  "autotune-policies": [],
  "boot-volume-replicas": [],
};

const compliantBlockVolume = {
  id: "root",
  "lifecycle-state": "AVAILABLE",
  "vpus-per-gb": 10,
  "is-auto-tune-enabled": false,
  "autotune-policies": [],
  "block-volume-replicas": [],
};

Deno.test("free volume proof requires balanced, non-autotuned, non-replicated resources", () => {
  const boot = proveFreeVolumeSettings(
    [compliantBootVolume],
    "boot-volume-replicas",
  );
  const block = proveFreeVolumeSettings(
    [compliantBlockVolume],
    "block-volume-replicas",
  );
  assert(
    boot.performanceProved && boot.autotuneProved && boot.replicationProved,
  );
  assert(
    block.performanceProved && block.autotuneProved &&
      block.replicationProved,
  );
});

Deno.test("free volume proof refuses missing or paid volume settings", () => {
  const missing = proveFreeVolumeSettings(
    [{ "lifecycle-state": "AVAILABLE", "vpus-per-gb": 10 }],
    "block-volume-replicas",
  );
  assert(!missing.autotuneProved && !missing.replicationProved);

  const paid = proveFreeVolumeSettings(
    [{
      ...compliantBlockVolume,
      "vpus-per-gb": 20,
      "is-auto-tune-enabled": true,
      "autotune-policies": [{ name: "automatic" }],
      "block-volume-replicas": [{ id: "replica" }],
    }],
    "block-volume-replicas",
  );
  assert(!paid.performanceProved && !paid.autotuneProved);
  assert(!paid.replicationProved);
});

Deno.test("custom image proof requires explicit zero billable size", () => {
  assert(proveNoBillableCustomImages([{
    id: "platform",
    "lifecycle-state": "AVAILABLE",
    "billable-size-in-gbs": 0,
  }]));
  assert(
    !proveNoBillableCustomImages([{
      id: "custom",
      "lifecycle-state": "AVAILABLE",
      "billable-size-in-gbs": 50,
    }]),
  );
  assert(
    !proveNoBillableCustomImages([{
      id: "unknown",
      "lifecycle-state": "AVAILABLE",
    }]),
  );
  assert(proveNoBillableCustomImages([{
    id: "deleted",
    "lifecycle-state": "DELETED",
  }]));
});

Deno.test("resource surface inventory reads every cost-sensitive API", async () => {
  const calls: string[][] = [];
  const runner = (
    _command: string,
    args: string[],
  ): Promise<CommandResult> => {
    calls.push(args);
    let data: unknown;
    if (args.includes("iam") && args.includes("compartment")) data = [];
    else if (args.includes("availability-domain")) data = [{ name: "ad-1" }];
    else if (args.includes("compute") && args.includes("image")) {
      data = [{
        id: "platform",
        "lifecycle-state": "AVAILABLE",
        "billable-size-in-gbs": 0,
      }];
    } else if (args.includes("boot-volume")) data = [compliantBootVolume];
    else if (args.includes("bv") && args.includes("volume")) {
      data = [compliantBlockVolume];
    } else throw new Error(`Unexpected command: ${args.join(" ")}`);
    return Promise.resolve({
      code: 0,
      stdout: JSON.stringify({ data }),
      stderr: "",
    });
  };
  const evidence = await readFreeResourceSurfaceEvidence({
    ociCliPath: "oci",
    ociProfile: "TEST",
    tenancyId: "tenancy",
    source: {
      instanceId: "instance",
      bootVolumeId: "boot",
      rootVolumeId: "root",
      compartmentId: "tenancy",
      region: "region",
    },
  }, runner);
  assert(evidence.freeResourceSurfaceProved);
  assert(evidence.activeBootVolumes.length === 1);
  assert(evidence.activeBlockVolumes.length === 1);
  assert(evidence.activeImages.length === 1);
  assert(
    calls.every((args) =>
      args.includes("--no-retry") && args.includes("--connection-timeout") &&
      args.includes("--read-timeout")
    ),
  );
});
