import {
  controllerCidr,
  drillLaunchRequest,
  type DrillPlan,
  drillPlanDigest,
  validateDrillApproval,
} from "../scripts/isolated-drill.ts";

const plan: DrillPlan = {
  source: {
    instanceId: "production",
    bootVolumeId: "production-boot",
    rootVolumeId: "production-root",
    compartmentId: "tenancy",
    region: "us-ashburn-1",
  },
  pair: {
    suffix: "20260905T080000Z",
    bootId: "fresh-boot-backup",
    rootId: "fresh-root-backup",
  },
  sourceAcceptedAtUtc: "2026-09-05T08:30:00Z",
  availabilityDomain: "AD",
  productionReservedIpId: "production-ip",
  productionSubnetId: "production-subnet",
  productionVcnId: "production-vcn",
  controllerIpv4: "74.72.113.64",
  suffix: "20260905T090000Z",
  maxDurationHours: 4,
  spendingCapUsd: 0.5,
  helperImageId: "helper-image",
  offlineFilesSha256: "0".repeat(64),
};
function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
async function refuses(run: () => unknown) {
  let rejected = false;
  try {
    await run();
  } catch {
    rejected = true;
  }
  assert(rejected);
}
Deno.test("drill launch attaches both cloned volumes and cannot reference production IP", async () => {
  const request = drillLaunchRequest(
    plan,
    "isolated-subnet",
    "cloned-boot",
    "cloned-root",
  );
  assert(request.launchVolumeAttachments[0].volumeId === "cloned-root");
  // OCI must inherit the restored boot volume's image launch capabilities.
  assert(!("launchOptions" in request));
  assert(!JSON.stringify(request).includes("production-ip"));
  await refuses(() =>
    drillLaunchRequest(plan, "production-subnet", "cloned-boot", "cloned-root")
  );
  await refuses(() =>
    drillLaunchRequest(
      plan,
      "isolated-subnet",
      "production-boot",
      "cloned-root",
    )
  );
});
Deno.test("drill SSH rule cannot widen to an entire CIDR", async () => {
  assert(controllerCidr(plan.controllerIpv4) === "74.72.113.64/32");
  await refuses(() => controllerCidr("0.0.0.0/0"));
  await refuses(() => controllerCidr("10.0.0.1"));
});
Deno.test("drill approval binds exact plan and cannot extend past trial expiry", async () => {
  const now = new Date("2026-09-05T09:00:00Z");
  const approval = {
    approvedAtUtc: now.toISOString(),
    expiresAtUtc: "2026-09-05T10:00:00Z",
    exactOperation: "one isolated trial-funded paired restore drill" as const,
    planSha256: await drillPlanDigest(plan),
  };
  const account = {
    observedAtUtc: now.toISOString(),
    subscriptionTier: "FREE_AND_TRIAL",
    paymentModel: "FREE_TRIAL",
    trialExpiresAtUtc: "2026-09-29T23:59:59Z",
    availableTrialCreditsUsd: 300,
  };
  const backup = (kind: "boot" | "root") => ({
    id: plan.pair[kind === "boot" ? "bootId" : "rootId"],
    "lifecycle-state": "AVAILABLE",
    "display-name": `arch-${
      kind === "boot" ? "stage" : "root"
    }-golden-${plan.pair.suffix}`,
    "size-in-gbs": kind === "boot" ? 50 : 150,
    type: "FULL",
    "compartment-id": "tenancy",
    [kind === "boot" ? "boot-volume-id" : "volume-id"]:
      plan.source[kind === "boot" ? "bootVolumeId" : "rootVolumeId"],
  });
  await validateDrillApproval(
    plan,
    approval,
    account,
    backup("boot"),
    backup("root"),
    now,
  );
  await refuses(() =>
    validateDrillApproval(
      { ...plan, controllerIpv4: "8.8.8.8" },
      approval,
      account,
      backup("boot"),
      backup("root"),
      now,
    )
  );
  await refuses(() =>
    validateDrillApproval(
      plan,
      approval,
      { ...account, trialExpiresAtUtc: "2026-09-05T12:00:00Z" },
      backup("boot"),
      backup("root"),
      now,
    )
  );
});
