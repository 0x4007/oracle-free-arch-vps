import {
  assertUnattendedRecoveryAuthority,
  deriveRecoveryStageApproval,
  UNATTENDED_RECOVERY_OPERATION,
  type UnattendedRecoveryConfig,
  unattendedRecoveryPlan,
} from "../scripts/pi-recovery-authority.ts";
import {
  replacementPlanDigest,
  TRIAL_OPERATION,
} from "../scripts/pi-machine-recovery.ts";
const now = Date.parse("2026-09-11T06:00:00Z"),
  index = "a".repeat(64),
  revision = "b".repeat(40);
function config(): UnattendedRecoveryConfig {
  const c: UnattendedRecoveryConfig = {
    action: "provision",
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
    consolePublicKey: "existing-public-key-fixture",
    trial: {
      spendingCapUsd: 5,
      expiresAtUtc: new Date(now + 3 * 3600000).toISOString(),
    },
  };
  c.approval = {
    planSha256: replacementPlanDigest(c),
    approvedAtUtc: new Date(now).toISOString(),
    exactOperation: TRIAL_OPERATION,
  };
  const expiresAtUtc = new Date(now + 2 * 3600000).toISOString();
  c.unattended = {
    planSha256:
      unattendedRecoveryPlan(c, index, revision, expiresAtUtc).planSha256,
    indexSha256: index,
    sourceRevision: revision,
    approvedAtUtc: new Date(now).toISOString(),
    expiresAtUtc,
    exactOperation: UNATTENDED_RECOVERY_OPERATION,
  };
  return c;
}
function refuses(fn: () => unknown) {
  try {
    fn();
  } catch {
    return;
  }
  throw Error("Expected refusal");
}
Deno.test("unattended authority survives routine elapsed time within its original bound", () => {
  const c = config();
  assertUnattendedRecoveryAuthority(c, index, revision, now + 90 * 60000);
});
Deno.test("provisioning permission alone does not authorize reconstruction", () => {
  const c = config();
  delete c.unattended;
  refuses(() => assertUnattendedRecoveryAuthority(c, index, revision, now));
});
Deno.test("changed generation, console key, runtime and archive index refuse", () => {
  for (
    const mutate of [(c: UnattendedRecoveryConfig) => {
      c.generation = "generation-781c4067-aec2-45d5-9afb-77ee530e3a97";
    }, (c: UnattendedRecoveryConfig) => {
      c.consolePublicKey = "changed";
    }]
  ) {
    const c = config();
    mutate(c);
    refuses(() => assertUnattendedRecoveryAuthority(c, index, revision, now));
  }
  refuses(() =>
    assertUnattendedRecoveryAuthority(config(), "c".repeat(64), revision, now)
  );
  refuses(() =>
    assertUnattendedRecoveryAuthority(config(), index, "d".repeat(40), now)
  );
});
Deno.test("expiry cannot be extended or bypassed by stage approval", () => {
  const c = config();
  refuses(() =>
    assertUnattendedRecoveryAuthority(c, index, revision, now + 2 * 3600000)
  );
  c.unattended!.expiresAtUtc = new Date(now + 3 * 3600000).toISOString();
  refuses(() => assertUnattendedRecoveryAuthority(c, index, revision, now));
  const a = config().unattended!;
  refuses(() =>
    deriveRecoveryStageApproval(
      { planSha256: index, operation: "fixture" },
      a,
      now + 2 * 3600000,
    )
  );
});
Deno.test("derived stage receipt records actual bound plan and current timestamp", () => {
  const a = config().unattended!,
    p = { planSha256: index, operation: "fixture" };
  const r = deriveRecoveryStageApproval(p, a, now + 60000);
  if (
    r.planSha256 !== index || r.exactOperation !== "fixture" ||
    r.approvedAtUtc !== new Date(now + 60000).toISOString()
  ) throw Error("Receipt differs");
});
