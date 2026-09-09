import {
  APPROVAL_MAX_AGE_MS,
  buildGroupRestoreLaunchRequest,
  buildRestoredBootVolumeRequest,
  buildRestoredRootVolumeRequest,
  type GroupRestoreApproval,
  groupRestoreCleanupOrder,
  groupRestoreCliArgs,
  groupRestoreDisplayName,
  type GroupRestoreEvidence,
  type GroupRestoreJournal,
  groupRestoreLifetime,
  groupRestoreMetadataState,
  type GroupRestorePlan,
  groupRestorePlanDigest,
  groupRestorePlanState,
  type GroupRestoreResourceKind,
  type GroupRestoreResourceRequest,
  type GroupRestoreRunner,
  guardGroupRestoreRun,
  journalGroupRestoreIntent,
  OCI_CLI_DISCIPLINE_FLAGS,
  reconcileGroupRestoreResource,
  TRIAL_EVIDENCE_MAX_AGE_MS,
  validateGroupRestoreApproval,
  validateGroupRestoreEvidence,
  validateGroupRestoreLifetime,
  validateGroupRestorePlan,
  validateGroupRestoreTargets,
} from "../scripts/oci-group-restore-drill.ts";

const plan: GroupRestorePlan = {
  source: {
    instanceId: "instance-source",
    bootVolumeId: "volume-source-boot",
    rootVolumeId: "volume-source-root",
    compartmentId: "compartment",
    region: "us-ashburn-1",
  },
  availabilityDomain: "AD-1",
  volumeGroupId: "group",
  volumeGroupBackupId: "capture",
  bootMemberBackupId: "member-boot",
  rootMemberBackupId: "member-root",
  productionSubnetId: "subnet-production",
  productionVcnId: "vcn-production",
  productionReservedIpId: "ip-production",
  isolatedSubnetId: "subnet-isolated",
  isolatedVcnId: "vcn-isolated",
  isolatedCidrBlock: "10.77.0.0/28",
  controllerIpv4: "74.72.113.64",
  suffix: "20260905T090000Z",
  maxDurationHours: 4,
  spendingCapUsd: 0.5,
};

const evidence: GroupRestoreEvidence = {
  group: {
    id: plan.volumeGroupBackupId,
    "volume-group-id": plan.volumeGroupId,
    "compartment-id": plan.source.compartmentId,
    "lifecycle-state": "AVAILABLE",
    type: "FULL",
    "time-created": "2026-09-05T09:00:00Z",
    "volume-backup-ids": [plan.bootMemberBackupId, plan.rootMemberBackupId],
  },
  bootMember: {
    id: plan.bootMemberBackupId,
    "display-name": `provider-boot-${plan.suffix}`,
    "lifecycle-state": "AVAILABLE",
    "size-in-gbs": 50,
    type: "FULL",
    "compartment-id": plan.source.compartmentId,
    "volume-group-backup-id": plan.volumeGroupBackupId,
    "boot-volume-id": plan.source.bootVolumeId,
    "time-created": "2026-09-05T09:00:01Z",
  },
  rootMember: {
    id: plan.rootMemberBackupId,
    "display-name": `provider-root-${plan.suffix}`,
    "lifecycle-state": "AVAILABLE",
    "size-in-gbs": 150,
    type: "FULL",
    "compartment-id": plan.source.compartmentId,
    "volume-group-backup-id": plan.volumeGroupBackupId,
    "volume-id": plan.source.rootVolumeId,
    "time-created": "2026-09-05T09:00:01Z",
  },
};

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

/** The restored boot-volume request must omit the launch-options override.
 * OCI rejects that override for this provider-restored image; capabilities
 * are inherited from the stored boot image instead. */
function assertNoLaunchOptions(argv: string[]): void {
  if (argv.includes("--launch-options")) {
    throw new Error("Launch request unexpectedly overrides launch options");
  }
}

async function refuses(run: () => unknown): Promise<void> {
  let rejected = false;
  try {
    await run();
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("Expected the guard to reject");
}

Deno.test("plan accepts a valid group-backed plan and member metadata", async () => {
  validateGroupRestorePlan(plan);
  validateGroupRestoreEvidence(plan, evidence);
  const state = groupRestoreMetadataState(plan, evidence);
  assertEquals(state.state, "METADATA_PROVED");
  assertEquals(state.suffix, plan.suffix);
  assertEquals(state.restoreDrillProved, false);
  const planState = groupRestorePlanState(plan);
  assertEquals(planState.state, "PLAN_VALID");
  assertEquals(planState.restoreDrillProved, false);
  const now = new Date("2026-09-05T09:30:00Z");
  const approval = {
    approvedAtUtc: "2026-09-05T09:00:00.000Z",
    expiresAtUtc: "2026-09-05T09:59:59.999Z",
    exactOperation:
      "one isolated trial-funded volume-group restore drill" as const,
    planSha256: await groupRestorePlanDigest(plan),
    subscriptionTier: "FREE_AND_TRIAL" as const,
    paymentModel: "FREE_TRIAL" as const,
    availableTrialCreditsUsd: 300,
    estimatedCostUsd: 0.05,
    trialExpiresAtUtc: "2026-09-29T23:59:59.999Z",
    observedAtUtc: "2026-09-05T09:20:00.000Z",
  };
  assertEquals(
    new Date(approval.expiresAtUtc).getTime() -
      new Date(approval.approvedAtUtc).getTime(),
    APPROVAL_MAX_AGE_MS - 1,
  );
  await validateGroupRestoreApproval(plan, approval, now);
});

Deno.test("metadata proof rejects wrong membership and group identity", async () => {
  const cases: GroupRestoreEvidence[] = [
    {
      ...evidence,
      group: {
        ...evidence.group,
        "volume-backup-ids": [
          plan.bootMemberBackupId,
          "member-unrelated",
        ],
      },
    },
    {
      ...evidence,
      group: { ...evidence.group, "volume-group-id": "another-group" },
    },
    {
      ...evidence,
      group: { ...evidence.group, id: "another-capture" },
    },
    { ...evidence, group: { ...evidence.group, type: "INCREMENTAL" } },
    {
      ...evidence,
      group: { ...evidence.group, "lifecycle-state": "UNAVAILABLE" },
    },
    {
      ...evidence,
      group: { ...evidence.group, "compartment-id": "another-compartment" },
    },
    {
      ...evidence,
      bootMember: {
        ...evidence.bootMember,
        "size-in-gbs": 100,
      },
    },
    {
      ...evidence,
      bootMember: {
        ...evidence.bootMember,
        "boot-volume-id": "another-boot-source",
      },
    },
    {
      ...evidence,
      rootMember: {
        ...evidence.rootMember,
        "volume-id": "another-root-source",
      },
    },
    {
      ...evidence,
      bootMember: { ...evidence.bootMember, type: "INCREMENTAL" },
    },
    {
      ...evidence,
      bootMember: {
        ...evidence.bootMember,
        "volume-group-backup-id": "another-capture",
      },
    },
    {
      ...evidence,
      bootMember: { ...evidence.bootMember, "lifecycle-state": "UNAVAILABLE" },
    },
  ];
  for (const bad of cases) {
    await refuses(() => validateGroupRestoreEvidence(plan, bad));
  }
  await refuses(() =>
    validateGroupRestoreEvidence(
      { ...plan, bootMemberBackupId: "member-other" },
      evidence,
    )
  );
});

Deno.test("plan rejects production network, malformed bounds and bad controller IP", async () => {
  await refuses(() =>
    validateGroupRestorePlan({
      ...plan,
      isolatedSubnetId: plan.productionSubnetId,
    })
  );
  await refuses(() =>
    validateGroupRestorePlan({
      ...plan,
      isolatedVcnId: plan.productionVcnId,
    })
  );
  await refuses(() =>
    validateGroupRestorePlan({
      ...plan,
      rootMemberBackupId: plan.bootMemberBackupId,
    })
  );
  await refuses(() =>
    validateGroupRestorePlan({
      ...plan,
      source: { ...plan.source, region: "eu-frankfurt-1" },
    })
  );
  for (const cidr of ["10.78.0.0", "10.78.0.0/33", "10.78.0.256/28", ""]) {
    await refuses(() =>
      validateGroupRestorePlan({ ...plan, isolatedCidrBlock: cidr })
    );
  }
  for (
    const ip of [
      "10.0.0.1",
      "192.168.1.5",
      "169.254.42.42",
      "8.8.8.8/32",
      "999.1.1.1",
      "",
    ]
  ) {
    await refuses(() =>
      validateGroupRestorePlan({ ...plan, controllerIpv4: ip })
    );
  }
  for (
    const suffix of ["20260905T090000", "2026-09-05T09:00:00Z", "20260905"]
  ) {
    await refuses(() => validateGroupRestorePlan({ ...plan, suffix }));
  }
  for (const hours of [0, -1, 5, Number.NaN]) {
    await refuses(() =>
      validateGroupRestorePlan({ ...plan, maxDurationHours: hours })
    );
  }
  for (const cap of [0, -0.1, Number.NaN]) {
    await refuses(() =>
      validateGroupRestorePlan({ ...plan, spendingCapUsd: cap })
    );
  }
  await refuses(() =>
    validateGroupRestorePlan({
      ...plan,
      volumeGroupBackupId: plan.volumeGroupId,
    })
  );
});

Deno.test("targets and launch refuse production resources", async () => {
  await refuses(() =>
    validateGroupRestoreTargets(plan, {
      bootVolumeId: plan.source.bootVolumeId,
      rootVolumeId: "target-root",
      instanceId: "target-instance",
    })
  );
  await refuses(() =>
    validateGroupRestoreTargets(plan, {
      bootVolumeId: "target-boot",
      rootVolumeId: plan.source.rootVolumeId,
      instanceId: "target-instance",
    })
  );
  await refuses(() =>
    validateGroupRestoreTargets(plan, {
      bootVolumeId: "target-boot",
      rootVolumeId: "target-root",
      instanceId: plan.source.instanceId,
    })
  );
  await refuses(() =>
    validateGroupRestoreTargets(plan, {
      bootVolumeId: "target-boot",
      rootVolumeId: "target-boot",
      instanceId: "target-instance",
    })
  );
  validateGroupRestoreTargets(plan, {
    bootVolumeId: "target-boot",
    rootVolumeId: "target-root",
    instanceId: "target-instance",
  });
  await refuses(() =>
    buildGroupRestoreLaunchRequest(
      plan,
      plan.source.bootVolumeId,
      "target-root",
    )
  );
  await refuses(() =>
    buildGroupRestoreLaunchRequest(
      plan,
      "target-boot",
      plan.source.rootVolumeId,
    )
  );
  await refuses(() =>
    buildGroupRestoreLaunchRequest(plan, "target-boot", "target-boot")
  );
});

Deno.test("request builders emit exact safe fields and no production references", () => {
  assertEquals(buildRestoredBootVolumeRequest(plan), [
    "bv",
    "boot-volume",
    "create",
    "--availability-domain",
    "AD-1",
    "--compartment-id",
    "compartment",
    "--boot-volume-backup-id",
    "member-boot",
    "--display-name",
    "arch-oracle-drill-boot-20260905T090000Z",
    "--vpus-per-gb",
    "10",
    "--wait-for-state",
    "AVAILABLE",
  ]);
  assertEquals(buildRestoredRootVolumeRequest(plan), [
    "bv",
    "volume",
    "create",
    "--availability-domain",
    "AD-1",
    "--compartment-id",
    "compartment",
    "--volume-backup-id",
    "member-root",
    "--display-name",
    "arch-oracle-drill-root-20260905T090000Z",
    "--vpus-per-gb",
    "10",
    "--wait-for-state",
    "AVAILABLE",
  ]);
  const launch = buildGroupRestoreLaunchRequest(
    plan,
    "target-boot",
    "target-root",
  );
  assertEquals(launch, [
    "compute",
    "instance",
    "launch",
    "--availability-domain",
    "AD-1",
    "--compartment-id",
    "compartment",
    "--subnet-id",
    "subnet-isolated",
    "--shape",
    "VM.Standard.A1.Flex",
    "--shape-config",
    JSON.stringify({ ocpus: 2, memoryInGBs: 12 }),
    "--source-boot-volume-id",
    "target-boot",
    "--launch-volume-attachments",
    JSON.stringify([{ type: "paravirtualized", volumeId: "target-root" }]),
    "--display-name",
    "arch-oracle-drill-20260905T090000Z",
    "--assign-public-ip",
    "true",
    "--wait-for-state",
    "RUNNING",
  ]);
  assertNoLaunchOptions(launch);
  for (
    const request of [
      buildRestoredBootVolumeRequest(plan),
      buildRestoredRootVolumeRequest(plan),
      launch,
    ]
  ) {
    const text = JSON.stringify(request);
    for (
      const production of [
        "subnet-production",
        "vcn-production",
        "ip-production",
        "volume-source-boot",
        "volume-source-root",
        "instance-source",
      ]
    ) {
      if (text.includes(production)) {
        throw new Error(`Production reference leaked into ${text}`);
      }
    }
  }
  const order = groupRestoreCleanupOrder(plan);
  assertEquals(groupRestoreCleanupOrder(plan), order);
  assertEquals(order, [
    {
      kind: "instance",
      requestName: "arch-oracle-drill-20260905T090000Z",
      action: "delete",
    },
    {
      kind: "root-volume",
      requestName: "arch-oracle-drill-root-20260905T090000Z",
      action: "delete",
    },
    {
      kind: "boot-volume",
      requestName: "arch-oracle-drill-boot-20260905T090000Z",
      action: "delete",
    },
  ]);
});

Deno.test("every crafted provider argv keeps the CLI discipline and no retry token", () => {
  const requests = [
    buildRestoredBootVolumeRequest(plan),
    buildRestoredRootVolumeRequest(plan),
    buildGroupRestoreLaunchRequest(plan, "target-boot", "target-root"),
  ];
  for (const request of requests) {
    const argv = groupRestoreCliArgs(runner, request);
    const subcommandStart = argv.indexOf(request[0]!);
    for (const flag of OCI_CLI_DISCIPLINE_FLAGS) {
      if (!argv.includes(flag)) {
        throw new Error(
          `Missing discipline flag ${flag} in ${JSON.stringify(argv)}`,
        );
      }
      if (subcommandStart !== -1 && argv.indexOf(flag) > subcommandStart) {
        throw new Error(`Discipline flag ${flag} is not before the subcommand`);
      }
    }
    if (
      argv.some((arg) =>
        arg === "--opc-retry-token" || arg === "--opc-request-id"
      )
    ) {
      throw new Error(
        `Unsupported retry/request token leaked into ${JSON.stringify(argv)}`,
      );
    }
    if (
      request.includes("--opc-retry-token") ||
      request.includes("--opc-request-id")
    ) {
      throw new Error("Request builder emitted an unsupported token");
    }
  }
});

const NOW = "2026-09-05T09:00:00.000Z";

function requestFor(
  kind: GroupRestoreResourceKind,
): GroupRestoreResourceRequest {
  return {
    suffix: plan.suffix,
    kind,
    requestName: groupRestoreDisplayName(kind, plan.suffix),
  };
}

function createdJournal(
  kind: GroupRestoreResourceKind = "boot-volume",
): GroupRestoreJournal {
  const request = requestFor(kind);
  let journal = journalGroupRestoreIntent([], request, "create", NOW);
  journal = reconcileGroupRestoreResource(
    journal,
    request,
    "create",
    [{ id: `drill-${kind}`, displayName: request.requestName }],
    NOW,
  );
  return journal;
}

Deno.test("journal guard requires intents and never accepts a same-name unjournaled resource", async () => {
  const request = requestFor("boot-volume");
  await refuses(() =>
    reconcileGroupRestoreResource(
      [],
      request,
      "create",
      [{ id: "drill-boot-volume", displayName: request.requestName }],
      NOW,
    )
  );
  await refuses(() => journalGroupRestoreIntent([], request, "delete", NOW));
  await refuses(() =>
    journalGroupRestoreIntent([], request, "create", NOW, [
      { id: "live", displayName: request.requestName },
    ])
  );
  await refuses(() =>
    reconcileGroupRestoreResource(
      createdJournal(),
      request,
      "delete",
      [{ id: "drill-boot-volume", displayName: request.requestName }],
      NOW,
    )
  );
});

Deno.test("journal guard refuses mismatched, incomplete and ambiguous identity", async () => {
  const request = requestFor("boot-volume");
  const journal = createdJournal();
  await refuses(() =>
    reconcileGroupRestoreResource(
      journal,
      request,
      "create",
      [{ id: "another-resource", displayName: request.requestName }],
      NOW,
    )
  );
  await refuses(() =>
    reconcileGroupRestoreResource(
      journal,
      request,
      "create",
      [
        { id: "drill-boot-volume", displayName: request.requestName },
        { id: "another-resource", displayName: request.requestName },
      ],
      NOW,
    )
  );
  const incomplete = [
    {
      request,
      intent: "create" as const,
      createdAtUtc: NOW,
      identity: { id: "", name: request.requestName },
    },
  ];
  await refuses(() =>
    journalGroupRestoreIntent(incomplete, request, "delete", NOW)
  );
  await refuses(() =>
    reconcileGroupRestoreResource(incomplete, request, "delete", [], NOW)
  );
  await refuses(() =>
    journalGroupRestoreIntent(
      journal,
      request,
      "create",
      "2026-09-05T09:00:01.000Z",
    )
  );
});

Deno.test("journal guard accepts only exact idempotent cleanup", async () => {
  const request = requestFor("boot-volume");
  let journal = createdJournal();
  const deleteJournal = journalGroupRestoreIntent(
    journal,
    request,
    "delete",
    NOW,
  );
  journal = reconcileGroupRestoreResource(
    deleteJournal,
    request,
    "delete",
    [{ id: "drill-boot-volume", displayName: request.requestName }],
    NOW,
  );
  assertEquals(journal, deleteJournal);
  journal = reconcileGroupRestoreResource(
    journal,
    request,
    "delete",
    [],
    "2026-09-05T09:05:00.000Z",
  );
  const completed = journal;
  const retry = reconcileGroupRestoreResource(
    journal,
    request,
    "delete",
    [],
    "2026-09-05T09:06:00.000Z",
  );
  assertEquals(retry, completed);
  const retryIntent = journalGroupRestoreIntent(
    journal,
    request,
    "delete",
    "2026-09-05T09:06:00.000Z",
  );
  assertEquals(retryIntent, completed);
  await refuses(() =>
    reconcileGroupRestoreResource(
      completed,
      request,
      "delete",
      [{ id: "drill-boot-volume", displayName: request.requestName }],
      "2026-09-05T09:07:00.000Z",
    )
  );
  await refuses(() =>
    journalGroupRestoreIntent(
      completed,
      request,
      "create",
      "2026-09-05T09:07:00.000Z",
    )
  );
});

Deno.test("approval validator binds the exact operation, digest and window", async () => {
  const approval = {
    approvedAtUtc: "2026-09-05T09:00:00.000Z",
    expiresAtUtc: "2026-09-05T10:00:00.000Z",
    exactOperation:
      "one isolated trial-funded volume-group restore drill" as const,
    planSha256: await groupRestorePlanDigest(plan),
    subscriptionTier: "FREE_AND_TRIAL" as const,
    paymentModel: "FREE_TRIAL" as const,
    availableTrialCreditsUsd: 300,
    estimatedCostUsd: 0.05,
    trialExpiresAtUtc: "2026-09-29T23:59:59.999Z",
    observedAtUtc: "2026-09-05T09:20:00.000Z",
  };
  await refuses(() =>
    validateGroupRestoreApproval(
      plan,
      approval,
      new Date("2026-09-05T10:00:00Z"),
    )
  );
  await refuses(() =>
    validateGroupRestoreApproval(
      { ...plan, maxDurationHours: 2 },
      approval,
      new Date("2026-09-05T09:30:00Z"),
    )
  );
  await refuses(() =>
    validateGroupRestoreApproval(
      plan,
      {
        ...approval,
        exactOperation: "another operation",
      } as unknown as GroupRestoreApproval,
      new Date("2026-09-05T09:30:00Z"),
    )
  );
});

Deno.test("approval validator requires live FREE_TRIAL coverage for the full window", async () => {
  const digest = await groupRestorePlanDigest(plan);
  const approved = new Date("2026-09-05T09:30:00Z");
  const good: GroupRestoreApproval = {
    approvedAtUtc: "2026-09-05T09:00:00.000Z",
    expiresAtUtc: "2026-09-05T09:59:59.999Z",
    exactOperation: "one isolated trial-funded volume-group restore drill",
    planSha256: digest,
    subscriptionTier: "FREE_AND_TRIAL",
    paymentModel: "FREE_TRIAL",
    availableTrialCreditsUsd: 300,
    estimatedCostUsd: 0.05,
    trialExpiresAtUtc: "2026-09-29T23:59:59.999Z",
    observedAtUtc: "2026-09-05T09:28:00.000Z",
  };
  await validateGroupRestoreApproval(plan, good, approved);
  const cases: GroupRestoreApproval[] = [
    { ...good, subscriptionTier: "PAID" } as unknown as GroupRestoreApproval,
    {
      ...good,
      paymentModel: "PAY_AS_YOU_GO",
    } as unknown as GroupRestoreApproval,
    { ...good, estimatedCostUsd: plan.spendingCapUsd + 0.01 },
    { ...good, estimatedCostUsd: 0 },
    { ...good, estimatedCostUsd: Number.NaN },
    { ...good, availableTrialCreditsUsd: plan.spendingCapUsd - 0.01 },
    { ...good, availableTrialCreditsUsd: Number.NaN },
    { ...good, trialExpiresAtUtc: "2026-09-05T13:29:59.999Z" },
    { ...good, trialExpiresAtUtc: "2026-09-05T13:30:00.000Z" },
    { ...good, trialExpiresAtUtc: "2026-09-05T09:00:00Z" },
    { ...good, observedAtUtc: "2026-09-05T09:45:00.000Z" },
    {
      ...good,
      observedAtUtc: new Date(
        approved.getTime() - TRIAL_EVIDENCE_MAX_AGE_MS - 1,
      )
        .toISOString(),
    },
    { ...good, observedAtUtc: "not-a-time" },
    { ...good, trialExpiresAtUtc: "not-a-time" },
    // Loose or non-canonical timestamp text must be refused outright:
    // only strict canonical UTC with an optional exactly-3-digit fraction.
    { ...good, approvedAtUtc: "2026-09-05 09:00:00.000Z" },
    { ...good, approvedAtUtc: "2026-09-05T09:00:00+00:00" },
    { ...good, expiresAtUtc: "2026-09-05T09:59:59.999-04:00" },
    { ...good, expiresAtUtc: "2026-09-05T09:59:59.9Z" },
    { ...good, observedAtUtc: "2026-09-05T09:20:00.000000Z" },
    { ...good, trialExpiresAtUtc: "2026-09-29T23:59:59.999+00:00" },
  ];
  for (const bad of cases) {
    await refuses(() => validateGroupRestoreApproval(plan, bad, approved));
  }
});

Deno.test("lifetime is exact, durable and refused once elapsed or malformed", async () => {
  const now = new Date("2026-09-05T09:30:00Z");
  const lifetime = groupRestoreLifetime(now, plan);
  assertEquals(
    new Date(lifetime.deadlineAtUtc).getTime() -
      new Date(lifetime.startedAtUtc).getTime(),
    plan.maxDurationHours * 3_600_000,
  );
  validateGroupRestoreLifetime(lifetime, plan, now);
  await refuses(() =>
    validateGroupRestoreLifetime(
      lifetime,
      plan,
      new Date("2026-09-05T13:30:00Z"),
    )
  );
  await refuses(() =>
    validateGroupRestoreLifetime(
      { ...lifetime, deadlineAtUtc: now.toISOString() },
      plan,
      now,
    )
  );
  await refuses(() =>
    validateGroupRestoreLifetime(
      { ...lifetime, deadlineAtUtc: "2026-09-05T13:31:00.000Z" },
      plan,
      now,
    )
  );
  await refuses(() =>
    validateGroupRestoreLifetime(
      { ...lifetime, startedAtUtc: "2026-09-05T09:31:00.000Z" },
      plan,
      now,
    )
  );
  await refuses(() =>
    validateGroupRestoreLifetime(
      { startedAtUtc: "soon", deadlineAtUtc: "later" },
      plan,
      now,
    )
  );
});

const runner: GroupRestoreRunner = {
  ociCliPath: "/home/pi/.venvs/oci/bin/oci",
  ociProfile: "DEFAULT",
  region: "us-ashburn-1",
  run: () => Promise.resolve({ code: 0, stdout: "", stderr: "" }),
};

const runApproval: GroupRestoreApproval = {
  approvedAtUtc: "2026-09-05T09:00:00.000Z",
  expiresAtUtc: "2026-09-05T09:59:59.999Z",
  exactOperation: "one isolated trial-funded volume-group restore drill",
  planSha256: await groupRestorePlanDigest(plan),
  subscriptionTier: "FREE_AND_TRIAL",
  paymentModel: "FREE_TRIAL",
  availableTrialCreditsUsd: 300,
  estimatedCostUsd: 0.05,
  trialExpiresAtUtc: "2026-09-29T23:59:59.999Z",
  observedAtUtc: "2026-09-05T09:20:00.000Z",
};

const runTargets = {
  bootVolumeId: "target-boot",
  rootVolumeId: "target-root",
  instanceId: "target-instance",
};

Deno.test("runner argv binds the exact injected surface and CLI discipline", async () => {
  assertEquals(groupRestoreCliArgs(runner, ["bv", "volume", "list"]), [
    "--profile",
    "DEFAULT",
    "--region",
    "us-ashburn-1",
    "--no-retry",
    "--connection-timeout",
    "10",
    "--read-timeout",
    "60",
    "bv",
    "volume",
    "list",
  ]);
  await refuses(() =>
    groupRestoreCliArgs({ ...runner, ociCliPath: "<HOME>/oci" }, [])
  );
  await refuses(() => groupRestoreCliArgs({ ...runner, ociProfile: "" }, []));
  await refuses(() =>
    groupRestoreCliArgs({ ...runner, region: "eu-frankfurt-1" }, [])
  );
});

Deno.test("run guard binds exact deterministic steps and never claims proof", async () => {
  const guard = await guardGroupRestoreRun(
    {
      plan,
      approval: runApproval,
      evidence,
      targets: runTargets,
      journal: [],
      now: new Date("2026-09-05T09:30:00Z"),
    },
    runner,
  );
  assertEquals(guard.state, "RUN_READY");
  assertEquals(guard.suffix, plan.suffix);
  assertEquals(guard.restoreDrillProved, false);
  assertEquals(guard.steps.map((step) => step.kind), [
    "boot-volume",
    "root-volume",
  ]);
  for (const step of guard.steps) {
    // Hard cutover: the guard carries no pre-boot isolation proof, so it must
    // never emit or authorize an instance-launch step or an instance launch
    // argv before isolation.
    if (step.kind === "instance") {
      throw new Error("Guard emitted an instance step before isolation");
    }
    if (
      step.argv[0] === "compute" && step.argv[1] === "instance" &&
      step.argv[2] === "launch"
    ) {
      throw new Error("Guard emitted an instance-launch argv before isolation");
    }
    assertEquals(step.intent, "create");
    assertEquals(step.ociCliPath, runner.ociCliPath);
    assertEquals(step.request.suffix, plan.suffix);
    assertEquals(
      step.request.requestName,
      groupRestoreDisplayName(step.kind, plan.suffix),
    );
  }
  assertEquals(
    guard.steps[0].argv,
    groupRestoreCliArgs(runner, buildRestoredBootVolumeRequest(plan)),
  );
  assertEquals(
    guard.steps[1].argv,
    groupRestoreCliArgs(runner, buildRestoredRootVolumeRequest(plan)),
  );
  assertEquals(guard.cleanup, groupRestoreCleanupOrder(plan));
  // No production identity or reserved production IP may appear anywhere.
  for (const step of guard.steps) {
    const text = JSON.stringify([step.ociCliPath, ...step.argv]);
    for (
      const production of [
        "instance-source",
        "volume-source-boot",
        "volume-source-root",
        "subnet-production",
        "vcn-production",
        "ip-production",
      ]
    ) {
      if (text.includes(production)) {
        throw new Error(`Production reference leaked into ${text}`);
      }
    }
  }
});

Deno.test("run guard refuses stale, ambiguous, mismatched and unbound runs", async () => {
  const base = {
    plan,
    approval: runApproval,
    evidence,
    targets: runTargets,
    journal: [],
    now: new Date("2026-09-05T09:30:00Z"),
  };
  await refuses(() =>
    guardGroupRestoreRun(
      { ...base, now: new Date("2026-09-05T10:00:00Z") },
      runner,
    )
  );
  const staleRequest = {
    suffix: plan.suffix,
    kind: "boot-volume" as GroupRestoreResourceKind,
    requestName: groupRestoreDisplayName("boot-volume", "20260101T000000Z"),
  };
  await refuses(() =>
    guardGroupRestoreRun({
      ...base,
      journal: [{
        request: staleRequest,
        intent: "create" as const,
        createdAtUtc: NOW,
      }],
    }, runner)
  );
  const exactRequest: GroupRestoreResourceRequest = {
    suffix: plan.suffix,
    kind: "boot-volume",
    requestName: groupRestoreDisplayName("boot-volume", plan.suffix),
  };
  const doubled = [
    { request: exactRequest, intent: "create" as const, createdAtUtc: NOW },
    { request: exactRequest, intent: "create" as const, createdAtUtc: NOW },
  ];
  await refuses(() =>
    guardGroupRestoreRun({ ...base, journal: doubled }, runner)
  );
  const unresolvedDelete = [{
    request: exactRequest,
    intent: "create" as const,
    createdAtUtc: NOW,
    identity: { id: "drill-boot-volume", name: exactRequest.requestName },
  }, {
    request: exactRequest,
    intent: "delete" as const,
    createdAtUtc: NOW,
  }];
  await refuses(() =>
    guardGroupRestoreRun({ ...base, journal: unresolvedDelete }, runner)
  );
  const cleanedUp = [{
    request: exactRequest,
    intent: "create" as const,
    createdAtUtc: NOW,
    identity: { id: "drill-boot-volume", name: exactRequest.requestName },
  }, {
    request: exactRequest,
    intent: "delete" as const,
    createdAtUtc: NOW,
    completedAtUtc: "2026-09-05T10:00:00.000Z",
  }];
  await refuses(() =>
    guardGroupRestoreRun({ ...base, journal: cleanedUp }, runner)
  );
  await refuses(() =>
    guardGroupRestoreRun({
      ...base,
      evidence: {
        ...evidence,
        bootMember: {
          ...evidence.bootMember,
          "boot-volume-id": "another-boot-source",
        },
      },
    }, runner)
  );
  await refuses(() =>
    guardGroupRestoreRun({
      ...base,
      targets: {
        bootVolumeId: plan.source.bootVolumeId,
        rootVolumeId: "target-root",
        instanceId: "target-instance",
      },
    }, runner)
  );
  await refuses(() =>
    guardGroupRestoreRun(base, { ...runner, ociProfile: "" })
  );
  await refuses(() =>
    guardGroupRestoreRun(base, { ...runner, region: "eu-frankfurt-1" })
  );
  await refuses(() =>
    guardGroupRestoreRun({
      ...base,
      lifetime: groupRestoreLifetime(
        new Date("2026-09-05T05:30:00Z"),
        plan,
      ),
    }, runner)
  );
});
