import {
  assertBackblazeLaunchAllowed,
  assertOracleMutationAllowed,
  canonicalUtcMillis,
  GATE_DEADLINE_HOURS,
  GATE_DEADLINE_MS,
  type GateClearProofState,
  validateGate,
  validateGateClearProof,
} from "../scripts/backblaze-controller-contract.ts";

const UUID = "681c4067-aec2-45d5-9afb-77ee530e3a97";
const INVOCATION = "a7064f4b7f524c3baa3725acc88f73ed";
const REQUEST_SHA = "ab".repeat(32);
const REQUESTED_AT = "2026-09-06T04:00:00.000Z";

function assert(value: unknown, message?: string): asserts value {
  if (!value) throw new Error(message ?? "Assertion failed");
}

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function assertThrows(run: () => unknown): void {
  let rejected = false;
  try {
    run();
  } catch {
    rejected = true;
  }
  assert(rejected, "Expected the call to throw");
}

function gateFixture(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    owner: "backblaze-direct",
    state: "active",
    jobId: `job-${UUID}`,
    periodKey: "2026-09-06",
    generation: `generation-${UUID}`,
    requestSha256: REQUEST_SHA,
    requestedAtUtc: REQUESTED_AT,
    deadlineAtUtc: iso(Date.parse(REQUESTED_AT) + GATE_DEADLINE_MS),
    createdAtUtc: "2026-09-06T04:00:01.000Z",
    updatedAtUtc: "2026-09-06T04:00:02.000Z",
    remoteHost: "codex@vps.pavlovcik.com",
    unitName: `arch-vps-b2-worker-${UUID}.service`,
    unitInvocationId: null,
    sourceLockPath: "/var/tmp/arch-vps-file-backup/source.lock",
    ...overrides,
  };
}

function boundGate(overrides: Record<string, unknown> = {}) {
  return gateFixture({ unitInvocationId: INVOCATION, ...overrides });
}

function proofFixture(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    checkedAtUtc: "2026-09-06T10:00:10.000Z",
    unitName: `arch-vps-b2-worker-${UUID}.service`,
    unitInvocationId: INVOCATION,
    unitLoadState: "loaded",
    unitActiveState: "active",
    unitSubState: "exited",
    unitResult: "success",
    mainPid: 0,
    controlPid: 0,
    controlGroup: "",
    tasksCurrent: null,
    statusPath: `/var/tmp/arch-vps-file-backup/jobs/job-${UUID}/status.json`,
    statusState: "PENDING_VERIFIER",
    statusJobId: `job-${UUID}`,
    statusPeriodKey: "2026-09-06",
    statusGeneration: `generation-${UUID}`,
    statusRequestSha256: REQUEST_SHA,
    statusInvocationId: INVOCATION,
    statusUpdatedAtUtc: "2026-09-06T10:00:05.000Z",
    statusHeartbeatAtUtc: "2026-09-06T10:00:04.000Z",
    statusFinishedAtUtc: "2026-09-06T10:00:05.000Z",
    sourceLockPath: "/var/tmp/arch-vps-file-backup/source.lock",
    sourceLockFree: true,
    clearBasis: "terminal",
    ...overrides,
  };
}

/** The live expiry shape: orphaned TERMINAL_PROOF_MISSING gate whose
 * immutable deadline passed, exact timed-out failed/failed unit with no
 * processes, free source lock, and a preserved nonterminal status whose
 * original finishedAtUtc is still null. */
function expiredGate(overrides: Record<string, unknown> = {}) {
  return validateGate(gateFixture({
    state: "orphaned",
    orphanReason: "TERMINAL_PROOF_MISSING",
    unitInvocationId: INVOCATION,
    ...overrides,
  }));
}

function expiredProofFixture(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return proofFixture({
    unitActiveState: "failed",
    unitSubState: "failed",
    unitResult: "timeout",
    statusState: "UPLOADING",
    statusFinishedAtUtc: null,
    clearBasis: "deadline-expired",
    ...overrides,
  });
}

const CLEAR_NOW = new Date("2026-09-06T10:00:15.000Z");

Deno.test("validateGate accepts the active gate and copies the input", () => {
  const input = gateFixture();
  const gate = validateGate(input);
  assertEquals(gate, input);
  assert(!Object.is(gate, input), "Validated result must be a fresh object");
  assert(gate.unitInvocationId === null);
  input.jobId = `job-${"0".repeat(8)}-${"0".repeat(4)}-${"0".repeat(4)}-${
    "0".repeat(4)
  }-${"0".repeat(12)}`;
  assert(
    gate.jobId === `job-${UUID}`,
    "Result must not share the input object",
  );
});

Deno.test("validateGate accepts every deterministic unit kind and binds the UUID", () => {
  for (const kind of ["worker", "verify", "prune"] as const) {
    const gate = validateGate(
      gateFixture({ unitName: `arch-vps-b2-${kind}-${UUID}.service` }),
    );
    assertEquals(gate.unitName, `arch-vps-b2-${kind}-${UUID}.service`);
  }
});

Deno.test("validateGate accepts an orphaned gate with a fixed reason", () => {
  const gate = validateGate(
    gateFixture({
      state: "orphaned",
      orphanReason: "TERMINAL_PROOF_MISSING",
    }),
  );
  assertEquals(gate.state, "orphaned");
  assertEquals(gate.orphanReason, "TERMINAL_PROOF_MISSING");
});

Deno.test("validateGate rejects unknown keys and missing keys", () => {
  assertThrows(() => validateGate(gateFixture({ extra: true })));
  assertThrows(() => validateGate(gateFixture({ cgroupEmpty: true })));
  assertThrows(() => validateGate(gateFixture({ statusPhase: "x" })));
  const missing = gateFixture();
  delete missing.unitName;
  assertThrows(() => validateGate(missing));
  const missing2 = gateFixture();
  delete missing2.sourceLockPath;
  assertThrows(() => validateGate(missing2));
});

Deno.test("validateGate rejects malformed identity values", () => {
  assertThrows(() => validateGate({}));
  assertThrows(() => validateGate([]));
  assertThrows(() => validateGate(null));
  assertThrows(() => validateGate(gateFixture({ schemaVersion: 2 })));
  assertThrows(() => validateGate(gateFixture({ owner: "other" })));
  assertThrows(() => validateGate(gateFixture({ state: "suspended" })));
  assertThrows(() => validateGate(gateFixture({ remoteHost: "root@vps" })));
  assertThrows(() =>
    validateGate(gateFixture({ sourceLockPath: "/tmp/source.lock" }))
  );
  assertThrows(() => validateGate(gateFixture({ jobId: "not-a-job-id" })));
  assertThrows(() =>
    validateGate(
      gateFixture({ generation: `generation-${UUID.replace("a", "A")}` }),
    )
  );
  assertThrows(() =>
    validateGate(gateFixture({ jobId: `job-${UUID.replace("a", "A")}` }))
  );
});

Deno.test("validateGate rejects malformed hashes and invocation ids", () => {
  assertThrows(() =>
    validateGate(gateFixture({ requestSha256: "a".repeat(63) }))
  );
  assertThrows(() =>
    validateGate(gateFixture({ requestSha256: "A".repeat(64) }))
  );
  assertThrows(() =>
    validateGate(gateFixture({ unitInvocationId: "a".repeat(31) }))
  );
  assertThrows(() =>
    validateGate(gateFixture({ unitInvocationId: "A".repeat(32) }))
  );
  assertThrows(() => validateGate(gateFixture({ unitInvocationId: 42 })));
});

Deno.test("validateGate accepts only valid Sunday period keys", () => {
  assertEquals(validateGate(gateFixture()).periodKey, "2026-09-06");
  assertThrows(() => validateGate(gateFixture({ periodKey: "2026-09-07" })));
  assertThrows(() => validateGate(gateFixture({ periodKey: "2026-02-30" })));
  assertThrows(() => validateGate(gateFixture({ periodKey: "2026-9-06" })));
  assertThrows(() =>
    validateGate(gateFixture({ periodKey: "2026-09-06T00:00:00.000Z" }))
  );
});

Deno.test(
  `validateGate binds deadline to requested plus ${GATE_DEADLINE_HOURS} hours exactly`,
  () => {
    const deadline = Date.parse(REQUESTED_AT) + GATE_DEADLINE_MS;
    assertThrows(() =>
      validateGate(gateFixture({ deadlineAtUtc: iso(deadline + 1_000) }))
    );
    assertThrows(() =>
      validateGate(gateFixture({ deadlineAtUtc: iso(deadline - 1_000) }))
    );
  },
);

Deno.test("validateGate rejects noncanonical or disordered timestamps", () => {
  assertThrows(() =>
    validateGate(gateFixture({ requestedAtUtc: "2026-09-06T04:00:00Z" }))
  );
  assertThrows(() =>
    validateGate(gateFixture({ createdAtUtc: "2026-09-06T03:59:59.000Z" }))
  );
  assertThrows(() =>
    validateGate(gateFixture({ updatedAtUtc: "2026-09-06T04:00:01.50Z" }))
  );
  const bad = gateFixture();
  delete bad.createdAtUtc;
  assertThrows(() => validateGate(bad));
});

Deno.test("validateGate rejects a unit name that is not canonical", () => {
  assertThrows(() =>
    validateGate(gateFixture({
      unitName: `arch-vps-b2-upload-${UUID}.service`,
    }))
  );
  assertThrows(() =>
    validateGate(gateFixture({
      unitName: `arch-vps-b2-worker-${"0".repeat(8)}-${"0".repeat(4)}-${
        "0".repeat(4)
      }-${"0".repeat(4)}-${"0".repeat(12)}.service`,
    }))
  );
  assertThrows(() =>
    validateGate(gateFixture({ unitName: `arch-vps-b2-worker-${UUID}.timer` }))
  );
  assertThrows(() =>
    validateGate(
      gateFixture({
        unitName: `system.slice/arch-vps-b2-worker-${UUID}.service`,
      }),
    )
  );
});

Deno.test("validateGate rejects orphanReason state mismatches", () => {
  assertThrows(() =>
    validateGate(gateFixture({
      state: "active",
      orphanReason: "TERMINAL_PROOF_MISSING",
    }))
  );
  assertThrows(() => validateGate(gateFixture({ state: "orphaned" })));
  assertThrows(() =>
    validateGate(gateFixture({
      state: "orphaned",
      orphanReason: "GIVE_UP",
    }))
  );
});

Deno.test("an expired gate is still a valid gate and still blocks mutation", () => {
  const requestedAtUtc = "2026-09-05T04:00:00.000Z";
  const deadlineAtUtc = iso(Date.parse(requestedAtUtc) + GATE_DEADLINE_MS);
  const gate = validateGate(
    gateFixture({
      requestedAtUtc,
      deadlineAtUtc,
      createdAtUtc: "2026-09-05T04:00:01.000Z",
      updatedAtUtc: "2026-09-05T04:00:02.000Z",
    }),
  );
  assertEquals(gate.deadlineAtUtc, deadlineAtUtc);
  assertThrows(() => assertOracleMutationAllowed(gate));
});

Deno.test("assertOracleMutationAllowed: absence permits, any gate blocks", () => {
  assertOracleMutationAllowed(null);
  assertOracleMutationAllowed(undefined);
  assertThrows(() => assertOracleMutationAllowed(validateGate(boundGate())));
  assertThrows(() =>
    assertOracleMutationAllowed(validateGate(gateFixture({
      state: "orphaned",
      orphanReason: "STATUS_INVALID",
    })))
  );
  assertThrows(() => assertOracleMutationAllowed({}));
  assertThrows(() => assertOracleMutationAllowed([]));
});

Deno.test("success terminal proof accepts every terminal status state", () => {
  for (
    const state of [
      "PENDING_VERIFIER",
      "ACCEPTED",
      "COMPLETE",
      "FAILED",
    ] as GateClearProofState[]
  ) {
    const gate = validateGate(boundGate());
    const proof = validateGateClearProof(
      proofFixture({ statusState: state }),
      gate,
      CLEAR_NOW,
    );
    assertEquals(proof.statusState, state);
  }
});

Deno.test("failed systemd proof accepts known failure results with FAILED status", () => {
  for (const result of ["exit-code", "timeout", "signal"]) {
    const gate = validateGate(boundGate());
    const proof = validateGateClearProof(
      proofFixture({
        unitActiveState: "failed",
        unitSubState: "failed",
        unitResult: result,
        statusState: "FAILED",
        statusFinishedAtUtc: "2026-09-06T09:59:58.000Z",
      }),
      gate,
      CLEAR_NOW,
    );
    assertEquals(proof.unitResult, result);
  }
});

Deno.test("deadline-expired proof accepts the preserved nonterminal timeout shape", () => {
  const gate = expiredGate();
  const input = expiredProofFixture();
  const proof = validateGateClearProof(input, gate, CLEAR_NOW);
  assertEquals(proof, input);
  assertEquals(proof.clearBasis, "deadline-expired");
  assert(proof.statusFinishedAtUtc === null, "finishedAt is never synthesized");
  assertEquals(proof.statusState, "UPLOADING");
  // The derived field must not make the returned proof invalid against the
  // same gate and comparison instant.
  assertEquals(validateGateClearProof(proof, gate, CLEAR_NOW), proof);
});

Deno.test("terminal proof without clearBasis defaults to a revalidatable terminal basis", () => {
  const gate = validateGate(boundGate());
  const input = proofFixture();
  delete input.clearBasis;
  const proof = validateGateClearProof(input, gate, CLEAR_NOW);
  assertEquals(proof.clearBasis, "terminal");
  assertEquals(proof.statusFinishedAtUtc, "2026-09-06T10:00:05.000Z");
  assertEquals(
    validateGateClearProof(proof, gate, CLEAR_NOW).clearBasis,
    "terminal",
  );
});

Deno.test("deadline-expired proof rejects every unsupported condition", () => {
  const gate = expiredGate();
  const rejects = (
    overrides: Record<string, unknown>,
    candidate = gate,
  ): void => {
    assertThrows(() =>
      validateGateClearProof(
        expiredProofFixture(overrides),
        candidate,
        CLEAR_NOW,
      )
    );
  };
  // Only the orphaned TERMINAL_PROOF_MISSING gate is reconcilable.
  rejects({}, validateGate(boundGate()));
  rejects({}, expiredGate({ orphanReason: "UNIT_IDENTITY_MISMATCH" }));
  rejects({}, expiredGate({ orphanReason: "STATUS_INVALID" }));
  rejects(
    {},
    expiredGate({ orphanReason: "SOURCE_UNREACHABLE_AT_DEADLINE" }),
  );
  // The immutable request deadline has not passed.
  rejects(
    {},
    expiredGate({
      requestedAtUtc: "2026-09-06T04:00:20.000Z",
      deadlineAtUtc: "2026-09-06T10:00:20.000Z",
      createdAtUtc: "2026-09-06T04:00:21.000Z",
      updatedAtUtc: "2026-09-06T04:00:22.000Z",
    }),
  );
  // Only Result=timeout on the exact failed/failed unit.
  rejects({ unitResult: "exit-code" });
  rejects({ unitResult: "signal" });
  rejects({
    unitResult: "success",
    unitActiveState: "active",
    unitSubState: "exited",
  });
  rejects({ unitActiveState: "active", unitSubState: "exited" });
  rejects({ unitActiveState: "failed", unitSubState: "exited" });
  // Unit, status and gate invocation identities must all match.
  rejects({ unitName: `arch-vps-b2-verify-${UUID}.service` });
  rejects({ unitInvocationId: "b".repeat(32) });
  rejects({ statusInvocationId: "b".repeat(32) });
  rejects({
    statusJobId: `job-${"0".repeat(8)}-${"0".repeat(4)}-${"0".repeat(4)}-${
      "0".repeat(4)
    }-${"0".repeat(12)}`,
  });
  rejects({ statusRequestSha256: "cd".repeat(32) });
  // Live processes or an unproven cgroup.
  rejects({ mainPid: 1 });
  rejects({ controlPid: 1 });
  rejects({ controlGroup: "", tasksCurrent: 0 });
  rejects({
    controlGroup: `/system.slice/arch-vps-b2-worker-${UUID}.service`,
    tasksCurrent: 1,
  });
  rejects({
    controlGroup: `/system.slice/arch-vps-b2-worker-${UUID}.service`,
    tasksCurrent: null,
  });
  // Busy source lock.
  rejects({ sourceLockFree: false });
  // Unknown or terminal status states are never preserved as nonterminal.
  rejects({ statusState: "PENDING_VERIFIER" });
  rejects({ statusState: "FAILED" });
  rejects({ statusState: "SLEEPING" });
  // A non-null finish instant is never accepted in the expired basis.
  rejects({ statusFinishedAtUtc: "2026-09-06T10:00:05.000Z" });
  // Stale, future or incoherent timestamp evidence.
  rejects({ checkedAtUtc: "2026-09-06T10:00:46.000Z" });
  rejects({ checkedAtUtc: "2026-09-06T10:00:20.000Z" });
  rejects({ statusHeartbeatAtUtc: "2026-09-06T10:00:06.000Z" });
  rejects({ statusUpdatedAtUtc: "2026-09-06T10:00:20.000Z" });
  rejects({ statusUpdatedAtUtc: "2026-09-06T03:59:59.000Z" });
  rejects({ statusHeartbeatAtUtc: "2026-09-06T03:59:59.000Z" });
  // An unknown basis is never accepted.
  rejects({ clearBasis: "guess" });
});

Deno.test("terminal proof rejects running or mismatched combinations", () => {
  const gate = validateGate(boundGate());
  // Success unit but failed service state.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ unitActiveState: "failed", unitSubState: "failed" }),
      gate,
      CLEAR_NOW,
    )
  );
  // Failed result with a non-FAILED status.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({
        unitActiveState: "failed",
        unitSubState: "failed",
        unitResult: "exit-code",
        statusState: "PENDING_VERIFIER",
      }),
      gate,
      CLEAR_NOW,
    )
  );
  // Timeout result with a still-active unit is a nonterminal state.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({
        unitResult: "timeout",
        statusState: "FAILED",
      }),
      gate,
      CLEAR_NOW,
    )
  );
  // Unsupported result value.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({
        unitActiveState: "failed",
        unitSubState: "failed",
        unitResult: "failed",
        statusState: "FAILED",
      }),
      gate,
      CLEAR_NOW,
    )
  );
});

Deno.test("clear proof rejects stale, future or noncanonical checked time", () => {
  const gate = validateGate(boundGate());
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ checkedAtUtc: "2026-09-06T10:00:46.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ checkedAtUtc: "2026-09-06T10:00:20.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ checkedAtUtc: "2026-09-06T10:00:10Z" }),
      gate,
      CLEAR_NOW,
    )
  );
});

Deno.test("clear proof binds every gate identity field and status path", () => {
  const gate = validateGate(boundGate());
  const cases: Record<string, unknown>[] = [
    {
      unitName: `arch-vps-b2-worker-${"0".repeat(8)}-${"0".repeat(4)}-${
        "0".repeat(4)
      }-${"0".repeat(4)}-${"0".repeat(12)}.service`,
    },
    { unitInvocationId: "" },
    { unitInvocationId: "b".repeat(32) },
    { statusPath: `/var/tmp/arch-vps-file-backup/jobs/other/status.json` },
    {
      statusJobId: `job-${"0".repeat(8)}-${"0".repeat(4)}-${"0".repeat(4)}-${
        "0".repeat(4)
      }-${"0".repeat(12)}`,
    },
    { statusPeriodKey: "2026-09-13" },
    {
      statusGeneration: `generation-${"0".repeat(8)}-${"0".repeat(4)}-${
        "0".repeat(4)
      }-${"0".repeat(4)}-${"0".repeat(12)}`,
    },
    { statusRequestSha256: "cd".repeat(32) },
    { statusInvocationId: "c".repeat(32) },
  ];
  for (const overrides of cases) {
    assertThrows(() =>
      validateGateClearProof(proofFixture(overrides), gate, CLEAR_NOW)
    );
  }
  // An unbound gate never yields terminal proof.
  const unbound = validateGate(gateFixture());
  assertThrows(() =>
    validateGateClearProof(proofFixture(), unbound, CLEAR_NOW)
  );
});

Deno.test("clear proof requires zero PIDs and an independent no-process cgroup proof", () => {
  const gate = validateGate(boundGate());
  assertThrows(() =>
    validateGateClearProof(proofFixture({ mainPid: 1 }), gate, CLEAR_NOW)
  );
  assertThrows(() =>
    validateGateClearProof(proofFixture({ controlPid: 7 }), gate, CLEAR_NOW)
  );
  // Empty group with zero tasks is not the systemd shape.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ controlGroup: "", tasksCurrent: 0 }),
      gate,
      CLEAR_NOW,
    )
  );
  // Canonical cgroup with unset tasks is not an observed empty count.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({
        controlGroup: `/system.slice/arch-vps-b2-worker-${UUID}.service`,
        tasksCurrent: null,
      }),
      gate,
      CLEAR_NOW,
    )
  );
  // Canonical cgroup with one task is not empty.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({
        controlGroup: `/system.slice/arch-vps-b2-worker-${UUID}.service`,
        tasksCurrent: 1,
      }),
      gate,
      CLEAR_NOW,
    )
  );
  // Another unit's cgroup is not this gate's cgroup.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({
        controlGroup: `/system.slice/arch-vps-b2-worker-${"0".repeat(8)}-${
          "0".repeat(4)
        }-${"0".repeat(4)}-${"0".repeat(4)}-${"0".repeat(12)}.service`,
        tasksCurrent: 0,
      }),
      gate,
      CLEAR_NOW,
    )
  );
  // A non-systemd path can never prove the unit cgroup is empty.
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({
        controlGroup: `/other.slice/${`arch-vps-b2-worker-${UUID}.service`}`,
        tasksCurrent: 0,
      }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({
        controlGroup: `/system.slice/arch-vps-b2-worker-${UUID}.service/`,
        tasksCurrent: 0,
      }),
      gate,
      CLEAR_NOW,
    )
  );
});

Deno.test("clear proof accepts the canonical nonempty cgroup with zero tasks", () => {
  const gate = validateGate(boundGate());
  const proof = validateGateClearProof(
    proofFixture({
      controlGroup: `/system.slice/arch-vps-b2-worker-${UUID}.service`,
      tasksCurrent: 0,
    }),
    gate,
    CLEAR_NOW,
  );
  assertEquals(
    proof.controlGroup,
    `/system.slice/arch-vps-b2-worker-${UUID}.service`,
  );
  assertEquals(proof.tasksCurrent, 0);
});

Deno.test("clear proof rejects unknown keys and nonterminal statuses", () => {
  const gate = validateGate(boundGate());
  assertThrows(() =>
    validateGateClearProof(proofFixture({ cgroupEmpty: true }), gate, CLEAR_NOW)
  );
  assertThrows(() =>
    validateGateClearProof(proofFixture({ statusPhase: "x" }), gate, CLEAR_NOW)
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusState: "CAPTURING" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusState: "REQUESTED" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ unitActiveState: "running" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ unitSubState: "dead" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ unitLoadState: "not-found" }),
      gate,
      CLEAR_NOW,
    )
  );
});

Deno.test("clear proof status timestamps must fit the gate window", () => {
  const gate = validateGate(boundGate());
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusFinishedAtUtc: "2026-09-06T03:59:59.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusFinishedAtUtc: "2026-09-06T10:00:11.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusHeartbeatAtUtc: "2026-09-06T10:00:06.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusUpdatedAtUtc: "2026-09-06T09:59:59.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusHeartbeatAtUtc: "2026-09-06T03:59:59.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusUpdatedAtUtc: "2026-09-06T10:00:11.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ statusHeartbeatAtUtc: "2026-09-06T10:00:06.000Z" }),
      gate,
      CLEAR_NOW,
    )
  );
});

Deno.test("clear proof requires the fixed source lock and a free lock observation", () => {
  const gate = validateGate(boundGate());
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ sourceLockPath: "/tmp/source.lock" }),
      gate,
      CLEAR_NOW,
    )
  );
  assertThrows(() =>
    validateGateClearProof(
      proofFixture({ sourceLockFree: false }),
      gate,
      CLEAR_NOW,
    )
  );
});

Deno.test("validated clear proof is a fresh copy", () => {
  const gate = validateGate(boundGate());
  const input = proofFixture();
  const proof = validateGateClearProof(input, gate, CLEAR_NOW);
  assertEquals(proof, input);
  assert(!Object.is(proof, input));
  input.statusState = "FAILED";
  assertEquals(proof.statusState, "PENDING_VERIFIER");
});

Deno.test("canonicalUtcMillis accepts only canonical UTC strings", () => {
  assertEquals(
    canonicalUtcMillis("2026-09-06T04:00:00.000Z", "x"),
    Date.parse("2026-09-06T04:00:00.000Z"),
  );
  assertThrows(() => canonicalUtcMillis("2026-09-06T04:00:00Z", "x"));
  assertThrows(() => canonicalUtcMillis("2026-09-06T04:00:00.00Z", "x"));
  assertThrows(() => canonicalUtcMillis(42, "x"));
  assertThrows(() => canonicalUtcMillis("2026-02-30T04:00:00.000Z", "x"));
});

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

const SOURCE = {
  instanceId: "ocid1.instance.oc1..aaaa",
  bootVolumeId: "ocid1.bootvolume.oc1..aaaa",
  rootVolumeId: "ocid1.volume.oc1..aaaa",
  compartmentId: "ocid1.compartment.oc1..aaaa",
  region: "us-ashburn-1",
};
const PAIR = {
  suffix: "20260903T191507Z",
  bootId: "ocid1.bootvolumebackup.oc1..bbbb",
  rootId: "ocid1.volumebackup.oc1..bbbb",
};
const GUEST = {
  rootUuid: "aaaaaaaa-1111-1111-1111-111111111111",
  stagingUuid: "bbbbbbbb-2222-2222-2222-222222222222",
  containers: [{ id: "c1", name: "guacamole", running: true }],
  units: [{ name: "caddy.service", active: true }],
  restored: true,
};

function stateFixture(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const acceptedAt = iso(Date.now() - 3_300_000);
  return {
    policy: {
      source: { ...SOURCE },
      standingApproval: {
        approvedAtUtc: iso(Date.now() - 86_400_000),
        exactOperation: "weekly paired backup rotation",
        source: { ...SOURCE },
      },
      acceptedPair: { ...PAIR },
      retainPreviousPair: true,
      allowFifthSlot: true,
    },
    cycle: {
      source: { ...SOURCE },
      previousPair: { ...PAIR },
      suffix: "20260905T050131Z",
      phase: "complete",
      createdAtUtc: iso(Date.now() - 7_200_000),
      updatedAtUtc: acceptedAt,
      sourceAcceptedAtUtc: acceptedAt,
    },
    guest: structuredClone(GUEST),
    ...overrides,
  };
}

Deno.test("launch preflight permits a complete cycle with no claim", () => {
  assertEquals(
    assertBackblazeLaunchAllowed(stateFixture(), undefined),
    undefined,
  );
  assertBackblazeLaunchAllowed(stateFixture(), null);
});

Deno.test("launch preflight binds the journal source to the validated policy source", () => {
  // The selected source is the VALIDATED policy source. Drifting only the
  // policy source (with its standing approval) must refuse even though the
  // journal binds itself; a self-bound journal must never authorize.
  const policyDrift = stateFixture();
  (policyDrift.policy as Record<string, unknown>).source = {
    ...SOURCE,
    region: "us-phoenix-1",
  };
  (
    (policyDrift.policy as Record<string, unknown>).standingApproval as Record<
      string,
      unknown
    >
  ).source = { ...SOURCE, region: "us-phoenix-1" };
  assertThrows(() => assertBackblazeLaunchAllowed(policyDrift, undefined));
  const cycleDrift = stateFixture();
  (cycleDrift.cycle as Record<string, unknown>).source = {
    ...SOURCE,
    instanceId: "ocid1.instance.oc1..bbbb",
  };
  assertThrows(() => assertBackblazeLaunchAllowed(cycleDrift, undefined));
});

Deno.test("launch preflight rejects a suffix equal to the previous pair suffix", () => {
  const sameSuffix = stateFixture();
  (sameSuffix.cycle as Record<string, unknown>).suffix = PAIR.suffix;
  assertThrows(() => assertBackblazeLaunchAllowed(sameSuffix, undefined));
});

Deno.test("launch preflight rejects sourceAcceptedAtUtc later than updatedAtUtc", () => {
  const state = stateFixture();
  const updatedAt = Date.parse(
    (state.cycle as Record<string, unknown>).updatedAtUtc as string,
  );
  (state.cycle as Record<string, unknown>).sourceAcceptedAtUtc = iso(
    updatedAt + 1,
  );
  assertThrows(() => assertBackblazeLaunchAllowed(state, undefined));
  // Equal is accepted: acceptance and the journal update may share a stamp.
  assertBackblazeLaunchAllowed(stateFixture(), undefined);
});

Deno.test("launch preflight treats absent guest as permitted but explicit null as malformed", () => {
  const absent = stateFixture();
  delete absent.guest;
  assertBackblazeLaunchAllowed(absent, undefined);
  const explicitUndefined = stateFixture();
  explicitUndefined.guest = undefined;
  assertBackblazeLaunchAllowed(explicitUndefined, undefined);
  const explicitNull = stateFixture();
  explicitNull.guest = null;
  assertThrows(() => assertBackblazeLaunchAllowed(explicitNull, undefined));
});

Deno.test("launch preflight fails closed on absent or malformed Oracle state", () => {
  assertThrows(() => assertBackblazeLaunchAllowed(null, undefined));
  assertThrows(() => assertBackblazeLaunchAllowed(undefined, undefined));
  assertThrows(() => assertBackblazeLaunchAllowed({}, undefined));
  assertThrows(() => assertBackblazeLaunchAllowed({ policy: {} }, undefined));
  const noSource = stateFixture();
  delete (noSource.cycle as Record<string, unknown>).source;
  assertThrows(() => assertBackblazeLaunchAllowed(noSource, undefined));
  const badSource = stateFixture();
  (badSource.cycle as Record<string, unknown>).source = {
    ...SOURCE,
    region: "",
  };
  assertThrows(() => assertBackblazeLaunchAllowed(badSource, undefined));
  const badPolicy = stateFixture();
  (badPolicy.policy as Record<string, unknown>).allowFifthSlot = "yes";
  assertThrows(() => assertBackblazeLaunchAllowed(badPolicy, undefined));
});

Deno.test("launch preflight rejects any cycle that is not complete", () => {
  for (const phase of ["planned", "failed", "source-accepted", "retiring"]) {
    const state = stateFixture();
    (state.cycle as Record<string, unknown>).phase = phase;
    assertThrows(() => assertBackblazeLaunchAllowed(state, undefined));
  }
});

Deno.test("launch preflight rejects a journal that needs source recovery", () => {
  for (const recoveryStatus of ["needed", "failed", "unknown-shape"]) {
    const state = stateFixture();
    (state.cycle as Record<string, unknown>).recoveryStatus = recoveryStatus;
    assertThrows(() => assertBackblazeLaunchAllowed(state, undefined));
  }
  const state = stateFixture();
  (state.cycle as Record<string, unknown>).recoveryStatus = "running-accepted";
  assertBackblazeLaunchAllowed(state, undefined);
});

Deno.test("launch preflight rejects a guest that is not restored or malformed", () => {
  const unRestored = stateFixture();
  (unRestored.guest as Record<string, unknown>).restored = false;
  assertThrows(() => assertBackblazeLaunchAllowed(unRestored, undefined));
  const badContainers = stateFixture();
  (badContainers.guest as Record<string, unknown>).containers = [{ id: "" }];
  assertThrows(() => assertBackblazeLaunchAllowed(badContainers, undefined));
  const badId = stateFixture();
  (badId.guest as Record<string, unknown>).rootUuid = "not-a-uuid";
  assertThrows(() => assertBackblazeLaunchAllowed(badId, undefined));
  const badUnits = stateFixture();
  (badUnits.guest as Record<string, unknown>).units = [{ active: true }];
  assertThrows(() => assertBackblazeLaunchAllowed(badUnits, undefined));
});

Deno.test("launch preflight rejects started or unknown claims and permits finished ones", () => {
  const started = {
    windowId: "2026-09-06@America/New_York",
    status: "started",
    updatedAtUtc: iso(Date.now() - 60_000),
  };
  assertThrows(() => assertBackblazeLaunchAllowed(stateFixture(), started));
  const unknown = { ...started, status: "pending" };
  assertThrows(() => assertBackblazeLaunchAllowed(stateFixture(), unknown));
  const malformed = { ...started, status: "complete", windowId: "" };
  assertThrows(() => assertBackblazeLaunchAllowed(stateFixture(), malformed));
  const complete = { ...started, status: "complete" };
  assertBackblazeLaunchAllowed(stateFixture(), complete);
  const failed = { ...started, status: "failed" };
  assertBackblazeLaunchAllowed(stateFixture(), failed);
});

Deno.test("standing approval accepts equivalent ISO timestamp text without rewriting it", () => {
  const state = stateFixture();
  const policy = state.policy as Record<string, unknown>;
  const approval = policy.standingApproval as Record<string, unknown>;
  approval.approvedAtUtc = "2026-09-05T01:51:00Z";
  assertBackblazeLaunchAllowed(state, undefined);
  assertEquals(approval.approvedAtUtc, "2026-09-05T01:51:00Z");
});
