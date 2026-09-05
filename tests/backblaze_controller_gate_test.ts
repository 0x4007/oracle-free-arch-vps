import {
  bindInvocation,
  clearGateAfterProof,
  markOrphaned,
  readGate,
  writeActiveGate,
} from "../scripts/backblaze-controller-gate.ts";
import {
  type BackupControllerGate,
  type OrphanReason,
  validateGate,
} from "../scripts/backblaze-controller-contract.ts";

const UUID = "681c4067-aec2-45d5-9afb-77ee530e3a97";
const INVOCATION = "a7064f4b7f524c3baa3725acc88f73ed";
const REQUEST_SHA = "ab".repeat(32);

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

async function assertThrowsAsync(
  run: () => Promise<unknown>,
  messageIncludes?: string,
): Promise<string> {
  try {
    await run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert(
      !messageIncludes || message.includes(messageIncludes),
      `Expected error to include ${messageIncludes}, got ${message}`,
    );
    return message;
  }
  throw new Error("Expected the call to throw");
}

/** Query-only permission probe; the default `deno test` task carries no
 * permissions, so filesystem cases skip there and only execute under the
 * explicit --allow-read/--allow-write invocation. */
async function runtimePermissionsGranted(): Promise<boolean> {
  const descriptors: Deno.PermissionDescriptor[] = [
    { name: "read" },
    { name: "write" },
  ];
  for (const descriptor of descriptors) {
    try {
      if ((await Deno.permissions.query(descriptor)).state !== "granted") {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

const runtimePermitted = await runtimePermissionsGranted();

function runtimeTest(
  name: string,
  fn: () => void | Promise<void>,
): void {
  Deno.test({ name: `runtime: ${name}`, ignore: !runtimePermitted, fn });
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function gateFixture(
  overrides: Record<string, unknown> = {},
  nowMs: number = Date.now(),
): BackupControllerGate {
  const requestedAt = nowMs - 7_200_000;
  const createdAt = nowMs - 3_600_000;
  return validateGate({
    schemaVersion: 1,
    owner: "backblaze-direct",
    state: "active",
    jobId: `job-${UUID}`,
    periodKey: "2026-09-06",
    generation: `generation-${UUID}`,
    requestSha256: REQUEST_SHA,
    requestedAtUtc: iso(requestedAt),
    deadlineAtUtc: iso(requestedAt + 6 * 3_600_000),
    createdAtUtc: iso(createdAt),
    updatedAtUtc: iso(createdAt + 1_000),
    remoteHost: "codex@vps.pavlovcik.com",
    unitName: `arch-vps-b2-worker-${UUID}.service`,
    unitInvocationId: null,
    sourceLockPath: "/var/tmp/arch-vps-file-backup/source.lock",
    ...overrides,
  });
}

function proofFixture(
  overrides: Record<string, unknown> = {},
  nowMs: number = Date.now(),
): Record<string, unknown> {
  const checkedAt = nowMs - 5_000;
  const finishedAt = nowMs - 30_000;
  return {
    checkedAtUtc: iso(checkedAt),
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
    statusState: "ACCEPTED",
    statusJobId: `job-${UUID}`,
    statusPeriodKey: "2026-09-06",
    statusGeneration: `generation-${UUID}`,
    statusRequestSha256: REQUEST_SHA,
    statusInvocationId: INVOCATION,
    statusUpdatedAtUtc: iso(finishedAt),
    statusHeartbeatAtUtc: iso(finishedAt - 1_000),
    statusFinishedAtUtc: iso(finishedAt),
    sourceLockPath: "/var/tmp/arch-vps-file-backup/source.lock",
    sourceLockFree: true,
    ...overrides,
  };
}

async function newGateDir(): Promise<string> {
  const dir = await Deno.makeTempDir({ prefix: "m06-gate-" });
  // The gate module resolves the parent through realPath, so the fixture
  // paths must use the canonical directory spelling (e.g. /private/tmp).
  const canonical = await Deno.realPath(dir);
  const parent = `${canonical}/.private`;
  await Deno.mkdir(parent, { mode: 0o700 });
  await Deno.chmod(parent, 0o700);
  return canonical;
}

async function listedNames(
  dir: string,
  parent = ".private",
): Promise<string[]> {
  const entries = [];
  for await (const entry of Deno.readDir(`${dir}/${parent}`)) {
    entries.push(entry.name);
  }
  return entries.sort();
}

runtimeTest("create, bounded readback and durable atomic write", async () => {
  const dir = await newGateDir();
  try {
    const path = `${dir}/.private/backup-controller-gate.json`;
    const gate = gateFixture();
    const created = await writeActiveGate(gate, path);
    assertEquals(created, gate);
    const read = await readGate(path);
    assertEquals(read, gate);
    assertEquals(read !== null && read === gate, false);
    const info = await Deno.lstat(path);
    const parent = await Deno.stat(`${dir}/.private`);
    assert(info.isFile && !info.isSymlink);
    assert(info.nlink === 1);
    assert(info.mode !== null && (info.mode & 0o777) === 0o600);
    assert(info.uid === parent.uid);
    assertEquals(await listedNames(dir), ["backup-controller-gate.json"]);
    const fileText = await Deno.readTextFile(path);
    assert(fileText.endsWith("\n"));
    const parsed = JSON.parse(fileText) as Record<string, unknown>;
    assertEquals(Object.keys(parsed), Object.keys(gate));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

runtimeTest("create refuses an existing path without overwriting", async () => {
  const dir = await newGateDir();
  try {
    const path = `${dir}/.private/backup-controller-gate.json`;
    await writeActiveGate(gateFixture(), path);
    const before = await Deno.readTextFile(path);
    await assertThrowsAsync(
      () => writeActiveGate(gateFixture(), path),
      "refusing to overwrite",
    );
    assertEquals(await Deno.readTextFile(path), before);
    assertEquals(await listedNames(dir), ["backup-controller-gate.json"]);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

runtimeTest("create refuses a bound, orphaned or malformed gate", async () => {
  const dir = await newGateDir();
  try {
    const path = `${dir}/.private/backup-controller-gate.json`;
    await assertThrowsAsync(
      () =>
        writeActiveGate(gateFixture({ unitInvocationId: INVOCATION }), path),
      "must be active with an unbound unit invocation",
    );
    await assertThrowsAsync(
      () =>
        writeActiveGate(
          gateFixture({
            state: "orphaned",
            orphanReason: "STATUS_INVALID",
          }),
          path,
        ),
      "must be active",
    );
    await assertThrowsAsync(
      () => writeActiveGate({} as BackupControllerGate, path),
      "schemaVersion must be 1",
    );
    assertEquals(await readGate(path), null);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

runtimeTest(
  "bind binds null to the exact invocation and preserves identity",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      const gate = gateFixture();
      await writeActiveGate(gate, path);
      const bound = await bindInvocation(gate, INVOCATION, path);
      assert(bound.unitInvocationId === INVOCATION);
      assert(
        bound.jobId === gate.jobId && bound.generation === gate.generation,
      );
      assert(bound.unitName === gate.unitName);
      assert(bound.deadlineAtUtc === gate.deadlineAtUtc);
      assert(bound.requestedAtUtc === gate.requestedAtUtc);
      assert(bound.state === "active");
      assert(bound.updatedAtUtc >= bound.createdAtUtc);
      const read = await readGate(path);
      assert(read !== null && read.unitInvocationId === INVOCATION);
      assert(gate.unitInvocationId === null, "Expected input gate unchanged");
      assertEquals(await listedNames(dir), ["backup-controller-gate.json"]);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "bind to the same id is a no-op; a different id is refused",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await writeActiveGate(gateFixture(), path);
      const gate = await readGate(path);
      assert(gate !== null);
      const first = await bindInvocation(gate, INVOCATION, path);
      const second = await bindInvocation(first, INVOCATION, path);
      assertEquals(second, first);
      await assertThrowsAsync(
        () => bindInvocation(first, "b".repeat(32), path),
        "already bound to a different id",
      );
      const read = await readGate(path);
      assert(read !== null && read.unitInvocationId === INVOCATION);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest("bind requires the exact expected gate identity", async () => {
  const dir = await newGateDir();
  try {
    const path = `${dir}/.private/backup-controller-gate.json`;
    await writeActiveGate(gateFixture(), path);
    const expected = await readGate(path);
    assert(expected !== null);
    const changed = validateGate({ ...expected, periodKey: "2026-09-13" });
    await assertThrowsAsync(
      () => bindInvocation(changed, INVOCATION, path),
      "Gate changed since it was read",
    );
    const read = await readGate(path);
    assert(read !== null && read.unitInvocationId === null);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

runtimeTest("bind refuses an absent gate", async () => {
  const dir = await newGateDir();
  try {
    const path = `${dir}/.private/backup-controller-gate.json`;
    await assertThrowsAsync(
      () => bindInvocation(gateFixture(), INVOCATION, path),
      "Gate is absent",
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

runtimeTest(
  "markOrphaned preserves identity and uses the fixed reason",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await writeActiveGate(gateFixture(), path);
      const gate = await readGate(path);
      assert(gate !== null);
      const orphaned = await markOrphaned(
        gate,
        "SOURCE_UNREACHABLE_AT_DEADLINE",
        path,
      );
      assertEquals(orphaned.state, "orphaned");
      assertEquals(
        orphaned.orphanReason,
        "SOURCE_UNREACHABLE_AT_DEADLINE",
      );
      assertEquals(
        {
          jobId: orphaned.jobId,
          generation: orphaned.generation,
          unitName: orphaned.unitName,
          deadlineAtUtc: orphaned.deadlineAtUtc,
          requestedAtUtc: orphaned.requestedAtUtc,
          periodKey: orphaned.periodKey,
          unitInvocationId: orphaned.unitInvocationId,
          sourceLockPath: orphaned.sourceLockPath,
        },
        {
          jobId: gate.jobId,
          generation: gate.generation,
          unitName: gate.unitName,
          deadlineAtUtc: gate.deadlineAtUtc,
          requestedAtUtc: gate.requestedAtUtc,
          periodKey: gate.periodKey,
          unitInvocationId: gate.unitInvocationId,
          sourceLockPath: gate.sourceLockPath,
        },
      );
      const read = await readGate(path);
      assertEquals(read, orphaned);
      assertEquals(await listedNames(dir), ["backup-controller-gate.json"]);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "markOrphaned validates the reason, expected identity and idempotence",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await writeActiveGate(gateFixture(), path);
      const gate = await readGate(path);
      assert(gate !== null);
      await assertThrowsAsync(
        () => markOrphaned(gate, "GIVE_UP" as OrphanReason, path),
        "Unknown orphan reason",
      );
      const changed = validateGate({
        ...gate,
        periodKey: "2026-09-13",
      });
      await assertThrowsAsync(
        () => markOrphaned(changed, "STATUS_INVALID", path),
        "Gate changed since it was read",
      );
      const orphaned = await markOrphaned(
        gate,
        "TERMINAL_PROOF_MISSING",
        path,
      );
      const again = await markOrphaned(
        orphaned,
        "TERMINAL_PROOF_MISSING",
        path,
      );
      assertEquals(again, orphaned);
      await assertThrowsAsync(
        () => markOrphaned(orphaned, "STATUS_INVALID", path),
        "already orphaned for a different reason",
      );
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "clear removes the gate only after a strict fresh bound proof",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await writeActiveGate(gateFixture(), path);
      const gate = await readGate(path);
      assert(gate !== null);
      const bound = await bindInvocation(gate, INVOCATION, path);
      const cleared = await clearGateAfterProof(
        bound,
        proofFixture(),
        path,
        new Date(),
      );
      assertEquals(cleared, bound);
      assertEquals(await readGate(path), null);
      assertEquals(await listedNames(dir), []);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "clear refuses stale, future or mismatched proofs and keeps the gate",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await writeActiveGate(gateFixture(), path);
      const gate = await readGate(path);
      assert(gate !== null);
      const bound = await bindInvocation(gate, INVOCATION, path);
      const proof = proofFixture();
      const checked = Date.parse(proof.checkedAtUtc as string);
      await assertThrowsAsync(
        () =>
          clearGateAfterProof(bound, proof, path, new Date(checked + 31_000)),
        "stale or was checked in the future",
      );
      await assertThrowsAsync(
        () =>
          clearGateAfterProof(bound, proof, path, new Date(checked - 1_000)),
        "stale or was checked in the future",
      );
      const mismatched = proofFixture({
        statusJobId: `job-${"0".repeat(8)}-${"0".repeat(4)}-${"0".repeat(4)}-${
          "0".repeat(4)
        }-${"0".repeat(12)}`,
      });
      await assertThrowsAsync(
        () => clearGateAfterProof(bound, mismatched, path, new Date()),
        "status identity does not match",
      );
      assertEquals(await readGate(path), bound);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "clear and bind demand the exact expected gate and presence",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await writeActiveGate(gateFixture(), path);
      const gate = await readGate(path);
      assert(gate !== null);
      const bound = await bindInvocation(gate, INVOCATION, path);
      const changed = validateGate({ ...bound, periodKey: "2026-09-13" });
      await assertThrowsAsync(
        () => clearGateAfterProof(changed, proofFixture(), path, new Date()),
        "Gate changed since it was read",
      );
      assertEquals(await readGate(path), bound);
      await clearGateAfterProof(bound, proofFixture(), path, new Date());
      await assertThrowsAsync(
        () => clearGateAfterProof(bound, proofFixture(), path, new Date()),
        "Gate is absent",
      );
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "readGate: missing means NotFound with a valid parent only",
  async () => {
    const dir = await newGateDir();
    try {
      assertEquals(
        await readGate(`${dir}/.private/backup-controller-gate.json`),
        null,
      );
      await assertThrowsAsync(
        () => readGate(`${dir}/missing-parent/gate.json`),
        "parent directory is missing",
      );
      await assertThrowsAsync(
        () => readGate(`${dir}/.private/`),
        "must name a file inside a directory",
      );
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "readGate: malformed or oversized file state never means absence",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await Deno.writeTextFile(path, `{"jobId": "CANARY_SECRET"`, {
        mode: 0o600,
      });
      let message = await assertThrowsAsync(
        () => readGate(path),
        "not valid JSON",
      );
      assert(!message.includes("CANARY_SECRET"));
      await Deno.writeTextFile(
        path,
        JSON.stringify({ schemaVersion: 1, owner: "CANARY_VALUE" }),
        { mode: 0o600 },
      );
      message = await assertThrowsAsync(() => readGate(path));
      assert(!message.includes("CANARY_VALUE"));
      const oversized = "x".repeat(64 * 1024 + 1);
      await Deno.writeTextFile(path, oversized, { mode: 0o600 });
      await assertThrowsAsync(() => readGate(path), "64 KiB read bound");
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "readGate rejects symlink, hardlink, mode and parent drift",
  async () => {
    const dir = await newGateDir();
    try {
      const parent = `${dir}/.private`;
      const realPath = `${parent}/real.json`;
      await writeActiveGate(gateFixture(), realPath);
      const linkPath = `${parent}/backup-controller-gate.json`;
      await Deno.symlink(realPath, linkPath);
      await assertThrowsAsync(() => readGate(linkPath), "regular file");

      await Deno.remove(linkPath);
      const hardlinkPath = `${parent}/copy.json`;
      await Deno.link(realPath, hardlinkPath);
      await assertThrowsAsync(
        () => readGate(realPath),
        "exactly one hard link",
      );
      await Deno.remove(realPath);
      await Deno.rename(hardlinkPath, realPath);

      await Deno.chmod(realPath, 0o644);
      await assertThrowsAsync(() => readGate(realPath), "only owner access");
      await Deno.chmod(realPath, 0o600);

      await Deno.chmod(parent, 0o755);
      await assertThrowsAsync(() => readGate(realPath), "only owner access");
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

/** Run fn with Deno.lstat wrapped; the trigger fires exactly once, on the
 * first call where it returns true (NotFound passes result null), and the
 * original function is restored afterwards. */
async function withPatchedLstat(
  trigger: (path: string, result: Deno.FileInfo | null) => boolean,
  action: () => Promise<void>,
  fn: () => Promise<void>,
): Promise<void> {
  const original = Deno.lstat.bind(Deno);
  let fired = false;
  (Deno as unknown as { lstat: typeof Deno.lstat }).lstat = async (
    path: string | URL,
  ) => {
    const name = typeof path === "string" ? path : path.toString();
    try {
      const info = await original(path);
      if (!fired && trigger(name, info)) {
        fired = true;
        await action();
      }
      return info;
    } catch (error) {
      if (!fired && error instanceof Deno.errors.NotFound) {
        if (trigger(name, null)) {
          fired = true;
          await action();
        }
      }
      throw error;
    }
  };
  try {
    await fn();
  } finally {
    Deno.lstat = original;
  }
}

/** Replace the trusted parent directory with a fresh 0700 directory of the
 * same path; the original directory is preserved as `.private.old`. */
async function swapParent(dir: string): Promise<void> {
  await Deno.rename(`${dir}/.private`, `${dir}/.private.old`);
  const fresh = `${dir}/.private`;
  await Deno.mkdir(fresh, { mode: 0o700 });
  await Deno.chmod(fresh, 0o700);
}

runtimeTest(
  "absent read fails closed when the parent is replaced during the read",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await withPatchedLstat(
        (p) => p === path,
        () => swapParent(dir),
        async () => {
          await assertThrowsAsync(
            () => readGate(path),
            "parent identity changed",
          );
        },
      );
      // Absence is never reported through a replaced parent: the fresh
      // parent must stay empty and the original directory is preserved.
      assertEquals(await listedNames(dir), []);
      assertEquals(await listedNames(dir, ".private.old"), []);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "mutation fails closed and preserves files when the parent is replaced mid-flight",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await writeActiveGate(gateFixture(), path);
      const expected = await readGate(path);
      assert(expected !== null);
      await withPatchedLstat(
        (p) => p.endsWith(".tmp"),
        () => swapParent(dir),
        async () => {
          await assertThrowsAsync(
            () => bindInvocation(expected, INVOCATION, path),
            "Gate temp is missing",
          );
        },
      );
      // Nothing may be published or removed through the replaced parent.
      const fresh = await listedNames(dir);
      assertEquals(fresh, []);
      const preserved = await listedNames(dir, ".private.old");
      assert(
        preserved.includes("backup-controller-gate.json"),
        "The original gate must be preserved",
      );
      assert(
        preserved.some((name) => name.endsWith(".tmp")),
        "Our own temp must be preserved, never deleted through a replaced parent",
      );
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "own temp replaced before publication fails closed and preserves the foreign file",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      // The replacement happens right after the second (pre-publication)
      // absence check, so the pre-link own-temp check must observe it.
      let finalNotFound = 0;
      await withPatchedLstat(
        (p, result) => {
          if (p !== path) return false;
          if (result === null) finalNotFound++;
          return finalNotFound === 2;
        },
        async () => {
          const tempName = (await listedNames(dir)).find((name) =>
            name.endsWith(".tmp")
          )!;
          assert(tempName, "The own temp must exist before publication");
          await Deno.remove(`${dir}/.private/${tempName}`);
          await Deno.writeTextFile(
            `${dir}/.private/${tempName}`,
            "FOREIGN_REPLACEMENT",
            { mode: 0o600 },
          );
        },
        async () => {
          await assertThrowsAsync(
            () => writeActiveGate(gateFixture(), path),
            "identity changed",
          );
        },
      );
      // The foreign temp is preserved and nothing was published.
      assertEquals(await readGate(path), null);
      const names = await listedNames(dir);
      assertEquals(names.length, 1);
      assert(names[0].endsWith(".tmp"));
      assertEquals(
        await Deno.readTextFile(`${dir}/.private/${names[0]}`),
        "FOREIGN_REPLACEMENT",
      );
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "create-new link publishes the exact temp inode and hardlink lifecycle",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      const observations: Array<{
        name: string;
        nlink: number | null;
        dev: number | null;
        ino: number | null;
        size: number;
      }> = [];
      const original = Deno.lstat.bind(Deno);
      (Deno as unknown as { lstat: typeof Deno.lstat }).lstat = async (
        targetPath: string | URL,
      ) => {
        const name = typeof targetPath === "string"
          ? targetPath
          : targetPath.toString();
        const info = await original(targetPath);
        if (name.includes(".tmp") || name === path) {
          observations.push({
            name,
            nlink: info.nlink,
            dev: info.dev,
            ino: info.ino,
            size: info.size,
          });
        }
        return info;
      };
      try {
        await writeActiveGate(gateFixture(), path);
      } finally {
        Deno.lstat = original;
      }
      assertEquals(await listedNames(dir), ["backup-controller-gate.json"]);
      const tempObs = observations.filter((o) => o.name.includes(".tmp"));
      const finalObs = observations.filter((o) => o.name === path);
      // Exact lifecycle: own temp nlink 1 -> both temp and final nlink 2 ->
      // final nlink 1, always the same dev/inode.
      const temp1 = tempObs.find((o) => o.nlink === 1);
      const temp2 = tempObs.find((o) => o.nlink === 2);
      const final2 = finalObs.find((o) => o.nlink === 2);
      const final1 = finalObs.find((o) => o.nlink === 1);
      assert(temp1, "The own temp must be observed with one link");
      assert(temp2, "The temp must gain a second link at publication");
      assert(final2, "The final must be observed as the linked temp inode");
      assert(final1, "The final must be observed with one link afterwards");
      assert(
        temp1.dev === temp2.dev && temp1.ino === temp2.ino &&
          final2.dev === temp2.dev && final2.ino === temp2.ino &&
          final1.dev === temp2.dev && final1.ino === temp2.ino,
        "All lifecycle observations must share the original temp inode",
      );
      assert(
        final1.size === temp2.size && final2.size === temp2.size,
        "The size must be stable across the whole lifecycle",
      );
      const info = await Deno.lstat(path);
      const parent = await Deno.stat(`${dir}/.private`);
      assert(info.isFile && info.nlink === 1);
      assert(info.mode !== null && (info.mode & 0o777) === 0o600);
      assert(info.uid === parent.uid);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "mutators snapshot their inputs before the first await",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      await writeActiveGate(gateFixture(), path);
      const expected = await readGate(path);
      assert(expected !== null);
      // Mutating the caller's objects while the operation awaits must not
      // change what is authorized: bind uses a synchronous snapshot.
      const pendingBind = bindInvocation(expected, INVOCATION, path);
      expected.periodKey = "2026-09-13";
      const bound = await pendingBind;
      assert(bound.unitInvocationId === INVOCATION);
      const read = await readGate(path);
      assert(read !== null && read.unitInvocationId === INVOCATION);
      // Mark orphaned with a mutated expected gate still validates the
      // ORIGINAL identity snapshot.
      const expectedForOrphan = { ...bound };
      const pendingOrphan = markOrphaned(
        expectedForOrphan,
        "STATUS_INVALID",
        path,
      );
      expectedForOrphan.periodKey = "2026-09-13";
      const orphaned = await pendingOrphan;
      assertEquals(orphaned.state, "orphaned");
      assertEquals(orphaned.orphanReason, "STATUS_INVALID");
      // Clear with a mutated proof and mutated comparison time still uses
      // the snapshots taken before the first await.
      const proof = proofFixture();
      const now = new Date();
      const pendingClear = clearGateAfterProof(orphaned, proof, path, now);
      (proof as Record<string, unknown>).statusJobId = `job-${"0".repeat(8)}-${
        "0".repeat(4)
      }-${"0".repeat(4)}-${"0".repeat(4)}-${"0".repeat(12)}`;
      now.setTime(Date.parse(proofFixture().checkedAtUtc as string) + 31_000);
      const cleared = await pendingClear;
      assertEquals(cleared, orphaned);
      assertEquals(await readGate(path), null);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "malformed temp write counts fail closed and leave no temp behind",
  async () => {
    const dir = await newGateDir();
    try {
      const path = `${dir}/.private/backup-controller-gate.json`;
      const malformedCounts: Array<{ value: number; message: string }> = [
        { value: 0, message: "write count" },
        { value: -7, message: "write count" },
        { value: Number.NaN, message: "write count" },
        { value: 1.5, message: "write count" },
        { value: Number.POSITIVE_INFINITY, message: "write count" },
      ];
      for (const malformed of malformedCounts) {
        await withTempHandleWrite(
          () => Promise.resolve(malformed.value),
          async () => {
            await assertThrowsAsync(
              () => writeActiveGate(gateFixture(), path),
              malformed.message,
            );
          },
        );
        assertEquals(await readGate(path), null);
        assertEquals(await listedNames(dir), []);
      }
      // A count longer than the requested length is also refused.
      await withTempHandleWrite(
        (requested) => Promise.resolve(requested + 1),
        async () => {
          await assertThrowsAsync(
            () => writeActiveGate(gateFixture(), path),
            "exceeds the requested length",
          );
        },
      );
      assertEquals(await readGate(path), null);
      assertEquals(await listedNames(dir), []);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

/** Wrap every write on a createNew+write handle with the given fake count. */
async function withTempHandleWrite(
  fakeWrite: (
    requested: number,
    buffer: Uint8Array,
  ) => Promise<number>,
  fn: () => Promise<void>,
): Promise<void> {
  const originalOpen = Deno.open.bind(Deno);
  (Deno as unknown as { open: typeof Deno.open }).open = async (
    path: string | URL,
    options?: Deno.OpenOptions,
  ) => {
    const handle = await originalOpen(path, options);
    if (!options?.createNew || !options?.write) return handle;
    return new Proxy(handle, {
      get(target, prop, receiver) {
        if (prop === "write") {
          return (buffer: Uint8Array) => fakeWrite(buffer.byteLength, buffer);
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as unknown as Deno.FsFile;
  };
  try {
    await fn();
  } finally {
    Deno.open = originalOpen;
  }
}
