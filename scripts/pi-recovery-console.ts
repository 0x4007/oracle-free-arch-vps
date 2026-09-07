/** Bounded, exactly approved Oracle console capture for the Pi SSH session.
 * The parent session owns the controller lock and supplies durable state.
 * Console text stays bounded in memory; only the verified public key is saved.
 */
import { createHash } from "node:crypto";
import {
  type ConsoleHostExpectation,
  recoveryControlRunner,
  type VerifiedRecoveryHost,
  verifyConsoleHostKey,
} from "./pi-recovery-ssh.ts";
import {
  type CommandRunner,
  dataArray,
  dataObject,
  type JsonRecord,
  runJson,
} from "./oci.ts";
import type { BackupInventoryConfig } from "./oci-backup-inventory.ts";
import {
  assertOracleMutationAllowed,
  readGate,
} from "./backblaze-controller-gate.ts";
import { backupControllerEvidence } from "./backup-controller-evidence.ts";

const OPERATION =
  "capture up to three console-history snapshots of the bound replacement boot phase for SSH host trust";
const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
export interface ConsoleCapturePlan {
  expected: ConsoleHostExpectation;
  compartmentId: string;
  operation: typeof OPERATION;
  maximumCaptures: 3;
  planSha256: string;
}
export interface ConsoleCaptureApproval {
  planSha256: string;
  exactOperation: string;
  approvedAtUtc: string;
}
export interface ConsoleCaptureState {
  planSha256: string;
  attempts: {
    number: number;
    intendedAtUtc: string;
    historyId?: string;
    markerMissing?: boolean;
  }[];
  host?: VerifiedRecoveryHost;
}
export interface ConsoleCapturePorts {
  json: (args: string[]) => Promise<JsonRecord>;
  text: (args: string[]) => Promise<string>;
  /** Refresh user authority, request ownership and competing-writer evidence. */
  beforeMutation: () => Promise<void>;
  /** Return only after fsync, atomic replacement and parent-directory fsync. */
  persist: (state: ConsoleCaptureState) => Promise<void>;
  now: () => number;
}
export function consoleCapturePlan(
  expected: ConsoleHostExpectation,
  compartmentId: string,
): ConsoleCapturePlan {
  if (
    !/^recovery-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(
      expected.requestId,
    ) ||
    !/^ocid1\.instance\.[a-zA-Z0-9.]+$/.test(expected.instanceId) ||
    !/^ocid1\.(?:compartment|tenancy)\.[a-zA-Z0-9.]+$/.test(compartmentId) ||
    !["loader", "ram", "restored"].includes(expected.phase) ||
    !Number.isFinite(Date.parse(expected.notBeforeUtc)) ||
    [expected.expectedBootId, expected.previousBootId].some((id) =>
      id !== undefined &&
      !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id)
    ) ||
    (expected.phase !== "loader" &&
      (!/^[0-9a-f]{64}$/.test(expected.manifestSha256 ?? "") ||
        !expected.previousBootId)) ||
    (expected.phase === "loader" && expected.manifestSha256 !== undefined) ||
    (expected.expectedBootId !== undefined &&
      expected.expectedBootId === expected.previousBootId)
  ) throw Error("Console capture target is incomplete");
  const body = {
    expected: structuredClone(expected),
    compartmentId,
    operation: OPERATION as typeof OPERATION,
    maximumCaptures: 3 as const,
  };
  return { ...body, planSha256: hash(body) };
}
export class ConsoleConnectionRequiredError extends Error {
  constructor() {
    super(
      "An active instance console connection is required before history capture",
    );
  }
}
async function requireConsoleConnection(
  plan: ConsoleCapturePlan,
  ports: ConsoleCapturePorts,
) {
  const connections = dataArray(
    await ports.json([
      "compute",
      "instance-console-connection",
      "list",
      "--compartment-id",
      plan.compartmentId,
      "--instance-id",
      plan.expected.instanceId,
      "--all",
    ]),
  );
  if (
    !connections.some((connection) =>
      connection["instance-id"] === plan.expected.instanceId &&
      connection["lifecycle-state"] === "ACTIVE" &&
      typeof connection.id === "string" &&
      /^ocid1\.instanceconsoleconnection\.[a-zA-Z0-9.]+$/.test(connection.id)
    )
  ) throw new ConsoleConnectionRequiredError();
}

function assertApproval(
  plan: ConsoleCapturePlan,
  approval: ConsoleCaptureApproval,
  now: number,
) {
  if (
    consoleCapturePlan(plan.expected, plan.compartmentId).planSha256 !==
      plan.planSha256 ||
    !approval || approval.planSha256 !== plan.planSha256 ||
    approval.exactOperation !== OPERATION ||
    !Number.isFinite(Date.parse(approval.approvedAtUtc)) ||
    Date.parse(approval.approvedAtUtc) > now ||
    now - Date.parse(approval.approvedAtUtc) > 3600000
  ) throw Error("Current exact console-capture approval is required");
}
function tag(plan: ConsoleCapturePlan, attempt: number) {
  return `${plan.expected.phase}-${attempt}-${plan.planSha256.slice(0, 16)}`;
}
function matches(
  plan: ConsoleCapturePlan,
  attempt: number,
  record: JsonRecord,
) {
  const tags = record["freeform-tags"] as JsonRecord | undefined;
  return record["instance-id"] === plan.expected.instanceId &&
    tags?.uosRecoveryRequest === plan.expected.requestId &&
    tags?.uosRecoveryConsole === tag(plan, attempt);
}
function verifyRecord(
  plan: ConsoleCapturePlan,
  attempt: number,
  record: JsonRecord,
) {
  if (
    !matches(plan, attempt, record) || typeof record.id !== "string" ||
    !/^ocid1\.consolehistory\.[a-zA-Z0-9.]+$/.test(record.id)
  ) {
    throw Error(
      "Console history does not belong to the approved recovery request",
    );
  }
  return record.id;
}

/** One bounded step. Pending captures are reread, never recreated. An absent
 * marker permits at most the next approved attempt after a 30-second backoff.
 * A lost CREATE response with no uniquely tagged record stays unresolved.
 */
export async function stepConsoleCapture(
  plan: ConsoleCapturePlan,
  approval: ConsoleCaptureApproval,
  state: ConsoleCaptureState,
  ports: ConsoleCapturePorts,
): Promise<
  {
    status:
      | "CONSOLE_CAPTURE_PENDING"
      | "CONSOLE_MARKER_PENDING"
      | "RECOVERY_HOST_KEY_VERIFIED";
    state: ConsoleCaptureState;
    host?: VerifiedRecoveryHost;
  }
> {
  if (
    consoleCapturePlan(plan.expected, plan.compartmentId).planSha256 !==
      plan.planSha256 ||
    plan.operation !== OPERATION || plan.maximumCaptures !== 3 ||
    state.planSha256 !== plan.planSha256 || !Array.isArray(state.attempts) ||
    state.attempts.length > 3 ||
    state.attempts.some((a, index) =>
      a.number !== index + 1 || !Number.isFinite(Date.parse(a.intendedAtUtc))
    )
  ) throw Error("Console capture journal differs from the plan");
  if (state.host) {
    const host = state.host;
    const checked = verifyConsoleHostKey(
      {
        id: host.consoleHistoryId,
        "instance-id": host.instanceId,
        "lifecycle-state": "SUCCEEDED",
        "time-created": host.consoleCapturedAtUtc,
      },
      `UOS_RECOVERY_HOST_KEY ${host.requestId} ${host.phase} ${host.bootId} ${
        host.manifestSha256 ?? "-"
      } ${host.publicKey}`,
      plan.expected,
      ports.now(),
    );
    if (checked.fingerprint !== host.fingerprint) {
      throw Error("Saved recovery host fingerprint changed");
    }
    return { status: "RECOVERY_HOST_KEY_VERIFIED", state, host: state.host };
  }
  let attempt = state.attempts.at(-1);
  let newlyIntended = false;
  if (!attempt || attempt.markerMissing) {
    if (attempt && ports.now() - Date.parse(attempt.intendedAtUtc) < 30_000) {
      return { status: "CONSOLE_MARKER_PENDING", state };
    }
    if (state.attempts.length >= 3) {
      throw Error(
        "Approved console capture limit exhausted; preserve existing histories",
      );
    }
    assertApproval(plan, approval, ports.now());
    await ports.beforeMutation();
    await requireConsoleConnection(plan, ports);
    // Check for a pre-existing tagged capture before creating a new intent.
    const next = state.attempts.length + 1;
    const existing = dataArray(
      await ports.json([
        "compute",
        "console-history",
        "list",
        "--compartment-id",
        plan.compartmentId,
        "--instance-id",
        plan.expected.instanceId,
        "--all",
      ]),
    ).filter((record) => matches(plan, next, record));
    if (existing.length !== 0) {
      throw Error(
        "Unrecorded matching console capture requires reconciliation",
      );
    }
    attempt = {
      number: next,
      intendedAtUtc: new Date(ports.now()).toISOString(),
    };
    state.attempts.push(attempt);
    await ports.persist(structuredClone(state));
    newlyIntended = true;
  }
  if (!attempt.historyId) {
    if (newlyIntended) {
      await ports.beforeMutation();
      assertApproval(plan, approval, ports.now());
      await requireConsoleConnection(plan, ports);
      const created = dataObject(
        await ports.json([
          "compute",
          "console-history",
          "capture",
          "--instance-id",
          plan.expected.instanceId,
          "--display-name",
          `${plan.expected.requestId}-${tag(plan, attempt.number)}`,
          "--freeform-tags",
          JSON.stringify({
            uosRecoveryRequest: plan.expected.requestId,
            uosRecoveryConsole: tag(plan, attempt.number),
          }),
        ]),
      );
      attempt.historyId = verifyRecord(plan, attempt.number, created);
    } else {
      const found = dataArray(
        await ports.json([
          "compute",
          "console-history",
          "list",
          "--compartment-id",
          plan.compartmentId,
          "--instance-id",
          plan.expected.instanceId,
          "--all",
        ]),
      ).filter((record) => matches(plan, attempt!.number, record));
      if (found.length !== 1) {
        throw Error(
          "Uncertain console capture must be reconciled before another CREATE",
        );
      }
      attempt.historyId = verifyRecord(plan, attempt.number, found[0]);
    }
    await ports.persist(structuredClone(state));
  }
  const metadata = dataObject(
    await ports.json([
      "compute",
      "console-history",
      "get",
      "--instance-console-history-id",
      attempt.historyId,
    ]),
  );
  if (verifyRecord(plan, attempt.number, metadata) !== attempt.historyId) {
    throw Error("Recorded console history identity changed");
  }
  if (
    ["REQUESTED", "GETTING-HISTORY"].includes(
      String(metadata["lifecycle-state"]),
    )
  ) return { status: "CONSOLE_CAPTURE_PENDING", state };
  if (metadata["lifecycle-state"] !== "SUCCEEDED") {
    throw Error("Console capture failed; preserve its recorded identity");
  }
  const content = await ports.text([
    "compute",
    "console-history",
    "get-content",
    "--instance-console-history-id",
    attempt.historyId,
    "--file",
    "-",
    "--length",
    String(1024 * 1024),
    "--offset",
    "0",
  ]);
  // Absence alone can justify another bounded snapshot. Ambiguity, invalid
  // keys, stale snapshots or mismatched boot/manifest evidence fail closed.
  const prefix =
    `UOS_RECOVERY_HOST_KEY ${plan.expected.requestId} ${plan.expected.phase} `;
  if (
    !content.replaceAll("\r", "").split("\n").some((line) =>
      line.trim().startsWith(prefix)
    )
  ) {
    attempt.markerMissing = true;
    await ports.persist(structuredClone(state));
    return { status: "CONSOLE_MARKER_PENDING", state };
  }
  const host = verifyConsoleHostKey(
    metadata,
    content,
    plan.expected,
    ports.now(),
  );
  state.host = host;
  await ports.persist(structuredClone(state));
  return { status: "RECOVERY_HOST_KEY_VERIFIED", state, host };
}

/** Real Pi API adapter; parent holds the existing controller lock and supplies
 * persistence into its session journal. No source SSH or archive fetch occurs.
 */
export function recoveryConsolePorts(
  controller: BackupInventoryConfig,
  plan: ConsoleCapturePlan,
  persist: ConsoleCapturePorts["persist"],
  currentApproval: () => Promise<ConsoleCaptureApproval>,
  runner: CommandRunner = recoveryControlRunner,
): ConsoleCapturePorts {
  const base = [
    "--profile",
    controller.ociProfile,
    "--region",
    controller.source.region,
    "--no-retry",
    "--connection-timeout",
    "10",
    "--read-timeout",
    "60",
  ];
  const json = (args: string[]) =>
    runJson(controller.ociCliPath, [...base, ...args], runner);
  return {
    json,
    now: () => Date.now(),
    persist,
    text: async (args) => {
      const result = await runner(controller.ociCliPath, [...base, ...args]);
      if (
        result.code !== 0 ||
        new TextEncoder().encode(result.stdout).length > 1024 * 1024
      ) throw Error("Bounded console content is unavailable");
      return result.stdout;
    },
    beforeMutation: async () => {
      assertApproval(plan, await currentApproval(), Date.now());
      assertOracleMutationAllowed(await readGate());
      await backupControllerEvidence(controller, runner)
        .assertNoOtherController();
      const instance = dataObject(
        await json([
          "compute",
          "instance",
          "get",
          "--instance-id",
          plan.expected.instanceId,
        ]),
      );
      if (
        plan.expected.instanceId === controller.source.instanceId ||
        plan.compartmentId !== controller.source.compartmentId ||
        instance.id !== plan.expected.instanceId ||
        instance["compartment-id"] !== plan.compartmentId ||
        instance["lifecycle-state"] !== "RUNNING" ||
        (instance["freeform-tags"] as JsonRecord | undefined)
            ?.uosRecoveryRequest !== plan.expected.requestId
      ) throw Error("Console capture is not bound to the running replacement");
    },
  };
}
