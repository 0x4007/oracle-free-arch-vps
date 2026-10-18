/** Per-invocation native facts, not inferred process/namespace completion. */
import { isDeepStrictEqual } from "node:util";
import {
  type BackupV2Gate,
  validateBackupV2Gate,
} from "./backup-v2-runtime-contract.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";

export const BACKUP_V2_NATIVE_CUSTODY_FILE = "native-custody.ndjson";
export type BackupV2NativeKind =
  | "main"
  | "metadata"
  | "bash"
  | "unshare"
  | "tar"
  | "zstd"
  | "gpg"
  | "sudo-gpg"
  | "curl";
export interface BackupV2NativeChild {
  pid: number;
  startTicks: string;
  bootId: string;
  cgroup: string;
  kind: BackupV2NativeKind;
}
export interface BackupV2NativeMount {
  scope: "UNIT" | "PRODUCER";
  leader: BackupV2NativeChild;
  device: string;
  inode: string;
  hostDevice: string;
  hostInode: string;
}
export type BackupV2NativeCustodyRecord =
  | { type: "BOUND"; schemaVersion: 1; gate: BackupV2Gate }
  | { type: "CHILD"; identity: BackupV2NativeChild }
  | {
    type: "EXIT";
    identity: BackupV2NativeChild;
    code: number;
    signal: string | null;
  }
  | { type: "MOUNT"; namespace: BackupV2NativeMount }
  | { type: "NO_PRIVATE_MOUNT" };
export interface BackupV2NativeCustody {
  gate: BackupV2Gate;
  children: {
    identity: BackupV2NativeChild;
    exit: Extract<BackupV2NativeCustodyRecord, { type: "EXIT" }> | null;
  }[];
  mounts: BackupV2NativeMount[];
  noPrivateMountProved: boolean;
  unresolvedNamespaceLeaders: BackupV2NativeChild[];
}
const kinds: readonly BackupV2NativeKind[] = [
  "main",
  "metadata",
  "bash",
  "unshare",
  "tar",
  "zstd",
  "gpg",
  "sudo-gpg",
  "curl",
];
function fail(): never {
  throw new Error("Backup v2 native custody record invalid or incomplete");
}
function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>;
  if (
    Object.keys(r).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(r, k))
  ) fail();
  return r;
}
function decimal(value: unknown, zero = false): string {
  if (
    typeof value !== "string" ||
    !(zero ? /^(0|[1-9][0-9]{0,19})$/ : /^[1-9][0-9]{0,19}$/).test(value)
  ) fail();
  return value;
}
function child(value: unknown, gate: BackupV2Gate): BackupV2NativeChild {
  const r = object(value, ["pid", "startTicks", "bootId", "cgroup", "kind"]);
  if (
    !Number.isSafeInteger(r.pid) || (r.pid as number) < 1 ||
    r.bootId !== gate.sourceBootId || typeof r.cgroup !== "string" ||
    !r.cgroup.startsWith("/") || r.cgroup.length > 2048 ||
    r.cgroup.split("/").some((part) =>
      part === ".." || /[\0\r\n]/.test(part)
    ) || !kinds.includes(r.kind as BackupV2NativeKind)
  ) fail();
  return {
    pid: r.pid as number,
    startTicks: decimal(r.startTicks),
    bootId: r.bootId as string,
    cgroup: r.cgroup,
    kind: r.kind as BackupV2NativeKind,
  };
}
export function backupV2NativeMain(
  gateInput: BackupV2Gate,
): BackupV2NativeChild {
  const gate = validateBackupV2Gate(gateInput);
  if (!gate.custody) fail();
  return {
    pid: gate.custody.mainPid,
    startTicks: gate.custody.mainStartTicks,
    bootId: gate.sourceBootId,
    cgroup: gate.custody.cgroup,
    kind: "main",
  };
}
export function validateBackupV2NativeCustodyRecord(
  value: unknown,
  gateInput: BackupV2Gate,
): BackupV2NativeCustodyRecord {
  const gate = validateBackupV2Gate(gateInput);
  if (!gate.custody) fail();
  const tag = (value as { type?: unknown } | null)?.type;
  if (tag === "BOUND") {
    const r = object(value, ["type", "schemaVersion", "gate"]),
      recorded = validateBackupV2Gate(r.gate);
    if (
      r.schemaVersion !== 1 || recorded.custody === null ||
      !isDeepStrictEqual({
        ...recorded,
        updatedAtUtc: gate.updatedAtUtc,
        state: gate.state,
      }, gate)
    ) fail();
    return { type: "BOUND", schemaVersion: 1, gate: recorded };
  }
  if (tag === "CHILD") {
    const r = object(value, ["type", "identity"]),
      identity = child(r.identity, gate);
    if (identity.kind === "main" || identity.pid === gate.custody.mainPid) {
      fail();
    }
    return { type: "CHILD", identity };
  }
  if (tag === "EXIT") {
    const r = object(value, ["type", "identity", "code", "signal"]),
      identity = child(r.identity, gate);
    if (
      !Number.isInteger(r.code) || (r.code as number) < -1 ||
      (r.code as number) > 255 ||
      r.signal !== null &&
        (typeof r.signal !== "string" || !/^SIG[A-Z0-9]{1,16}$/.test(r.signal))
    ) fail();
    return {
      type: "EXIT",
      identity,
      code: r.code as number,
      signal: r.signal as string | null,
    };
  }
  if (tag === "NO_PRIVATE_MOUNT") {
    object(value, ["type"]);
    return { type: "NO_PRIVATE_MOUNT" };
  }
  if (tag === "MOUNT") {
    const r = object(value, ["type", "namespace"]),
      n = object(r.namespace, [
        "scope",
        "leader",
        "device",
        "inode",
        "hostDevice",
        "hostInode",
      ]);
    if (n.scope !== "UNIT" && n.scope !== "PRODUCER") fail();
    const leader = child(n.leader, gate);
    if (
      n.scope === "UNIT" && !isDeepStrictEqual(leader, backupV2NativeMain(gate))
    ) fail();
    return {
      type: "MOUNT",
      namespace: {
        scope: n.scope,
        leader,
        device: decimal(n.device, true),
        inode: decimal(n.inode),
        hostDevice: decimal(n.hostDevice, true),
        hostInode: decimal(n.hostInode),
      },
    };
  }
  return fail();
}
/** Requires complete NDJSON frames, an exact first binding, and coherent known
 * births/exits. An unexited child remains unexited; absence is never invented. */
export function parseBackupV2NativeCustody(
  bytes: Uint8Array,
  gateInput: BackupV2Gate,
): BackupV2NativeCustody {
  const gate = validateBackupV2Gate(gateInput);
  if (bytes.length === 0 || bytes.length > BACKUP_V2_LIMITS.journalBytes) {
    fail();
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!text.endsWith("\n")) fail();
  const lines = text.slice(0, -1).split("\n");
  if (lines.length > BACKUP_V2_LIMITS.physicalPuts * 16) fail();
  const children = new Map<string, BackupV2NativeCustody["children"][number]>(),
    mounts: BackupV2NativeMount[] = [];
  let noPrivateMountProved = false;
  let recordedGate = gate;
  const key = (identity: BackupV2NativeChild) =>
    `${identity.pid}/${identity.startTicks}`;
  for (let at = 0; at < lines.length; at++) {
    if (new TextEncoder().encode(lines[at]).length > 16 * 1024) fail();
    const record = validateBackupV2NativeCustodyRecord(
      JSON.parse(lines[at]),
      gate,
    );
    if (at === 0) {
      if (record.type !== "BOUND") fail();
      recordedGate = record.gate;
      continue;
    }
    if (record.type === "BOUND") fail();
    if (record.type === "CHILD") {
      const id = key(record.identity);
      if (children.has(id)) fail();
      children.set(id, { identity: record.identity, exit: null });
    }
    if (record.type === "EXIT") {
      const known = children.get(key(record.identity));
      if (
        !known || known.exit ||
        !isDeepStrictEqual(known.identity, record.identity)
      ) fail();
      known.exit = record;
    }
    if (record.type === "MOUNT") {
      const n = record.namespace;
      if (
        mounts.some((m) =>
          m.hostDevice !== n.hostDevice || m.hostInode !== n.hostInode
        )
      ) fail();
      if (n.scope === "UNIT") {
        if (mounts.some((m) => m.scope === "UNIT")) fail();
      } else {
        const known = children.get(key(n.leader));
        if (
          !known || known.exit || !isDeepStrictEqual(known.identity, n.leader)
        ) fail();
      }
      if (
        noPrivateMountProved &&
        (n.device !== n.hostDevice || n.inode !== n.hostInode)
      ) fail();
      if (
        mounts.some((m) =>
          m.scope === n.scope && key(m.leader) === key(n.leader) &&
          m.device === n.device && m.inode === n.inode
        )
      ) fail();
      mounts.push(n);
    }
    if (record.type === "NO_PRIVATE_MOUNT") {
      const unit = mounts.find((m) => m.scope === "UNIT");
      if (
        noPrivateMountProved || !unit || [...children.values()].some((c) =>
          c.identity.kind === "unshare"
        ) || mounts.some((m) =>
          m.device !== m.hostDevice || m.inode !== m.hostInode
        )
      ) fail();
      noPrivateMountProved = true;
    }
  }
  return {
    gate: recordedGate,
    children: [...children.values()],
    mounts,
    noPrivateMountProved,
    unresolvedNamespaceLeaders: [...children.values()].filter((c) =>
      c.identity.kind === "unshare" &&
      !mounts.some((m) =>
        m.scope === "PRODUCER" && isDeepStrictEqual(m.leader, c.identity)
      )
    ).map((c) => c.identity),
  };
}
export function backupV2NativeCustodyBytes(
  record: BackupV2NativeCustodyRecord,
): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(record) + "\n");
}
