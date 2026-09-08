/** Recovery SSH trust comes from Oracle console evidence, never keyscan or
 * disabled checking. Only public host keys and bounded control text enter Pi.
 */
import { createHash } from "node:crypto";
import { shellQuote } from "./backup-guest.ts";
import type { CommandRunner, JsonRecord } from "./oci.ts";

export type RecoveryBootPhase = "loader" | "ram" | "restored";
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const REQUEST = /^recovery-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const PHASES = ["loader", "ram", "restored"];
const LIMIT = 1024 * 1024;
export interface ConsoleHostExpectation {
  requestId: string;
  instanceId: string;
  phase: RecoveryBootPhase;
  notBeforeUtc: string;
  expectedBootId?: string;
  previousBootId?: string;
  manifestSha256?: string;
}
export interface VerifiedRecoveryHost {
  requestId: string;
  instanceId: string;
  phase: RecoveryBootPhase;
  bootId: string;
  manifestSha256: string | null;
  publicKey: string;
  fingerprint: string;
  consoleHistoryId: string;
  consoleCapturedAtUtc: string;
}
function publicKeyFingerprint(publicKey: string): string {
  const match = publicKey.match(/^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})$/);
  if (!match) throw Error("Recovery host key must be Ed25519");
  const bytes = Uint8Array.from(atob(match[1]), (c) => c.charCodeAt(0));
  const view = new DataView(bytes.buffer);
  if (
    bytes.length !== 51 || btoa(String.fromCharCode(...bytes)) !== match[1] ||
    view.getUint32(0) !== 11 ||
    new TextDecoder().decode(bytes.slice(4, 15)) !== "ssh-ed25519" ||
    view.getUint32(15) !== 32
  ) throw Error("Recovery host key is malformed");
  return "SHA256:" +
    createHash("sha256").update(bytes).digest("base64").replace(/=+$/, "");
}
/** The manifest path is produced by the bootstrap/isolation stage. This only
 * emits a public key already present on the guest; it creates no key or user.
 * Marker output goes to the OCI AArch64 serial device (ttyAMA0), never the
 * active console: the rescue console=ttyAMA0 precedes console=tty0, so
 * /dev/console can resolve to a graphical tty and the marker must reach OCI
 * serial history regardless of the active console device.
 */
export function hostKeyConsoleCommand(
  requestId: string,
  phase: RecoveryBootPhase,
): string {
  if (!REQUEST.test(requestId) || !PHASES.includes(phase)) {
    throw Error("Invalid recovery host-key marker identity");
  }
  const manifest = phase === "loader"
    ? "-"
    : "$(sha256sum /etc/uos-rescue/manifest.json | cut -d' ' -f1)";
  return `test -f /etc/ssh/ssh_host_ed25519_key.pub
printf '\\nUOS_RECOVERY_HOST_KEY %s %s %s %s %s\\n' ${shellQuote(requestId)} ${
    shellQuote(phase)
  } "$(cat /proc/sys/kernel/random/boot_id)" "${manifest}" "$(awk '{print $1 \" \" $2}' /etc/ssh/ssh_host_ed25519_key.pub)" >/dev/ttyAMA0`;
}
export function verifyConsoleHostKey(
  metadata: JsonRecord,
  content: string,
  expected: ConsoleHostExpectation,
  now = Date.now(),
): VerifiedRecoveryHost {
  const created = Date.parse(String(metadata["time-created"]));
  const notBefore = Date.parse(expected.notBeforeUtc);
  if (
    !REQUEST.test(expected.requestId) || !PHASES.includes(expected.phase) ||
    !/^ocid1\.instance\.[a-zA-Z0-9.]+$/.test(expected.instanceId) ||
    metadata["instance-id"] !== expected.instanceId ||
    metadata["lifecycle-state"] !== "SUCCEEDED" ||
    typeof metadata.id !== "string" ||
    !/^ocid1\.consolehistory\.[a-zA-Z0-9.]+$/.test(metadata.id) ||
    !Number.isFinite(created) || !Number.isFinite(notBefore) ||
    created < notBefore || created > now ||
    new TextEncoder().encode(content).length > LIMIT ||
    expected.phase !== "loader" &&
      !/^[0-9a-f]{64}$/.test(expected.manifestSha256 ?? "")
  ) {
    throw Error(
      "Console evidence is stale, incomplete or bound to another instance",
    );
  }
  const matches = new Map<string, string[]>();
  for (const line of content.replaceAll("\r", "").split("\n")) {
    const fields = line.trim().split(/\s+/);
    if (
      fields[0] !== "UOS_RECOVERY_HOST_KEY" ||
      fields[1] !== expected.requestId || fields[2] !== expected.phase
    ) continue;
    if (fields.length !== 7 || !UUID.test(fields[3])) {
      throw Error("Malformed recovery console marker");
    }
    if (expected.expectedBootId && fields[3] !== expected.expectedBootId) {
      continue;
    }
    matches.set(fields.join(" "), fields);
  }
  if (matches.size !== 1) {
    throw Error("Recovery console marker is absent or ambiguous");
  }
  const fields = [...matches.values()][0];
  if (
    fields[3] === expected.previousBootId ||
    fields[4] !== (expected.phase === "loader" ? "-" : expected.manifestSha256)
  ) {
    throw Error(
      "Recovery boot or manifest does not match the expected transition",
    );
  }
  const publicKey = fields.slice(5).join(" ");
  return {
    requestId: expected.requestId,
    instanceId: expected.instanceId,
    phase: expected.phase,
    bootId: fields[3],
    manifestSha256: fields[4] === "-" ? null : fields[4],
    publicKey,
    fingerprint: publicKeyFingerprint(publicKey),
    consoleHistoryId: metadata.id,
    consoleCapturedAtUtc: String(metadata["time-created"]),
  };
}
function hostAlias(host: VerifiedRecoveryHost): string {
  if (
    !REQUEST.test(host.requestId) || !UUID.test(host.bootId) ||
    !PHASES.includes(host.phase) ||
    publicKeyFingerprint(host.publicKey) !== host.fingerprint
  ) throw Error("Recovery SSH host receipt is invalid");
  return `${host.requestId}-${host.phase}-${host.bootId}`;
}
export interface RecoverySshTarget {
  host: VerifiedRecoveryHost;
  address: string;
  knownHostsPath: string;
}
/** Task-owned known-host file; never edits the user's global SSH configuration.
 * Call from the Pi controller directory while holding its existing lock.
 */
export async function retainRecoveryHost(
  host: VerifiedRecoveryHost,
  address: string,
): Promise<RecoverySshTarget> {
  assertPublicAddress(address);
  const alias = hostAlias(host);
  const directory = ".private/recovery-known-hosts";
  await Deno.mkdir(directory, { recursive: true, mode: 0o700 });
  const dir = await Deno.lstat(directory);
  if (!dir.isDirectory || dir.isSymlink || (dir.mode! & 0o077) !== 0) {
    throw Error("Recovery known-host directory is not private");
  }
  const path = `${directory}/${alias}`;
  const content = `${alias} ${host.publicKey}\n`;
  try {
    using file = await Deno.open(path, {
      createNew: true,
      write: true,
      mode: 0o600,
    });
    const bytes = new TextEncoder().encode(content);
    let offset = 0;
    while (offset < bytes.length) {
      offset += await file.write(bytes.subarray(offset));
    }
    await file.sync();
    using parent = await Deno.open(directory, { read: true });
    await parent.sync();
  } catch (error) {
    if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
  }
  const stat = await Deno.lstat(path);
  if (
    !stat.isFile || stat.isSymlink || (stat.mode! & 0o077) !== 0 ||
    await Deno.readTextFile(path) !== content
  ) throw Error("Recovery known-host file changed");
  return {
    host: structuredClone(host),
    address,
    knownHostsPath: await Deno.realPath(path),
  };
}
function assertPublicAddress(address: string) {
  const octets = address.split(".").map(Number);
  if (
    !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(address) ||
    octets.some((n) => n < 0 || n > 255) ||
    octets.map(String).join(".") !== address ||
    [0, 10, 127].includes(octets[0]) || octets[0] >= 224 ||
    octets[0] === 169 && octets[1] === 254 ||
    octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 ||
    octets[0] === 192 && octets[1] === 168
  ) throw Error("Recovery SSH requires the provider-bound public IPv4 address");
}
export function recoverySshArgs(
  target: RecoverySshTarget,
  command: string,
  args: string[] = [],
): string[] {
  assertPublicAddress(target.address);
  const alias = hostAlias(target.host);
  if (
    !target.knownHostsPath.startsWith("/") ||
    /[\r\n\0]/.test(target.knownHostsPath) ||
    !target.knownHostsPath.endsWith(`/recovery-known-hosts/${alias}`) ||
    !command || [command, ...args].some((v) => v.includes("\0"))
  ) throw Error("Recovery SSH target or command is invalid");
  return [
    "-F",
    "/dev/null",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-i",
    "/home/pi/.ssh/id_ed25519",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${target.knownHostsPath}`,
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    `HostKeyAlias=${alias}`,
    "-o",
    "HostKeyAlgorithms=ssh-ed25519",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=2",
    `codex@${target.address}`,
    [command, ...args].map(shellQuote).join(" "),
  ];
}

/** Each invocation owns just the child it starts. A timeout or excess output
 * terminates that SSH child, never a shared terminal or another agent's process.
 */
export const recoveryControlRunner: CommandRunner = async (command, args) => {
  const child = new Deno.Command(command, {
    args,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  let stopped = false;
  let finished = false;
  let forceTimer: ReturnType<typeof setTimeout> | undefined;
  const status = child.status.then((value) => {
    finished = true;
    return value;
  });
  const signal = (value: "SIGTERM" | "SIGKILL") => {
    if (finished) return;
    try {
      child.kill(value);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  };
  const stop = () => {
    if (stopped || finished) return;
    stopped = true;
    signal("SIGTERM");
    forceTimer = setTimeout(() => signal("SIGKILL"), 1000);
  };
  const timer = setTimeout(stop, 60_000);
  const collect = async (stream: ReadableStream<Uint8Array>) => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for await (const bytes of stream) {
      total += bytes.length;
      if (total > LIMIT) {
        stop();
        throw Error("Recovery control output exceeds the control bound");
      }
      chunks.push(bytes);
    }
    const result = new Uint8Array(total);
    let offset = 0;
    for (const bytes of chunks) {
      result.set(bytes, offset);
      offset += bytes.length;
    }
    return new TextDecoder().decode(result);
  };
  try {
    const results = await Promise.allSettled([
      collect(child.stdout),
      collect(child.stderr),
      status,
    ]);
    if (stopped || results.some((r) => r.status !== "fulfilled")) {
      throw Error("Recovery control command failed or timed out");
    }
    return {
      code:
        (results[2] as PromiseFulfilledResult<Deno.CommandStatus>).value.code,
      stdout: (results[0] as PromiseFulfilledResult<string>).value,
      stderr: (results[1] as PromiseFulfilledResult<string>).value,
    };
  } finally {
    clearTimeout(timer);
    clearTimeout(forceTimer);
  }
};

export function recoverySshRunner(target: RecoverySshTarget): CommandRunner {
  return (command, args) =>
    recoveryControlRunner("ssh", recoverySshArgs(target, command, args));
}
