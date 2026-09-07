/** Pi-owned prerequisite for OCI console history. This creates no instance,
 * disk, IP or backup and never connects to the console or handles private keys.
 * The session holds the controller lock and rechecks ownership before CREATE.
 */
import { createHash } from "node:crypto";
import { dataArray, dataObject, type JsonRecord } from "./oci.ts";

const OPERATION =
  "create one tagged console connection on the bound replacement using the specified existing RSA public key";
const digest = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
export interface ConsoleConnectionPlan {
  requestId: string;
  instanceId: string;
  compartmentId: string;
  publicKeySha256: string;
  operation: typeof OPERATION;
  planSha256: string;
}
export interface ConsoleConnectionApproval {
  planSha256: string;
  exactOperation: string;
  approvedAtUtc: string;
}
export interface ConsoleConnectionState {
  planSha256: string;
  intendedAtUtc?: string;
  connectionId?: string;
}
export interface ConsoleConnectionPorts {
  json: (args: string[]) => Promise<JsonRecord>;
  beforeMutation: () => Promise<void>;
  approval: () => Promise<ConsoleConnectionApproval | undefined>;
  persist: (state: ConsoleConnectionState) => Promise<void>;
  now: () => number;
}

/** Oracle documents RSA for local console connections. Do not silently reuse
 * the separate Ed25519 guest bootstrap key or generate another credential. */
function rsaPublicKey(value: string): string {
  const match = typeof value === "string" && value.length <= 16384
    ? value.trim().match(/^ssh-rsa ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]+)?$/)
    : null;
  if (!match) throw Error("An existing RSA console public key is required");
  const bytes = Uint8Array.from(atob(match[1]), (c) => c.charCodeAt(0));
  if (btoa(String.fromCharCode(...bytes)) !== match[1]) {
    throw Error("Console public key encoding differs");
  }
  const view = new DataView(bytes.buffer);
  let offset = 0;
  const field = () => {
    if (offset + 4 > bytes.length) throw Error("Truncated console public key");
    const length = view.getUint32(offset);
    offset += 4;
    if (length < 1 || offset + length > bytes.length) {
      throw Error("Malformed console public key");
    }
    const part = bytes.slice(offset, offset + length);
    offset += length;
    return part;
  };
  const algorithm = new TextDecoder().decode(field());
  const exponent = field();
  const rawModulus = field();
  const positiveCanonical = (part: Uint8Array) =>
    part[0] < 128 &&
    (part[0] !== 0 || (part.length > 1 && part[1] >= 128));
  const exponentValue = exponent.length <= 8
    ? exponent.reduce((result, byte) => (result << 8n) | BigInt(byte), 0n)
    : 0n;
  const modulus = rawModulus[0] === 0 ? rawModulus.slice(1) : rawModulus;
  const bits = modulus.length === 0
    ? 0
    : (modulus.length - 1) * 8 + 32 - Math.clz32(modulus[0]);
  if (
    algorithm !== "ssh-rsa" || offset !== bytes.length ||
    !positiveCanonical(exponent) || !positiveCanonical(rawModulus) ||
    exponentValue < 3n || (exponentValue & 1n) !== 1n ||
    bits < 2048 || bits > 8192 || (modulus.at(-1)! & 1) !== 1
  ) throw Error("Console public key is not a supported positive RSA key");
  return `ssh-rsa ${match[1]}`;
}
export function consoleConnectionPlan(
  requestId: string,
  instanceId: string,
  compartmentId: string,
  publicKey: string,
): ConsoleConnectionPlan {
  if (
    !/^recovery-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(requestId) ||
    !/^ocid1\.instance\.[a-zA-Z0-9.]+$/.test(instanceId) ||
    !/^ocid1\.(?:compartment|tenancy)\.[a-zA-Z0-9.]+$/.test(compartmentId)
  ) throw Error("Console connection target is malformed");
  const body = {
    requestId,
    instanceId,
    compartmentId,
    publicKeySha256: digest(rsaPublicKey(publicKey)),
    operation: OPERATION as typeof OPERATION,
  };
  return { ...body, planSha256: digest(body) };
}
function assertApproval(
  plan: ConsoleConnectionPlan,
  approval: ConsoleConnectionApproval | undefined,
  now: number,
) {
  const age = now - Date.parse(approval?.approvedAtUtc ?? "");
  if (
    !approval || approval.planSha256 !== plan.planSha256 ||
    approval.exactOperation !== OPERATION ||
    !Number.isFinite(age) || age < 0 || age > 3600000
  ) throw Error("Current exact console-connection approval is required");
}
async function retainPublicKey(
  plan: ConsoleConnectionPlan,
  publicKey: string,
): Promise<string> {
  const directory = ".private/recovery-console";
  await Deno.mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await Deno.lstat(directory);
  if (!info.isDirectory || info.isSymlink || (info.mode! & 0o077) !== 0) {
    throw Error("Console key directory is not private");
  }
  const path = `${directory}/${plan.planSha256}.pub`;
  const content = rsaPublicKey(publicKey) + "\n";
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
  const fileInfo = await Deno.lstat(path);
  if (
    !fileInfo.isFile || fileInfo.isSymlink || (fileInfo.mode! & 0o077) !== 0 ||
    await Deno.readTextFile(path) !== content
  ) {
    throw Error("Retained console public key differs");
  }
  return await Deno.realPath(path);
}
function owned(plan: ConsoleConnectionPlan, item: JsonRecord): boolean {
  const tags = item["freeform-tags"] as JsonRecord | undefined;
  return item["instance-id"] === plan.instanceId &&
    item["compartment-id"] === plan.compartmentId &&
    tags?.uosRecoveryRequest === plan.requestId &&
    tags?.uosRecoveryConsoleConnection === plan.planSha256;
}
function identity(plan: ConsoleConnectionPlan, item: JsonRecord): string {
  if (
    !owned(plan, item) || typeof item.id !== "string" ||
    !/^ocid1\.instanceconsoleconnection\.[a-zA-Z0-9.]+$/.test(item.id)
  ) {
    throw Error("Console connection is not bound to the approved request");
  }
  return item.id;
}

/** A missing response is reconciled by exact tags; no match or ambiguity never
 * triggers another CREATE. Existing unowned connections are preserved. */
export async function stepConsoleConnection(
  plan: ConsoleConnectionPlan,
  publicKey: string,
  state: ConsoleConnectionState,
  ports: ConsoleConnectionPorts,
): Promise<
  | "CONSOLE_CONNECTION_ACTIVE"
  | "CONSOLE_CONNECTION_PENDING"
  | "CONSOLE_CONNECTION_APPROVAL_REQUIRED"
> {
  if (
    consoleConnectionPlan(
        plan.requestId,
        plan.instanceId,
        plan.compartmentId,
        publicKey,
      ).planSha256 !== plan.planSha256 ||
    plan.operation !== OPERATION ||
    plan.publicKeySha256 !== digest(rsaPublicKey(publicKey)) ||
    state.planSha256 !== plan.planSha256 ||
    (state.connectionId !== undefined && !state.intendedAtUtc) ||
    (state.intendedAtUtc !== undefined &&
      !Number.isFinite(Date.parse(state.intendedAtUtc)))
  ) throw Error("Console connection plan or journal changed");
  const list = async () =>
    dataArray(
      await ports.json([
        "compute",
        "instance-console-connection",
        "list",
        "--compartment-id",
        plan.compartmentId,
        "--instance-id",
        plan.instanceId,
        "--all",
      ]),
    );
  if (!state.connectionId) {
    const existing = await list();
    const matching = existing.filter((item) => owned(plan, item));
    if (state.intendedAtUtc) {
      if (matching.length !== 1) {
        throw Error(
          "Uncertain console CREATE requires reconciliation; no duplicate is permitted",
        );
      }
      state.connectionId = identity(plan, matching[0]);
      await ports.persist(structuredClone(state));
    } else {
      if (existing.some((item) => item["lifecycle-state"] !== "DELETED")) {
        throw Error(
          "Existing console connection requires reconciliation; preserve it",
        );
      }
      const approval = await ports.approval();
      if (!approval) return "CONSOLE_CONNECTION_APPROVAL_REQUIRED";
      assertApproval(plan, approval, ports.now());
      await ports.beforeMutation();
      const path = await retainPublicKey(plan, publicKey);
      if (
        (await list()).some((item) => item["lifecycle-state"] !== "DELETED")
      ) throw Error("Console connection appeared before CREATE");
      state.intendedAtUtc = new Date(ports.now()).toISOString();
      await ports.persist(structuredClone(state));
      await ports.beforeMutation();
      assertApproval(plan, await ports.approval(), ports.now());
      if (await retainPublicKey(plan, publicKey) !== path) {
        throw Error("Console public key path changed before CREATE");
      }
      const created = dataObject(
        await ports.json([
          "compute",
          "instance-console-connection",
          "create",
          "--instance-id",
          plan.instanceId,
          "--ssh-public-key-file",
          path,
          "--freeform-tags",
          JSON.stringify({
            uosRecoveryRequest: plan.requestId,
            uosRecoveryConsoleConnection: plan.planSha256,
          }),
        ]),
      );
      state.connectionId = identity(plan, created);
      await ports.persist(structuredClone(state));
    }
  }
  const observed = dataObject(
    await ports.json([
      "compute",
      "instance-console-connection",
      "get",
      "--instance-console-connection-id",
      state.connectionId!,
    ]),
  );
  if (identity(plan, observed) !== state.connectionId) {
    throw Error("Retained console connection changed");
  }
  if (observed["lifecycle-state"] === "ACTIVE") {
    return "CONSOLE_CONNECTION_ACTIVE";
  }
  if (observed["lifecycle-state"] === "CREATING") {
    return "CONSOLE_CONNECTION_PENDING";
  }
  throw Error(
    "Console connection did not become active; preserve its identity",
  );
}
