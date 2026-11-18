import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import {
  B2CredentialError,
  type B2KeyScope,
  type B2Settings,
  b2SettingsFromConfig,
} from "./backblaze-storage.ts";
import {
  B2_CONFIG_PATH,
  CONTROLLER_STATE_PATH,
  GATE_PATH,
  MANIFEST_PATH,
  PI_CONTROLLER_CWD,
  proveBackblazeSourceIdle,
  realRemoteRunner,
  realRemoteSeam,
  validateControllerState,
} from "./backblaze-file-backup.ts";
import {
  backupV2RetentionNeedsReconcile,
  readBackupV2RetentionControl,
  validateBackupV2ControllerState,
} from "./backup-v2-controller.ts";
import { assertBackblazeLaunchAllowed } from "./backblaze-controller-contract.ts";
import { BackupV2Store } from "./backup-v2-store.ts";

const snapshotPath = ".private/b2-file-backup.rollback.json";
const maximumConfigBytes = 64 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

type Action = "install" | "rollback";
type ChangeFailure =
  | "B2_CREDENTIAL_LOCAL_CUSTODY_UNPROVED"
  | "B2_CREDENTIAL_SOURCE_CUSTODY_UNPROVED"
  | "B2_CREDENTIAL_ENV_MISSING"
  | "B2_CREDENTIAL_SCOPE_REJECTED"
  | "B2_CREDENTIAL_ROLLBACK_MISSING"
  | "B2_CREDENTIAL_CONFIG_CHANGED"
  | "B2_CREDENTIAL_PERSISTENCE_UNPROVED";

class ChangeError extends Error {
  constructor(readonly reason: ChangeFailure) {
    super(reason);
  }
}

function fail(reason: ChangeFailure): never {
  throw new ChangeError(reason);
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseObject(text: string): Record<string, unknown> {
  const value: unknown = JSON.parse(text.replace(/^\uFEFF/u, ""));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
  }
  return value as Record<string, unknown>;
}

async function lstatOptional(path: string): Promise<Deno.FileInfo | undefined> {
  try {
    return await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return undefined;
    throw error;
  }
}

async function readPrivate(
  path: string,
  owner: number,
  maximum: number,
): Promise<Uint8Array | undefined> {
  const before = await lstatOptional(path);
  if (!before) return undefined;
  if (
    !before.isFile || before.uid !== owner || before.nlink !== 1 ||
    before.mode === null || (before.mode & 0o7777) !== 0o600 ||
    before.size <= 0 || before.size > maximum ||
    await Deno.realPath(path) !== path
  ) fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
  using file = await Deno.open(path, { read: true });
  const opened = await file.stat();
  if (
    opened.dev !== before.dev || opened.ino !== before.ino ||
    opened.size !== before.size || opened.uid !== before.uid ||
    opened.mode !== before.mode || opened.nlink !== 1
  ) fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
  const bytes = new Uint8Array(before.size);
  for (let offset = 0; offset < bytes.length;) {
    const count = await file.read(bytes.subarray(offset));
    if (!count) fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
    offset += count;
  }
  const after = await file.stat();
  if (
    after.size !== opened.size ||
    after.mtime?.getTime() !== opened.mtime?.getTime() ||
    after.ctime?.getTime() !== opened.ctime?.getTime()
  ) fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
  return bytes;
}

async function writePrivateAtomic(
  path: string,
  bytes: Uint8Array,
): Promise<void> {
  const parent = dirname(path);
  const temporary = await Deno.makeTempFile({
    dir: parent,
    prefix: ".b2-credential-",
  });
  try {
    await Deno.writeFile(temporary, bytes, { mode: 0o600 });
    {
      using file = await Deno.open(temporary, { read: true, write: true });
      await file.sync();
    }
    await Deno.rename(temporary, path);
    using directory = await Deno.open(parent, { read: true });
    await directory.sync();
  } finally {
    await Deno.remove(temporary).catch((error) => {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    });
  }
}

async function proveLocalIdle(root: string, owner: number): Promise<void> {
  const read = async <T>(path: string): Promise<T | undefined> => {
    const bytes = await readPrivate(
      resolve(root, path),
      owner,
      16 * 1024 * 1024,
    );
    return bytes === undefined ? undefined : JSON.parse(decoder.decode(bytes));
  };
  try {
    if (await lstatOptional(resolve(root, GATE_PATH))) {
      fail("B2_CREDENTIAL_LOCAL_CUSTODY_UNPROVED");
    }
    const oracle = await read(".private/backup-runtime.json");
    const claim = await read(MANIFEST_PATH);
    if (oracle !== undefined || claim !== undefined) {
      assertBackblazeLaunchAllowed(oracle, claim);
    }
    const state = await read<{ schemaVersion?: unknown }>(
      CONTROLLER_STATE_PATH,
    );
    if (state !== undefined) {
      const states = state?.schemaVersion === 1
        ? [validateControllerState(state)]
        : (() => {
          const current = validateBackupV2ControllerState(state);
          return [current, current.legacy];
        })();
      if (
        states.some(({ job }) =>
          job && !["COMPLETE", "FAILED"].includes(job.phase)
        )
      ) fail("B2_CREDENTIAL_LOCAL_CUSTODY_UNPROVED");
    }
    for (const catalogOnly of [false, true]) {
      const control = await readBackupV2RetentionControl({ read }, catalogOnly);
      if (control && backupV2RetentionNeedsReconcile(control)) {
        fail("B2_CREDENTIAL_LOCAL_CUSTODY_UNPROVED");
      }
    }
  } catch {
    fail("B2_CREDENTIAL_LOCAL_CUSTODY_UNPROVED");
  }
}

interface CredentialInstallerDeps {
  owner: number;
  proveSourceIdle(): Promise<void>;
  masterCredential(): { accessKeyId?: string; secretAccessKey?: string };
  verify(settings: B2Settings): Promise<B2KeyScope>;
}

/** The operator wrapper holds the existing controller flock for the entire change. */
export async function runB2CredentialChange(
  root: string,
  action: Action,
  deps: CredentialInstallerDeps,
): Promise<string> {
  const { owner } = deps;
  const privateDir = resolve(root, ".private");
  const directory = await Deno.lstat(privateDir);
  if (
    !directory.isDirectory || directory.uid !== owner ||
    directory.mode === null || (directory.mode & 0o7777) !== 0o700 ||
    await Deno.realPath(privateDir) !== privateDir
  ) fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
  await proveLocalIdle(root, owner);
  try {
    await deps.proveSourceIdle();
  } catch {
    fail("B2_CREDENTIAL_SOURCE_CUSTODY_UNPROVED");
  }
  const config = resolve(root, B2_CONFIG_PATH);
  const snapshot = resolve(root, snapshotPath);
  const previous = await readPrivate(config, owner, maximumConfigBytes);
  if (!previous) fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
  const oldText = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
    .decode(previous);
  const old = parseObject(oldText);
  const priorCredentials = b2SettingsFromConfig(old);
  const saved = await readPrivate(snapshot, owner, 4 * maximumConfigBytes);
  const assertUnchanged = async () => {
    await proveLocalIdle(root, owner);
    const current = await readPrivate(config, owner, maximumConfigBytes);
    if (!current || digest(current) !== digest(previous)) {
      fail("B2_CREDENTIAL_CONFIG_CHANGED");
    }
  };
  if (action === "rollback") {
    if (!saved) fail("B2_CREDENTIAL_ROLLBACK_MISSING");
    const record = parseObject(decoder.decode(saved));
    if (
      Object.keys(record).length !== 2 ||
      typeof record.previousConfig !== "string" ||
      typeof record.installedSha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(record.installedSha256)
    ) fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
    const restored = encoder.encode(record.previousConfig);
    if (restored.length > maximumConfigBytes) {
      fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
    }
    b2SettingsFromConfig(parseObject(record.previousConfig));
    if (digest(previous) === digest(restored)) {
      return "B2_CREDENTIAL_ROLLED_BACK";
    }
    if (digest(previous) !== record.installedSha256) {
      fail("B2_CREDENTIAL_CONFIG_CHANGED");
    }
    await assertUnchanged();
    await writePrivateAtomic(config, restored);
    return "B2_CREDENTIAL_ROLLED_BACK";
  }
  const { accessKeyId, secretAccessKey } = deps.masterCredential();
  if (!accessKeyId || !secretAccessKey) fail("B2_CREDENTIAL_ENV_MISSING");
  const candidate = { ...old, accessKeyId, secretAccessKey };
  const settings = b2SettingsFromConfig(candidate);
  if (await deps.verify(settings) !== "unrestricted") {
    fail("B2_CREDENTIAL_SCOPE_REJECTED");
  }
  await assertUnchanged();
  if (
    accessKeyId === priorCredentials.accessKeyId &&
    secretAccessKey === priorCredentials.secretAccessKey
  ) return "B2_CREDENTIAL_INSTALLED";
  const replacement = encoder.encode(JSON.stringify(candidate, null, 2) + "\n");
  if (replacement.length > maximumConfigBytes) {
    fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
  }
  await writePrivateAtomic(
    snapshot,
    encoder.encode(
      JSON.stringify({
        previousConfig: oldText,
        installedSha256: digest(replacement),
      }) + "\n",
    ),
  );
  await assertUnchanged();
  await writePrivateAtomic(config, replacement);
  return "B2_CREDENTIAL_INSTALLED";
}

if (import.meta.main) {
  const [action] = Deno.args;
  try {
    if (action !== "install" && action !== "rollback") {
      fail("B2_CREDENTIAL_PERSISTENCE_UNPROVED");
    }
    const owner = Deno.uid();
    if (
      owner === null || owner === 0 ||
      await Deno.realPath(".") !== PI_CONTROLLER_CWD
    ) fail("B2_CREDENTIAL_LOCAL_CUSTODY_UNPROVED");
    console.log(
      await runB2CredentialChange(Deno.cwd(), action, {
        owner,
        proveSourceIdle: () =>
          proveBackblazeSourceIdle(realRemoteSeam(realRemoteRunner)),
        masterCredential: () => ({
          accessKeyId: Deno.env.get("BACKBLAZE_MASTER_KEY_ID"),
          secretAccessKey: Deno.env.get("BACKBLAZE_MASTER_KEY"),
        }),
        verify: (settings) =>
          new BackupV2Store(settings).verifyCredential(
            AbortSignal.timeout(20_000),
          ),
      }),
    );
  } catch (error) {
    console.error(
      error instanceof B2CredentialError || error instanceof ChangeError
        ? error.reason
        : "B2_CREDENTIAL_PERSISTENCE_UNPROVED",
    );
    Deno.exitCode = 1;
  }
}
