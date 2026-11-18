import { fileURLToPath } from "node:url";
import {
  B2CredentialError,
  type B2KeyScope,
  type B2Settings,
} from "../scripts/backblaze-storage.ts";
import { runB2CredentialChange } from "../scripts/install-b2-credential.ts";

const testRoot = "tests/.backup-test-fixtures";
const oldText = `{
  "accessKeyId": "old-fake-id",
  "secretAccessKey": "old-fake-key",
  "bucketId": "fake-bucket-id",
  "bucketName": "pavlovcik-arch-vps-backups",
  "sources": [{"role":"arch-root","fixture":["keep",17]}],
  "extra": {"arbitrary":true}
}
`;
const synthetic = {
  accessKeyId: "master-fake-id",
  secretAccessKey: "master-fake-key",
};

function equal(actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("Credential fixture assertion failed");
  }
}

async function refuses(work: Promise<unknown>, reason: string) {
  try {
    await work;
  } catch (error) {
    equal(
      error instanceof B2CredentialError
        ? error.reason
        : error instanceof Error
        ? error.message
        : undefined,
      reason,
    );
    return;
  }
  throw new Error("Expected credential change refusal");
}

async function fixture(
  work: (
    root: string,
    config: string,
    snapshot: string,
    owner: number,
  ) => Promise<void>,
) {
  await Deno.mkdir(testRoot, { recursive: true, mode: 0o700 });
  const root = await Deno.realPath(
    await Deno.makeTempDir({
      dir: testRoot,
      prefix: "r5-credential-",
    }),
  );
  try {
    await Deno.mkdir(root + "/.private", { mode: 0o700 });
    const config = root + "/.private/b2-file-backup.json";
    const snapshot = root + "/.private/b2-file-backup.rollback.json";
    await Deno.writeTextFile(config, oldText, { mode: 0o600 });
    await work(root, config, snapshot, (await Deno.stat(config)).uid!);
  } finally {
    await Deno.remove(root, { recursive: true });
  }
}

const deps = (owner: number) => ({
  owner,
  proveSourceIdle: () => Promise.resolve(),
  masterCredential: () => synthetic,
  verify: (_settings: B2Settings): Promise<B2KeyScope> =>
    Promise.resolve("unrestricted"),
});

Deno.test("installer changes only the credential, keeps private exact rollback and refuses later edits", () =>
  fixture(async (root, config, snapshot, owner) => {
    const seen: B2Settings[] = [];
    const io = {
      ...deps(owner),
      async verify(settings: B2Settings): Promise<B2KeyScope> {
        equal(await Deno.readTextFile(config), oldText);
        seen.push(settings);
        return "unrestricted";
      },
    };
    equal(
      await runB2CredentialChange(root, "install", io),
      "B2_CREDENTIAL_INSTALLED",
    );
    equal(seen, [{
      ...synthetic,
      bucketId: "fake-bucket-id",
      bucketName: "pavlovcik-arch-vps-backups",
    }]);
    const installed = await Deno.readTextFile(config);
    equal(JSON.parse(installed), { ...JSON.parse(oldText), ...synthetic });
    equal(
      JSON.parse(await Deno.readTextFile(snapshot)).previousConfig,
      oldText,
    );
    equal((await Deno.stat(config)).mode! & 0o7777, 0o600);
    equal((await Deno.stat(snapshot)).mode! & 0o7777, 0o600);
    await Deno.writeTextFile(config, installed + "\n");
    await refuses(
      runB2CredentialChange(root, "rollback", io),
      "B2_CREDENTIAL_CONFIG_CHANGED",
    );
    equal(await Deno.readTextFile(config), installed + "\n");
    await Deno.writeTextFile(config, installed);
    equal(
      await runB2CredentialChange(root, "rollback", io),
      "B2_CREDENTIAL_ROLLED_BACK",
    );
    equal(await Deno.readTextFile(config), oldText);
    equal(
      await runB2CredentialChange(root, "rollback", io),
      "B2_CREDENTIAL_ROLLED_BACK",
    );
    equal(seen.length, 1);
  }));

Deno.test("installer refuses local or source custody, empty variables and failed read-only verification before editing", () =>
  fixture(async (root, config, snapshot, owner) => {
    const io = deps(owner);
    const gate = root + "/.private/backup-controller-gate.json";
    await Deno.writeTextFile(gate, "{}", { mode: 0o600 });
    await refuses(
      runB2CredentialChange(root, "install", {
        ...io,
        proveSourceIdle: () => Promise.reject(new Error("must not run")),
      }),
      "B2_CREDENTIAL_LOCAL_CUSTODY_UNPROVED",
    );
    await Deno.remove(gate);
    await refuses(
      runB2CredentialChange(root, "install", {
        ...io,
        proveSourceIdle: () =>
          Promise.reject(new Error("synthetic busy source")),
      }),
      "B2_CREDENTIAL_SOURCE_CUSTODY_UNPROVED",
    );
    await refuses(
      runB2CredentialChange(root, "install", {
        ...io,
        masterCredential: () => ({}),
      }),
      "B2_CREDENTIAL_ENV_MISSING",
    );
    await refuses(
      runB2CredentialChange(root, "install", {
        ...io,
        verify: () => Promise.resolve("scoped"),
      }),
      "B2_CREDENTIAL_SCOPE_REJECTED",
    );
    await refuses(
      runB2CredentialChange(root, "install", {
        ...io,
        verify: () =>
          Promise.reject(
            new B2CredentialError(
              "B2_BUCKET_IDENTITY_MISMATCH",
              "synthetic bucket differs",
            ),
          ),
      }),
      "B2_BUCKET_IDENTITY_MISMATCH",
    );
    equal(await Deno.readTextFile(config), oldText);
    let missing = false;
    try {
      await Deno.stat(snapshot);
    } catch (error) {
      missing = error instanceof Deno.errors.NotFound;
    }
    equal(missing, true);
  }));

const bash = "/usr/bin/bash";
const native =
  (await Deno.permissions.query({ name: "run", command: bash })).state ===
    "granted";
Deno.test({
  name: "installer rejects non-Pi execution and takes the existing kernel lock",
  ignore: !native,
  fn: () =>
    fixture(async (root, config) => {
      const script = fileURLToPath(
        new URL(
          "../config/backup-repair/install-b2-credential.sh",
          import.meta.url,
        ),
      );
      const shell = (args: string[]) =>
        new Deno.Command(bash, {
          args: ["--noprofile", "--norc", ...args],
          cwd: root,
          clearEnv: true,
          env: {
            PATH: "/usr/bin:/bin",
            BACKBLAZE_MASTER_KEY_ID: synthetic.accessKeyId,
            BACKBLAZE_MASTER_KEY: synthetic.secretAccessKey,
          },
        }).output();
      const refused = await shell(["-x", script, "install"]);
      equal(refused.code, 1);
      equal(new TextDecoder().decode(refused.stdout), "");
      equal(
        new TextDecoder().decode(refused.stderr).trim().split("\n").at(-1),
        "B2_CREDENTIAL_CONTROLLER_DIRECTORY_UNPROVED",
      );
      const lockPath = root + "/.private/backup-controller.lock";
      using lock = await Deno.open(lockPath, {
        createNew: true,
        write: true,
        mode: 0o600,
      });
      await lock.lock(true);
      const lockOnly = [
        "-c",
        'source "$1"; take_b2_controller_lock',
        "_",
        script,
      ];
      const busy = await shell(lockOnly);
      equal(busy.code, 1);
      equal(
        new TextDecoder().decode(busy.stderr).trim(),
        "B2_CREDENTIAL_CONTROLLER_LOCK_BUSY",
      );
      await lock.unlock();
      equal((await shell(lockOnly)).code, 0);
      equal(await Deno.readTextFile(config), oldText);
    }),
});
