// Pure async process fakes preserve the native capability signatures.
// deno-lint-ignore-file require-await
import assert, { deepEqual, rejects } from "node:assert/strict";
import { makeStreamDecryptArchive } from "../scripts/backblaze-file-backup.ts";
import {
  type BackupV2DecryptProcessRegistry,
  spawnBackupV2GpgDecrypt,
} from "../scripts/backup-v2-decrypt.ts";
import type { BackupV2NativeChild } from "../scripts/backup-v2-native-custody.ts";

const encoder = new TextEncoder(), decoder = new TextDecoder();
const identity: BackupV2NativeChild = {
  pid: 100,
  startTicks: "123",
  bootId: "00000000-0000-4000-8000-000000000001",
  cgroup: "/fixture",
  kind: "sudo-gpg",
};
function bytes(text: string) {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(text));
      controller.close();
    },
  });
}
async function text(stream: ReadableStream<Uint8Array>) {
  let result = "";
  for await (const part of stream) result += decoder.decode(part);
  return result;
}
function fixture(
  options: {
    uid?: number;
    rejectRegistration?: boolean;
    missingExit?: boolean;
    outerCode?: number;
    trailing?: string;
    corruptAck?: boolean;
  } = {},
) {
  const events: string[] = [], payload: string[] = [];
  let release!: () => void;
  const durable = new Promise<void>((resolve) => release = resolve);
  const status = {
    success: (options.outerCode ?? 0) === 0,
    code: options.outerCode ?? 0,
    signal: null,
  };
  const registry: BackupV2DecryptProcessRegistry = {
    async spawn(kind, command, args, commandOptions) {
      assert(kind === "sudo-gpg" && command === "sudo");
      deepEqual(args.slice(0, 6), [
        "-n",
        "-u",
        "codex",
        "/usr/bin/bash",
        "--noprofile",
        "--norc",
      ]);
      assert(commandOptions?.cwd === "/");
      const nonce = args[args.indexOf("backup-v2-sudo-gpg") + 1];
      let stderr!: ReadableStreamDefaultController<Uint8Array>;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          stderr = controller;
          const message = `B2_GPG_PID:${nonce}:200:${options.uid ?? 1002}\n`;
          controller.enqueue(encoder.encode(message.slice(0, 9)));
          controller.enqueue(encoder.encode(message.slice(9)));
        },
      });
      let started = false;
      return {
        pid: 100,
        identity,
        kill() {},
        status: Promise.resolve(status),
        stdin: new WritableStream<Uint8Array>({
          write(part) {
            if (!started) {
              assert(events.includes("durable"));
              assert(decoder.decode(part) === `B2_GPG_START:${nonce}\n`);
              started = true;
              events.push("start");
              stderr.enqueue(
                encoder.encode(
                  `B2_GPG_ACK:${options.corruptAck ? "wrong" : nonce}\n`,
                ),
              );
            } else payload.push(decoder.decode(part));
          },
          close() {
            stderr.enqueue(
              encoder.encode("[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n"),
            );
            if (!options.missingExit) {
              stderr.enqueue(encoder.encode(`B2_GPG_EXIT:${nonce}:0\n`));
            }
            if (options.trailing) {
              stderr.enqueue(encoder.encode(options.trailing));
            }
            stderr.close();
          },
          abort() {
            events.push("aborted");
          },
        }),
        stdout: bytes("plaintext"),
        stderr: stream,
      };
    },
    async registerChild(pid, kind) {
      assert(pid === 200 && kind === "gpg");
      events.push("register");
      if (options.rejectRegistration) throw new Error("journal unavailable");
      await durable;
      events.push("durable");
      return {
        identity: { ...identity, pid, kind },
        exit(status) {
          events.push(`exit:${status.code}`);
          return Promise.resolve();
        },
      };
    },
  };
  return { registry, events, payload, release };
}

Deno.test("GPG custody waits for durable post-drop PID and ACK before exposing binary stdin", async () => {
  const f = fixture(),
    pending = spawnBackupV2GpgDecrypt(f.registry, ["--decrypt"]);
  await Promise.resolve();
  await Promise.resolve();
  assert(!f.events.includes("start"));
  f.release();
  const child = await pending;
  const diagnostics = text(child.stderr), writer = child.stdin.getWriter();
  await writer.write(encoder.encode("ciphertext"));
  await writer.close();
  writer.releaseLock();
  assert((await child.status).success);
  assert((await diagnostics).includes("GOODMDC"));
  deepEqual(f.payload, ["ciphertext"]);
  deepEqual(f.events, ["register", "durable", "start", "exit:0"]);
});

Deno.test("GPG custody rejects root PID, uncertain registration and wrong ACK without payload", async () => {
  for (
    const options of [{ uid: 0 }, { rejectRegistration: true }, {
      corruptAck: true,
    }]
  ) {
    const f = fixture(options);
    f.release();
    await rejects(() => spawnBackupV2GpgDecrypt(f.registry, []));
    deepEqual(f.payload, []);
    assert(f.events.includes("aborted"));
  }
});

Deno.test("GPG custody requires final EXIT, matching outer status and clean diagnostics EOF", async () => {
  for (
    const options of [{ missingExit: true }, { outerCode: 1 }, {
      trailing: "foreign diagnostics\n",
    }]
  ) {
    const f = fixture(options);
    f.release();
    const child = await spawnBackupV2GpgDecrypt(f.registry, []);
    const diagnostics = text(child.stderr);
    diagnostics.catch(() => {});
    const writer = child.stdin.getWriter();
    await writer.close();
    writer.releaseLock();
    await rejects(() => child.status);
    await diagnostics.catch(() => {});
  }
});

Deno.test("real stream decrypt seam preserves socket and integrity checks with tracked GPG", async () => {
  const f = fixture();
  f.release();
  const original = Object.getOwnPropertyDescriptor(Deno, "readDir")!;
  const commands: string[][] = [], output: number[] = [];
  try {
    Object.defineProperty(Deno, "readDir", {
      ...original,
      value: () => ({
        async *[Symbol.asyncIterator]() {
          yield* [];
        },
      }),
    });
    const decrypt = makeStreamDecryptArchive("/fixture/public-only", {
      command(args) {
        commands.push(args);
        return Promise.resolve({
          success: true,
          stdout: encoder.encode(
            args.includes("--homedir")
              ? "/custom/socket\n"
              : "/default/socket\n",
          ),
        });
      },
      spawn: (args) => spawnBackupV2GpgDecrypt(f.registry, args),
    });
    deepEqual(
      await decrypt(bytes("ciphertext"), {
        write(part) {
          const count = Math.min(3, part.length);
          output.push(...part.subarray(0, count));
          return Promise.resolve(count);
        },
      }),
      { integrityChecked: true },
    );
    assert(decoder.decode(new Uint8Array(output)) === "plaintext");
    assert(
      commands.length === 2 &&
        commands.every((args) => args.includes("gpgconf")),
    );
    deepEqual(f.payload, ["ciphertext"]);
    assert(f.events.includes("exit:0"));
  } finally {
    Object.defineProperty(Deno, "readDir", original);
  }
});
