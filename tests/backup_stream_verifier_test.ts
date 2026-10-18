import assert, {
  deepEqual as assertEquals,
  rejects as assertRejects,
} from "node:assert/strict";
import { createHash } from "node:crypto";
import { BACKUP_V2_LIMITS } from "../scripts/backup-v2-profile.ts";
import {
  type BackupStreamProcess,
  fanoutBackupStream,
  verifyBackupStreamArchive,
} from "../scripts/backup-stream-verifier.ts";

const text = new TextEncoder();
const sha = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
const stream = (bytes: Uint8Array) =>
  new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(bytes);
      c.close();
    },
  });
const empty = () => stream(new Uint8Array());
function tarHeader(size: number) {
  const header = new Uint8Array(512);
  header.set(text.encode("./file"));
  header.set(text.encode(size.toString(8).padStart(11, "0") + "\0"), 124);
  header[156] = 48;
  return header;
}
function joinBytes(...parts: Uint8Array[]) {
  const result = new Uint8Array(
    parts.reduce((sum, bytes) => sum + bytes.length, 0),
  );
  let offset = 0;
  for (const bytes of parts) {
    result.set(bytes, offset);
    offset += bytes.length;
  }
  return result;
}
const payload = joinBytes(
  tarHeader(3),
  Uint8Array.of(1, 2, 3),
  new Uint8Array(509 + 1024),
);
const descriptor = {
  role: "efi" as const,
  format: "tar.zst.gpg" as const,
  ciphertextBytes: payload.length,
  ciphertextSha256: sha(payload),
  compressedPlaintext: { bytes: payload.length, sha256: sha(payload) },
};
function tools(options: { nativeCode?: number; listing?: string } = {}) {
  return (command: "tar" | "zstd"): BackupStreamProcess => {
    if (command === "zstd") {
      const pipe = new TransformStream<Uint8Array, Uint8Array>();
      return {
        stdin: pipe.writable,
        stdout: pipe.readable,
        stderr: empty(),
        status: Promise.resolve({ code: 0, success: true }),
      };
    }
    return {
      stdin: new WritableStream({ write() {} }),
      stdout: stream(
        text.encode(
          options.listing ?? '-rw-r--r-- 0/0 3 2026-01-01 00:00:00 "./file"\n',
        ),
      ),
      stderr: empty(),
      status: Promise.resolve({
        code: options.nativeCode ?? 0,
        success: !options.nativeCode,
      }),
    };
  };
}
const decrypt = async (
  cipher: ReadableStream<Uint8Array>,
  sink: { write(bytes: Uint8Array): Promise<number> },
) => {
  for await (const bytes of cipher) await sink.write(bytes);
  return { integrityChecked: true as const };
};

Deno.test("stream verifier fully binds ciphertext, compressed bytes and native inventory", async () => {
  const events: number[] = [];
  const native = tools();
  const result = await verifyBackupStreamArchive(descriptor, {
    ciphertext: () => stream(payload),
    decrypt,
    spawn(command, args) {
      if (command === "zstd") {
        assertEquals(
          args[2],
          `--memory=${BACKUP_V2_LIMITS.decoderMemoryBytes / (1024 * 1024)}MiB`,
        );
      }
      return native(command);
    },
    progress(event) {
      events.push(event.bytes);
      return Promise.resolve();
    },
  });
  assertEquals(result.proof.compressedSha256, sha(payload));
  assertEquals(result.proof.inventory?.members, 1);
  assertEquals(result.passes.length, 1);
  assert(events.length > 0);
});

Deno.test("stream verifier rejects late crypto, final hash and native status failures", async () => {
  for (
    const change of [
      {
        decrypt: async (
          cipher: ReadableStream<Uint8Array>,
          sink: { write(bytes: Uint8Array): Promise<number> },
        ) => {
          await decrypt(cipher, sink);
          throw Error("late authentication failure");
        },
      },
      { ciphertext: () => stream(payload.subarray(0, payload.length - 1)) },
      { spawn: tools({ nativeCode: 2 }) },
      { spawn: tools({ listing: "" }) },
    ]
  ) {
    await assertRejects(() =>
      verifyBackupStreamArchive(descriptor, {
        ciphertext: () => stream(payload),
        decrypt,
        spawn: tools(),
        ...change,
      })
    );
  }
  await assertRejects(() =>
    verifyBackupStreamArchive({
      ...descriptor,
      compressedPlaintext: { bytes: payload.length, sha256: "0".repeat(64) },
    }, { ciphertext: () => stream(payload), decrypt, spawn: tools() })
  );
});

Deno.test("stream verifier rejects a decrypt capability returning before input EOF", async () => {
  await assertRejects(() =>
    verifyBackupStreamArchive(descriptor, {
      ciphertext: () => stream(payload),
      spawn: tools(),
      async decrypt(_cipher, sink) {
        await sink.write(payload);
        return { integrityChecked: true };
      },
    })
  );
});

Deno.test("stream pipeline failures identify stages without exposing raw diagnostics", async () => {
  const sentinel = "private-filename-or-provider-body";
  const native = tools({ nativeCode: 2 });
  await assertRejects(() =>
    verifyBackupStreamArchive(descriptor, {
      ciphertext: () => stream(payload),
      decrypt,
      spawn(command) {
        const child = native(command);
        if (command === "tar") {
          child.stderr = stream(text.encode(`Permission denied: ${sentinel}`));
        }
        return child;
      },
    }), (error: unknown) => {
    assert(error instanceof Error);
    assert(!error.message.includes(sentinel));
    const detail = JSON.parse(error.message.slice(error.message.indexOf("{")));
    const listing = detail.children.find((item: { stage: string }) =>
      item.stage === "tar-listing"
    );
    assertEquals(listing.code, 2);
    assertEquals(listing.diagnostics.categories, ["permission"]);
    assertEquals(
      listing.diagnostics.bytes,
      text.encode(`Permission denied: ${sentinel}`).length,
    );
    assertEquals(listing.diagnostics.sha256.length, 64);
    return true;
  });
});

Deno.test("fanout applies slow-consumer backpressure and drains after failure", async () => {
  let release!: () => void, pulled = 0, consumed = 0;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const source = new ReadableStream<Uint8Array>({
    pull(c) {
      pulled++;
      if (pulled <= 3) c.enqueue(Uint8Array.of(pulled));
      else c.close();
    },
  }, { highWaterMark: 0 });
  const slow = new WritableStream<Uint8Array>({
    async write() {
      consumed++;
      if (consumed === 1) await blocked;
    },
  });
  const broken = new WritableStream<Uint8Array>({
    write() {
      throw Error("consumer failed");
    },
  });
  const result = fanoutBackupStream(
    source,
    [slow, broken],
    () => {},
    () => false,
  );
  await Promise.resolve();
  await Promise.resolve();
  assert(pulled <= 1);
  release();
  assertEquals(await result, false);
  assertEquals(consumed, 3);
  assertEquals(pulled, 4);
});

Deno.test("stream verifier recovery metadata is bounded and hash-bound", async () => {
  const bytes = text.encode('{"synthetic":true}');
  const metadata = {
    role: "recovery" as const,
    format: "json.zst.gpg" as const,
    ciphertextBytes: bytes.length,
    ciphertextSha256: sha(bytes),
  };
  const result = await verifyBackupStreamArchive(metadata, {
    ciphertext: () => stream(bytes),
    decrypt,
    spawn: tools(),
  }, { metadataSha256: sha(bytes) });
  assertEquals(result.metadata, bytes);
  await assertRejects(() =>
    verifyBackupStreamArchive(metadata, {
      ciphertext: () => stream(bytes),
      decrypt,
      spawn: tools(),
    }, { metadataSha256: "0".repeat(64) })
  );
});

const native =
  (await Deno.permissions.query({ name: "run", command: "/usr/bin/tar" }))
      .state === "granted" &&
  (await Deno.permissions.query({ name: "run", command: "/usr/bin/zstd" }))
      .state === "granted" &&
  (await Deno.permissions.query({ name: "run", command: "/usr/bin/python3" }))
      .state === "granted" &&
  (await Deno.permissions.query({ name: "write", path: ".private" })).state ===
    "granted";

async function nativeCompress(bytes: Uint8Array) {
  const child = new Deno.Command("/usr/bin/zstd", {
    args: ["-3", "-T1", "--check", "-c"],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const [_, result] = await Promise.all([
    stream(bytes).pipeTo(child.stdin),
    child.output(),
  ]);
  assert(result.success && result.stdout.length <= 16 * 1024 * 1024);
  return result.stdout;
}
async function nativeArchive(source: string, members = ["."]) {
  const result = await new Deno.Command("/usr/bin/tar", {
    args: [
      "--create",
      "--format=pax",
      "--sparse",
      "--numeric-owner",
      "--acls",
      "--xattrs",
      "--xattrs-include=*",
      "--file=-",
      "--directory",
      source,
      ...members,
    ],
    stdout: "piped",
    stderr: "piped",
  }).output();
  assert(result.success && result.stdout.length <= 16 * 1024 * 1024);
  return {
    raw: result.stdout,
    compressed: await nativeCompress(result.stdout),
  };
}

/** Execute only through the sole operator's bounded managed native-test unit. */
Deno.test({
  name: "native GNU pax sparse, arbitrary filename and stream proof",
  ignore: !native,
  async fn() {
    await Deno.mkdir(".private", { recursive: true });
    const directory = await Deno.makeTempDir({
      dir: `${Deno.cwd()}/.private`,
      prefix: "m03-native-",
    });
    try {
      const source = `${directory}/source`;
      await Deno.mkdir(source);
      await Deno.writeTextFile(`${source}/line\nbreak\\quote\"`, "synthetic");
      const file = await Deno.open(`${source}/sparse`, {
        createNew: true,
        write: true,
      });
      await file.truncate(8 * 1024 * 1024);
      await file.write(text.encode("extent"));
      file.close();
      const generated = await new Deno.Command("/usr/bin/python3", {
        args: [
          "-c",
          "import os,sys; p=os.fsencode(sys.argv[1])+b'/invalid-'+bytes([255]); f=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.write(f,b'synthetic'); os.close(f)",
          source,
        ],
        stdout: "piped",
        stderr: "piped",
      }).output();
      assert(generated.success);
      const archive = await nativeArchive(source);
      const ciphertext = archive.compressed;
      const item = {
        role: "efi" as const,
        format: "tar.zst.gpg" as const,
        ciphertextBytes: ciphertext.length,
        ciphertextSha256: sha(ciphertext),
        compressedPlaintext: {
          bytes: ciphertext.length,
          sha256: sha(ciphertext),
        },
      };
      const result = await verifyBackupStreamArchive(item, {
        ciphertext: () => stream(ciphertext),
        decrypt,
        temporaryDirectory: directory,
      });
      assertEquals(result.proof.inventory?.members, 4);
      await assertRejects(() =>
        verifyBackupStreamArchive({
          ...item,
          ciphertextSha256: sha(ciphertext.subarray(0, ciphertext.length - 1)),
          ciphertextBytes: ciphertext.length - 1,
        }, {
          ciphertext: () =>
            stream(ciphertext.subarray(0, ciphertext.length - 1)),
          decrypt,
          temporaryDirectory: directory,
        })
      );
      for (
        const raw of [
          joinBytes(archive.raw, new Uint8Array(512).fill(1)),
          joinBytes(archive.raw, archive.raw),
        ]
      ) {
        const bad = await nativeCompress(raw);
        await assertRejects(() =>
          verifyBackupStreamArchive({
            ...item,
            ciphertextBytes: bad.length,
            ciphertextSha256: sha(bad),
            compressedPlaintext: undefined,
          }, {
            ciphertext: () => stream(bad),
            decrypt,
            temporaryDirectory: directory,
          })
        );
      }
      console.log(
        JSON.stringify({
          native: "GNU pax sparse and quoted names",
          passes: result.passes.length,
          bytes: ciphertext.length,
          realGpgTested: false,
        }),
      );
    } finally {
      await Deno.remove(directory, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "native linked boot samples replay exact raw names and reject duplicates",
  ignore: !native,
  async fn() {
    await Deno.mkdir(".private", { recursive: true });
    const directory = await Deno.makeTempDir({
      dir: `${Deno.cwd()}/.private`,
      prefix: "m03-linked-",
    });
    try {
      const source = `${directory}/source`;
      await Deno.mkdir(source);
      const code =
        "import os,sys; r=os.fsencode(sys.argv[1]); os.mkdir(r+b'/images'); open(r+b'/images/kernel-'+bytes([255]),'wb').write(b'synthetic kernel'); open(r+b'/images/initrd','wb').write(b'synthetic initrd'); os.mkdir(r+b'/boot'); os.symlink(b'../images/kernel-'+bytes([255]),r+b'/boot/Image'); os.link(r+b'/images/initrd',r+b'/boot/initramfs-linux.img'); os.mkdir(r+b'/etc'); open(r+b'/etc/os-release','wb').write(b'synthetic OS'); os.symlink(b'images/kernel-'+bytes([255]),r+b'/arch-vmlinuz'); os.link(r+b'/images/initrd',r+b'/arch-initrd.img')";
      const built = await new Deno.Command("/usr/bin/python3", {
        args: ["-c", code, source],
        stdout: "piped",
        stderr: "piped",
      }).output();
      assert(built.success);
      const archive = await nativeArchive(source);
      const bytes = archive.compressed;
      const item = {
        role: "root" as const,
        format: "tar.zst.gpg" as const,
        ciphertextBytes: bytes.length,
        ciphertextSha256: sha(bytes),
      };
      const samples = [{
        role: "root" as const,
        member: text.encode("./boot/Image"),
        sha256: sha(text.encode("synthetic kernel")),
      }, {
        role: "root" as const,
        member: text.encode("./boot/initramfs-linux.img"),
        sha256: sha(text.encode("synthetic initrd")),
      }];
      const result = await verifyBackupStreamArchive(item, {
        ciphertext: () => stream(bytes),
        decrypt,
        temporaryDirectory: directory,
      }, { samples });
      assertEquals(result.samples.length, 2);
      assert(result.passes.length <= 3);
      const trusted = samples.map((sample, index) => ({
        ...sample,
        contentMember: result.samples[index].contentMember,
      }));
      const fast = await verifyBackupStreamArchive(item, {
        ciphertext: () => stream(bytes),
        decrypt,
        temporaryDirectory: directory,
      }, { samples: trusted });
      assertEquals(fast.passes.length, 1);
      const staging = await verifyBackupStreamArchive({
        ...item,
        role: "staging-boot",
      }, {
        ciphertext: () => stream(bytes),
        decrypt,
        temporaryDirectory: directory,
      }, {
        samples: [
          {
            role: "staging-boot",
            member: text.encode("./arch-vmlinuz"),
            sha256: samples[0].sha256,
          },
          {
            role: "staging-boot",
            member: text.encode("./arch-initrd.img"),
            sha256: samples[1].sha256,
          },
        ],
      });
      assertEquals(staging.samples.length + result.samples.length, 4);
      const normalizedSelection = `${directory}/normalized.nul`;
      const selectedName = result.samples[0].contentMember;
      const bareName = selectedName[0] === 46 && selectedName[1] === 47
        ? selectedName.subarray(2)
        : selectedName;
      await Deno.writeFile(
        normalizedSelection,
        joinBytes(bareName, Uint8Array.of(0)),
      );
      const probe = new Deno.Command("/usr/bin/tar", {
        args: [
          "--extract",
          "--to-stdout",
          "--file=-",
          "--no-wildcards",
          "--anchored",
          "--no-recursion",
          "--null",
          "--verbatim-files-from",
          "--no-unquote",
          `--files-from=${normalizedSelection}`,
        ],
        env: { LC_ALL: "C" },
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
      }).spawn();
      const [_, normalization] = await Promise.all([
        stream(archive.raw).pipeTo(probe.stdin),
        probe.output(),
      ]);
      const normalizedWorks = normalization.success &&
        sha(normalization.stdout) === samples[0].sha256;
      if (!normalizedWorks) {
        assert(
          normalization.code === 2 &&
            new TextDecoder().decode(normalization.stderr).includes(
              "Not found in archive",
            ),
        );
      }
      const duplicate =
        (await nativeArchive(source, [".", "./boot/Image"])).compressed;
      await assertRejects(() =>
        verifyBackupStreamArchive({
          ...item,
          ciphertextBytes: duplicate.length,
          ciphertextSha256: sha(duplicate),
        }, {
          ciphertext: () => stream(duplicate),
          decrypt,
          temporaryDirectory: directory,
        }, { samples })
      );
      console.log(
        JSON.stringify({
          native: "linked raw-byte boot samples",
          passes: result.passes.length,
          stagingPasses: staging.passes.length,
          trustedPasses: fast.passes.length,
          selectorNormalizationProved: normalizedWorks,
          realGpgTested: false,
        }),
      );
    } finally {
      await Deno.remove(directory, { recursive: true });
    }
  },
});
