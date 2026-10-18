import { createHash } from "node:crypto";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ArchiveProof,
  type BackupV2ArchiveSourceDescriptor,
  type BackupV2CiphertextFactory,
  type BackupV2DecryptStream,
  type BackupV2SampleExpectation,
} from "./backup-v2-contract.ts";
import { assertBackupV2Budget, BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";
import {
  consumeNativeTarListing,
  createTarInventory,
  createTarTerminationGuard,
  resolveTarSample,
  type TarObservation,
  tarPathKey,
} from "./backup-tar-consumers.ts";

export interface BackupStreamProcess {
  stdin: WritableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
  status: Promise<{ code: number; success: boolean }>;
}
export interface BackupStreamSelection {
  path: string;
  close(): Promise<void>;
}
export interface BackupStreamVerifierDependencies {
  ciphertext: BackupV2CiphertextFactory;
  decrypt: BackupV2DecryptStream;
  spawn?: (command: "tar" | "zstd", args: string[]) => BackupStreamProcess;
  selection?: (member: Uint8Array) => Promise<BackupStreamSelection>;
  temporaryDirectory?: string;
  progress?: (
    event: { role: string; pass: number; kind: string; bytes: number },
  ) => Promise<void>;
}
export interface BackupStreamSample {
  member: Uint8Array;
  contentMember: Uint8Array;
  bytes: number;
  sha256: string;
}
export interface BackupStreamPass {
  proof: BackupV2ArchiveProof;
  decodedBytes: number;
  samples: { bytes: number; sha256: string }[];
}
function fail(detail: string): never {
  throw new Error(`Stream verification failed: ${detail}`);
}
const hexHash = (value: string) => /^[0-9a-f]{64}$/.test(value);
const encoder = new TextEncoder();

/** Caller creates and budgets this private directory inside its managed workspace. */
async function nativeSelection(
  directory: string | undefined,
  member: Uint8Array,
) {
  if (
    !directory || !directory.startsWith("/") || member.includes(0) ||
    !member.length
  ) fail("selection scope");
  const dir = await Deno.lstat(directory);
  if (
    !dir.isDirectory || dir.isSymlink || (dir.mode! & 0o077) !== 0 ||
    await Deno.realPath(directory) !== directory
  ) fail("selection directory");
  assertBackupV2Budget("metadataRecordBytes", member.length + 1);
  const path = `${directory}/stream-member-${crypto.randomUUID()}.nul`;
  const file = await Deno.open(path, {
    createNew: true,
    write: true,
    mode: 0o600,
  });
  const bytes = new Uint8Array(member.length + 1);
  bytes.set(member);
  let offset = 0;
  try {
    while (offset < bytes.length) {
      const count = await file.write(bytes.subarray(offset));
      if (
        !Number.isSafeInteger(count) || count <= 0 ||
        count > bytes.length - offset
      ) fail("selection write");
      offset += count;
    }
    await file.sync();
  } finally {
    file.close();
  }
  const bound = await Deno.lstat(path);
  return {
    path,
    async close() {
      const now = await Deno.lstat(path);
      if (
        !now.isFile || now.isSymlink || now.nlink !== 1 ||
        now.ino !== bound.ino || now.dev !== bound.dev ||
        now.size !== bytes.length
      ) fail("selection identity");
      await Deno.remove(path);
    },
  };
}

function nativeSpawn(
  command: "tar" | "zstd",
  args: string[],
): BackupStreamProcess {
  return new Deno.Command(`/usr/bin/${command}`, {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
    clearEnv: true,
    env: { LC_ALL: "C", PATH: "/usr/bin:/bin" },
  }).spawn();
}

/** A failed consumer never stops the healthy consumers or upstream drain. */
export async function fanoutBackupStream(
  source: ReadableStream<Uint8Array>,
  destinations: readonly WritableStream<Uint8Array>[],
  inspect: (bytes: Uint8Array) => void | Promise<void>,
  terminated: () => boolean,
  report: (stage: string, error: unknown) => void = () => {},
): Promise<boolean> {
  const writers = destinations.map((stream) => stream.getWriter());
  const closed = writers.map(() => false);
  let good = true;
  try {
    for await (const bytes of source) {
      try {
        await inspect(bytes);
      } catch (error) {
        good = false;
        report("decoded-inspection", error);
      }
      for (let index = 0; index < writers.length; index++) {
        if (closed[index]) continue;
        try {
          await writers[index].write(bytes);
        } catch (error) {
          closed[index] = true;
          if (!terminated() || !(error instanceof Deno.errors.BrokenPipe)) {
            good = false;
            report(`consumer-write-${index}`, error);
          }
        }
      }
    }
  } finally {
    for (let index = 0; index < writers.length; index++) {
      if (!closed[index]) {
        try {
          await writers[index].close();
        } catch (error) {
          if (!terminated() || !(error instanceof Deno.errors.BrokenPipe)) {
            good = false;
            report(`consumer-close-${index}`, error);
          }
        }
      }
      writers[index].releaseLock();
    }
  }
  return good;
}

async function consumeHash(
  stream: ReadableStream<Uint8Array>,
  maximum = BACKUP_V2_LIMITS.logicalSourceBytes,
) {
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of stream) {
    bytes += chunk.length;
    if (!Number.isSafeInteger(bytes) || bytes > maximum) {
      fail("consumer byte budget");
    }
    hash.update(chunk);
  }
  return { bytes, sha256: hash.digest("hex") };
}

async function boundedDiagnostics(stream: ReadableStream<Uint8Array>) {
  let bytes = 0;
  const hash = createHash("sha256");
  const retained: Uint8Array[] = [];
  for await (const chunk of stream) {
    hash.update(chunk);
    if (bytes < 256 * 1024) retained.push(chunk.slice(0, 256 * 1024 - bytes));
    bytes += chunk.length;
  }
  const data = new Uint8Array(Math.min(bytes, 256 * 1024));
  let offset = 0;
  for (const chunk of retained) {
    data.set(chunk, offset);
    offset += chunk.length;
  }
  const text = new TextDecoder().decode(data);
  const categories = [
    ["permission", /Permission denied|Read-only file system/i],
    [
      "unsupported-option",
      /unrecognized option|unknown option|invalid option/i,
    ],
    ["decoder-memory", /too much memory|window.*larger|memory.*limit/i],
    ["corrupt-or-truncated", /corrupt|checksum|unexpected end|premature end/i],
    ["missing-selection", /Not found in archive/i],
  ] as const;
  return {
    bytes,
    sha256: hash.digest("hex"),
    overflow: bytes > 256 * 1024,
    categories: categories.filter(([, pattern]) => pattern.test(text)).map((
      [name],
    ) => name),
  };
}

function safeStageFailure(stage: string, error: unknown) {
  const names = new Set([
    "Error",
    "TypeError",
    "RangeError",
    "BadResource",
    "BrokenPipe",
    "PermissionDenied",
    "NotFound",
    "InvalidData",
    "Interrupted",
  ]);
  const name = error instanceof Error && names.has(error.name)
    ? error.name
    : "UnknownError";
  const message = error instanceof Error ? error.message : "";
  // Only our own fixed parser labels are exposed, never provider/filename diagnostics.
  const detail =
    /^(Stream tar rejected|Stream verification failed): [a-z /:-]+$/.test(
        message,
      )
      ? message.slice(0, 160)
      : null;
  return { stage, name, detail };
}

function countedCiphertext(
  descriptor: BackupV2ArchiveSourceDescriptor,
  source: ReadableStream<Uint8Array>,
) {
  const reader = source.getReader();
  const hash = createHash("sha256");
  let bytes = 0, complete = false, sha256 = "";
  return {
    stream: new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const next = await reader.read();
          if (next.done) {
            sha256 = hash.digest("hex");
            complete = true;
            reader.releaseLock();
            controller.close();
            return;
          }
          if (next.value.length > BACKUP_V2_LIMITS.slotBytes) {
            fail("ciphertext chunk bound");
          }
          bytes += next.value.length;
          if (bytes > descriptor.ciphertextBytes) fail("ciphertext overflow");
          hash.update(next.value);
          controller.enqueue(next.value);
        } catch (error) {
          try {
            await reader.cancel(error);
          } catch { /* Preserve source failure. */ }
          reader.releaseLock();
          controller.error(error);
        }
      },
      async cancel(reason) {
        await reader.cancel(reason);
        reader.releaseLock();
      },
    }, { highWaterMark: 0 }),
    finish() {
      if (
        !complete || bytes !== descriptor.ciphertextBytes ||
        sha256 !== descriptor.ciphertextSha256
      ) fail("ciphertext EOF/hash");
    },
  };
}

function observedOne(
  observed: ReadonlyMap<string, TarObservation>,
  name: Uint8Array,
) {
  const entry = observed.get(tarPathKey(name));
  if (!entry || entry.count !== 1) fail("missing or duplicate sample/target");
  return entry.member;
}

async function runPass(
  descriptor: BackupV2ArchiveSourceDescriptor,
  deps: BackupStreamVerifierDependencies,
  selected: readonly Uint8Array[],
  targets: readonly Uint8Array[],
  pass: number,
) {
  const spawn = deps.spawn ?? nativeSpawn;
  const selections: BackupStreamSelection[] = [];
  const children: BackupStreamProcess[] = [];
  const childStages: string[] = [];
  const tasks: Promise<unknown>[] = [];
  const failures: ReturnType<typeof safeStageFailure>[] = [];
  const report = (stage: string, error: unknown) => {
    if (failures.length < 32) failures.push(safeStageFailure(stage, error));
  };
  const start = (command: "tar" | "zstd", args: string[]) => {
    const child = spawn(command, args);
    childStages.push(
      command === "zstd"
        ? "zstd"
        : args.includes("--list")
        ? "tar-listing"
        : `tar-sample-${children.length - 2}`,
    );
    children.push(child);
    return child;
  };
  const selectionsFor = deps.selection ??
    ((name) => nativeSelection(deps.temporaryDirectory, name));
  try {
    for (const target of targets) selections.push(await selectionsFor(target));
    const zstd = start("zstd", ["-d", "-c", "-M128", "--no-pass-through"]);
    const isTar = descriptor.format === "tar.zst.gpg";
    const listing = isTar
      ? start("tar", [
        "--list",
        "--verbose",
        "--numeric-owner",
        "--full-time",
        "--utc",
        "--quoting-style=c",
        "--file=-",
      ])
      : null;
    const samples = selections.map((selection) =>
      start("tar", [
        "--extract",
        "--to-stdout",
        "--file=-",
        "--no-wildcards",
        "--anchored",
        "--no-recursion",
        "--null",
        "--verbatim-files-from",
        "--no-unquote",
        `--files-from=${selection.path}`,
      ])
    );
    const inventory = createTarInventory(
      selected,
      pass === 1 && targets.length > 0,
    );
    const guard = createTarTerminationGuard();
    let decodedBytes = 0;
    const metadata: Uint8Array[] = [];
    const observe = <T>(
      promise: Promise<T>,
      stage = "pipeline",
    ): Promise<T | undefined> =>
      promise.catch((error) => {
        report(stage, error);
        return undefined;
      });
    const listingTask = listing
      ? observe(
        consumeNativeTarListing(listing.stdout, inventory.add),
        "native-listing",
      )
      : Promise.resolve();
    tasks.push(listingTask);
    const sampleTasks = samples.map((child) =>
      observe(
        consumeHash(child.stdout),
        `sample-output-${samples.indexOf(child)}`,
      )
    );
    tasks.push(...sampleTasks);
    const fanout = observe(
      fanoutBackupStream(
        zstd.stdout,
        listing
          ? [
            listing.stdin,
            ...samples.map((child) => child.stdin),
          ]
          : [],
        async (bytes) => {
          decodedBytes = assertBackupV2Budget(
            "logicalSourceBytes",
            decodedBytes + bytes.length,
          );
          if (isTar) guard.write(bytes);
          else {
            if (decodedBytes > 8 * 1024 * 1024) fail("recovery metadata bound");
            metadata.push(bytes.slice());
          }
          await deps.progress?.({
            role: descriptor.role,
            pass,
            kind: "decoded",
            bytes: decodedBytes,
          });
        },
        () => isTar && guard.terminated(),
        report,
      ),
    );
    tasks.push(fanout);
    const statuses = children.map((child, index) =>
      observe(child.status, `${childStages[index]}-status`)
    );
    const diagnostics = children.map((child, index) =>
      observe(
        boundedDiagnostics(child.stderr),
        `${childStages[index]}-diagnostics`,
      )
    );
    tasks.push(
      ...statuses,
      ...diagnostics,
    );
    const input = countedCiphertext(
      descriptor,
      deps.ciphertext(descriptor.role),
    );
    const writer = zstd.stdin.getWriter();
    const hash = createHash("sha256");
    let compressedBytes = 0, pipeFailed = false;
    const decryption = observe(
      (async () => {
        try {
          const integrity = await deps.decrypt(input.stream, {
            async write(bytes) {
              compressedBytes = assertBackupV2Budget(
                "ciphertextBytes",
                compressedBytes + bytes.length,
              );
              if (!isTar && compressedBytes > 8 * 1024 * 1024) {
                fail("compressed metadata bound");
              }
              hash.update(bytes);
              if (!pipeFailed) {
                try {
                  await writer.write(bytes);
                } catch (error) {
                  pipeFailed = true;
                  report("zstd-input", error);
                }
              }
              await deps.progress?.({
                role: descriptor.role,
                pass,
                kind: "compressedPlaintext",
                bytes: compressedBytes,
              });
              return bytes.length;
            },
          });
          if (integrity?.integrityChecked !== true) {
            fail("decryption integrity result");
          }
          input.finish();
          await writer.close();
        } catch (error) {
          try {
            await input.stream.cancel(error);
          } catch { /* Backend may still own its lock. */ }
          try {
            await writer.abort(error);
          } catch { /* Preserve primary failure. */ }
          throw error;
        } finally {
          writer.releaseLock();
        }
      })(),
      "decryption",
    );
    tasks.push(decryption);
    await Promise.all(tasks);
    const nativeStatuses = await Promise.all(statuses);
    const nativeDiagnostics = await Promise.all(diagnostics);
    if (
      failures.length || await fanout !== true ||
      nativeStatuses.some((status) => !status?.success || status.code !== 0) ||
      nativeDiagnostics.some((item) => item?.overflow !== false)
    ) {
      fail(`pipeline ${
        JSON.stringify({
          failures,
          fanout: await fanout,
          children: childStages.map((stage, index) => ({
            stage,
            code: nativeStatuses[index]?.code ?? null,
            diagnostics: nativeDiagnostics[index] ?? null,
          })),
        })
      }`);
    }
    const compressedSha256 = hash.digest("hex");
    if (
      !compressedBytes || (descriptor.compressedPlaintext &&
        (compressedBytes !== descriptor.compressedPlaintext.bytes ||
          compressedSha256 !== descriptor.compressedPlaintext.sha256))
    ) fail("compressed plaintext hash/length");
    const listingResult = isTar ? inventory.finish() : null;
    if (
      listingResult &&
      guard.finish().members !== listingResult.inventory.members
    ) fail("native inventory did not cover physical members");
    const proof: BackupV2ArchiveProof = {
      role: descriptor.role,
      format: descriptor.format,
      ciphertextBytes: descriptor.ciphertextBytes,
      ciphertextSha256: descriptor.ciphertextSha256,
      compressedBytes,
      compressedSha256,
      inventory: listingResult?.inventory ?? null,
      inputComplete: true,
      integrityChecked: true,
      decompressionComplete: true,
      gpgExitCode: 0,
      zstdExitCode: 0,
      tarExitCode: 0,
    };
    const data = new Uint8Array(decodedBytes && !isTar ? decodedBytes : 0);
    let offset = 0;
    for (const chunk of metadata) {
      data.set(chunk, offset);
      offset += chunk.length;
    }
    return {
      proof,
      decodedBytes,
      samples: (await Promise.all(sampleTasks)).map((item) => item!),
      listing: listingResult,
      metadata: data,
    };
  } finally {
    // Startup/factory failure must also close and reap every already-started child.
    await Promise.allSettled(
      children.map((child) =>
        child.stdin.locked ? Promise.resolve() : child.stdin.abort()
      ),
    );
    await Promise.allSettled([
      ...tasks,
      ...children.map((child) => child.status),
      ...children.flatMap((child) =>
        [child.stdout, child.stderr].filter((stream) => !stream.locked)
          .map(async (stream) => {
            for await (
              const _chunk of stream
            ) { /* Drain without retaining payload. */ }
          })
      ),
    ]);
    for (const selection of selections) await selection.close();
  }
}

export interface BackupStreamArchiveOptions {
  samples?: readonly BackupV2SampleExpectation[];
  metadataSha256?: string;
}

/** Per-archive proof only. Caller validates the complete seven-role/root contract. */
export async function verifyBackupStreamArchive(
  descriptor: BackupV2ArchiveSourceDescriptor,
  deps: BackupStreamVerifierDependencies,
  options: BackupStreamArchiveOptions = {},
) {
  assertBackupV2Budget("ciphertextBytes", descriptor.ciphertextBytes);
  if (
    !BACKUP_V2_ROLES.includes(descriptor.role) || !descriptor.ciphertextBytes ||
    !hexHash(descriptor.ciphertextSha256) ||
    descriptor.format !==
      (descriptor.role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg")
  ) fail("archive descriptor");
  const expectations = options.samples ?? [];
  const fixed = BACKUP_V2_BOOT_SAMPLES.filter((item) =>
    item.role === descriptor.role
  );
  if (
    expectations.length !== fixed.length ||
    expectations.some((item, index) =>
      item.role !== descriptor.role ||
      tarPathKey(item.member) !==
        tarPathKey(encoder.encode(fixed[index].member)) ||
      !hexHash(item.sha256) ||
      (item.bytes !== undefined &&
        (!Number.isSafeInteger(item.bytes) || item.bytes <= 0))
    )
  ) fail("sample expectations");
  const aliases = expectations.map((item) => item.member);
  const initialTargets = expectations.map((item) =>
    item.contentMember ?? item.member
  );
  const selected = [...aliases, ...initialTargets];
  if (descriptor.role === "root") {
    selected.push(encoder.encode("./etc/os-release"));
  }
  const first = await runPass(descriptor, deps, selected, initialTargets, 1);
  const evidence = (
    { proof, decodedBytes, samples }: BackupStreamPass,
  ): BackupStreamPass => ({ proof, decodedBytes, samples });
  const passes: BackupStreamPass[] = [evidence(first)];
  if (!first.listing) {
    const sha256 = createHash("sha256").update(first.metadata).digest("hex");
    if (!options.metadataSha256 || sha256 !== options.metadataSha256) {
      fail("recovery metadata hash");
    }
    JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(first.metadata),
    );
    return {
      proof: first.proof,
      passes,
      samples: [] as BackupStreamSample[],
      metadata: first.metadata,
    };
  }
  if (
    descriptor.role === "root" &&
    !first.listing.observed.get(tarPathKey(encoder.encode("./etc/os-release")))
  ) fail("missing os-release");
  const resolutions = expectations.map((item) => {
    observedOne(first.listing!.observed, item.member);
    const result = resolveTarSample(item.member, first.listing!.links);
    if (
      item.contentMember &&
      tarPathKey(item.contentMember) !== tarPathKey(result.content)
    ) fail("trusted content target differs");
    return result;
  });
  if (
    new Set(resolutions.map((item) => tarPathKey(item.content))).size !==
      resolutions.length
  ) fail("duplicate sample content target");
  first.listing.links.clear();
  let active = first;
  let targets = initialTargets;
  const needed = resolutions.flatMap((item) => item.chain);
  if (needed.some((name) => !first.listing!.observed.has(tarPathKey(name)))) {
    const known = resolutions.every((item) =>
      first.listing!.observed.get(tarPathKey(item.content))?.member.type === "-"
    );
    if (!known) {
      // Discover exact stored raw spellings without retaining every member name.
      active = await runPass(descriptor, deps, [...selected, ...needed], [], 2);
      passes.push(evidence(active));
    }
    targets = resolutions.map((item) =>
      observedOne(active.listing!.observed, item.content).path
    );
    active = await runPass(
      descriptor,
      deps,
      [...selected, ...needed],
      targets,
      known ? 2 : 3,
    );
    passes.push(evidence(active));
  }
  for (const pass of passes) {
    if (
      pass.proof.compressedBytes !== first.proof.compressedBytes ||
      pass.proof.compressedSha256 !== first.proof.compressedSha256 ||
      pass.proof.inventory?.sha256 !== first.proof.inventory?.sha256
    ) fail("replayed archive differs");
  }
  const samples = expectations.map((expectation, index): BackupStreamSample => {
    for (const member of resolutions[index].chain) {
      observedOne(active.listing!.observed, member);
    }
    const target = observedOne(
      active.listing!.observed,
      resolutions[index].content,
    );
    const sample = active.samples[index];
    if (
      target.type !== "-" || !sample?.bytes || sample.bytes !== target.size ||
      sample.sha256 !== expectation.sha256 ||
      (expectation.bytes !== undefined && sample.bytes !== expectation.bytes) ||
      tarPathKey(targets[index]) !== tarPathKey(resolutions[index].content)
    ) fail("sample content proof");
    return {
      member: expectation.member,
      contentMember: target.path,
      ...sample,
    };
  });
  return { proof: first.proof, passes, samples, metadata: undefined };
}
