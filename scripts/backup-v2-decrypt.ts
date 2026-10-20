/** Preserve the existing sudo/user/GPG/socket protocol while recording the
 * actual post-uid-drop GPG PID, not only sudo's launcher/monitor. */
import type {
  BackupV2NativeSpawn,
  BackupV2RegisteredChild,
} from "./backup-v2-native-process.ts";
export interface BackupV2DecryptProcessRegistry {
  spawn: BackupV2NativeSpawn;
  registerChild(pid: number, kind: "gpg"): Promise<BackupV2RegisteredChild>;
}
const encoder = new TextEncoder();
const SCRIPT = String.raw`
nonce=$1; shift
/usr/bin/bash --noprofile --norc -c '
nonce=$1; shift
printf "B2_GPG_PID:%s:%s:%s\n" "$nonce" "$BASHPID" "$EUID" >&2
IFS= read -r start && test "$start" = "B2_GPG_START:$nonce" || exit 78
printf "B2_GPG_ACK:%s\n" "$nonce" >&2
exec /usr/bin/gpg "$@"
' backup-v2-gpg "$nonce" "$@" <&0 &
child=$!
set +e
wait "$child"
result=$?
printf "B2_GPG_EXIT:%s:%s\n" "$nonce" "$result" >&2
exit "$result"
`.trim();
function fail(): never {
  throw new Error("Backup v2 GPG child custody protocol invalid");
}
async function line(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  pending: Uint8Array,
  maximum = 4096,
): Promise<{ line: Uint8Array; pending: Uint8Array }> {
  let buffer = pending;
  while (true) {
    const end = buffer.indexOf(10);
    if (end >= 0) {
      if (end >= maximum) fail();
      return { line: buffer.slice(0, end + 1), pending: buffer.slice(end + 1) };
    }
    if (buffer.length > maximum) fail();
    const next = await reader.read();
    if (next.done) fail();
    const joined = new Uint8Array(buffer.length + next.value.length);
    joined.set(buffer);
    joined.set(next.value, buffer.length);
    buffer = joined;
  }
}
async function bounded<T>(work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Backup v2 GPG child ACK missing")),
          5000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function spawnBackupV2GpgDecrypt(
  registry: BackupV2DecryptProcessRegistry,
  args: string[],
  signal?: AbortSignal,
) {
  const nonce = crypto.randomUUID();
  const child = await registry.spawn("sudo-gpg", "sudo", [
    "-n",
    "-u",
    "codex",
    "/usr/bin/bash",
    "--noprofile",
    "--norc",
    "-c",
    SCRIPT,
    "backup-v2-sudo-gpg",
    nonce,
    ...args,
  ], { cwd: "/", stdin: "piped", stdout: "piped", stderr: "piped", signal });
  const reader = child.stderr.getReader();
  let pending: Uint8Array = new Uint8Array(0), released = false;
  let resolveExit!: (code: number) => void,
    rejectExit!: (error: unknown) => void;
  const exit = new Promise<number>((resolve, reject) => {
    resolveExit = resolve;
    rejectExit = reject;
  });
  exit.catch(() => {});
  let registered: BackupV2RegisteredChild;
  try {
    const first = await bounded(line(reader, pending));
    pending = first.pending;
    const match = new RegExp(
      `^B2_GPG_PID:${nonce}:([1-9][0-9]*):([1-9][0-9]*)\n$`,
    ).exec(new TextDecoder().decode(first.line));
    if (
      !match || !Number.isSafeInteger(Number(match[1])) ||
      Number(match[2]) === 0
    ) fail();
    registered = await registry.registerChild(Number(match[1]), "gpg");
    const writer = child.stdin.getWriter();
    try {
      await writer.write(encoder.encode(`B2_GPG_START:${nonce}\n`));
    } finally {
      writer.releaseLock();
    }
    const ack = await bounded(line(reader, pending));
    pending = ack.pending;
    if (new TextDecoder().decode(ack.line) !== `B2_GPG_ACK:${nonce}\n`) fail();
  } catch (error) {
    rejectExit(error);
    await child.stdin.abort(error).catch(() => {});
    await reader.cancel().catch(() => {});
    reader.releaseLock();
    throw error;
  }
  let sawExit = false, exitCode = -1;
  const stderr = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        while (true) {
          const end = pending.indexOf(10);
          if (end >= 0) {
            if (end > 64 * 1024) fail();
            const item = pending.slice(0, end + 1);
            pending = pending.slice(end + 1);
            const text = new TextDecoder().decode(item),
              match = new RegExp(`^B2_GPG_EXIT:${nonce}:(0|[1-9][0-9]{0,2})\n$`)
                .exec(text);
            if (match) {
              if (sawExit || Number(match[1]) > 255) fail();
              sawExit = true;
              exitCode = Number(match[1]);
              await registered.exit({ code: exitCode, signal: null });
              continue;
            }
            if (sawExit || text.startsWith(`B2_GPG_EXIT:${nonce}:`)) fail();
            controller.enqueue(item);
            return;
          }
          if (pending.length > 64 * 1024) fail();
          const next = await reader.read();
          if (next.done) {
            if (pending.length) {
              if (sawExit) fail();
              controller.enqueue(pending);
              pending = new Uint8Array(0);
            }
            if (!sawExit) fail();
            reader.releaseLock();
            released = true;
            resolveExit(exitCode);
            controller.close();
            return;
          }
          const joined = new Uint8Array(pending.length + next.value.length);
          joined.set(pending);
          joined.set(next.value, pending.length);
          pending = joined;
        }
      } catch (error) {
        rejectExit(error);
        if (!released) {
          await reader.cancel().catch(() => {});
          reader.releaseLock();
          released = true;
        }
        controller.error(error);
      }
    },
    async cancel(reason) {
      rejectExit(reason ?? new Error("Backup v2 GPG diagnostics cancelled"));
      if (!released) {
        await reader.cancel().catch(() => {});
        reader.releaseLock();
        released = true;
      }
    },
  }, { highWaterMark: 0 });
  const status = Promise.all([child.status, exit]).then(([outer, code]) => {
    if (outer.code !== code) fail();
    return outer;
  });
  status.catch(() => {});
  return { ...child, stderr, status };
}
