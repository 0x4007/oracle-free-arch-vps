/** File-backed v2 transport. A PUT result is a candidate, never readback proof.
 * Curl has a real DNS/TCP/TLS connection-phase timeout and a low-speed window;
 * the latter is deliberately NOT described as an exact socket-idle timeout. */
import { createHash } from "node:crypto";
import { dirname, isAbsolute, resolve } from "node:path";
import {
  B2_VERSION_LOOKUP,
  b2BasicAuthorization,
  b2BucketLookup,
  B2CredentialError,
  b2ExactVersionRequest,
  type B2KeyPurpose,
  type B2KeyScope,
  type B2Settings,
  validateB2AllowedScope,
  validateB2ApiUrl,
  validateB2BucketLookup,
  validateB2ExactVersionLookup,
  validateB2Settings,
  validateB2UploadUrl,
} from "./backblaze-storage.ts";
import {
  type BackupV2Cursor,
  type BackupV2ListedVersion,
  type BackupV2ObjectRef,
  type BackupV2ObjectStore,
  type BackupV2PutIntent,
  type BackupV2SealedSlot,
  type BackupV2SlotTarget,
  type BackupV2VersionPage,
  validateBackupV2Cursor,
  validateBackupV2ObjectRef,
  validateBackupV2PutIntent,
  validateBackupV2SealedSlot,
  validateBackupV2VersionPage,
} from "./backup-v2-contract.ts";
import {
  type BackupV2RetentionPart,
  type BackupV2RetentionVersion,
  retentionInteger,
  retentionOwnedName,
  retentionOwnedResticName,
  retentionText,
  validateRetentionListedVersion,
} from "./backup-v2-retention-inventory.ts";
import {
  BACKUP_V2_LIMITS as LIMIT,
  BACKUP_V2_NAMESPACE,
} from "./backup-v2-profile.ts";
import type { BackupV2NativeSpawn } from "./backup-v2-native-process.ts";
import {
  type BackupV2KernelCommand,
  realBackupV2KernelCommand,
} from "./backup-v2-kernel.ts";

const AUTH = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account";
const API = "/b2api/v3/";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const CONTROL_MS = 120_000;
const SETTLEMENT_MS = 30_000;
/** Worst-case uncached chains, not expected rates or whole-job deadlines. */
export const BACKUP_V2_TRANSPORT_BOUNDS = Object.freeze({
  connectMs: 30_000,
  lowSpeedMs: 120_000,
  controlMs: CONTROL_MS,
  payloadMs: LIMIT.blockedTransportMs,
  settlementMs: SETTLEMENT_MS,
  putControlRequests: 3,
  readbackControlRequests: 3,
  putEpisodeMs: 3 * CONTROL_MS + LIMIT.blockedTransportMs + SETTLEMENT_MS,
  readbackEpisodeMs: 3 * CONTROL_MS + LIMIT.blockedTransportMs + SETTLEMENT_MS,
});
type AuthorizedScope = {
  token: string;
  api: string;
  download: string;
  keyScope: B2KeyScope;
};
export type BackupV2ExactObjectState = "PRESENT" | "ABSENT";
export interface BackupV2ExactObjectStore extends BackupV2ObjectStore {
  reconcileExact(
    object: BackupV2ObjectRef,
    signal?: AbortSignal,
  ): Promise<BackupV2ExactObjectState>;
  /** Caller owns durable deletion intent and reconciliation after any failure. */
  removeExact(object: BackupV2ObjectRef, signal?: AbortSignal): Promise<void>;
}
export type BackupV2TransportCategory =
  | "network"
  | "http"
  | "integrity"
  | "protocol"
  | "cancelled"
  | "limit";
export class BackupV2TransportError extends Error {
  readonly retryable: boolean;
  constructor(
    readonly category: BackupV2TransportCategory,
    reason: string,
    readonly httpStatus?: number,
    readonly putMayHaveCommitted = false,
  ) {
    super(`Backup v2 transport: ${reason}`);
    this.name = "BackupV2TransportError";
    this.retryable = category === "network" || category === "http" &&
        (httpStatus === 408 || httpStatus === 429 ||
          (httpStatus !== undefined && httpStatus >= 500 && httpStatus <= 599));
  }
}
function safeFailure(
  error: unknown,
  category: BackupV2TransportCategory = "protocol",
) {
  return error instanceof BackupV2TransportError
    ? error
    : new BackupV2TransportError(category, "operation failed");
}
function fail(
  reason: string,
  category: BackupV2TransportCategory = "integrity",
): never {
  throw new BackupV2TransportError(category, reason);
}
function require(value: unknown, reason: string): asserts value {
  if (!value) fail(reason);
}

export interface BackupV2WireRequest {
  url: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  json?: string;
  uploadPath?: string;
  maximumBodyBytes: number;
  /** Includes connection, headers and complete response body. */
  maximumTimeMs?: number;
  signal?: AbortSignal;
}
export interface BackupV2WireResponse {
  status: number;
  headers: Headers;
  body: ReadableStream<Uint8Array>;
  finished: Promise<void>;
  cancel(): Promise<void>;
}
export type BackupV2Wire = (
  request: BackupV2WireRequest,
) => Promise<BackupV2WireResponse>;

function join(parts: Uint8Array[], size: number): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
function hasControl(value: string, space = false): boolean {
  return [...value].some((character) =>
    character.charCodeAt(0) <= (space ? 32 : 31) ||
    character.charCodeAt(0) === 127
  );
}
function quote(value: string): string {
  require(!hasControl(value), "invalid config value");
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

/** No executable/path/auth overrides. The fixture option permits loopback only;
 * the B2 store still independently rejects non-provider API/upload endpoints. */
export function createCurlBackupV2Wire(
  fixture?: { loopback: true; connectSeconds: number; lowSpeedSeconds: number },
  spawn?: BackupV2NativeSpawn,
): BackupV2Wire {
  if (fixture) {
    require(
      fixture.connectSeconds > 0 && fixture.connectSeconds <= 30 &&
        Number.isInteger(fixture.lowSpeedSeconds) &&
        fixture.lowSpeedSeconds >= 1 && fixture.lowSpeedSeconds <= 120,
      "invalid fixture time limits",
    );
  }
  return async (request) => {
    if (request.signal?.aborted) fail("cancelled before request", "cancelled");
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      fail("invalid wire URL");
    }
    require(
      url.username === "" && url.password === "" && url.hash === "",
      "invalid wire URL",
    );
    if (fixture) {
      require(
        ["http:", "https:"].includes(url.protocol) &&
          ["127.0.0.1", "[::1]"].includes(url.hostname),
        "fixture must be loopback",
      );
    } else require(url.protocol === "https:", "HTTPS required");
    require(
      Number.isSafeInteger(request.maximumBodyBytes) &&
        request.maximumBodyBytes >= 0 &&
        request.maximumBodyBytes <= LIMIT.slotBytes,
      "invalid body bound",
    );
    require(
      !(request.uploadPath && request.json !== undefined),
      "multiple wire bodies",
    );
    const maximumTimeMs = request.maximumTimeMs ?? LIMIT.blockedTransportMs;
    require(
      Number.isSafeInteger(maximumTimeMs) && maximumTimeMs > 0 &&
        maximumTimeMs <= LIMIT.blockedTransportMs,
      "invalid request time bound",
    );
    const config = [
      "silent",
      "show-error",
      "no-buffer",
      "include",
      "globoff",
      "http1.1",
      "retry = 0",
      "max-redirs = 0",
      `proto = "=${fixture ? url.protocol.slice(0, -1) : "https"}"`,
      'noproxy = "*"',
      `connect-timeout = ${
        fixture?.connectSeconds ?? BACKUP_V2_TRANSPORT_BOUNDS.connectMs / 1000
      }`,
      `speed-time = ${
        fixture?.lowSpeedSeconds ?? BACKUP_V2_TRANSPORT_BOUNDS.lowSpeedMs / 1000
      }`,
      "speed-limit = 1",
      `max-time = ${maximumTimeMs / 1000}`,
      `max-filesize = ${Math.max(1, request.maximumBodyBytes)}`,
      `url = ${quote(request.url)}`,
      `request = ${quote(request.method)}`,
      'header = "Expect:"',
      'header = "Connection: close"',
    ];
    for (const [name, value] of Object.entries(request.headers)) {
      require(/^[a-z0-9-]+$/i.test(name), "invalid header name");
      config.push(`header = ${quote(`${name}: ${value}`)}`);
    }
    if (request.uploadPath) {
      config.push(`upload-file = ${quote(request.uploadPath)}`);
    }
    if (request.json !== undefined) {
      require(
        encoder.encode(request.json).length <= LIMIT.controlResponseBytes,
        "request body bound",
      );
      config.push(`data-binary = ${quote(request.json)}`);
    }
    const input = encoder.encode(config.join("\n") + "\n");
    require(input.length <= LIMIT.controlResponseBytes, "config bound");
    const abort = new AbortController();
    const relay = () => abort.abort();
    request.signal?.addEventListener("abort", relay, { once: true });
    const args = ["--disable", "--config", "-"];
    const childOptions: Deno.CommandOptions = {
      clearEnv: true,
      env: { LC_ALL: "C" },
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
      signal: abort.signal,
    };
    const child = spawn
      ? await spawn("curl", "/usr/bin/curl", args, childOptions)
      : new Deno.Command("/usr/bin/curl", { ...childOptions, args }).spawn();
    let exited = false;
    const status = child.status.finally(() => {
      exited = true;
    });
    const stop = async () => {
      abort.abort();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          status,
          new Promise<void>((done) => {
            timer = setTimeout(() => {
              if (!exited) {
                try {
                  child.kill("SIGKILL");
                } catch { /* already exited */ }
              }
              done();
            }, SETTLEMENT_MS);
          }),
        ]);
        await status;
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    };
    const inputTask = (async () => {
      const writer = child.stdin.getWriter();
      try {
        await writer.write(input);
        await writer.close();
      } finally {
        writer.releaseLock();
        input.fill(0);
      }
    })();
    const diagnostics = (async () => {
      let count = 0;
      for await (const bytes of child.stderr) {
        count += bytes.length;
        if (count > LIMIT.responseHeaderBytes) {
          abort.abort();
          fail("diagnostics bound");
        }
      }
    })();
    const finished = Promise.all([status, inputTask, diagnostics]).then(
      ([result]) => {
        if (request.signal?.aborted) fail("cancelled", "cancelled");
        if (!result.success || abort.signal.aborted) {
          fail(
            "wire failed",
            [5, 6, 7, 18, 28, 35, 52, 55, 56, 92].includes(result.code)
              ? "network"
              : "protocol",
          );
        }
      },
    ).finally(() => request.signal?.removeEventListener("abort", relay));
    finished.catch(() => {}); // The caller must await it; prevent an early unhandled rejection.
    const reader = child.stdout.getReader();
    let pending = new Uint8Array(0), headerBytes = 0, finalStatus = 0;
    const headers = new Headers();
    try {
      for (let blocks = 0; !finalStatus; blocks++) {
        require(blocks < 8, "too many interim responses");
        let end = -1;
        while (end < 0) {
          for (let i = 0; i + 3 < pending.length; i++) {
            if (
              pending[i] === 13 && pending[i + 1] === 10 &&
              pending[i + 2] === 13 && pending[i + 3] === 10
            ) {
              end = i + 4;
              break;
            }
          }
          if (end >= 0) break;
          require(
            headerBytes + pending.length <= LIMIT.responseHeaderBytes,
            "response headers bound",
          );
          const next = await reader.read();
          if (next.done) {
            await finished;
            fail("missing response headers", "protocol");
          }
          pending = join(
            [pending, next.value],
            pending.length + next.value.length,
          );
        }
        headerBytes += end;
        require(
          headerBytes <= LIMIT.responseHeaderBytes,
          "response headers bound",
        );
        const lines = decoder.decode(pending.subarray(0, end - 4)).split(
          "\r\n",
        );
        pending = pending.slice(end);
        const match = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: .*)?$/.exec(
          lines.shift() ?? "",
        );
        require(match, "invalid HTTP status");
        const code = Number(match[1]);
        if (code < 200) continue;
        finalStatus = code;
        for (const line of lines) {
          const split = line.indexOf(":");
          require(split > 0 && !/^[ \t]/.test(line), "invalid HTTP header");
          const name = line.slice(0, split).toLowerCase();
          require(!headers.has(name), "duplicate HTTP header");
          headers.set(name, line.slice(split + 1).trim());
        }
      }
      let total = 0;
      const body = new ReadableStream<Uint8Array>({
        async pull(controller) {
          try {
            const next = pending.length
              ? { done: false, value: pending }
              : await reader.read();
            pending = new Uint8Array(0);
            if (next.done) {
              await finished;
              controller.close();
              return;
            }
            total += next.value.length;
            require(total <= request.maximumBodyBytes, "response body bound");
            controller.enqueue(next.value);
          } catch (error) {
            await stop();
            controller.error(
              request.signal?.aborted
                ? new BackupV2TransportError("cancelled", "cancelled")
                : safeFailure(error, "network"),
            );
          }
        },
        async cancel() {
          await stop();
          await reader.cancel().catch(() => {});
        },
      }, { highWaterMark: 0 });
      return {
        status: finalStatus,
        headers,
        body,
        finished,
        cancel: async () => {
          await stop();
          await reader.cancel().catch(() => {});
        },
      };
    } catch (error) {
      await stop();
      await reader.cancel().catch(() => {});
      throw request.signal?.aborted
        ? new BackupV2TransportError("cancelled", "cancelled")
        : safeFailure(error, "network");
    }
  };
}

function record(value: unknown): Record<string, unknown> {
  require(
    value !== null && typeof value === "object" && !Array.isArray(value),
    "invalid control object",
  );
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  require(
    typeof value === "string" && value.length > 0 &&
      encoder.encode(value).length <= 8192 &&
      !hasControl(value),
    "invalid control string",
  );
  return value;
}
async function jsonBody(
  response: BackupV2WireResponse,
  exactNotPresent?: false,
): Promise<Record<string, unknown>>;
async function jsonBody(
  response: BackupV2WireResponse,
  exactNotPresent: true,
): Promise<Record<string, unknown> | null>;
async function jsonBody(
  response: BackupV2WireResponse,
  exactNotPresent = false,
): Promise<Record<string, unknown> | null> {
  try {
    const rejected = response.status !== 200;
    if (rejected && !(exactNotPresent && response.status === 404)) {
      throw new BackupV2TransportError(
        "http",
        "HTTP rejected",
        response.status,
      );
    }
    const parts: Uint8Array[] = [];
    let total = 0;
    for await (const bytes of response.body) {
      total += bytes.length;
      require(total <= LIMIT.controlResponseBytes, "control response bound");
      parts.push(bytes);
    }
    await response.finished;
    const body = record(JSON.parse(decoder.decode(join(parts, total))));
    if (rejected) {
      // https://www.backblaze.com/apidocs/b2-get-file-info (11 Sep 2026).
      if (body.status === 404 && body.code === "not_found") return null;
      throw new BackupV2TransportError(
        "http",
        "HTTP rejected",
        response.status,
      );
    }
    return body;
  } catch (error) {
    await response.cancel();
    throw safeFailure(error);
  }
}

type AncestorInfo = Pick<
  Deno.FileInfo,
  "isDirectory" | "isSymlink" | "uid" | "mode"
>;
export interface BackupV2AncestorIO {
  lstat(path: string): Promise<AncestorInfo>;
  metadata: BackupV2KernelCommand;
}
const ancestorIO: BackupV2AncestorIO = {
  lstat: Deno.lstat,
  metadata: realBackupV2KernelCommand,
};
async function ancestorInfo(
  path: string,
  io: BackupV2AncestorIO,
): Promise<AncestorInfo> {
  try {
    return await io.lstat(path);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotCapable)) throw error;
  }
  // No -L: preserve lstat semantics and reject a symlink at this exact path.
  // This command reads metadata only, under the existing bounded stat grant.
  const result = await io.metadata("/usr/bin/stat", [
    "--printf=%u\\0%f\\0%n\\0",
    "--",
    path,
  ]);
  require(
    result.code === 0 && result.stderr === "" &&
      encoder.encode(result.stdout).length <= encoder.encode(path).length + 128,
    "slot parent metadata unavailable",
  );
  const parts = result.stdout.split("\0");
  require(
    parts.length === 4 && parts[3] === "" && parts[2] === path &&
      /^[0-9]+$/.test(parts[0]) && /^[0-9a-f]{1,8}$/.test(parts[1]),
    "slot parent metadata binding rejected",
  );
  const uid = Number(parts[0]), mode = parseInt(parts[1], 16);
  require(
    Number.isSafeInteger(uid) && uid >= 0 && mode <= 0o177777,
    "slot parent metadata values rejected",
  );
  return {
    uid,
    mode,
    isDirectory: (mode & 0o170000) === 0o040000,
    isSymlink: (mode & 0o170000) === 0o120000,
  };
}
export async function assertBackupV2SlotParents(
  path: string,
  io: BackupV2AncestorIO = ancestorIO,
): Promise<void> {
  require(isAbsolute(path) && resolve(path) === path, "invalid slot path");
  let parent = dirname(path);
  while (parent !== "/") {
    const info = await ancestorInfo(parent, io);
    const stickyTemporary = ["/tmp", "/var/tmp"].includes(parent) &&
      (info.mode! & 0o1000) !== 0;
    require(
      info.isDirectory && !info.isSymlink && info.uid === 0 &&
        info.mode !== null &&
        ((info.mode! & 0o022) === 0 || stickyTemporary),
      "slot parent is not controlled",
    );
    parent = dirname(parent);
  }
}
async function identity(path: string): Promise<Deno.FileInfo> {
  const info = await Deno.lstat(path);
  require(
    info.isFile && !info.isSymlink && info.uid === 0 &&
      (info.mode! & 0o7777) === 0o600 && info.nlink === 1,
    "slot identity rejected",
  );
  return info;
}
async function hashes(
  file: Deno.FsFile,
): Promise<{ bytes: number; sha1: string; sha256: string }> {
  const first = createHash("sha1"), second = createHash("sha256");
  const buffer = new Uint8Array(64 * 1024);
  let bytes = 0;
  for (;;) {
    const count = await file.read(buffer);
    if (count === null) break;
    require(count > 0, "file read made no progress");
    bytes += count;
    require(bytes <= LIMIT.slotBytes, "slot bytes bound");
    first.update(buffer.subarray(0, count));
    second.update(buffer.subarray(0, count));
  }
  return { bytes, sha1: first.digest("hex"), sha256: second.digest("hex") };
}
async function verifySlot(
  slot: BackupV2SealedSlot,
  io: BackupV2AncestorIO,
): Promise<void> {
  validateBackupV2SealedSlot(slot);
  await assertBackupV2SlotParents(slot.path, io);
  const before = await identity(slot.path);
  require(
    before.dev === slot.device && before.ino === slot.inode &&
      before.size === slot.bytes,
    "sealed slot changed",
  );
  using file = await Deno.open(slot.path, { read: true });
  const opened = await file.stat();
  require(
    opened.dev === before.dev && opened.ino === before.ino,
    "slot changed while opening",
  );
  const got = await hashes(file), after = await identity(slot.path);
  require(
    got.bytes === slot.bytes && got.sha1 === slot.sha1 &&
      got.sha256 === slot.sha256 &&
      after.dev === before.dev && after.ino === before.ino &&
      after.size === before.size &&
      after.mtime?.getTime() === before.mtime?.getTime() &&
      after.ctime?.getTime() === before.ctime?.getTime(),
    "slot integrity rejected",
  );
}

export class BackupV2Store implements BackupV2ExactObjectStore {
  readonly #settings: B2Settings;
  readonly #wire: BackupV2Wire;
  readonly #ancestors: BackupV2AncestorIO;
  readonly #purpose: B2KeyPurpose;
  readonly #usedPuts = new Set<string>();
  #scope?: Promise<AuthorizedScope>;
  constructor(
    settings: B2Settings,
    wire: BackupV2Wire = createCurlBackupV2Wire(),
    metadata: BackupV2KernelCommand = realBackupV2KernelCommand,
    purpose: B2KeyPurpose = "backup",
  ) {
    validateB2Settings(settings);
    for (
      const value of [
        settings.accessKeyId,
        settings.secretAccessKey,
        settings.bucketId,
      ]
    ) text(value);
    this.#settings = { ...settings };
    this.#wire = wire;
    this.#ancestors = { ...ancestorIO, metadata };
    this.#purpose = purpose;
  }
  async #request(
    url: string,
    token: string,
    payload?: unknown,
    signal?: AbortSignal,
    exactNotPresent?: false,
  ): Promise<Record<string, unknown>>;
  async #request(
    url: string,
    token: string,
    payload: unknown,
    signal: AbortSignal | undefined,
    exactNotPresent: true,
  ): Promise<Record<string, unknown> | null>;
  async #request(
    url: string,
    token: string,
    payload?: unknown,
    signal?: AbortSignal,
    exactNotPresent = false,
  ): Promise<Record<string, unknown> | null> {
    if (signal?.aborted) fail("cancelled before request", "cancelled");
    try {
      const response = await this.#wire({
        url,
        method: payload === undefined ? "GET" : "POST",
        headers: { authorization: token, "content-type": "application/json" },
        json: payload === undefined ? undefined : JSON.stringify(payload),
        maximumBodyBytes: LIMIT.controlResponseBytes,
        maximumTimeMs: CONTROL_MS,
        signal,
      });
      return exactNotPresent
        ? await jsonBody(response, true)
        : await jsonBody(response);
    } catch (error) {
      throw safeFailure(error, "network");
    }
  }
  #authorized(signal?: AbortSignal) {
    if (signal?.aborted) fail("cancelled before request", "cancelled");
    if (!this.#scope) {
      const pending = this.#request(
        AUTH,
        b2BasicAuthorization(this.#settings),
        undefined,
        signal,
      ).then(async (body) => {
        const storage = record(record(body.apiInfo).storageApi);
        const api = text(storage.apiUrl), download = text(storage.downloadUrl);
        validateB2ApiUrl("v2 authorize", "api", api);
        validateB2ApiUrl("v2 authorize", "download", download);
        const keyScope = validateB2AllowedScope(
          "v2 authorize",
          this.#settings,
          record(storage.allowed),
          this.#purpose,
        );
        const token = text(body.authorizationToken);
        if (keyScope === "unrestricted") {
          const accountId = text(body.accountId);
          const buckets = await this.#request(
            `${api}${API}b2_list_buckets`,
            token,
            b2BucketLookup(accountId),
            signal,
          );
          validateB2BucketLookup(buckets, accountId, this.#settings);
        }
        return { token, api, download, keyScope };
      });
      this.#scope = pending;
      pending.catch(() => {
        if (this.#scope === pending) this.#scope = undefined;
      });
    }
    return this.#scope;
  }

  /** Read-only credential and bucket proof without listing any objects. */
  async verifyCredential(signal?: AbortSignal): Promise<B2KeyScope> {
    try {
      return (await this.#authorized(signal)).keyScope;
    } catch (error) {
      if (error instanceof B2CredentialError) throw error;
      throw new B2CredentialError(
        "B2_CREDENTIAL_AUTH_UNPROVED",
        "Backblaze authorization or bucket readback failed",
      );
    }
  }

  #matchesObject(
    body: Record<string, unknown>,
    object: BackupV2ObjectRef,
  ): boolean {
    return body.bucketId === this.#settings.bucketId &&
      body.fileId === object.fileId && body.fileName === object.fileName &&
      body.action === object.action &&
      body.contentLength === object.contentLength &&
      body.contentSha1 === object.contentSha1 &&
      body.uploadTimestamp === object.uploadTimestamp;
  }

  async #lookupVersion(
    scope: AuthorizedScope,
    object: Pick<BackupV2ListedVersion, "fileId" | "fileName">,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown> | null> {
    return validateB2ExactVersionLookup(
      await this.#request(
        `${scope.api}${API}${B2_VERSION_LOOKUP}`,
        scope.token,
        b2ExactVersionRequest(this.#settings.bucketId, object),
        signal,
      ),
      this.#settings.bucketId,
      object,
    );
  }

  async #requireObjectInBucket(
    scope: AuthorizedScope,
    object: BackupV2ObjectRef,
    signal?: AbortSignal,
  ): Promise<void> {
    if (scope.keyScope === "scoped") return;
    const exact = await this.#lookupVersion(scope, object, signal);
    require(
      exact && this.#matchesObject(exact, object),
      "exact object metadata mismatch",
    );
  }

  async putFileOnce(
    value: BackupV2PutIntent,
    signal?: AbortSignal,
  ): Promise<BackupV2ObjectRef> {
    require(this.#purpose === "backup", "writer scope required");
    const intent = validateBackupV2PutIntent(value);
    await verifySlot(intent.slot, this.#ancestors);
    const scope = await this.#authorized(signal);
    const target = await this.#request(
      `${scope.api}${API}b2_get_upload_url`,
      scope.token,
      { bucketId: this.#settings.bucketId },
      signal,
    );
    const url = text(target.uploadUrl);
    validateB2UploadUrl("v2 upload", "target", url);
    require(
      target.bucketId === this.#settings.bucketId,
      "upload bucket mismatch",
    );
    require(
      !this.#usedPuts.has(intent.name) &&
        this.#usedPuts.size < LIMIT.physicalPuts,
      "physical PUT name already attempted or budget exhausted",
    );
    this.#usedPuts.add(intent.name);
    try {
      const response = await this.#wire({
        url,
        method: "POST",
        uploadPath: intent.slot.path,
        headers: {
          authorization: text(target.authorizationToken),
          "content-type": "application/octet-stream",
          "content-length": String(intent.slot.bytes),
          "x-bz-file-name": encodeURIComponent(intent.name),
          "x-bz-content-sha1": intent.slot.sha1,
        },
        maximumBodyBytes: LIMIT.controlResponseBytes,
        maximumTimeMs: LIMIT.blockedTransportMs,
        signal,
      });
      const body = await jsonBody(response);
      require(
        body.bucketId === this.#settings.bucketId &&
          body.fileName === intent.name &&
          body.contentLength === intent.slot.bytes &&
          body.contentSha1 === intent.slot.sha1 && body.action === "upload",
        "PUT response binding mismatch",
      );
      await verifySlot(intent.slot, this.#ancestors);
      return validateBackupV2ObjectRef({
        fileId: body.fileId,
        fileName: body.fileName,
        contentLength: body.contentLength,
        contentSha1: body.contentSha1,
        uploadTimestamp: body.uploadTimestamp,
        action: "upload",
        sha256: intent.slot.sha256,
      });
    } catch (error) {
      const safe = safeFailure(error, "network");
      throw new BackupV2TransportError(
        safe.category,
        "PUT failed; exact intent requires reconciliation",
        safe.httpStatus,
        true,
      );
    }
  }
  /** Full exact-version proof with no third slot and no decoder delivery. */
  async verifyExactReadback(
    value: BackupV2ObjectRef,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.#readback(value, signal);
  }
  async #readback(
    value: BackupV2ObjectRef,
    signal?: AbortSignal,
    file?: Deno.FsFile,
  ): Promise<number> {
    const object = validateBackupV2ObjectRef(value);
    const scope = await this.#authorized(signal);
    await this.#requireObjectInBucket(scope, object, signal);
    const response = await this.#wire({
      url: `${scope.download}${API}b2_download_file_by_id?fileId=${
        encodeURIComponent(object.fileId)
      }`,
      method: "GET",
      headers: { authorization: scope.token, "accept-encoding": "identity" },
      maximumBodyBytes: object.contentLength,
      maximumTimeMs: LIMIT.blockedTransportMs,
      signal,
    });
    try {
      if (response.status === 401) this.#scope = undefined;
      if (response.status !== 200) {
        throw new BackupV2TransportError(
          "http",
          "GET HTTP rejected",
          response.status,
        );
      }
      require(
        response.headers.get("x-bz-file-id") === object.fileId &&
          decodeURIComponent(response.headers.get("x-bz-file-name") ?? "") ===
            object.fileName &&
          response.headers.get("x-bz-content-sha1") === object.contentSha1 &&
          [null, "identity"].includes(response.headers.get("content-encoding")),
        "GET response binding mismatch",
      );
      const declared = response.headers.get("content-length");
      require(
        declared === null || declared === String(object.contentLength),
        "GET declared length mismatch",
      );
      const first = createHash("sha1"), second = createHash("sha256");
      let total = 0;
      for await (const bytes of response.body) {
        require(
          total + bytes.length <= object.contentLength,
          "GET body overflow",
        );
        first.update(bytes);
        second.update(bytes);
        if (file) {
          let offset = 0;
          while (offset < bytes.length) {
            const count = await file.write(bytes.subarray(offset));
            require(count > 0, "write made no progress");
            offset += count;
          }
        }
        total += bytes.length;
      }
      await response.finished;
      require(
        total === object.contentLength &&
          first.digest("hex") === object.contentSha1 &&
          second.digest("hex") === object.sha256,
        "GET readback integrity mismatch",
      );
      return total;
    } catch (error) {
      await response.cancel();
      throw safeFailure(error);
    }
  }
  async getExactToFile(
    value: BackupV2ObjectRef,
    target: BackupV2SlotTarget,
    signal?: AbortSignal,
  ): Promise<BackupV2SealedSlot> {
    const object = validateBackupV2ObjectRef(value);
    require(target.index === 0 || target.index === 1, "invalid target index");
    await assertBackupV2SlotParents(target.path, this.#ancestors);
    try {
      using file = await Deno.open(target.path, {
        createNew: true,
        write: true,
        read: true,
        mode: 0o600,
      });
      await identity(target.path);
      const total = await this.#readback(object, signal, file);
      await file.sync();
      await file.seek(0, Deno.SeekMode.Start);
      const got = await hashes(file),
        info = await identity(target.path),
        opened = await file.stat();
      require(
        got.sha1 === object.contentSha1 && got.sha256 === object.sha256 &&
          info.dev === opened.dev && info.ino === opened.ino &&
          info.size === object.contentLength,
        "GET readback integrity mismatch",
      );
      return validateBackupV2SealedSlot({
        ...target,
        device: info.dev,
        inode: info.ino,
        bytes: total,
        sha1: got.sha1,
        sha256: got.sha256,
        uid: info.uid,
        mode: info.mode! & 0o7777,
        links: info.nlink,
      });
    } catch (error) {
      throw safeFailure(error);
    }
  }
  async versionsPage(
    prefix: string,
    cursor: BackupV2Cursor | null,
    signal?: AbortSignal,
  ): Promise<BackupV2VersionPage> {
    require(
      prefix.startsWith(BACKUP_V2_NAMESPACE) &&
        !hasControl(prefix, true) &&
        encoder.encode(prefix).length <= 1000,
      "listing prefix rejected",
    );
    if (cursor) {
      cursor = validateBackupV2Cursor(cursor);
      require(cursor.fileName.startsWith(prefix), "cursor outside prefix");
    }
    const scope = await this.#authorized(signal);
    const body = await this.#request(
      `${scope.api}${API}b2_list_file_versions`,
      scope.token,
      {
        bucketId: this.#settings.bucketId,
        prefix,
        maxFileCount: LIMIT.listEntries,
        ...(cursor
          ? { startFileName: cursor.fileName, startFileId: cursor.fileId }
          : {}),
      },
      signal,
    );
    require(
      Array.isArray(body.files) && body.files.length <= LIMIT.listEntries,
      "list page entries bound",
    );
    const items = body.files.map((value) => {
      const item = record(value);
      require(
        item.bucketId === this.#settings.bucketId &&
          typeof item.fileName === "string" && item.fileName.startsWith(prefix),
        "list scope mismatch",
      );
      return {
        fileId: item.fileId,
        fileName: item.fileName,
        contentLength: item.contentLength ?? 0,
        contentSha1: item.contentSha1 ?? "",
        uploadTimestamp: item.uploadTimestamp ?? 0,
        action: item.action,
      };
    });
    require(
      (body.nextFileName == null) === (body.nextFileId == null),
      "incomplete list cursor",
    );
    const next = body.nextFileName == null
      ? null
      : { fileName: body.nextFileName, fileId: body.nextFileId };
    const page = validateBackupV2VersionPage({ items, next });
    require(
      page.next === null || page.next.fileName.startsWith(prefix),
      "continuation outside prefix",
    );
    require(
      cursor === null || page.next === null ||
        cursor.fileName !== page.next.fileName ||
        cursor.fileId !== page.next.fileId,
      "nonadvancing list cursor",
    );
    return page;
  }
  /** Metadata reconciliation is not complete hash readback proof. */
  async reconcileExact(
    value: BackupV2ObjectRef,
    signal?: AbortSignal,
  ): Promise<BackupV2ExactObjectState> {
    const object = validateBackupV2ObjectRef(value);
    const scope = await this.#authorized(signal);
    const body = scope.keyScope === "unrestricted"
      ? await this.#lookupVersion(scope, object, signal)
      : await this.#request(
        `${scope.api}${API}b2_get_file_info`,
        scope.token,
        { fileId: object.fileId },
        signal,
        true,
      );
    if (body === null) return "ABSENT";
    require(
      this.#matchesObject(body, object),
      "exact object metadata mismatch",
    );
    return "PRESENT";
  }
  async removeExact(
    value: BackupV2ObjectRef,
    signal?: AbortSignal,
  ): Promise<void> {
    const object = validateBackupV2ObjectRef(value);
    const scope = await this.#authorized(signal);
    await this.#requireObjectInBucket(scope, object, signal);
    const body = await this.#request(
      `${scope.api}${API}b2_delete_file_version`,
      scope.token,
      { fileName: object.fileName, fileId: object.fileId },
      signal,
    );
    require(
      body.fileId === object.fileId && body.fileName === object.fileName &&
        (body.bucketId === undefined ||
          body.bucketId === this.#settings.bucketId),
      "DELETE response binding mismatch",
    );
  }

  #retentionRequest(endpoint: string, payload: unknown, signal?: AbortSignal) {
    return this.#retentionScope(signal).then((scope) =>
      this.#request(
        `${scope.api}${API}${endpoint}`,
        scope.token,
        payload,
        signal,
      )
    );
  }

  #retentionScope(signal?: AbortSignal): Promise<AuthorizedScope> {
    require(this.#purpose === "retention", "whole-bucket key scope required");
    return this.#authorized(signal);
  }

  async #lookupUnfinished(
    scope: AuthorizedScope,
    fileId: string,
    signal?: AbortSignal,
    fileName?: string,
  ): Promise<Extract<BackupV2ListedVersion, { action: "start" }>> {
    const body = await this.#request(
      `${scope.api}${API}b2_list_unfinished_large_files`,
      scope.token,
      {
        bucketId: this.#settings.bucketId,
        startFileId: fileId,
        maxFileCount: 1,
        ...(fileName === undefined ? {} : { namePrefix: fileName }),
      },
      signal,
    );
    require(
      Array.isArray(body.files) && body.files.length === 1 &&
        (body.nextFileId === null || retentionText(body.nextFileId, 512)),
      "exact unfinished version is absent or unproved",
    );
    const exact = this.#retentionVersion(body.files[0], "start");
    require(
      exact.action === "start" && exact.fileId === fileId &&
        (fileName === undefined || exact.fileName === fileName),
      "exact unfinished version mismatch",
    );
    return exact;
  }

  #retentionVersion(value: unknown, action?: "start"): BackupV2ListedVersion {
    const item = record(value);
    require(item.bucketId === this.#settings.bucketId, "list bucket mismatch");
    const kind = action ?? item.action;
    require(
      kind === "upload" || kind === "hide" || kind === "start",
      "list version action rejected",
    );
    require(
      action === undefined || item.action === undefined ||
        item.action === action,
      "unfinished version action mismatch",
    );
    return validateRetentionListedVersion({
      fileId: retentionText(item.fileId, 512),
      fileName: retentionText(item.fileName, 1_000),
      action: kind,
      contentLength: retentionInteger(
        action === "start" && item.contentLength === undefined
          ? 0
          : item.contentLength,
      ),
      contentSha1: kind === "upload" ? text(item.contentSha1) : "",
      uploadTimestamp: retentionInteger(item.uploadTimestamp, 1),
    });
  }

  async bucketVersionsPage(
    cursor: BackupV2Cursor | null,
    prefix?: string,
    signal?: AbortSignal,
  ): Promise<BackupV2VersionPage> {
    if (prefix !== undefined) retentionText(prefix, 1_000);
    const body = await this.#retentionRequest("b2_list_file_versions", {
      bucketId: this.#settings.bucketId,
      maxFileCount: LIMIT.listEntries,
      ...(prefix === undefined ? {} : { prefix }),
      ...(cursor
        ? {
          startFileName: retentionText(cursor.fileName, 1_000),
          startFileId: retentionText(cursor.fileId, 512),
        }
        : {}),
    }, signal);
    require(
      Array.isArray(body.files) && body.files.length <= LIMIT.listEntries,
      "retention version page exceeded",
    );
    const next = body.nextFileName === null && body.nextFileId === null
      ? null
      : {
        fileName: retentionText(body.nextFileName, 1_000),
        fileId: retentionText(body.nextFileId, 512),
      };
    const items = body.files.map((item) => this.#retentionVersion(item));
    require(
      prefix === undefined ||
        items.every((item) => item.fileName.startsWith(prefix)),
      "retention version name outside prefix",
    );
    return { items, next };
  }

  async unfinishedFilesPage(
    cursor: string | null,
    prefix?: string,
    signal?: AbortSignal,
  ): Promise<{
    items: Extract<BackupV2ListedVersion, { action: "start" }>[];
    next: string | null;
  }> {
    if (prefix !== undefined) retentionText(prefix, 1_000);
    const body = await this.#retentionRequest(
      "b2_list_unfinished_large_files",
      {
        bucketId: this.#settings.bucketId,
        maxFileCount: LIMIT.listEntries,
        ...(prefix === undefined ? {} : { namePrefix: prefix }),
        ...(cursor === null ? {} : { startFileId: retentionText(cursor, 512) }),
      },
      signal,
    );
    require(
      Array.isArray(body.files) && body.files.length <= LIMIT.listEntries,
      "retention unfinished page exceeded",
    );
    const items = body.files.map((item) => {
      const version = this.#retentionVersion(item, "start");
      require(version.action === "start", "unfinished version missing");
      require(
        prefix === undefined || version.fileName.startsWith(prefix),
        "unfinished name outside prefix",
      );
      return version;
    });
    return {
      items,
      next: body.nextFileId === null
        ? null
        : retentionText(body.nextFileId, 512),
    };
  }

  async unfinishedPartsPage(
    fileId: string,
    cursor: number | null,
    signal?: AbortSignal,
  ): Promise<{ items: BackupV2RetentionPart[]; next: number | null }> {
    retentionText(fileId, 512);
    const scope = await this.#retentionScope(signal);
    if (scope.keyScope === "unrestricted") {
      await this.#lookupUnfinished(scope, fileId, signal);
    }
    const body = await this.#request(
      `${scope.api}${API}b2_list_parts`,
      scope.token,
      {
        fileId,
        maxPartCount: LIMIT.listEntries,
        ...(cursor === null
          ? {}
          : { startPartNumber: retentionInteger(cursor, 1) }),
      },
      signal,
    );
    require(
      Array.isArray(body.parts) && body.parts.length <= LIMIT.listEntries,
      "retention parts page exceeded",
    );
    return {
      items: body.parts.map((value) => {
        const item = record(value);
        require(item.fileId === fileId, "part file ID mismatch");
        const contentSha1 = text(item.contentSha1);
        require(/^[a-f0-9]{40}$/.test(contentSha1), "part hash rejected");
        return {
          fileId,
          partNumber: retentionInteger(item.partNumber, 1),
          contentLength: retentionInteger(item.contentLength, 1),
          contentSha1,
          uploadTimestamp: retentionInteger(item.uploadTimestamp, 1),
        };
      }),
      next: body.nextPartNumber === null
        ? null
        : retentionInteger(body.nextPartNumber, 1),
    };
  }

  /** The retention executor has already reconciled exact current identity
   * against its immutable plan and fsynced intent before this single request. */
  async removeRetentionVersion(
    object: BackupV2RetentionVersion,
    signal?: AbortSignal,
    retiredResticPrefix?: string,
  ): Promise<void> {
    const fileName = retentionText(object.fileName, 1_000);
    const fileId = retentionText(object.fileId, 512);
    require(
      retentionOwnedName(fileName) !== null ||
        retiredResticPrefix !== undefined &&
          retentionOwnedResticName(fileName, retiredResticPrefix),
      "retention name not owned",
    );
    const scope = await this.#retentionScope(signal);
    if (object.action === "start") {
      if (scope.keyScope === "unrestricted") {
        const exact = await this.#lookupUnfinished(
          scope,
          fileId,
          signal,
          fileName,
        );
        require(
          exact.uploadTimestamp === object.uploadTimestamp,
          "unfinished upload timestamp mismatch",
        );
      }
      const body = await this.#request(
        `${scope.api}${API}b2_cancel_large_file`,
        scope.token,
        { fileId },
        signal,
      );
      require(
        body.fileId === fileId && body.fileName === fileName &&
          body.bucketId === this.#settings.bucketId,
        "CANCEL response binding mismatch",
      );
      return;
    }
    require(
      object.action === "upload" || object.action === "hide",
      "retention delete action rejected",
    );
    if (scope.keyScope === "unrestricted") {
      const row = await this.#lookupVersion(scope, object, signal);
      require(row, "retention version is absent");
      const current = this.#retentionVersion(row);
      require(
        current.action === object.action &&
          current.contentLength === object.contentLength &&
          current.contentSha1 === object.contentSha1 &&
          current.uploadTimestamp === object.uploadTimestamp,
        "retention version metadata mismatch",
      );
    }
    const body = await this.#request(
      `${scope.api}${API}b2_delete_file_version`,
      scope.token,
      { fileName, fileId },
      signal,
    );
    require(
      body.fileId === fileId && body.fileName === fileName &&
        (body.bucketId === undefined ||
          body.bucketId === this.#settings.bucketId),
      "DELETE response binding mismatch",
    );
  }
}
