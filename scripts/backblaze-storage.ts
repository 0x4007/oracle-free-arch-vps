/**
 * B2 native API storage adapter for dedicated-bucket direct backups.
 *
 * Every object read or written by this client is one bounded encrypted chunk
 * under the exact DIRECT_PREFIX namespace. The caller owns encryption,
 * manifests, acceptance, retention and four-point selection: this client
 * never labels an object as a recovered backup, never enumerates or deletes
 * anything outside DIRECT_PREFIX (in particular the previous `restic/`
 * repository), and never retries an API request automatically, so a
 * caller-driven retry decides exactly how duplicates are reconciled.
 *
 * Credentials are validated before any network call and held in memory only.
 * Authorization must prove exactly one bucket (id and name), the required
 * capabilities and namePrefix `restic/`, with HTTPS api/download endpoints
 * under backblazeb2.com. The v3 upload target from b2_get_upload_url is
 * restricted separately to HTTPS hosts under backblazeb2.com or
 * backblaze.com (the pod-* upload hosts) and must echo the authorized
 * bucketId. Every request rejects redirects, sends the authorization token
 * only in the Authorization header, and reports errors with operation plus
 * HTTP status without credentials, response bodies, token-bearing URLs or
 * raw provider errors.
 */

export const DIRECT_PREFIX = "restic/direct-v1/";

export const MAX_CHUNK_BYTES = 64 * 1024 * 1024;

const BUCKET_NAME = "pavlovcik-arch-vps-backups";
const AUTH_URL = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account";
const API_PATH = "/b2api/v3/";
const REQUIRED_CAPABILITIES = [
  "listFiles",
  "readFiles",
  "writeFiles",
  "deleteFiles",
] as const;
const ALLOWED_NAME_PREFIX = "restic/";
const MAX_OBJECT_NAME_BYTES = 1000;
const LIST_PAGE_SIZE = 1000;
const MAX_LIST_PAGES = 10000;
const SHA1_PATTERN = /^[0-9a-f]{40}$/;

export interface B2Settings {
  accessKeyId: string;
  secretAccessKey: string;
  bucketId: string;
  bucketName: string;
}

export interface B2Object {
  fileId: string;
  fileName: string;
  contentLength: number;
  contentSha1: string;
  action: string;
  uploadTimestamp: number;
}

export type B2Fetcher = typeof fetch;

interface AuthorizedScope {
  token: string;
  apiUrl: string;
  downloadUrl: string;
}

interface UploadTarget {
  url: string;
  token: string;
}

type JsonRecord = Record<string, unknown>;

function operationError(operation: string, reason: string): Error {
  return new Error(`${operation} failed: ${reason}`);
}

function invalidResponse(operation: string, field?: string): Error {
  if (field === undefined) return operationError(operation, "invalid response");
  return operationError(operation, `invalid response (${field})`);
}

function expectRecord(operation: string, value: unknown): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidResponse(operation);
  }
  return value as JsonRecord;
}

function requiredString(
  operation: string,
  record: JsonRecord,
  field: string,
): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw invalidResponse(operation, field);
  }
  return value;
}

function requiredNumber(
  operation: string,
  record: JsonRecord,
  field: string,
): number {
  const value = record[field];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw invalidResponse(operation, field);
  }
  return value;
}

function stringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const entries: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") return null;
    entries.push(entry);
  }
  return entries;
}

function validateSettings(settings: B2Settings): void {
  if (typeof settings !== "object" || settings === null) {
    throw new Error("settings rejected: missing settings");
  }
  if (
    typeof settings.accessKeyId !== "string" ||
    settings.accessKeyId.length === 0
  ) {
    throw new Error("settings rejected: empty accessKeyId");
  }
  if (
    typeof settings.secretAccessKey !== "string" ||
    settings.secretAccessKey.length === 0
  ) {
    throw new Error("settings rejected: empty secretAccessKey");
  }
  if (typeof settings.bucketId !== "string" || settings.bucketId.length === 0) {
    throw new Error("settings rejected: empty bucketId");
  }
  if (settings.bucketName !== BUCKET_NAME) {
    throw new Error(`settings rejected: bucketName must be ${BUCKET_NAME}`);
  }
}

function basicAuthorization(settings: B2Settings): string {
  const raw = new TextEncoder().encode(
    `${settings.accessKeyId}:${settings.secretAccessKey}`,
  );
  let binary = "";
  for (const byte of raw) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

function assertBackblazeUrl(
  operation: string,
  label: string,
  value: string,
): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw operationError(operation, `${label} is not a valid URL`);
  }
  const host = url.hostname.toLowerCase();
  const allowedHost = host === "backblazeb2.com" ||
    host.endsWith(".backblazeb2.com");
  if (
    url.protocol !== "https:" || url.username !== "" ||
    url.password !== "" || (url.port !== "" && url.port !== "443") ||
    !allowedHost
  ) {
    throw operationError(operation, `${label} host rejected`);
  }
}

function assertUploadUrl(
  operation: string,
  label: string,
  value: string,
): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw operationError(operation, `${label} is not a valid URL`);
  }
  const host = url.hostname.toLowerCase();
  // Production upload targets are HTTPS pod-*.backblaze.com (newer) or
  // pod-*.backblazeb2.com (legacy) hosts. The host must be a subdomain:
  // lookalikes such as pod.backblaze.com.evil.test do not end with
  // .backblaze.com and are rejected below.
  const allowedHost = host.endsWith(".backblaze.com") ||
    host.endsWith(".backblazeb2.com");
  if (
    url.protocol !== "https:" || url.username !== "" ||
    url.password !== "" || (url.port !== "" && url.port !== "443") ||
    !allowedHost
  ) {
    throw operationError(operation, `${label} host rejected`);
  }
}

function assertObjectName(fileName: string): void {
  if (typeof fileName !== "string") {
    throw new Error("object name rejected: not a string");
  }
  if (fileName.length === 0) {
    throw new Error("object name rejected: empty");
  }
  if (!fileName.startsWith(DIRECT_PREFIX)) {
    throw new Error(`object name rejected: outside ${DIRECT_PREFIX}`);
  }
  const suffix = fileName.slice(DIRECT_PREFIX.length);
  if (suffix.length === 0) {
    throw new Error("object name rejected: empty suffix");
  }
  if (fileName.includes("\\")) {
    throw new Error("object name rejected: backslash");
  }
  if (fileName.includes("%")) {
    throw new Error("object name rejected: percent-encoded characters");
  }
  for (const segment of suffix.split("/")) {
    if (segment === "" || segment === "." || segment === "..") {
      throw new Error("object name rejected: unsafe path segment");
    }
  }
  const byteLength = new TextEncoder().encode(fileName).byteLength;
  if (byteLength > MAX_OBJECT_NAME_BYTES) {
    throw new Error("object name rejected: too long");
  }
}

async function sha1Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return [...new Uint8Array(digest)].map((byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function cancelBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The connection is already unusable; only the status matters.
  }
}

async function failHttp(operation: string, response: Response): Promise<never> {
  await cancelBody(response);
  throw new Error(`${operation} failed (HTTP ${response.status})`);
}

async function sendRequest(
  fetcher: B2Fetcher,
  operation: string,
  url: string,
  init: RequestInit,
): Promise<Response> {
  try {
    return await fetcher(url, { ...init, redirect: "error" });
  } catch {
    // The provider error, URL or token is never included in the message.
    throw new Error(`${operation} failed (network error)`);
  }
}

async function readJson(
  operation: string,
  response: Response,
): Promise<JsonRecord> {
  const status = response.status;
  let text: string;
  try {
    text = await response.text();
  } catch {
    throw new Error(`${operation} failed (HTTP ${status}): unreadable body`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${operation} failed (HTTP ${status}): invalid body`);
  }
  return expectRecord(operation, parsed);
}

async function sendJson(
  fetcher: B2Fetcher,
  operation: string,
  url: string,
  token: string,
  payload: JsonRecord,
): Promise<JsonRecord> {
  const response = await sendRequest(fetcher, operation, url, {
    method: "POST",
    headers: {
      authorization: token,
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) await failHttp(operation, response);
  return readJson(operation, response);
}

function bucketScope(
  operation: string,
  allowed: JsonRecord,
): Array<{ id: string; name: string }> {
  // The v4 contract authorizes buckets through allowed.buckets only. The
  // legacy top-level bucketId/bucketName shape is not accepted, even when
  // its values match the expected bucket.
  const bucketsValue = allowed["buckets"];
  if (!Array.isArray(bucketsValue) || bucketsValue.length === 0) {
    throw operationError(operation, "bucket scope missing");
  }
  const buckets: Array<{ id: string; name: string }> = [];
  for (const entry of bucketsValue) {
    const record = expectRecord(operation, entry);
    buckets.push({
      id: requiredString(operation, record, "id"),
      name: requiredString(operation, record, "name"),
    });
  }
  return buckets;
}

function verifyAllowedScope(
  operation: string,
  settings: B2Settings,
  allowed: JsonRecord,
): void {
  const capabilities = stringArray(allowed["capabilities"]);
  if (capabilities === null) throw invalidResponse(operation, "capabilities");
  for (const required of REQUIRED_CAPABILITIES) {
    if (!capabilities.includes(required)) {
      throw operationError(operation, `capability ${required} not granted`);
    }
  }
  if (allowed["namePrefix"] !== ALLOWED_NAME_PREFIX) {
    throw operationError(operation, "allowed namePrefix rejected");
  }
  const buckets = bucketScope(operation, allowed);
  if (buckets.length !== 1) {
    throw operationError(operation, "scope must contain exactly one bucket");
  }
  const exact = buckets[0];
  if (exact.id !== settings.bucketId || exact.name !== BUCKET_NAME) {
    throw operationError(operation, "bucket scope mismatch");
  }
}

async function authorizeAccount(
  settings: B2Settings,
  fetcher: B2Fetcher,
): Promise<AuthorizedScope> {
  const operation = "b2_authorize_account";
  const response = await sendRequest(fetcher, operation, AUTH_URL, {
    headers: { authorization: basicAuthorization(settings) },
  });
  if (!response.ok) await failHttp(operation, response);
  const body = await readJson(operation, response);
  const token = requiredString(operation, body, "authorizationToken");
  const apiInfo = expectRecord(operation, body["apiInfo"]);
  const storageApi = expectRecord(operation, apiInfo["storageApi"]);
  const apiUrl = requiredString(operation, storageApi, "apiUrl");
  const downloadUrl = requiredString(operation, storageApi, "downloadUrl");
  const allowed = expectRecord(operation, storageApi["allowed"]);
  assertBackblazeUrl(operation, "apiUrl", apiUrl);
  assertBackblazeUrl(operation, "downloadUrl", downloadUrl);
  verifyAllowedScope(operation, settings, allowed);
  return { token, apiUrl, downloadUrl };
}

function markerNonnegativeIntegerOrDefault(
  operation: string,
  item: JsonRecord,
  field: string,
): number {
  const value = item[field];
  // B2 omits (returns null for) the content fields of a start marker for an
  // incomplete large file upload. Only that absent/null case takes the safe
  // zero default; any present value must still be a nonnegative integer.
  if (value === undefined || value === null) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw invalidResponse(operation, field);
  }
  return value;
}

function markerSha1OrDefault(
  operation: string,
  item: JsonRecord,
): string {
  const value = item["contentSha1"];
  if (value === undefined || value === null) return "";
  if (typeof value !== "string" || !SHA1_PATTERN.test(value)) {
    throw invalidResponse(operation, "contentSha1");
  }
  return value;
}

function listedObject(
  operation: string,
  bucketId: string,
  value: unknown,
): B2Object {
  const item = expectRecord(operation, value);
  const fileName = requiredString(operation, item, "fileName");
  // Any item outside the exact namespace fails the whole listing.
  assertObjectName(fileName);
  const fileId = requiredString(operation, item, "fileId");
  const action = requiredString(operation, item, "action");
  if (action !== "upload" && action !== "hide" && action !== "start") {
    throw operationError(operation, "unexpected action");
  }
  if (requiredString(operation, item, "bucketId") !== bucketId) {
    throw operationError(operation, "bucket mismatch");
  }
  if (action === "start") {
    // An incomplete large file upload is inventory only: this client performs
    // regular chunk uploads and never resumes multipart uploads, so start
    // markers get safe zero content defaults and can never be used for
    // download or removal.
    return {
      fileId,
      fileName,
      contentLength: markerNonnegativeIntegerOrDefault(
        operation,
        item,
        "contentLength",
      ),
      contentSha1: markerSha1OrDefault(operation, item),
      action,
      uploadTimestamp: markerNonnegativeIntegerOrDefault(
        operation,
        item,
        "uploadTimestamp",
      ),
    };
  }
  const contentLength = requiredNumber(operation, item, "contentLength");
  if (
    !Number.isInteger(contentLength) || contentLength < 0 ||
    contentLength > MAX_CHUNK_BYTES
  ) {
    throw invalidResponse(operation, "contentLength");
  }
  const contentSha1 = requiredString(operation, item, "contentSha1");
  if (!SHA1_PATTERN.test(contentSha1)) {
    throw invalidResponse(operation, "contentSha1");
  }
  const uploadTimestamp = requiredNumber(operation, item, "uploadTimestamp");
  if (!Number.isInteger(uploadTimestamp) || uploadTimestamp < 0) {
    throw invalidResponse(operation, "uploadTimestamp");
  }
  return {
    fileId,
    fileName,
    contentLength,
    contentSha1,
    action,
    uploadTimestamp,
  };
}

function joinChunks(
  chunks: Uint8Array[],
  total: number,
): Uint8Array<ArrayBuffer> {
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return joined;
}

export class B2Store {
  readonly #settings: B2Settings;
  readonly #fetch: B2Fetcher;
  #scope: Promise<AuthorizedScope> | null = null;

  constructor(settings: B2Settings, fetcher: B2Fetcher = fetch) {
    validateSettings(settings);
    // Snapshot the validated string fields so later mutation of the caller's
    // settings object cannot change the bucket or credentials used by an
    // authorized operation.
    this.#settings = {
      accessKeyId: settings.accessKeyId,
      secretAccessKey: settings.secretAccessKey,
      bucketId: settings.bucketId,
      bucketName: settings.bucketName,
    };
    this.#fetch = fetcher;
  }

  /** Fetch and verify the v4 scoped authorization; rejects on any mismatch. */
  async authorize(): Promise<void> {
    await this.#authorizeOnce();
  }

  async #authorizeOnce(): Promise<AuthorizedScope> {
    const current = this.#scope;
    if (current !== null) return current;
    const pending = authorizeAccount(this.#settings, this.#fetch);
    this.#scope = pending;
    try {
      return await pending;
    } catch (error) {
      if (this.#scope === pending) this.#scope = null;
      throw error;
    }
  }

  async #uploadUrl(scope: AuthorizedScope): Promise<UploadTarget> {
    const operation = "b2_get_upload_url";
    const body = await sendJson(
      this.#fetch,
      operation,
      `${scope.apiUrl}${API_PATH}b2_get_upload_url`,
      scope.token,
      {
        bucketId: this.#settings.bucketId,
      },
    );
    const url = requiredString(operation, body, "uploadUrl");
    const token = requiredString(operation, body, "authorizationToken");
    assertUploadUrl(operation, "uploadUrl", url);
    // Never send an encrypted payload to a target that does not echo the
    // authorized bucket.
    if (
      requiredString(operation, body, "bucketId") !==
        this.#settings.bucketId
    ) {
      throw operationError(operation, "bucket mismatch");
    }
    return { url, token };
  }

  async #upload(
    target: UploadTarget,
    fileName: string,
    bytes: Uint8Array<ArrayBuffer>,
    contentSha1: string,
  ): Promise<B2Object> {
    const operation = "b2_upload_file";
    const response = await sendRequest(this.#fetch, operation, target.url, {
      method: "POST",
      headers: {
        authorization: target.token,
        "content-type": "application/octet-stream",
        "content-length": String(bytes.byteLength),
        "x-bz-file-name": encodeURIComponent(fileName),
        "x-bz-content-sha1": contentSha1,
      },
      body: bytes,
    });
    if (!response.ok) await failHttp(operation, response);
    const body = await readJson(operation, response);
    const fileId = requiredString(operation, body, "fileId");
    const returnedName = requiredString(operation, body, "fileName");
    const returnedSha1 = requiredString(operation, body, "contentSha1");
    const returnedLength = requiredNumber(operation, body, "contentLength");
    const returnedAction = requiredString(operation, body, "action");
    const returnedBucket = requiredString(operation, body, "bucketId");
    const uploadTimestamp = requiredNumber(operation, body, "uploadTimestamp");
    if (returnedAction !== "upload") {
      throw operationError(operation, "unexpected action");
    }
    if (returnedBucket !== this.#settings.bucketId) {
      throw operationError(operation, "bucket mismatch");
    }
    if (returnedName !== fileName) {
      throw operationError(operation, "file name mismatch");
    }
    if (returnedLength !== bytes.byteLength) {
      throw operationError(operation, "content length mismatch");
    }
    if (returnedSha1 !== contentSha1) {
      throw operationError(operation, "content sha1 mismatch");
    }
    return {
      fileId,
      fileName,
      contentLength: returnedLength,
      contentSha1: returnedSha1,
      action: returnedAction,
      uploadTimestamp,
    };
  }

  /** Upload one bounded encrypted chunk; zero length through MAX_CHUNK_BYTES. */
  async put(
    fileName: string,
    bytes: Uint8Array<ArrayBuffer>,
  ): Promise<B2Object> {
    assertObjectName(fileName);
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("put failed: chunk is not bytes");
    }
    if (bytes.byteLength > MAX_CHUNK_BYTES) {
      throw new Error(`put failed: chunk exceeds ${MAX_CHUNK_BYTES} bytes`);
    }
    const scope = await this.#authorizeOnce();
    const contentSha1 = await sha1Hex(bytes);
    const target = await this.#uploadUrl(scope);
    return this.#upload(target, fileName, bytes, contentSha1);
  }

  /** Download one upload-version chunk and verify length and SHA-1. */
  async get(object: B2Object): Promise<Uint8Array> {
    assertObjectName(object.fileName);
    if (object.action !== "upload") {
      throw new Error("get failed: object is not an upload");
    }
    if (typeof object.fileId !== "string" || object.fileId.length === 0) {
      throw new Error("get failed: empty file id");
    }
    if (
      typeof object.contentLength !== "number" ||
      !Number.isInteger(object.contentLength) || object.contentLength < 0 ||
      object.contentLength > MAX_CHUNK_BYTES
    ) {
      throw new Error("get failed: content length outside chunk bounds");
    }
    if (
      typeof object.contentSha1 !== "string" ||
      !SHA1_PATTERN.test(object.contentSha1)
    ) {
      throw new Error("get failed: invalid content sha1");
    }
    const scope = await this.#authorizeOnce();
    const operation = "b2_download_file_by_id";
    const url = `${scope.downloadUrl}${API_PATH}b2_download_file_by_id?fileId=${
      encodeURIComponent(object.fileId)
    }`;
    const response = await sendRequest(this.#fetch, operation, url, {
      headers: { authorization: scope.token },
    });
    if (!response.ok) await failHttp(operation, response);
    const declaredLength = response.headers.get("content-length");
    if (declaredLength !== null) {
      const declared = Number(declaredLength);
      if (!Number.isInteger(declared) || declared !== object.contentLength) {
        await cancelBody(response);
        throw operationError(operation, "content length mismatch");
      }
    }
    const body = response.body;
    if (body === null) throw operationError(operation, "missing body");
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        let next: ReadableStreamReadResult<Uint8Array>;
        try {
          next = await reader.read();
        } catch {
          // A provider stream error may embed tokens, URLs or response
          // bodies; surface only the fixed operation error.
          throw operationError(operation, "body read failed");
        }
        if (next.done) break;
        const chunk = next.value;
        if (chunk === undefined) {
          throw operationError(operation, "empty read");
        }
        total += chunk.byteLength;
        if (total > MAX_CHUNK_BYTES) {
          throw operationError(operation, "body exceeds chunk limit");
        }
        chunks.push(chunk);
      }
      if (total !== object.contentLength) {
        throw operationError(operation, "content length mismatch");
      }
    } catch (error) {
      // Always cancel an overflow or failed body; never retry it.
      try {
        await reader.cancel();
      } catch {
        // The body is already unusable.
      }
      throw error;
    }
    const bytes = joinChunks(chunks, total);
    const actualSha1 = await sha1Hex(bytes);
    if (actualSha1 !== object.contentSha1) {
      throw operationError(operation, "content sha1 mismatch");
    }
    return bytes;
  }

  /** List every version under DIRECT_PREFIX, including hide and start markers. */
  async versions(): Promise<B2Object[]> {
    const scope = await this.#authorizeOnce();
    const operation = "b2_list_file_versions";
    const found: B2Object[] = [];
    let startFileName: string | undefined;
    let startFileId: string | undefined;
    const requestedCursors = new Set<string>();
    let pages = 0;
    while (true) {
      pages += 1;
      const payload: JsonRecord = {
        bucketId: this.#settings.bucketId,
        prefix: DIRECT_PREFIX,
        maxFileCount: LIST_PAGE_SIZE,
      };
      if (startFileName !== undefined) {
        payload["startFileName"] = startFileName;
        payload["startFileId"] = startFileId;
      }
      const body = await sendJson(
        this.#fetch,
        operation,
        `${scope.apiUrl}${API_PATH}b2_list_file_versions`,
        scope.token,
        payload,
      );
      const filesValue = body["files"];
      if (!Array.isArray(filesValue)) {
        throw invalidResponse(operation, "files");
      }
      for (const item of filesValue) {
        found.push(listedObject(operation, this.#settings.bucketId, item));
      }
      const nextFileName = body["nextFileName"];
      const nextFileId = body["nextFileId"];
      const hasNext = typeof nextFileName === "string" &&
        nextFileName.length > 0;
      const hasNextId = typeof nextFileId === "string" && nextFileId.length > 0;
      if (!hasNext && !hasNextId) break;
      if (!hasNext || !hasNextId) {
        throw operationError(operation, "incomplete continuation");
      }
      if (pages >= MAX_LIST_PAGES) {
        throw operationError(operation, "more than 10000 pages");
      }
      const cursor = JSON.stringify([nextFileName, nextFileId]);
      if (requestedCursors.has(cursor)) {
        throw operationError(operation, "repeated continuation cursor");
      }
      requestedCursors.add(cursor);
      startFileName = nextFileName;
      startFileId = nextFileId;
    }
    return found;
  }

  /** Delete exactly one file version; the response must echo name and id. */
  async remove(object: B2Object): Promise<void> {
    assertObjectName(object.fileName);
    // start markers need the separate b2_cancel_large_file API; this client
    // never cancels multipart uploads, so refuse before any network call.
    if (object.action !== "upload" && object.action !== "hide") {
      throw new Error("remove failed: object is not an upload or hide marker");
    }
    if (typeof object.fileId !== "string" || object.fileId.length === 0) {
      throw new Error("remove failed: empty file id");
    }
    const scope = await this.#authorizeOnce();
    const operation = "b2_delete_file_version";
    const body = await sendJson(
      this.#fetch,
      operation,
      `${scope.apiUrl}${API_PATH}b2_delete_file_version`,
      scope.token,
      {
        fileName: object.fileName,
        fileId: object.fileId,
      },
    );
    const returnedName = requiredString(operation, body, "fileName");
    const returnedId = requiredString(operation, body, "fileId");
    if (returnedName !== object.fileName || returnedId !== object.fileId) {
      throw operationError(operation, "response mismatch");
    }
  }
}
