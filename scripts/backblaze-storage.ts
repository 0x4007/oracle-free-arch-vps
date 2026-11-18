/**
 * B2 native API storage adapter for dedicated-bucket direct backups.
 *
 * Every object read or written by this client is one bounded encrypted chunk
 * under the exact DIRECT_PREFIX namespace. The caller owns encryption,
 * manifests, acceptance, retention and four-point selection: this client
 * never labels an object as a recovered backup, never enumerates or deletes
 * payload outside DIRECT_PREFIX (in particular the previous `restic/`
 * repository), and never retries an API request automatically, so a
 * caller-driven retry decides exactly how duplicates are reconciled.
 *
 * Credentials are validated before any network call and held in memory only.
 * Authorization must prove the exact deployed bucket and required capabilities.
 * A scoped writer must have prefix `restic/`. For an unrestricted key, the
 * client verifies the deployed bucket by name and each account-wide ID against
 * its bucket-scoped version listing. API and download endpoints use HTTPS
 * under backblazeb2.com. The v3 upload target from b2_get_upload_url is
 * restricted separately to HTTPS hosts under backblazeb2.com or
 * backblaze.com (the pod-* upload hosts) and must echo the authorized
 * bucketId. Every request rejects redirects, sends the authorization token
 * only in the Authorization header, and reports errors with operation plus
 * HTTP status without credentials, response bodies, token-bearing URLs or
 * raw provider errors.
 */

import { BACKUP_V2_LIMITS, BACKUP_V2_NAMESPACE } from "./backup-v2-profile.ts";
export const DIRECT_PREFIX = "restic/direct-v1/";

export const MAX_CHUNK_BYTES = 64 * 1024 * 1024;

/** Per-request B2 deadline. It covers the fetch and the response body read,
 * because the fetch signal stays live while the body is read; one 64 MiB
 * chunk at the 4 MiB/s transfer pace plus network overhead fits inside it.
 * Internal only: this is never a caller-visible option. */
const B2_REQUEST_TIMEOUT_MS = 120_000;
const REQUEST_SIGNALS = new WeakMap<Response, AbortSignal>();

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

export type B2CredentialReason =
  | "B2_CREDENTIAL_SETTINGS_INVALID"
  | "B2_RETENTION_CREDENTIAL_INVALID"
  | "B2_CREDENTIAL_SCOPE_REJECTED"
  | "B2_BUCKET_IDENTITY_MISMATCH"
  | "B2_CREDENTIAL_AUTH_UNPROVED";

/** Only fixed local descriptions may cross the credential/report boundary. */
export class B2CredentialError extends Error {
  constructor(readonly reason: B2CredentialReason, message: string) {
    super(message);
    this.name = "B2CredentialError";
  }
}

export type B2KeyPurpose = "backup" | "retention";
export type B2KeyScope = "scoped" | "unrestricted";

const B2_SETTINGS_FIELDS = [
  "accessKeyId",
  "secretAccessKey",
  "bucketId",
  "bucketName",
] as const;

export function b2SettingsFromConfig(value: unknown): B2Settings {
  const settings = Object.fromEntries(B2_SETTINGS_FIELDS.map((field) => [
    field,
    value && typeof value === "object" ? Reflect.get(value, field) : undefined,
  ])) as unknown as B2Settings;
  validateSettings(settings);
  return settings;
}

export async function selectB2RetentionCredential(
  writer: B2Settings,
  readOverride: () => Promise<unknown>,
): Promise<B2Settings> {
  validateSettings(writer);
  try {
    const value = await readOverride();
    if (value === undefined) return { ...writer };
    if (
      !value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== B2_SETTINGS_FIELDS.length ||
      !B2_SETTINGS_FIELDS.every((field) => Object.hasOwn(value, field))
    ) throw new Error("Invalid retention credential fields");
    const settings = b2SettingsFromConfig(value);
    if (
      settings.bucketName !== writer.bucketName ||
      settings.bucketId !== writer.bucketId
    ) throw new Error("Retention credential bucket mismatch");
    return settings;
  } catch {
    throw new B2CredentialError(
      "B2_RETENTION_CREDENTIAL_INVALID",
      "The explicit Backblaze retention credential is malformed, unreadable, or bound to a different bucket",
    );
  }
}

// Pure policy checks shared with the separately versioned, bounded v2 wire adapter.
export {
  assertBackblazeUrl as validateB2ApiUrl,
  assertUploadUrl as validateB2UploadUrl,
  basicAuthorization as b2BasicAuthorization,
  validateSettings as validateB2Settings,
  verifyAllowedScope as validateB2AllowedScope,
};

interface AuthorizedScope {
  token: string;
  apiUrl: string;
  downloadUrl: string;
  keyScope: B2KeyScope;
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
    throw new B2CredentialError(
      "B2_CREDENTIAL_SETTINGS_INVALID",
      "settings rejected: missing settings",
    );
  }
  for (const field of ["accessKeyId", "secretAccessKey", "bucketId"] as const) {
    const value = settings[field];
    if (
      typeof value !== "string" || value.length === 0 ||
      value.length > 8192 || /[\s:]/u.test(value) ||
      [...value].some((char) =>
        char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127
      )
    ) {
      throw new B2CredentialError(
        "B2_CREDENTIAL_SETTINGS_INVALID",
        `settings rejected: invalid or empty ${field}`,
      );
    }
  }
  if (settings.bucketName !== BUCKET_NAME) {
    throw new B2CredentialError(
      "B2_BUCKET_IDENTITY_MISMATCH",
      "settings rejected: backup bucket name does not match the deployment",
    );
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
    !allowedHost || url.pathname !== "/" || url.search || url.hash ||
    value !== url.origin
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

function assertObjectName(fileName: string, prefix = DIRECT_PREFIX): void {
  if (typeof fileName !== "string") {
    throw new Error("object name rejected: not a string");
  }
  if (fileName.length === 0) {
    throw new Error("object name rejected: empty");
  }
  if (!fileName.startsWith(prefix)) {
    throw new Error(`object name rejected: outside ${prefix}`);
  }
  const suffix = fileName.slice(prefix.length);
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

/** The deadline applies to every request, and a caller signal is composed with
 * it rather than replacing it (`init.signal ?? deadline` would silently drop
 * the deadline whenever a caller passes its own signal). The composed signal
 * stays live after the headers arrive, so the same bound covers the later
 * response body read. */
async function sendRequest(
  fetcher: B2Fetcher,
  operation: string,
  url: string,
  init: RequestInit,
): Promise<Response> {
  const deadline = AbortSignal.timeout(B2_REQUEST_TIMEOUT_MS);
  const signal = init.signal === null || init.signal === undefined
    ? deadline
    : AbortSignal.any([init.signal, deadline]);
  try {
    const response = await fetcher(url, { ...init, signal, redirect: "error" });
    REQUEST_SIGNALS.set(response, signal);
    return response;
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
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    if (response.body === null) throw invalidResponse(operation);
    for await (const chunk of response.body) {
      bytes += chunk.length;
      if (bytes > BACKUP_V2_LIMITS.controlResponseBytes) {
        throw invalidResponse(operation);
      }
      chunks.push(chunk);
    }
  } catch {
    throw new Error(`${operation} failed (HTTP ${status}): unreadable body`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(
        joinChunks(chunks, bytes),
      ),
    );
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
  purpose: B2KeyPurpose = "backup",
): B2KeyScope {
  const reject = (detail: string): never => {
    throw new B2CredentialError(
      "B2_CREDENTIAL_SCOPE_REJECTED",
      `${operation} failed: ${detail}`,
    );
  };
  const capabilities = stringArray(allowed["capabilities"]);
  if (capabilities === null) return reject("invalid response (capabilities)");
  const requiredCapabilities = purpose === "retention"
    ? ["listFiles", "writeFiles", "deleteFiles"]
    : REQUIRED_CAPABILITIES;
  for (const required of requiredCapabilities) {
    if (!capabilities.includes(required)) {
      return reject(`capability ${required} not granted`);
    }
  }
  const bucketsValue = allowed["buckets"];
  if (
    bucketsValue === null ||
    (Array.isArray(bucketsValue) && bucketsValue.length === 0)
  ) {
    if (!capabilities.includes("listBuckets")) {
      return reject(
        "bucket scope missing and capability listBuckets not granted",
      );
    }
    if (allowed["namePrefix"] !== null) {
      return reject("allowed namePrefix rejected");
    }
    return "unrestricted";
  }
  if (
    allowed["namePrefix"] !==
      (purpose === "retention" ? null : ALLOWED_NAME_PREFIX)
  ) {
    return reject("allowed namePrefix rejected");
  }
  let buckets;
  try {
    buckets = bucketScope(operation, allowed);
  } catch {
    return reject("bucket scope missing or malformed");
  }
  if (buckets.length !== 1) {
    return reject("scope must contain exactly one bucket");
  }
  const exact = buckets[0];
  if (exact.id !== settings.bucketId || exact.name !== BUCKET_NAME) {
    throw new B2CredentialError(
      "B2_BUCKET_IDENTITY_MISMATCH",
      `${operation} failed: bucket scope mismatch`,
    );
  }
  return "scoped";
}

/** The filter comes from the deployment, never from supplied bucket settings. */
export function b2BucketLookup(accountId: string): JsonRecord {
  return { accountId, bucketName: BUCKET_NAME };
}

export function validateB2BucketLookup(
  value: JsonRecord,
  accountId: string,
  settings: B2Settings,
): void {
  const buckets = value["buckets"];
  const entry = Array.isArray(buckets) && buckets.length === 1
    ? buckets[0]
    : null;
  if (
    !entry || typeof entry !== "object" || Array.isArray(entry) ||
    entry.accountId !== accountId || entry.bucketId !== settings.bucketId ||
    entry.bucketName !== BUCKET_NAME
  ) {
    throw new B2CredentialError(
      "B2_BUCKET_IDENTITY_MISMATCH",
      "b2_list_buckets failed: exact backup bucket identity is unproved",
    );
  }
}

async function authorizeAccount(
  settings: B2Settings,
  fetcher: B2Fetcher,
): Promise<AuthorizedScope> {
  const operation = "b2_authorize_account";
  try {
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
    const keyScope = verifyAllowedScope(operation, settings, allowed);
    if (keyScope === "unrestricted") {
      const accountId = requiredString(operation, body, "accountId");
      const lookup = "b2_list_buckets";
      validateB2BucketLookup(
        await sendJson(
          fetcher,
          lookup,
          `${apiUrl}${API_PATH}${lookup}`,
          token,
          b2BucketLookup(accountId),
        ),
        accountId,
        settings,
      );
    }
    return { token, apiUrl, downloadUrl, keyScope };
  } catch (error) {
    if (error instanceof B2CredentialError) throw error;
    throw new B2CredentialError(
      "B2_CREDENTIAL_AUTH_UNPROVED",
      error instanceof Error ? error.message : "Backblaze authorization failed",
    );
  }
}

/** Authenticate and prove the expected role without touching any objects. */
export const B2_VERSION_LOOKUP = "b2_list_file_versions";
type B2VersionPointer = Pick<B2Object, "fileId" | "fileName">;

export function b2ExactVersionRequest(
  bucketId: string,
  { fileId, fileName }: B2VersionPointer,
): JsonRecord {
  return {
    bucketId,
    prefix: fileName,
    startFileName: fileName,
    startFileId: fileId,
    maxFileCount: 1,
  };
}

/** Backblaze returns the requested name and ID first if the version exists.
 * A foreign-bucket ID can therefore never reach an account-wide ID endpoint. */
export function validateB2ExactVersionLookup(
  value: JsonRecord,
  bucketId: string,
  expected: B2VersionPointer,
): JsonRecord | null {
  const { files, nextFileName, nextFileId } = value;
  if (
    !Array.isArray(files) || files.length > 1 ||
    !(nextFileName === null && nextFileId === null ||
      files.length === 1 && typeof nextFileName === "string" && nextFileName &&
        typeof nextFileId === "string" && nextFileId)
  ) throw invalidResponse(B2_VERSION_LOOKUP);
  if (!files.length) return null;
  const row = expectRecord(B2_VERSION_LOOKUP, files[0]);
  const name = requiredString(B2_VERSION_LOOKUP, row, "fileName");
  const id = requiredString(B2_VERSION_LOOKUP, row, "fileId");
  if (row.bucketId !== bucketId || !name.startsWith(expected.fileName)) {
    throw operationError(B2_VERSION_LOOKUP, "exact lookup scope mismatch");
  }
  if (id !== expected.fileId) return null;
  if (name !== expected.fileName) {
    throw operationError(B2_VERSION_LOOKUP, "version name mismatch");
  }
  return row;
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
  prefix = DIRECT_PREFIX,
): B2Object {
  const item = expectRecord(operation, value);
  const fileName = requiredString(operation, item, "fileName");
  // Any item outside the exact namespace fails the whole listing.
  assertObjectName(fileName, prefix);
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

function matchesDownloadName(response: Response, name: string): boolean {
  try {
    return decodeURIComponent(response.headers.get("x-bz-file-name") ?? "") ===
      name;
  } catch {
    return false;
  }
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

  async #proveExact(
    scope: AuthorizedScope,
    object: B2Object,
  ): Promise<void> {
    if (scope.keyScope === "scoped") return;
    const row = validateB2ExactVersionLookup(
      await sendJson(
        this.#fetch,
        B2_VERSION_LOOKUP,
        `${scope.apiUrl}${API_PATH}${B2_VERSION_LOOKUP}`,
        scope.token,
        b2ExactVersionRequest(this.#settings.bucketId, object),
      ),
      this.#settings.bucketId,
      object,
    );
    if (!row) throw operationError(B2_VERSION_LOOKUP, "version is absent");
    const listed = listedObject(
      B2_VERSION_LOOKUP,
      this.#settings.bucketId,
      row,
    );
    if (
      listed.action !== object.action ||
      listed.contentLength !== object.contentLength ||
      listed.contentSha1 !== object.contentSha1 ||
      listed.uploadTimestamp !== object.uploadTimestamp
    ) throw operationError(B2_VERSION_LOOKUP, "version metadata mismatch");
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
    await this.#proveExact(scope, object);
    const operation = "b2_download_file_by_id";
    const url = `${scope.downloadUrl}${API_PATH}b2_download_file_by_id?fileId=${
      encodeURIComponent(object.fileId)
    }`;
    const requestStarted = performance.now();
    const response = await sendRequest(this.#fetch, operation, url, {
      headers: { authorization: scope.token },
    });
    if (!response.ok) await failHttp(operation, response);
    if (
      scope.keyScope === "unrestricted" &&
      (response.headers.get("x-bz-file-id") !== object.fileId ||
        !matchesDownloadName(response, object.fileName) ||
        response.headers.get("x-bz-content-sha1") !== object.contentSha1)
    ) {
      await cancelBody(response);
      throw operationError(operation, "response binding mismatch");
    }
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
        } catch (error) {
          // Never log provider messages, URLs, tokens, file ids or stacks.
          const safeName = (value: unknown): string => {
            const name = value instanceof Error ? value.name : "";
            return ["TimeoutError", "AbortError", "TypeError"].includes(name)
              ? name
              : "Other";
          };
          const signal = REQUEST_SIGNALS.get(response);
          console.error(`[readback-failure] ${
            JSON.stringify({
              operation,
              category: "body read failed",
              elapsedMs: Math.round(performance.now() - requestStarted),
              receivedBytes: total,
              expectedBytes: object.contentLength,
              signalAborted: signal?.aborted ?? null,
              abortReason: signal?.aborted ? safeName(signal.reason) : null,
              exceptionName: safeName(error),
            })
          }`);
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

  /** Read-only inventory of one exact backup namespace. Writes stay v1-only. */
  async versions(prefix = DIRECT_PREFIX): Promise<B2Object[]> {
    if (prefix !== DIRECT_PREFIX && prefix !== BACKUP_V2_NAMESPACE) {
      throw new Error("versions failed: namespace rejected");
    }
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
        prefix,
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
        found.push(
          listedObject(operation, this.#settings.bucketId, item, prefix),
        );
        if (
          prefix === BACKUP_V2_NAMESPACE &&
          found.length > BACKUP_V2_LIMITS.pruneCandidates
        ) throw operationError(operation, "version inventory bound");
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
      assertObjectName(nextFileName as string, prefix);
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
    await this.#proveExact(scope, object);
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
    if (
      returnedName !== object.fileName || returnedId !== object.fileId ||
      (body.bucketId !== undefined && body.bucketId !== this.#settings.bucketId)
    ) {
      throw operationError(operation, "response mismatch");
    }
  }
}
