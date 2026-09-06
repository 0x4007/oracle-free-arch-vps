/** Mocked-transport tests for the dedicated-bucket B2 storage client.
 *
 * All responses are synthetic; nothing here reaches the network, and no
 * credential value from the environment is read. The fakes replicate real
 * B2 v3/v4 request and response shapes so the client's scope checks,
 * validation and error redaction are exercised end to end.
 */
import {
  type B2Fetcher,
  type B2Object,
  type B2Settings,
  B2Store,
  DIRECT_PREFIX,
  MAX_CHUNK_BYTES,
} from "../scripts/backblaze-storage.ts";

const BUCKET_ID = "0000000000000001";
const BUCKET_NAME = "pavlovcik-arch-vps-backups";
const ACCESS_KEY_ID = "key-id-abc";
const SECRET_ACCESS_KEY = "secret-xyz";
const ACCOUNT_TOKEN = "account-authorization-token";
const API_URL = "https://api001.backblazeb2.com";
const DOWNLOAD_URL = "https://f001.backblazeb2.com";
const UPLOAD_URL =
  "https://pod-050-1027-00.backblaze.com/b2api/v3/b2_upload_file";
const AUTH_URL = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account";

function assert(condition: unknown, message?: string): asserts condition {
  if (!condition) throw new Error(message ?? "assertion failed");
}

function assertThrows(fn: () => unknown): Error {
  try {
    fn();
  } catch (error) {
    if (error instanceof Error) return error;
    throw new Error("expected an Error");
  }
  throw new Error("expected a throw");
}

async function rejectWith(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof Error) return error;
    throw new Error("expected an Error");
  }
  throw new Error("expected a rejection");
}

function assertBytes(actual: Uint8Array, expected: Uint8Array): void {
  assert(actual.byteLength === expected.byteLength, "byte length mismatch");
  for (let i = 0; i < expected.byteLength; i += 1) {
    assert(actual[i] === expected[i], `byte ${i} mismatch`);
  }
}

async function sha1Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return [...new Uint8Array(digest)].map((byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function settings(overrides: Partial<B2Settings> = {}): B2Settings {
  return {
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    bucketId: BUCKET_ID,
    bucketName: BUCKET_NAME,
    ...overrides,
  };
}

function chunkObject(
  fileName = `${DIRECT_PREFIX}2026-09-05/chunk-001`,
  overrides: Partial<B2Object> = {},
): B2Object {
  return {
    fileId: "file-1",
    fileName,
    contentLength: 3,
    contentSha1: "1111111111111111111111111111111111111111",
    action: "upload",
    uploadTimestamp: 1753500000000,
    ...overrides,
  };
}

function authBody(
  allowedOverrides: Record<string, unknown> = {},
  storageOverrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    accountId: "account-id",
    authorizationToken: ACCOUNT_TOKEN,
    apiInfo: {
      storageApi: {
        apiUrl: API_URL,
        downloadUrl: DOWNLOAD_URL,
        allowed: {
          buckets: [{ id: BUCKET_ID, name: BUCKET_NAME }],
          capabilities: ["listFiles", "readFiles", "writeFiles", "deleteFiles"],
          namePrefix: "restic/",
          ...allowedOverrides,
        },
        ...storageOverrides,
      },
    },
  };
}

interface RecordedCall {
  url: string;
  init: RequestInit;
}

type TransportHandler = (
  call: RecordedCall,
  index: number,
) => Response | Promise<Response>;

function fakeFetch(
  handler: TransportHandler,
): { fetch: B2Fetcher; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetch: B2Fetcher = (input, init = {}) => {
    const url = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.href
      : input.url;
    const call = { url, init };
    calls.push(call);
    return Promise.resolve(handler(call, calls.length - 1));
  };
  return { fetch, calls };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function bytesResponse(
  bytes: Uint8Array<ArrayBuffer>,
  headers: Record<string, string> = {},
): Response {
  return new Response(bytes, { status: 200, headers });
}

function streamResponse(
  chunks: Uint8Array[],
  cancelState: { cancelled: boolean },
  headers: Record<string, string> = {},
): Response {
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      const next = chunks.shift();
      if (next === undefined) controller.close();
      else controller.enqueue(next);
    },
    cancel() {
      cancelState.cancelled = true;
    },
  });
  return new Response(stream, { status: 200, headers });
}

function headersOf(call: RecordedCall): Record<string, string> {
  return (call.init.headers ?? {}) as Record<string, string>;
}

function bodyOf(call: RecordedCall): Record<string, unknown> {
  return JSON.parse(call.init.body as string) as Record<string, unknown>;
}

function base64(text: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(text)));
}

function uploadItem(
  fileName: string,
  fileId: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    fileId,
    fileName,
    action: "upload",
    bucketId: BUCKET_ID,
    contentLength: 3,
    contentSha1: "a".repeat(40),
    uploadTimestamp: 1700000000,
    ...overrides,
  };
}

function hideItem(
  fileName: string,
  fileId: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    fileId,
    fileName,
    action: "hide",
    bucketId: BUCKET_ID,
    contentLength: 3,
    contentSha1: "b".repeat(40),
    uploadTimestamp: 1700001000,
    ...overrides,
  };
}

function startItem(
  fileName: string,
  fileId: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    fileId,
    fileName,
    action: "start",
    bucketId: BUCKET_ID,
    // B2 omits the content fields of an incomplete large file marker, so the
    // client must default them to safe zeros.
    contentLength: null,
    contentSha1: null,
    uploadTimestamp: null,
    ...overrides,
  };
}

function orderedUploadHandler(
  name: string,
  sha1: string,
  length: number,
  uploadOverrides: Record<string, unknown> = {},
): TransportHandler {
  return (call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    if (call.url === `${API_URL}/b2api/v3/b2_get_upload_url`) {
      return jsonResponse({
        uploadUrl: UPLOAD_URL,
        authorizationToken: "upload-token",
        bucketId: BUCKET_ID,
      });
    }
    if (call.url === UPLOAD_URL) {
      return jsonResponse({
        fileId: "file-1",
        fileName: name,
        action: "upload",
        contentLength: length,
        contentSha1: sha1,
        uploadTimestamp: 1753500000000,
        bucketId: BUCKET_ID,
        ...uploadOverrides,
      });
    }
    return jsonResponse({}, 404);
  };
}

Deno.test("constructor validates settings before any network", () => {
  const { fetch, calls } = fakeFetch(() => jsonResponse({}, 500));
  assertThrows(() => new B2Store(settings({ accessKeyId: "" }), fetch));
  assertThrows(() => new B2Store(settings({ secretAccessKey: "" }), fetch));
  assertThrows(() => new B2Store(settings({ bucketId: "" }), fetch));
  assertThrows(() =>
    new B2Store(settings({ bucketName: "other-bucket" }), fetch)
  );
  assert(calls.length === 0);
});

Deno.test("put rejects unsafe names and chunk sizes before authorization", async () => {
  const { fetch, calls } = fakeFetch(() => jsonResponse(authBody()));
  const store = new B2Store(settings(), fetch);
  const chunk = new Uint8Array([1, 2, 3]);
  const badNames = [
    "",
    DIRECT_PREFIX,
    "restic/direct-v1",
    "restic/2026-09-05/chunk",
    `${DIRECT_PREFIX}../x`,
    `${DIRECT_PREFIX}./x`,
    `${DIRECT_PREFIX}a//b`,
    `${DIRECT_PREFIX}a\\b`,
    `${DIRECT_PREFIX}a%2Fb`,
    `${DIRECT_PREFIX}${"x".repeat(1000)}`,
  ];
  for (const name of badNames) {
    const error = await rejectWith(store.put(name, chunk));
    assert(error.message.includes("object name rejected"), error.message);
  }
  const oversized = await rejectWith(
    store.put(`${DIRECT_PREFIX}big`, new Uint8Array(MAX_CHUNK_BYTES + 1)),
  );
  assert(oversized.message.includes("chunk exceeds"), oversized.message);
  const notBytes = await rejectWith(
    store.put(
      `${DIRECT_PREFIX}x`,
      undefined as unknown as Uint8Array<ArrayBuffer>,
    ),
  );
  assert(notBytes.message.includes("chunk is not bytes"), notBytes.message);
  assert(calls.length === 0, "no request may leave before local validation");
});

Deno.test("put authorizes then uploads with the exact header and body shape", async () => {
  const name = `${DIRECT_PREFIX}2026-09-05/chunk-001`;
  const bytes = new TextEncoder().encode("encrypted-chunk-bytes");
  const sha1 = await sha1Hex(bytes);
  const { fetch, calls } = fakeFetch(
    orderedUploadHandler(name, sha1, bytes.byteLength),
  );
  const store = new B2Store(settings(), fetch);
  const object = await store.put(name, bytes);
  assert(object.fileId === "file-1");
  assert(object.fileName === name);
  assert(object.contentLength === bytes.byteLength);
  assert(object.contentSha1 === sha1);
  assert(object.action === "upload");
  assert(object.uploadTimestamp === 1753500000000);
  assert(calls.length === 3);
  for (const call of calls) {
    assert(call.init.redirect === "error", "every call must reject redirects");
  }
  const [authCall, urlCall, uploadCall] = calls;
  assert(authCall.url === AUTH_URL);
  assert(
    headersOf(authCall).authorization ===
      `Basic ${base64(`${ACCESS_KEY_ID}:${SECRET_ACCESS_KEY}`)}`,
  );
  assert(urlCall.url === `${API_URL}/b2api/v3/b2_get_upload_url`);
  assert(urlCall.init.method === "POST");
  assert(bodyOf(urlCall).bucketId === BUCKET_ID);
  assert(headersOf(urlCall).authorization === ACCOUNT_TOKEN);
  assert(headersOf(urlCall)["content-type"] === "application/json");
  assert(uploadCall.url === UPLOAD_URL);
  assert(uploadCall.init.method === "POST");
  assert(uploadCall.init.body === bytes);
  assert(headersOf(uploadCall).authorization === "upload-token");
  assert(headersOf(uploadCall)["content-type"] === "application/octet-stream");
  assert(
    headersOf(uploadCall)["content-length"] ===
      String(bytes.byteLength),
  );
  assert(headersOf(uploadCall)["x-bz-file-name"] === encodeURIComponent(name));
  assert(headersOf(uploadCall)["x-bz-content-sha1"] === sha1);
});

Deno.test("put accepts a zero-length chunk", async () => {
  const name = `${DIRECT_PREFIX}empty-marker`;
  const sha1 = await sha1Hex(new Uint8Array(0));
  const { fetch, calls } = fakeFetch(orderedUploadHandler(name, sha1, 0));
  const object = await new B2Store(settings(), fetch).put(
    name,
    new Uint8Array(0),
  );
  assert(object.contentLength === 0);
  assert(object.contentSha1 === sha1);
  assert(object.action === "upload");
  assert(headersOf(calls[2])["content-length"] === "0");
});

Deno.test("put rejects mismatched upload responses without echoing them", async () => {
  const name = `${DIRECT_PREFIX}2026-09-05/chunk-001`;
  const bytes = new Uint8Array([1, 2, 3]);
  const sha1 = await sha1Hex(bytes);
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ contentSha1: "0".repeat(40) }, "content sha1 mismatch"],
    [{ contentLength: 999 }, "content length mismatch"],
    [{ fileName: "restic/direct-v1/other" }, "file name mismatch"],
    [{ bucketId: "other-bucket" }, "bucket mismatch"],
    [{ action: "hide" }, "unexpected action"],
  ];
  for (const [overrides, expected] of cases) {
    const { fetch } = fakeFetch(
      orderedUploadHandler(name, sha1, bytes.byteLength, overrides),
    );
    const error = await rejectWith(
      new B2Store(settings(), fetch).put(name, bytes),
    );
    assert(error.message.includes(expected), error.message);
    assert(!error.message.includes("0".repeat(40)), error.message);
  }
});

Deno.test("authorize rejects disallowed bucket, capability and namePrefix scope", async () => {
  const cases: Array<[Record<string, unknown>, string]> = [
    [
      { buckets: [{ id: "other-bucket-id", name: BUCKET_NAME }] },
      "bucket scope mismatch",
    ],
    [{
      buckets: [
        { id: BUCKET_ID, name: BUCKET_NAME },
        { id: "other", name: "other-bucket" },
      ],
    }, "exactly one bucket"],
    [
      { buckets: [], bucketId: undefined, bucketName: undefined },
      "bucket scope missing",
    ],
    [{ buckets: "nope" }, "bucket scope missing"],
    [
      { capabilities: ["listFiles", "readFiles", "writeFiles"] },
      "deleteFiles not granted",
    ],
    [{
      capabilities: ["listFiles", "readFiles", "writeFiles", "deleteFiles"],
      namePrefix: "",
    }, "namePrefix rejected"],
    [{ capabilities: "all" }, "invalid response"],
  ];
  for (const [allowedOverrides, expected] of cases) {
    const { fetch, calls } = fakeFetch(() =>
      jsonResponse(authBody(allowedOverrides))
    );
    const error = await rejectWith(new B2Store(settings(), fetch).authorize());
    assert(error.message.includes("b2_authorize_account"), error.message);
    assert(error.message.includes(expected), error.message);
    assert(calls.length === 1);
  }
});

Deno.test("authorize rejects legacy bucket fields and misconfigured namePrefix", async () => {
  const legacy = fakeFetch(() =>
    jsonResponse(authBody({
      buckets: [],
      bucketId: BUCKET_ID,
      bucketName: BUCKET_NAME,
    }))
  );
  const legacyError = await rejectWith(
    new B2Store(settings(), legacy.fetch).authorize(),
  );
  assert(
    legacyError.message.includes("bucket scope missing"),
    legacyError.message,
  );
  assert(!legacyError.message.includes(BUCKET_ID), legacyError.message);
  const wrongPrefix = fakeFetch(() =>
    jsonResponse(authBody({ namePrefix: "direct/" }))
  );
  const error = await rejectWith(
    new B2Store(settings(), wrongPrefix.fetch).authorize(),
  );
  assert(error.message.includes("namePrefix rejected"), error.message);
});

Deno.test("authorize rejects unsafe api and download endpoints", async () => {
  const endpointCases: Array<[Record<string, unknown>, string]> = [
    [{ apiUrl: "http://api001.backblazeb2.com" }, "apiUrl host rejected"],
    [
      { apiUrl: "https://api001.backblazeb2.com.evil.io" },
      "apiUrl host rejected",
    ],
    [{ apiUrl: "https://evil.com" }, "apiUrl host rejected"],
    [
      { apiUrl: "https://user:pass@api001.backblazeb2.com" },
      "apiUrl host rejected",
    ],
    [{ apiUrl: "https://api001.backblazeb2.com:8443" }, "apiUrl host rejected"],
    [
      { downloadUrl: "http://f001.backblazeb2.com" },
      "downloadUrl host rejected",
    ],
    [
      { downloadUrl: "https://f001.backblazeb2.com.evil.io" },
      "downloadUrl host rejected",
    ],
    [
      { downloadUrl: "https://user:pass@f001.backblazeb2.com" },
      "downloadUrl host rejected",
    ],
  ];
  for (const [storageOverrides, expected] of endpointCases) {
    const { fetch } = fakeFetch(() =>
      jsonResponse(authBody({}, storageOverrides))
    );
    const error = await rejectWith(new B2Store(settings(), fetch).authorize());
    assert(error.message.includes("b2_authorize_account"), error.message);
    assert(error.message.includes(expected), error.message);
  }
});

Deno.test("upload target policy accepts pod backblaze.com hosts and rejects lookalikes", async () => {
  const uploadCases: Array<[string, string]> = [
    [
      "https://attacker.example.com/b2api/v3/b2_upload_file",
      "uploadUrl host rejected",
    ],
    [
      "https://pod.backblaze.com.evil.test/b2api/v3/b2_upload_file",
      "uploadUrl host rejected",
    ],
    [
      "http://pod-050-1027-00.backblaze.com/b2api/v3/b2_upload_file",
      "uploadUrl host rejected",
    ],
    [
      "https://user:pass@pod-050-1027-00.backblaze.com/b2api/v3/b2_upload_file",
      "uploadUrl host rejected",
    ],
    [
      "https://pod-050-1027-00.backblaze.com:8443/b2api/v3/b2_upload_file",
      "uploadUrl host rejected",
    ],
    [
      "https://upload001.backblazeb2.com.evil.io/b2api/v3/b2_upload_file",
      "uploadUrl host rejected",
    ],
  ];
  for (const [uploadUrl, expected] of uploadCases) {
    const { fetch, calls } = fakeFetch((call) => {
      if (call.url === AUTH_URL) return jsonResponse(authBody());
      return jsonResponse({
        uploadUrl,
        authorizationToken: "upload-token",
        bucketId: BUCKET_ID,
      });
    });
    const error = await rejectWith(
      new B2Store(settings(), fetch)
        .put(`${DIRECT_PREFIX}x`, new Uint8Array([1])),
    );
    assert(error.message.includes(expected), error.message);
    assert(
      calls.length === 2,
      `no payload may reach a rejected host, got ${calls.length} calls`,
    );
  }
  // The live pod hostname succeeds end to end, including the bucketId echo.
  const name = `${DIRECT_PREFIX}x`;
  const bytes = new Uint8Array([1, 2, 3]);
  const sha1 = await sha1Hex(bytes);
  const ok = fakeFetch(orderedUploadHandler(name, sha1, bytes.byteLength));
  const object = await new B2Store(settings(), ok.fetch).put(name, bytes);
  assert(object.action === "upload");
  assert(ok.calls[1].url === `${API_URL}/b2api/v3/b2_get_upload_url`);
  assert(ok.calls[2].url === UPLOAD_URL);
  assert(bodyOf(ok.calls[1]).bucketId === BUCKET_ID);
});

Deno.test("put verifies the get_upload_url bucketId before sending the payload", async () => {
  const mismatched = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return jsonResponse({
      uploadUrl: UPLOAD_URL,
      authorizationToken: "upload-token",
      bucketId: "other-bucket-id",
    });
  });
  const mismatchError = await rejectWith(
    new B2Store(settings(), mismatched.fetch)
      .put(`${DIRECT_PREFIX}x`, new Uint8Array([1])),
  );
  assert(
    mismatchError.message.includes("bucket mismatch"),
    mismatchError.message,
  );
  assert(
    !mismatchError.message.includes("other-bucket-id"),
    mismatchError.message,
  );
  assert(mismatched.calls.length === 2, "no payload may be sent on mismatch");

  const missing = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return jsonResponse({
      uploadUrl: UPLOAD_URL,
      authorizationToken: "upload-token",
    });
  });
  const missingError = await rejectWith(
    new B2Store(settings(), missing.fetch)
      .put(`${DIRECT_PREFIX}x`, new Uint8Array([1])),
  );
  assert(
    missingError.message.includes("invalid response (bucketId)"),
    missingError.message,
  );
  assert(missing.calls.length === 2, "no payload may be sent without bucketId");
});

Deno.test("constructor snapshots settings so later caller mutation cannot change scope", async () => {
  const name = `${DIRECT_PREFIX}2026-09-05/chunk-001`;
  const bytes = new Uint8Array([1, 2, 3]);
  const sha1 = await sha1Hex(bytes);
  const { fetch, calls } = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    if (call.url === `${API_URL}/b2api/v3/b2_get_upload_url`) {
      return jsonResponse({
        uploadUrl: UPLOAD_URL,
        authorizationToken: "upload-token",
        bucketId: BUCKET_ID,
      });
    }
    if (call.url === UPLOAD_URL) {
      return jsonResponse({
        fileId: "file-1",
        fileName: name,
        action: "upload",
        contentLength: bytes.byteLength,
        contentSha1: sha1,
        uploadTimestamp: 1753500000000,
        bucketId: BUCKET_ID,
      });
    }
    if (call.url === `${API_URL}/b2api/v3/b2_list_file_versions`) {
      return jsonResponse({
        files: [uploadItem(`${DIRECT_PREFIX}existing`, "id-existing")],
        nextFileName: null,
        nextFileId: null,
      });
    }
    return jsonResponse({}, 404);
  });
  const original = settings();
  const store = new B2Store(original, fetch);
  original.accessKeyId = "mutated-key";
  original.secretAccessKey = "mutated-secret";
  original.bucketName = "mutated-bucket-name";
  // Credentials are snapshotted: authorization uses the values validated at
  // construction, not the mutated caller object.
  await store.authorize();
  const authHeader = headersOf(calls[0]).authorization;
  assert(
    authHeader === `Basic ${base64(`${ACCESS_KEY_ID}:${SECRET_ACCESS_KEY}`)}`,
  );
  assert(!authHeader.includes("mutated-secret"), authHeader);
  // The bucket is snapshotted: mutation after authorize (and after every
  // operation) cannot redirect put/versions to another bucket.
  original.bucketId = "mutated-bucket-id";
  const object = await store.put(name, bytes);
  assert(object.action === "upload");
  assert(object.contentLength === bytes.byteLength);
  assert(bodyOf(calls[1]).bucketId === BUCKET_ID);
  const versions = await store.versions();
  assert(versions.length === 1);
  assert(versions[0].fileId === "id-existing");
  assert(bodyOf(calls[3]).bucketId === BUCKET_ID);
});

Deno.test("versions paginates the exact prefix and preserves upload, hide and start actions", async () => {
  const { fetch, calls } = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    const body = bodyOf(call);
    if (body.startFileName === undefined) {
      return jsonResponse({
        files: [
          uploadItem(`${DIRECT_PREFIX}a`, "id-a"),
          hideItem(`${DIRECT_PREFIX}b`, "id-b"),
        ],
        nextFileName: `${DIRECT_PREFIX}cur-1`,
        nextFileId: "cur-id-1",
      });
    }
    if (body.startFileName === `${DIRECT_PREFIX}cur-1`) {
      return jsonResponse({
        files: [
          startItem(`${DIRECT_PREFIX}large-pending`, "start-id-1"),
          // B2 also omits the marker fields entirely; same safe defaults.
          startItem(`${DIRECT_PREFIX}large-pending-2`, "start-id-2", {
            contentLength: undefined,
            contentSha1: undefined,
            uploadTimestamp: undefined,
          }),
        ],
        nextFileName: `${DIRECT_PREFIX}cur-2`,
        nextFileId: "cur-id-2",
      });
    }
    return jsonResponse({
      files: [uploadItem(`${DIRECT_PREFIX}c`, "id-c")],
      nextFileName: null,
      nextFileId: null,
    });
  });
  const versions = await new B2Store(settings(), fetch).versions();
  assert(versions.length === 5);
  assert(versions[0].action === "upload");
  assert(versions[0].fileId === "id-a");
  assert(versions[0].contentSha1 === "a".repeat(40));
  assert(versions[1].action === "hide");
  assert(versions[1].fileId === "id-b");
  assert(versions[1].contentSha1 === "b".repeat(40));
  assert(versions[1].uploadTimestamp === 1700001000);
  assert(versions[2].action === "start");
  assert(versions[2].fileId === "start-id-1");
  assert(versions[2].contentLength === 0);
  assert(versions[2].contentSha1 === "");
  assert(versions[2].uploadTimestamp === 0);
  assert(versions[3].action === "start");
  assert(versions[3].fileId === "start-id-2");
  assert(versions[3].contentLength === 0);
  assert(versions[3].contentSha1 === "");
  assert(versions[3].uploadTimestamp === 0);
  assert(versions[4].action === "upload");
  assert(versions[4].fileId === "id-c");
  assert(calls.length === 4);
  const listCalls = calls.slice(1);
  for (const call of listCalls) {
    assert(headersOf(call).authorization === ACCOUNT_TOKEN);
    assert(call.init.redirect === "error");
    const body = bodyOf(call);
    assert(body.bucketId === BUCKET_ID);
    assert(body.prefix === DIRECT_PREFIX);
    assert(body.maxFileCount === 1000);
  }
  assert(bodyOf(listCalls[1]).startFileName === `${DIRECT_PREFIX}cur-1`);
  assert(bodyOf(listCalls[1]).startFileId === "cur-id-1");
  assert(bodyOf(listCalls[2]).startFileName === `${DIRECT_PREFIX}cur-2`);
  assert(bodyOf(listCalls[2]).startFileId === "cur-id-2");
});

Deno.test("versions rejects out-of-scope and malformed list entries", async () => {
  const badPages: Record<string, unknown>[] = [
    { files: [uploadItem("restic/old-repo/repo-file", "id-x")] },
    { files: [uploadItem(`${DIRECT_PREFIX}../up`, "id-x")] },
    { files: [{ fileName: `${DIRECT_PREFIX}a`, action: "upload" }] },
    {
      files: [{
        fileName: `${DIRECT_PREFIX}a`,
        fileId: "id-x",
        action: "upload",
        contentLength: 3,
        uploadTimestamp: 1,
      }],
    },
    { files: "not-an-array" },
    // The client lists without delimiter, so folder and null-ID entries are
    // unexpected and must fail closed instead of expanding the schema.
    {
      files: [{
        fileId: "folder-id",
        fileName: `${DIRECT_PREFIX}subdir`,
        action: "folder",
        bucketId: BUCKET_ID,
      }],
    },
    {
      files: [{
        fileId: null,
        fileName: `${DIRECT_PREFIX}a`,
        action: "upload",
        bucketId: BUCKET_ID,
        contentLength: 3,
        contentSha1: "a".repeat(40),
        uploadTimestamp: 1,
      }],
    },
  ];
  for (const page of badPages) {
    const { fetch } = fakeFetch((call) =>
      call.url === AUTH_URL ? jsonResponse(authBody()) : jsonResponse(page)
    );
    const error = await rejectWith(new B2Store(settings(), fetch).versions());
    assert(error.message.length > 0, error.message);
  }
});

Deno.test("versions rejects wrong bucket and invalid size or time on listed items", async () => {
  const badCases: Array<[Record<string, unknown>, string]> = [
    [
      {
        files: [uploadItem(`${DIRECT_PREFIX}a`, "id-a", {
          bucketId: "other-bucket-id",
        })],
      },
      "bucket mismatch",
    ],
    [
      {
        files: [uploadItem(`${DIRECT_PREFIX}a`, "id-a", {
          contentLength: MAX_CHUNK_BYTES + 1,
        })],
      },
      "contentLength",
    ],
    [
      {
        files: [uploadItem(`${DIRECT_PREFIX}a`, "id-a", {
          contentLength: -1,
        })],
      },
      "contentLength",
    ],
    [
      {
        files: [uploadItem(`${DIRECT_PREFIX}a`, "id-a", {
          contentLength: 3.5,
        })],
      },
      "contentLength",
    ],
    [
      {
        files: [uploadItem(`${DIRECT_PREFIX}a`, "id-a", {
          uploadTimestamp: -1,
        })],
      },
      "uploadTimestamp",
    ],
    [
      {
        files: [uploadItem(`${DIRECT_PREFIX}a`, "id-a", {
          uploadTimestamp: 1.5,
        })],
      },
      "uploadTimestamp",
    ],
    [
      {
        files: [hideItem(`${DIRECT_PREFIX}a`, "id-a", {
          contentLength: -1,
        })],
      },
      "contentLength",
    ],
    // start markers take zero defaults only when B2 omits the fields; a
    // present invalid value still fails closed.
    [
      {
        files: [startItem(`${DIRECT_PREFIX}a`, "id-a", {
          uploadTimestamp: -1,
        })],
      },
      "uploadTimestamp",
    ],
  ];
  for (const [page, expected] of badCases) {
    const { fetch } = fakeFetch((call) =>
      call.url === AUTH_URL ? jsonResponse(authBody()) : jsonResponse(page)
    );
    const error = await rejectWith(new B2Store(settings(), fetch).versions());
    assert(error.message.includes("b2_list_file_versions"), error.message);
    assert(error.message.includes(expected), error.message);
  }
});

Deno.test("versions rejects a repeated continuation cursor without looping", async () => {
  const { fetch, calls } = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return jsonResponse({
      files: [],
      nextFileName: `${DIRECT_PREFIX}loop`,
      nextFileId: "id-loop",
    });
  });
  const error = await rejectWith(new B2Store(settings(), fetch).versions());
  assert(error.message.includes("repeated continuation cursor"), error.message);
  assert(calls.length === 3, `bounded calls expected, got ${calls.length}`);
});

Deno.test("versions rejects listing beyond 10000 pages", async () => {
  let page = 0;
  const { fetch, calls } = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    page += 1;
    return jsonResponse({
      files: [],
      nextFileName: `${DIRECT_PREFIX}cur-${page}`,
      nextFileId: `id-${page}`,
    });
  });
  const error = await rejectWith(new B2Store(settings(), fetch).versions());
  assert(error.message.includes("more than 10000 pages"), error.message);
  assert(calls.length === 10001, `expected 10001 calls, got ${calls.length}`);
});

Deno.test("get downloads and verifies length and SHA-1", async () => {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  const sha1 = await sha1Hex(bytes);
  const object = chunkObject(undefined, {
    contentLength: 4,
    contentSha1: sha1,
  });
  const { fetch, calls } = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return bytesResponse(bytes, {
      "content-length": String(bytes.byteLength),
    });
  });
  const body = await new B2Store(settings(), fetch).get(object);
  assertBytes(body, bytes);
  const downloadCall = calls[1];
  assert(
    downloadCall.url ===
      `${DOWNLOAD_URL}/b2api/v3/b2_download_file_by_id?fileId=${
        encodeURIComponent("file-1")
      }`,
  );
  assert(downloadCall.init.redirect === "error");
  assert(headersOf(downloadCall).authorization === ACCOUNT_TOKEN);
});

Deno.test("get rejects a wrong content SHA-1 without echoing it", async () => {
  const bytes = new Uint8Array([1, 2, 3]);
  const wrongSha1 = await sha1Hex(new Uint8Array([9, 9]));
  const object = chunkObject(undefined, { contentSha1: wrongSha1 });
  const { fetch } = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return bytesResponse(bytes, { "content-length": "3" });
  });
  const error = await rejectWith(new B2Store(settings(), fetch).get(object));
  assert(error.message.includes("content sha1 mismatch"), error.message);
  assert(!error.message.includes(wrongSha1), error.message);
});

Deno.test("get enforces bounds on lying responses and cancels overflow bodies", async () => {
  const cancelledHeader = { cancelled: false };
  // content-length header declares 1000 while the expected object is 100 bytes.
  const headerLie = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return streamResponse(
      [new Uint8Array([1, 2, 3])],
      cancelledHeader,
      { "content-length": "1000" },
    );
  });
  const headerError = await rejectWith(
    new B2Store(settings(), headerLie.fetch)
      .get(chunkObject(undefined, { contentLength: 100 })),
  );
  assert(
    headerError.message.includes("content length mismatch"),
    headerError.message,
  );
  assert(headerLie.calls.length === 2);
  assert(cancelledHeader.cancelled, "mismatched body must be cancelled");

  const bodyLie = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return streamResponse([new Uint8Array([1, 2, 3, 4])], { cancelled: false });
  });
  const bodyError = await rejectWith(
    new B2Store(settings(), bodyLie.fetch).get(chunkObject()),
  );
  assert(
    bodyError.message.includes("content length mismatch"),
    bodyError.message,
  );

  const cancelledOverflow = { cancelled: false };
  const overflowStream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(MAX_CHUNK_BYTES + 1));
    },
    pull() {
      // Keep the stream open until the client cancels it.
    },
    cancel() {
      cancelledOverflow.cancelled = true;
    },
  });
  const overflow = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return new Response(overflowStream, { status: 200 });
  });
  const overflowError = await rejectWith(
    new B2Store(settings(), overflow.fetch).get(chunkObject()),
  );
  assert(
    overflowError.message.includes("body exceeds chunk limit"),
    overflowError.message,
  );
  assert(cancelledOverflow.cancelled, "overflow body must be cancelled");
});

Deno.test("get redacts reader failures and still attempts cancellation", async () => {
  const secret = "provider-stream-secret-do-not-leak";
  const cancelState = { attempted: false, reason: undefined as unknown };
  let pulls = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls += 1;
      if (pulls === 1) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
        return;
      }
      throw new Error(`provider stream exploded with ${secret}`);
    },
    cancel() {
      // The provider errored the stream, so this source cancel is not
      // reachable; the reader-level cancel attempt is recorded below.
    },
  });
  // Observe the client's best-effort reader.cancel() attempt: once the
  // provider errors the stream, cancel() only rejects and never reaches
  // the underlying source. The reader is created lazily after the Response
  // wraps the stream, so the body stays unlockable at construction time.
  const originalGetReader = stream.getReader.bind(stream);
  let tracked: {
    readonly closed: Promise<void>;
    read: () => Promise<ReadableStreamReadResult<Uint8Array>>;
    cancel: (reason?: unknown) => Promise<void>;
    releaseLock: () => void;
  } | null = null;
  (stream as unknown as { getReader: unknown }).getReader = () => {
    if (tracked === null) {
      const reader = originalGetReader();
      tracked = {
        get closed() {
          return reader.closed;
        },
        read: () => reader.read(),
        cancel: (reason?: unknown) => {
          cancelState.attempted = true;
          cancelState.reason = reason;
          return reader.cancel(reason);
        },
        releaseLock: () => reader.releaseLock(),
      };
    }
    return tracked;
  };
  const { fetch } = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return new Response(stream, {
      status: 200,
      headers: { "content-length": "3" },
    });
  });
  const error = await rejectWith(
    new B2Store(settings(), fetch).get(chunkObject()),
  );
  assert(
    error.message === "b2_download_file_by_id failed: body read failed",
    error.message,
  );
  assert(!error.message.includes(secret), error.message);
  assert(!error.message.includes("provider stream"), error.message);
  assert(
    cancelState.attempted,
    "cancel must be attempted after a read failure",
  );
});

Deno.test("get refuses unsafe objects before any network", async () => {
  const { fetch, calls } = fakeFetch(() => jsonResponse(authBody()));
  const store = new B2Store(settings(), fetch);
  const cases: Array<Partial<B2Object>> = [
    { fileName: "restic/old-repo/file" },
    { fileName: `${DIRECT_PREFIX}../up` },
    { action: "hide" },
    { action: "start" },
    { fileId: "" },
    { contentLength: MAX_CHUNK_BYTES + 1 },
    { contentLength: -1 },
    { contentSha1: "not-hex" },
  ];
  for (const overrides of cases) {
    const error = await rejectWith(
      store.get(chunkObject(undefined, overrides)),
    );
    assert(error instanceof Error, error.message);
  }
  assert(calls.length === 0);
});

Deno.test("remove deletes one exact version and verifies the provider echo", async () => {
  const object = chunkObject();
  const { fetch, calls } = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return jsonResponse({ fileName: object.fileName, fileId: object.fileId });
  });
  const store = new B2Store(settings(), fetch);
  await store.remove(object);
  assert(calls.length === 2);
  const deleteCall = calls[1];
  assert(deleteCall.url === `${API_URL}/b2api/v3/b2_delete_file_version`);
  assert(deleteCall.init.method === "POST");
  assert(deleteCall.init.redirect === "error");
  const requestBody = bodyOf(deleteCall);
  assert(requestBody.fileName === object.fileName);
  assert(requestBody.fileId === object.fileId);
  assert(headersOf(deleteCall).authorization === ACCOUNT_TOKEN);
  assert(headersOf(deleteCall)["content-type"] === "application/json");

  const mismatched = fakeFetch((_call, index) => {
    if (index === 0) return jsonResponse(authBody());
    return jsonResponse({
      fileName: `${DIRECT_PREFIX}other`,
      fileId: "other-id",
    });
  });
  const mismatchError = await rejectWith(
    new B2Store(settings(), mismatched.fetch).remove(object),
  );
  assert(
    mismatchError.message.includes("response mismatch"),
    mismatchError.message,
  );

  const { fetch: preflightFetch, calls: preflightCalls } = fakeFetch(
    () => jsonResponse(authBody()),
  );
  const preflightStore = new B2Store(settings(), preflightFetch);
  await rejectWith(
    preflightStore.remove(chunkObject(undefined, { fileName: "restic/old/x" })),
  );
  await rejectWith(
    preflightStore.remove(chunkObject(undefined, { fileId: "" })),
  );
  assert(preflightCalls.length === 0);
});

Deno.test("remove refuses start and other non-version actions before any network", async () => {
  const { fetch, calls } = fakeFetch(() => jsonResponse(authBody()));
  const store = new B2Store(settings(), fetch);
  for (const action of ["start", "folder", "unfinished"]) {
    const error = await rejectWith(
      store.remove(chunkObject(undefined, { action })),
    );
    assert(
      error.message === "remove failed: object is not an upload or hide marker",
      error.message,
    );
  }
  assert(calls.length === 0, "no delete request may leave before refusal");
});

Deno.test("provider and network errors only report operation plus status", async () => {
  const network = fakeFetch(() => {
    throw new Error(
      `connection failed for ${UPLOAD_URL}?token=${ACCOUNT_TOKEN}`,
    );
  });
  const networkError = await rejectWith(
    new B2Store(settings(), network.fetch).authorize(),
  );
  assert(
    networkError.message === "b2_authorize_account failed (network error)",
  );
  assert(!networkError.message.includes(ACCOUNT_TOKEN));
  assert(!networkError.message.includes(UPLOAD_URL));

  const provider = fakeFetch((call) => {
    if (call.url === AUTH_URL) return jsonResponse(authBody());
    return jsonResponse({
      message: `provider broke with ${SECRET_ACCESS_KEY} and ${ACCOUNT_TOKEN}`,
    }, 500);
  });
  const providerError = await rejectWith(
    new B2Store(settings(), provider.fetch)
      .remove(chunkObject()),
  );
  assert(providerError.message === "b2_delete_file_version failed (HTTP 500)");
  assert(!providerError.message.includes(SECRET_ACCESS_KEY));
  assert(!providerError.message.includes(ACCOUNT_TOKEN));
  assert(!providerError.message.includes("provider broke"));

  const authFailure = fakeFetch(() =>
    jsonResponse({ message: `bad key ${SECRET_ACCESS_KEY}` }, 401)
  );
  const authError = await rejectWith(
    new B2Store(settings(), authFailure.fetch).authorize(),
  );
  assert(authError.message === "b2_authorize_account failed (HTTP 401)");
  assert(!authError.message.includes(SECRET_ACCESS_KEY));
});
