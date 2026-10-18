/** Pure policy tests by default. --native enables owned loopback/curl/file
 * fixtures ONLY when the sole live operator runs them inside a bounded unit. */
import { createHash } from "node:crypto";
import {
  BACKUP_V2_TRANSPORT_BOUNDS,
  BackupV2Store,
  BackupV2TransportError,
  type BackupV2Wire,
  type BackupV2WireRequest,
  type BackupV2WireResponse,
  createCurlBackupV2Wire,
} from "../scripts/backup-v2-store.ts";
import {
  backupV2ObjectName,
  type BackupV2ObjectRef,
  type BackupV2PutIntent,
  type BackupV2SealedSlot,
} from "../scripts/backup-v2-contract.ts";
import {
  BACKUP_V2_LIMITS,
  BACKUP_V2_NAMESPACE,
} from "../scripts/backup-v2-profile.ts";

const encoder = new TextEncoder();
const bucketId = "fixture-bucket";
const settings = {
  accessKeyId: "fixture-id",
  secretAccessKey: "fixture-secret",
  bucketId,
  bucketName: "pavlovcik-arch-vps-backups",
};
const captureId = "generation-11111111-1111-4111-8111-111111111111";
const attemptId = "22222222-2222-4222-8222-222222222222";
const putId = "33333333-3333-4333-8333-333333333333";
const name = backupV2ObjectName(captureId, attemptId, "data", 0, putId);
const native = Deno.args.includes("--native");
function assert(value: unknown, message = "assertion failed"): asserts value {
  if (!value) throw new Error(message);
}
async function rejects(action: Promise<unknown>, pattern?: RegExp) {
  try {
    await action;
  } catch (error) {
    assert(error instanceof Error);
    if (pattern) assert(pattern.test(error.message), error.message);
    return error;
  }
  throw new Error("expected rejection");
}
function hash(bytes: Uint8Array, algorithm = "sha256") {
  return createHash(algorithm).update(bytes).digest("hex");
}
const data = encoder.encode("encrypted synthetic object\n");
function ref(overrides: Partial<BackupV2ObjectRef> = {}): BackupV2ObjectRef {
  return {
    fileId: "fixture-file-id",
    fileName: name,
    contentLength: data.length,
    contentSha1: hash(data, "sha1"),
    sha256: hash(data),
    action: "upload",
    uploadTimestamp: 1,
    ...overrides,
  };
}
function auth() {
  return {
    authorizationToken: "fixture-account-token",
    apiInfo: {
      storageApi: {
        apiUrl: "https://api001.backblazeb2.com",
        downloadUrl: "https://f001.backblazeb2.com",
        allowed: {
          buckets: [{ id: bucketId, name: settings.bucketName }],
          namePrefix: "restic/",
          capabilities: ["listFiles", "readFiles", "writeFiles", "deleteFiles"],
        },
      },
    },
  };
}
function response(value: unknown, status = 200): BackupV2WireResponse {
  const bytes = typeof value === "string"
    ? encoder.encode(value)
    : encoder.encode(JSON.stringify(value));
  return {
    status,
    headers: new Headers(),
    body: new ReadableStream({
      start(c) {
        c.enqueue(bytes);
        c.close();
      },
    }),
    finished: Promise.resolve(),
    cancel: () => Promise.resolve(),
  };
}
function listed(object = ref()) {
  const { sha256: _sha256, ...version } = object;
  return { ...version, bucketId };
}
function fakeWire(
  page: unknown,
  calls: BackupV2WireRequest[] = [],
): BackupV2Wire {
  return (request) => {
    calls.push(request);
    return Promise.resolve(
      response(request.url.endsWith("b2_authorize_account") ? auth() : page),
    );
  };
}

Deno.test("v2 namespace and cursor rejection occur before any wire request", async () => {
  const calls: BackupV2WireRequest[] = [];
  const store = new BackupV2Store(settings, fakeWire({}, calls));
  await rejects(store.versionsPage("restic/direct-v1/", null));
  await rejects(
    store.versionsPage(BACKUP_V2_NAMESPACE, {
      fileName: "restic/direct-v1/x",
      fileId: "id",
    }),
  );
  await rejects(
    store.getExactToFile(ref({ fileName: "restic/direct-v1/x" }), {
      index: 0,
      path: "/not-used",
    }),
  );
  assert(calls.length === 0);
});
Deno.test("v2 one bounded page preserves markers and exact continuation", async () => {
  const calls: BackupV2WireRequest[] = [];
  const page = {
    files: [listed(), {
      ...listed(),
      action: "hide",
      contentSha1: "none",
      contentLength: 0,
    }],
    nextFileName: name,
    nextFileId: "next-id",
  };
  const store = new BackupV2Store(settings, fakeWire(page, calls));
  const got = await store.versionsPage(BACKUP_V2_NAMESPACE, null);
  assert(
    got.items.length === 2 && got.items[1].action === "hide" &&
      got.next?.fileId === "next-id",
  );
  assert(calls.length === 2 && JSON.parse(calls[1].json!).maxFileCount === 100);
  assert(
    calls.every((call) =>
      call.maximumBodyBytes === BACKUP_V2_LIMITS.controlResponseBytes &&
      call.maximumTimeMs === 120_000
    ),
  );
});
Deno.test("v2 pathological pages and cursor cycles fail closed without retries", async () => {
  for (
    const page of [
      { files: Array.from({ length: 101 }, () => listed()) },
      { files: [{ ...listed(), bucketId: "other" }] },
      { files: [{ ...listed(), fileName: "restic/direct-v1/x" }] },
      { files: [], nextFileName: name },
      { files: [], nextFileName: name, nextFileId: "same" },
    ]
  ) {
    const calls: BackupV2WireRequest[] = [];
    const store = new BackupV2Store(settings, fakeWire(page, calls));
    await rejects(
      store.versionsPage(BACKUP_V2_NAMESPACE, {
        fileName: name,
        fileId: "same",
      }),
    );
    assert(calls.length === 2);
  }
});
Deno.test("v2 rejects oversized and invalid control JSON with redacted errors", async () => {
  for (
    const body of [
      "fixture-secret not JSON",
      " ".repeat(BACKUP_V2_LIMITS.controlResponseBytes + 1),
    ]
  ) {
    const store = new BackupV2Store(
      settings,
      () => Promise.resolve(response(body)),
    );
    const error = await rejects(store.versionsPage(BACKUP_V2_NAMESPACE, null));
    assert(!error.message.includes("fixture-secret"));
  }
});
Deno.test("v2 strict auth scope does not broaden credentials", async () => {
  for (
    const mutate of [
      (value: ReturnType<typeof auth>) => {
        value.apiInfo.storageApi.apiUrl = "https://evil.invalid";
      },
      (value: ReturnType<typeof auth>) => {
        value.apiInfo.storageApi.allowed.namePrefix = "";
      },
      (value: ReturnType<typeof auth>) => {
        value.apiInfo.storageApi.allowed.buckets.push({
          id: "other",
          name: settings.bucketName,
        });
      },
    ]
  ) {
    const value = auth();
    mutate(value);
    let count = 0;
    const store = new BackupV2Store(settings, () => {
      count++;
      return Promise.resolve(response(value));
    });
    await rejects(store.versionsPage(BACKUP_V2_NAMESPACE, null));
    assert(count === 1);
  }
});
Deno.test("v2 already cancelled operations never contact the wire", async () => {
  let calls = 0;
  const store = new BackupV2Store(settings, () => {
    calls++;
    return Promise.resolve(response(auth()));
  });
  await rejects(
    store.versionsPage(BACKUP_V2_NAMESPACE, null, AbortSignal.abort()),
  );
  assert(calls === 0);
});

Deno.test("v2 slotless exact readback drains and hashes without filesystem permissions", async () => {
  const object = ref();
  for (
    const variant of [
      "good",
      "wrong-id",
      "corrupt",
      "truncated",
      "overflow",
      "failed-finish",
    ]
  ) {
    let calls = 0, cancelled = 0;
    const store = new BackupV2Store(settings, (request) => {
      calls++;
      if (request.url.endsWith("b2_authorize_account")) {
        return Promise.resolve(response(auth()));
      }
      assert(new URL(request.url).searchParams.get("fileId") === object.fileId);
      const headers = new Headers({
        "x-bz-file-id": variant === "wrong-id" ? "wrong" : object.fileId,
        "x-bz-file-name": encodeURIComponent(object.fileName),
        "x-bz-content-sha1": object.contentSha1,
      });
      let bytes = data.slice();
      if (variant === "corrupt") bytes[0] ^= 1;
      if (variant === "truncated") bytes = bytes.slice(1);
      if (variant === "overflow") bytes = new Uint8Array(data.length + 1);
      const finished = variant === "failed-finish"
        ? Promise.reject(new Error("SENSITIVE_PROVIDER_ERROR"))
        : Promise.resolve();
      finished.catch(() => {});
      return Promise.resolve({
        status: 200,
        headers,
        body: new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(bytes);
            c.close();
          },
        }),
        finished,
        cancel: () => {
          cancelled++;
          return Promise.resolve();
        },
      });
    });
    if (variant === "good") await store.verifyExactReadback(object);
    else {
      const error = await rejects(store.verifyExactReadback(object));
      assert(cancelled === 1 && !error.message.includes("SENSITIVE"));
    }
    assert(calls === 2, "exact readback silently retried");
  }
});

Deno.test("v2 GET HTTP failure classification preserves retry policy", async () => {
  for (const status of [429, 503, 403]) {
    const store = new BackupV2Store(
      settings,
      (request) =>
        Promise.resolve(
          request.url.endsWith("b2_authorize_account")
            ? response(auth())
            : response("not payload", status),
        ),
    );
    const error = await rejects(store.verifyExactReadback(ref()));
    assert(error instanceof BackupV2TransportError);
    assert(error.category === "http" && error.httpStatus === status);
    assert(error.retryable === (status !== 403) && !error.putMayHaveCommitted);
  }
});

Deno.test("v2 control and payload chains expose separate finite wait bounds", async () => {
  const bounds = BACKUP_V2_TRANSPORT_BOUNDS;
  assert(bounds.connectMs === 30_000 && bounds.lowSpeedMs === 120_000);
  assert(bounds.controlMs === 120_000 && bounds.payloadMs === 21_600_000);
  assert(bounds.settlementMs === 30_000);
  assert(
    bounds.putControlRequests === 2 && bounds.readbackControlRequests === 1,
  );
  assert(bounds.putEpisodeMs === 21_870_000);
  assert(bounds.readbackEpisodeMs === 21_750_000);
  const calls: BackupV2WireRequest[] = [];
  const store = new BackupV2Store(settings, (request) => {
    calls.push(request);
    if (request.url.endsWith("b2_authorize_account")) {
      return Promise.resolve(response(auth()));
    }
    const result = response("not payload", 503);
    return Promise.resolve(result);
  });
  await rejects(store.verifyExactReadback(ref()));
  assert(calls.length === 2);
  assert(calls[0].maximumTimeMs === bounds.controlMs);
  assert(calls[1].maximumTimeMs === bounds.payloadMs);
});

Deno.test("v2 exact reconciliation and deletion reject invalid refs before wire", async () => {
  const calls: BackupV2WireRequest[] = [];
  const store = new BackupV2Store(settings, fakeWire({}, calls));
  for (
    const invalid of [
      ref({ fileName: "restic/direct-v1/x" }),
      ref({ fileId: "" }),
      ref({ contentLength: 0 }),
      ref({ contentSha1: "none" }),
      ref({ uploadTimestamp: -1 }),
      ref({ sha256: "bad" }),
      { ...ref(), action: "hide" },
      { ...ref(), unknown: true },
    ]
  ) {
    await rejects(store.reconcileExact(invalid as BackupV2ObjectRef));
    await rejects(store.removeExact(invalid as BackupV2ObjectRef));
  }
  await rejects(store.reconcileExact(ref(), AbortSignal.abort()));
  await rejects(store.removeExact(ref(), AbortSignal.abort()));
  assert(calls.length === 0);
});

Deno.test("v2 exact reconciliation binds provider identity and immutable metadata", async () => {
  const calls: BackupV2WireRequest[] = [];
  const store = new BackupV2Store(settings, fakeWire(listed(), calls));
  assert(await store.reconcileExact(ref()) === "PRESENT");
  assert(calls.length === 2);
  assert(calls[1].url.endsWith("/b2api/v3/b2_get_file_info"));
  assert(
    JSON.stringify(JSON.parse(calls[1].json!)) === JSON.stringify({
      fileId: ref().fileId,
    }),
  );
  assert(calls.every((call) => call.maximumTimeMs === 120_000));
  for (
    const change of [
      { bucketId: "other" },
      { fileId: "other" },
      { fileName: "restic/direct-v1/x" },
      { action: "hide" },
      { contentLength: data.length + 1 },
      { contentSha1: "a".repeat(40) },
      { uploadTimestamp: 2 },
    ]
  ) {
    const conflicting = new BackupV2Store(
      settings,
      fakeWire({ ...listed(), ...change }),
    );
    await rejects(conflicting.reconcileExact(ref()), /metadata mismatch/);
  }
});

Deno.test("v2 exact absence requires the documented get-info status and code", async () => {
  for (
    const [status, body, absent] of [
      [404, { status: 404, code: "not_found" }, true],
      [404, { status: 400, code: "not_found" }, false],
      [404, { status: 404, code: "unknown" }, false],
      [404, { code: "not_found" }, false],
      [404, "not JSON", false],
      [400, { status: 400, code: "file_not_present" }, false],
      [401, { status: 401, code: "not_found" }, false],
      [403, { status: 403, code: "not_found" }, false],
      [500, { status: 500, code: "not_found" }, false],
      [200, { status: 404, code: "not_found" }, false],
      [202, listed(), false],
    ] as const
  ) {
    const calls: BackupV2WireRequest[] = [];
    const store = new BackupV2Store(settings, (request) => {
      calls.push(request);
      return Promise.resolve(
        request.url.endsWith("b2_authorize_account")
          ? response(auth())
          : response(body, status),
      );
    });
    if (absent) assert(await store.reconcileExact(ref()) === "ABSENT");
    else await rejects(store.reconcileExact(ref()));
    assert(calls.length === 2, "reconciliation silently retried");
  }
});

Deno.test("v2 exact reconciliation never treats auth network or lost body as absence", async () => {
  for (const fault of ["auth", "network", "body", "finished"]) {
    let calls = 0;
    const store = new BackupV2Store(settings, (request) => {
      calls++;
      if (request.url.endsWith("b2_authorize_account")) {
        return Promise.resolve(
          fault === "auth"
            ? response({ status: 401, code: "bad_auth_token" }, 401)
            : response(auth()),
        );
      }
      if (fault === "network") {
        return Promise.reject(new Error("SENSITIVE_NETWORK_DETAIL"));
      }
      const result = response({ status: 404, code: "not_found" }, 404);
      if (fault === "body") {
        result.body = new ReadableStream({
          start(controller) {
            controller.error(new Error("SENSITIVE_BODY_DETAIL"));
          },
        });
      } else {
        result.finished = Promise.reject(new Error("SENSITIVE_FINISH_DETAIL"));
        result.finished.catch(() => {});
      }
      return Promise.resolve(result);
    });
    const error = await rejects(store.reconcileExact(ref()));
    assert(!error.message.includes("SENSITIVE"));
    assert(calls === (fault === "auth" ? 1 : 2));
  }
});

Deno.test("v2 exact deletion sends one version and validates its echoed identity", async () => {
  const calls: BackupV2WireRequest[] = [];
  const object = ref();
  const store = new BackupV2Store(
    settings,
    fakeWire({
      fileId: object.fileId,
      fileName: object.fileName,
    }, calls),
  );
  await store.removeExact(object);
  assert(calls.length === 2);
  assert(calls[1].url.endsWith("/b2api/v3/b2_delete_file_version"));
  assert(calls[1].method === "POST" && calls[1].maximumTimeMs === 120_000);
  assert(
    calls[1].json === JSON.stringify({
      fileName: object.fileName,
      fileId: object.fileId,
    }),
  );
});

Deno.test("v2 exact deletion response loss conflicts and errors never replay deletion", async () => {
  for (
    const fault of [
      "network",
      "body",
      "finished",
      "id",
      "name",
      "http",
      "absent",
      "accepted",
    ]
  ) {
    let deletes = 0, cancelled = 0;
    const store = new BackupV2Store(settings, (request) => {
      if (request.url.endsWith("b2_authorize_account")) {
        return Promise.resolve(response(auth()));
      }
      assert(request.url.endsWith("b2_delete_file_version"));
      deletes++;
      if (fault === "network") {
        return Promise.reject(new Error("SENSITIVE_DELETE_DETAIL"));
      }
      const result = fault === "http"
        ? response({ status: 503, code: "service_unavailable" }, 503)
        : fault === "absent"
        ? response({ status: 400, code: "file_not_present" }, 400)
        : fault === "accepted"
        ? response({ fileId: ref().fileId, fileName: name }, 202)
        : response({
          fileId: fault === "id" ? "other" : ref().fileId,
          fileName: fault === "name" ? "other" : name,
        });
      result.cancel = () => {
        cancelled++;
        return Promise.resolve();
      };
      if (fault === "body") {
        result.body = new ReadableStream({
          start(controller) {
            controller.error(new Error("SENSITIVE_DELETE_BODY"));
          },
        });
      }
      if (fault === "finished") {
        result.finished = Promise.reject(new Error("SENSITIVE_DELETE_FINISH"));
        result.finished.catch(() => {});
      }
      return Promise.resolve(result);
    });
    const error = await rejects(store.removeExact(ref()));
    assert(deletes === 1 && !error.message.includes("SENSITIVE"));
    assert(cancelled === (["network", "id", "name"].includes(fault) ? 0 : 1));
  }
});

async function consume(
  result: BackupV2WireResponse,
): Promise<Uint8Array<ArrayBuffer>> {
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    for await (const part of result.body) {
      parts.push(part);
      size += part.length;
    }
    await result.finished;
    const all = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) {
      all.set(part, offset);
      offset += part.length;
    }
    return all;
  } catch (error) {
    await result.cancel();
    throw error;
  }
}
function loopback(
  handler: (request: Request) => Response | Promise<Response>,
) {
  const server = Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen() {} },
    handler,
  );
  const address = server.addr as Deno.NetAddr;
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => server.shutdown(),
  };
}
function curl() {
  return createCurlBackupV2Wire({
    loopback: true,
    connectSeconds: 0.25,
    lowSpeedSeconds: 1,
  });
}

Deno.test({
  name:
    "native: curl total request bound covers delayed headers and active body",
  ignore: !native,
  async fn() {
    for (const phase of ["headers", "body"]) {
      let timer: ReturnType<typeof setInterval> | undefined;
      let finishTimer: ReturnType<typeof setTimeout> | undefined;
      const server = await loopback(async () => {
        if (phase === "headers") {
          await new Promise((done) => setTimeout(done, 600));
          return new Response("finished");
        }
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(encoder.encode("a"));
              timer = setInterval(
                () => controller.enqueue(encoder.encode("a")),
                50,
              );
              finishTimer = setTimeout(() => {
                clearInterval(timer);
                controller.close();
              }, 600);
            },
            cancel() {
              clearInterval(timer);
              clearTimeout(finishTimer);
            },
          }),
        );
      });
      try {
        const started = performance.now();
        await rejects(
          curl()(raw(server.url, { maximumTimeMs: 250 })).then(consume),
        );
        assert(
          performance.now() - started < 1000,
          "total request bound did not apply",
        );
      } finally {
        clearInterval(timer);
        clearTimeout(finishTimer);
        await server.close();
      }
    }
  },
});

Deno.test({
  name:
    "native: curl TLS connection timeout is distinct from delayed HTTP headers",
  ignore: !native,
  async fn() {
    for (const tls of [true, false]) {
      const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
      const address = listener.addr as Deno.NetAddr;
      const served = (async () => {
        const connection = await listener.accept();
        try {
          const buffer = new Uint8Array(8192);
          await connection.read(buffer);
          if (tls) {
            while (
              await connection.read(buffer) !== null
            ) { /* leave TLS handshake incomplete */ }
          } else {
            await new Promise((done) => setTimeout(done, 550));
            await connection.write(
              encoder.encode(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
              ),
            );
          }
        } finally {
          connection.close();
        }
      })();
      try {
        const started = performance.now();
        const result = curl()(
          raw(`${tls ? "https" : "http"}://127.0.0.1:${address.port}/`),
        ).then(consume);
        if (tls) {
          await rejects(result);
          assert(
            performance.now() - started < 4000,
            "TLS connect bound not applied",
          );
        } else {
          await result;
          assert(
            performance.now() - started >= 500,
            "response header delay was not exercised",
          );
        }
        await served;
      } finally {
        listener.close();
      }
    }
  },
});
const raw = (
  url: string,
  overrides: Partial<BackupV2WireRequest> = {},
): BackupV2WireRequest => ({
  url,
  method: "GET",
  headers: {},
  maximumBodyBytes: 1024,
  ...overrides,
});

Deno.test({
  name: "native: curl does not follow redirect or replay retryable HTTP status",
  ignore: !native,
  async fn() {
    let count = 0;
    const server = await loopback(() => {
      count++;
      return new Response("", {
        status: count === 1 ? 307 : 503,
        headers: { location: "/again" },
      });
    });
    try {
      const first = await curl()(raw(server.url));
      assert(first.status === 307);
      await consume(first);
      assert(count === 1);
      const second = await curl()(raw(server.url));
      assert(second.status === 503);
      await consume(second);
      assert(Number(count) === 2);
    } finally {
      await server.close();
    }
  },
});
Deno.test({
  name:
    "native: curl body bounds cancellation and low speed settle owned child",
  ignore: !native,
  async fn() {
    let keep: ReadableStreamDefaultController<Uint8Array> | undefined;
    const server = await loopback((request) => {
      if (new URL(request.url).pathname === "/overflow") {
        return new Response("x".repeat(2048));
      }
      return new Response(
        new ReadableStream({
          start(c) {
            keep = c;
            c.enqueue(encoder.encode("a"));
          },
        }),
      );
    });
    try {
      await rejects(curl()(raw(server.url + "/overflow")).then(consume));
      const before = performance.now();
      await rejects(curl()(raw(server.url + "/stall")).then(consume));
      assert(
        performance.now() - before < 8000,
        "low-speed window did not stop transfer",
      );
      const cancel = new AbortController();
      const pending = curl()(
        raw(server.url + "/abort", { signal: cancel.signal }),
      ).then(consume);
      const timer = setTimeout(() => cancel.abort(), 100);
      try {
        await rejects(pending);
      } finally {
        clearTimeout(timer);
      }
    } finally {
      try {
        keep?.close();
      } catch { /* cancelled */ }
      await server.close();
    }
  },
});
Deno.test({
  name: "native: curl dropped PUT response is one wire attempt",
  ignore: !native,
  async fn() {
    const directory = await Deno.makeTempDir({
      dir: "/var/tmp",
      prefix: "backup-v2-wire-",
    });
    const path = directory + "/payload";
    await Deno.writeFile(path, data, { mode: 0o600 });
    const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
    const address = listener.addr as Deno.NetAddr;
    let requests = 0;
    const handle = async (connection: Deno.Conn) => {
      requests++;
      try {
        let bytes = new Uint8Array(0), boundary = -1;
        const scratch = new Uint8Array(4096);
        while (boundary < 0) {
          const n = await connection.read(scratch);
          assert(n !== null);
          const joined = new Uint8Array(bytes.length + n);
          joined.set(bytes);
          joined.set(scratch.subarray(0, n), bytes.length);
          bytes = joined;
          boundary = new TextDecoder().decode(bytes).indexOf("\r\n\r\n");
        }
        const header = new TextDecoder().decode(bytes.subarray(0, boundary));
        assert(header.startsWith("POST "));
        assert(!/^expect:/im.test(header), "Expect replay path was enabled");
        assert(
          /content-length: 27\r?$/im.test(header) ||
            header.toLowerCase().includes(`content-length: ${data.length}`),
        );
        let received = bytes.length - boundary - 4;
        while (received < data.length) {
          const n = await connection.read(scratch);
          assert(n !== null);
          received += n;
        }
      } finally {
        connection.close();
      }
    };
    const served = (async () => {
      for await (const connection of listener) await handle(connection);
    })();
    served.catch(() => {});
    try {
      const attempts = [["upload", 1], ["counter-proof", 2]] as const;
      for (const [suffix, expected] of attempts) {
        await rejects(
          curl()(
            raw(`http://127.0.0.1:${address.port}/${suffix}`, {
              method: "POST",
              uploadPath: path,
              headers: {
                authorization: "SYNTHETIC_TOKEN",
                "content-length": String(data.length),
              },
            }),
          ).then(consume),
        );
        assert(
          requests === expected,
          "concealed replay or listener counter failure",
        );
      }
    } finally {
      listener.close();
      await served.catch((error) => {
        if (!(error instanceof Deno.errors.BadResource)) throw error;
      });
      await Deno.remove(directory, { recursive: true });
    }
  },
});
Deno.test({
  name:
    "native: v2 actual root slot PUT exact GET and failed slot preservation",
  ignore: !native,
  async fn() {
    const directory = await Deno.makeTempDir({
      dir: "/var/tmp",
      prefix: "backup-v2-store-",
    });
    await Deno.chmod(directory, 0o700);
    const path = directory + "/sealed";
    await Deno.writeFile(path, data, { mode: 0o600 });
    const info = await Deno.stat(path);
    assert(info.uid === 0, "native slot fixture requires root-owned files");
    const slot: BackupV2SealedSlot = {
      index: 0,
      path,
      device: info.dev!,
      inode: info.ino!,
      bytes: data.length,
      sha1: hash(data, "sha1"),
      sha256: hash(data),
      uid: 0,
      mode: 0o600,
      links: 1,
    };
    const intent: BackupV2PutIntent = {
      captureId,
      role: "root",
      attemptId,
      kind: "data",
      ordinal: 0,
      offset: 0,
      putId,
      createdAtUtc: "2026-10-18T00:00:00.000Z",
      slot,
      name,
    };
    let uploads = 0, corrupt = false;
    const server = await loopback(async (request) => {
      const uri = new URL(request.url);
      if (uri.pathname.endsWith("b2_authorize_account")) {
        return Response.json(auth());
      }
      if (uri.pathname.endsWith("b2_get_upload_url")) {
        return Response.json({
          bucketId,
          uploadUrl: "https://pod-x.backblaze.com/upload",
          authorizationToken: "fixture-upload-token",
        });
      }
      if (uri.pathname === "/upload") {
        uploads++;
        const received = new Uint8Array(await request.arrayBuffer());
        assert(hash(received) === hash(data));
        return Response.json({ ...listed(), action: "upload" });
      }
      assert(uri.searchParams.get("fileId") === "fixture-file-id");
      const payload = data.slice();
      if (corrupt) payload[0] ^= 1;
      return new Response(payload, {
        headers: {
          "x-bz-file-id": "fixture-file-id",
          "x-bz-file-name": encodeURIComponent(name),
          "x-bz-content-sha1": hash(data, "sha1"),
          "content-length": String(data.length),
        },
      });
    });
    const transport = curl();
    const store = new BackupV2Store(settings, (request) => {
      const url = new URL(request.url);
      return transport({
        ...request,
        url: server.url + url.pathname + url.search,
      });
    });
    try {
      const object = await store.putFileOnce(intent);
      assert(uploads === 1 && object.sha256 === slot.sha256);
      const originalEntries = Array.from(
        Deno.readDirSync(directory),
        (item) => item.name,
      ).sort().join();
      await store.verifyExactReadback(object);
      assert(
        Array.from(Deno.readDirSync(directory), (item) => item.name).sort()
          .join() === originalEntries,
        "slotless readback created a third payload file",
      );
      const restored = await store.getExactToFile(object, {
        index: 1,
        path: directory + "/readback",
      });
      assert(restored.sha256 === hash(data));
      corrupt = true;
      await rejects(store.verifyExactReadback(object));
      await rejects(
        store.getExactToFile(object, { index: 1, path: directory + "/bad" }),
      );
      assert(
        (await Deno.stat(directory + "/bad")).size === data.length,
        "unverified partial was silently reclaimed",
      );
      await Deno.link(path, directory + "/hardlink");
      await rejects(store.putFileOnce(intent));
      assert(uploads === 1, "changed sealed identity reached upload");
    } finally {
      await server.close();
      await Deno.remove(directory, { recursive: true });
    }
  },
});
