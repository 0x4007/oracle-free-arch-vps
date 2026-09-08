import {
  type ConsoleHostExpectation,
  hostKeyConsoleCommand,
  recoveryControlRunner,
  recoverySshArgs,
  retainRecoveryHost,
  verifyConsoleHostKey,
} from "../scripts/pi-recovery-ssh.ts";
function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
function refuses(work: () => unknown, fragment: string) {
  try {
    work();
  } catch (error) {
    assert(String(error).includes(fragment));
    return;
  }
  throw Error("Expected refusal");
}
const requestId = "recovery-681c4067-aec2-45d5-9afb-77ee530e3a97";
const bootId = "781c4067-aec2-45d5-9afb-77ee530e3a97";
const keyBytes = new Uint8Array(51);
const view = new DataView(keyBytes.buffer);
view.setUint32(0, 11);
keyBytes.set(new TextEncoder().encode("ssh-ed25519"), 4);
view.setUint32(15, 32);
keyBytes.fill(2, 19);
const publicKey = "ssh-ed25519 " + btoa(String.fromCharCode(...keyBytes));
const expected: ConsoleHostExpectation = {
  requestId,
  instanceId: "ocid1.instance.example.replacement",
  phase: "ram",
  notBeforeUtc: "2026-09-07T02:00:00.000Z",
  previousBootId: "681c4067-aec2-45d5-9afb-77ee530e3a97",
  manifestSha256: "ab".repeat(32),
};
const metadata = {
  id: "ocid1.consolehistory.example.snapshot",
  "instance-id": expected.instanceId,
  "lifecycle-state": "SUCCEEDED",
  "time-created": "2026-09-07T02:00:01.000Z",
};
const now = Date.parse("2026-09-07T02:00:02.000Z");
const marker =
  `UOS_RECOVERY_HOST_KEY ${requestId} ram ${bootId} ${expected.manifestSha256} ${publicKey}`;
Deno.test("console public key is bound to request phase boot and manifest", () => {
  const host = verifyConsoleHostKey(
    metadata,
    "boot messages\n" + marker + "\n" + marker,
    expected,
    now,
  );
  assert(
    host.publicKey === publicKey && host.bootId === bootId &&
      host.manifestSha256 === expected.manifestSha256 &&
      host.fingerprint.startsWith("SHA256:"),
  );
});
Deno.test("wrong instance stale capture wrong phase copied boot and changed manifest refuse", () => {
  for (
    const [meta, text, want, fragment] of [
      [
        { ...metadata, "instance-id": "ocid1.instance.example.source" },
        marker,
        expected,
        "Console evidence",
      ],
      [
        { ...metadata, "time-created": "2026-09-07T01:00:00.000Z" },
        marker,
        expected,
        "Console evidence",
      ],
      [metadata, marker.replace(" ram ", " loader "), expected, "absent"],
      [metadata, marker, { ...expected, previousBootId: bootId }, "transition"],
      [
        metadata,
        marker,
        { ...expected, manifestSha256: "cd".repeat(32) },
        "transition",
      ],
    ] as const
  ) refuses(() => verifyConsoleHostKey(meta, text, want, now), fragment);
});
Deno.test("ambiguous console boots and malformed host-key blobs refuse", () => {
  refuses(
    () =>
      verifyConsoleHostKey(
        metadata,
        marker + "\n" +
          marker.replace(bootId, "881c4067-aec2-45d5-9afb-77ee530e3a97"),
        expected,
        now,
      ),
    "ambiguous",
  );
  refuses(
    () =>
      verifyConsoleHostKey(
        metadata,
        marker.replace(publicKey, "ssh-ed25519 YWJj"),
        expected,
        now,
      ),
    "malformed",
  );
  refuses(
    () => verifyConsoleHostKey(metadata, marker + " extra", expected, now),
    "Malformed",
  );
  refuses(
    () =>
      verifyConsoleHostKey(
        metadata,
        "x".repeat(1024 * 1024 + 1),
        expected,
        now,
      ),
    "Console evidence",
  );
});
Deno.test("SSH command uses dedicated pinned host key and existing non-root Pi identity", () => {
  const host = verifyConsoleHostKey(metadata, marker, expected, now);
  const alias = `${requestId}-ram-${bootId}`;
  const target = {
    host,
    address: "203.0.113.10",
    knownHostsPath:
      `/home/pi/ops/weekly-backup-controller/.private/recovery-known-hosts/${alias}`,
  };
  const args = recoverySshArgs(target, "printf", ["$(touch /bad); literal"]);
  assert(
    args.includes("StrictHostKeyChecking=yes") &&
      args.includes("GlobalKnownHostsFile=/dev/null") &&
      args.includes("HostKeyAlgorithms=ssh-ed25519") &&
      args.includes("codex@203.0.113.10") &&
      args.includes("/home/pi/.ssh/id_ed25519"),
  );
  assert(args.at(-1) === "'printf' '$(touch /bad); literal'");
  for (
    const address of [
      "pi.local",
      "127.0.0.1",
      "192.168.1.1",
      "203.000.113.10",
      "203.0.113.10 -o Bad=yes",
    ]
  ) {
    refuses(
      () => recoverySshArgs({ ...target, address }, "true"),
      "public IPv4",
    );
  }
  refuses(
    () =>
      recoverySshArgs({
        ...target,
        knownHostsPath: "/home/pi/.ssh/known_hosts",
      }, "true"),
    "target or command",
  );
});
const io =
  (await Deno.permissions.query({ name: "read" })).state === "granted" &&
  (await Deno.permissions.query({ name: "write" })).state === "granted";
Deno.test({
  name:
    "known-host retention is private idempotent and refuses changed content",
  ignore: !io,
  fn: async () => {
    const previous = Deno.cwd();
    const directory = await Deno.makeTempDir();
    try {
      Deno.chdir(directory);
      const host = verifyConsoleHostKey(metadata, marker, expected, now);
      const target = await retainRecoveryHost(host, "203.0.113.10");
      assert(
        ((await Deno.stat(target.knownHostsPath)).mode! & 0o777) === 0o600,
      );
      await retainRecoveryHost(host, "203.0.113.10");
      await Deno.writeTextFile(target.knownHostsPath, "changed\n");
      let refused = false;
      try {
        await retainRecoveryHost(host, "203.0.113.10");
      } catch {
        refused = true;
      }
      assert(refused);
    } finally {
      Deno.chdir(previous);
      await Deno.remove(directory, { recursive: true });
    }
  },
});
Deno.test("host-key marker targets the OCI serial device for every phase", () => {
  for (const phase of ["loader", "ram", "restored"] as const) {
    const script = hostKeyConsoleCommand(requestId, phase);
    assert(
      script.endsWith(">/dev/ttyAMA0") &&
        !script.includes(">/dev/console"),
    );
  }
});
Deno.test({
  name: "console marker commands parse as shell without generating keys",
  ignore:
    (await Deno.permissions.query({ name: "run", command: "bash" })).state !==
      "granted",
  fn: async () => {
    for (const phase of ["loader", "ram", "restored"] as const) {
      const script = hostKeyConsoleCommand(requestId, phase);
      assert(!script.includes("ssh-keygen"));
      const child = new Deno.Command("bash", {
        args: ["-n"],
        stdin: "piped",
        stdout: "null",
        stderr: "piped",
      }).spawn();
      const writer = child.stdin.getWriter();
      await writer.write(new TextEncoder().encode(script));
      await writer.close();
      writer.releaseLock();
      assert((await child.output()).success);
    }
  },
});

Deno.test({
  name: "control runner bounds both streams from real harmless subprocesses",
  ignore:
    (await Deno.permissions.query({ name: "run", command: Deno.execPath() }))
      .state !== "granted",
  fn: async () => {
    for (const stream of ["stdout", "stderr"]) {
      let refused = false;
      try {
        await recoveryControlRunner(Deno.execPath(), [
          "eval",
          `Deno.${stream}.writeSync(new Uint8Array(1024 * 1024 + 1));`,
        ]);
      } catch (error) {
        refused = String(error).includes("control command failed");
      }
      assert(refused);
    }
    const result = await recoveryControlRunner(Deno.execPath(), [
      "eval",
      'console.log("control record")',
    ]);
    assert(result.code === 0 && result.stdout.trim() === "control record");
  },
});
