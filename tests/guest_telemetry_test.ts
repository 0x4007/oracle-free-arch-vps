import {
  guestNetworkRate,
  main,
  parseGuestSample,
  readGuestTelemetrySummary,
  summarizeGuestSamples,
} from "../scripts/guest-telemetry.ts";
const root = "11111111-1111-4111-8111-111111111111";
const instance = "ocid1.instance.oc1.iad.fixture";
const time = new Date("2026-09-11T06:00:00.000Z");
const raw = `BOOT 22222222-2222-4222-8222-222222222222
ROOT ${root}
UPTIME 1000.00 1500.00
MEMORY
MemTotal: 1000 kB
MemAvailable: 600 kB
ROUTES
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
enp0s6 00000000 0101000A 0003 0 0 1024 00000000 0 0 0
NETWORK
Inter-| Receive | Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
lo: 99999 0 0 0 0 0 0 0 99999 0 0 0 0 0 0 0
enp0s6: 10000 0 0 0 0 0 0 0 20000 0 0 0 0 0 0 0
docker0: 99999 0 0 0 0 0 0 0 99999 0 0 0 0 0 0 0
`;
const sample = () => parseGuestSample(raw, instance, root, time);
function assert(value: unknown) {
  if (!value) throw Error("Assertion failed");
}
function rejects(run: () => unknown) {
  let failed = false;
  try {
    run();
  } catch {
    failed = true;
  }
  assert(failed);
}
Deno.test("guest telemetry uses available memory and only the default-route interface", () => {
  const s = sample();
  assert(s.memoryUsedPercent === 40 && s.memoryTotalBytes === 1024000);
  assert(
    s.interface === "enp0s6" && s.receivedBytes === 10000 &&
      s.transmittedBytes === 20000,
  );
});
Deno.test("guest telemetry refuses wrong roots, missing memory and ambiguous default routes", () => {
  rejects(() =>
    parseGuestSample(raw, instance, root.replaceAll("1", "3"), time)
  );
  rejects(() =>
    parseGuestSample(
      raw.replace("MemAvailable: 600 kB", "MemAvailable: 1001 kB"),
      instance,
      root,
      time,
    )
  );
  rejects(() =>
    parseGuestSample(
      raw.replace("MemAvailable: 600 kB", ""),
      instance,
      root,
      time,
    )
  );
  rejects(() =>
    parseGuestSample(
      raw.replace(
        "NETWORK\n",
        "enp1 00000000 0101000A 0003 0 0 1024 00000000 0 0 0\nNETWORK\n",
      ),
      instance,
      root,
      time,
    )
  );
});
Deno.test("network rates require consecutive same-boot and same-interface samples", () => {
  const first = sample();
  const next = {
    ...first,
    uptimeSeconds: 1060,
    observedAtUtc: "2026-09-11T06:01:00.000Z",
    receivedBytes: 16000,
    transmittedBytes: 32000,
  };
  const rate = guestNetworkRate(next, first);
  assert(
    rate.status === "observed" && rate.receivedBytesPerSecond === 100 &&
      rate.transmittedBytesPerSecond === 200,
  );
  assert(guestNetworkRate(next).status === "baseline-required");
  for (
    const change of [
      { bootId: root },
      { interface: "enp1" },
      { receivedBytes: 1 },
      { uptimeSeconds: 1200 },
      { observedAtUtc: "invalid" },
      { receivedBytes: NaN },
    ]
  ) {
    assert(
      guestNetworkRate({ ...next, ...change }, first).status ===
        "discontinuity",
    );
  }
});
Deno.test("guest coverage does not fill missing minutes or include other sources and endpoints", () => {
  const s = sample(), end = new Date(time.getTime() + 3600000);
  const points = Array.from(
    { length: 60 },
    (_, i) => ({
      ...s,
      observedAtUtc: new Date(time.getTime() + i * 60000).toISOString(),
      uptimeSeconds: 1000 + i * 60,
      receivedBytes: 10000 + i * 100,
      transmittedBytes: 20000 + i * 100,
    }),
  );
  const full = summarizeGuestSamples(points, instance, time, end);
  assert(
    full.status === "complete" && full.missingMinutes === 0 &&
      full.networkIntervalsObserved === 59 && full.networkStatus === "complete",
  );
  const partial = summarizeGuestSamples(
    [...points.slice(1), points[1], { ...s, instanceId: "other" }, {
      ...s,
      observedAtUtc: end.toISOString(),
    }],
    instance,
    time,
    end,
  );
  assert(
    partial.status === "incomplete" && partial.observedMinutes === 59 &&
      partial.missingMinutes === 1,
  );
  assert(
    partial.nativeOracleAgent === false && partial.idlePolicyEvidence === false,
  );
});
Deno.test("guest network discontinuity remains visible with complete memory coverage", () => {
  const s = sample(), end = new Date(time.getTime() + 120000);
  const result = summarizeGuestSamples(
    [s, {
      ...s,
      observedAtUtc: new Date(time.getTime() + 60000).toISOString(),
      bootId: root,
      uptimeSeconds: 10,
    }],
    instance,
    time,
    end,
  );
  assert(
    result.status === "complete" && result.networkStatus === "incomplete" &&
      result.networkIntervalsObserved === 0,
  );
});

Deno.test({
  name:
    "collector preserves an interrupted fragment and the next successful sample",
  ignore:
    (await Deno.permissions.query({ name: "read" })).state !== "granted" ||
    (await Deno.permissions.query({ name: "write" })).state !== "granted",
  fn: async () => {
    const previous = Deno.cwd(), directory = await Deno.makeTempDir();
    try {
      Deno.chdir(directory);
      await Deno.mkdir(".private/guest-telemetry", { recursive: true });
      await Deno.writeTextFile(
        ".private/backup-controller.json",
        JSON.stringify({
          source: { instanceId: instance },
          guest: { host: "codex@vps.pavlovcik.com", rootUuid: root },
        }),
        { mode: 0o600 },
      );
      const date = new Date().toISOString().slice(0, 10);
      const path = `.private/guest-telemetry/${date}.jsonl`;
      await Deno.writeTextFile(path, '{"sample":');
      await main(() => Promise.resolve({ code: 0, stdout: raw, stderr: "" }));
      const lines = (await Deno.readTextFile(path)).trimEnd().split("\n");
      assert(lines.length === 2 && lines[0] === '{"sample":');
      assert(JSON.parse(lines[1]).sample.instanceId === instance);
      const end = new Date(Math.floor(Date.now() / 60000) * 60000 + 60000);
      const summary = await readGuestTelemetrySummary(
        instance,
        new Date(end.getTime() - 120000),
        end,
      );
      assert(summary.observedMinutes === 1 && summary.malformedRecords === 1);
    } finally {
      Deno.chdir(previous);
      await Deno.remove(directory, { recursive: true });
    }
  },
});
