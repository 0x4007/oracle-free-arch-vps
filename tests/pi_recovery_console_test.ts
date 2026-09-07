import {
  consoleCapturePlan,
  type ConsoleCapturePorts,
  type ConsoleCaptureState,
  stepConsoleCapture,
} from "../scripts/pi-recovery-console.ts";
import type { JsonRecord } from "../scripts/oci.ts";
function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
async function rejects(work: Promise<unknown>, fragment: string) {
  try {
    await work;
  } catch (error) {
    assert(String(error).includes(fragment));
    return;
  }
  throw Error("Expected refusal");
}
const time = Date.parse("2026-09-07T02:00:00.000Z");
const requestId = "recovery-681c4067-aec2-45d5-9afb-77ee530e3a97";
const plan = consoleCapturePlan({
  requestId,
  instanceId: "ocid1.instance.example.replacement",
  phase: "loader",
  notBeforeUtc: new Date(time).toISOString(),
}, "ocid1.compartment.example.target");
const approval = {
  planSha256: plan.planSha256,
  exactOperation: plan.operation,
  approvedAtUtc: new Date(time).toISOString(),
};
const bytes = new Uint8Array(51);
const view = new DataView(bytes.buffer);
view.setUint32(0, 11);
bytes.set(new TextEncoder().encode("ssh-ed25519"), 4);
view.setUint32(15, 32);
bytes.fill(3, 19);
const key = "ssh-ed25519 " + btoa(String.fromCharCode(...bytes));
const marker =
  `UOS_RECOVERY_HOST_KEY ${requestId} loader 781c4067-aec2-45d5-9afb-77ee530e3a97 - ${key}`;
function fixture() {
  const f = {
    now: time + 1000,
    creates: 0,
    saves: 0,
    before: 0,
    lost: false,
    pending: false,
    noMarker: false,
    failPersist: false,
    records: [] as JsonRecord[],
    saved: { planSha256: plan.planSha256, attempts: [] } as ConsoleCaptureState,
  };
  const ports: ConsoleCapturePorts = {
    now: () => f.now,
    beforeMutation: () => {
      f.before++;
      return Promise.resolve();
    },
    persist: (state) => {
      if (f.failPersist) return Promise.reject(Error("Pi fsync failed"));
      f.saves++;
      f.saved = structuredClone(state);
      return Promise.resolve();
    },
    text: () => Promise.resolve(f.noMarker ? "booting" : marker),
    json: (args) => {
      let data: unknown;
      if (args[2] === "list") data = f.records;
      else if (args[2] === "capture") {
        assert(
          f.saved.attempts.at(-1)?.historyId === undefined &&
            f.saved.attempts.length === f.creates + 1,
        );
        f.creates++;
        const record = {
          id: `ocid1.consolehistory.example.capture${f.creates}`,
          "instance-id": plan.expected.instanceId,
          "lifecycle-state": "REQUESTED",
          "time-created": new Date(f.now).toISOString(),
          "freeform-tags": JSON.parse(
            args[args.indexOf("--freeform-tags") + 1],
          ),
        };
        f.records.push(record);
        if (f.lost) {
          f.lost = false;
          return Promise.reject(Error("lost CREATE response"));
        }
        data = record;
      } else if (args[2] === "get") {
        data = {
          ...f.records.find((record) => record.id === args.at(-1)),
          "lifecycle-state": f.pending ? "GETTING-HISTORY" : "SUCCEEDED",
        };
      } else throw Error("Unexpected Oracle operation");
      return Promise.resolve({ data });
    },
  };
  return { f, ports, state: () => structuredClone(f.saved) };
}
Deno.test("console capture persists intent before CREATE and saves verified host key", async () => {
  const { f, ports, state } = fixture();
  const result = await stepConsoleCapture(plan, approval, state(), ports);
  assert(
    result.status === "RECOVERY_HOST_KEY_VERIFIED" && f.creates === 1 &&
      f.before === 2 && f.saved.host?.publicKey === key,
  );
  await stepConsoleCapture(plan, approval, state(), ports);
  assert(f.creates === 1);
});
Deno.test("lost capture response reconciles exact tags without duplicate CREATE", async () => {
  const { f, ports, state } = fixture();
  f.lost = true;
  await rejects(
    stepConsoleCapture(plan, approval, state(), ports),
    "lost CREATE",
  );
  assert(f.creates === 1 && !f.saved.attempts[0].historyId);
  const result = await stepConsoleCapture(plan, approval, state(), ports);
  assert(result.status === "RECOVERY_HOST_KEY_VERIFIED" && f.creates === 1);
});
Deno.test("uncertain capture with no matching provider record cannot be recreated", async () => {
  const { f, ports, state } = fixture();
  f.lost = true;
  await rejects(
    stepConsoleCapture(plan, approval, state(), ports),
    "lost CREATE",
  );
  f.records = [];
  await rejects(
    stepConsoleCapture(plan, approval, state(), ports),
    "Uncertain console capture",
  );
  assert(f.creates === 1);
});
Deno.test("failed persistence or expired approval prevents console mutation", async () => {
  const { f, ports, state } = fixture();
  f.failPersist = true;
  await rejects(
    stepConsoleCapture(plan, approval, state(), ports),
    "fsync failed",
  );
  assert(f.creates === 0);
  f.failPersist = false;
  await rejects(
    stepConsoleCapture(
      plan,
      { ...approval, approvedAtUtc: new Date(time - 3600001).toISOString() },
      state(),
      ports,
    ),
    "exact console-capture",
  );
  assert(f.creates === 0);
});
Deno.test("pending history is reread and missing markers have a fixed capture budget", async () => {
  const first = fixture();
  first.f.pending = true;
  assert(
    (await stepConsoleCapture(plan, approval, first.state(), first.ports))
      .status === "CONSOLE_CAPTURE_PENDING",
  );
  await stepConsoleCapture(plan, approval, first.state(), first.ports);
  assert(first.f.creates === 1);
  const { f, ports, state } = fixture();
  f.noMarker = true;
  for (let index = 0; index < 3; index++) {
    await stepConsoleCapture(plan, approval, state(), ports);
    await stepConsoleCapture(plan, approval, state(), ports);
    assert(f.creates === index + 1);
    f.now += 30000;
  }
  await rejects(
    stepConsoleCapture(plan, approval, state(), ports),
    "limit exhausted",
  );
  assert(f.creates === 3 && f.records.length === 3);
});
Deno.test("saved host receipt cannot be replayed with a changed phase or fingerprint", async () => {
  const { f, ports, state } = fixture();
  await stepConsoleCapture(plan, approval, state(), ports);
  f.saved.host!.fingerprint = "SHA256:changed";
  await rejects(
    stepConsoleCapture(plan, approval, state(), ports),
    "fingerprint changed",
  );
  await rejects(
    stepConsoleCapture(
      { ...plan, expected: { ...plan.expected, phase: "ram" } },
      approval,
      state(),
      ports,
    ),
    "target is incomplete",
  );
  assert(f.creates === 1);
});

Deno.test("console plans reject invalid boot transitions before capture", () => {
  const prior = "781c4067-aec2-45d5-9afb-77ee530e3a97";
  const valid = {
    ...plan.expected,
    phase: "ram" as const,
    previousBootId: prior,
    manifestSha256: "a".repeat(64),
  };
  consoleCapturePlan(valid, plan.compartmentId);
  for (
    const change of [
      { manifestSha256: undefined },
      { manifestSha256: "bad" },
      { previousBootId: undefined },
      { previousBootId: "bad" },
      { expectedBootId: "bad" },
      { expectedBootId: prior },
    ]
  ) {
    let refused = false;
    try {
      consoleCapturePlan({ ...valid, ...change }, plan.compartmentId);
    } catch {
      refused = true;
    }
    assert(refused);
  }
});
