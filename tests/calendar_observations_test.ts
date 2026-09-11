import {
  observationFailure,
  observationTiming,
  readPostedCosts,
  summarizePostedCosts,
} from "../scripts/calendar-observations.ts";
import { readGuestTelemetrySummary } from "../scripts/guest-telemetry.ts";
function assert(v: unknown) {
  if (!v) throw Error("Assertion failed");
}
function refuses(fn: () => unknown) {
  try {
    fn();
  } catch {
    return;
  }
  throw Error("Expected refusal");
}
Deno.test("early observations cannot stand in for future calendar evidence", () => {
  const r = observationTiming(new Date("2026-09-11T06:00:00Z"));
  assert(
    r.mode === "baseline" && r.latestDueAtUtc === null &&
      !r.historicalStateReconstructed,
  );
});
Deno.test("catch-up records current time rather than backdating a missed milestone", () => {
  const r = observationTiming(new Date("2026-09-21T06:00:00Z"));
  assert(
    r.mode === "late-current-observation" &&
      r.observedAtUtc === "2026-09-21T06:00:00.000Z" &&
      r.latestDueAtUtc === "2026-09-20T06:00:00.000Z" &&
      !r.historicalStateReconstructed,
  );
});
const item = {
  currency: "USD",
  "is-forecast": false,
  "computed-amount": 0,
  "time-usage-started": "2026-10-01T00:00:00Z",
  "time-usage-ended": "2026-10-02T00:00:00Z",
};
Deno.test("empty and zero posted cost do not establish a finalized zero bill", () => {
  const empty = summarizePostedCosts({ data: { items: [] } }),
    zero = summarizePostedCosts({ data: { items: [item] } });
  assert(empty.status === "no-cost-data" && !empty.zeroBillProved);
  assert(
    zero.status === "provisional-cost-reported" && zero.postedAmountUsd === 0 &&
      !zero.finalizedStatementProved && !zero.zeroBillProved,
  );
});
Deno.test("forecast, unknown currency and missing cost rows refuse", () => {
  for (
    const change of [{ currency: "EUR" }, { "is-forecast": true }, {
      "computed-amount": null,
    }, { "time-usage-ended": "missing" }]
  ) {
    refuses(() =>
      summarizePostedCosts({ data: { items: [{ ...item, ...change }] } })
    );
  }
  refuses(() => summarizePostedCosts({ data: {} }));
});

Deno.test("cost collection follows continuation pages before publishing the total", async () => {
  const calls: string[][] = [];
  const result = await readPostedCosts((args) => {
    calls.push(args);
    return Promise.resolve(
      calls.length === 1
        ? {
          data: { items: [{ ...item, "computed-amount": 2 }] },
          "opc-next-page": "next",
        }
        : { data: { items: [{ ...item, "computed-amount": 3 }] } },
    );
  }, ["cost-request"]);
  assert(
    JSON.stringify(calls) ===
      JSON.stringify([["cost-request"], ["cost-request", "--page", "next"]]),
  );
  assert(result.collectionComplete && result.summary?.postedAmountUsd === 5);
  assert(result.responses.length === 2 && !observationFailure(result));
});

Deno.test("interrupted or cyclic cost pagination retains evidence without a complete subtotal", async () => {
  for (const cyclic of [false, true]) {
    let calls = 0;
    const result = await readPostedCosts(() => {
      calls++;
      if (!cyclic && calls === 2) throw Error("Interrupted request");
      return Promise.resolve({
        data: { items: [item] },
        "opc-next-page": "next",
      });
    }, []);
    assert(
      calls === 2 && !result.collectionComplete && result.summary === null,
    );
    assert(result.responses.length === (cyclic ? 2 : 1));
    assert(!!observationFailure(result));
  }
});

Deno.test({
  name:
    "absent guest collection is unavailable while partial historical coverage remains descriptive",
  ignore:
    (await Deno.permissions.query({ name: "read" })).state !== "granted" ||
    (await Deno.permissions.query({ name: "write" })).state !== "granted",
  fn: async () => {
    const previous = Deno.cwd(), directory = await Deno.makeTempDir();
    try {
      Deno.chdir(directory);
      const summary = await readGuestTelemetrySummary(
        "fixture",
        new Date("2026-09-11T00:00:00Z"),
        new Date("2026-09-12T00:00:00Z"),
      );
      assert(summary.status === "unavailable" && summary.observedMinutes === 0);
      assert(!!observationFailure(summary));
      assert(
        !observationFailure({
          ...summary,
          status: "incomplete",
          observedMinutes: 1,
        }),
      );
    } finally {
      Deno.chdir(previous);
      await Deno.remove(directory, { recursive: true });
    }
  },
});

Deno.test("cost page bound retains all fetched pages as incomplete", async () => {
  let calls = 0;
  const result = await readPostedCosts(() =>
    Promise.resolve({
      data: { items: [item] },
      "opc-next-page": `page-${++calls}`,
    }), []);
  assert(calls === 5 && result.responses.length === 5);
  assert(!result.collectionComplete && result.summary === null);
});
