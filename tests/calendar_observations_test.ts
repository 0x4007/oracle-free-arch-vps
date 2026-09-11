import {
  observationTiming,
  summarizePostedCosts,
} from "../scripts/calendar-observations.ts";
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
