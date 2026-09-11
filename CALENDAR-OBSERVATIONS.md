# Calendar-dependent observations

The Pi's `calendar-observations.timer` records dated, read-only evidence on:

| UTC date and time | Intended observation |
| --- | --- |
| September 13, 2026, 06:00 | First next normal weekly cycle |
| September 18, 2026, 06:00 | First possible completed seven-day guest window |
| September 20 and 27, 2026, 06:00 | Later natural weekly periods |
| September 30, 2026, 06:00 | Post-trial account and resource state |
| October 2, 2026, 06:00 | Provisional posted post-trial cost |

The usual Oracle, Backblaze and weekly-audit timers remain the operational
schedules. This observer creates no backup and changes no cloud resource.
It reads the tenancy inventory, actual subscription response, month-to-date
posted cost, retained catalog, Oracle controller journal and seven completed
hours-based days of supporting guest telemetry. Reports are private dated JSON
files named `.private/reports/calendar-*.json`.

A missing or failed surface produces `PARTIAL_OBSERVATION` and nonzero exit. A
persistent timer that catches up after a missed date records its actual current
observation time; it cannot recover historical state that was not observed.
Baseline manual execution before the first date is labelled `baseline`.

Retained-generation count and distinct capture periods are descriptive. They do
not prove that four runs occurred naturally or unattended. Compare the retained
controller journals, scheduled-run evidence and exact generations. Existing
closely spaced development captures remain development evidence.

Posted cost may lag or contain no data. Neither an empty result nor a posted zero
proves a finalized zero bill. The subscription response is retained without
guessing Oracle's undocumented post-trial representation. Account eligibility,
actual resource retention and the first finalized post-trial statement still
need evaluation against provider evidence. Guest SSH samples remain supporting
evidence, separate from native Oracle idle-policy metrics.

A completed implementation or an enabled timer does not complete these future
observations. Read PROJECT-VISION.md and the current revision-bound recovery kit
status for the complete acceptance boundaries.
