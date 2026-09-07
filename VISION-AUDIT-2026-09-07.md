# Vision audit and correction evidence — 2026-09-07

The owner-controlled charter remains unchanged at
`/Users/nv/repos/0x4007/oracle-free-arch-vps/PROJECT-VISION.md`.
This report records evidence and disposition; it does not change requirements.

## Fresh audit baseline

Origin was fetched on September 7 before the fresh DeepSeek audit. Default branch
`main` was `7adb8533e93b1428e9cdfbe96a46ba6dfcee57ec`. DeepSeek audited that
checkout directly. Its tracked tree exactly matched recovery branch `4c66451`.
The audit completed with exit zero and a terminal completed result. Persisted
request configuration verified `deepseek-official`,
`deepseek-v4-flash-vision-exp`, reasoning effort `max`.

The earlier audit's unmerged-code conclusion was incorrect: PR #23 had already
squash-merged at 14:42:22 UTC. The fresh audit supersedes that stale Git claim.
Source inspection does not establish current recovery or billing acceptance.

## Branch disposition

| Branch/tip | Disposition | Evidence |
| --- | --- | --- |
| Default `main`, `7adb853` | Current audit baseline | Fresh fetch and exact tree comparison. |
| Canonical weekly recovery, `4c66451` | Changes integrated by PR #23; reused for corrections | Identical tracked tree to `main`; latest `main` merged into the existing lane before fixes. |
| B2 restore worker, `59c5194` | Superseded; reference retained | It replaces an invalid GNU tar option. Main's `a235eea` removed the invalid option; extraction uses relative members and GNU tar's normal behavior. Reintroducing the flag is unnecessary. |
| Native RDP pilot, `915f2dc` | Historical rejected migration; reference and worktree retained | Owner selected Guacamole and disabled RDP on September 5. PR #6 closed on September 7. No installed packages or services changed. |

No branch or worktree was deleted. The untracked owner documents and the
canonical untracked Backblaze handoff remain preserved.

## Validated correction scope

1. Oracle schedule approval was reread but not validated on every pre-create
   path. Commit `11b1f7c` binds pending captures to the approved schedule and
   rejects changed, malformed or future authority while retaining late catch-up.
2. Active instructions conflicted with the charter by recommending stopped
   routine backups. The same commit scopes outage procedures to separately
   approved build/recovery work and points routine operation to online capture.
3. B2 job creation was limited to six hours after Sunday 00:05. Late triggers
   could lose a week. The correction must retain the due period while keeping
   each actual request's six-hour execution deadline and gate identity.
4. The controller service timeout equaled the request deadline. Its correction
   needs final-observation margin and recurring catch-up checks without the
   old three-start/six-hour limiter blocking those checks.
5. Default test discovery searched archived `.private` tests and failed on an
   obsolete import. Target current `tests/` and ignore local worktree artifacts.

The fresh audit's proposed 00:00/00:05 documentation conflict is rejected:
Oracle and B2 intentionally start at different preferred times. Line counts,
duplicate helper structure alone, and a historical authorized home drill are
not treated as implementation defects. Future home payload transfers remain
prohibited. Unknown post-trial account representations remain fail-closed.

## Independent checks

On the fresh baseline, type checking passed. Explicit current-suite execution
passed 340 tests; 149 permission-gated tests were skipped. The archived-test
discovery failure above was diagnosed before retrying with the current suite.

Fresh read-only Pi checks around 18:12 UTC verified all 47 installed file hashes
against the deployment receipt for `4c66451`, dated 14:47:37.585 UTC. Thus the
previous undeployed-code claim was also outdated. That receipt explicitly says
`runtimeAccepted: false`; installation is not replacement-recovery proof.

Both timers were active, with preferred starts September 13 at 00:00 and 00:05
New York time. Both services were idle with successful results. The Oracle
journal was complete/online, accepted September 6 at 17:07:41.657 UTC. The B2
controller held two catalog entries and a completed August 30 request, created
September 6 at 03:50:42.411 UTC and completed after the next weekly boundary.
Changing timer behavior therefore requires attention to a possible immediate
catch-up. No production service was stopped or restarted during these checks.

The retained B2 boot receipt reports `RESTORE_DRILL_PROVED` with boot time
September 6 at 17:15:23 UTC. This is dated proof of the corrected isolated drill,
not proof of clean automated Pi replacement recovery or every newer generation.

## Remaining acceptance boundaries

- Separate boot proof for the online Oracle group remains owner-deferred.
- Pi replacement recovery, actual restored applications/desktop, and clean
  repeatability require their own real acceptance. A second production-sized
  machine would exceed the currently recorded free storage allowance; the
  first-release source-loss recovery objective does not require such coexistence.
- Interrupted-restore automatic resumption was owner-deferred for the first
  release. Uncertain destructive operations must continue to stop safely.
- Current post-trial account mapping, actual billing, and independent recovery-kit
  custody cannot be established by local source tests.
- Four B2 generations are a retention policy that must accumulate through normal
  weekly runs; two current catalog entries are not four-generation evidence.
- A merged change, an installed file, a timer update, and an observed capture
  are distinct states. Final correction checks and delivery follow below.

## Correction verification

Commit `11b1f7c` passed 21 focused schedule tests and 347 current-suite tests
(149 permission-gated tests skipped). Independent local review with
`codex review --commit 11b1f7c` exited zero with no actionable defects at
18:20 UTC. No live OCI capture was used for those checks.

The first B2 writer was stopped after repeated test-discovery probes produced
no implementation changes. Its exact task-owned process exited, no children
were running at stop, and the worktree diff was empty. The replacement received
a bounded implementation assignment using the already established evidence.

The replacement DeepSeek implementation completed with exit zero and verified
provider/model/max request evidence. B2 catch-up now uses the latest Sunday
00:05 civil period until the next Sunday, including 167/169-hour DST weeks.
Each request still has its immutable six-hour deadline. Blocked next-period
creation preserves the prior terminal job and reports an unhealthy retryable
skip. Active or uncertain gates and same-period duplicate protection remain.
Source timer configuration adds 15-minute checks and a seven-hour service
timeout; live activation is not claimed.

Independent verification at 18:30 UTC passed 94 focused schedule/B2 tests,
including local process fixtures in a credential-free environment without
network permission. The current default suite passed 349 tests, with 149
permission-gated tests skipped. Repository type, format, lint and whitespace
checks passed. Archived private tests are no longer discovered by the default
test task. These checks do not create cloud resources or establish live restore
acceptance.

Aggregate local review of `09b9f35` with `codex review --base origin/main`
(base `7adb853`) completed at 18:32 UTC with exit zero and no actionable
regressions. It independently reran the 349-test default suite with 149 skipped.
This was the second review round for this correction set; no additional
correction round was needed. Git delivery and guarded installation follow;
the new B2 timer's activation remains a distinct operational boundary.
