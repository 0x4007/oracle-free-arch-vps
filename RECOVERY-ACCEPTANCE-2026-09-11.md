# Recovery acceptance, September 11, 2026

## Clean unattended reconstruction

The Pi completed one clean unattended Backblaze reconstruction using unchanged
runtime revision `d462c6d159dc2103af3d94b703a61b530dfd051b` and independent
generation `generation-a0f12b6f-6c4b-436a-b547-58090e39ae71`. Request
`recovery-03c060d9-437c-4369-b204-6bcdb511d93a` began at 10:07:31 UTC and
reached `RESTORED_APPLICATIONS_ACCEPTED` at 11:43:28 UTC. The driver exited zero
and its systemd service and process scope became inactive.

After the target and generation were selected and the bounded operation was
authorized, the driver completed provisioning, console-bound SSH trust, loader
staging, RAM boot, disk preparation, all eight reconstruction checkpoints, clone
isolation and restored application acceptance without an operator repair or a
runtime/configuration change. All six filesystem archives travelled directly
from Backblaze to the target. The controller used its retained off-source
catalog, tooling and protected inputs. Archive payloads did not traverse Mac, Pi
or home.

The restored boot ID was `a3c22802-d0b2-4ef9-9d87-004bff4229bf`. A separate
operator visual check at 11:44 UTC inspected the actual 1920 by 1080 Xfce
desktop: panel, dock, home/filesystem icons and retained desktop folders
rendered. X11 authentication needed no correction. This visual check was outside
the unattended driver. Screenshot SHA-256:
`2923aa569c9d387143b39dce4b8eccaba973e7cd05e37a34c95c9dc220e35335`.

Private evidence is retained under
`.private/reports/unattended-telemetry-20260911/`: `v4-acceptance-records.json`,
`v4-desktop-acceptance.json` and `desktop-v4.png`. The matching controller
reports and journals remain on Pi. Private contents are not published here.

Cleanup completed at 12:04:54 UTC. The temporary instance, both disks, three
console histories, console connection, reserved IP and isolated network were
removed. Final inventory proved one running production instance, 2 OCPUs,
12 GB RAM, 200 GB of live disks and one public IP. The three backup members and
their group wrapper were unchanged. The wrapper is not a fourth backup member.
The exact cleanup receipt is `v4-cleanup.json` in the private evidence directory.

The post-cleanup check passed all 64 installed runtime hashes, installed telemetry
and calendar unit hashes, and consecutive scheduled guest samples with unchanged
production boot/root identities. Test-evidence reference:
`047ecd50480277305bd956560cc5c9c0484f10fec5edb8175151d66ba6c9b251/ec0ced3c-0254-4ac3-899b-653b0551407a`.
This was fresh execution after cleanup; the earlier unit-test results were reused,
since this acceptance update changes documentation only.

Earlier September 11 attempts remain operator-repaired or failed evidence. In
particular, the earlier completed checkpoint was preserved and the startup
preflight was corrected in PR #72 before this new request began. The successful
run does not relabel those earlier attempts or prove future generations.
Oracle-group restoration remains its separate September 10 proof obligation and
receipt; this Backblaze run does not replace it.

## Guest and calendar evidence

Minute guest collection started September 11 at 05:59 UTC. A scheduled sample at
10:53:04 UTC during this drill had a valid 60.35-second network interval and
unchanged production boot/root identities. These are supporting Linux SSH
observations. Native Oracle memory/network metrics and a complete native
idle-policy verdict remain unavailable on this Arch Linux ARM installation.

The 10:04 baseline calendar observation recorded 241 of 10,080 guest minutes,
240 network intervals, no malformed records, and three accepted generations
across two capture periods. Posted Oracle cost was USD 0.486635051182; it was
provisional, not a finalized bill or a live remaining-credit balance.

The enabled observer is scheduled for September 13, 18, 20, 27 and 30, and
October 2, each at 06:00 UTC. Seven-day coverage is first assessable
September 18. Natural weekly history, post-trial eligibility and finalized zero
billing remain pending actual observations. A scheduled timer cannot establish
those results in advance. Read
[CALENDAR-OBSERVATIONS.md](CALENDAR-OBSERVATIONS.md).

The accepted restore revision had three tracked observation defects: telemetry interrupted-append loss
[#64](https://github.com/0x4007/oracle-free-arch-vps/issues/64), cost pagination
[#67](https://github.com/0x4007/oracle-free-arch-vps/issues/67), and missing
guest surface status
[#68](https://github.com/0x4007/oracle-free-arch-vps/issues/68). Subsequent collector
corrections preserve record boundaries, follow bounded cost pagination and report
unavailable guest summaries as partial. Local regressions cover these failures;
they do not change or extend the historical restore proof. The full owner charter is not complete
while calendar evidence and its other required outcomes remain open.
