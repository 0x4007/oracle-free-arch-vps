# Arch guest telemetry

The Pi collects guest memory and default-interface network counters once per
minute through the existing pinned non-root SSH connection. The collector reads
Linux `/proc` files and the root UUID; it installs no software on the VPS and
does not change a guest service. Configuration comes from the existing
`.private/backup-controller.json` source and guest identity.

`config/guest-telemetry.timer` runs `scripts/guest-telemetry.ts` through the Pi
`safepi` wrapper with a 45-second limit. A separate telemetry lock prevents
overlap without blocking a long backup. No cloud API or paid service is used.
The latest observation is `.private/reports/guest-telemetry.json`; timestamped
raw observations are appended to `.private/guest-telemetry/YYYY-MM-DD.jsonl`.
Nine UTC files are retained. Failed SSH checks leave the last good observation
unchanged and write a separate failure record; check the timestamp and service
result, not just the presence of a report.

Memory used is `100 * (MemTotal - MemAvailable) / MemTotal`, so reclaimable
memory is not counted as unavailable. Network counters are taken only from the
unique active IPv4 default-route interface; loopback, Docker and tunnel counters
are not added. Rates use monotonic guest uptime between samples on the same
source, boot, root and interface. Reboots, counter resets, clock disagreement
and gaps over 150 seconds produce a discontinuity, not a rate.

The weekly OCI audit includes these measurements as `supportingGuestTelemetry`.
It reports unique minute coverage, missing minutes, memory statistics and
network interval coverage for the same completed seven-day window. Duplicate
samples and the current partial hour cannot fill missing minutes. An interrupted
JSONL write remains visible as a malformed record; it is not fabricated data.
Successful collection today does not establish a complete seven-day history.

## Oracle-native metrics remain separate

Oracle's
[Cloud Agent documentation](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/manage-plugins.htm),
checked September 11, 2026, supports current platform images and custom images
based on them. It does not list Arch Linux ARM. Live inspection of this VPS
found no Oracle Cloud Agent installation or service.

The
[native compute metric namespace](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computemetrics.htm)
is `oci_computeagent`; Oracle documents six samples per minute from the agent.
This collector instead labels its source `linux-proc-over-ssh` and records
`nativeOracleAgent: false` and `idlePolicyEvidence: false`. It does not publish
into a reserved Oracle namespace or relabel local samples as Oracle data.

Hypervisor CPU remains sourced from `oci_vmi_resource_utilization`. Missing
native memory/network metrics and the full Oracle idle-policy verdict stay
explicit in the audit. Local byte rates do not establish Oracle's network
utilization percentage or prevent instance reclamation.
