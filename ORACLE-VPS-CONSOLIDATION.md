# Former oracle-vps scaffold

On 2026-09-10, the owner requested consolidation of the sibling `oracle-vps`
directory into this repository. It had no Git commits; its source files were
untracked. This repository remains the canonical backup, recovery and OCI
telemetry implementation, under the owner-controlled `PROJECT-VISION.md`.

The complete working-file snapshot is retained in the ignored private path
`.private/imports/oracle-vps-20260910/`, with an `import-manifest.json` recording
each source path, byte count, SHA-256 and original mode. The original directory
was preserved. Resource inventory, backup identifiers and recovered historical
notes stay private. The snapshot is historical source material, not a deployment
package or an accepted recovery kit.

| Former material | Disposition in this repository |
| --- | --- |
| `scripts/healthcheck.sh`, `systemd/vps-data.service`, Docker mount dependency | Missing-mount failure guidance incorporated into `06-TROUBLESHOOTING.md`. Local health checks do not replace OCI metrics. No old service was installed. |
| `scripts/oci-backup.sh` | Superseded by the online volume-group controller. It creates independent backups and carries obsolete separate backup-limit assumptions. Do not use it for the current two-volume recovery unit. |
| `scripts/restore.sh`, `docs/disaster-recovery.md` | Superseded by the current Oracle group restore and independent Backblaze recovery procedures. The old boot-plus-data layout is not the current staging-boot/Arch-root contract. |
| `bootstrap.sh`, SSH/firewall/package configuration, update units | Preserved privately as historical material. Running bootstrap would change packages, services, users, firewall and mounts; it is not part of this consolidation or telemetry deployment. |
| Local archive script and backup timer | Preserved privately. A same-machine archive is not the independent encrypted Backblaze recovery layer. |
| `docker/compose.yml`, logging configuration, static checks | Preserved privately as scaffold examples, with no claim of current runtime acceptance. |
| Inventory, verification, state and recovered notes | Preserved privately with their original bytes. Their dates, old capacity assumptions and recovery claims are historical, not current acceptance evidence. |

The OCI audit is `scripts/oci-weekly-audit.ts`; its controller schedule is
`config/weekly-audit.timer`. The old `vps-health.timer` only ran local checks
and did not query OCI metrics. See `README.md` for the current audit behavior.
