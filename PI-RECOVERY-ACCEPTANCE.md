# Pi-orchestrated replacement recovery

Audit started 2026-09-07 against bf70caf210fcbd19b27fde91c36361fa71d4d06c.
The owner-controlled repository-root PROJECT-VISION.md remains the authority.
The owner has prohibited all backup payload transfers through the home network.

## Required path

The Pi must select one accepted recovery point, reconcile Oracle resources,
provision the approved replacement through Oracle's API, direct B2 downloads
onto that remote target, reconstruct the machine, and check real boot and
applications. The Pi carries control/status and limited decryption-agent traffic;
it must not carry archive payloads. The source VPS must not supply missing files.

## What the audit actually found

| Stage | Existing implementation | Evidence and gap |
| --- | --- | --- |
| Pi entry point | `deno task restore` invokes `scripts/oci-restore.ts` | Installed on Pi; restores OCI backup volumes, not B2 archives. |
| OCI provisioning | `oci-restore.ts` creates boot/root volumes, launches A1, attaches root and assigns the reserved IP | Source implementation exists; the new recovery path has not been live proved. It refuses unrecorded live volumes/instances. |
| Guest acceptance | `oci-restore.ts` verify action | Returns `METADATA_PROVED`; delegates live guest checks to a checklist. No automated boot/application acceptance from this action. |
| Backup recovery task | `backup-recovery.ts` | Diagnoses old interrupted backup transactions. It is not replacement-machine recovery. |
| B2 retrieval | `backblaze-recovery.ts` | Reconstructs exact indexed encrypted object versions on its execution host. Does not provision or boot. |
| Decryption and archive verification | `backblaze-verifier.ts`, `makeDecryptArchive` in `backblaze-file-backup.ts` | Existing VPS-side verification with a public-only keyring and Pi decryption-agent access. No payload relay is needed. |
| Disk reconstruction | `backblaze-machine-restore.ts` | Previously bound to dated QEMU target/serial constants. Requires two empty serial-bound disks plus already verified archive files on separate scratch. |
| Previous boot evidence | Retained off-source drill procedures | QEMU-specific procedures with operator repairs; not evidence for the requested Pi/Oracle/B2 sequence. |

## Live cost and drill constraint

Read-only Pi inventory observed at 2026-09-07T00:08:51.877Z:
one instance, 2 OCPUs, 12 GB RAM, 200 GB live disks, three backup members,
one group wrapper, and one public IP. No resource was created or changed.

Oracle's [Always Free documentation](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
was fetched again on 2026-09-07. It gives 200 GB combined boot/block storage,
five backup members, and 1,500 OCPU-hours/9,000 GB-hours monthly for A1
(equivalent to continuous 2 OCPUs/12 GB). A second complete 50/150 GB pair
would raise live storage to 400 GB while production remains online. It cannot
be provisioned under the current free-only and uninterrupted-production limits.
Actual loss of compute alone does not prove disks are gone or free: inventory
and exact authority must settle remaining resource ownership before replacement.

## First implementation correction

The machine-restorer target now includes explicit boot/root serials, each bound
into the approval and durable journal alongside the target ID and stable paths.
Serial substitution, duplicate serial matches, source UUID presence, mounted
source disks, and wrong capacity remain refused. New journals use schema 2;
old journals must not be silently replayed against a different target. Historical
kit copies and completed drill evidence remain preserved.

This change removes the dated target restriction; it does not establish an OCI
bootstrap, approve any target, or prove real recovery. Tests validate a different
approved target and refuse stale approvals before commands. Live disk writes
have not been performed.

## Remaining implementation and acceptance

- A Pi entry point joining provisioning, remote B2 restore, boot and application
  acceptance with one bound recovery-point/target journal.
- A verified rescue boot and scratch strategy within the final 200 GB footprint;
  adding a third rescue volume would itself exceed that budget after loss.
- Target identity derived from Oracle attachment data and verified on the guest.
- Clone isolation before restored services can start, and automated acceptance.
- A full live drill consistent with available free capacity and exact authority.
  Neither a synthetic test nor an in-place source-assisted check proves this.
- Post-trial API eligibility mapping remains unverified. The separate earlier
  OCI backup drill was owner-deferred; this document does not erase that history.

The prior schedule-approval finding is tracked in GitHub issue #12. It is not a
reason to extend the completed backup review loop or to claim that defect fixed.

## Streaming reconstruction candidate, 2026-09-07

PR #13 merged the portable target correction at
7eebac7 (source correction 3a56ca9). All 19 deployment-manifest hashes were
verified on the Pi; the historical kit was not overwritten.

The next candidate adds a lazy, exact-version ciphertext stream with chunk and
archive hash checks, a streaming adapter for the existing Pi-backed GPG decryptor,
and an extraction pipeline that requires the accepted plaintext hash, GPG
integrity result and successful GNU tar exit. The machine restorer accepts that
extractor without local archive paths. `backblaze-stream-restore.ts` binds the
directly fetched recovery metadata to the accepted catalog and checks the target's OCI instance metadata before any archive request. It writes no private keys.

A small synthetic archive was generated and extracted on the VPS in a unique
/tmp directory; GNU tar success, plaintext mismatch rejection and decrypt failure
rejection passed (one integration test, repeated with metadata-hash rejection, 54 ms). The directory was removed. No
B2 request, real backup payload download, disk format or production restart was
part of this test. The GPG callback's real agent tunnel and a complete machine
restore were not exercised by this synthetic check.

The proposed no-third-disk bootstrap is an AArch64 RAM-rescue system, followed by
bounded B2/GPG/tar streams into the final 50/150 GB target. Its actual Oracle boot,
networking, target preparation and Pi checkpoint persistence remain to be built
and proved. A platform-image boot disk is not pristine: only exact-approved
replacement-disk preparation after proving RAM execution can make it eligible
for the existing pristine-target checks. Never weaken those checks merely to
make an occupied boot disk pass. All earlier full live-drill constraints remain.

## Pi provisioning controller, 2026-09-07

`scripts/pi-machine-recovery.ts` adds the Pi-owned Oracle provisioning stage.
It reads the existing controller configuration and a private recovery plan at
`.private/pi-machine-recovery.json`. The plan binds the request UUID, selected
generation, tenancy, home region, compartment, availability domain, subnet,
existing reserved IP, platform image and exact public cloud-init bytes.
`replacementPlanDigest` produces the approval digest. The `plan` action writes
current and projected resource totals without cloud mutations. A plan result
does not prove that bootstrap, restore or boot will work.

The `provision` action requires a current exact approval for that digest. It
rechecks account eligibility, resource totals, ownership, image compatibility,
subnet scope, approval and competing writers before each mutation. It creates
one 150 GB balanced root and one 50 GB platform boot with a 2 OCPU/12 GB A1
instance. It never deletes existing resources or moves an assigned production
address. It counts both regional reserved and availability-domain ephemeral IPs.
The existing reserved address is assigned only to the proved replacement VNIC,
using an ETag condition against concurrent address changes.

The private journal is `.private/pi-machine-recovery-state.json`. A durable
intent precedes each CREATE. Resume reconciles the request tag, resource
specification and recorded IDs. An inconclusive CREATE is refused rather than
repeated; a missing recorded resource is not silently recreated. Run the same
request again after provider provisioning completes. Control-plane acceptance
requires the running instance, both attachments, primary VNIC and assigned IP.
`REPLACEMENT_CONTROL_PLANE_PROVED` still explicitly reports restore and boot
acceptance as false. No SSH bootstrap or disk preparation is implied.

The stream-restore executable also now reads the actual flat scoped B2 settings
format already used on the Pi; it previously expected an absent nested `b2`
object. Scoped credentials remain private and no real backup payload was fetched
to check this wiring.

Focused tests exercise production-capacity refusal, post-loss totals, orphaned
resources, malformed inventory, approval expiry and changes, lost CREATE
responses, and repeated control-plane resumes without duplicate creation or IP
assignment. A credential-free runner rejects unexpected provider operations.
The first read-only Pi plan hit its four-minute timeout; the controller now
reuses the volume evidence already read during eligibility verification instead
of repeating that inventory. The failed process exited and its temporary code
directory was removed. It performed no cloud mutation.

Provider contracts checked against Oracle documentation:

- [Image and shape compatibility](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image-shape-compatibility-entry/list.html).
- [Boot volume image identity](https://raw.githubusercontent.com/oracle/oci-python-sdk/master/src/oci/core/models/boot_volume.py).
- [Instance launch](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/launchinginstance.htm).

The RAM-rescue bootstrap, approved disk clearing, Pi checkpoint persistence for
stream restoration, clone isolation, and real boot/application acceptance remain
unfinished. The provisioner must not be represented as the complete recovery
entry point or invoked against the occupied production tenancy.

The corrected read-only Pi plan completed at 2026-09-07T01:11:45.623Z:
`REPLACEMENT_CAPACITY_BLOCKED`, current 200 GB/2 OCPU/12 GB and projected
400 GB/4 OCPU/24 GB, three backup members, one public IP and 1,453,785,088
Object Storage bytes. It ran from temporary candidate code under `safepi` with
an additional runner that refused mutation commands. The temporary code was
removed. The plan remains private, action `plan`, with no mutation approval.
The plan is capacity evidence only; its placeholder cloud-init is not a prepared
rescue bootstrap and must not be approved as one.

Source 2f841ad passed 26 focused tests, 279 default tests (139 permission-gated
checks skipped), type, format, lint and whitespace checks. Local Codex review
against d112157 completed with no actionable findings; it did not run live
provisioning or recovery. Private receipts: `pi-replacement-plan.json`,
`pi-replacement-focused-tests.txt`, and `pi-replacement-review-round1.txt` under
`.private` or `.private/reports` as appropriate.

## RAM bootstrap and Pi checkpoint candidate, 2026-09-07

The next source candidate generates public cloud-init for a current Oracle
Ubuntu 24.04 AArch64 platform image. Image compatibility is checked before each
provisioning mutation. The replacement stages the pinned Alpine 3.24.1 netboot
archive directly into tmpfs and checks its published SHA256 and release
signature. The public release key is retained in
`config/alpine-release-public.asc` and must be included in Pi deployment.
The Pi and Mac fetch no netboot binary or backup archive.

The generated overlay prepares non-root public-key SSH, explicit OpenRC
network/udev services, and a RAM scratch directory. Its account service validates
and reuses an existing account and never recursively changes ownership under
restore mounts. Staging does not load kexec, reboot, or prepare disks. A separate
reboot-script builder binds current exact approval to the replacement instance,
volume IDs, original boot ID, and staged kernel/initramfs hashes, then rechecks
those facts before a graceful kexec request. A disconnect is not boot proof.

`backblaze-stream-restore.ts` now checks request-tagged OCI identity, AArch64,
RAM root and scratch, private non-symlink scratch, absence of swap/disk-root
arguments and the rescue request marker before requesting metadata from B2.
Every machine-restorer journal stage, including the initial preflight, is sent
as a bounded control record and requires a matching Pi acknowledgement before
later disk work. The acknowledgement helper writes the checkpoint durably on
Pi before returning it. Request, instance, RAM boot, generation, index digest,
stable disk paths/serials, immutable journal fields and ordered stages are bound.
Exact replay is accepted; missing acknowledgement, altered identity/hash,
regression, skipped stage, oversized input and failed persistence stop the path.

These are implementation and synthetic/file-persistence checks. They do not
prove artifact assembly, Alpine boot/package installation, kexec handoff,
OCI-console-to-SSH host-key trust, mounted disk safety in a real guest, GPG
forwarding or a real archive restore. The Pi session controller still must join
the checkpoint receiver to its SSH child under the controller lock, reconcile
RAM-loss journals against actual disks, and complete approved disk clearing,
clone isolation, reboot and application/desktop acceptance. RAM checks alone
are not attestation that the approved staged artifact booted. None of these
remaining steps may be represented as implemented or accepted by this candidate.

A private candidate cloud-init is prepared from the existing Pi outgoing public
SSH key at `.private/pi-rescue-bootstrap-candidate.json`. It is not approved
and does not replace the private provisioner's placeholder configuration.
The live 200 GB storage/coexistence blocker still applies; production and
existing backups remain untouched.

Source candidate 1413dc38ca7780623af9a91f40e819a255249c68 passed type,
format, lint and whitespace checks, 42 focused tests (one GNU-tar integration
check skipped on Mac), and 297 default tests (143 permission-gated checks
skipped). Eight checkpoint tests then passed on the Pi under `safepi`, including
an actual private-file fsync/rename roundtrip, at 2026-09-07T02:07:51.718Z.
The first isolated Pi test package omitted three unchanged source dependencies;
that temporary test failed type checking and was removed. The corrected test
package included the dependencies and passed. The installed Pi controller
already had those dependency files; it was not the source of that test failure.

Local Codex review against 262674d2ce859e967109c9664f31a866284921c4 exited
successfully after one round. Its substantiated P2 timeout finding is backlogged:
[issue #16](https://github.com/0x4007/oracle-free-arch-vps/issues/16). A blocked
output write can keep abort cleanup pending past the deadline; the passing
missing-ack test covers a pending read only. Do not claim bounded failure for
all SSH stalls. Per the bounded review rule, no P2-only correction round was
started. Remaining audit/integration findings are retained in
[issue #17](https://github.com/0x4007/oracle-free-arch-vps/issues/17) for approved
rescue boot evidence and
[issue #18](https://github.com/0x4007/oracle-free-arch-vps/issues/18) for
OCI-console-based SSH host trust. None is fixed by backlogging.

Private evidence is retained in `pi-rescue-focused-tests.txt`,
`pi-rescue-default-tests.txt`, `pi-rescue-review-round1.txt`, and
`reports/pi-checkpoint-tests.json` under `.private`. The prepared cloud-init
is 15,443 bytes with SHA256
`9e19d12689505978c8ac8b42abd52eff6f176cedac0171fdcc07135faded20ea`;
it remains unapproved and unprovisioned. No real boot or backup archive was
performed in these tests.

## Provider-bound disk preparation candidate, 2026-09-07

The next implementation connects the Ubuntu loader's device identities to the
RAM disk-preparation boundary. Oracle documents `/dev/oracleoci/oraclevda` as
the boot device for compatible platform images. The provisioner now explicitly
requests consistent volume naming and `/dev/oracleoci/oraclevdb` for the root
attachment, includes these choices in the approval digest, and verifies them
on the returned instance and attachment. Old provisioning digests must not be
reused for this changed launch contract. No replacement has been provisioned.

`scripts/pi-recovery-disk-identity.ts` takes fresh authenticated provider reads
and a host-key-verified loader SSH runner. It verifies the exact boot and root
attachments, resource sizes, request tag and consistent naming, observes Ubuntu
24.04 AArch64, resolves the Oracle paths, proves the platform root belongs to
the boot disk, and records full SCSI hardware serials plus verified by-id aliases.
It rereads the boot ID and provider attachments before returning a hashed
receipt. A RAM binding must retain that receipt and use a different boot ID.
It does not establish SSH trust or attest the new RAM artifact by itself.

`scripts/pi-recovery-disk-preparation.ts` requires a separately approved digest
that binds the source exclusions, replacement instance/volume IDs, RAM boot,
serials, paths, capacities and initial disk/signature snapshot. Read-only guards
require exactly two physical disks, RAM root/private scratch, matching IMDS,
no swap, no target mounts (including major/minor mount aliases), no read-only or
mapped children, no kernel device holders and no alternate mount namespaces.
Before each clear it requires a controller exchange contract for fresh OCI and
writer checks plus durable Pi acknowledgement, then rereads the target state.
Each disk must become pristine before the next one is touched. An interrupted
preparation requires a new observed plan and exact approval, not an automatic
repeat. Its result explicitly leaves restore and boot acceptance false.

The new modules are not yet wired into a complete Pi executable session. The
caller must supply the authenticated OCI reads, verified SSH transport and
actual durable preparation exchange under the controller lock; a mock callback
is not live controller evidence. No live disk was cleared, partitioned or
formatted. Remaining issues #16, #17 and #18 and the 200 GB coexistence blocker
continue to apply. The original machine-restorer's pristine-target checks are
preserved.

Primary-source contracts checked:
- https://docs.oracle.com/en-us/iaas/Content/Block/References/consistentdevicepaths.htm
- https://raw.githubusercontent.com/oracle/oci-python-sdk/master/src/oci/core/models/launch_attach_volume_details.py

Focused tests cover provider/guest identity mismatch, reversed Linux disk order,
swapped aliases, changed attachments, changed boot IDs, source-resource refusal,
mounted/held/extra/read-only disks, changed serials, expired approval, failed Pi
acknowledgements, changed state during acknowledgement, incomplete clearing and
refusal to silently resume. These are synthetic command-runner checks plus
actual shell syntax parsing, not proof of OCI device naming or real disk writes.

The first local review found a P1 defect in this candidate: both `lsblk` calls
omitted `--tree`, so real partition nodes would be flat even though the initial
test fixtures were nested. Correction f9e068bf072fee4b7f21adb8458f887531f04a2c
requests trees explicitly, refuses top-level partition records, and makes the
fixtures return flat data when the option is absent. A read-only Pi probe at
2026-09-07T02:30:20.927Z confirmed two top-level partitions without `--tree` and
two nested partitions with it. No disk was modified by that probe.

The corrected source passed type, format, lint and whitespace checks, 42 focused
tests, and 313 default tests (144 permission-gated checks skipped). All 17 new
disk-module tests passed on Pi under `safepi` at 2026-09-07T02:31:03.111Z.
These Pi tests still use synthetic provider/command runners; the read-only
`lsblk` probe is separate actual tool-behavior evidence. Local Codex review
round two against 87ae6165d3575567333184fa6e362f9bd7931203 exited successfully
with no further actionable findings. No new unresolved review finding requires
a backlog issue; existing issues #12 and #16–#18 remain open.

Private receipts: `pi-disk-focused-tests.txt`, `pi-disk-default-tests.txt`,
`pi-disk-review-round1.txt`, `pi-disk-review-round2.txt`,
`reports/pi-disk-tests.json`, and `reports/pi-lsblk-tree-contract.json` under
`.private`. Alpine's published v3.24 AArch64 `util-linux-misc` file listing
includes `/sbin/blockdev`, which the preparation stage needs; the existing RAM
bootstrap already requests that package.

## Pi session integration candidate, 2026-09-07

Source candidate `52f4170` adds `deno task backup:replace`, a Pi entry point that
runs replacement provisioning and then joins console capture, pinned non-root
SSH, loader disk identity, staged rescue receipt, durable reboot intent and
new RAM boot acceptance under the existing controller lock. The ordinary
`backup:recover` service retains its source-recovery purpose. Provisioning and
each console/reboot mutation require their own exact approvals; no approval is
created by the controller. The existing private replacement configuration holds
optional `sessionApprovals.loaderConsole`, `ramConsole` and `rescueReboot`.
Their plans are written to `.private/reports/pi-recovery-session.json` for review.

The parent persists `.private/pi-recovery-session.json` before sending a reboot.
After an uncertain SSH response it observes the next boot instead of repeating
the reboot. The boot is accepted only when console and SSH boot IDs agree,
the loader boot differs, RAM checks pass, and the rescue manifest matches the
approved bootstrap. This is software identity evidence, not hardware attestation.
The manifest binds the request, public SSH key, overlay contents and pinned
Alpine release. A changed bootstrap is refused before provisioning and again
under the provisioner's lock before cloud mutation.

Oracle console history establishes each boot's public Ed25519 key. Dedicated
private known-host files leave the controller's global SSH configuration alone.
Captures have durable intent, exact resource tags, a three-capture limit and
lost-response reconciliation. The OCI/SSH control runner bounds stdout and
stderr to 1 MiB each. Checkpoint shutdown no longer waits for a permanently
stalled writer; the stream executable disposes its own pipe descriptors.

Current acceptance stops at `RAM_RESCUE_ACCEPTED`, with restoration and
application acceptance explicitly false. Disk preparation, runtime and scoped
credential installation, the Pi GPG extra-socket tunnel, direct archive restore,
clone isolation and restored boot/application acceptance still need to be joined
to this parent. This candidate does not close issues #17 or #18 by itself and
is not end-to-end recovery proof. No live cloud, disk, package, reboot, service,
backup-payload or production mutation was performed for these checks.

The local candidate passed 62 focused tests, 333 default tests (148 skipped),
type checking, formatting, lint and whitespace checks. Focused tests use fake
provider/SSH ports; actual local subprocess checks verify bounded output and
shell parsing. Review, corrected Pi test evidence and deployment evidence follow
below when available. The 200 GB free-storage coexistence blocker and unproved
post-trial eligibility mapping remain unresolved.

Review round one found a P1 overlay-permission defect and a P2 resume-approval
defect. Correction `af92bf3` makes the task-owned public overlay directories
traversable while preserving file modes and private assembly/scratch paths.
A real shell/stat regression checks this under umask 077. Completed reserved-IP
assignment now reconciles read-only after provisioning approval expires; an
unassigned address still requires fresh authority before UPDATE. The provider
fixture verifies both cases and no duplicate creation or assignment.

The corrected source passed 75 focused local tests, 333 default tests (149
permission-gated tests skipped), and type/format/lint checks. All 58 selected
provisioning/session/bootstrap/transport tests passed on Pi under `safepi` at
2026-09-07T03:40:27.571Z, in an owned temporary directory that was removed afterward.
Those Pi checks used fake provider/SSH ports plus real local shell, filesystem
and bounded subprocess operations; they did not invoke a live recovery.
Private evidence is in `reports/pi-session-tests.json`,
`pi-session-focused-tests.txt`, `pi-session-default-tests.txt` and
`pi-session-review-round1.txt` under `.private`.

Review round two found Oracle's documented console-connection prerequisite:
https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/displayingconsole-capturing.htm .
Correction `b0df24c` requires an ACTIVE instance console connection for the exact
replacement before saving capture intent, and checks again before CREATE. An
absent prerequisite writes `CONSOLE_CONNECTION_REQUIRED` to the private session
report. The Pi does not yet create that connection automatically. This remaining
P1 setup integration is retained in the existing host-trust issue
https://github.com/0x4007/oracle-free-arch-vps/issues/18 with provider evidence,
affected revision and acceptance criteria. It is a live-recovery blocker, not
an excuse to record a failed or unattempted capture as successful.

The final correction passed 76 focused local tests, 334 default tests (149
permission-gated tests skipped), and type/format/lint checks. The third local
review is the last permitted round for this candidate; any remaining
substantiated findings are backlogged before GitHub delivery.

Review round three against `f1ddfcc206c069970b188969c4bb65de68ac2d78` exited zero
with no further actionable defects on source `b0df24c`. No fourth review was run.
The corrected 59-test Pi selection passed at 2026-09-07T03:46:14.462Z under
`safepi`; its exact source bundle digest is retained in the private receipt.
Issue #16's pending-write regression passes locally and on Pi. Issues #17 and
#18 remain open for their full integrated/live acceptance; #18 also retains the
P1 console-connection setup gap. Review receipt: `pi-session-review-round3.txt`.

## First-release post-restore integration — source only

The canonical source now connects the successful path after direct archive
reconstruction. `pi-recovery-isolation-executor.ts` has a target-side command
that accepts only the bounded plan, inspection and an exact isolation approval;
it mounts the serial/UUID-bound copies, applies the copied-root firewall,
timer/service masks, SSH host-key replacement and isolated default target, then
releases its mounts. An isolation intent is persisted before writes; an
interrupted or uncertain write reports reconciliation and is never replayed
automatically.

`pi-recovery-acceptance.ts` binds a second exact approval to the applied
isolation receipt, requests a guest reboot into the reconstructed disks, and
keeps a durable boot intent before the request. The session then captures the
restored console marker, retains its host key, connects over pinned SSH and
checks the restored architecture, root filesystem, recovery manifest, SSH,
Docker service activity, both required Guacamole containers, the served
Guacamole page and a live Xvnc process. The Codex remote service stays masked by
the isolation policy, so its unit-file presence is not used as application
evidence. The read-only result is recorded as `RESTORED_APPLICATIONS_ACCEPTED`
only after every live check passes.

This closes the source integration for the first-release successful path. It
does not prove a real replacement: no OCI resource, disk, reboot, archive
payload, production service or Pi installation was used for this continuation.
The existing 200 GB Always Free coexistence gate, console-connection setup
authority, restored boot/application acceptance and Pi deployment remain
unproved and require the exact operational approvals described by `AGENTS.md`.
