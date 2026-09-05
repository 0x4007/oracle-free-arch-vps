# Native RDP migration and on-demand Docker handoff

Date: 2026-09-05. Status: planned; no live changes made by the planner.

## Objective and authority

Evaluate and, only after real-client acceptance, migrate the existing Arch Linux ARM VPS from Caddy/Guacamole/guacd/TigerVNC to Tailscale → xrdp → xorgxrdp → existing Xfce. Deliver comfortable crisp Pro Display XDR use, usable iPhone access, low login friction, reliable reconnect, measured resource use, secure boot behavior and easy rollback.

The user's latest instruction is authoritative: Sentinel and Prospector are temporary active development workloads, not permanent infrastructure. Keep Docker installed, but Docker must not start at system boot in the accepted final state. Keep current development sessions running until their owner releases them or explicitly authorizes a coordinated interruption. Do not perpetually retain VNC or boot-enabled Docker solely because these workloads exist today.

This handoff is self-contained. Prior research is supporting evidence, not required conversation context. Use one live infrastructure writer; no implementation subagents are assigned. The successor acts as orchestrator and sole implementer. Do not spawn implementation workers or create competing lanes.

## Canonical Goal Identity

- Canonical plan path and goal identifier: `/Users/nv/repos/0x4007/oracle-free-arch-vps/NATIVE-RDP-MIGRATION-2026-09-05.md`.
- Goal slug: `native-rdp-migration-2026-09-05`.
- gid10: `5c911ade25`; hash suffix: `g5c911ade25`.
- Canonical worktree name: `native-rdp-migration-2026-09-05-g5c911ade25`.
- Repository root: `/Users/nv/repos/0x4007/oracle-free-arch-vps`.
- Canonical worktree path: `/Users/nv/repos/0x4007/oracle-free-arch-vps/.codex-worktrees/native-rdp-migration-2026-09-05-g5c911ade25`.
- Canonical branch: `codex/native-rdp-migration-2026-09-05-g5c911ade25`.
- Base ref: `origin/main`; exact base SHA: `770dbc440a976811721aa257b3c81a5d54a21f39`.
- Lane state: planned; successor creates/reuses only this lane after reconciliation; planner creates no lane.
- Ownership: one successor primary owns all tracked changes and live mutations; no module lanes.

Paste-ready goal sentence:

Goal: Use canonical worktree name native-rdp-migration-2026-09-05-g5c911ade25 at /Users/nv/repos/0x4007/oracle-free-arch-vps/.codex-worktrees/native-rdp-migration-2026-09-05-g5c911ade25 on branch codex/native-rdp-migration-2026-09-05-g5c911ade25; read AGENTS.md and /Users/nv/repos/0x4007/oracle-free-arch-vps/NATIVE-RDP-MIGRATION-2026-09-05.md in full, then act as orchestrator and sole infrastructure implementer to validate and migrate native RDP over Tailscale for Mac and iPhone, preserve active development until released, leave Docker installed but disabled at boot, complete the recorded acceptance and delivery gates, and never switch the canonical branch or worktree.

## Required instructions and boundaries

Read `AGENTS.md` in the repository, `/Users/nv/.codex/AGENTS.md`, `/Users/nv/.codex/agents/project-workflow.md`, `/Users/nv/.codex/agents/git-coordination.md`, and the relevant Deno/review guidance before implementation or delivery. Use `codex@vps.pavlovcik.com` and bounded sudo; never root SSH. Preserve active writers, unrelated dirty work, credentials and existing recovery configuration.

The repository requires exact approval for package/user/credential/firewall changes and managed-service or instance restarts. Apply existing user authorization where it covers the concrete operation; do not ask again for the already selected final policy of installed but non-booting Docker. Before a disruptive action whose timing or exact scope is not covered, finish its non-disruptive preparation, state the exact change and active-workload impact, cite the applicable repository instruction, and request only the missing authorization. The handoff does not authorize stopping another developer's browser or Sentinel run. Do not use a blanket approval request to delay read-only inventory, package preparation, plan validation or other authorized work.

No public TCP 3389, OCI RDP ingress, weakened SSH authentication, new desktop environment, global passwordless login, or permanent deletion. Do not change OCI resources, disks, backups, DNS or unrelated service policy as part of this task. Do not add environment variables or new CLI interfaces without the user's approval. Reuse installed gpt-pro for any substantial new research and cached results where sufficient.

## Current repository and task state

- Repository: `/Users/nv/repos/0x4007/oracle-free-arch-vps`.
- Root checkout at inspection: main, HEAD `263128dfde5902659c087289cde1ddb72461b3aa`, 20 commits behind origin/main.
- GitHub main and local origin/main verified as `770dbc440a976811721aa257b3c81a5d54a21f39` at 20:35 UTC; use that exact planned base, not the stale root checkout.
- Pre-existing untracked `WEEKLY-BACKUP-RESTORE-CYCLE.md` belongs to other work. Existing weekly-backup worktrees and branches must be preserved. GitHub open-PR query returned none at planning time.
- This handoff is a new untracked planning artifact. No branch/worktree/commit/PR was created. Reconcile future drift, task branches and PRs before creating the exact recorded lane. Do not pull or switch the dirty root checkout to simplify setup. Include a copy of this handoff in the focused implementation delivery without staging unrelated files.

## Verified live state, 2026-09-05 20:17–20:35 UTC

Recheck before mutation; active development can change this state quickly.

| Surface | Discovered state |
| --- | --- |
| Host | Oracle A1, Arch Linux ARM, aarch64, 2 CPUs, 11,937 MiB RAM, no swap |
| Browser path | Caddy HTTPS `/guacamole/` → Java/Tomcat 127.0.0.1:8080 → guacd 127.0.0.1:4822 → Xvnc loopback :5901 → Xfce, codex display :1 |
| Live compose | `/home/codex/.config/guacamole-trial/compose.yaml`, confirmed by container labels |
| Misleading legacy path | `/home/opc/oracle-vps/docker/compose.yml` is an nginx example template, not live Guacamole |
| Containers | `guacamole-trial-guacamole-1` and `guacamole-trial-guacd-1`, images 1.6.0, host networking, restart `unless-stopped` |
| Guacamole auth | Local `/home/codex/.config/guacamole-trial/config/user-mapping.xml`, MD5 encoding; do not expose values |
| Caddy | `/etc/caddy/Caddyfile`; current site redirects `/` and proxies `/guacamole/*` |
| Desktop | TigerVNC 1.16.2-5; Xfce session 4.20.4-1, settings 4.20.5-1, panel 4.20.8-1 |
| X server | Xvnc is the X server; xorg-server, xrdp, xorgxrdp absent |
| VNC startup | User unit `/home/codex/.config/systemd/user/vncserver.service` plus `vncserver.service.d/backup-recovery.conf`; xinit → TigerVNC Xsession → startxfce4, Xvnc :1 at 1920×1080 depth 24, localhost/VncAuth; linger enabled |
| Tailscale | System instance with tailnet-only TCP 5901 Serve forward to loopback VNC; an additional user Tailscale instance exists and must not be changed blindly |
| Firewall | Firewalld plus Tailscale/Docker iptables-nft rules; public SSH/HTTP/HTTPS, existing ShadowsocksR 8388/port forwards; no 3389 listener |
| SSH | Key-based access works; PermitRootLogin no, PasswordAuthentication no, KbdInteractiveAuthentication no |
| Sentinel | `uos-sentinel-vps-runner-20260905`, active, restart policy `no`; keep current run intact |
| Prospector | Active transient user service `ubiquity-sales-nav-browser.service`, DISPLAY=:1, XAUTHORITY=/home/codex/.Xauthority, working directory `/home/codex/repos/ubiquity/prospector`; depends on current VNC display |
| Docker boot | docker.service enabled and active; docker.socket disabled but active; containerd.service disabled but active |
| Docker dependencies | docker.service Requires=docker.socket and Wants=containerd.service; stopping or disabling one unit does not fully describe the runtime/boot policy |

No OCI security-list audit or public RDP negative test was performed. No services/configuration were changed. Current Guacamole desktop activity was observed during sampling; do not disconnect it for measurement.

## Research facts and design limits

- Current upstream xrdp 0.10.6.1 fixes ten vulnerabilities and a regression; xorgxrdp 0.10.5 is intended for xrdp 0.10.5 or later. AUR recipes 0.10.6.1-1 / 0.10.5-1 explicitly list aarch64. These are build recipes, not a proven Arch Linux ARM binary install. Cached host repositories did not contain these packages. Verify current patched versions and actual native build without an unsafe partial Arch upgrade.
- Linux/ARM is a mature upstream target. Some stable xorgxrdp/RemoteFX SIMD paths are x86-specific. H.264 support requires compiled x264/OpenH264 support; current AUR xrdp enables x264. Upstream documents software encoding, not OCI GPU acceleration. Verify compiled options and negotiated codec, not merely installed codec libraries. Keep a fallback codec available.
- Windows App source versions: Mac 11.3.9 (3064), iOS 11.3.4 (5926), August 11, 2026. Record actual installed client versions during acceptance.
- Mac Retina optimization, fit-to-window bitmap scaling and dynamic resolution are different settings. Explicit custom resolution selection is unavailable with Retina/dynamic resize selected. Dynamic pixel resizing is not evidence of Xfce/toolkit DPI adaptation. Do not accept a tiny 6K 1× desktop or stretched low-resolution text as success.
- Microsoft lists dynamic resolution on Mac, not iOS. iPad external-display exceptions do not establish iPhone rotation support. Older xrdp wiki claims iOS lacks H.264; current iPhone/xrdp negotiation remains unverified. Record the actual result, not a timeless non-support claim.
- xorgxrdp starts a new Xorg desktop; it cannot adopt the existing Xvnc windows. Default sesman matching is UB (user and bits-per-pixel), with KillDisconnected=false. Avoid initial dimensions/client IP as matching keys when reconnecting Mac/phone to one session. Verify matching depths, session identity and simultaneous-connection behavior. A single desktop does not give two independent simultaneous DPI settings.
- Same-user VNC/RDP sessions can conflict through DBus, per-user systemd, xfconf, keyrings, audio and browser profile locks. Prefer an approved temporary unprivileged test account using existing Xfce for initial trial, then a controlled existing-user rehearsal. A separate DBus bus is not complete isolation. Never run a second Chromium on the live Prospector profile.
- Saved credentials in Windows App plus xrdp autorun=Xorg can provide select/connect/desktop with PAM/TLS authentication. This is not passwordless SSO or NLA. Preserve SSH policy. Test desktop lock/keyring prompts independently; retain client locks, narrow tailnet grants and server-certificate validation.
- Text/image clipboard and file/drive redirection are distinct. iOS storage redirection uses `On My iPhone\Windows`; arbitrary folder selection is not documented. FUSE enables file/drive redirection; desktop audio needs an extra PipeWire/PulseAudio bridge. Add optional audio/drives only if needed.
- Guacamole 1.6.0 supports RDP/GFX and resize-method=display-update. It could be an on-demand browser fallback over RDP, but still depends on xrdp and retains Java/guacd. The user's preference is to retire unnecessary services; do not retain a permanently running fallback by default. Existing public Guacamole remains an alternate desktop entry point during migration even if RDP itself is tailnet-only.

## Initial resource evidence

Observed total memory 11,937 MiB, used about 1,659–1,696 MiB, available 10,241–10,278 MiB. These are changing snapshots, not a controlled baseline.

| Component | PSS MiB | RSS MiB |
| --- | ---: | ---: |
| Docker | 96.3 | 99.7 |
| containerd | 39.0 | 40.2 |
| Java/Tomcat | 198.0 | 198.0 |
| guacd parent | 6.8 | 13.0 |
| guacd active connection child | 89.9 | 96.0 |
| Xvnc, including X server | 358.9 | 466.2 |
| Xfce session | 24.0 | 72.0 |
| xfwm4 | 42.3 | 100.9 |
| xfsettingsd | 9.0 | 29.0 |
| panel | 13.8 | 41.3 |
| xfdesktop | 72.7 | 156.5 |
| Thunar | 8.9 | 28.7 |
| Caddy | 53.2 | 56.2 |

Container memory changed from Java 194.5 / guacd 14.04 MiB before a connection was observed to Java 195.1 / guacd 95.76 MiB while connected. Sentinel used about 71 MiB. Chromium has additional large processes. Three one-second whole-host intervals were 83%, 71%, 62% CPU idle, not attributable desktop CPU measurements.

Do not sum RSS or double-count Xvnc, container PSS and cgroup usage. New Xorg/xrdp/desktop memory offsets removal savings. Unlike the initial research assumption, final Docker idle overhead can disappear once development workloads are released and Docker is stopped; measure it then rather than assuming the observed 135 MiB daemon PSS is net savings.

## Execution sequence and gates

1. Re-anchor to the exact canonical lane after reconciling current Git/PR/runtime state. Inspect active remote writers and development workloads. Save restricted copies of configs, units/drop-ins, enable state, restart policies, firewall/Serve state and package versions in the existing secure recovery location. Do not print credentials. Inspect current OCI ingress read-only. Do not create a new cloud backup or change recovery schedules without its required authority.
2. Obtain controlled baseline samples with clients deliberately disconnected only by their owner. Use the same workload, applications, content, resolution, color depth and network route for architecture comparison; separately test intended XDR and phone resolutions. Record tailnet direct/relay status, latency, process trees, PSS/RSS, cgroups/cache accounting, interval CPU and available RAM. Prefer three repeated settled runs for disconnected, connected-static and active typing/scrolling/window-dragging states. No-session measurement is optional while live development prevents it. Preserve samples and test versions.
3. Prepare reviewed reproducible ARM packages, checksums, dependencies and session configuration. Add Xorg, not another desktop environment. Follow exact package/user-change authorization as applicable. Keep package artifacts and build options for recovery. Do not use unmanaged make install or blindly upgrade the rolling system.
4. Configure fail-closed Tailscale-only listening before enabling xrdp. Prefer explicit tailnet binding with actual address-readiness checks and retry behavior; all configured addresses must exist at start. No wildcard fallback. A loopback listener with the existing Tailscale TCP Serve model is an alternative if it proves simpler and meets the same access/boot gates; never Funnel. With direct binding, validate host firewall enforcement across firewalld/Tailscale/Docker chains. Keep sesman local, TLS required and tailnet access restricted. Document IPv4-only versus dual-stack deliberately.
5. Prove allowed tailnet connection and denied public/non-tailnet access, including public IPv4 and IPv6 where present. Inspect effective listeners and OCI ingress; a probe from the host to its own public IP is insufficient. Check denied unauthorized tailnet access, delayed Tailscale startup, firewall reload and Tailscale restart at an approved time. Verify fresh key-based SSH without changing SSH configuration.
6. Run an isolated Xfce RDP trial, then Mac/XDR testing: crisp comfortably sized terminal/browser/menu text, colored text, cursor alignment, typing, scrolling, window/fullscreen changes and dynamic resizing. Record remote pixel dimensions, Mac display mode, client options and effective toolkit DPI. Reject global scaling changes that disturb the existing desktop or phone.
7. Test the real iPhone independently: connection/authentication, touch pointer mode, keyboard, text clipboard both ways, image clipboard if needed, rotation, backgrounding, temporary network loss and reconnect. Test Mac → iPhone → Mac using identifiable open applications and server-side session identity. Verify usable per-client dimensions, no unwanted duplicates, and reliable reconnection. If rotation requires reconnect, record that supported behavior; do not claim live resize. If already-open apps need relaunch for DPI changes, report the limitation and obtain explicit acceptance rather than claiming seamless operation.
8. Prove existing-user RDP behavior without stopping another writer's session. Arrange release or an explicitly approved transition for Prospector before stopping its VNC display. Temporary isolated-account success alone is not migration acceptance. Reuse the existing desktop environment and preserve profiles/data.
9. Coordinate the first reboot with development owners and required restart authorization. Keep the old Guacamole/VNC boot path available for this first acceptance reboot. Verify SSH, Tailscale, native RDP startup, login/reconnect and old browser fallback. Reboot means recovery to a new session, not preservation of unsaved RAM state.
10. Once native acceptance passes on both clients, present the exact old-component disable list and observation period. Apply the final no-Docker-at-boot policy below without killing current workloads. Do not stop Docker/containerd until active runs are released or their interruption is explicitly authorized. Disable old VNC only after the Prospector display dependency has ended. If development continues, leave a named owner/next action for the pending stop; do not mark final boot acceptance complete prematurely.
11. Run final boot acceptance after approved workload quiescence. Native RDP must work with Docker/socket/containerd and old desktop services inactive. Measure final idle/active resources, test an intentional on-demand Docker start/stop in an approved window, and verify the old stack does not silently restart. Complete the focused GitHub delivery loop for tracked changes, required bounded review and CI, preserving unrelated work.

## Required final Docker lifecycle

User decision: keep installed; no boot startup; start explicitly for development only. The live current session need not be stopped to edit enable state.

- Final persistent enable state: docker.service disabled, docker.socket disabled, containerd.service disabled unless a separately identified non-Docker consumer requires a revised user decision. No such consumer was established by this inventory.
- Audit enabled system/user units, socket activation, timers, cron, compose launchers and development/bootstrap/recovery scripts for paths that start Docker or its workloads at boot. Disabling a unit does not prevent another enabled unit from pulling it in. Fix only task-owned relevant launch paths, or report an external owner dependency. Do not add a periodic service that undoes the user's policy.
- Use disable without `--now` while active development runs. Do not mask Docker by default: the user wants on-demand usability, and the installed Docker unit requires its socket. Do not stop its socket under a running managed daemon merely to demonstrate a state.
- Prevent the two old Guacamole containers from returning when Docker is later started for development: after acceptance, change their live restart policies and retained compose definitions from unless-stopped to no, then stop them in the approved cutover. Sentinel already has restart=no; preserve that and do not promote it to a boot service. Recheck any new containers before changing their policies; no global container rewrite/prune.
- Prospector is a transient service today. Do not add persistent enablement. Inspect launch/recovery scripts that may recreate it; preserve active work while making its final launch explicitly on demand. Do not make migration completion depend on keeping its development browser forever.
- Once released, stop the relevant workloads, then docker.service and docker.socket, and containerd if unused. Capture enable/active state before and after. The coordinated stop is distinct from the already authorized boot policy.
- Final cold/reboot check must show those units inactive and disabled, no Docker API socket listener, no old containers automatically started, no old VNC session, native RDP and SSH functioning. Do not run `docker ps` as the first boot proof: an accidentally active socket could start Docker. Inspect systemd/process/socket state first.
- Document on-demand workflow using existing systemctl/docker interfaces: explicitly start docker.service (its dependency starts socket/containerd), start only the selected project, then shut down that project's containers and stop Docker/socket/containerd when released. Never enable them as part of a routine development start. Verify the retained old desktop containers remain stopped on daemon start.
- Ensure recovery documentation/scripts restore this final disabled-by-default policy rather than restoring the old enabled Docker state. Do not rewrite unrelated backup machinery; make only required focused corrections.

## Cutover and rollback contract

Before either disable stage, enumerate exact units, files, containers, Serve forwards and current state. Initial candidates after acceptance: the two named Guacamole containers/compose restart policies; dedicated Caddy site/route; VNC user unit/drop-in and tailnet 5901 forwarding once released. Keep config/data/packages. Recheck Caddy consumers before disabling the service; do not automatically remove public 80/443 ingress. Retain Docker/containerd packages and development data. Permanent deletion is a separate later task.

During pilot rollback: stop only new xrdp/sesman and revert only task-added RDP config/exposure; reconnect using unchanged Guacamole/VNC. Do not disturb development sessions. After old-stack disable, restore the saved VNC and Caddy configuration as needed, explicitly start Docker and the exact old compose project, and verify browser access. An on-demand rollback does not require re-enabling Docker at boot. Restoring boot-enabled Docker would reverse the latest user decision and needs explicit authorization. Preserve the prior enable/restart-state record so a separately authorized full rollback is possible. Do not automatically restart Prospector or Sentinel as part of desktop rollback.

## Completion matrix and final report

Record PASS/FAIL/NOT TESTED with timestamp, version/SHA and evidence for: Mac tailnet connection; iPhone tailnet connection; crisp comfortable XDR; Mac-phone-Mac dimensions/scaling; supported resize/rotation behavior; clipboard; authentication; reconnect/session identity; public isolation IPv4/IPv6; unchanged OCI/SSH posture; Tailscale startup/reload resilience; first reboot with old fallback; final reboot without Docker; on-demand Docker without old container resurrection; released development dependencies; controlled before/after memory/CPU; rollback; recovery configuration consistency; canonical GitHub delivery.

Return a concise report with discovered architecture, exact installed/build/client versions, ARM/codec limits, security settings, Mac/XDR and iPhone results, login behavior, measured versus subjective comparison, chosen architecture, disabled components, installed-but-off Docker status, rollback steps, remaining issues and final Git/PR state. Do not call this successful if either real client or final boot behavior is unproved. If an active owner blocks a stop/reboot, state the exact pending dependency while completing safe independent work.

## Source evidence and prior artifacts

One gpt-6-pro research job `0f99929f-fbaa-49ac-b7ac-0b8650ed5864` completed successfully on 2026-09-05 (20:17:46–20:31:40 UTC). Major claims were independently checked against retrieved primary sources. Reuse its cached answer rather than resubmitting the same research.

- Local detailed report: `/Users/nv/reports/xrdp-fact-check-2026-09-05/REPORT.md`.
- Full Pro answer: `/Users/nv/reports/xrdp-fact-check-2026-09-05/GPT-PRO-REVIEW.md`.
- Source snapshots: `/Users/nv/reports/xrdp-fact-check-2026-09-05/sources/`.
- https://github.com/neutrinolabs/xrdp/releases/tag/v0.10.6.1
- https://github.com/neutrinolabs/xorgxrdp/releases/tag/v0.10.5
- https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=xrdp
- https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=xorgxrdp
- https://github.com/neutrinolabs/xrdp/wiki/H.264-encoding
- https://github.com/neutrinolabs/xrdp/wiki/Platform-Support-Tier
- https://github.com/neutrinolabs/xrdp/blob/v0.10.6.1/xrdp/xrdp.ini.in
- https://github.com/neutrinolabs/xrdp/blob/v0.10.6.1/sesman/sesman.ini.in
- https://github.com/neutrinolabs/xrdp/issues/3473 (older KDE/Windows DPI report, not proof about this host)
- https://learn.microsoft.com/en-us/windows-app/display-settings
- https://learn.microsoft.com/en-us/windows-app/compare-platforms-features
- https://learn.microsoft.com/en-us/windows-app/user-account-settings-add-remove-manage
- https://learn.microsoft.com/en-us/windows-app/device-audio-folder-redirection-teams
- https://learn.microsoft.com/en-us/windows-app/whats-new
- https://guacamole.apache.org/doc/gug/configuring-guacamole.html

## Canonical execution record — 2026-09-05 20:46 UTC

Role: orchestrator and sole infrastructure implementer. The canonical lane is
now existing, at the exact recorded path and branch. Base and HEAD remain
`770dbc440a976811721aa257b3c81a5d54a21f39`. The root checkout and the two weekly
backup lanes were preserved. No matching task branch or PR existed before lane
creation. This worktree copy is the continuation record; the root handoff remains
the identity anchor. No implementation workers were created.

### Completed preparation and evidence

- Live reconciliation confirms Sentinel running with restart=no, and transient
  Prospector browser PID 20327 still active on the original VNC session.
  Docker/socket/containerd and the old desktop services remain active. No
  package installation, account change, service restart, firewall change,
  Tailscale configuration change, or old-stack disable has occurred.
- Saved restricted live configuration and policy records on the VPS at
  `/home/codex/ops/weekly-backup-controller/pre-native-rdp-20260905T2042Z`.
  Directory is root-owned mode 0700; configuration.tar is mode 0600. Archive
  SHA-256: `ccda8fa8d768c7f4a26d7cba03022eacd27f56542bd2187d79b82ef223e68585`.
  Includes current Guacamole credentials and VNC authentication material; keep
  this archive on the host or encrypt before copying off-host. Package list,
  container restart state, system/user enable state, firewalld, nftables and
  Tailscale Serve records are saved beside it. This is a configuration snapshot,
  not a new OCI backup or a restore drill.
- OCI read-only inspection confirms one attached VNIC, no NSG, no public IPv6,
  and an attached security list allowing TCP 22/80/443 and TCP/UDP 6000–8999.
  No OCI rule permits TCP 3389. Full private evidence is in this worktree's
  `.private/native-rdp/oci-ingress.json`. A Mac public-address TCP 3389 probe
  timed out before RDP deployment; repeat after deployment. This does not prove
  unauthorized tailnet denial.
- Mac Tailscale 1.98.10 is running. Three pings to arch used DERP(iad), at
  86/24/33 ms; a direct path was not established. No Windows App was found in
  `/Applications` or `~/Applications`; no real RDP client acceptance occurred.
- Downloaded and signature-checked 18 new repository dependencies (4.86 MiB)
  with pacman download-only. Installed packages were not changed. Four unrelated
  upgrades are available (adwaita-fonts, docker-compose, libxml2, linux-aarch64);
  they are excluded. No package database refresh or system upgrade was run.
- Reviewed source recipes and install hook are in `packages/native-rdp/`.
  Both source SHA-256 values match; the xorgxrdp detached signature verifies
  against its pinned upstream key. Recipes and session startup pass shell
  syntax checks. Native build and upstream tests are NOT TESTED.
- Prepared `config/native-rdp/`: loopback-only 127.0.0.1:3389, TLS 1.2/1.3,
  unprivileged xrdp runtime, local sesman socket, root login denied, required
  rdp-users membership, Xorg-only session selection, UB reconnect policy,
  persistent disconnected sessions, existing Xfce with a separate DBus bus,
  text/image clipboard, audio and drive mounting disabled for the pilot.
  These files are staged in an inactive remote preparation directory, not /etc.
- Remote build inputs and candidate configs are under
  `/home/codex/ops/native-rdp-migration-2026-09-05/`. They have not been built,
  installed, or enabled.
- Uncontrolled host observation: 2,040 MiB used, 9,896 MiB available; three
  one-second vmstat intervals showed 93/95/93 percent idle. Active development
  was preserved. These figures are NOT a controlled architecture benchmark.

### Concrete next approval: isolated trial

Repository AGENTS.md requires current exact approval for changes to package
versions, users and credentials. No previous approval for these exact changes
was found in this goal session. Prepared scope on the existing VPS:

1. Install only the 18 downloaded dependency additions listed below; build as
   codex with low CPU priority, run upstream checks, inspect the resulting
   packages, then install xrdp 0.10.6.1-1 and xorgxrdp 0.10.5-1 if checks pass.
   Recheck the package transaction and stop if it would upgrade an installed
   package or add an unlisted dependency.
2. Create a locked, non-login system account/group `xrdp`, a login group
   `rdp-users`, and a temporary unprivileged account `rdp-trial` in that group.
   Create only the trial account password and RDP TLS certificate/key. Deliver
   the password through the client credential UI or another approved secure
   channel, never chat, Git, logs, or a checked-in RDP file. Verify the server
   certificate fingerprint on each client. Do not change codex or SSH passwords.
3. Install the prepared loopback/TLS configuration and start only the new
   xrdp/xrdp-sesman services. Add Tailscale TCP Serve 3389 to 127.0.0.1:3389,
   retaining the existing 5901 forward. Do not enable Funnel or alter public
   ingress. Resolve and verify tailnet authorization before accepting access.

| New dependency | Version |
| --- | --- |
| nasm | 3.02-1 |
| cmocka | 2.0.2-1 |
| check | 0.15.2-4 |
| libfdk-aac | 2.0.3-2 |
| imlib2 | 1.12.7-3 |
| fuse-common | 3.18.2-1 |
| fuse3 | 3.18.2-1 |
| xorg-setxkbmap | 1.3.5-1 |
| xorg-server-common | 21.1.24-1 |
| libevdev | 1.13.7-1 |
| libwacom | 2.19.1-1 |
| lua54 | 5.4.9-1 |
| mtdev | 1.1.7-1 |
| libinput | 1.31.3-1 |
| xf86-input-libinput | 1.5.0-1 |
| xorg-server | 21.1.24-1 |
| xorg-util-macros | 1.20.2-1 |
| xorg-server-devel | 21.1.24-1 |

This approval does not release Sentinel or Prospector, authorize a reboot, or
approve stopping/restarting an existing managed service. Those timing gates
remain pending. Both actual clients must still pass before cutover.

### Remaining acceptance and delivery

All real-client, native build/runtime, controlled comparison, existing-user,
unauthorized-tailnet, restart/reload, reboot, native rollback, final Docker,
and GitHub delivery gates remain NOT TESTED. Current source files reveal a
required integration: `scripts/backup-guest.ts` explicitly requires Docker,
VNC, and Guacamole in recovery acceptance. Update that contract and its deployed
controller consistently after native acceptance; do not silently leave recovery
expecting the retired stack. Inspect Docker-activating inventory calls before
final no-Docker boot evidence. Preserve unrelated backup behavior.

Disposition: canonical worktree has only task-owned uncommitted preparation;
no task commit, push or PR yet. The full migration goal remains active. First
execution turn produced live evidence and prepared artifacts; it was progress,
not a verified wait or a completed migration. Approval for the isolated trial
is the next required user input.

### Trial approval — 2026-09-05 20:49 UTC

The user explicitly answered yes to installing the listed dependencies and RDP
packages, creating the restricted trial accounts and TLS credentials, and
starting tailnet-only RDP. This authorizes the concrete isolated-trial scope
above. Existing-service interruption, workload release, and reboot remain
separate pending gates. Read-only follow-up confirmed the local recovery code
also rejects any desktop container restart policy other than unless-stopped;
this check must change at cutover. System/user unit scan found no extra Docker
launcher beyond Docker's own enable link and dependencies. No cron command or
cron configuration was found. The existing weekly vps-update timer invokes
pacman -Syu on Monday; its policy remains outside this migration.

### Native runtime and Mac connection — 2026-09-05 21:10 UTC

The approved package/account/TLS/start work is implemented. All 18 listed
repository additions were installed without upgrading an existing package.

- xrdp 0.10.6.1-1 built natively on ARM. The initial AUR imlib2 build failed
  four login-artwork scale/zoom pixel tests (expected red 0xff0000, observed
  0x5f0000 or 0x9b0000). Failed logs are preserved. The focused recipe change
  disables optional imlib2 backgrounds and uses upstream built-in BMP support;
  no tests were disabled manually. The resulting configured test suite passed
  all 213 tests: common 139, libipm 35, libxrdp 13, memtest 1, xrdp 25.
  Software x264, RemoteFX, JPEG, pixman and the normal desktop codecs remain
  enabled. imlib2 remains installed; no package cleanup was performed.
- xorgxrdp 0.10.5-1 built successfully from the signed upstream source and was
  installed. Its AUR check function does not execute tests; actual driver
  loading and native Xorg session creation were verified instead.
- Package SHA-256: xrdp
  `f9781a2beb7eb5804b203e86506b8fab759405ad3a35674ceff965460bed102d`;
  xorgxrdp
  `d7a2a482e4eeeb982d133ae772a1847c10a421fc90d8c7c61851f4e015491fd1`.
  Package files, build logs and `.BUILDINFO` are retained remotely; package
  copies and logs are also in the canonical worktree's ignored
  `.private/native-rdp/` (these package files contain no credentials).
- Created xrdp system user/group (UID/GID 963), rdp-users group, and temporary
  unprivileged rdp-trial user UID 1003. Only that user has RDP group access;
  codex is not yet enrolled. The daemon account is locked with nologin.
  Trial password is root-only in the recovery directory's
  `trial-credentials/password`; never print it. It was supplied directly into
  the native client's secure field. Persistent client credential saving is
  not yet proved.
- Installed candidate configuration in /etc/xrdp. `xrdp-chkpriv` passed all
  permissions checks. xrdp runs as xrdp:xrdp. xrdp and sesman are active but
  not enabled at boot yet. Serve now publishes TCP 3389 on the tailnet's IPv4
  and IPv6, forwarding to 127.0.0.1:3389; existing 5901 is preserved. No public
  wildcard 3389 listener exists. A post-start external public IPv4 probe timed
  out. No public IPv6 exists on the inspected VNIC. No firewall/OCI mutation.
- TLS certificate SANs match the tailnet hostname and addresses. SHA-256
  `AE:02:EE:99:BB:70:B9:D5:DB:FA:C4:65:A8:BB:48:30:CE:3B:05:9F:AF:39:6E:3C:6A:79:20:0B:3E:95:38:24`
  was compared against the native client certificate details. The user changed
  the trust selection and completed the certificate dialog while automation
  was observing it. Do not infer a fully audited trust-store policy from this.
- Read-only netmap confirms the current tailnet filter permits all tailnet
  peers to all ports. Narrow intended-client authorization and an unauthorized
  tailnet negative test are still required; no ACL changes were made.
- Microsoft Windows App 11.4.0 (3078), ARM64, obtained from Microsoft's official
  package, matching SHA-256
  `bdc7ccf2914960074d8eaeaa0b3661127bb3a29291f6832ab7dfdadf70c4171a`.
  Package signature/notarization and app code signature verified. Because Mac
  sudo requires the user's password, installed the intact signed app bundle
  into `/Users/nv/Applications/Windows App.app` without installing AutoUpdate
  or running the system installer scripts. App launched successfully.
- Client profile is named **Arch RDP**. The earlier word trial meant temporary
  testing, not paid licensing; user objected and the visible name was corrected.
  Windows App/xrdp have no paid-trial requirement for this use. Profile uses
  tailnet hostname, Retina optimization, dynamic resize, 32-bit color,
  bidirectional clipboard, no gateway, and no redirected camera, microphone,
  printer, smart card, folders or audio.
- Actual Mac TLS 1.3 session authenticated through PAM, started Xorg display :10
  PID 143943 and Xfce PID 143952 as rdp-trial at 20:59:52 UTC. Negotiated GFX
  H.264 with software x264 and ARMv8 NEON. Initial 6016×3384 framebuffer then
  dynamically resized to 3008×1598 in the client window; server recorded the
  resize completing in 405 ms. These are runtime observations, not a measured
  interactive latency benchmark. Mac display is Pro Display XDR, 6016×3384.
- The initial tiny desktop did not pass comfort. Changed only rdp-trial's
  Xfce settings: Gdk/WindowScalingFactor=2, Xft/DPI=96,
  xfwm4 general/theme=Default-xhdpi. An intermediate DPI=192 doubled scaling
  again and was corrected. Terminal and menu text visibly grew and window
  borders matched. Existing codex/VNC settings were not changed. These settings
  are per test user, not a proven per-client DPI solution; phone behavior and
  user approval of the XDR presentation remain open.
- In Scancode keyboard mode, automated mixed-case input arrived lowercase and
  modifier combinations behaved incorrectly. Switching Windows App to Unicode
  mode made the visible `RDP AbC 123 !@# clipboard check` test accurate. This
  proves that tested input only; real keyboard shortcuts remain unproved.
- Clipboard acceptance is incomplete. Direct automation paste timed out, and
  later a local TextEdit fixture was copied, but remote paste was not verified.
  A temporary unsaved TextEdit document contains only the harmless marker
  `RDP_CLIPBOARD_Mac_to_Arch_2104`. No personal document was modified.
- Coordinate clicks repeatedly failed with CUA `noWindowsAvailable`. Closing
  the RDP window through its AX close button returned timeoutReached, but
  server evidence proves disconnect at 21:07:21 UTC. Xorg PID 143943 and Xfce
  PID 143952 survived. Reconnect remains unproved. Subsequent CUA getApp/state
  calls timed out even after resetting the CUA runtime. A three-second sample
  of Windows App PID 25271 showed its main thread in the normal event wait,
  not proof of a client deadlock. Do not label this a server or client crash.
  The next UI action needs Windows App reopened to its Devices window, then
  Arch RDP selected. Do not restart xrdp or destroy the retained session.
- Sentinel remains running and Prospector retains PID 20327. Docker remains
  installed, active and boot-enabled during this pilot as required for the
  first fallback stage. No old service has been stopped or disabled.

Current gates: native package build, isolated Mac connection, negotiated codec,
TLS fingerprint comparison, tailnet listener isolation and dynamic resize have
live evidence. Reconnect, clipboard, mouse/cursor, real browser comfort,
controlled resource comparison, iPhone and Mac-phone-Mac, existing-user
rehearsal, narrow ACL/negative test, restart/reload resilience, both reboot
stages, Docker-on-demand, old-stack cutover, rollback and recovery/GitHub
integration remain incomplete. The iPhone readiness question is pending.

This execution turn made progress (installed packages, started native RDP,
proved a real Mac desktop). It is not a completed migration and the goal stays
active. No new package/account approval is needed for the already approved
trial. The current interruption is UI access/testing, not that earlier gate.

### Strict TLS correction — 2026-09-05 21:16 UTC

The next continuation revalidated the unchanged canonical lane and retained
Xorg PID 143943/Xfce PID 143952. The prior turn was progress, not completion.
Windows App CUA access still returned timeoutReached; no reconnect or phone
acceptance was inferred.

An independent real RDP negotiation test discovered that the initial OpenSSL
self-signed certificate had CA:TRUE and Deno/rustls rejected its use as a server
certificate with `CaUsedAsEndEntity`. Corrected the certificate using the same
protected key and endpoint SANs, with critical CA:FALSE, digitalSignature and
keyEncipherment, plus serverAuth extended usage. No service restart was needed;
xrdp read the replacement on the next connection. The older certificate remains
in the restricted recovery record and is superseded, not the restore target.

Current certificate SHA-256 (supersedes the fingerprint above):
`7A:6F:8C:77:62:B9:5C:79:11:43:A4:CA:D4:6F:B0:C4:E2:C1:9F:C7:FF:61:D7:01:A2:BA:6A:9E:BD:F9:7F:59`.
Current saved server certificate:
`/home/codex/ops/weekly-backup-controller/pre-native-rdp-20260905T2042Z/trial-credentials/cert-server.pem`.
`config/native-rdp/server-certificate.cnf` records the required extensions.
The already approved TLS credential setup covered this focused correction.
Clients may show the new certificate at the next connection; compare its new
fingerprint before accepting it. Do not disable certificate validation.

At 21:16:34 UTC, real RDP X.224 negotiation proved that offering only classic
RDP returns SSL_REQUIRED, while offering TLS succeeds and the TLS handshake
passes hostname and pinned-certificate verification with no insecure bypass.
The probe and JSON result are retained in `.private/native-rdp/` as
`verify-rdp-security.ts` and `rdp-security-results.json`. This is protocol-level
security evidence, not a substitute for the pending real client acceptance.
The goal remains active; this continuation made concrete security progress.

### Blocked audit — 2026-09-05 21:18 UTC

The same client-access/testing blocker has now persisted across three
consecutive goal turns: the native runtime turn, the strict TLS correction
turn, and this revalidation. The previous turn was progress because it fixed
and verified the certificate; this turn is a blocker revalidation, not a
verified wait. Current CUA getApp again returned timeoutReached. SSH confirms
xrdp PID 143516 remains active, no RDP client is connected, and Xorg PID 143943
with Xfce PID 143952 remains retained. Canonical branch/path and dirty task
files are unchanged.

Safe independent package, configuration and protocol preparation is complete
for the isolated pilot. Further client acceptance requires restored Windows
App access and the user's iPhone; neither GUI success nor phone readiness may
be inferred from automatic goal continuations. Cutover and reboot remain gated
by those tests and active-workload release. Do not bypass them or stop the
existing desktop. Mark the goal blocked pending the user reopening Windows App
to Devices and selecting Arch RDP, then confirming iPhone readiness. Resume the
same worktree/session; no new installation approval is needed. Full GitHub
integration remains pending actual migration acceptance.

### Saved credentials and reconnect accepted by observation — 2026-09-05 21:22 UTC

The user reopened Windows App and explicitly requested saving the credentials.
Used Configure PC → Credentials → Add Credentials to save the existing
rdp-trial username/password with friendly name Arch RDP, selected that saved
credential on the Arch RDP PC profile, and saved the profile. The secret was
read directly into the native secure field and never emitted in tool output.

Double-clicking Arch RDP then connected without a username/password prompt.
The native screenshot showed the retained terminal and its earlier test text.
At 21:22:17 UTC sesman recorded reconnection to display :10.0, session PID
143927; Xorg PID 143943 and Xfce PID 143952 remained the same. This proves
saved-credential use and one Mac disconnect/reconnect with session identity
preserved. A full application restart, screen-lock behavior, and phone
credential setup remain untested. The current profile still targets the
temporary isolated account, not the existing codex desktop.

The immediate Windows App access blocker was cleared by the user reopening
its window. Do not repeat the earlier claim that all UI access remains blocked.
Coordinate-click reliability, clipboard, iPhone readiness, existing-user and
cutover/reboot gates remain open. The full migration is not complete.

### Mac user acceptance and checkpoint — 2026-09-05 21:36 UTC

The user reported a much sharper image and then confirmed that native RDP and
the existing browser desktop feel roughly the same in responsiveness. Record
this as subjective Mac image/performance acceptance, not a controlled benchmark
or full keyboard/clipboard/XDR comfort acceptance. No performance settings were
changed during that comparison. User window resizing caused framebuffer changes
from 1280×960 to 6016×3260; software x264 remained selected. Tailscale was direct
at about 23 ms. Concurrent backup CPU usage varied substantially, including
intervals with 89–93% host idle, so saturation was not established as the cause
of the earlier perceived delay. No competing workload was stopped or throttled.

At 21:36 UTC, live xrdp and sesman are active and boot-disabled. Docker is active
and boot-enabled; its socket and containerd are active but boot-disabled. This
is still the pre-cutover state, not final Docker acceptance. SHA-256 checks of
the live xrdp.ini, sesman.ini and startwm.sh match the canonical source files.
Package recipes/install hook and session script pass shell syntax checks.

The accepted native package/configuration slice and this continuation report
are being committed on the canonical branch. Private evidence and credentials
remain excluded. Final PR delivery remains pending the full migration gates.
Next client step: iPhone readiness, then real Mac–phone–Mac session testing.
Clipboard, actual shortcuts, narrow tailnet authorization, existing-user
rehearsal, recovery integration, coordinated reboots, cutover, Docker lifecycle,
rollback and controlled resource comparison remain incomplete.

### iPhone connection and open input defect — 2026-09-05 21:54 UTC

Canonical accepted-package/Mac checkpoint is commit
`2a0a477cab21ba3caa3a986ec0f40acb91883abc`. Its source patch has one intentional
space-only unified-diff context line reported by git whitespace checking;
retain the upstream patch bytes and their pinned checksum. Shell checks pass.

The user installed the free Microsoft Windows App Mobile from the official
App Store and authorized direct phone configuration through iPhone Mirroring.
The in-app connection information reports version 11.3.5 (5932), iOS 26.1.
Saved PC Arch RDP targets arch.tail18c5da.ts.net with saved existing rdp-trial
credentials named Arch RDP. Clipboard is enabled, sound is Don't Play Sound,
microphone/camera are off and no gateway is configured. The password was read
directly into the secure field without output. No Apple credential was read;
the user completed the App Store authentication themselves.

At 21:49:19–20 UTC the real iPhone connected with TLS 1.3,
TLS_AES_256_GCM_SHA384, authenticated successfully and resumed display :10.0,
session PID 143927, Xorg PID 143943 and Xfce PID 143952. The retained Chromium
window was visible. No duplicate desktop was created. The server explicitly
matched RFX and started a GFX RFX Pro codec session; do not infer H.264 from the
generic encoder-library message. Client resolution is 736×1374, with a padded
server allocation of 768×1408. Phone certificate-dialog inspection was not
captured during this connection, so per-phone trust verification remains open.

The user could not close the remote browser tab by clicking its visible close
control. Mirrored pointer actions have not proved accurate. Phone connection
and saved-login checks PASS, but touch accuracy and usable phone interaction
remain FAIL/unresolved, not accepted. Zoom was toggled on and restored; no
server DPI change was made. At 21:53 UTC the user began physical-phone testing,
which paused iPhone Mirroring. Determine whether this defect also occurs with
physical touch before attributing it to RDP coordinate handling or Mirroring.

Mac clipboard checks also remain unproved: CUA paste timed out and a native
TextEdit copy followed by remote Control-V produced no visible marker in the
remote browser address field. No search or form submission was made. Do not
claim clipboard works solely from enabled channel settings.

Next: isolate physical touch versus Mirroring; complete phone keyboard,
clipboard, rotation/background/reconnect, then return to the same session from
Mac. The cutover, workload release, ACL, recovery and reboot gates remain open.
