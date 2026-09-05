import type { BackupGuestControl } from "./oci-backup-operations.ts";
import { type CommandRunner, defaultRunner } from "./oci.ts";

export interface GuestPolicy {
  host: "codex@vps.pavlovcik.com";
  rootUuid: string;
  stagingUuid: string;
  activityScriptPath: string;
}
export interface GuestJournal {
  rootUuid: string;
  stagingUuid: string;
  containers: {
    id: string;
    name: string;
    running: boolean;
    stopIntent?: boolean;
  }[];
  units: { name: string; active: boolean; stopIntent?: boolean }[];
  restored: boolean;
}
const containerNames = [
  "guacamole-trial-guacamole-1",
  "guacamole-trial-guacd-1",
];
const unitNames = ["caddy.service", "shadowsocksr.service"];

export function shellQuote(value: string): string {
  if (value.includes("\0")) throw new Error("NUL is not a shell argument");
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/** The caller persists guest intent outside the VPS before every stop. This
 * adapter never stops Codex, shells, browsers, SSH sessions or the VNC desktop.
 */
export function backupGuestControl(
  policy: GuestPolicy,
  getJournal: () => GuestJournal | undefined,
  save: (journal: GuestJournal) => Promise<void>,
  runner: CommandRunner = defaultRunner,
): BackupGuestControl {
  if (
    policy.host !== "codex@vps.pavlovcik.com" ||
    ![policy.rootUuid, policy.stagingUuid].every((id) =>
      /^[a-f0-9-]{36}$/.test(id)
    ) ||
    !/^\/home\/codex\/ops\/[a-zA-Z0-9/_.-]+\.ts$/.test(
      policy.activityScriptPath,
    )
  ) throw new Error("Guest policy is not bound to the approved VPS");
  const remote = async (command: string) => {
    const result = await runner("ssh", [
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      "ConnectTimeout=10",
      "-o",
      "ServerAliveInterval=10",
      "-o",
      "ServerAliveCountMax=3",
      policy.host,
      "bash -c " + shellQuote("set -euo pipefail\n" + command),
    ]);
    // Remote output can contain configuration or credentials. Keep failures
    // terse; private diagnostics must be collected deliberately.
    if (result.code !== 0) {
      const busy = result.stderr.trim().match(
        /^MAINTENANCE_BUSY process=([a-zA-Z0-9_.-]+) pid=(\d+) parent=(\d+)$/,
      );
      const detail = busy && [20, 21].includes(result.code)
        ? `; process=${busy[1]} pid=${busy[2]} parent=${busy[3]}`
        : "";
      throw new Error(`Guest operation failed (${result.code}${detail})`);
    }
    return result.stdout.trim();
  };
  const inspectContainers = async () => {
    const output = await remote(
      "sudo -n docker inspect --format " + shellQuote(
        "{{json .Id}} {{json .Name}} {{json .State.Running}} {{json .State.ExitCode}} {{json .HostConfig.RestartPolicy.Name}}",
      ) + " " + containerNames.map(shellQuote).join(" "),
    );
    return output.split("\n").map((line) => {
      const parts = line.match(
        /^"([a-f0-9]{64})" "\/([^" ]+)" (true|false) (\d+) "([a-z-]+)"$/,
      );
      if (
        !parts || !containerNames.includes(parts[2]) ||
        parts[5] !== "unless-stopped"
      ) {
        throw new Error("Container identity or restart policy changed");
      }
      return {
        id: parts[1],
        name: parts[2],
        running: parts[3] === "true",
        exitCode: Number(parts[4]),
      };
    });
  };
  const active = async (unit: string) => {
    const state = await remote(
      "systemctl show --value -p ActiveState " + shellQuote(unit),
    );
    if (!["active", "inactive"].includes(state)) {
      throw new Error("Service is in an ambiguous state");
    }
    return state === "active";
  };
  const requireJournal = () => {
    const journal = getJournal();
    if (
      !journal || journal.rootUuid !== policy.rootUuid ||
      journal.stagingUuid !== policy.stagingUuid ||
      journal.containers.length !== 2 || journal.units.length !== 2 ||
      !containerNames.every((name) =>
        journal.containers.filter((c) => c.name === name).length === 1
      ) ||
      !unitNames.every((name) =>
        journal.units.filter((u) => u.name === name).length === 1
      )
    ) throw new Error("Guest recovery journal is absent or mismatched");
    return structuredClone(journal);
  };
  const bootProof = async () => {
    const script = [
      "set -eu",
      `test "$(findmnt -nro UUID /)" = ${shellQuote(policy.rootUuid)}`,
      `test "$(lsblk -nro START /dev/disk/by-uuid/${policy.rootUuid})" = 1050624`,
      `test "$(blkid -s TYPE -o value /dev/disk/by-uuid/${policy.stagingUuid})" = xfs`,
      "mount --make-rprivate /",
      `mount -o ro,norecovery ${
        shellQuote("UUID=" + policy.stagingUuid)
      } /mnt/staged`,
      "trap 'umount /mnt/staged' EXIT",
      "cmp -s /boot/Image /mnt/staged/arch-vmlinuz",
      "cmp -s /boot/initramfs-linux.img /mnt/staged/arch-initrd.img",
      `grep -Fq ${
        shellQuote("root=UUID=" + policy.rootUuid)
      } /mnt/staged/grub2/grub.cfg`,
      "grep -Fq 'Oracle Linux (fallback)' /mnt/staged/grub2/grub.cfg",
    ].join("\n");
    await remote("sudo -n unshare --mount bash -c " + shellQuote(script));
  };
  const assertNoActiveWork = async () => {
    const socket =
      "/home/codex/.codex/app-server-control/app-server-control.sock";
    const activity = JSON.parse(
      await remote(
        "/usr/local/bin/deno run --allow-net --allow-read=" +
          shellQuote(socket) +
          " --allow-write=" + shellQuote(socket) + " " +
          shellQuote(policy.activityScriptPath),
      ),
    );
    if (activity.loadedThreads !== 0) {
      throw new Error("Loaded Codex threads prevent maintenance");
    }
    // Fail closed on shell sessions, jobs, browser processes and other writers.
    // Exclude only this SSH command's own process ancestry. Do not infer idle
    // from CPU utilization, process age, or a transcript timestamp.
    const script = `set -eu
self=$$
ancestors=" "
while [ "$self" -gt 1 ]; do
  ancestors="$ancestors$self "
  self=$(ps -o ppid= -p "$self" | tr -d ' ')
done
while read -r pid parent uid comm; do
  case "$ancestors" in *" $pid "*) continue ;; esac
  case "$comm" in
    bash|sh|zsh|fish|ssh|sshd-session|tmux*|screen|git|oci|pacman|dnf|apt*|rsync|rclone|deno|node|bun|python3|firefox*|chrome*|chromium*|code|claude|aider)
      printf 'MAINTENANCE_BUSY process=%s pid=%s parent=%s\\n' "$comm" "$pid" "$parent" >&2
      exit 20 ;;
  esac
  if [ "$uid" = "$(id -u)" ]; then
    case "$comm" in
      systemd|"(sd-pam)"|Thunar|Xvnc|at-spi-bus-laun|at-spi2-registr|codex|dbus-broker|dbus-broker-lau|dconf-service|gpg-agent|polkit-gnome-au|ssh-agent|tailscaled|wrapper-2.0|xfce4-panel|xfce4-session|xfconfd|xfdesktop|xfsettingsd|xfwm4|xinit|ps) ;;
      *) printf 'MAINTENANCE_BUSY process=%s pid=%s parent=%s\\n' "$comm" "$pid" "$parent" >&2; exit 21 ;;
    esac
  fi
done < <(ps -eo pid=,ppid=,uid=,comm=)
test "$(pgrep -x codex | wc -l)" -eq 1
test -z "$(systemctl list-jobs --no-legend --no-pager)"
while read -r unit rest; do
  case "$unit" in
    caddy.service|containerd.service|dbus-broker.service|docker.service|firewalld.service|getty@tty1.service|polkit.service|serial-getty@ttyAMA0.service|shadowsocksr.service|sshd.service|systemd-journald.service|systemd-logind.service|systemd-networkd.service|systemd-resolved.service|systemd-timesyncd.service|systemd-udevd.service|systemd-userdbd.service|tailscaled.service|user@1002.service) ;;
    *) exit 22 ;;
  esac
done < <(systemctl list-units --type=service --state=running --no-legend --no-pager)
# Proxy clients are drained by the already-approved shadowsocksr shutdown.
# They are not evidence of another local agent, shell or desktop job.
for port in 5901 4822 8080 443 80; do
  test -z "$(ss -tnH state established "sport = :$port")"
done`;
    await remote("bash -c " + shellQuote(script));
  };
  const verifyQuiesced = async () => {
    const journal = requireJournal();
    const containers = await inspectContainers();
    for (const expected of journal.containers) {
      const current = containers.find((c) => c.name === expected.name);
      if (
        !current || current.id !== expected.id || current.running ||
        ![0, 143].includes(current.exitCode)
      ) {
        throw new Error("Container did not quiesce cleanly");
      }
    }
    for (const unit of journal.units) {
      if (await active(unit.name)) {
        throw new Error("Application service is still active");
      }
      if (
        unit.stopIntent &&
        await remote(
            "systemctl show --value -p Result " + shellQuote(unit.name),
          ) !== "success"
      ) {
        throw new Error("Application service did not stop cleanly");
      }
    }
    await assertNoActiveWork();
    await remote("sync");
  };
  return {
    assertNoActiveWork,
    quiesce: async () => {
      await assertNoActiveWork();
      await bootProof();
      if (getJournal()) {
        throw new Error("Existing guest journal requires reconciliation");
      }
      const containers = await inspectContainers();
      const runningNames =
        (await remote("sudo -n docker ps --format '{{.Names}}'")).split("\n");
      if (runningNames.some((name) => !containerNames.includes(name))) {
        throw new Error("Uninventoried running container");
      }
      const journal: GuestJournal = {
        rootUuid: policy.rootUuid,
        stagingUuid: policy.stagingUuid,
        containers: containers.map(({ id, name, running }) => ({
          id,
          name,
          running,
        })),
        units: [],
        restored: false,
      };
      for (const name of unitNames) {
        journal.units.push({ name, active: await active(name) });
      }
      if (
        journal.containers.some((c) => !c.running) ||
        journal.units.some((u) => !u.active)
      ) {
        throw new Error(
          "Expected source applications are not running before backup",
        );
      }
      await save(structuredClone(journal));
      for (const unit of journal.units) {
        if (!unit.active) continue;
        await assertNoActiveWork();
        unit.stopIntent = true;
        await save(structuredClone(journal));
        await remote("sudo -n systemctl stop " + shellQuote(unit.name));
      }
      for (const container of journal.containers) {
        if (!container.running) continue;
        await assertNoActiveWork();
        container.stopIntent = true;
        await save(structuredClone(journal));
        await remote(
          "sudo -n docker stop --timeout 120 " + shellQuote(container.id),
        );
      }
      await verifyQuiesced();
    },
    verifyQuiesced,
    acceptSource: async () => {
      // SSH may be unavailable while the source finishes booting. Retry only
      // reads; do not replay a failed application mutation blindly.
      let reachable = false;
      for (let attempt = 0; attempt < 60; attempt++) {
        try {
          await remote("true");
          reachable = true;
          break;
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 5_000));
        }
      }
      if (!reachable) throw new Error("Source SSH did not recover");
      const journal = getJournal() ? requireJournal() : undefined;
      if (journal) {
        const containers = await inspectContainers();
        for (const expected of [...journal.containers].reverse()) {
          const current = containers.find((c) => c.name === expected.name);
          if (!current || current.id !== expected.id) {
            throw new Error("Recovery container identity changed");
          }
          if (expected.running && expected.stopIntent && !current.running) {
            await remote("sudo -n docker start " + shellQuote(current.id));
          }
        }
        for (const unit of journal.units) {
          if (unit.active && unit.stopIntent && !await active(unit.name)) {
            await remote("sudo -n systemctl start " + shellQuote(unit.name));
          }
        }
      }
      await bootProof();
      const containers = await inspectContainers();
      if (journal) {
        for (const expected of journal.containers) {
          if (
            containers.find((c) => c.id === expected.id)?.running !==
              expected.running
          ) throw new Error("Container running state was not restored");
        }
        for (const unit of journal.units) {
          if (await active(unit.name) !== unit.active) {
            throw new Error("Service running state was not restored");
          }
        }
      }
      // is-active with multiple units succeeds when any one is active.
      // Check each required service independently.
      for (const unit of ["docker.service", "tailscaled.service"]) {
        await remote("systemctl is-active " + shellQuote(unit) + " >/dev/null");
      }
      for (
        const unit of [
          "vncserver.service",
          "tailscaled.service",
          "codex-remote-daemon.service",
        ]
      ) {
        await remote(
          "systemctl --user is-active " + shellQuote(unit) + " >/dev/null",
        );
      }
      const socket =
        "/home/codex/.codex/app-server-control/app-server-control.sock";
      const daemon = JSON.parse(
        await remote(
          "/usr/local/bin/deno run --allow-net --allow-read=" +
            shellQuote(socket) + " --allow-write=" + shellQuote(socket) + " " +
            shellQuote(policy.activityScriptPath),
        ),
      );
      if (!Number.isInteger(daemon.loadedThreads) || daemon.loadedThreads < 0) {
        throw new Error("Codex daemon control API did not recover");
      }
      // Read actual served application markup, not only its health endpoint.
      let applicationReady = false;
      for (let attempt = 0; attempt < 30; attempt++) {
        try {
          await remote(
            "page=$(curl --fail --silent --show-error --max-time 15 http://127.0.0.1:8080/guacamole/); [[ $page == *guacamole* && $page == *ng-app* ]]",
          );
          applicationReady = true;
          break;
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 2_000));
        }
      }
      if (!applicationReady) {
        throw new Error(
          "Guacamole did not serve its application after recovery",
        );
      }
      if (journal) {
        journal.restored = true;
        await save(journal);
      }
    },
  };
}
