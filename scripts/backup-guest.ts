import {
  RetryableObservationError,
  type SourceContinuityEvidence,
} from "./online-backup-contract.ts";
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

export function shellQuote(value: string): string {
  if (value.includes("\0")) throw new Error("NUL is not a shell argument");
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/** Read-only acceptance of the running source. Legacy GuestJournal is retained
 * only for parsing saved historical evidence, never for replaying mutations.
 */
export function backupGuestControl(
  policy: GuestPolicy,
  runner: CommandRunner = defaultRunner,
): {
  acceptSource(): Promise<void>;
  observeSource(): Promise<SourceContinuityEvidence>;
} {
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
    if (result.code === 255) {
      throw new RetryableObservationError("Source SSH observation unavailable");
    }
    if (result.code !== 0) {
      throw new Error(`Guest observation failed (${result.code})`);
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
  return {
    observeSource: async () => {
      const bootId = await remote("cat /proc/sys/kernel/random/boot_id");
      if (!/^[a-f0-9-]{36}$/.test(bootId)) {
        throw new Error("Invalid source boot ID");
      }
      const serviceInvocations: Record<string, string> = {};
      for (
        const [scope, units] of [
          ["system", [
            "docker.service",
            "caddy.service",
            "shadowsocksr.service",
            "tailscaled.service",
          ]],
          ["user", [
            "vncserver.service",
            "tailscaled.service",
            "codex-remote-daemon.service",
          ]],
        ] as const
      ) {
        for (const unit of units) {
          const output = await remote(
            "systemctl " + (scope === "user" ? "--user " : "") +
              "show -p ActiveState -p InvocationID " + shellQuote(unit),
          );
          const values = Object.fromEntries(
            output.split("\n").map((line) => line.split("=")),
          );
          if (
            values.ActiveState !== "active" ||
            !/^[a-f0-9]{32}$/.test(values.InvocationID ?? "")
          ) {
            throw new Error(
              "Source service is not active with a bound invocation: " + scope +
                ":" + unit,
            );
          }
          serviceInvocations[scope + ":" + unit] = values.InvocationID;
        }
      }
      return {
        bootId,
        serviceInvocations,
        observedAtUtc: new Date().toISOString(),
      };
    },
    acceptSource: async () => {
      // The online engine owns durable backoff. A transport outage must not
      // become a terminal journal failure after an in-process retry loop.
      await remote("true");
      await bootProof();
      const containers = await inspectContainers();
      if (
        containers.length !== containerNames.length ||
        containers.some((item) => !item.running)
      ) {
        throw new Error("Required source container is not running");
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
    },
  };
}
