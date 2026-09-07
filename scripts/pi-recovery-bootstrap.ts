/** Public bootstrap for an approved Ubuntu 24.04 AArch64 replacement.
 * Generates cloud-init only; the builder downloads no binary and changes no
 * target. Artifacts are fetched by the replacement into tmpfs, never by Pi.
 */
import { createHash } from "node:crypto";
import { shellQuote } from "./backup-guest.ts";
import { hostKeyConsoleCommand } from "./pi-recovery-ssh.ts";

export const RESCUE_DIRECTORY = "/run/uos-recovery-bootstrap";
export const ALPINE_RELEASE = {
  version: "3.24.1",
  archiveUrl:
    "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-netboot-3.24.1-aarch64.tar.gz",
  archiveSha256:
    "54fe38fa41cce740ba379458ed63cfcd89ab06ae5e6a47a06dafe0a34e8427e8",
  signerFingerprint: "0482D84022F52DF1C4E7CD43293ACD0907D9495A",
  publicKeySha256:
    "75a9a7e0cc35bfa946ce40c26133b3ed29a204fbd98a3b33331b659d927b3027",
} as const;
const MAIN_REPOSITORY = "https://dl-cdn.alpinelinux.org/alpine/v3.24/main";
const COMMUNITY_REPOSITORY =
  "https://dl-cdn.alpinelinux.org/alpine/v3.24/community";
const MODLOOP_URL =
  "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/netboot-3.24.1/modloop-virt";
const PACKAGES = [
  "alpine-base",
  "bash",
  "blkid",
  "ca-certificates",
  "curl",
  "deno=2.7.4-r2",
  "dosfstools",
  "e2fsprogs",
  "eudev",
  "findmnt",
  "gnupg",
  "ifupdown-ng",
  "lsblk",
  "lvm2",
  "openssh",
  "openssl",
  "sfdisk",
  "sudo",
  "tar",
  "udev-init-scripts-openrc",
  "util-linux-misc",
  "wipefs",
  "xfsprogs",
  "zstd",
];
export interface PublicRescueBootstrap {
  requestId: string;
  /** Existing Pi SSH public key; private SSH/GPG keys never enter cloud-init. */
  sshPublicKey: string;
}
export interface RescueFile {
  path: string;
  mode: "0600" | "0644" | "0755";
  content: string;
}
function validate(input: PublicRescueBootstrap): void {
  if (
    !/^recovery-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(
      input.requestId,
    )
  ) {
    throw Error("Invalid rescue request identity");
  }
  const match = input.sshPublicKey.trim().match(
    /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]+)?$/,
  );
  if (!match) throw Error("Use the existing Pi Ed25519 public key");
  let raw: Uint8Array;
  try {
    raw = Uint8Array.from(atob(match[1]), (c) => c.charCodeAt(0));
  } catch {
    throw Error("Malformed SSH public key");
  }
  const view = new DataView(raw.buffer);
  if (
    raw.length !== 51 || view.getUint32(0) !== 11 ||
    new TextDecoder().decode(raw.slice(4, 15)) !== "ssh-ed25519" ||
    view.getUint32(15) !== 32
  ) {
    throw Error("Malformed SSH Ed25519 public key");
  }
}
export function rescueKernelCommandLine(): string {
  return [
    "console=ttyAMA0,115200",
    "console=tty0",
    "ip=dhcp",
    "modules=virtio_pci,virtio_net,virtio_scsi,loop,squashfs",
    "apkovl=/uos-rescue.apkovl.tar.gz",
    "rootflags=size=8G",
    `alpine_repo=${MAIN_REPOSITORY},${COMMUNITY_REPOSITORY}`,
    `modloop=${MODLOOP_URL}`,
  ].join(" ");
}
/** Local apkovl is appended to initramfs and unpacked into Alpine tmpfs.
 * The target assembler supplies verified modloop bytes at lib/modloop-virt,
 * where Alpine's modloop service finds its cached URL file.
 */
export function rescueOverlayFiles(input: PublicRescueBootstrap): RescueFile[] {
  validate(input);
  const files: RescueFile[] = [
    {
      path: "etc/apk/world",
      mode: "0644",
      content: PACKAGES.join("\n") + "\n",
    },
    { path: "etc/hostname", mode: "0644", content: "uos-ram-rescue\n" },
    {
      path: "etc/network/interfaces",
      mode: "0644",
      content: "auto lo\niface lo inet loopback\n",
    },
    {
      path: "etc/conf.d/networking",
      mode: "0644",
      content: 'rc_need="uos-rescue-network"\n',
    },
    {
      path: "etc/lvm/lvm.conf",
      mode: "0644",
      content: "activation { auto_activation_volume_list = [] }\n",
    },
    {
      path: "etc/init.d/uos-rescue-network",
      mode: "0755",
      content: `#!/sbin/openrc-run
description="Bind DHCP to the sole replacement Ethernet interface"
depend() { need udev-settle; before networking; }
start() {
  [ "$(findmnt -n -o FSTYPE /)" = tmpfs ] || return 1
  rescue_iface=
  for rescue_nic in /sys/class/net/*; do
    [ "$(cat "$rescue_nic/type")" = 1 ] || continue
    [ -z "$rescue_iface" ] || return 1
    rescue_iface=$(basename "$rescue_nic")
  done
  case "$rescue_iface" in ''|*[!a-zA-Z0-9_.-]*) return 1;; esac
  printf 'auto lo\\niface lo inet loopback\\nauto %s\\niface %s inet dhcp\\n' "$rescue_iface" "$rescue_iface" > /etc/network/interfaces
}
`,
    },
    {
      path: "etc/uos-rescue/request-id",
      mode: "0644",
      content: input.requestId + "\n",
    },
    {
      path: "etc/uos-rescue/authorized_keys",
      mode: "0644",
      content: input.sshPublicKey.trim() + "\n",
    },
    {
      path: "etc/ssh/sshd_config",
      mode: "0600",
      content: `PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers codex
AllowTcpForwarding no
AllowStreamLocalForwarding remote
StreamLocalBindUnlink yes
X11Forwarding no
Subsystem sftp internal-sftp
`,
    },
    {
      path: "etc/conf.d/sshd",
      mode: "0644",
      content: 'rc_need="uos-rescue-account"\n',
    },
    {
      path: "etc/sudoers.d/uos-rescue",
      mode: "0600",
      content: "codex ALL=(ALL) NOPASSWD: ALL\n",
    },
    {
      path: "etc/init.d/uos-rescue-account",
      mode: "0755",
      content: `#!/sbin/openrc-run
description="Prepare the non-root recovery account in RAM"
depend() { need localmount; before sshd; }
start() {
  [ "$(findmnt -n -o FSTYPE /)" = tmpfs ] || return 1
  [ "$(uname -m)" = aarch64 ] || return 1
  if ! awk -F: '$1 == "codex" { found=1 } END { exit !found }' /etc/group; then
    addgroup -g 1000 codex || return 1
  fi
  awk -F: '$1 == "codex" && $3 == 1000 { found++ } END { exit found != 1 }' /etc/group || return 1
  if ! id codex >/dev/null 2>&1; then
    adduser -D -u 1000 -G codex -s /bin/bash codex || return 1
  fi
  [ "$(id -u codex):$(id -g codex)" = 1000:1000 ] || return 1
  awk -F: '$1 == "codex" && $6 == "/home/codex" && $7 == "/bin/bash" { found++ } END { exit found != 1 }' /etc/passwd || return 1
  # Unknown random password hash avoids a locked-account public-key rejection.
  # All SSH password authentication remains disabled.
  rescue_hash=$(head -c 48 /dev/urandom | base64 | openssl passwd -6 -stdin) || return 1
  printf 'codex:%s\\n' "$rescue_hash" | chpasswd -e || return 1
  unset rescue_hash
  mkdir -p /home/codex/.ssh /run/uos-recovery/gnupg || return 1
  cp /etc/uos-rescue/authorized_keys /home/codex/.ssh/authorized_keys || return 1
  chmod 700 /home/codex/.ssh /run/uos-recovery /run/uos-recovery/gnupg || return 1
  chmod 600 /home/codex/.ssh/authorized_keys || return 1
  chown codex:codex /home/codex /home/codex/.ssh /home/codex/.ssh/authorized_keys /run/uos-recovery /run/uos-recovery/gnupg || return 1
  ssh-keygen -A || return 1
  ${hostKeyConsoleCommand(input.requestId, "ram")} || return 1
  return 0
}
`,
    },
  ];
  const manifest = {
    schemaVersion: 1,
    requestId: input.requestId,
    alpine: ALPINE_RELEASE,
    commandLine: rescueKernelCommandLine(),
    overlayFilesSha256: createHash("sha256").update(JSON.stringify(files))
      .digest("hex"),
  };
  files.push({
    path: "etc/uos-rescue/manifest.json",
    mode: "0644",
    content: JSON.stringify(manifest) + "\n",
  });
  return files;
}
export function rescueManifestSha256(input: PublicRescueBootstrap): string {
  const manifest = rescueOverlayFiles(input).find((file) =>
    file.path === "etc/uos-rescue/manifest.json"
  )!;
  return createHash("sha256").update(manifest.content).digest("hex");
}
function base64(text: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(text)));
}
/** Runs as root only on the new platform loader. Stages artifacts and hashes.
 * Pi must verify the receipt and obtain exact reboot approval before kexec.
 */
export function rescueAssemblerScript(input: PublicRescueBootstrap): string {
  const writes = rescueOverlayFiles(input).map((file) => {
    const directory = file.path.slice(0, file.path.lastIndexOf("/"));
    return `mkdir -p "$rescue_dir/overlay/${directory}"
printf '%s' '${
      base64(file.content)
    }' | base64 -d > "$rescue_dir/overlay/${file.path}"
chmod ${file.mode} "$rescue_dir/overlay/${file.path}"`;
  }).join("\n");
  return `#!/bin/bash
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(uname -m)" = aarch64
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:24.04
test "$(findmnt -n -o FSTYPE --target /run)" = tmpfs
rescue_dir=${shellQuote(RESCUE_DIRECTORY)}
test ! -e "$rescue_dir"
mkdir -m 700 "$rescue_dir"
mkdir "$rescue_dir/overlay" "$rescue_dir/append" "$rescue_dir/artifacts" "$rescue_dir/release-gnupg"
curl --fail --silent --show-error --max-time 10 -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/ > "$rescue_dir/instance.json"
jq -e --arg request ${
    shellQuote(input.requestId)
  } '.freeformTags.uosRecoveryRequest == $request and (.id | startswith("ocid1.instance."))' "$rescue_dir/instance.json" >/dev/null
${hostKeyConsoleCommand(input.requestId, "loader")}
curl --fail --silent --show-error --proto '=https' --max-time 300 --max-filesize 1073741824 ${
    shellQuote(ALPINE_RELEASE.archiveUrl)
  } -o "$rescue_dir/netboot.tar.gz"
printf '%s  %s\\n' '${ALPINE_RELEASE.archiveSha256}' "$rescue_dir/netboot.tar.gz" | sha256sum -c -
curl --fail --silent --show-error --proto '=https' --max-time 30 --max-filesize 16384 ${
    shellQuote(ALPINE_RELEASE.archiveUrl + ".asc")
  } -o "$rescue_dir/netboot.asc"
printf '%s  %s\\n' '${ALPINE_RELEASE.publicKeySha256}' /etc/uos-recovery-bootstrap/alpine-release-public.asc | sha256sum -c -
gpg --batch --homedir "$rescue_dir/release-gnupg" --with-colons --show-keys /etc/uos-recovery-bootstrap/alpine-release-public.asc > "$rescue_dir/release-key.txt"
test "$(awk -F: '$1 == "fpr" { print $10; exit }' "$rescue_dir/release-key.txt")" = '${ALPINE_RELEASE.signerFingerprint}'
gpg --batch --homedir "$rescue_dir/release-gnupg" --dearmor -o "$rescue_dir/release.gpg" /etc/uos-recovery-bootstrap/alpine-release-public.asc
gpgv --homedir "$rescue_dir/release-gnupg" --keyring "$rescue_dir/release.gpg" "$rescue_dir/netboot.asc" "$rescue_dir/netboot.tar.gz"
tar -xzf "$rescue_dir/netboot.tar.gz" --no-same-owner -C "$rescue_dir/artifacts" boot/vmlinuz-virt boot/initramfs-virt boot/modloop-virt
${writes}
mkdir -p "$rescue_dir/overlay/lib"
cp "$rescue_dir/artifacts/boot/modloop-virt" "$rescue_dir/overlay/lib/modloop-virt"
for rescue_level in sysinit boot default shutdown; do
  mkdir -p "$rescue_dir/overlay/etc/runlevels/$rescue_level"
done
for rescue_service in devfs dmesg udev udev-trigger udev-settle hwdrivers modloop; do
  ln -s /etc/init.d/"$rescue_service" "$rescue_dir/overlay/etc/runlevels/sysinit/$rescue_service"
done
for rescue_service in modules sysctl hostname bootmisc syslog uos-rescue-network networking; do
  ln -s /etc/init.d/"$rescue_service" "$rescue_dir/overlay/etc/runlevels/boot/$rescue_service"
done
for rescue_service in uos-rescue-account sshd; do
  ln -s /etc/init.d/"$rescue_service" "$rescue_dir/overlay/etc/runlevels/default/$rescue_service"
done
for rescue_service in mount-ro killprocs; do
  ln -s /etc/init.d/"$rescue_service" "$rescue_dir/overlay/etc/runlevels/shutdown/$rescue_service"
done
tar --numeric-owner --owner=0 --group=0 -czf "$rescue_dir/append/uos-rescue.apkovl.tar.gz" -C "$rescue_dir/overlay" .
(cd "$rescue_dir/append" && printf 'uos-rescue.apkovl.tar.gz\\n' | cpio --quiet -o --format=newc | gzip -n > "$rescue_dir/overlay.cpio.gz")
cat "$rescue_dir/artifacts/boot/initramfs-virt" "$rescue_dir/overlay.cpio.gz" > "$rescue_dir/initramfs-rescue"
cp "$rescue_dir/artifacts/boot/vmlinuz-virt" "$rescue_dir/vmlinuz-rescue"
printf '%s\\n' ${
    shellQuote(rescueKernelCommandLine())
  } > "$rescue_dir/kernel-command-line"
rescue_kernel_sha=$(sha256sum "$rescue_dir/vmlinuz-rescue" | cut -d' ' -f1)
rescue_initramfs_sha=$(sha256sum "$rescue_dir/initramfs-rescue" | cut -d' ' -f1)
jq -n --arg boot "$(cat /proc/sys/kernel/random/boot_id)" --arg request ${
    shellQuote(input.requestId)
  } --arg instance "$(jq -r .id "$rescue_dir/instance.json")" --arg kernel "$rescue_kernel_sha" --arg initramfs "$rescue_initramfs_sha" '{status:"RAM_RESCUE_STAGED",requestId:$request,instanceId:$instance,sourceBootId:$boot,kernelSha256:$kernel,initramfsSha256:$initramfs,rebooted:false,disksPrepared:false}' > "$rescue_dir/receipt.json"
sync
printf 'UOS_RAM_RESCUE_STAGED ${input.requestId}\\n' >/dev/console
`;
}
/** Copy this string into ReplacementConfig.cloudInit before approval digest.
 * Ubuntu is an explicit loader prerequisite, not a fallback for other images.
 * Nothing in runcmd invokes kexec.
 */
export async function buildRescueCloudInit(
  input: PublicRescueBootstrap,
): Promise<string> {
  validate(input);
  const releaseKey = await Deno.readTextFile(
    new URL("../config/alpine-release-public.asc", import.meta.url),
  );
  if (
    createHash("sha256").update(releaseKey).digest("hex") !==
      ALPINE_RELEASE.publicKeySha256
  ) {
    throw Error("Pinned Alpine release public key differs");
  }
  const guard =
    `test "$(uname -m)" = aarch64 && . /etc/os-release && test "$ID:$VERSION_ID" = ubuntu:24.04`;
  return "#cloud-config\n" + JSON.stringify(
    {
      users: [{
        name: "codex",
        groups: ["sudo"],
        shell: "/bin/bash",
        lock_passwd: true,
        sudo: "ALL=(ALL) NOPASSWD: ALL",
        ssh_authorized_keys: [input.sshPublicKey.trim()],
      }],
      disable_root: true,
      ssh_pwauth: false,
      bootcmd: [["bash", "-ec", guard]],
      packages: [
        "kexec-tools",
        "cpio",
        "curl",
        "ca-certificates",
        "gnupg",
        "jq",
      ],
      write_files: [
        {
          path: "/etc/default/kexec",
          permissions: "0644",
          content: "LOAD_KEXEC=false\n",
        },
        {
          path: "/etc/uos-recovery-bootstrap/alpine-release-public.asc",
          permissions: "0644",
          content: releaseKey,
        },
        {
          path: "/usr/local/sbin/uos-prepare-ram-rescue",
          permissions: "0700",
          content: rescueAssemblerScript(input),
        },
      ],
      runcmd: [["/usr/local/sbin/uos-prepare-ram-rescue"]],
    },
    null,
    2,
  ) + "\n";
}
