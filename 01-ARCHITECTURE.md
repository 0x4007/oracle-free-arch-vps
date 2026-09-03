# Architecture

The numeric allocation in this file is the target that fit Oracle's published
limits on 2026-09-03. Verify the current official policy and signed-in account
state before using it.

## Selected design

Use one OCI Ampere A1 Flex instance with 2 OCPUs and 12 GB RAM. After current
limit verification, allocate the 200 GB live-volume target as follows:

```text
OCI firmware
  -> 50 GB staging boot volume
       -> UEFI and GRUB
       -> /arch-vmlinuz
       -> /arch-initrd.img
       -> root=UUID=<ARCH_ROOT_UUID>
  -> 150 GB Arch root volume
       -> partition 1: small EFI/recovery partition if used
       -> partition 2: ext4 root mounted at /
```

The exact partition names and device paths are deployment facts. Agents must
discover and record them. The root UUID is the stable contract between GRUB, the
kernel command line, `fstab`, and the restored volume.

The accepted steady state is one `RUNNING` OCI instance with display name `arch`
and one running Arch guest with hostname `arch`.

## Why not assume a native Arch boot image

Oracle supports importing Linux VMDK and QCOW2 images, and recommends
paravirtualized mode where supported. However, Oracle's published supported-OS
matrix and Linux image requirements are not an Arch-on-A1 guarantee. Firmware,
boot loader, network initialization, cloud-init, and shape compatibility must
all work before an imported image is useful.

Treat native Arch custom-image import as an optional experiment. Do not use it
as the production plan unless it passes an isolated launch, serial-console, SSH,
stop/start, and recovery test without consuming the live-volume allowance needed
by the accepted machine.

A custom image contains only the boot disk and excludes attached block-volume
data. Verify current image-storage pricing and quota before retaining one. In
this architecture it cannot replace the matched boot/root backup pair.

The staging design is preferred because it:

- Starts from an OCI-supported A1 image and firmware path.
- Keeps an Oracle recovery entry.
- Lets Arch run natively on AArch64 from its own root filesystem.
- Avoids rebuilding the instance when the Arch root changes.
- Produces a clear two-object recovery contract.

## Arch root requirements

The Arch root must contain:

- A current Arch Linux ARM AArch64 userspace.
- An AArch64 kernel and initramfs that boot on the OCI A1 virtual hardware.
- `systemd`, networking, DNS, SSH, and a non-root administrative user.
- A stable `/etc/fstab` based on UUIDs.
- Paravirtualized block and network drivers in the kernel/initramfs.
- DHCP-based network configuration with no hard-coded MAC address.
- A staged-boot synchronization hook that copies the current kernel and
  initramfs to the staging boot filesystem after relevant package updates.

## Staging boot requirements

The staging volume must retain:

- Its OCI-compatible UEFI and boot loader layout.
- A default GRUB entry that loads the staged Arch kernel and initramfs.
- `root=UUID=<ARCH_ROOT_UUID>` on the Arch kernel command line.
- An OCI-supported recovery entry.
- Enough free space for atomic kernel/initramfs replacement.

The synchronization script must fail loudly, use a temporary file plus atomic
rename where possible, verify source and destination hashes, and write a local
log. The package hook must run only after the kernel or initramfs changes.

## Storage performance tradeoff

Oracle's Balanced-volume page stated 60 IOPS/GB and 480 KB/s/GB when checked on
2026-09-03. This gives the 150 GB Arch root a theoretical ceiling of about 9,000
IOPS and 72 MB/s. A hypothetical single 200 GB root could reach about 12,000
IOPS and 96 MB/s. Verify the current rates before using these estimates.

Do not rebuild the accepted two-volume machine only for that theoretical gain.
The staging boot path and paired recovery contract are deliberate safety
tradeoffs.

## Network design

- One VCN and public subnet in the home region.
- One primary VNIC using DHCP.
- One reserved public IPv4 address assigned to the primary private IP.
- One stateful ingress rule for TCP 22 from the operator's approved source.
  Prefer a narrow source CIDR over `0.0.0.0/0` when practical.
- Required egress only.
- No public application ports until a real service and an explicit approval
  require them.
- DNS-only A records can point the main hostname and wildcard to the reserved
  address.

## Recovery unit

The staging boot backup and Arch root backup with the same UTC suffix are one
unit. Restoring either object alone is incomplete.
