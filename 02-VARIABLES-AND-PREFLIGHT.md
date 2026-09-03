# Variables and Preflight Worksheet

Complete this worksheet with local notes. Do not commit real credentials or
private keys.

## Account facts

| Field | Value |
|---|---|
| Verification date | `<UTC_DATE>` |
| Account type shown in OCI | `<FREE_TIER_OR_ALWAYS_FREE>` |
| Tenancy home region | `<HOME_REGION>` |
| Compartment name | `<COMPARTMENT_NAME>` |
| Compartment OCID | `<COMPARTMENT_OCID>` |
| A1 OCPU allowance | `<CURRENT_LIMIT>` |
| A1 memory allowance | `<CURRENT_LIMIT>` |
| Combined boot/block storage allowance | `<CURRENT_LIMIT_GB>` |
| Combined boot/block backup count | `<CURRENT_LIMIT>` |
| Object Storage allowance | `<CURRENT_LIMIT_GB>` |
| Current spend shown | `<CURRENCY_AND_AMOUNT>` |

## Target resources

| Field | Value |
|---|---|
| Instance display name | `arch` |
| Instance OCID | `<INSTANCE_OCID>` |
| Availability domain | `<AD>` |
| Shape | `VM.Standard.A1.Flex` |
| OCPUs | `2` after current-limit verification |
| RAM | `12 GB` after current-limit verification |
| VCN OCID | `<VCN_OCID>` |
| Subnet OCID | `<SUBNET_OCID>` |
| Security-list OCID | `<SECURITY_LIST_OCID>` |
| Primary VNIC OCID | `<VNIC_OCID>` |
| Primary private-IP OCID | `<PRIVATE_IP_OCID>` |
| Reserved public-IP OCID | `<RESERVED_PUBLIC_IP_OCID>` |
| Reserved public IPv4 | `<RESERVED_IPV4>` |
| DNS hostname | `<HOSTNAME>` |
| DNS wildcard | `<WILDCARD_HOSTNAME>` |

## Storage and boot facts

| Field | Value |
|---|---|
| Staging boot-volume OCID | `<BOOT_VOLUME_OCID>` |
| Staging boot size | `50 GB` |
| Arch root-volume OCID | `<ROOT_VOLUME_OCID>` |
| Arch root size | `150 GB` |
| Root attachment OCID | `<ROOT_ATTACHMENT_OCID>` |
| Root device discovered in guest | `<ROOT_DEVICE>` |
| Root partition start sector | `<START_SECTOR>` |
| Root filesystem type | `ext4` |
| Root filesystem UUID | `<ARCH_ROOT_UUID>` |
| Staging filesystem/device | `<STAGING_DEVICE_AND_FS>` |
| Staged kernel path | `<STAGED_KERNEL_PATH>` |
| Staged initramfs path | `<STAGED_INITRAMFS_PATH>` |

## Access facts

| Field | Value |
|---|---|
| Normal SSH user | `<NON_ROOT_USER>` |
| Recovery SSH user | `<IMAGE_DEFAULT_USER>` |
| Host-key fingerprint | `<EXPECTED_FINGERPRINT>` |
| Serial-console recovery path | `<LOCAL_REFERENCE_ONLY>` |

## Read-only preflight

Before the first mutation, record:

- All non-terminated instances and shape allocations.
- All boot and block volumes, sizes, performance levels, and attachments.
- All boot-volume and block-volume backups.
- All custom images and relevant Object Storage objects.
- All regional public IPs.
- The complete security-list and network-security-group rules.
- Current DNS records and authoritative answers.
- Active OCI CLI, SSH, browser, and agent writers.
- Guest `lsblk`, `findmnt`, `df`, `fstab`, failed units, listeners, and free
  space.

Stop if any resource is unexpected, another writer is active, the account is
not eligible, the limits differ from the plan, or the total after the proposed
operation would exceed the free allowance.
