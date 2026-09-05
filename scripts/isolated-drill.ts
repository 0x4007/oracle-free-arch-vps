import type { BackupPair, BackupSource } from "./weekly-backup.ts";
import type { JsonRecord } from "./oci.ts";
import { validateBackupPair } from "./oci-restore.ts";

export interface DrillPlan {
  source: BackupSource;
  pair: BackupPair;
  sourceAcceptedAtUtc: string;
  availabilityDomain: string;
  productionReservedIpId: string;
  productionSubnetId: string;
  productionVcnId: string;
  controllerIpv4: string;
  suffix: string;
  maxDurationHours: number;
  spendingCapUsd: number;
}
export interface DrillApproval {
  approvedAtUtc: string;
  expiresAtUtc: string;
  exactOperation: "one isolated trial-funded paired restore drill";
  planSha256: string;
}
export interface DrillAccountEvidence {
  observedAtUtc: string;
  subscriptionTier: string;
  paymentModel: string;
  trialExpiresAtUtc: string;
  availableTrialCreditsUsd: number;
}
export interface DrillNetworkEvidence {
  subnet: JsonRecord;
  securityLists: JsonRecord[];
  routeTable: JsonRecord;
  internetGateway: JsonRecord;
  dhcpOptions: JsonRecord;
}

export function controllerCidr(ip: string): string {
  const octets = ip.split(".");
  if (
    octets.length !== 4 ||
    octets.some((n) => !/^(0|[1-9]\d{0,2})$/.test(n) || Number(n) > 255)
  ) throw new Error("Controller requires one public IPv4 address");
  const [a, b] = octets.map(Number);
  if (
    [0, 10, 127].includes(a) || a >= 224 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
  ) throw new Error("Controller SSH source is not a public IPv4 address");
  return ip + "/32";
}
export function drillSecurityRules(plan: DrillPlan) {
  return {
    ingressSecurityRules: [{
      protocol: "6",
      source: controllerCidr(plan.controllerIpv4),
      sourceType: "CIDR_BLOCK",
      isStateless: false,
      tcpOptions: { destinationPortRange: { min: 22, max: 22 } },
    }],
    egressSecurityRules: [],
  };
}
export function drillDhcpOptions() {
  // TEST-NET-1 is not a resolver. Routed DNS is blocked by the empty egress
  // list; DHCP must not advertise OCI's exempt link-local recursive resolver.
  return [{
    type: "DomainNameServer",
    serverType: "CustomDnsServer",
    customDnsServers: ["192.0.2.1"],
  }];
}
export function drillHourlyCostUsd(): number {
  // Current Oracle A1 and Balanced volume prices; September has 720 hours.
  return 2 * 0.01 + 12 * 0.0015 + 200 * (0.0255 + 10 * 0.0017) / 720;
}
export async function drillPlanDigest(plan: DrillPlan): Promise<string> {
  // Preserve the exact reviewed JSON bytes; reordered plans require review.
  return [
    ...new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(JSON.stringify(plan)),
      ),
    ),
  ].map((b) => b.toString(16).padStart(2, "0")).join("");
}
export async function validateDrillApproval(
  plan: DrillPlan,
  approval: DrillApproval,
  account: DrillAccountEvidence,
  bootBackup: JsonRecord,
  rootBackup: JsonRecord,
  now: Date,
): Promise<void> {
  validateBackupPair(
    bootBackup,
    rootBackup,
    plan.pair.suffix,
    plan.source.bootVolumeId,
    plan.source.rootVolumeId,
    plan.source.compartmentId,
  );
  if (
    bootBackup.id !== plan.pair.bootId || rootBackup.id !== plan.pair.rootId
  ) throw new Error("Drill backups differ from the accepted fresh pair");
  const timestamp = now.getTime();
  const approved = Date.parse(approval.approvedAtUtc);
  const expires = Date.parse(approval.expiresAtUtc);
  const accountAt = Date.parse(account.observedAtUtc);
  const accepted = Date.parse(plan.sourceAcceptedAtUtc);
  if (
    approval.exactOperation !==
      "one isolated trial-funded paired restore drill" ||
    approval.planSha256 !== await drillPlanDigest(plan) ||
    !Number.isFinite(approved) || !Number.isFinite(expires) ||
    approved > timestamp || timestamp >= expires ||
    expires - approved > 3_600_000 || timestamp - approved > 3_600_000 ||
    !Number.isFinite(accountAt) || accountAt > timestamp ||
    timestamp - accountAt > 300_000 ||
    !Number.isFinite(accepted) || accepted > timestamp ||
    !/^\d{8}T\d{6}Z$/.test(plan.suffix) ||
    plan.source.region !== "us-ashburn-1" ||
    !Number.isFinite(plan.maxDurationHours) || plan.maxDurationHours <= 0 ||
    plan.maxDurationHours > 4 ||
    !Number.isFinite(plan.spendingCapUsd) || plan.spendingCapUsd <= 0 ||
    plan.spendingCapUsd < drillHourlyCostUsd() * plan.maxDurationHours ||
    account.subscriptionTier !== "FREE_AND_TRIAL" ||
    account.paymentModel !== "FREE_TRIAL" ||
    !Number.isFinite(account.availableTrialCreditsUsd) ||
    account.availableTrialCreditsUsd < plan.spendingCapUsd ||
    !Number.isFinite(Date.parse(account.trialExpiresAtUtc)) ||
    timestamp + plan.maxDurationHours * 3_600_000 >=
      Date.parse(account.trialExpiresAtUtc)
  ) {
    throw new Error(
      "Exact drill approval, trial coverage, source acceptance or spending bound is not proved",
    );
  }
  controllerCidr(plan.controllerIpv4);
}

/** Verify routed-traffic restrictions on the actual subnet and every list.
 * OCI exempts 169.254.0.0/16 from security rules. This function alone is NOT
 * proof of full first-boot isolation; no mutation entry point may rely on it.
 * OCI security lists are additive: a second permissive list invalidates proof.
 */
export function verifyDrillRoutedNetwork(
  plan: DrillPlan,
  network: DrillNetworkEvidence,
): void {
  const { subnet, securityLists, routeTable, internetGateway, dhcpOptions } =
    network;
  const ids = subnet["security-list-ids"];
  if (
    subnet.id === plan.productionSubnetId || !subnet.id ||
    subnet["vcn-id"] === plan.productionVcnId ||
    subnet["compartment-id"] !== plan.source.compartmentId ||
    subnet["prohibit-public-ip-on-vnic"] !== false ||
    subnet["lifecycle-state"] !== "AVAILABLE" ||
    subnet["cidr-block"] !== "10.77.0.0/28" ||
    !Array.isArray(ids) || ids.length !== 1 || securityLists.length !== 1 ||
    ids[0] !== securityLists[0].id ||
    subnet["route-table-id"] !== routeTable.id || !subnet["vcn-id"] ||
    subnet["dhcp-options-id"] !== dhcpOptions.id ||
    (subnet["ipv6-cidr-block"] != null) ||
    (Array.isArray(subnet["ipv6-cidr-blocks"]) &&
      subnet["ipv6-cidr-blocks"].length !== 0) ||
    [routeTable, internetGateway, dhcpOptions, ...securityLists].some((r) =>
      r["vcn-id"] !== subnet["vcn-id"] ||
      r["compartment-id"] !== plan.source.compartmentId
    ) ||
    internetGateway["is-enabled"] !== true
  ) throw new Error("Drill network identity or isolation is unproved");
  const options = dhcpOptions.options as JsonRecord[];
  const resolver = Array.isArray(options) && options.length === 1
    ? options[0]
    : undefined;
  if (
    !resolver || resolver.type !== "DomainNameServer" ||
    resolver["server-type"] !== "CustomDnsServer" ||
    JSON.stringify(resolver["custom-dns-servers"]) !==
      JSON.stringify(["192.0.2.1"])
  ) {
    throw new Error("Drill DHCP would allow the default recursive resolver");
  }
  const security = securityLists[0];
  const expected = drillSecurityRules(plan);
  const ingress = security["ingress-security-rules"] as JsonRecord[];
  const egress = security["egress-security-rules"];
  if (
    !Array.isArray(egress) || egress.length !== 0 || !Array.isArray(ingress) ||
    ingress.length !== 1
  ) throw new Error("Drill security rules permit unapproved traffic");
  const rule = ingress[0];
  const ports = (rule["tcp-options"] as JsonRecord)
    ?.["destination-port-range"] as JsonRecord;
  if (
    rule.protocol !== "6" ||
    rule.source !== expected.ingressSecurityRules[0].source ||
    rule["source-type"] !== "CIDR_BLOCK" || rule["is-stateless"] !== false ||
    ports?.min !== 22 || ports?.max !== 22
  ) throw new Error("Drill SSH ingress is not restricted to the Pi");
  const routes = routeTable["route-rules"] as JsonRecord[];
  if (
    !Array.isArray(routes) || routes.length !== 1 ||
    routes[0].destination !== "0.0.0.0/0" ||
    routes[0]["destination-type"] !== "CIDR_BLOCK" ||
    routes[0]["network-entity-id"] !== internetGateway.id
  ) throw new Error("Drill route table is not the reviewed isolated route");
}

export function drillLaunchRequest(
  plan: DrillPlan,
  subnetId: string,
  bootVolumeId: string,
  rootVolumeId: string,
) {
  if (
    !subnetId || subnetId === plan.productionSubnetId || !bootVolumeId ||
    !rootVolumeId || bootVolumeId === rootVolumeId ||
    [bootVolumeId, rootVolumeId].some((id) =>
      [plan.source.bootVolumeId, plan.source.rootVolumeId].includes(id)
    )
  ) throw new Error("Drill launch cannot use production network or volumes");
  return {
    availabilityDomain: plan.availabilityDomain,
    compartmentId: plan.source.compartmentId,
    displayName: "arch-drill-" + plan.suffix,
    shape: "VM.Standard.A1.Flex",
    shapeConfig: { ocpus: 2, memoryInGBs: 12 },
    sourceDetails: { sourceType: "bootVolume", bootVolumeId },
    launchVolumeAttachments: [{
      type: "paravirtualized",
      volumeId: rootVolumeId,
    }],
    createVnicDetails: { subnetId, assignPublicIp: true, nsgIds: [] },
    launchOptions: {
      networkType: "PARAVIRTUALIZED",
      remoteDataVolumeType: "PARAVIRTUALIZED",
      firmware: "UEFI_64",
      isConsistentVolumeNamingEnabled: false,
      isPvEncryptionInTransitEnabled: false,
    },
  };
}
