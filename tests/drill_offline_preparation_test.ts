import {
  drillGuestBundle,
  drillGuestFilesDigest,
  offlinePreparationCommand,
  type OfflinePreparationEvidence,
} from "../scripts/drill-offline-preparation.ts";
import type { DrillPlan } from "../scripts/isolated-drill.ts";

const plan: DrillPlan = {
  source: {
    instanceId: "production",
    bootVolumeId: "source-boot",
    rootVolumeId: "source-root",
    compartmentId: "tenancy",
    region: "us-ashburn-1",
  },
  pair: {
    suffix: "20260905T050131Z",
    bootId: "fresh-boot",
    rootId: "fresh-root",
  },
  sourceAcceptedAtUtc: "2026-09-05T05:45:54Z",
  availabilityDomain: "AD",
  productionReservedIpId: "production-ip",
  productionSubnetId: "production-subnet",
  productionVcnId: "production-vcn",
  controllerIpv4: "203.0.113.10",
  suffix: "20260905T070000Z",
  maxDurationHours: 4,
  spendingCapUsd: 0.5,
  helperImageId: "helper-image",
  offlineFilesSha256: "0".repeat(64),
};
const evidence: OfflinePreparationEvidence = {
  helper: {
    id: "helper",
    "image-id": "helper-image",
    "lifecycle-state": "RUNNING",
    "compartment-id": "tenancy",
    "availability-domain": "AD",
    "display-name": "arch-drill-helper-20260905T070000Z",
  },
  bootAttachment: {
    "instance-id": "helper",
    "volume-id": "copied-boot",
    "lifecycle-state": "ATTACHED",
    "attachment-type": "paravirtualized",
    device: "/dev/oracleoci/oraclevdb",
  },
  rootAttachment: {
    "instance-id": "helper",
    "volume-id": "copied-root",
    "lifecycle-state": "ATTACHED",
    "attachment-type": "paravirtualized",
    device: "/dev/oracleoci/oraclevdc",
  },
  bootVolumeId: "copied-boot",
  rootVolumeId: "copied-root",
  rootUuid: "11111111-1111-4111-8111-111111111111",
  stagingUuid: "22222222-2222-4222-8222-222222222222",
  kernelSha256: "a".repeat(64),
  initramfsSha256: "b".repeat(64),
  grubSha256: "c".repeat(64),
};
function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}
async function refuses(run: () => Promise<unknown>) {
  let error = false;
  try {
    await run();
  } catch {
    error = true;
  }
  assert(error, "Unsafe preparation must be refused");
}
Deno.test("offline preparation rejects production disks and attachment drift", async () => {
  plan.offlineFilesSha256 = await drillGuestFilesDigest(
    await drillGuestBundle(plan),
  );
  for (
    const change of [
      (e: OfflinePreparationEvidence) => e.helper.id = "production",
      (e: OfflinePreparationEvidence) => e.rootVolumeId = "source-root",
      (e: OfflinePreparationEvidence) => e.bootVolumeId = "source-boot",
      (e: OfflinePreparationEvidence) =>
        e.rootAttachment["instance-id"] = "production",
      (e: OfflinePreparationEvidence) =>
        e.bootAttachment["volume-id"] = "source-boot",
      (e: OfflinePreparationEvidence) =>
        e.rootAttachment["lifecycle-state"] = "ATTACHING",
      (e: OfflinePreparationEvidence) => e.rootAttachment.device = "/dev/sda",
      (e: OfflinePreparationEvidence) => e.rootAttachment.device = null,
      (e: OfflinePreparationEvidence) =>
        e.rootAttachment.device = e.bootAttachment.device,
      (e: OfflinePreparationEvidence) =>
        e.helper["availability-domain"] = "other-AD",
    ]
  ) {
    const changed = structuredClone(evidence);
    change(changed);
    await refuses(() => offlinePreparationCommand(plan, changed));
  }
  assert(
    (await offlinePreparationCommand(plan, evidence)).startsWith(
      "sudo -n python3 -c '",
    ),
  );
});
Deno.test("boot volume attached as data permits OCI automatic device selection", async () => {
  const reviewed = {
    ...plan,
    offlineFilesSha256: await drillGuestFilesDigest(
      await drillGuestBundle(plan),
    ),
  };
  const automatic = structuredClone(evidence);
  automatic.bootAttachment.device = null;
  assert(
    (await offlinePreparationCommand(reviewed, automatic)).startsWith(
      "sudo -n python3 -c '",
    ),
  );
});
Deno.test("helper metadata retains Unicode in the encoded preparation payload", async () => {
  const reviewed = {
    ...plan,
    offlineFilesSha256: await drillGuestFilesDigest(
      await drillGuestBundle(plan),
    ),
  };
  const unicode = structuredClone(evidence);
  unicode.helper["defined-tags"] = { note: "恢復 helper" };
  const command = await offlinePreparationCommand(reviewed, unicode);
  const encoded = command.match(/[A-Za-z0-9+/=]{100,}/)?.[0];
  assert(encoded);
  const decoded = JSON.parse(
    new TextDecoder().decode(
      Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0)),
    ),
  );
  assert(decoded.evidence.helper["defined-tags"].note === "恢復 helper");
});
Deno.test("clone firewall requires exact controller and does not enable forwarding or metadata HTTP", async () => {
  const bundle = await drillGuestBundle(plan);
  const firewall = bundle.files["etc/arch-drill.nft"];
  assert(firewall.includes("policy drop"));
  assert(!firewall.includes("dport 80") && !firewall.includes("dport 53"));
  const outputPriority = Number(
    firewall.match(/hook output priority (-?\d+)/)?.[1],
  );
  assert(outputPriority > -200 && outputPriority < 0);
  assert(
    bundle.masks.includes(
      "etc/systemd/system/systemd-imds-early-network.service",
    ),
  );
  assert(
    bundle.masks.includes(
      "home/codex/.config/systemd/user/codex-remote-daemon.service",
    ),
  );
  await refuses(() =>
    drillGuestBundle({ ...plan, controllerIpv4: "203.0.113.10; accept" })
  );
  await refuses(() =>
    drillGuestBundle({ ...plan, controllerIpv4: "169.254.169.254" })
  );
});

Deno.test("preparation refuses changed isolation after plan approval", async () => {
  await refuses(() =>
    offlinePreparationCommand(
      { ...plan, offlineFilesSha256: "f".repeat(64) },
      evidence,
    )
  );
});

Deno.test("isolated boot permits normal user sessions without starting multi-user workloads", async () => {
  const bundle = await drillGuestBundle(plan);
  const target = bundle.files["etc/systemd/system/arch-drill.target"];
  for (const relationship of ["Requires=", "After="]) {
    const line = target.split("\n").find((line) =>
      line.startsWith(relationship)
    );
    assert(line?.includes("systemd-user-sessions.service"));
    assert(line?.includes("systemd-logind.service"));
  }
  assert(!target.includes("multi-user.target"));
  assert(
    bundle.files["etc/systemd/system/sshd.service.d/arch-drill.conf"].includes(
      "Requires=arch-drill-firewall.service",
    ),
  );
});
