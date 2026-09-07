import {
  type BackupInventoryConfig,
  readFreeResourceSurfaceEvidence,
} from "./oci-backup-inventory.ts";
import type { BackupControllerEvidence } from "./oci-backup-operations.ts";
import {
  type CommandRunner,
  dataObject,
  defaultRunner,
  type JsonRecord,
  runJson,
  stringField,
} from "./oci.ts";
import { objectStorage } from "./oci-weekly-audit.ts";
import { RetryableObservationError } from "./online-backup-contract.ts";

export const FREE_LIMITS_URL =
  "https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm";

export const SUBSCRIPTION_API_URL =
  "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/organizations/subscription/get.html";

export const CUSTOM_IMAGE_COST_URL =
  "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/managingcustomimages.htm";

export const VOLUME_PERFORMANCE_URL =
  "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumebalancedperformance.htm";

/** Refuse changed or missing published terms rather than assuming an old
 * allowance remains valid. These are the supported zero-cost limits, not the
 * larger temporary trial capacity.
 */
export function verifyPublishedFreeLimits(html: string): number {
  const text = html.replace(/<[^>]*>/g, " ").replace(/&nbsp;|&#160;/g, " ")
    .replace(/\s+/g, " ");
  for (
    const statement of [
      /first 1,500 OCPU hours and 9,000 GB hours per month for free/,
      /equivalent to 2 OCPUs and 12 GB of memory/,
      /total of 200 GB of Block Volume storage, and five volume backups/,
      /amounts apply to both boot volumes and block volumes combined/,
      /20 GB of combined Standard tier, Infrequent Access tier, and Archive tier data/,
    ]
  ) {
    if (!statement.test(text)) {
      throw new Error(
        "Official Always Free terms changed or could not be verified",
      );
    }
  }
  return 5;
}

export function verifyFreeSubscription(
  subscription: JsonRecord,
  tenancyId: string,
): void {
  if (
    subscription["compartment-id"] !== tenancyId ||
    subscription["lifecycle-state"] !== "ACTIVE" ||
    subscription["subscription-tier"] !== "FREE_AND_TRIAL" ||
    subscription["payment-model"] !== "FREE_TRIAL"
  ) {
    throw new Error(
      "Current subscription is not the verified Free Tier account; the post-trial representation is unverified",
    );
  }
  // Oracle's public Organizations API schema does not document a stable
  // post-trial Always Free enum mapping. Keep unknown representations refused
  // until a dated provider source and live account response establish one.
}

export function backupControllerEvidence(
  config: BackupInventoryConfig,
  runner: CommandRunner = defaultRunner,
  fetchDocument: () => Promise<string> = async () => {
    try {
      const response = await fetch(FREE_LIMITS_URL, {
        signal: AbortSignal.timeout(30_000),
      });
      if (
        !response.ok || new URL(response.url).hostname !== "docs.oracle.com"
      ) {
        throw new RetryableObservationError(
          "Official Always Free page is unavailable",
        );
      }
      return await response.text();
    } catch (error) {
      if (error instanceof RetryableObservationError) throw error;
      throw new RetryableObservationError(
        "Official Always Free page request failed",
      );
    }
  },
): BackupControllerEvidence {
  const call = (args: string[]) =>
    runJson(config.ociCliPath, [
      "--profile",
      config.ociProfile,
      "--region",
      config.source.region,
      "--no-retry",
      "--connection-timeout",
      "10",
      "--read-timeout",
      "60",
      ...args,
    ], runner);
  let officialProof: { checkedAt: number; limit: number } | undefined;
  const boundedObjectStorageRunner: CommandRunner = (command, args) => {
    const bounded = args.includes("--no-retry") &&
      args.includes("--connection-timeout") && args.includes("--read-timeout");
    return runner(
      command,
      bounded ? args : [
        "--no-retry",
        "--connection-timeout",
        "10",
        "--read-timeout",
        "60",
        ...args,
      ],
    );
  };
  return {
    verify: async () => {
      if (!officialProof || Date.now() - officialProof.checkedAt > 300_000) {
        let document: string;
        try {
          document = await fetchDocument();
        } catch (error) {
          if (error instanceof RetryableObservationError) throw error;
          throw new RetryableObservationError(
            "Official Always Free page request failed",
          );
        }
        officialProof = {
          checkedAt: Date.now(),
          limit: verifyPublishedFreeLimits(document),
        };
      }
      const collection = dataObject(
        await call([
          "organizations",
          "subscription",
          "list",
          "--compartment-id",
          config.tenancyId,
          "--all",
        ]),
      );
      if (!Array.isArray(collection.items) || collection.items.length !== 1) {
        throw new Error(
          "Subscription inventory changed; account reconciliation required",
        );
      }
      const summary = collection.items[0] as JsonRecord;
      const subscription = dataObject(
        await call([
          "organizations",
          "subscription",
          "get",
          "--subscription-id",
          stringField(summary, "id"),
        ]),
      );
      verifyFreeSubscription(subscription, config.tenancyId);
      const storage = await objectStorage({
        ociCliPath: config.ociCliPath,
        ociProfile: config.ociProfile,
        region: config.source.region,
        compartmentId: config.tenancyId,
        instanceId: config.source.instanceId,
        objectStorageLimitGb: 20,
      }, boundedObjectStorageRunner);
      const surfaces = await readFreeResourceSurfaceEvidence(config, runner);
      return {
        freeResourceSurface: surfaces,
        accountAndLimitsProved:
          subscription["subscription-tier"] === "FREE_AND_TRIAL" &&
          subscription["payment-model"] === "FREE_TRIAL" &&
          officialProof.limit === 5 && surfaces.freeResourceSurfaceProved,
        backupLimit: officialProof.limit,
        objectStorageComplete: storage.inventoryComplete,
        // Use the conservative decimal-GB bound, including every stored version.
        objectStorageWithinLimit: storage.inventoryComplete &&
          storage.bytes <= 20_000_000_000,
        objectStorageBytes: storage.bytes,
        objectStorageHeadroomBytes: 20_000_000_000 - storage.bytes,
      };
    },
    assertNoOtherController: async () => {
      const result = await runner("ps", ["-eo", "pid=,ppid=,comm=,args="]);
      if (result.code !== 0) {
        throw new Error("Controller process inventory failed");
      }
      const processes = result.stdout.trim().split("\n").map((line) => {
        const match = line.trim().match(/^(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/);
        if (!match) {
          throw new Error("Controller process inventory is malformed");
        }
        return {
          pid: Number(match[1]),
          parent: Number(match[2]),
          name: match[3],
          args: match[4],
        };
      });
      const ancestry = new Set<number>();
      let current = Deno.pid;
      while (current > 1 && !ancestry.has(current)) {
        ancestry.add(current);
        current = processes.find((p) => p.pid === current)?.parent ?? 0;
      }
      const otherProcesses = processes.filter((p) => !ancestry.has(p.pid));
      const writerActive = () =>
        new Error("Another backup or infrastructure writer is active");
      if (
        otherProcesses.some((p) =>
          /^oci$/.test(
            p.name.split("/").at(-1)!,
          ) ||
          /(?:^|\s|\/)oci(?:\s|$)/.test(p.args) ||
          /(?:scp|sftp|rsync).*weekly-backup-controller/.test(p.args)
        )
      ) throw writerActive();
      const namedCandidates = otherProcesses.filter((p) =>
        /(?:backup-runtime|backup-scheduled|backup-recovery|oci-restore|pi-machine-recovery|pi-recovery-session|weekly-backup|backblaze-file-backup)\.ts/
          .test(p.args)
      );
      if (namedCandidates.length === 0) return;
      const lockPath = (await Deno.realPath(".private")) +
        "/backup-controller.lock";
      const locksResult = await runner("lslocks", [
        "--json",
        "--notruncate",
        "--output",
        "PID,TYPE,MODE,PATH,BLOCKER,INODE,MAJ:MIN",
      ]);
      if (locksResult.code !== 0) throw writerActive();
      let parsed: unknown;
      try {
        parsed = JSON.parse(locksResult.stdout);
      } catch {
        throw writerActive();
      }
      const locks = (parsed as { locks?: unknown } | null)?.locks;
      if (
        !Array.isArray(locks) ||
        !locks.every((row): boolean =>
          typeof row === "object" && row !== null && !Array.isArray(row)
        )
      ) throw writerActive();
      const rows = locks as JsonRecord[];
      const lockInode = (row: JsonRecord): number | null => {
        const inode = row.inode;
        return (
            typeof inode === "number" && Number.isSafeInteger(inode) &&
            inode > 0
          )
          ? inode
          : null;
      };
      const lockDevice = (row: JsonRecord): string | null => {
        const device = row["maj:min"];
        return typeof device === "string" && /^\d+:\d+$/.test(device)
          ? device
          : null;
      };
      const holders = rows.filter((row) =>
        row.pid === Deno.pid &&
        row.type === "FLOCK" &&
        row.mode === "WRITE" &&
        row.path === lockPath &&
        row.blocker === null &&
        lockInode(row) !== null &&
        lockDevice(row) !== null
      );
      if (holders.length !== 1) throw writerActive();
      const holder = holders[0]!;
      const holderInode = lockInode(holder)!;
      const holderDevice = lockDevice(holder)!;
      for (const candidate of namedCandidates) {
        const proved = rows.filter((row) =>
          row.pid === candidate.pid &&
          row.type === "FLOCK" &&
          row.mode === "WRITE*" &&
          row.blocker === Deno.pid &&
          row.path === lockPath &&
          row.inode === holderInode &&
          row["maj:min"] === holderDevice
        ).length;
        if (proved !== 1) throw writerActive();
      }
    },
  };
}
