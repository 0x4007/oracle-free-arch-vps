import {
  backupV2ObjectName,
  type BackupV2ObjectRef,
} from "../scripts/backup-v2-contract.ts";
import {
  backupV2ProtectionPageName,
  buildBackupV2Protection,
  parseBackupV2ProtectionManifest,
  parseBackupV2ProtectionPage,
  validateBackupV2ProtectionDescriptor,
} from "../scripts/backup-v2-protection.ts";
const id = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const capture = `generation-${id(1)}`;
function object(
  n: number,
  kind: "data" | "manifest" = "data",
): BackupV2ObjectRef {
  return {
    fileId: `file-${n}`,
    fileName: backupV2ObjectName(capture, id(2), kind, n, id(n + 10)),
    contentLength: 10,
    contentSha1: "a".repeat(40),
    sha256: "b".repeat(64),
    action: "upload",
    uploadTimestamp: 1,
  };
}
const root = { object: object(0, "manifest"), plaintextSha256: "c".repeat(64) };
function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
function rejects(run: () => unknown) {
  let failed = false;
  try {
    run();
  } catch {
    failed = true;
  }
  assert(failed);
}
Deno.test("verified graph pages are deterministic, bounded and hash-bound independently of source mounts", () => {
  const refs = Array.from({ length: 300 }, (_, i) => object(i + 1)),
    bundle = buildBackupV2Protection(root, [...refs, refs[0]]);
  assert(
    bundle.descriptor.objectCount === 301 && bundle.descriptor.pageCount === 4,
  );
  const reversed = buildBackupV2Protection(root, [...refs].reverse());
  assert(
    reversed.descriptor.manifestSha256 === bundle.descriptor.manifestSha256,
  );
  const manifest = parseBackupV2ProtectionManifest(
      bundle.manifestBytes,
      bundle.descriptor,
    ),
    loaded = bundle.pages.flatMap((page, i) =>
      parseBackupV2ProtectionPage(page.bytes, manifest, i).objects
    );
  assert(
    loaded.length === 301 &&
      loaded.some((ref) => ref.fileId === root.object.fileId),
  );
  assert(backupV2ProtectionPageName(3) === "page-00000003.json");
});
Deno.test("graph corruption, missing pages, conflicting physical IDs and descriptor inflation fail closed", () => {
  const bundle = buildBackupV2Protection(root, [object(1)]);
  const broken = bundle.pages[0].bytes.slice();
  broken[broken.length - 2] ^= 1;
  rejects(() => parseBackupV2ProtectionPage(broken, bundle.manifest, 0));
  rejects(() =>
    parseBackupV2ProtectionPage(bundle.pages[0].bytes, bundle.manifest, 1)
  );
  const manifest = bundle.manifestBytes.slice();
  manifest[manifest.length - 2] ^= 1;
  rejects(() => parseBackupV2ProtectionManifest(manifest, bundle.descriptor));
  rejects(() =>
    buildBackupV2Protection(root, [object(1), {
      ...object(1),
      sha256: "e".repeat(64),
    }])
  );
  rejects(() =>
    validateBackupV2ProtectionDescriptor({
      ...bundle.descriptor,
      pageCount: 2000,
    })
  );
});
