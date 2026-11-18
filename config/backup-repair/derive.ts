import { collectBackupV2Release } from "../../scripts/backup-v2-controller.ts";
import { backupV2ArtifactSha256 } from "../../scripts/backup-v2-worker.ts";

const [revision] = Deno.args;
const read = async (path: string) => {
  if (!/^scripts\/[A-Za-z0-9_.-]+\.ts$/.test(path)) {
    throw Error("Unexpected module path");
  }
  const stagePath = "tree/" + path;
  if (!(await Deno.lstat(stagePath)).isFile) {
    throw Error("Expected a regular file");
  }
  return await Deno.readFile(stagePath);
};
const b2Entries = [
  "scripts/backblaze-file-backup.ts",
  "scripts/backup-v2-controller.ts",
  "scripts/backup-v2-worker.ts",
  "scripts/backup-v2-bridge-runtime.ts",
];
const pending = [
  ...b2Entries,
  "scripts/alerting-backup-scheduled.ts",
  "scripts/scheduled-backblaze-file-backup.ts",
  "scripts/plan-backblaze-retention.ts",
  "scripts/verify-backblaze-catalog.ts",
  "scripts/backup-watchdog.ts",
  "scripts/calendar-observations.ts",
  "scripts/pi-recovery-session.ts",
];
const hashes: Record<string, string> = {};
for (let path = pending.shift(); path !== undefined; path = pending.shift()) {
  if (hashes[path]) continue;
  const bytes = await read(path);
  hashes[path] = backupV2ArtifactSha256(bytes);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  for (
    const [, relative] of text.matchAll(
      /(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["'](\.[^"']+\.ts)["']/g,
    )
  ) {
    if (!/^\.\/[A-Za-z0-9_.-]+\.ts$/.test(relative)) {
      throw Error("Unexpected import path");
    }
    pending.push("scripts/" + relative.slice(2));
  }
}
const release = await collectBackupV2Release(revision, b2Entries, read, hashes);
for (
  const path of [
    "deno.json",
    "config/weekly-backup.service",
    "config/backblaze-file-backup.service",
    "config/weekly-backup-watchdog.service",
  ]
) {
  const stagePath = "tree/" + path;
  if (!(await Deno.lstat(stagePath)).isFile) {
    throw Error("Expected a regular file");
  }
  hashes[path] = backupV2ArtifactSha256(await Deno.readFile(stagePath));
}
const paths = Object.keys(hashes).sort();
const json = (value: unknown) => JSON.stringify(value, null, 2) + "\n";
await Deno.writeTextFile("install-paths.txt", paths.join("\n") + "\n");
await Deno.writeTextFile("install-hashes.json", json(hashes));
await Deno.writeTextFile("release.new.json", json(release.manifest));
await Deno.writeTextFile(
  "source-closure.json",
  json(Object.fromEntries(
    release.manifest.files.map(({ path, sha256 }) => [path, sha256]),
  )),
);
