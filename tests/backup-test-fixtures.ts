import { fileURLToPath } from "node:url";

const fixtureRoot = new URL("./.backup-test-fixtures/", import.meta.url);

export const canUseBackupTestFixtures =
  (await Deno.permissions.query({ name: "read", path: fixtureRoot })).state ===
    "granted" &&
  (await Deno.permissions.query({ name: "write", path: fixtureRoot })).state ===
    "granted";

export async function withBackupTestFixture(
  prefix: string,
  test: (directory: string) => Promise<void>,
): Promise<void> {
  const directory = new URL(`${prefix}-${crypto.randomUUID()}`, fixtureRoot);
  await Deno.mkdir(directory, { recursive: true, mode: 0o700 });
  try {
    await test(fileURLToPath(directory));
  } finally {
    await Deno.remove(directory, { recursive: true });
  }
}
