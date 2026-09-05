/** Keep this inode for the controller's lifetime. Removing a lock pathname
 * permits a second process to lock a different inode at the same path.
 * The kernel releases the lock when the controller exits, including crashes.
 */
export async function withBackupLock<T>(
  path: string,
  work: () => Promise<T>,
): Promise<T> {
  using lock = await Deno.open(path, {
    create: true,
    read: true,
    write: true,
    mode: 0o600,
  });
  await lock.lock(true);
  try {
    return await work();
  } finally {
    await lock.unlock();
  }
}
