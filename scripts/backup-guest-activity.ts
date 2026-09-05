/** Read-only activity probe for the existing VPS control socket. This is an
 * observation, not an admission lock: callers must not infer that new work
 * cannot begin after it returns. No thread is resumed, interrupted or stopped.
 */
export async function readGuestActivity(): Promise<{ loadedThreads: number }> {
  const socketPath =
    "/home/codex/.codex/app-server-control/app-server-control.sock";
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  let tcp: Deno.Conn | undefined;
  let unix: Deno.Conn | undefined;
  const bridge = (async () => {
    tcp = await listener.accept();
    listener.close();
    unix = await Deno.connect({ transport: "unix", path: socketPath });
    await Promise.allSettled([
      tcp.readable.pipeTo(unix.writable),
      unix.readable.pipeTo(tcp.writable),
    ]);
  })();
  const ws = new WebSocket(`ws://127.0.0.1:${listener.addr.port}`);
  const pending = new Map<number, {
    resolve(value: unknown): void;
    reject(error: Error): void;
  }>();
  let nextId = 0;
  let rejectOpen: (error: Error) => void = () => {};
  const fail = (error: Error) => {
    rejectOpen(error);
    for (const request of pending.values()) request.reject(error);
    pending.clear();
  };
  const timer = setTimeout(
    () => fail(new Error("Activity probe timed out")),
    15_000,
  );
  const rpc = (method: string, params: unknown): Promise<unknown> =>
    new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });
  ws.onmessage = (event) => {
    try {
      const response = JSON.parse(event.data);
      const request = pending.get(response.id);
      if (!request) return;
      pending.delete(response.id);
      if (response.error) request.reject(new Error("Activity RPC refused"));
      else request.resolve(response.result);
    } catch {
      fail(new Error("Malformed activity response"));
    }
  };
  ws.onerror = () => fail(new Error("Activity transport failed"));
  ws.onclose = () => fail(new Error("Activity transport closed"));
  const bridgeResult = bridge.catch(() =>
    fail(new Error("Control socket unavailable"))
  );
  try {
    await new Promise<void>((resolve, reject) => {
      rejectOpen = reject;
      ws.onopen = () => resolve();
    });
    await rpc("initialize", {
      clientInfo: { name: "weekly_backup_preflight", version: "0.1.0" },
    });
    ws.send(JSON.stringify({ method: "initialized", params: {} }));
    const result = await rpc("thread/loaded/list", {}) as Record<
      string,
      unknown
    >;
    if (
      !result || !Array.isArray(result.data) ||
      !result.data.every((id) => typeof id === "string") ||
      result.nextCursor != null
    ) throw new Error("Loaded-thread inventory is incomplete");
    return { loadedThreads: result.data.length };
  } finally {
    clearTimeout(timer);
    ws.close();
    for (const connection of [tcp, unix]) {
      try {
        connection?.close();
      } catch { /* already closed by pipe */ }
    }
    try {
      listener.close();
    } catch { /* closed after accept */ }
    await bridgeResult;
  }
}

if (import.meta.main) {
  console.log(JSON.stringify(await readGuestActivity()));
}
