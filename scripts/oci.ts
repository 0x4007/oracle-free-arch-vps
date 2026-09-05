export type JsonRecord = Record<string, unknown>;

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type CommandRunner = (
  command: string,
  args: string[],
) => Promise<CommandResult>;

export const defaultRunner: CommandRunner = async (command, args) => {
  const child = new Deno.Command(command, {
    args,
    stdout: "piped",
    stderr: "piped",
  });
  const output = await child.output();
  return {
    code: output.code,
    stdout: new TextDecoder().decode(output.stdout),
    stderr: new TextDecoder().decode(output.stderr),
  };
};

export async function runJson(
  command: string,
  args: string[],
  runner: CommandRunner = defaultRunner,
): Promise<JsonRecord> {
  const result = await runner(command, [...args, "--output", "json"]);
  if (result.code !== 0) {
    const message = redactOcid(result.stderr.trim() || result.stdout.trim());
    throw new Error(`OCI command failed (${result.code}): ${message}`);
  }
  if (result.stdout.trim() === "") return { data: [] };
  return JSON.parse(result.stdout) as JsonRecord;
}

export function redactOcid(value: string): string {
  return value.replaceAll(/ocid1\.[a-z0-9.-]+/gi, "<REDACTED_OCID>");
}

export function dataArray(value: JsonRecord): JsonRecord[] {
  const data = value.data;
  if (!Array.isArray(data)) {
    throw new Error("OCI response data is not an array");
  }
  return data as JsonRecord[];
}

export function dataObject(value: JsonRecord): JsonRecord {
  const data = value.data;
  if (!data || Array.isArray(data) || typeof data !== "object") {
    throw new Error("OCI response data is not an object");
  }
  return data as JsonRecord;
}

export function dataString(value: JsonRecord): string {
  if (typeof value.data !== "string") {
    throw new Error("OCI response data is not a string");
  }
  return value.data;
}

export function stringField(value: JsonRecord, name: string): string {
  const field = value[name];
  if (typeof field !== "string") {
    throw new Error(`Missing string field: ${name}`);
  }
  return field;
}

export function numberField(value: JsonRecord, name: string): number {
  const field = value[name];
  if (typeof field !== "number") {
    throw new Error(`Missing number field: ${name}`);
  }
  return field;
}

export async function writePrivateJson(
  path: string,
  value: unknown,
): Promise<void> {
  const slash = path.lastIndexOf("/");
  const directory = slash > 0 ? path.slice(0, slash) : ".";
  if (slash > 0) await Deno.mkdir(directory, { recursive: true });
  const temporaryPath = `${directory}/.${
    path.slice(slash + 1)
  }.${crypto.randomUUID()}.tmp`;
  try {
    const file = await Deno.open(temporaryPath, {
      write: true,
      createNew: true,
      mode: 0o600,
    });
    try {
      const bytes = new TextEncoder().encode(
        `${JSON.stringify(value, null, 2)}\n`,
      );
      let offset = 0;
      while (offset < bytes.length) {
        offset += await file.write(bytes.subarray(offset));
      }
      await file.sync();
    } finally {
      file.close();
    }
    await Deno.chmod(temporaryPath, 0o600);
    await Deno.rename(temporaryPath, path);
    using parent = await Deno.open(directory, { read: true });
    await parent.sync();
  } catch (error) {
    try {
      await Deno.remove(temporaryPath);
    } catch (cleanupError) {
      if (!(cleanupError instanceof Deno.errors.NotFound)) throw cleanupError;
    }
    throw error;
  }
}

export async function readPrivateJson<T>(path: string): Promise<T> {
  const info = await Deno.stat(path);
  if (info.mode !== null && (info.mode & 0o077) !== 0) {
    throw new Error(`${path} must not grant group or other permissions`);
  }
  return JSON.parse(await Deno.readTextFile(path)) as T;
}
