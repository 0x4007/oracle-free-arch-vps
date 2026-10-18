import { Buffer } from "node:buffer";
import { createBackupV2InventorySummary } from "./backup-v2-inventory.ts";
import { assertBackupV2Budget } from "./backup-v2-profile.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
function failure(detail: string): never {
  throw new Error(`Stream tar rejected: ${detail}`);
}

export interface NativeTarMember {
  path: Uint8Array;
  type: string;
  size: number;
  target?: Uint8Array;
  metadata: Uint8Array;
}

/** LC_ALL=C and GNU --quoting-style=c are mandatory at the native boundary. */
export function decodeTarCString(text: string, start = 0) {
  if (text[start] !== '"') failure("unquoted native name");
  const bytes: number[] = [];
  let index = start + 1;
  const escapes: Record<string, number> = {
    a: 7,
    b: 8,
    f: 12,
    n: 10,
    r: 13,
    t: 9,
    v: 11,
    "\\": 92,
    '"': 34,
  };
  for (; index < text.length; index++) {
    const char = text[index];
    if (char === '"') return { bytes: Uint8Array.from(bytes), end: index + 1 };
    if (char === "\\") {
      const next = text[++index];
      if (next in escapes) bytes.push(escapes[next]);
      else if (/[0-7]/.test(next ?? "")) {
        let octal = next;
        for (
          let count = 1;
          count < 3 && /[0-7]/.test(text[index + 1] ?? "");
          count++
        ) {
          octal += text[++index];
        }
        const value = Number.parseInt(octal, 8);
        if (value > 255) failure("native octal overflow");
        bytes.push(value);
      } else failure("unknown native name escape");
    } else {
      const value = char.charCodeAt(0);
      if (value < 32 || value > 126) failure("unescaped native name byte");
      bytes.push(value);
    }
  }
  return failure("unterminated native name");
}

export function parseNativeTarLine(line: string): NativeTarMember {
  const quote = line.indexOf('"');
  if (quote < 0) failure("native listing grammar");
  const prefix = line.slice(0, quote);
  const fields =
    /^([^\s]{10,12})\s+(\d+\/\d+)\s+((?:\d+,\s*)?\d+)\s+\d{4}-\d\d-\d\d\s+[0-9:.+-]+\s+$/
      .exec(prefix);
  if (!fields) failure("native listing metadata");
  const name = decodeTarCString(line, quote);
  let target: Uint8Array | undefined;
  const suffix = line.slice(name.end);
  const type = fields[1][0];
  const marker = type === "l" ? " -> " : type === "h" ? " link to " : "";
  if (marker) {
    if (!suffix.startsWith(marker)) failure("native link grammar");
    const link = decodeTarCString(suffix, marker.length);
    if (link.end !== suffix.length || link.bytes.includes(0)) {
      failure("native link tail");
    }
    target = link.bytes;
  } else if (suffix !== "") failure("native listing tail");
  if (!"-dlhcbp".includes(type)) failure("unsupported native member type");
  const size = fields[3].includes(",") ? 0 : Number(fields[3]);
  assertBackupV2Budget("logicalSourceBytes", size);
  return {
    path: name.bytes,
    type,
    size,
    target,
    metadata: encoder.encode(
      prefix.trim().replace(/\s+/g, " ") + "\0" +
        (target ? Buffer.from(target).toString("hex") : ""),
    ),
  };
}

/** Normalise bytes, never Unicode; symlink targets may walk within their root. */
export function normalizeTarPath(
  path: Uint8Array,
  parent?: Uint8Array,
): Uint8Array {
  if (path.includes(0)) failure("NUL path");
  const components: Uint8Array[] = [];
  const add = (value: Uint8Array, targets: boolean) => {
    let start = 0;
    for (let index = 0; index <= value.length; index++) {
      if (index !== value.length && value[index] !== 47) continue;
      const part = value.subarray(start, index);
      start = index + 1;
      if (!part.length || (part.length === 1 && part[0] === 46)) continue;
      if (part.length === 2 && part[0] === 46 && part[1] === 46) {
        if (!targets || !components.length) {
          failure("path escapes archive root");
        }
        components.pop();
      } else components.push(part.slice());
    }
  };
  if (path[0] === 47 && parent === undefined) failure("absolute member path");
  if (parent && path[0] !== 47) add(parent, false);
  add(path, parent !== undefined);
  return Uint8Array.from(
    components.flatMap((part, index) => index ? [47, ...part] : [...part]),
  );
}

export const tarPathKey = (path: Uint8Array): string =>
  Buffer.from(normalizeTarPath(path)).toString("hex");

export interface TarObservation {
  count: number;
  member: NativeTarMember;
}

/** Only link metadata and the explicitly selected names are retained. */
export function createTarInventory(
  selected: readonly Uint8Array[],
  retainLinks = true,
) {
  const summary = createBackupV2InventorySummary();
  const selectedKeys = new Set(selected.map(tarPathKey));
  const observed = new Map<string, TarObservation>();
  const links = new Map<string, NativeTarMember>();
  let linkBytes = 0;
  return {
    add(member: NativeTarMember) {
      summary.add({ path: member.path, metadata: member.metadata });
      const key = tarPathKey(member.path);
      if (selectedKeys.has(key)) {
        observed.set(key, {
          count: (observed.get(key)?.count ?? 0) + 1,
          member,
        });
      }
      if (retainLinks && member.target) {
        if (links.has(key)) failure("duplicate link name");
        assertBackupV2Budget("hardlinkedNames", links.size + 1);
        linkBytes = assertBackupV2Budget(
          "pathBytes",
          linkBytes + member.path.length + member.target.length,
        );
        links.set(key, member);
      }
    },
    finish() {
      const inventory = summary.finish();
      if (!inventory.members) failure("empty archive");
      return { inventory, observed, links };
    },
  };
}

export function resolveTarSample(
  path: Uint8Array,
  links: ReadonlyMap<string, NativeTarMember>,
) {
  let current = normalizeTarPath(path);
  const chain: Uint8Array[] = [];
  const seen = new Set<string>();
  while (true) {
    const key = tarPathKey(current);
    if (seen.has(key)) failure("sample link cycle");
    seen.add(key);
    chain.push(current);
    assertBackupV2Budget("depth", chain.length);
    const link = links.get(key);
    if (!link) return { content: current, chain };
    const slash = current.lastIndexOf(47);
    const parent = slash < 0 ? new Uint8Array() : current.subarray(0, slash);
    current = link.type === "l"
      ? normalizeTarPath(link.target!, parent)
      : normalizeTarPath(link.target!);
  }
}

export async function consumeNativeTarListing(
  stream: ReadableStream<Uint8Array>,
  add: (member: NativeTarMember) => void,
) {
  let pending = new Uint8Array();
  for await (const bytes of stream) {
    if (bytes.some((byte) => byte > 127)) failure("non-ASCII native protocol");
    const combined = new Uint8Array(pending.length + bytes.length);
    combined.set(pending);
    combined.set(bytes, pending.length);
    let start = 0;
    for (let index = 0; index < combined.length; index++) {
      if (combined[index] !== 10) continue;
      assertBackupV2Budget("metadataRecordBytes", index - start);
      add(parseNativeTarLine(decoder.decode(combined.subarray(start, index))));
      start = index + 1;
    }
    pending = combined.slice(start);
    assertBackupV2Budget("metadataRecordBytes", pending.length);
  }
  if (pending.length) failure("unterminated native listing record");
}

function tarNumber(bytes: Uint8Array): number {
  if (bytes[0] & 128) {
    if (bytes[0] & 64) failure("negative tar size");
    let value = BigInt(bytes[0] & 127);
    for (const byte of bytes.subarray(1)) value = value * 256n + BigInt(byte);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) failure("tar size overflow");
    return Number(value);
  }
  const value = decoder.decode(bytes).replace(/\0.*$/, "").trim();
  if (!/^[0-7]+$/.test(value)) failure("invalid tar size");
  const result = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(result)) failure("tar size overflow");
  return result;
}

function paxSize(bytes: Uint8Array): { present: boolean; size?: number } {
  let offset = 0, present = false, size: number | undefined;
  while (offset < bytes.length) {
    const space = bytes.indexOf(32, offset);
    if (space < 0 || space - offset > 10) failure("pax record length");
    const text = decoder.decode(bytes.subarray(offset, space));
    if (!/^[1-9]\d*$/.test(text)) failure("pax record length");
    const end = offset + Number(text);
    if (end <= space + 1 || end > bytes.length || bytes[end - 1] !== 10) {
      failure("pax record boundary");
    }
    const item = bytes.subarray(space + 1, end - 1);
    if (
      item.length >= 5 &&
      item.subarray(0, 5).every((byte, i) => byte === "size=".charCodeAt(i))
    ) {
      const value = decoder.decode(item.subarray(5));
      if (value && !/^\d+$/.test(value)) failure("pax size");
      present = true;
      size = value === ""
        ? undefined
        : assertBackupV2Budget("logicalSourceBytes", Number(value));
    }
    offset = end;
  }
  return { present, size };
}

/** Narrow physical framing guard, not a filename, extraction or sparse parser.
 * GNU tar remains authoritative. Only GNU pax/ustar physical framing is admitted. */
export function createTarTerminationGuard() {
  const header = new Uint8Array(512);
  let used = 0, remaining = 0, padding = 0, zeros = 0, total = 0, members = 0;
  let metadata: Uint8Array | undefined, metadataUsed = 0, global = false;
  let localSize: number | undefined, globalSize: number | undefined;
  const finishMetadata = () => {
    if (!metadata) return;
    const value = paxSize(metadata);
    if (value.present) {
      if (global) globalSize = value.size;
      else localSize = value.size;
    }
    metadata = undefined;
  };
  return {
    write(bytes: Uint8Array) {
      total = assertBackupV2Budget("logicalSourceBytes", total + bytes.length);
      let index = 0;
      while (index < bytes.length) {
        if (zeros >= 2) {
          if (bytes.subarray(index).some((byte) => byte !== 0)) {
            failure("nonzero data after tar terminator");
          }
          break;
        }
        if (remaining) {
          const take = Math.min(remaining, bytes.length - index);
          if (metadata) {
            metadata.set(bytes.subarray(index, index + take), metadataUsed);
            metadataUsed += take;
          }
          index += take;
          remaining -= take;
          if (!remaining) finishMetadata();
          continue;
        }
        if (padding) {
          const take = Math.min(padding, bytes.length - index);
          index += take;
          padding -= take;
          continue;
        }
        const take = Math.min(512 - used, bytes.length - index);
        header.set(bytes.subarray(index, index + take), used);
        used += take;
        index += take;
        if (used !== 512) continue;
        used = 0;
        if (header.every((byte) => byte === 0)) {
          zeros++;
          continue;
        }
        if (zeros) failure("single zero block within archive");
        const type = String.fromCharCode(header[156]);
        if (type === "S") failure("old GNU sparse framing is not admitted");
        let size = tarNumber(header.subarray(124, 136));
        if (type === "x" || type === "g") {
          assertBackupV2Budget("metadataRecordBytes", size);
          metadata = new Uint8Array(size);
          metadataUsed = 0;
          global = type === "g";
        } else if (type !== "L" && type !== "K") {
          members = assertBackupV2Budget("members", members + 1);
          if (type === "0" || type === "\0" || type === "7") {
            size = localSize ?? globalSize ?? size;
          }
          localSize = undefined;
        }
        remaining = assertBackupV2Budget("logicalSourceBytes", size);
        padding = (512 - size % 512) % 512;
        if (!remaining) finishMetadata();
      }
    },
    finish() {
      if (remaining || padding || used || zeros < 2 || total % 512) {
        failure("incomplete tar termination");
      }
      return { bytes: total, members, zeroTerminated: true as const };
    },
    terminated: () => zeros >= 2,
  };
}
