import assert, {
  deepEqual as assertEquals,
  throws as assertThrows,
} from "node:assert/strict";
import {
  consumeNativeTarListing,
  createTarInventory,
  createTarTerminationGuard,
  decodeTarCString,
  normalizeTarPath,
  parseNativeTarLine,
  resolveTarSample,
  tarPathKey,
} from "../scripts/backup-tar-consumers.ts";

const text = new TextEncoder();
const line = (name: string, type = "-", tail = "") =>
  `${type}rw-r--r-- 0/0 3 2026-01-01 00:00:00 ${name}${tail}`;
export function tarHeader(size: number, type = "0") {
  const bytes = new Uint8Array(512);
  bytes.set(text.encode("./file"));
  bytes.set(text.encode(size.toString(8).padStart(11, "0") + "\0"), 124);
  bytes[156] = type.charCodeAt(0);
  return bytes;
}
export function joinBytes(...parts: Uint8Array[]) {
  const bytes = new Uint8Array(
    parts.reduce((sum, part) => sum + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
}

Deno.test("tar C protocol preserves newline, backslash and non-UTF8 bytes", () => {
  assertEquals(
    decodeTarCString('"a\\n\\t\\\\\\"\\377"').bytes,
    Uint8Array.of(97, 10, 9, 92, 34, 255),
  );
  assertThrows(() => decodeTarCString('"bad\\q"'));
  assertThrows(() => decodeTarCString('"unfinished'));
  const member = parseNativeTarLine(line('"./a\\n\\377"'));
  assertEquals(member.path, Uint8Array.of(46, 47, 97, 10, 255));
  assertThrows(() => parseNativeTarLine(line('"./a"') + " garbage"));
});

Deno.test("tar native inventory hashes complete framed records and counts aliases", async () => {
  const inventory = createTarInventory([text.encode("./a")]);
  const bytes = text.encode(line('"./a"') + "\n" + line('"a"') + "\n");
  await consumeNativeTarListing(
    new ReadableStream({
      start(c) {
        c.enqueue(bytes.subarray(0, 9));
        c.enqueue(bytes.subarray(9));
        c.close();
      },
    }),
    inventory.add,
  );
  const result = inventory.finish();
  assertEquals(result.inventory.members, 2);
  assertEquals(result.observed.get(tarPathKey(text.encode("a")))?.count, 2);
  assertEquals(result.inventory.sha256.length, 64);
});

Deno.test("tar links resolve bytes and reject cycles and escapes", () => {
  const inventory = createTarInventory([]);
  inventory.add(
    parseNativeTarLine(line('"./boot/Image"', "l", ' -> "../kernel\\377"')),
  );
  inventory.add(
    parseNativeTarLine(
      line('"./kernel\\377"', "h", ' link to "./content\\377"'),
    ),
  );
  const result = inventory.finish();
  assertEquals(
    resolveTarSample(text.encode("./boot/Image"), result.links).content,
    Uint8Array.of(...text.encode("content"), 255),
  );
  assertThrows(() =>
    normalizeTarPath(text.encode("../../escape"), text.encode("boot"))
  );
  const cycle = createTarInventory([]);
  cycle.add(parseNativeTarLine(line('"./a"', "l", ' -> "b"')));
  cycle.add(parseNativeTarLine(line('"./b"', "l", ' -> "a"')));
  assertThrows(() => resolveTarSample(text.encode("a"), cycle.finish().links));
});

Deno.test("inventory summaries bind paths independently of native display metadata", () => {
  const original = parseNativeTarLine(line('"./same\\377"'));
  const display = parseNativeTarLine(
    line('"./same\\377"').replace("-rw-r--r--", "-rw-r--r--*").replace(
      "0/0",
      "1002/1002",
    ),
  );
  const first = createTarInventory([original.path]);
  const second = createTarInventory([display.path]);
  first.add(original);
  second.add(display);
  const left = first.finish(), right = second.finish();
  assertEquals(left.inventory, right.inventory);
  assertEquals(
    left.observed.get(tarPathKey(original.path))?.member.metadata,
    original.metadata,
  );
  assertEquals(
    right.observed.get(tarPathKey(display.path))?.member.metadata,
    display.metadata,
  );
  assert(
    original.metadata.some((byte, index) => byte !== display.metadata[index]),
  );
});

Deno.test("tar framing requires two terminators and rejects hidden second archive", () => {
  const valid = joinBytes(
    tarHeader(3),
    Uint8Array.of(1, 2, 3),
    new Uint8Array(509 + 1024),
  );
  const guard = createTarTerminationGuard();
  for (let index = 0; index < valid.length; index += 37) {
    guard.write(valid.subarray(index, index + 37));
  }
  assertEquals(guard.finish(), {
    bytes: 2048,
    members: 1,
    zeroTerminated: true,
  });
  for (
    const bad of [
      valid.subarray(0, valid.length - 512),
      valid.subarray(0, 513),
      joinBytes(valid, tarHeader(0)),
    ]
  ) {
    const rejected = createTarTerminationGuard();
    assertThrows(() => {
      rejected.write(bad);
      rejected.finish();
    });
  }
});

Deno.test("tar framing admits bounded pax size and sparse physical payload", () => {
  const pax = text.encode("10 size=3\n");
  const bytes = joinBytes(
    tarHeader(pax.length, "x"),
    pax,
    new Uint8Array(512 - pax.length),
    tarHeader(0),
    Uint8Array.of(1, 2, 3),
    new Uint8Array(509 + 1024),
  );
  const guard = createTarTerminationGuard();
  guard.write(bytes);
  assertEquals(guard.finish().members, 1);
  const sparse = createTarTerminationGuard();
  assertThrows(() => sparse.write(tarHeader(0, "S")));
  const bad = createTarTerminationGuard();
  assertThrows(() => {
    bad.write(
      joinBytes(
        tarHeader(5, "x"),
        text.encode("99 x\n"),
        new Uint8Array(507 + 1024),
      ),
    );
    bad.finish();
  });
  assert(guard.terminated());
});
