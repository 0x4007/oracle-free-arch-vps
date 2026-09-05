import {
  assertLiveMountTargets,
  type CaptureSettings,
  exclusionPaths,
  type FileSource,
  fsRelativeExclusions,
  inventoryAwk,
  inventoryPipeline,
  isPublicKeyArmorForm,
  type LsblkNode,
  pipelineStatusLines,
  sha256File,
  swapfileRecreation,
  swapfileStatLines,
  validateCaptureSettings,
  validateGeneration,
  validateSources,
  validateSourceShapes,
} from "../scripts/backblaze-capture.ts";

function assert(value: unknown, message?: string): asserts value {
  if (!value) throw new Error(message ?? "Assertion failed");
}
function assertThrows(run: () => unknown): void {
  let rejected = false;
  try {
    run();
  } catch {
    rejected = true;
  }
  assert(rejected);
}
async function assertThrowsAsync(run: () => Promise<unknown>): Promise<void> {
  let rejected = false;
  try {
    await run();
  } catch {
    rejected = true;
  }
  assert(rejected);
}

async function runBash(script: string, options?: {
  cwd?: string;
  env?: Record<string, string>;
}): Promise<{ code: number; stdout: string; stderr: string }> {
  const child = new Deno.Command("bash", {
    args: ["-c", script],
    cwd: options?.cwd,
    env: options?.env,
    stdout: "piped",
    stderr: "piped",
  });
  const output = await child.output();
  return {
    code: output.code,
    stdout: new TextDecoder().decode(output.stdout),
    stderr: new TextDecoder().decode(output.stderr),
  };
}

/** Query-only permission probe for the synthetic runtime checks; it never
 * requests a grant. Deno's default `deno test` task carries no permissions,
 * so these tests must skip there and only execute under the explicit
 * --allow-read/--allow-write/--allow-run invocation. */
async function runtimePermissionsGranted(): Promise<boolean> {
  const descriptors: Deno.PermissionDescriptor[] = [
    { name: "run", command: "bash" },
    { name: "read" },
    { name: "write" },
  ];
  for (const descriptor of descriptors) {
    try {
      if ((await Deno.permissions.query(descriptor)).state !== "granted") {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

const runtimePermitted = await runtimePermissionsGranted();

/** Runtime check registration: names carry a "runtime:" prefix so skipped
 * cases are unmistakably identified as runtime checks in every report. */
function runtimeTest(
  name: string,
  fn: (context: Deno.TestContext) => void | Promise<void>,
): void {
  Deno.test({ name: `runtime: ${name}`, ignore: !runtimePermitted, fn });
}

const ROOT_UUID = "aaaaaaaa-1111-1111-1111-111111111111";
const EFI_UUID = "AAAA-1111";
const STAGING_BOOT_UUID = "bbbbbbbb-2222-2222-2222-222222222222";
const STAGING_EFI_UUID = "BBBB-2222";
const ORACLE_ROOT_UUID = "cccccccc-3333-3333-3333-333333333333";
const ORACLE_OLED_UUID = "dddddddd-4444-4444-4444-444444444444";

const ROOT_SIZE = 161_061_273_600;
const EFI_SIZE = 536_870_912;
const STAGING_BOOT_SIZE = 1_073_741_824;
const STAGING_EFI_SIZE = 268_435_456;
const ORACLE_ROOT_SIZE = 16_106_127_360;
const ORACLE_OLED_SIZE = 1_073_741_824;

function device(
  name: string,
  path: string,
  size: number,
  type: string,
  fstype: string | null,
  uuid: string | null,
  mountpoints: (string | null)[] | null,
  children?: LsblkNode[],
): LsblkNode {
  return { name, path, size, type, fstype, uuid, mountpoints, children };
}

function blockDevices(overrides: {
  rootMounts?: (string | null)[] | null;
  efiMounts?: (string | null)[] | null;
  stagingBootMounts?: (string | null)[] | null;
  extra?: LsblkNode[];
} = {}): LsblkNode[] {
  return [
    device("sda", "/dev/sda", 53_687_091_200, "disk", null, null, null, [
      device(
        "sda1",
        "/dev/sda1",
        EFI_SIZE,
        "part",
        "vfat",
        EFI_UUID,
        overrides.efiMounts ?? ["/efi"],
      ),
      device(
        "sda2",
        "/dev/sda2",
        STAGING_BOOT_SIZE,
        "part",
        "xfs",
        STAGING_BOOT_UUID,
        overrides.stagingBootMounts ?? [null],
      ),
      device(
        "sda3",
        "/dev/sda3",
        34_359_738_368,
        "part",
        "LVM2_member",
        "lvm-pv-1",
        null,
        [
          device(
            "ocivolume-root",
            "/dev/mapper/ocivolume-root",
            ORACLE_ROOT_SIZE,
            "lvm",
            "xfs",
            ORACLE_ROOT_UUID,
            [null],
          ),
          device(
            "ocivolume-oled",
            "/dev/mapper/ocivolume-oled",
            ORACLE_OLED_SIZE,
            "lvm",
            "xfs",
            ORACLE_OLED_UUID,
            [null],
          ),
        ],
      ),
    ]),
    device("sdb", "/dev/sdb", ROOT_SIZE, "disk", null, null, null, [
      device(
        "sdb1",
        "/dev/sdb1",
        ROOT_SIZE,
        "part",
        "ext4",
        ROOT_UUID,
        overrides.rootMounts ?? ["/"],
      ),
      device(
        "sdb2",
        "/dev/sdb2",
        STAGING_EFI_SIZE,
        "part",
        "vfat",
        STAGING_EFI_UUID,
        [null],
      ),
    ]),
    ...(overrides.extra ?? []),
  ];
}

function sources(): FileSource[] {
  return [
    {
      name: "root",
      uuid: ROOT_UUID,
      filesystem: "ext4",
      size: ROOT_SIZE,
      livePath: "/",
    },
    {
      name: "efi",
      uuid: EFI_UUID,
      filesystem: "vfat",
      size: EFI_SIZE,
      livePath: "/efi",
    },
    {
      name: "staging-boot",
      uuid: STAGING_BOOT_UUID,
      filesystem: "xfs",
      size: STAGING_BOOT_SIZE,
    },
    {
      name: "staging-efi",
      uuid: STAGING_EFI_UUID,
      filesystem: "vfat",
      size: STAGING_EFI_SIZE,
    },
    {
      name: "oracle-root",
      uuid: ORACLE_ROOT_UUID,
      filesystem: "xfs",
      size: ORACLE_ROOT_SIZE,
    },
    {
      name: "oracle-oled",
      uuid: ORACLE_OLED_UUID,
      filesystem: "xfs",
      size: ORACLE_OLED_SIZE,
    },
  ];
}

const EXCLUSION_TEXT = [
  "/home/codex/repos",
  "/home/codex/.codex/packages",
  "/home/codex/.cache",
  "/home/codex/.npm/_cacache",
  "/home/codex/.npm/_logs",
  "/home/codex/.codex/cache",
  "/home/codex/.codex/.tmp",
  "/home/codex/.codex/tmp",
  "/var/cache/pacman/pkg",
  "/var/log",
  "/tmp",
  "/var/tmp",
  "/run",
  "/proc",
  "/sys",
  "/dev",
  "/.swapfile",
].join("\n");

function validSettings(): CaptureSettings {
  return {
    sources: sources(),
    generation: "generation-5d2b15ce-9f1a-4c3e-8a7b-0e1f2a3b4c5d",
    recipientFile: "/var/tmp/backup-recipient.asc",
    recipientSha256: "a".repeat(64),
    recipientFingerprint: "E".repeat(40),
    exclusionsText: EXCLUSION_TEXT,
  };
}

Deno.test("exact six-role layout matches the required schema", () => {
  validateSourceShapes(sources());
  validateSources(sources(), blockDevices());
  assertLiveMountTargets(blockDevices());
});

Deno.test("coverage rejects a missing and an extra role", () => {
  assertThrows(() => validateSourceShapes(sources().slice(1)));
  assertThrows(() =>
    validateSourceShapes([
      ...sources(),
      { name: "extra-role", uuid: "eeee-9999", filesystem: "xfs", size: 1 },
    ])
  );
  assertThrows(() => validateSourceShapes([...sources(), sources()[5]]));
  assertThrows(() => validateSources(sources().slice(1), blockDevices()));
});

Deno.test("coverage rejects resized, retyped and duplicated sources", () => {
  const resized = sources();
  resized[0] = { ...resized[0], size: ROOT_SIZE + 4096 };
  assertThrows(() => validateSources(resized, blockDevices()));

  const retyped = sources();
  retyped[2] = { ...retyped[2], filesystem: "ext4" };
  assertThrows(() => validateSourceShapes(retyped));

  const deviceRetyped = sources();
  const swapped = blockDevices();
  (swapped[0].children![1] as LsblkNode).fstype = "ext4";
  assertThrows(() => validateSources(deviceRetyped, swapped));

  const duplicated = sources();
  duplicated[5] = { ...duplicated[5], uuid: ORACLE_ROOT_UUID };
  assertThrows(() => validateSourceShapes(duplicated));
});

Deno.test("live bindings must match each role exactly", () => {
  const noLive = sources();
  noLive[0] = { ...noLive[0], livePath: undefined };
  assertThrows(() => validateSourceShapes(noLive));

  const wrongLive = sources();
  wrongLive[0] = { ...wrongLive[0], livePath: "/efi" };
  assertThrows(() => validateSourceShapes(wrongLive));

  const efiNotLive = sources();
  efiNotLive[1] = { ...efiNotLive[1], livePath: undefined };
  assertThrows(() => validateSourceShapes(efiNotLive));

  const coldIsLive = sources();
  coldIsLive[5] = { ...coldIsLive[5], livePath: "/" };
  assertThrows(() => validateSourceShapes(coldIsLive));
});

Deno.test("UUIDs are hex/dash syntax and sizes are exact positive integers", () => {
  const notHex = sources();
  notHex[0] = { ...notHex[0], uuid: "zzzz-1111" };
  assertThrows(() => validateSourceShapes(notHex));

  const onlyDashes = sources();
  onlyDashes[0] = { ...onlyDashes[0], uuid: "----" };
  assertThrows(() => validateSourceShapes(onlyDashes));

  const zeroSize = sources();
  zeroSize[0] = { ...zeroSize[0], size: 0 };
  assertThrows(() => validateSourceShapes(zeroSize));

  const fractionalSize = sources();
  fractionalSize[0] = { ...fractionalSize[0], size: 1.5 };
  assertThrows(() => validateSourceShapes(fractionalSize));
});

Deno.test("extra persistent filesystems and foreign mounts are rejected", () => {
  const extra = device(
    "sdc1",
    "/dev/sdc1",
    1_048_576,
    "part",
    "ext4",
    "eeee-9999",
    null,
  );
  assertThrows(() =>
    validateSources(sources(), blockDevices({ extra: [extra] }))
  );
  assertThrows(() =>
    assertLiveMountTargets(blockDevices({ efiMounts: ["/efi", "/boot"] }))
  );
  assertThrows(() =>
    assertLiveMountTargets(
      blockDevices({ stagingBootMounts: ["/mnt/staging"] }),
    )
  );
  assertThrows(() =>
    assertLiveMountTargets(blockDevices({ rootMounts: ["/", "/srv"] }))
  );
});

Deno.test("LVM2_member and swap containers are ignored by coverage", () => {
  const swap = device(
    "sdz1",
    "/dev/sdz1",
    4_294_967_296,
    "part",
    "swap",
    "swap-uuid-1234",
    null,
  );
  validateSources(sources(), blockDevices({ extra: [swap] }));
});

Deno.test("exclusions convert to literal anchored filesystem-relative paths", () => {
  const parsed = exclusionPaths(EXCLUSION_TEXT);
  const relative = fsRelativeExclusions(parsed);
  for (
    const expected of [
      "./home/codex/repos",
      "./.swapfile",
      "./tmp",
      "./var/tmp",
      "./run",
      "./proc",
      "./sys",
      "./dev",
      "./var/log",
      "./var/cache/pacman/pkg",
      "./home/codex/.npm/_cacache",
      "./home/codex/.codex/packages",
    ]
  ) {
    assert(relative.includes(expected));
  }
  assert(new Set(relative).size === relative.length);
});

Deno.test("exclusions reject globs, dotdot and critical broad roots", () => {
  assertThrows(() =>
    exclusionPaths(EXCLUSION_TEXT.replace("/.swapfile", "/.swapfile*"))
  );
  assertThrows(() => exclusionPaths(EXCLUSION_TEXT.replace("/tmp", "/tmp/*")));
  assertThrows(() =>
    exclusionPaths(EXCLUSION_TEXT.replace("/tmp", "/tmp/../etc"))
  );
  assertThrows(() => exclusionPaths(EXCLUSION_TEXT.replace("/var/log", "/")));
  assertThrows(() =>
    exclusionPaths(EXCLUSION_TEXT.replace("/var/log", "/etc"))
  );
  assertThrows(() =>
    exclusionPaths(EXCLUSION_TEXT.replace("/var/log", "/home/codex"))
  );
  assertThrows(() =>
    exclusionPaths(EXCLUSION_TEXT.replace("/var/log", "/usr"))
  );
});

Deno.test("exclusions reject noncanonical aliases and protected ancestors", () => {
  const replacements = [
    "/.", // dot segment
    "//", // repeated slash with empty segments
    "//var/log", // repeated leading slash
    "/var//log", // repeated inner slash
    "/var/log/", // trailing slash
    "/home/codex/../repos", // dotdot segment
    "/.swapfile/", // trailing-slash alias of a required path
    "/etc/", // trailing-slash alias of a protected root
    "/home/codex/.codex/", // trailing-slash alias of a protected root
    "/var/log/..", // dotdot segment at the end
    "/var", // ancestor of the protected /var/lib
    "/var/lib", // protected root
    "/boot", // protected root
    "/home", // protected root and ancestor
  ];
  for (const replacement of replacements) {
    const text = EXCLUSION_TEXT.replace("/var/log", replacement);
    assert(
      text.split("\n").includes("/tmp") && text.includes("/.swapfile"),
      `required exclusions must still be supplied for ${replacement}`,
    );
    assertThrows(() => exclusionPaths(text));
  }
});

Deno.test("normal canonical exclusions and protected-root descendants remain accepted", () => {
  exclusionPaths(EXCLUSION_TEXT);
  exclusionPaths(EXCLUSION_TEXT + "\n/var/lib/pacman");
  exclusionPaths(EXCLUSION_TEXT + "\n/mnt/data");
});

Deno.test("exclusions must include the swap and temporary paths", () => {
  const missingSwapfile = EXCLUSION_TEXT.split("\n").filter((line) =>
    line !== "/.swapfile"
  ).join("\n");
  const missingTemp = EXCLUSION_TEXT.split("\n").filter((line) =>
    line !== "/tmp" && line !== "/var/tmp"
  ).join("\n");
  assertThrows(() => exclusionPaths(missingSwapfile));
  assertThrows(() => exclusionPaths(missingTemp));
  assertThrows(() => exclusionPaths(missingSwapfile.replace("/tmp", "/tmp2")));
});

Deno.test("generation must be a canonical lowercase generation-UUID", () => {
  validateGeneration("generation-5d2b15ce-9f1a-4c3e-8a7b-0e1f2a3b4c5d");
  assertThrows(() =>
    validateGeneration("generation-5D2B15CE-9F1A-4C3E-8A7B-0E1F2A3B4C5D")
  );
  assertThrows(() =>
    validateGeneration("5d2b15ce-9f1a-4c3e-8a7b-0e1f2a3b4c5d")
  );
  assertThrows(() => validateGeneration("generation-5d2b15ce-9f1a-4c3e"));
  assertThrows(() => validateGeneration("generation-" + "g".repeat(36)));
  assertThrows(() => validateGeneration("generation-"));
});

Deno.test("invalid recipient input is rejected before any side effect", () => {
  validateCaptureSettings(validSettings());
  assertThrows(() =>
    validateCaptureSettings({
      ...validSettings(),
      recipientSha256: "A".repeat(64),
    })
  );
  assertThrows(() =>
    validateCaptureSettings({
      ...validSettings(),
      recipientSha256: "a".repeat(63),
    })
  );
  assertThrows(() =>
    validateCaptureSettings({
      ...validSettings(),
      recipientFingerprint: "e".repeat(40),
    })
  );
  assertThrows(() =>
    validateCaptureSettings({
      ...validSettings(),
      recipientFingerprint: "E".repeat(39),
    })
  );
  assertThrows(() =>
    validateCaptureSettings({
      ...validSettings(),
      recipientFile: "recipient.asc",
    })
  );
  assertThrows(() =>
    validateCaptureSettings({
      ...validSettings(),
      recipientFile: "/tmp/recipient;.asc",
    })
  );
  assertThrows(() =>
    validateCaptureSettings({
      ...validSettings(),
      generation: "generation-XYZ",
    })
  );
  assertThrows(() =>
    validateCaptureSettings({
      ...validSettings(),
      exclusionsText: EXCLUSION_TEXT.replace("/.swapfile", "/recreated-swap"),
    })
  );
});

function publicArmorText(body: string[]): string {
  return [
    "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    ...body,
    "-----END PGP PUBLIC KEY BLOCK-----",
  ].join("\n") + "\n";
}

const PUBLIC_ARMOR_BODY = [
  "Version: GnuPG v2.4.4",
  "",
  "mQENBFpvY9MBCADH0q9IcbwJ0xEe+1234567890ABCDEFghijklmnopqrstu",
  "=AbCd",
];

Deno.test("recipient armor accepts exactly one ASCII public key block", () => {
  const normal = publicArmorText(PUBLIC_ARMOR_BODY);
  assert(isPublicKeyArmorForm(normal));
  // No trailing newline and CRLF endings are both accepted export forms.
  assert(isPublicKeyArmorForm(normal.trimEnd()));
  assert(isPublicKeyArmorForm(normal.replaceAll("\n", "\r\n")));
});

Deno.test("recipient armor rejects secret, private, binary, extra and mixed blocks", () => {
  const normal = publicArmorText(PUBLIC_ARMOR_BODY);
  const rearmored = (label: string): string =>
    normal.replaceAll("PUBLIC KEY", `${label} KEY`);
  assert(!isPublicKeyArmorForm(rearmored("SECRET")));
  assert(!isPublicKeyArmorForm(rearmored("PRIVATE")));
  const signature = "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n=BBBB\n" +
    "-----END PGP SIGNATURE-----\n";
  assert(!isPublicKeyArmorForm(normal + signature));
  assert(!isPublicKeyArmorForm(signature + normal));
  assert(!isPublicKeyArmorForm(normal + normal));
  assert(
    !isPublicKeyArmorForm(`${normal}\n-----BEGIN PGP PRIVATE KEY BLOCK-----`),
  );
  assert(!isPublicKeyArmorForm(`text before\n${normal}`));
  assert(!isPublicKeyArmorForm(`${normal}text after`));
  assert(!isPublicKeyArmorForm(normal.slice(0, -20)));
  assert(
    !isPublicKeyArmorForm("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n=AbCd"),
  );
  assert(!isPublicKeyArmorForm(""));
  // Binary-like secret bytes and non-ASCII content are rejected outright.
  assert(!isPublicKeyArmorForm("\x00\x01\x02\x03secret"));
  assert(!isPublicKeyArmorForm("recipient\x80\xffbytes"));
  assert(!isPublicKeyArmorForm(`public\u00e9key`));
});

Deno.test("real unmounted lsblk nodes report mountpoints [null] and are accepted", () => {
  validateSources(
    sources(),
    blockDevices({
      rootMounts: ["/", null],
      efiMounts: [null, "/efi"],
    }),
  );
  assertLiveMountTargets(blockDevices({ stagingBootMounts: [null] }));
});

Deno.test("mixed mountpoints reject a real foreign path next to null", () => {
  assertThrows(() =>
    assertLiveMountTargets(
      blockDevices({ stagingBootMounts: [null, "/mnt/staging"] }),
    )
  );
  assertThrows(() =>
    assertLiveMountTargets(blockDevices({ rootMounts: [null, "/srv"] }))
  );
});

Deno.test("malformed mountpoint data is rejected", () => {
  assertThrows(() =>
    assertLiveMountTargets(
      blockDevices({ rootMounts: [42 as unknown as string] }),
    )
  );
  const malformed: LsblkNode = {
    name: "sdb1",
    path: "/dev/sdb1",
    size: ROOT_SIZE,
    type: "part",
    fstype: "ext4",
    uuid: ROOT_UUID,
    mountpoints: "oops" as unknown as (string | null)[],
  };
  assertThrows(() => assertLiveMountTargets([malformed]));
});

runtimeTest(
  "generated producer checks snapshot PIPESTATUS once and pass on success",
  async () => {
    const producers = [
      { label: "tar", variable: "ts", exitCode: 60 },
      { label: "zstd", variable: "zs", exitCode: 61 },
    ];
    const script = [
      "set -u",
      "set -o pipefail",
      ...pipelineStatusLines("true | cat", producers),
      "printf 'ok\\n'",
    ].join("\n");
    const result = await runBash(script);
    assert(
      result.code === 0,
      `unexpected status ${result.code}: ${result.stderr}`,
    );
    assert(result.stdout.trim() === "ok");
  },
);

runtimeTest(
  "generated producer checks fail with each producer status individually",
  async () => {
    const tarZstd = [
      { label: "tar", variable: "ts", exitCode: 60 },
      { label: "zstd", variable: "zs", exitCode: 61 },
    ];
    const first = await runBash([
      "set -u",
      "set -o pipefail",
      ...pipelineStatusLines("false | cat", tarZstd),
    ].join("\n"));
    assert(first.code === 60, first.stderr);
    assert(first.stderr.includes("tar producer exit 1"));
    assert(!first.stderr.includes("zstd producer exit"));

    const second = await runBash([
      "set -u",
      "set -o pipefail",
      ...pipelineStatusLines("true | false", tarZstd),
    ].join("\n"));
    assert(second.code === 61, second.stderr);
    assert(second.stderr.includes("zstd producer exit 1"));
    assert(!second.stderr.includes("tar producer exit"));

    const third = await runBash([
      "set -u",
      "set -o pipefail",
      ...pipelineStatusLines("true | cat | false", [
        { label: "zstd", variable: "s0", exitCode: 63 },
        { label: "tar", variable: "s1", exitCode: 63 },
        { label: "awk", variable: "s2", exitCode: 63 },
      ]),
    ].join("\n"));
    assert(third.code === 63, third.stderr);
    assert(third.stderr.includes("awk producer exit 1"));
    assert(!third.stderr.includes("zstd producer exit"));
  },
);

const REQUIRED_MEMBERS = [
  "./etc/os-release",
  "./boot/Image",
  "./boot/initramfs-linux.img",
];

const INVENTORY_PRODUCERS = [
  { label: "zstd", variable: "s0", exitCode: 63 },
  { label: "tar", variable: "s1", exitCode: 63 },
  { label: "awk", variable: "s2", exitCode: 63 },
];

async function inventoryFixture(
  dir: string,
  members: string[],
): Promise<string> {
  const tree = `${dir}/tree`;
  await Deno.mkdir(`${tree}/etc`, { recursive: true });
  await Deno.mkdir(`${tree}/boot`, { recursive: true });
  await Deno.writeTextFile(`${tree}/etc/os-release`, "NAME=Arch Linux\n");
  await Deno.writeTextFile(`${tree}/boot/Image`, "vmlinuz\n");
  await Deno.writeTextFile(`${tree}/boot/initramfs-linux.img`, "initramfs\n");
  const fixture = `${dir}/fixture.tar.zst`;
  const archive = await runBash(
    `tar --format=pax -cf - -C ${JSON.stringify(tree)} ${
      members.join(" ")
    } | zstd -3 -c > ${JSON.stringify(fixture)}`,
  );
  assert(archive.code === 0, archive.stderr);
  return fixture;
}

runtimeTest(
  "generated inventory pipeline succeeds on a real tar stream",
  async () => {
    const dir = await Deno.makeTempDir({ prefix: "capture-inventory-" });
    try {
      const fixture = await inventoryFixture(dir, REQUIRED_MEMBERS);
      const script = [
        "set -u",
        "set -o pipefail",
        ...pipelineStatusLines(
          inventoryPipeline(fixture, REQUIRED_MEMBERS),
          INVENTORY_PRODUCERS,
        ),
      ].join("\n");
      const result = await runBash(script);
      assert(result.code === 0, `unexpected ${result.code}: ${result.stderr}`);
      assert(result.stdout.trim() === "entries=3");
      assert(result.stderr === "");
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest(
  "generated inventory pipeline detects a missing required member",
  async () => {
    const dir = await Deno.makeTempDir({ prefix: "capture-inventory-" });
    try {
      const fixture = await inventoryFixture(
        dir,
        ["./etc/os-release", "./boot/Image"],
      );
      const script = [
        "set -u",
        "set -o pipefail",
        ...pipelineStatusLines(
          inventoryPipeline(fixture, REQUIRED_MEMBERS),
          INVENTORY_PRODUCERS,
        ),
      ].join("\n");
      const result = await runBash(script);
      assert(result.code === 63, `unexpected ${result.code}: ${result.stderr}`);
      assert(
        result.stderr.includes("missing ./boot/initramfs-linux.img"),
        result.stderr,
      );
      assert(result.stderr.includes("awk producer exit 1"), result.stderr);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

runtimeTest("generated inventory code rejects an empty listing", async () => {
  const empty = await new Deno.Command("awk", {
    args: [inventoryAwk(REQUIRED_MEMBERS)],
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).output();
  assert(empty.code === 1, `unexpected ${empty.code}`);
  assert(
    new TextDecoder().decode(empty.stderr).includes("empty archive"),
  );
});

runtimeTest(
  "sha256File hashes a synthetic staged file through checked sha256sum",
  async () => {
    const dir = await Deno.makeTempDir({ prefix: "capture-hash-" });
    try {
      const data = new Uint8Array(2 * 1024 * 1024 + 37);
      for (let offset = 0; offset < data.length; offset += 65_536) {
        crypto.getRandomValues(
          data.subarray(offset, Math.min(offset + 65_536, data.length)),
        );
      }
      const path = `${dir}/synthetic.bin`;
      await Deno.writeFile(path, data);
      const digest = await sha256File(path, "hash:test");
      const expected = [
        ...new Uint8Array(
          await crypto.subtle.digest("SHA-256", data),
        ),
      ].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      assert(digest === expected);
      await assertThrowsAsync(() =>
        sha256File(`${dir}/missing.bin`, "hash:test")
      );
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);

Deno.test("swapfile recreation metadata distinguishes present from absent", () => {
  const present = swapfileRecreation("present 4294967296 1000 0 0\n");
  assert(present.present);
  assert(present.path === "/.swapfile");
  assert(present.bytes === 4_294_967_296);
  assert(present.mode === 0o1000);
  assert(present.uid === 0);
  assert(present.gid === 0);
  const absent = swapfileRecreation("absent\n");
  assert(!absent.present);
  assert(absent.note.includes("absent"));
  assertThrows(() => swapfileRecreation(""));
  assertThrows(() => swapfileRecreation("maybe 1 2 3 4"));
  assertThrows(() => swapfileRecreation("present 1 2 3 4 5"));
  assertThrows(() => swapfileRecreation("present 1 2 3 4x"));
});

const STAT_SHIM = `#!/bin/bash
# GNU stat -c subset emulation so the generated swapfile fragment executes on
# hosts whose stat speaks BSD -f; values come from the real host stat.
file="\${@: -1}"
if /usr/bin/stat -c '%s %a %u %g' "$file" >/dev/null 2>&1; then
  /usr/bin/stat -c '%s %a %u %g' "$file"
else
  printf '%s %s %s %s\\n' "$(/usr/bin/stat -f '%z' "$file")" "$(/usr/bin/stat -f '%Lp' "$file")" "$(/usr/bin/stat -f '%u' "$file")" "$(/usr/bin/stat -f '%g' "$file")"
fi
`;

runtimeTest(
  "generated swapfile stat lines record oracle-root /.swapfile before exclusion",
  async () => {
    const dir = await Deno.makeTempDir({ prefix: "capture-swap-" });
    try {
      const stage = `${dir}/stage`;
      await Deno.mkdir(stage);
      const bin = `${dir}/bin`;
      await Deno.mkdir(bin);
      await Deno.writeTextFile(`${bin}/stat`, STAT_SHIM);
      await Deno.chmod(`${bin}/stat`, 0o755);
      const env = { PATH: `${bin}:/bin:/usr/bin` };
      const lines = swapfileStatLines(stage);

      const presentDir = `${dir}/present`;
      await Deno.mkdir(presentDir);
      await Deno.writeFile(`${presentDir}/.swapfile`, new Uint8Array(65_536));
      await Deno.chmod(`${presentDir}/.swapfile`, 0o600);
      const present = await runBash(["set -u", ...lines].join("\n"), {
        cwd: presentDir,
        env,
      });
      assert(present.code === 0, present.stderr);
      const info = await Deno.stat(`${presentDir}/.swapfile`);
      const parsed = swapfileRecreation(
        await Deno.readTextFile(`${stage}/oracle-root.swapfile.stat`),
      );
      assert(parsed.present);
      assert(parsed.bytes === info.size);
      assert(parsed.uid === info.uid);
      assert(parsed.gid === info.gid);
      assert(parsed.mode === ((info.mode ?? 0) & 0o777));

      const absentDir = `${dir}/absent`;
      await Deno.mkdir(absentDir);
      const absent = await runBash(["set -u", ...lines].join("\n"), {
        cwd: absentDir,
        env,
      });
      assert(absent.code === 0, absent.stderr);
      assert(
        !swapfileRecreation(
          await Deno.readTextFile(`${stage}/oracle-root.swapfile.stat`),
        ).present,
      );
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
);
