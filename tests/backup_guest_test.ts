import {
  backupGuestControl,
  type GuestJournal,
  shellQuote,
} from "../scripts/backup-guest.ts";

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function fixture() {
  let journal: GuestJournal | undefined;
  let busy = false;
  let exitCode = 0;
  let inactiveDesktop = false;
  const stopped: string[] = [];
  const running = new Map([["guacamole-trial-guacamole-1", true], [
    "guacamole-trial-guacd-1",
    true,
  ]]);
  const units = new Map([["caddy.service", true], [
    "shadowsocksr.service",
    true,
  ]]);
  const ids = ["a".repeat(64), "b".repeat(64)];
  const control = backupGuestControl(
    {
      host: "codex@vps.pavlovcik.com",
      rootUuid: "a".repeat(36),
      stagingUuid: "b".repeat(36),
      activityScriptPath:
        "/home/codex/ops/weekly-backup-controller/backup-guest-activity.ts",
    },
    () => journal,
    (value) => {
      journal = structuredClone(value);
      return Promise.resolve();
    },
    (_command, args) => {
      const command = args.at(-1)!;
      let stdout = "";
      if (command.includes("systemctl --user is-active")) {
        const queried = [
          "vncserver.service",
          "tailscaled.service",
          "codex-remote-daemon.service",
        ].filter((unit) => command.includes(unit));
        if (
          queried.length > 0 &&
          queried.every((unit) =>
            inactiveDesktop && unit === "vncserver.service"
          )
        ) return Promise.resolve({ code: 3, stdout: "inactive", stderr: "" });
      }
      if (command.includes("deno run")) {
        stdout = JSON.stringify({
          loadedThreads: busy ? 1 : 0,
        });
      } else if (command.includes("docker inspect")) {
        stdout = [...running]
          .map(([name, active], i) =>
            `"${ids[i]}" "/${name}" ${active} ${exitCode} "unless-stopped"`
          ).join("\n");
      } else if (command.includes("docker ps")) {
        stdout = [
          ...running.keys(),
        ].join("\n");
      } else if (command.includes("-p ActiveState")) {
        stdout = units.get(
            [...units.keys()].find((name) => command.includes(name))!,
          )
          ? "active"
          : "inactive";
      } else if (command.includes("-p Result")) stdout = "success";
      else if (command.includes("systemctl stop")) {
        const name = [...units.keys()].find((name) => command.includes(name))!;
        assert(journal?.units.find((u) => u.name === name)?.stopIntent);
        units.set(name, false);
        stopped.push(name);
      } else if (command.includes("docker stop")) {
        const index = ids.findIndex((id) => command.includes(id));
        assert(journal?.containers[index].stopIntent);
        running.set([...running.keys()][index], false);
        stopped.push(ids[index]);
      } else if (command.includes("docker start")) {
        running.set(
          [...running.keys()][ids.findIndex((id) => command.includes(id))],
          true,
        );
      } else if (command.includes("systemctl start")) {
        units.set(
          [...units.keys()].find((name) => command.includes(name))!,
          true,
        );
      }
      return Promise.resolve({ code: 0, stdout, stderr: "" });
    },
  );
  return {
    control,
    stopped,
    journal: () => journal,
    busy: () => {
      busy = true;
    },
    forceKilled: () => {
      exitCode = 137;
    },
    failDesktop: () => {
      inactiveDesktop = true;
    },
  };
}
async function refuses(run: () => Promise<void>) {
  let rejected = false;
  try {
    await run();
  } catch {
    rejected = true;
  }
  assert(rejected);
}

Deno.test("guest stop intents are durable and original applications recover", async () => {
  const f = fixture();
  await f.control.quiesce();
  assert(f.stopped.length === 4);
  await f.control.acceptSource();
  assert(f.journal()?.restored);
});
Deno.test("loaded Codex thread prevents all guest stop operations", async () => {
  const f = fixture();
  f.busy();
  await refuses(() => f.control.quiesce());
  assert(f.stopped.length === 0 && !f.journal());
});
Deno.test("guest recovery journal cannot be replaced by a new quiescence", async () => {
  const f = fixture();
  await f.control.quiesce();
  await refuses(() => f.control.quiesce());
  assert(f.stopped.length === 4);
});
Deno.test("forced container termination cannot count as clean quiescence", async () => {
  const f = fixture();
  f.forceKilled();
  await refuses(() => f.control.quiesce());
  await f.control.acceptSource();
  assert(f.journal()?.restored);
});
Deno.test("shell quoting retains literal metacharacters", () => {
  assert(shellQuote("a'b$(x)") === "'a'\\''b$(x)'");
});

Deno.test("healthy Tailscale cannot hide an inactive desktop during acceptance", async () => {
  const f = fixture();
  f.failDesktop();
  await refuses(() => f.control.acceptSource());
});
