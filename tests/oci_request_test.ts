import { OciCommandError, runJson } from "../scripts/oci.ts";

Deno.test("OCI request failure is distinct from invalid successful response", async () => {
  for (const [code, stdout] of [[1, ""], [0, "not JSON"]] as const) {
    let failure: unknown;
    try {
      await runJson("oci", ["read"], () =>
        Promise.resolve({
          code,
          stdout,
          stderr: "request failed for ocid1.volume.oc1.test.example",
        }));
    } catch (error) {
      failure = error;
    }
    if (
      !(failure instanceof Error) ||
      (failure instanceof OciCommandError) !== (code !== 0)
    ) {
      throw new Error("Request and validation failures must remain distinct");
    }
    if (failure.message.includes("ocid1.")) {
      throw new Error("Identifier exposed");
    }
  }
});
