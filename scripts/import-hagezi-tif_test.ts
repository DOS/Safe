import { isCompleteUpload, parseTifDomains, TIF_URL } from "./hagezi-tif.ts";

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

Deno.test("HaGeZi importer uses the current plain-domain TIF feed", () => {
  assertEquals(
    TIF_URL,
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif-onlydomains.txt",
  );
});

Deno.test("parseTifDomains removes metadata, blanks, case variants, and duplicates", () => {
  const input = [
    "# metadata",
    "! comment",
    "Example.COM",
    "example.com",
    "",
    "evil.test",
  ].join("\n");

  assertEquals(parseTifDomains(input), ["example.com", "evil.test"]);
});

Deno.test("isCompleteUpload rejects empty and partial imports", () => {
  assertEquals(isCompleteUpload(0, 0), false);
  assertEquals(isCompleteUpload(5_000, 10_000), false);
  assertEquals(isCompleteUpload(10_000, 10_000), true);
});

