export const TIF_URL =
  "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif-onlydomains.txt";

export function isCompleteUpload(uploaded: number, expected: number): boolean {
  return expected > 0 && uploaded === expected;
}

export function parseTifDomains(text: string): string[] {
  const domains = text.split("\n").filter((line) => {
    const value = line.trim();
    return value && !value.startsWith("#") && !value.startsWith("!");
  });

  return [...new Set(domains.map((domain) => domain.trim().toLowerCase()))];
}
