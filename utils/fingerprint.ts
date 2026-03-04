import crypto from "node:crypto";

export function hashUserAgent(userAgent: string): string {
  return crypto.createHash("sha256").update(userAgent).digest("hex");
}

export function toIpPrefix(ip: string): string {
  if (ip.includes(".")) {
    const parts = ip.split(".");
    if (parts.length >= 3) {
      return `${parts[0]}.${parts[1]}.${parts[2]}`;
    }
  }

  const normalized = ip.split(":").filter(Boolean);
  return normalized.slice(0, 4).join(":");
}

export function randomDeviceId(): string {
  return crypto.randomBytes(12).toString("hex");
}
