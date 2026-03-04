import { SlidingWindowStore, SprayWindowStats } from "./Store";

interface Entry {
  timestamp: number;
  username: string;
}

export class InMemorySlidingWindowStore implements SlidingWindowStore {
  private attemptsByIp = new Map<string, Entry[]>();
  private blockedIps = new Map<string, number>();

  public async recordIpUsernameAttempt(
    ip: string,
    username: string,
    windowMs: number,
    now: number,
  ): Promise<SprayWindowStats> {
    const windowStart = now - windowMs;
    const existing = this.attemptsByIp.get(ip) ?? [];
    const filtered = existing.filter((entry) => entry.timestamp >= windowStart);
    filtered.push({ timestamp: now, username });
    this.attemptsByIp.set(ip, filtered);

    return {
      attemptCount: filtered.length,
      distinctUserCount: new Set(filtered.map((entry) => entry.username)).size,
    };
  }

  public async setIpBlock(ip: string, ttlMs: number): Promise<void> {
    this.blockedIps.set(ip, Date.now() + ttlMs);
  }

  public async isIpBlocked(ip: string): Promise<boolean> {
    const expiresAt = this.blockedIps.get(ip);
    if (!expiresAt) {
      return false;
    }
    if (expiresAt <= Date.now()) {
      this.blockedIps.delete(ip);
      return false;
    }
    return true;
  }
}
