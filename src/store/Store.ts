export interface SprayWindowStats {
  attemptCount: number;
  distinctUserCount: number;
}

export interface SlidingWindowStore {
  recordIpUsernameAttempt(
    ip: string,
    username: string,
    windowMs: number,
    now: number,
  ): Promise<SprayWindowStats>;
  setIpBlock(ip: string, ttlMs: number): Promise<void>;
  isIpBlocked(ip: string): Promise<boolean>;
}
