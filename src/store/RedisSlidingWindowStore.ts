import Redis from "ioredis";
import { SlidingWindowStore, SprayWindowStats } from "./Store";

export interface RedisSlidingWindowStoreOptions {
  keyPrefix?: string;
}

export class RedisSlidingWindowStore implements SlidingWindowStore {
  private readonly keyPrefix: string;

  public constructor(
    private readonly redis: Redis,
    options: RedisSlidingWindowStoreOptions = {},
  ) {
    this.keyPrefix = options.keyPrefix ?? "authshield";
  }

  public async recordIpUsernameAttempt(
    ip: string,
    username: string,
    windowMs: number,
    now: number,
  ): Promise<SprayWindowStats> {
    const attemptsKey = `${this.keyPrefix}:spray:${ip}:attempts`;
    const usersKey = `${this.keyPrefix}:spray:${ip}:users`;
    const windowStart = now - windowMs;
    const uniqueAttemptId = `${now}:${username}:${Math.random().toString(36).slice(2, 10)}`;

    const pipeline = this.redis.pipeline();
    pipeline.zadd(attemptsKey, now, uniqueAttemptId);
    pipeline.zremrangebyscore(attemptsKey, 0, windowStart);
    pipeline.zcard(attemptsKey);

    pipeline.zadd(usersKey, now, username);
    pipeline.zremrangebyscore(usersKey, 0, windowStart);
    pipeline.zcard(usersKey);

    const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000));
    pipeline.expire(attemptsKey, ttlSeconds);
    pipeline.expire(usersKey, ttlSeconds);

    const results = await pipeline.exec();
    if (!results) {
      throw new Error("Redis pipeline failed for spraying window update");
    }

    const attemptCount = Number(results[2]?.[1] ?? 0);
    const distinctUserCount = Number(results[5]?.[1] ?? 0);

    return { attemptCount, distinctUserCount };
  }

  public async setIpBlock(ip: string, ttlMs: number): Promise<void> {
    const key = `${this.keyPrefix}:block:ip:${ip}`;
    const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
    await this.redis.set(key, "1", "EX", ttlSeconds);
  }

  public async isIpBlocked(ip: string): Promise<boolean> {
    const key = `${this.keyPrefix}:block:ip:${ip}`;
    const blocked = await this.redis.get(key);
    return blocked === "1";
  }
}
