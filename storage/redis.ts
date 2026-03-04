import Redis from "ioredis";
import { Fingerprint } from "../types";
import {
  AuthShieldStore,
  BruteForceWindowStats,
  FingerprintObservation,
  SprayWindowStats,
  StuffingWindowStats,
} from "./store";

export interface RedisAuthShieldStoreOptions {
  keyPrefix?: string;
}

export class RedisAuthShieldStore implements AuthShieldStore {
  private readonly keyPrefix: string;

  public constructor(
    private readonly redis: Redis,
    options: RedisAuthShieldStoreOptions = {},
  ) {
    this.keyPrefix = options.keyPrefix ?? "authshield";
  }

  public async incrementWindowCounter(key: string, windowMs: number, now: number): Promise<number> {
    const redisKey = `${this.keyPrefix}:counter:${key}`;
    const windowStart = now - windowMs;
    const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000));

    const pipeline = this.redis.pipeline();
    pipeline.zadd(redisKey, now, `${now}:${Math.random().toString(36).slice(2, 10)}`);
    pipeline.zremrangebyscore(redisKey, 0, windowStart);
    pipeline.zcard(redisKey);
    pipeline.expire(redisKey, ttlSeconds);

    const results = await pipeline.exec();
    if (!results) {
      throw new Error("Redis pipeline failed for incrementWindowCounter");
    }

    return Number(results[2]?.[1] ?? 0);
  }

  public async recordSprayFailure(
    ip: string,
    username: string,
    windowMs: number,
    now: number,
  ): Promise<SprayWindowStats> {
    const attemptsKey = `${this.keyPrefix}:spray:ip:${ip}:attempts`;
    const usersKey = `${this.keyPrefix}:spray:ip:${ip}:users`;
    const windowStart = now - windowMs;

    const pipeline = this.redis.pipeline();
    pipeline.zadd(attemptsKey, now, `${now}:${username}:${Math.random().toString(36).slice(2, 10)}`);
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
      throw new Error("Redis pipeline failed for spray update");
    }

    return {
      attemptCount: Number(results[2]?.[1] ?? 0),
      distinctUserCount: Number(results[5]?.[1] ?? 0),
    };
  }

  public async recordStuffingFailure(
    username: string,
    ip: string,
    windowMs: number,
    now: number,
  ): Promise<StuffingWindowStats> {
    const attemptsKey = `${this.keyPrefix}:stuff:user:${username}:attempts`;
    const ipsKey = `${this.keyPrefix}:stuff:user:${username}:ips`;
    const windowStart = now - windowMs;

    const pipeline = this.redis.pipeline();
    pipeline.zadd(attemptsKey, now, `${now}:${ip}:${Math.random().toString(36).slice(2, 10)}`);
    pipeline.zremrangebyscore(attemptsKey, 0, windowStart);
    pipeline.zcard(attemptsKey);

    pipeline.zadd(ipsKey, now, ip);
    pipeline.zremrangebyscore(ipsKey, 0, windowStart);
    pipeline.zcard(ipsKey);

    const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000));
    pipeline.expire(attemptsKey, ttlSeconds);
    pipeline.expire(ipsKey, ttlSeconds);

    const results = await pipeline.exec();
    if (!results) {
      throw new Error("Redis pipeline failed for stuffing update");
    }

    return {
      attemptCount: Number(results[2]?.[1] ?? 0),
      distinctIpCount: Number(results[5]?.[1] ?? 0),
    };
  }

  public async recordBruteForceFailure(
    ip: string,
    username: string,
    windowMs: number,
    now: number,
  ): Promise<BruteForceWindowStats> {
    const attemptsKey = `${this.keyPrefix}:brute:ip_user:${ip}:${username}:attempts`;
    const windowStart = now - windowMs;
    const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000));

    const pipeline = this.redis.pipeline();
    pipeline.zadd(attemptsKey, now, `${now}:${Math.random().toString(36).slice(2, 10)}`);
    pipeline.zremrangebyscore(attemptsKey, 0, windowStart);
    pipeline.zcard(attemptsKey);
    pipeline.expire(attemptsKey, ttlSeconds);

    const results = await pipeline.exec();
    if (!results) {
      throw new Error("Redis pipeline failed for brute force update");
    }

    return {
      attemptCount: Number(results[2]?.[1] ?? 0),
    };
  }

  public async getRecentUserFailures(username: string, windowMs: number, now: number): Promise<number> {
    const attemptsKey = `${this.keyPrefix}:stuff:user:${username}:attempts`;
    const windowStart = now - windowMs;

    const pipeline = this.redis.pipeline();
    pipeline.zremrangebyscore(attemptsKey, 0, windowStart);
    pipeline.zcard(attemptsKey);
    pipeline.expire(attemptsKey, Math.max(1, Math.ceil(windowMs / 1000)));

    const results = await pipeline.exec();
    if (!results) {
      throw new Error("Redis pipeline failed for recent failures");
    }

    return Number(results[1]?.[1] ?? 0);
  }

  public async observeUserFingerprint(
    username: string,
    fingerprint: Fingerprint,
    windowMs: number,
    now: number,
  ): Promise<FingerprintObservation> {
    const devicesKey = `${this.keyPrefix}:user:${username}:devices`;
    const prefixesKey = `${this.keyPrefix}:user:${username}:ip_prefixes`;
    const windowStart = now - windowMs;
    const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000));

    const [deviceScore, prefixScore] = await Promise.all([
      this.redis.zscore(devicesKey, fingerprint.deviceId),
      this.redis.zscore(prefixesKey, fingerprint.ipPrefix),
    ]);

    const pipeline = this.redis.pipeline();
    pipeline.zadd(devicesKey, now, fingerprint.deviceId);
    pipeline.zremrangebyscore(devicesKey, 0, windowStart);
    pipeline.expire(devicesKey, ttlSeconds);

    pipeline.zadd(prefixesKey, now, fingerprint.ipPrefix);
    pipeline.zremrangebyscore(prefixesKey, 0, windowStart);
    pipeline.expire(prefixesKey, ttlSeconds);

    await pipeline.exec();

    return {
      isNewDevice: deviceScore === null,
      isNewIpPrefix: prefixScore === null,
    };
  }

  public async setIpBlock(ip: string, ttlMs: number): Promise<void> {
    await this.redis.set(this.ipBlockKey(ip), "1", "EX", Math.max(1, Math.ceil(ttlMs / 1000)));
  }

  public async isIpBlocked(ip: string): Promise<boolean> {
    return (await this.redis.get(this.ipBlockKey(ip))) === "1";
  }

  public async setSessionFingerprint(sessionId: string, fingerprint: Fingerprint, ttlMs: number): Promise<void> {
    const key = this.sessionKey(sessionId);
    const pipeline = this.redis.pipeline();
    pipeline.hset(key, {
      uaHash: fingerprint.uaHash,
      ipPrefix: fingerprint.ipPrefix,
      deviceId: fingerprint.deviceId,
    });
    pipeline.expire(key, Math.max(1, Math.ceil(ttlMs / 1000)));
    await pipeline.exec();
  }

  public async getSessionFingerprint(sessionId: string): Promise<Fingerprint | null> {
    const key = this.sessionKey(sessionId);
    const data = await this.redis.hgetall(key);
    if (!data.uaHash || !data.ipPrefix || !data.deviceId) {
      return null;
    }
    return {
      uaHash: data.uaHash,
      ipPrefix: data.ipPrefix,
      deviceId: data.deviceId,
    };
  }

  public async revokeSession(sessionId: string, ttlMs: number): Promise<void> {
    await this.redis.set(this.revokedSessionKey(sessionId), "1", "EX", Math.max(1, Math.ceil(ttlMs / 1000)));
  }

  public async isSessionRevoked(sessionId: string): Promise<boolean> {
    return (await this.redis.get(this.revokedSessionKey(sessionId))) === "1";
  }

  private ipBlockKey(ip: string): string {
    return `${this.keyPrefix}:block:ip:${ip}`;
  }

  private sessionKey(sessionId: string): string {
    return `${this.keyPrefix}:session:${sessionId}`;
  }

  private revokedSessionKey(sessionId: string): string {
    return `${this.keyPrefix}:revoke:session:${sessionId}`;
  }
}
