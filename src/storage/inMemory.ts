import {
  AccountEnumerationStats,
  AuthShieldStore,
  BruteForceWindowStats,
  FingerprintObservation,
  LastSuccessfulLoginRecord,
  LastTokenFingerprintRecord,
  SessionIpUsageStats,
  SprayWindowStats,
  StuffingWindowStats,
} from "./store";
import { Fingerprint } from "../types";

interface TimedValue<T> {
  value: T;
  timestamp: number;
}

export class InMemoryAuthShieldStore implements AuthShieldStore {
  private counters = new Map<string, number[]>();
  private sprayByIp = new Map<string, TimedValue<string>[]>();
  private stuffingByUser = new Map<string, TimedValue<string>[]>();
  private bruteForceByIpUser = new Map<string, number[]>();
  private enumerationUsersByIp = new Map<string, TimedValue<string>[]>();
  private enumerationTotalByIp = new Map<string, number[]>();
  private enumerationFailsByIp = new Map<string, number[]>();
  private sessionIpUsage = new Map<string, TimedValue<string>[]>();
  private sessionUsageTotals = new Map<string, number[]>();
  private failuresByUser = new Map<string, number[]>();
  private userDevices = new Map<string, TimedValue<string>[]>();
  private userIpPrefixes = new Map<string, TimedValue<string>[]>();
  private blockedIps = new Map<string, number>();
  private sessionFingerprints = new Map<string, { fingerprint: Fingerprint; expiresAt: number }>();
  private lastTokenFingerprintBySession = new Map<
    string,
    { fingerprint: Fingerprint; timestamp: number; expiresAt: number }
  >();
  private lastSuccessfulLoginByUser = new Map<
    string,
    { username: string; fingerprint: Fingerprint; timestamp: number; expiresAt: number }
  >();
  private challengedUsers = new Map<string, number>();
  private revokedSessions = new Map<string, number>();

  public async incrementWindowCounter(key: string, windowMs: number, now: number): Promise<number> {
    const entries = this.pruneTimes(this.counters.get(key) ?? [], windowMs, now);
    entries.push(now);
    this.counters.set(key, entries);
    return entries.length;
  }

  public async recordSprayFailure(
    ip: string,
    username: string,
    windowMs: number,
    now: number,
  ): Promise<SprayWindowStats> {
    const entries = this.pruneTimed(this.sprayByIp.get(ip) ?? [], windowMs, now);
    entries.push({ value: username, timestamp: now });
    this.sprayByIp.set(ip, entries);

    return {
      attemptCount: entries.length,
      distinctUserCount: new Set(entries.map((entry) => entry.value)).size,
    };
  }

  public async recordStuffingFailure(
    username: string,
    ip: string,
    windowMs: number,
    now: number,
  ): Promise<StuffingWindowStats> {
    const entries = this.pruneTimed(this.stuffingByUser.get(username) ?? [], windowMs, now);
    entries.push({ value: ip, timestamp: now });
    this.stuffingByUser.set(username, entries);

    const failures = this.pruneTimes(this.failuresByUser.get(username) ?? [], windowMs, now);
    failures.push(now);
    this.failuresByUser.set(username, failures);

    return {
      attemptCount: entries.length,
      distinctIpCount: new Set(entries.map((entry) => entry.value)).size,
    };
  }

  public async recordBruteForceFailure(
    ip: string,
    username: string,
    windowMs: number,
    now: number,
  ): Promise<BruteForceWindowStats> {
    const key = `${ip}|${username}`;
    const entries = this.pruneTimes(this.bruteForceByIpUser.get(key) ?? [], windowMs, now);
    entries.push(now);
    this.bruteForceByIpUser.set(key, entries);
    return { attemptCount: entries.length };
  }

  public async recordAccountEnumerationAttempt(
    ip: string,
    username: string,
    success: boolean,
    windowMs: number,
    now: number,
  ): Promise<AccountEnumerationStats> {
    const users = this.pruneTimed(this.enumerationUsersByIp.get(ip) ?? [], windowMs, now);
    users.push({ value: username, timestamp: now });
    this.enumerationUsersByIp.set(ip, users);

    const totals = this.pruneTimes(this.enumerationTotalByIp.get(ip) ?? [], windowMs, now);
    totals.push(now);
    this.enumerationTotalByIp.set(ip, totals);

    const fails = this.pruneTimes(this.enumerationFailsByIp.get(ip) ?? [], windowMs, now);
    if (!success) {
      fails.push(now);
    }
    this.enumerationFailsByIp.set(ip, fails);

    return {
      uniqueUserCount: new Set(users.map((entry) => entry.value)).size,
      failCount: fails.length,
      totalCount: totals.length,
    };
  }

  public async getRecentUserFailures(username: string, windowMs: number, now: number): Promise<number> {
    const failures = this.pruneTimes(this.failuresByUser.get(username) ?? [], windowMs, now);
    this.failuresByUser.set(username, failures);
    return failures.length;
  }

  public async recordSessionIpUsage(
    sessionId: string,
    ipPrefix: string,
    windowMs: number,
    now: number,
  ): Promise<SessionIpUsageStats> {
    const usage = this.pruneTimed(this.sessionIpUsage.get(sessionId) ?? [], windowMs, now);
    usage.push({ value: ipPrefix, timestamp: now });
    this.sessionIpUsage.set(sessionId, usage);

    const totals = this.pruneTimes(this.sessionUsageTotals.get(sessionId) ?? [], windowMs, now);
    totals.push(now);
    this.sessionUsageTotals.set(sessionId, totals);

    return {
      distinctIpPrefixCount: new Set(usage.map((entry) => entry.value)).size,
      totalCount: totals.length,
    };
  }

  public async observeUserFingerprint(
    username: string,
    fingerprint: Fingerprint,
    windowMs: number,
    now: number,
  ): Promise<FingerprintObservation> {
    const devices = this.pruneTimed(this.userDevices.get(username) ?? [], windowMs, now);
    const prefixes = this.pruneTimed(this.userIpPrefixes.get(username) ?? [], windowMs, now);

    const isNewDevice = !devices.some((entry) => entry.value === fingerprint.deviceId);
    const isNewIpPrefix = !prefixes.some((entry) => entry.value === fingerprint.ipPrefix);

    devices.push({ value: fingerprint.deviceId, timestamp: now });
    prefixes.push({ value: fingerprint.ipPrefix, timestamp: now });

    this.userDevices.set(username, devices);
    this.userIpPrefixes.set(username, prefixes);

    return { isNewDevice, isNewIpPrefix };
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

  public async setSessionFingerprint(sessionId: string, fingerprint: Fingerprint, ttlMs: number): Promise<void> {
    this.sessionFingerprints.set(sessionId, {
      fingerprint,
      expiresAt: Date.now() + ttlMs,
    });
  }

  public async getSessionFingerprint(sessionId: string): Promise<Fingerprint | null> {
    const record = this.sessionFingerprints.get(sessionId);
    if (!record) {
      return null;
    }
    if (record.expiresAt <= Date.now()) {
      this.sessionFingerprints.delete(sessionId);
      return null;
    }
    return record.fingerprint;
  }

  public async setLastTokenFingerprint(
    sessionId: string,
    fingerprint: Fingerprint,
    timestamp: number,
    ttlMs: number,
  ): Promise<void> {
    this.lastTokenFingerprintBySession.set(sessionId, {
      fingerprint,
      timestamp,
      expiresAt: Date.now() + ttlMs,
    });
  }

  public async getLastTokenFingerprint(sessionId: string): Promise<LastTokenFingerprintRecord | null> {
    const record = this.lastTokenFingerprintBySession.get(sessionId);
    if (!record) {
      return null;
    }
    if (record.expiresAt <= Date.now()) {
      this.lastTokenFingerprintBySession.delete(sessionId);
      return null;
    }

    return {
      fingerprint: record.fingerprint,
      timestamp: record.timestamp,
    };
  }

  public async setLastSuccessfulLogin(
    username: string,
    fingerprint: Fingerprint,
    timestamp: number,
    ttlMs: number,
  ): Promise<void> {
    this.lastSuccessfulLoginByUser.set(username, {
      username,
      fingerprint,
      timestamp,
      expiresAt: Date.now() + ttlMs,
    });
  }

  public async getLastSuccessfulLogin(username: string): Promise<LastSuccessfulLoginRecord | null> {
    const record = this.lastSuccessfulLoginByUser.get(username);
    if (!record) {
      return null;
    }
    if (record.expiresAt <= Date.now()) {
      this.lastSuccessfulLoginByUser.delete(username);
      return null;
    }

    return {
      username: record.username,
      fingerprint: record.fingerprint,
      timestamp: record.timestamp,
    };
  }

  public async setUserChallenge(username: string, ttlMs: number): Promise<void> {
    this.challengedUsers.set(username, Date.now() + ttlMs);
  }

  public async isUserChallenged(username: string): Promise<boolean> {
    const expiresAt = this.challengedUsers.get(username);
    if (!expiresAt) {
      return false;
    }
    if (expiresAt <= Date.now()) {
      this.challengedUsers.delete(username);
      return false;
    }
    return true;
  }

  public async revokeSession(sessionId: string, ttlMs: number): Promise<void> {
    this.revokedSessions.set(sessionId, Date.now() + ttlMs);
  }

  public async isSessionRevoked(sessionId: string): Promise<boolean> {
    const expiresAt = this.revokedSessions.get(sessionId);
    if (!expiresAt) {
      return false;
    }
    if (expiresAt <= Date.now()) {
      this.revokedSessions.delete(sessionId);
      return false;
    }
    return true;
  }

  private pruneTimed<T>(entries: TimedValue<T>[], windowMs: number, now: number): TimedValue<T>[] {
    const windowStart = now - windowMs;
    return entries.filter((entry) => entry.timestamp >= windowStart);
  }

  private pruneTimes(entries: number[], windowMs: number, now: number): number[] {
    const windowStart = now - windowMs;
    return entries.filter((timestamp) => timestamp >= windowStart);
  }
}
