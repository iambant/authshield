import {
  AuthShieldStore,
  BruteForceWindowStats,
  FingerprintObservation,
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
  private failuresByUser = new Map<string, number[]>();
  private userDevices = new Map<string, TimedValue<string>[]>();
  private userIpPrefixes = new Map<string, TimedValue<string>[]>();
  private blockedIps = new Map<string, number>();
  private sessionFingerprints = new Map<string, { fingerprint: Fingerprint; expiresAt: number }>();
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

  public async getRecentUserFailures(username: string, windowMs: number, now: number): Promise<number> {
    const failures = this.pruneTimes(this.failuresByUser.get(username) ?? [], windowMs, now);
    this.failuresByUser.set(username, failures);
    return failures.length;
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
