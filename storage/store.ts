import { Fingerprint } from "../types";

export interface SprayWindowStats {
  attemptCount: number;
  distinctUserCount: number;
}

export interface StuffingWindowStats {
  attemptCount: number;
  distinctIpCount: number;
}

export interface BruteForceWindowStats {
  attemptCount: number;
}

export interface FingerprintObservation {
  isNewDevice: boolean;
  isNewIpPrefix: boolean;
}

export interface AuthShieldStore {
  incrementWindowCounter(key: string, windowMs: number, now: number): Promise<number>;
  recordSprayFailure(ip: string, username: string, windowMs: number, now: number): Promise<SprayWindowStats>;
  recordStuffingFailure(username: string, ip: string, windowMs: number, now: number): Promise<StuffingWindowStats>;
  recordBruteForceFailure(
    ip: string,
    username: string,
    windowMs: number,
    now: number,
  ): Promise<BruteForceWindowStats>;
  getRecentUserFailures(username: string, windowMs: number, now: number): Promise<number>;
  observeUserFingerprint(
    username: string,
    fingerprint: Fingerprint,
    windowMs: number,
    now: number,
  ): Promise<FingerprintObservation>;
  setIpBlock(ip: string, ttlMs: number): Promise<void>;
  isIpBlocked(ip: string): Promise<boolean>;
  setSessionFingerprint(sessionId: string, fingerprint: Fingerprint, ttlMs: number): Promise<void>;
  getSessionFingerprint(sessionId: string): Promise<Fingerprint | null>;
  revokeSession(sessionId: string, ttlMs: number): Promise<void>;
  isSessionRevoked(sessionId: string): Promise<boolean>;
}
