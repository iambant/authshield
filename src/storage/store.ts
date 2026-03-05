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

export interface AccountEnumerationStats {
  uniqueUserCount: number;
  failCount: number;
  totalCount: number;
}

export interface LastTokenFingerprintRecord {
  fingerprint: Fingerprint;
  timestamp: number;
}

export interface LastSuccessfulLoginRecord {
  username: string;
  fingerprint: Fingerprint;
  timestamp: number;
}

export interface SessionIpUsageStats {
  distinctIpPrefixCount: number;
  totalCount: number;
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
  recordAccountEnumerationAttempt(
    ip: string,
    username: string,
    success: boolean,
    windowMs: number,
    now: number,
  ): Promise<AccountEnumerationStats>;
  getRecentUserFailures(username: string, windowMs: number, now: number): Promise<number>;
  recordSessionIpUsage(
    sessionId: string,
    ipPrefix: string,
    windowMs: number,
    now: number,
  ): Promise<SessionIpUsageStats>;
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
  setLastTokenFingerprint(
    sessionId: string,
    fingerprint: Fingerprint,
    timestamp: number,
    ttlMs: number,
  ): Promise<void>;
  getLastTokenFingerprint(sessionId: string): Promise<LastTokenFingerprintRecord | null>;
  setLastSuccessfulLogin(
    username: string,
    fingerprint: Fingerprint,
    timestamp: number,
    ttlMs: number,
  ): Promise<void>;
  getLastSuccessfulLogin(username: string): Promise<LastSuccessfulLoginRecord | null>;
  setUserChallenge(username: string, ttlMs: number): Promise<void>;
  isUserChallenged(username: string): Promise<boolean>;
  revokeSession(sessionId: string, ttlMs: number): Promise<void>;
  isSessionRevoked(sessionId: string): Promise<boolean>;
}
