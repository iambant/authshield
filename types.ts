export type AuthShieldMode = "monitor" | "enforce";
export type ActionType = "allow" | "block_ip" | "challenge_login" | "revoke_token";

export interface LoginAttemptEvent {
  ip: string;
  username: string;
  success: boolean;
  timestamp?: number;
  userAgent?: string;
  deviceId?: string;
  sessionId?: string;
}

export interface TokenUsageEvent {
  ip: string;
  sessionId: string;
  timestamp?: number;
  userAgent?: string;
  deviceId?: string;
}

export interface Fingerprint {
  uaHash: string;
  ipPrefix: string;
  deviceId: string;
}

export interface Incident {
  detectorId: string;
  attackType:
    | "brute_force"
    | "password_spraying"
    | "credential_stuffing"
    | "phishing_login_anomaly"
    | "token_hijack";
  severity: "low" | "medium" | "high";
  confidence: number;
  action: ActionType;
  reason: string;
  evidence: Record<string, unknown>;
  timestamp: number;
}

export interface MitigationDecision {
  allowed: boolean;
  action: ActionType;
  incidents: Incident[];
}

export interface AuthShieldRequestContext {
  requestId?: string;
  route?: string;
}
