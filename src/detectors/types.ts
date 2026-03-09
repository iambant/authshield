import { AuthShieldStore } from "../storage/store";
import { Incident, LoginAttemptEvent, RegistrationAttemptEvent, TokenUsageEvent } from "../types";

export interface DetectorContext {
  store: AuthShieldStore;
  now: number;
}

export interface LoginDetector {
  id: string;
  detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null>;
}

export interface TokenDetector {
  id: string;
  detectToken(event: TokenUsageEvent, context: DetectorContext): Promise<Incident | null>;
}

export interface RegistrationDetector {
  id: string;
  detectRegistration(event: RegistrationAttemptEvent, context: DetectorContext): Promise<Incident | null>;
}
