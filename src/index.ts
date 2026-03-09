export { authShield, AuthShield } from "./core/AuthShield";
export type {
  AuthShieldConfig,
  DecisionPayload,
  LimitEvent,
  LimitEventType,
  LimitHandlerResult,
} from "./core/AuthShield";
export { DetectionEngine } from "./core/DetectionEngine";

export { ActionExecutor } from "./actions/ActionExecutor";

export { SprayDetector } from "./detectors/spray";
export { BruteForceDetector } from "./detectors/bruteForce";
export { AccountEnumerationDetector } from "./detectors/accountEnumeration";
export { StuffingDetector } from "./detectors/stuffing";
export { DistributedBruteForceDetector } from "./detectors/distributedBruteForce";
export { PhishingHeuristicsDetector } from "./detectors/phishingHeuristics";
export { ImpossibleTravelDetector } from "./detectors/impossibleTravel";
export { SessionFixationDetector } from "./detectors/sessionFixation";
export { SessionFanoutDetector } from "./detectors/sessionFanout";
export { SuccessAfterFailBurstDetector } from "./detectors/successAfterFailBurst";
export { RegistrationBurstDetector } from "./detectors/registrationBurst";
export { DisposableEmailAbuseDetector } from "./detectors/disposableEmailAbuse";
export { TokenReplayDetector } from "./detectors/tokenReplay";
export { TokenHijackDetector } from "./detectors/tokenHijack";
export type { LoginDetector, RegistrationDetector, TokenDetector } from "./detectors/types";

export { ConsoleIncidentLogger } from "./logging/IncidentLogger";
export { DISPOSABLE_EMAIL_DOMAINS } from "./data/disposableDomains";

export type {
  AuthShieldStore,
  AccountEnumerationStats,
  BruteForceWindowStats,
  LastSuccessfulLoginRecord,
  LastTokenFingerprintRecord,
  SessionIpUsageStats,
  SprayWindowStats,
  StuffingWindowStats,
  FingerprintObservation,
} from "./storage/store";
export { RedisAuthShieldStore } from "./storage/redis";
export { InMemoryAuthShieldStore } from "./storage/inMemory";

export { preLoginGuard } from "./middleware/preLoginGuard";
export { postLoginReporter } from "./middleware/postLoginReporter";
export { tokenGuard } from "./middleware/tokenGuard";
export { revokeHandler } from "./middleware/revokeHandler";
export { preRegistrationGuard } from "./middleware/preRegistrationGuard";
export { postRegistrationReporter } from "./middleware/postRegistrationReporter";

export type {
  ActionType,
  AuthShieldMode,
  Fingerprint,
  Incident,
  LoginAttemptEvent,
  RegistrationAttemptEvent,
  MitigationDecision,
  TokenUsageEvent,
} from "./types";
