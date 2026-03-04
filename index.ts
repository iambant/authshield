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
export { StuffingDetector } from "./detectors/stuffing";
export { PhishingHeuristicsDetector } from "./detectors/phishingHeuristics";
export { TokenHijackDetector } from "./detectors/tokenHijack";
export type { LoginDetector, TokenDetector } from "./detectors/types";

export { ConsoleIncidentLogger } from "./logging/IncidentLogger";

export type {
  AuthShieldStore,
  BruteForceWindowStats,
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

export type {
  ActionType,
  AuthShieldMode,
  Fingerprint,
  Incident,
  LoginAttemptEvent,
  MitigationDecision,
  TokenUsageEvent,
} from "./types";
