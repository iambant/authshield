import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";

export interface SessionFixationDetectorOptions {
  action: "revoke_token" | "challenge_login";
}

export class SessionFixationDetector implements LoginDetector {
  public readonly id = "session-fixation-v1";

  public constructor(private readonly options: SessionFixationDetectorOptions) {}

  public async detectLogin(event: LoginAttemptEvent, _context: DetectorContext): Promise<Incident | null> {
    if (!event.success) {
      return null;
    }

    if (!event.beforeSessionId || !event.afterSessionId) {
      return null;
    }

    if (event.beforeSessionId !== event.afterSessionId) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "session_fixation",
      severity: "high",
      confidence: 0.91,
      action: this.options.action,
      reason: `Session fixation suspected for ${event.username}: session ID did not rotate after login.`,
      evidence: {
        username: event.username,
        sessionId: event.afterSessionId,
      },
      timestamp: event.timestamp ?? Date.now(),
    };
  }
}
