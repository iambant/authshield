import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";

export interface SuccessAfterFailBurstDetectorOptions {
  windowMs: number;
  failThreshold: number;
  action: "challenge_login" | "block_ip";
}

export class SuccessAfterFailBurstDetector implements LoginDetector {
  public readonly id = "success-after-fail-burst-v1";

  public constructor(private readonly options: SuccessAfterFailBurstDetectorOptions) {}

  public async detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null> {
    if (!event.success) {
      return null;
    }

    const failCount = await context.store.getRecentUserFailures(
      event.username,
      this.options.windowMs,
      context.now,
    );

    if (failCount < this.options.failThreshold) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "success_after_fail_burst",
      severity: "medium",
      confidence: 0.8,
      action: this.options.action,
      reason: `Successful login after fail burst for ${event.username}: ${failCount} recent failures.`,
      evidence: {
        username: event.username,
        ip: event.ip,
        failCount,
      },
      timestamp: context.now,
    };
  }
}
