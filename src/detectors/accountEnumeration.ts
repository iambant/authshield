import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";

export interface AccountEnumerationDetectorOptions {
  windowMs: number;
  uniqueUsersThreshold: number;
  failsThreshold: number;
  failRatioThreshold: number;
  action: "block_ip" | "challenge_login";
}

export class AccountEnumerationDetector implements LoginDetector {
  public readonly id = "account-enumeration-v1";

  public constructor(private readonly options: AccountEnumerationDetectorOptions) {}

  public async detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null> {
    const stats = await context.store.recordAccountEnumerationAttempt(
      event.ip,
      event.username,
      event.success,
      this.options.windowMs,
      context.now,
    );

    if (stats.uniqueUserCount < this.options.uniqueUsersThreshold) {
      return null;
    }
    if (stats.failCount < this.options.failsThreshold) {
      return null;
    }

    const failRatio = stats.totalCount === 0 ? 0 : stats.failCount / stats.totalCount;
    if (failRatio < this.options.failRatioThreshold) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "account_enumeration",
      severity: "high",
      confidence: 0.9,
      action: this.options.action,
      reason:
        `Account enumeration suspected from ${event.ip}: ` +
        `${stats.failCount}/${stats.totalCount} fails across ${stats.uniqueUserCount} users.`,
      evidence: {
        ip: event.ip,
        uniqueUserCount: stats.uniqueUserCount,
        failCount: stats.failCount,
        totalCount: stats.totalCount,
        failRatio,
      },
      timestamp: context.now,
    };
  }
}
