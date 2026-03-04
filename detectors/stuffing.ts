import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";

export interface StuffingDetectorOptions {
  windowMs: number;
  attemptsThreshold: number;
  distinctIpsThreshold: number;
}

export class StuffingDetector implements LoginDetector {
  public readonly id = "stuffing-v1";

  public constructor(private readonly options: StuffingDetectorOptions) {}

  public async detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null> {
    if (event.success) {
      return null;
    }

    const stats = await context.store.recordStuffingFailure(
      event.username,
      event.ip,
      this.options.windowMs,
      context.now,
    );

    if (
      stats.attemptCount < this.options.attemptsThreshold ||
      stats.distinctIpCount < this.options.distinctIpsThreshold
    ) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "credential_stuffing",
      severity: "high",
      confidence: 0.9,
      action: "challenge_login",
      reason:
        `Potential credential stuffing on ${event.username}: ` +
        `${stats.attemptCount} attempts from ${stats.distinctIpCount} IPs.`,
      evidence: {
        username: event.username,
        ip: event.ip,
        attemptCount: stats.attemptCount,
        distinctIpCount: stats.distinctIpCount,
      },
      timestamp: context.now,
    };
  }
}
