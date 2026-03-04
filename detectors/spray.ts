import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";

export interface SprayDetectorOptions {
  windowMs: number;
  distinctUsersThreshold: number;
  minAttemptsThreshold: number;
}

export class SprayDetector implements LoginDetector {
  public readonly id = "spray-v1";

  public constructor(private readonly options: SprayDetectorOptions) {}

  public async detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null> {
    if (event.success) {
      return null;
    }

    const stats = await context.store.recordSprayFailure(
      event.ip,
      event.username,
      this.options.windowMs,
      context.now,
    );

    if (
      stats.distinctUserCount < this.options.distinctUsersThreshold ||
      stats.attemptCount < this.options.minAttemptsThreshold
    ) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "password_spraying",
      severity: "high",
      confidence: 0.95,
      action: "block_ip",
      reason:
        `Potential password spraying from ${event.ip}: ` +
        `${stats.attemptCount} failed attempts across ${stats.distinctUserCount} users.`,
      evidence: {
        ip: event.ip,
        username: event.username,
        attemptCount: stats.attemptCount,
        distinctUserCount: stats.distinctUserCount,
      },
      timestamp: context.now,
    };
  }
}
