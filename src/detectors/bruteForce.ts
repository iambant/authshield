import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";

export interface BruteForceDetectorOptions {
  windowMs: number;
  attemptsThreshold: number;
  action?: "block_ip" | "challenge_login";
}

export class BruteForceDetector implements LoginDetector {
  public readonly id = "bruteforce-v1";

  public constructor(private readonly options: BruteForceDetectorOptions) {}

  public async detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null> {
    if (event.success) {
      return null;
    }

    const stats = await context.store.recordBruteForceFailure(
      event.ip,
      event.username,
      this.options.windowMs,
      context.now,
    );

    if (stats.attemptCount < this.options.attemptsThreshold) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "brute_force",
      severity: "high",
      confidence: 0.92,
      action: this.options.action ?? "block_ip",
      reason:
        `Brute-force pattern for ${event.username} from ${event.ip}: ` +
        `${stats.attemptCount} failed attempts in ${Math.round(this.options.windowMs / 1000)}s.`,
      evidence: {
        ip: event.ip,
        username: event.username,
        attemptCount: stats.attemptCount,
      },
      timestamp: context.now,
    };
  }
}
