import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";

export interface DistributedBruteForceDetectorOptions {
  windowMs: number;
  failsThreshold: number;
  action: "challenge_login" | "block_ip";
}

export class DistributedBruteForceDetector implements LoginDetector {
  public readonly id = "distributed-bruteforce-v1";

  public constructor(private readonly options: DistributedBruteForceDetectorOptions) {}

  public async detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null> {
    if (event.success) {
      return null;
    }

    const failCount = await context.store.getRecentUserFailures(
      event.username,
      this.options.windowMs,
      context.now,
    );

    if (failCount < this.options.failsThreshold) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "distributed_bruteforce",
      severity: "high",
      confidence: 0.88,
      action: this.options.action,
      reason: `Distributed brute-force suspected for ${event.username}: ${failCount} failures in window.`,
      evidence: {
        username: event.username,
        ip: event.ip,
        failCount,
      },
      timestamp: context.now,
    };
  }
}
