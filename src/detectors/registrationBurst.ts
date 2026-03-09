import { DetectorContext, RegistrationDetector } from "./types";
import { Incident, RegistrationAttemptEvent } from "../types";

export interface RegistrationBurstDetectorOptions {
  windowMs: number;
  attemptsThreshold: number;
  action?: "challenge_login" | "block_ip";
}

export class RegistrationBurstDetector implements RegistrationDetector {
  public readonly id = "registration-burst-v1";

  public constructor(private readonly options: RegistrationBurstDetectorOptions) {}

  public async detectRegistration(
    event: RegistrationAttemptEvent,
    context: DetectorContext,
  ): Promise<Incident | null> {
    const attemptCount = await context.store.incrementWindowCounter(
      `register:ip:${event.ip}`,
      this.options.windowMs,
      context.now,
    );

    if (attemptCount < this.options.attemptsThreshold) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "registration_burst",
      severity: "high",
      confidence: 0.9,
      action: this.options.action ?? "challenge_login",
      reason:
        `Registration burst from ${event.ip}: ` +
        `${attemptCount} attempts in ${Math.round(this.options.windowMs / 1000)}s.`,
      evidence: {
        ip: event.ip,
        attemptCount,
        windowMs: this.options.windowMs,
      },
      timestamp: context.now,
    };
  }
}
