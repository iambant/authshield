import { Detector, DetectorContext } from "./Detector";
import { Incident, LoginAttemptEvent } from "../types";

export interface PasswordSprayingDetectorOptions {
  windowMs: number;
  distinctUsersThreshold: number;
  minAttemptsThreshold: number;
  onlyFailedAttempts?: boolean;
  action?: "block_ip" | "challenge_login";
}

export class PasswordSprayingDetector implements Detector {
  public readonly id = "password-spraying-v1";

  private readonly options: Required<PasswordSprayingDetectorOptions>;

  public constructor(options?: Partial<PasswordSprayingDetectorOptions>) {
    this.options = {
      windowMs: options?.windowMs ?? 5 * 60 * 1000,
      distinctUsersThreshold: options?.distinctUsersThreshold ?? 8,
      minAttemptsThreshold: options?.minAttemptsThreshold ?? 12,
      onlyFailedAttempts: options?.onlyFailedAttempts ?? true,
      action: options?.action ?? "block_ip",
    };
  }

  public async detect(
    event: LoginAttemptEvent,
    context: DetectorContext,
  ): Promise<Incident | null> {
    if (this.options.onlyFailedAttempts && event.success) {
      return null;
    }

    const stats = await context.store.recordIpUsernameAttempt(
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

    const reason =
      `Detected potential password spraying from IP ${event.ip}: ` +
      `${stats.attemptCount} attempts across ${stats.distinctUserCount} usernames ` +
      `in ${Math.round(this.options.windowMs / 1000)}s.`;

    const confidence = Math.min(
      1,
      0.55 +
        stats.distinctUserCount / (this.options.distinctUsersThreshold * 4) +
        stats.attemptCount / (this.options.minAttemptsThreshold * 4),
    );

    return {
      detectorId: this.id,
      attackType: "password_spraying",
      severity: "high",
      confidence,
      action: this.options.action,
      reason,
      evidence: {
        ip: event.ip,
        attemptCount: stats.attemptCount,
        distinctUserCount: stats.distinctUserCount,
        username: event.username,
      },
      timestamp: context.now,
    };
  }
}
