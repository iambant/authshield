import { DetectorContext, RegistrationDetector } from "./types";
import { Incident, RegistrationAttemptEvent } from "../types";

export interface DisposableEmailAbuseDetectorOptions {
  windowMs: number;
  attemptsThreshold: number;
  disposableDomains: string[];
  action?: "challenge_login" | "block_ip";
}

export class DisposableEmailAbuseDetector implements RegistrationDetector {
  public readonly id = "disposable-email-abuse-v1";
  private readonly disposableDomainSet: Set<string>;

  public constructor(private readonly options: DisposableEmailAbuseDetectorOptions) {
    this.disposableDomainSet = new Set(options.disposableDomains.map((domain) => domain.toLowerCase()));
  }

  public async detectRegistration(
    event: RegistrationAttemptEvent,
    context: DetectorContext,
  ): Promise<Incident | null> {
    const domain = this.extractDomain(event.email);
    if (!domain || !this.disposableDomainSet.has(domain)) {
      return null;
    }

    const attemptCount = await context.store.incrementWindowCounter(
      `register:ip:${event.ip}:disposable:${domain}`,
      this.options.windowMs,
      context.now,
    );

    if (attemptCount < this.options.attemptsThreshold) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "disposable_email_abuse",
      severity: "medium",
      confidence: 0.86,
      action: this.options.action ?? "challenge_login",
      reason:
        `Disposable-email signup pattern from ${event.ip}: ` +
        `${attemptCount} attempts on ${domain} in ${Math.round(this.options.windowMs / 1000)}s.`,
      evidence: {
        ip: event.ip,
        emailDomain: domain,
        attemptCount,
        windowMs: this.options.windowMs,
      },
      timestamp: context.now,
    };
  }

  private extractDomain(email?: string): string | null {
    if (!email) {
      return null;
    }
    const normalized = email.trim().toLowerCase();
    const at = normalized.lastIndexOf("@");
    if (at <= 0 || at === normalized.length - 1) {
      return null;
    }
    return normalized.slice(at + 1);
  }
}
