import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";
import { hashUserAgent, toIpPrefix } from "../utils/fingerprint";

export interface PhishingHeuristicsOptions {
  recentFailWindowMs: number;
  failThreshold: number;
  fingerprintWindowMs: number;
}

export class PhishingHeuristicsDetector implements LoginDetector {
  public readonly id = "phishing-heuristics-v1";

  public constructor(private readonly options: PhishingHeuristicsOptions) {}

  public async detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null> {
    const deviceId = event.deviceId ?? "unknown-device";
    const uaHash = hashUserAgent(event.userAgent ?? "");
    const ipPrefix = toIpPrefix(event.ip);

    const observation = await context.store.observeUserFingerprint(
      event.username,
      { deviceId, uaHash, ipPrefix },
      this.options.fingerprintWindowMs,
      context.now,
    );

    if (!event.success) {
      return null;
    }

    const recentFailures = await context.store.getRecentUserFailures(
      event.username,
      this.options.recentFailWindowMs,
      context.now,
    );

    const suspiciousShift = observation.isNewDevice || observation.isNewIpPrefix;
    if (!suspiciousShift || recentFailures < this.options.failThreshold) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "phishing_login_anomaly",
      severity: "medium",
      confidence: 0.78,
      action: "challenge_login",
      reason:
        `Suspicious login after failures for ${event.username}: new device/IP pattern detected.`,
      evidence: {
        username: event.username,
        recentFailures,
        isNewDevice: observation.isNewDevice,
        isNewIpPrefix: observation.isNewIpPrefix,
      },
      timestamp: context.now,
    };
  }
}
