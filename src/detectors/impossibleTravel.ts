import { DetectorContext, LoginDetector } from "./types";
import { Incident, LoginAttemptEvent } from "../types";
import { hashUserAgent, toIpPrefix } from "../utils/fingerprint";

export interface ImpossibleTravelDetectorOptions {
  minDeltaMs: number;
  action: "challenge_login" | "block_ip" | "revoke_token";
  stateTtlMs: number;
}

export class ImpossibleTravelDetector implements LoginDetector {
  public readonly id = "impossible-travel-v1";

  public constructor(private readonly options: ImpossibleTravelDetectorOptions) {}

  public async detectLogin(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null> {
    if (!event.success) {
      return null;
    }

    const now = context.now;
    const current = {
      deviceId: event.deviceId ?? "unknown-device",
      uaHash: hashUserAgent(event.userAgent ?? ""),
      ipPrefix: toIpPrefix(event.ip),
    };

    const previous = await context.store.getLastSuccessfulLogin(event.username);
    await context.store.setLastSuccessfulLogin(event.username, current, now, this.options.stateTtlMs);

    if (!previous) {
      return null;
    }

    if (previous.fingerprint.ipPrefix === current.ipPrefix) {
      return null;
    }

    const deltaMs = now - previous.timestamp;
    if (deltaMs >= this.options.minDeltaMs) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "impossible_travel",
      severity: "medium",
      confidence: 0.82,
      action: this.options.action,
      reason: `Impossible-travel heuristic for ${event.username}: IP prefix changed in ${deltaMs}ms.`,
      evidence: {
        username: event.username,
        previousIpPrefix: previous.fingerprint.ipPrefix,
        currentIpPrefix: current.ipPrefix,
        deltaMs,
      },
      timestamp: now,
    };
  }
}
