import { DetectorContext, TokenDetector } from "./types";
import { Incident, TokenUsageEvent } from "../types";
import { toIpPrefix } from "../utils/fingerprint";

export interface SessionFanoutDetectorOptions {
  windowMs: number;
  distinctIpPrefixThreshold: number;
  action: "revoke_token" | "challenge_login";
}

export class SessionFanoutDetector implements TokenDetector {
  public readonly id = "session-fanout-v1";

  public constructor(private readonly options: SessionFanoutDetectorOptions) {}

  public async detectToken(event: TokenUsageEvent, context: DetectorContext): Promise<Incident | null> {
    const ipPrefix = toIpPrefix(event.ip);
    const stats = await context.store.recordSessionIpUsage(
      event.sessionId,
      ipPrefix,
      this.options.windowMs,
      context.now,
    );

    if (stats.distinctIpPrefixCount < this.options.distinctIpPrefixThreshold) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "session_fanout",
      severity: "high",
      confidence: 0.9,
      action: this.options.action,
      reason:
        `Session fanout suspected for ${event.sessionId}: ` +
        `${stats.distinctIpPrefixCount} ip prefixes in ${this.options.windowMs}ms.`,
      evidence: {
        sessionId: event.sessionId,
        ipPrefix,
        distinctIpPrefixCount: stats.distinctIpPrefixCount,
        totalCount: stats.totalCount,
      },
      timestamp: context.now,
    };
  }
}
