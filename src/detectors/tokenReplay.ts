import { DetectorContext, TokenDetector } from "./types";
import { Incident, TokenUsageEvent } from "../types";
import { hashUserAgent, toIpPrefix } from "../utils/fingerprint";

export interface TokenReplayDetectorOptions {
  replayWindowMs: number;
  replayAction: "revoke_token" | "challenge_login";
  replayStateTtlMs: number;
}

export class TokenReplayDetector implements TokenDetector {
  public readonly id = "token-replay-v1";

  public constructor(private readonly options: TokenReplayDetectorOptions) {}

  public async detectToken(event: TokenUsageEvent, context: DetectorContext): Promise<Incident | null> {
    const now = context.now;
    const current = {
      deviceId: event.deviceId ?? "unknown-device",
      uaHash: hashUserAgent(event.userAgent ?? ""),
      ipPrefix: toIpPrefix(event.ip),
    };

    const previous = await context.store.getLastTokenFingerprint(event.sessionId);
    await context.store.setLastTokenFingerprint(event.sessionId, current, now, this.options.replayStateTtlMs);

    if (!previous) {
      return null;
    }

    const sameFingerprint =
      previous.fingerprint.deviceId === current.deviceId &&
      previous.fingerprint.uaHash === current.uaHash &&
      previous.fingerprint.ipPrefix === current.ipPrefix;

    if (sameFingerprint) {
      return null;
    }

    const deltaMs = now - previous.timestamp;
    if (deltaMs > this.options.replayWindowMs) {
      return null;
    }

    return {
      detectorId: this.id,
      attackType: "token_replay",
      severity: "high",
      confidence: 0.94,
      action: this.options.replayAction,
      reason: `Token replay suspected for ${event.sessionId}: fingerprint changed within ${deltaMs}ms.`,
      evidence: {
        sessionId: event.sessionId,
        deltaMs,
        previous: previous.fingerprint,
        current,
      },
      timestamp: now,
    };
  }
}
