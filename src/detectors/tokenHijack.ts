import { DetectorContext, TokenDetector } from "./types";
import { Incident, TokenUsageEvent } from "../types";
import { hashUserAgent, toIpPrefix } from "../utils/fingerprint";

export interface TokenHijackDetectorOptions {
  sessionTtlMs: number;
  revokeTtlMs: number;
}

export class TokenHijackDetector implements TokenDetector {
  public readonly id = "token-hijack-v1";

  public constructor(private readonly options: TokenHijackDetectorOptions) {}

  public async detectToken(event: TokenUsageEvent, context: DetectorContext): Promise<Incident | null> {
    const current = {
      deviceId: event.deviceId ?? "unknown-device",
      uaHash: hashUserAgent(event.userAgent ?? ""),
      ipPrefix: toIpPrefix(event.ip),
    };

    const known = await context.store.getSessionFingerprint(event.sessionId);
    if (!known) {
      await context.store.setSessionFingerprint(event.sessionId, current, this.options.sessionTtlMs);
      return null;
    }

    const mismatch =
      known.deviceId !== current.deviceId ||
      known.uaHash !== current.uaHash ||
      known.ipPrefix !== current.ipPrefix;

    if (!mismatch) {
      return null;
    }

    await context.store.revokeSession(event.sessionId, this.options.revokeTtlMs);

    return {
      detectorId: this.id,
      attackType: "token_hijack",
      severity: "high",
      confidence: 0.93,
      action: "revoke_token",
      reason: `Session fingerprint mismatch for ${event.sessionId}. Possible token hijack.`,
      evidence: {
        sessionId: event.sessionId,
        known,
        current,
      },
      timestamp: context.now,
    };
  }
}
