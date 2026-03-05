import { describe, expect, it } from "vitest";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";
import { TokenReplayDetector } from "../src/detectors/tokenReplay";

describe("TokenReplayDetector sanity", () => {
  it("does not trigger when same fingerprint is reused", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new TokenReplayDetector({
      replayWindowMs: 5000,
      replayAction: "revoke_token",
      replayStateTtlMs: 60_000,
    });

    await detector.detectToken(
      { ip: "203.0.113.1", sessionId: "sess-1", userAgent: "ua-a", deviceId: "dev-a", timestamp: 1000 },
      { store, now: 1000 },
    );

    const result = await detector.detectToken(
      { ip: "203.0.113.1", sessionId: "sess-1", userAgent: "ua-a", deviceId: "dev-a", timestamp: 2000 },
      { store, now: 2000 },
    );

    expect(result).toBeNull();
  });
});
