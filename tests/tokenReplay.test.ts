import { describe, expect, it } from "vitest";
import { TokenReplayDetector } from "../src/detectors/tokenReplay";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("TokenReplayDetector", () => {
  it("triggers on different fingerprint within replay window", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new TokenReplayDetector({
      replayWindowMs: 10_000,
      replayAction: "revoke_token",
      replayStateTtlMs: 60_000,
    });

    const first = await detector.detectToken(
      { ip: "203.0.113.10", sessionId: "sess-1", userAgent: "ua-a", deviceId: "dev-a", timestamp: 1000 },
      { store, now: 1000 },
    );
    expect(first).toBeNull();

    const second = await detector.detectToken(
      { ip: "198.51.100.7", sessionId: "sess-1", userAgent: "ua-b", deviceId: "dev-b", timestamp: 6000 },
      { store, now: 6000 },
    );

    expect(second).not.toBeNull();
    expect(second?.attackType).toBe("token_replay");
    expect(second?.action).toBe("revoke_token");
  });

  it("does not trigger when fingerprint changed after replay window", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new TokenReplayDetector({
      replayWindowMs: 5000,
      replayAction: "revoke_token",
      replayStateTtlMs: 60_000,
    });

    await detector.detectToken(
      { ip: "203.0.113.10", sessionId: "sess-2", userAgent: "ua-a", deviceId: "dev-a", timestamp: 1000 },
      { store, now: 1000 },
    );

    const result = await detector.detectToken(
      { ip: "198.51.100.8", sessionId: "sess-2", userAgent: "ua-z", deviceId: "dev-z", timestamp: 8000 },
      { store, now: 8000 },
    );

    expect(result).toBeNull();
  });
});
