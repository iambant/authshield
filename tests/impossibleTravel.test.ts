import { describe, expect, it } from "vitest";
import { ImpossibleTravelDetector } from "../src/detectors/impossibleTravel";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("ImpossibleTravelDetector", () => {
  it("triggers on fast ipPrefix shift after successful login", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new ImpossibleTravelDetector({
      minDeltaMs: 300_000,
      action: "challenge_login",
      stateTtlMs: 86_400_000,
    });

    const first = await detector.detectLogin(
      { ip: "203.0.113.4", username: "alice", success: true, userAgent: "ua-a", deviceId: "dev-a", timestamp: 1000 },
      { store, now: 1000 },
    );
    expect(first).toBeNull();

    const second = await detector.detectLogin(
      { ip: "198.51.100.9", username: "alice", success: true, userAgent: "ua-a", deviceId: "dev-a", timestamp: 2000 },
      { store, now: 2000 },
    );

    expect(second).not.toBeNull();
    expect(second?.attackType).toBe("impossible_travel");
  });

  it("does not trigger when travel delta is larger than threshold", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new ImpossibleTravelDetector({
      minDeltaMs: 10_000,
      action: "challenge_login",
      stateTtlMs: 86_400_000,
    });

    await detector.detectLogin(
      { ip: "203.0.113.4", username: "bob", success: true, userAgent: "ua-a", deviceId: "dev-a", timestamp: 1000 },
      { store, now: 1000 },
    );

    const result = await detector.detectLogin(
      { ip: "198.51.100.10", username: "bob", success: true, userAgent: "ua-a", deviceId: "dev-a", timestamp: 20_000 },
      { store, now: 20_000 },
    );

    expect(result).toBeNull();
  });
});
