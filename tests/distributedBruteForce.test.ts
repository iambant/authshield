import { describe, expect, it } from "vitest";
import { DistributedBruteForceDetector } from "../src/detectors/distributedBruteForce";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("DistributedBruteForceDetector", () => {
  it("triggers when user fail count exceeds threshold", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new DistributedBruteForceDetector({
      windowMs: 60_000,
      failsThreshold: 3,
      action: "challenge_login",
    });

    await store.recordStuffingFailure("alice", "198.51.100.1", 60_000, 1000);
    await store.recordStuffingFailure("alice", "198.51.100.2", 60_000, 1001);
    await store.recordStuffingFailure("alice", "198.51.100.3", 60_000, 1002);

    const incident = await detector.detectLogin(
      { ip: "198.51.100.4", username: "alice", success: false, timestamp: 1003 },
      { store, now: 1003 },
    );

    expect(incident).not.toBeNull();
    expect(incident?.attackType).toBe("distributed_bruteforce");
  });

  it("does not trigger below threshold", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new DistributedBruteForceDetector({
      windowMs: 60_000,
      failsThreshold: 5,
      action: "challenge_login",
    });

    await store.recordStuffingFailure("alice", "198.51.100.1", 60_000, 1000);

    const incident = await detector.detectLogin(
      { ip: "198.51.100.4", username: "alice", success: false, timestamp: 1003 },
      { store, now: 1003 },
    );

    expect(incident).toBeNull();
  });
});
