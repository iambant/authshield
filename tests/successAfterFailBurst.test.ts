import { describe, expect, it } from "vitest";
import { SuccessAfterFailBurstDetector } from "../src/detectors/successAfterFailBurst";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("SuccessAfterFailBurstDetector", () => {
  it("triggers on successful login after fail burst", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new SuccessAfterFailBurstDetector({
      windowMs: 60_000,
      failThreshold: 3,
      action: "challenge_login",
    });

    await store.recordStuffingFailure("bob", "198.51.100.1", 60_000, 1000);
    await store.recordStuffingFailure("bob", "198.51.100.2", 60_000, 1001);
    await store.recordStuffingFailure("bob", "198.51.100.3", 60_000, 1002);

    const incident = await detector.detectLogin(
      { ip: "198.51.100.4", username: "bob", success: true, timestamp: 1003 },
      { store, now: 1003 },
    );

    expect(incident).not.toBeNull();
    expect(incident?.attackType).toBe("success_after_fail_burst");
  });

  it("does not trigger on success without enough fails", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new SuccessAfterFailBurstDetector({
      windowMs: 60_000,
      failThreshold: 5,
      action: "challenge_login",
    });

    await store.recordStuffingFailure("bob", "198.51.100.1", 60_000, 1000);

    const incident = await detector.detectLogin(
      { ip: "198.51.100.4", username: "bob", success: true, timestamp: 1003 },
      { store, now: 1003 },
    );

    expect(incident).toBeNull();
  });
});
