import { describe, expect, it } from "vitest";
import { RegistrationBurstDetector } from "../src/detectors/registrationBurst";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("RegistrationBurstDetector", () => {
  it("triggers on high registration rate from one IP", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new RegistrationBurstDetector({
      windowMs: 60_000,
      attemptsThreshold: 3,
      action: "challenge_login",
    });

    await detector.detectRegistration(
      { ip: "203.0.113.50", success: false, timestamp: 1 },
      { store, now: 1 },
    );
    await detector.detectRegistration(
      { ip: "203.0.113.50", success: false, timestamp: 2 },
      { store, now: 2 },
    );

    const incident = await detector.detectRegistration(
      { ip: "203.0.113.50", success: true, timestamp: 3 },
      { store, now: 3 },
    );

    expect(incident).not.toBeNull();
    expect(incident?.attackType).toBe("registration_burst");
    expect(incident?.action).toBe("challenge_login");
  });
});
