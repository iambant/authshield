import { describe, expect, it } from "vitest";
import { DisposableEmailAbuseDetector } from "../src/detectors/disposableEmailAbuse";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("DisposableEmailAbuseDetector", () => {
  it("triggers when disposable domain attempts exceed threshold", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new DisposableEmailAbuseDetector({
      windowMs: 60_000,
      attemptsThreshold: 2,
      disposableDomains: ["mailinator.com"],
      action: "block_ip",
    });

    await detector.detectRegistration(
      {
        ip: "198.51.100.80",
        email: "a@mailinator.com",
        success: true,
        timestamp: 1,
      },
      { store, now: 1 },
    );

    const incident = await detector.detectRegistration(
      {
        ip: "198.51.100.80",
        email: "b@mailinator.com",
        success: true,
        timestamp: 2,
      },
      { store, now: 2 },
    );

    expect(incident).not.toBeNull();
    expect(incident?.attackType).toBe("disposable_email_abuse");
    expect(incident?.action).toBe("block_ip");
  });

  it("does not trigger for non-disposable domains", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new DisposableEmailAbuseDetector({
      windowMs: 60_000,
      attemptsThreshold: 1,
      disposableDomains: ["mailinator.com"],
    });

    const incident = await detector.detectRegistration(
      {
        ip: "198.51.100.81",
        email: "user@gmail.com",
        success: true,
        timestamp: 10,
      },
      { store, now: 10 },
    );

    expect(incident).toBeNull();
  });
});
