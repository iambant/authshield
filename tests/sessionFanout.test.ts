import { describe, expect, it } from "vitest";
import { SessionFanoutDetector } from "../src/detectors/sessionFanout";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("SessionFanoutDetector", () => {
  it("triggers when session appears from too many ip prefixes", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new SessionFanoutDetector({
      windowMs: 60_000,
      distinctIpPrefixThreshold: 3,
      action: "revoke_token",
    });

    await detector.detectToken(
      { ip: "203.0.113.10", sessionId: "sess-x", timestamp: 1 },
      { store, now: 1 },
    );
    await detector.detectToken(
      { ip: "198.51.100.20", sessionId: "sess-x", timestamp: 2 },
      { store, now: 2 },
    );
    const incident = await detector.detectToken(
      { ip: "192.0.2.30", sessionId: "sess-x", timestamp: 3 },
      { store, now: 3 },
    );

    expect(incident).not.toBeNull();
    expect(incident?.attackType).toBe("session_fanout");
  });

  it("does not trigger when threshold not reached", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new SessionFanoutDetector({
      windowMs: 60_000,
      distinctIpPrefixThreshold: 4,
      action: "revoke_token",
    });

    await detector.detectToken(
      { ip: "203.0.113.10", sessionId: "sess-y", timestamp: 1 },
      { store, now: 1 },
    );
    const incident = await detector.detectToken(
      { ip: "198.51.100.20", sessionId: "sess-y", timestamp: 2 },
      { store, now: 2 },
    );

    expect(incident).toBeNull();
  });
});
