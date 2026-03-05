import { describe, expect, it } from "vitest";
import { SessionFixationDetector } from "../src/detectors/sessionFixation";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("SessionFixationDetector", () => {
  it("triggers when session id does not rotate on successful login", async () => {
    const detector = new SessionFixationDetector({ action: "revoke_token" });
    const store = new InMemoryAuthShieldStore();

    const result = await detector.detectLogin(
      {
        ip: "203.0.113.44",
        username: "alice",
        success: true,
        beforeSessionId: "sess-fixed",
        afterSessionId: "sess-fixed",
        timestamp: 123,
      },
      { store, now: 123 },
    );

    expect(result).not.toBeNull();
    expect(result?.attackType).toBe("session_fixation");
    expect(result?.action).toBe("revoke_token");
  });

  it("does not trigger when session id rotated", async () => {
    const detector = new SessionFixationDetector({ action: "revoke_token" });
    const store = new InMemoryAuthShieldStore();

    const result = await detector.detectLogin(
      {
        ip: "203.0.113.44",
        username: "alice",
        success: true,
        beforeSessionId: "sess-old",
        afterSessionId: "sess-new",
        timestamp: 123,
      },
      { store, now: 123 },
    );

    expect(result).toBeNull();
  });
});
