import { describe, expect, it } from "vitest";
import { AccountEnumerationDetector } from "../src/detectors/accountEnumeration";
import { InMemoryAuthShieldStore } from "../src/storage/inMemory";

describe("AccountEnumerationDetector", () => {
  it("triggers when unique usernames and failures exceed threshold", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new AccountEnumerationDetector({
      windowMs: 60_000,
      uniqueUsersThreshold: 4,
      failsThreshold: 4,
      failRatioThreshold: 0.8,
      action: "block_ip",
    });

    const usernames = ["u1", "u2", "u3", "u4", "u5"];
    let incident = null;

    for (let i = 0; i < usernames.length; i += 1) {
      incident = await detector.detectLogin(
        {
          ip: "203.0.113.30",
          username: usernames[i],
          success: false,
          timestamp: 1000 + i,
        },
        { store, now: 1000 + i },
      );
    }

    expect(incident).not.toBeNull();
    expect(incident?.attackType).toBe("account_enumeration");
    expect(incident?.action).toBe("block_ip");
  });

  it("does not trigger when fail ratio is low", async () => {
    const store = new InMemoryAuthShieldStore();
    const detector = new AccountEnumerationDetector({
      windowMs: 60_000,
      uniqueUsersThreshold: 3,
      failsThreshold: 3,
      failRatioThreshold: 0.8,
      action: "block_ip",
    });

    await detector.detectLogin(
      { ip: "203.0.113.31", username: "u1", success: false, timestamp: 1 },
      { store, now: 1 },
    );
    await detector.detectLogin(
      { ip: "203.0.113.31", username: "u2", success: true, timestamp: 2 },
      { store, now: 2 },
    );
    const result = await detector.detectLogin(
      { ip: "203.0.113.31", username: "u3", success: true, timestamp: 3 },
      { store, now: 3 },
    );

    expect(result).toBeNull();
  });
});
