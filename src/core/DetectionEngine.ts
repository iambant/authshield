import { LoginDetector, RegistrationDetector, TokenDetector } from "../detectors/types";
import { AuthShieldStore } from "../storage/store";
import { Incident, LoginAttemptEvent, RegistrationAttemptEvent, TokenUsageEvent } from "../types";

export class DetectionEngine {
  public constructor(
    private readonly loginDetectors: LoginDetector[],
    private readonly tokenDetectors: TokenDetector[],
    private readonly registrationDetectors: RegistrationDetector[],
    private readonly store: AuthShieldStore,
  ) {}

  public async evaluateLogin(event: LoginAttemptEvent): Promise<Incident[]> {
    const now = event.timestamp ?? Date.now();
    const incidents: Incident[] = [];

    for (const detector of this.loginDetectors) {
      const incident = await detector.detectLogin(event, { now, store: this.store });
      if (incident) {
        incidents.push(incident);
      }
    }

    return incidents;
  }

  public async evaluateToken(event: TokenUsageEvent): Promise<Incident[]> {
    const now = event.timestamp ?? Date.now();
    const incidents: Incident[] = [];

    for (const detector of this.tokenDetectors) {
      const incident = await detector.detectToken(event, { now, store: this.store });
      if (incident) {
        incidents.push(incident);
      }
    }

    return incidents;
  }

  public async evaluateRegistration(event: RegistrationAttemptEvent): Promise<Incident[]> {
    const now = event.timestamp ?? Date.now();
    const incidents: Incident[] = [];

    for (const detector of this.registrationDetectors) {
      const incident = await detector.detectRegistration(event, { now, store: this.store });
      if (incident) {
        incidents.push(incident);
      }
    }

    return incidents;
  }
}
