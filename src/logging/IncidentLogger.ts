import { Incident } from "../types";

export interface IncidentLogger {
  log(incident: Incident): Promise<void>;
}

export class ConsoleIncidentLogger implements IncidentLogger {
  public async log(incident: Incident): Promise<void> {
    const payload = {
      type: incident.attackType,
      detector: incident.detectorId,
      severity: incident.severity,
      confidence: incident.confidence,
      action: incident.action,
      reason: incident.reason,
      evidence: incident.evidence,
      timestamp: incident.timestamp,
    };

    // Structured JSON log for SIEM ingestion.
    console.log(JSON.stringify({ authshield_incident: payload }));
  }
}
