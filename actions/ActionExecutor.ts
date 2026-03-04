import { Incident, AuthShieldMode } from "../types";
import { AuthShieldStore } from "../storage/store";

export interface ActionExecutorOptions {
  mode: AuthShieldMode;
  ipBlockDurationMs: number;
  sessionRevokeDurationMs: number;
}

export class ActionExecutor {
  public constructor(
    private readonly store: AuthShieldStore,
    private readonly options: ActionExecutorOptions,
  ) {}

  public async execute(incident: Incident): Promise<void> {
    if (this.options.mode !== "enforce") {
      return;
    }

    if (incident.action === "block_ip") {
      const ip = incident.evidence.ip;
      if (typeof ip === "string" && ip.length > 0) {
        await this.store.setIpBlock(ip, this.options.ipBlockDurationMs);
      }
      return;
    }

    if (incident.action === "revoke_token") {
      const sessionId = incident.evidence.sessionId;
      if (typeof sessionId === "string" && sessionId.length > 0) {
        await this.store.revokeSession(sessionId, this.options.sessionRevokeDurationMs);
      }
    }
  }
}
