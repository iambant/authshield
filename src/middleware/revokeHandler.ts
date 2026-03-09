import type { RequestHandler } from "express";
import { AuthShield } from "../core/AuthShield";

export function revokeHandler(shield: AuthShield): RequestHandler {
  return shield.revokeHandler();
}
