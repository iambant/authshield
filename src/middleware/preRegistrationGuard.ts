import type { RequestHandler } from "express";
import { AuthShield } from "../core/AuthShield";

export function preRegistrationGuard(shield: AuthShield): RequestHandler {
  return shield.preRegistrationGuard();
}
