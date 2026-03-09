import type { RequestHandler } from "express";
import { AuthShield } from "../core/AuthShield";

export function postRegistrationReporter(shield: AuthShield): RequestHandler {
  return shield.postRegistrationReporter();
}
