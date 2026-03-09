import type { RequestHandler } from "express";
import { AuthShield } from "../core/AuthShield";

export function postLoginReporter(shield: AuthShield): RequestHandler {
  return shield.postLoginReporter();
}
