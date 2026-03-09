import type { RequestHandler } from "express";
import { AuthShield } from "../core/AuthShield";

export function tokenGuard(shield: AuthShield): RequestHandler {
  return shield.tokenGuard();
}
