import { RequestHandler } from "express";
import { AuthShield } from "../core/AuthShield";

export function preLoginGuard(shield: AuthShield): RequestHandler {
  return shield.preLoginGuard();
}
