import { Incident, LoginAttemptEvent } from "../types";
import { SlidingWindowStore } from "../store/Store";

export interface DetectorContext {
  store: SlidingWindowStore;
  now: number;
}

export interface Detector {
  id: string;
  detect(event: LoginAttemptEvent, context: DetectorContext): Promise<Incident | null>;
}
