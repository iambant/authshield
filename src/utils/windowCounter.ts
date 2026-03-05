export function withinWindow(timestamp: number, now: number, windowMs: number): boolean {
  return timestamp >= now - windowMs;
}
