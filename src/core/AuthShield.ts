import { NextFunction, Request, RequestHandler, Response } from "express";
import Redis from "ioredis";
import { ActionExecutor } from "../actions/ActionExecutor";
import { AccountEnumerationDetector } from "../detectors/accountEnumeration";
import { BruteForceDetector } from "../detectors/bruteForce";
import { DistributedBruteForceDetector } from "../detectors/distributedBruteForce";
import { ImpossibleTravelDetector } from "../detectors/impossibleTravel";
import { SessionFixationDetector } from "../detectors/sessionFixation";
import { SessionFanoutDetector } from "../detectors/sessionFanout";
import { SuccessAfterFailBurstDetector } from "../detectors/successAfterFailBurst";
import { StuffingDetector } from "../detectors/stuffing";
import { SprayDetector } from "../detectors/spray";
import { TokenHijackDetector } from "../detectors/tokenHijack";
import { TokenReplayDetector } from "../detectors/tokenReplay";
import { PhishingHeuristicsDetector } from "../detectors/phishingHeuristics";
import { ConsoleIncidentLogger, IncidentLogger } from "../logging/IncidentLogger";
import { InMemoryAuthShieldStore } from "../storage/inMemory";
import { RedisAuthShieldStore } from "../storage/redis";
import { AuthShieldStore } from "../storage/store";
import { randomDeviceId } from "../utils/fingerprint";
import { DetectionEngine } from "./DetectionEngine";
import {
  ActionType,
  AuthShieldMode,
  Incident,
  LoginAttemptEvent,
  MitigationDecision,
  TokenUsageEvent,
} from "../types";

export interface AuthShieldConfig {
  redisUrl?: string;
  redisClient?: Redis;
  keyPrefix?: string;
  mode?: AuthShieldMode;
  ipBlockDurationMs?: number;
  tokenRevokeDurationMs?: number;
  sessionTtlMs?: number;
  deviceCookieName?: string;
  extractors?: {
    getIp?: (req: Request) => string;
    getUsername?: (req: Request) => string;
    getSessionId?: (req: Request) => string | null;
    getDeviceId?: (req: Request, res: Response) => string;
  };
  logger?: IncidentLogger;
  onIncident?: (incident: Incident) => void | Promise<void>;
  onDecision?: (payload: DecisionPayload) => void | Promise<void>;
  consoleLog?: boolean;
  loginRateLimit?: {
    windowMs?: number;
    maxPerIp?: number;
    maxPerIpAndUser?: number;
  };
  captcha?: {
    enabled?: boolean;
    thresholdPerIpAndUser?: number;
    singleAsk?: boolean;
    tokenField?: string;
    verifyToken?: (token: string, req: Request) => boolean | Promise<boolean>;
  };
  replayWindowMs?: number;
  replayAction?: "revoke_token" | "challenge_login";
  impossibleTravelMinDeltaMs?: number;
  impossibleTravelAction?: "challenge_login" | "block_ip" | "revoke_token";
  enumWindowSec?: number;
  enumUniqueUsersThreshold?: number;
  enumFailsThreshold?: number;
  enumAction?: "block_ip" | "challenge_login";
  fixationAction?: "revoke_token" | "challenge_login";
  distributedFailWindowMs?: number;
  distributedFailThreshold?: number;
  distributedFailAction?: "challenge_login" | "block_ip";
  sessionFanoutWindowMs?: number;
  sessionFanoutDistinctIpThreshold?: number;
  sessionFanoutAction?: "revoke_token" | "challenge_login";
  successAfterFailWindowMs?: number;
  successAfterFailThreshold?: number;
  successAfterFailAction?: "challenge_login" | "block_ip";
  onLimitEvent?: (
    event: LimitEvent,
    req: Request,
  ) => LimitHandlerResult | undefined | Promise<LimitHandlerResult | undefined>;
}

export interface DecisionPayload {
  flow: "pre_login_guard" | "login" | "token";
  event: Partial<LoginAttemptEvent & TokenUsageEvent>;
  decision: MitigationDecision;
}

export type LimitEventType =
  | "rate_limit_ip"
  | "rate_limit_ip_user"
  | "captcha_required"
  | "ip_blocked";

export interface LimitEvent {
  type: LimitEventType;
  ip: string;
  username?: string;
  defaultAction: ActionType;
  defaultStatus: number;
  defaultBody: Record<string, unknown>;
  retryAfterSec?: number;
}

export interface LimitHandlerResult {
  allow?: boolean;
  action?: ActionType;
  status?: number;
  body?: Record<string, unknown>;
  headers?: Record<string, string>;
}

const defaultExtractors = {
  getIp: (req: Request): string => req.ip || req.socket.remoteAddress || "unknown",
  getUsername: (req: Request): string => String(req.body?.username ?? "").trim(),
  getSessionId: (req: Request): string | null => {
    const auth = req.get("authorization");
    if (!auth) {
      const fromHeader = req.get("x-session-id");
      return fromHeader ? fromHeader.trim() : null;
    }
    if (!auth.toLowerCase().startsWith("bearer ")) {
      return null;
    }
    return auth.slice(7).trim();
  },
};

export class AuthShield {
  private readonly mode: AuthShieldMode;
  private readonly ipBlockDurationMs: number;
  private readonly tokenRevokeDurationMs: number;
  private readonly sessionTtlMs: number;
  private readonly deviceCookieName: string;
  private readonly loginRateLimit: {
    windowMs: number;
    maxPerIp: number;
    maxPerIpAndUser: number;
  };
  private readonly captcha: {
    enabled: boolean;
    thresholdPerIpAndUser: number;
    singleAsk: boolean;
    tokenField: string;
    verifyToken?: (token: string, req: Request) => boolean | Promise<boolean>;
  };
  private readonly getIp: (req: Request) => string;
  private readonly getUsername: (req: Request) => string;
  private readonly getSessionId: (req: Request) => string | null;
  private readonly getDeviceId: (req: Request, res: Response) => string;
  private readonly onIncident?: (incident: Incident) => void | Promise<void>;
  private readonly onDecision?: (payload: DecisionPayload) => void | Promise<void>;
  private readonly onLimitEvent?: (
    event: LimitEvent,
    req: Request,
  ) => LimitHandlerResult | undefined | Promise<LimitHandlerResult | undefined>;

  public constructor(
    private readonly store: AuthShieldStore,
    private readonly engine: DetectionEngine,
    private readonly actions: ActionExecutor,
    private readonly logger: IncidentLogger,
    config: AuthShieldConfig,
  ) {
    this.mode = config.mode ?? "enforce";
    this.ipBlockDurationMs = config.ipBlockDurationMs ?? 10 * 60 * 1000;
    this.tokenRevokeDurationMs = config.tokenRevokeDurationMs ?? 24 * 60 * 60 * 1000;
    this.sessionTtlMs = config.sessionTtlMs ?? 24 * 60 * 60 * 1000;
    this.deviceCookieName = config.deviceCookieName ?? "ash_device_id";
    this.loginRateLimit = {
      windowMs: config.loginRateLimit?.windowMs ?? 60_000,
      maxPerIp: config.loginRateLimit?.maxPerIp ?? 30,
      maxPerIpAndUser: config.loginRateLimit?.maxPerIpAndUser ?? 10,
    };
    this.captcha = {
      enabled: config.captcha?.enabled ?? false,
      thresholdPerIpAndUser: config.captcha?.thresholdPerIpAndUser ?? 5,
      singleAsk: config.captcha?.singleAsk ?? false,
      tokenField: config.captcha?.tokenField ?? "captchaToken",
      verifyToken: config.captcha?.verifyToken,
    };

    this.getIp = config.extractors?.getIp ?? defaultExtractors.getIp;
    this.getUsername = config.extractors?.getUsername ?? defaultExtractors.getUsername;
    this.getSessionId = config.extractors?.getSessionId ?? defaultExtractors.getSessionId;
    this.getDeviceId =
      config.extractors?.getDeviceId ??
      ((req: Request, res: Response) => this.resolveDeviceId(req, res, true));
    this.onIncident = config.onIncident;
    this.onDecision = config.onDecision;
    this.onLimitEvent = config.onLimitEvent;
  }

  public preLoginGuard(): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const ip = this.getIp(req);
      const username = this.getUsername(req);
      const now = Date.now();

      const ipRateCount = await this.store.incrementWindowCounter(
        `login:ip:${ip}`,
        this.loginRateLimit.windowMs,
        now,
      );
      if (ipRateCount > this.loginRateLimit.maxPerIp) {
        const handled = await this.handleLimitEvent(req, res, {
          type: "rate_limit_ip",
          ip,
          username,
          defaultAction: "challenge_login",
          defaultStatus: 429,
          defaultBody: {
            error: "Too many login attempts from this IP",
            code: "AUTHSHIELD_RATE_LIMIT_IP",
          },
          retryAfterSec: Math.ceil(this.loginRateLimit.windowMs / 1000),
        });
        if (!handled) {
          next();
        }
        return;
      }

      if (username) {
        if (await this.store.isUserChallenged(username)) {
          const handled = await this.handleLimitEvent(req, res, {
            type: "rate_limit_ip_user",
            ip,
            username,
            defaultAction: "challenge_login",
            defaultStatus: 403,
            defaultBody: {
              error: "Additional verification required for this account",
              code: "AUTHSHIELD_LOGIN_CHALLENGE",
            },
          });
          if (!handled) {
            next();
          }
          return;
        }

        const pairRateCount = await this.store.incrementWindowCounter(
          `login:ip_user:${ip}:${username}`,
          this.loginRateLimit.windowMs,
          now,
        );

        if (this.captcha.enabled && pairRateCount > this.captcha.thresholdPerIpAndUser) {
          const rawToken = req.body?.[this.captcha.tokenField] ?? req.get("x-captcha-token");
          const captchaToken = typeof rawToken === "string" ? rawToken.trim() : "";
          const tokenIsValid = this.captcha.verifyToken
            ? await this.captcha.verifyToken(captchaToken, req)
            : captchaToken === "demo-captcha-pass";

          if (!tokenIsValid) {
            if (this.captcha.singleAsk) {
              const askCount = await this.store.incrementWindowCounter(
                `captcha:ask:${ip}:${username}`,
                this.loginRateLimit.windowMs,
                now,
              );
              if (askCount > 1) {
                // singleAsk mode: challenge only once per window for the pair.
              } else {
                const handled = await this.handleLimitEvent(req, res, {
                  type: "captcha_required",
                  ip,
                  username,
                  defaultAction: "challenge_login",
                  defaultStatus: 403,
                  defaultBody: {
                    error: "Captcha required",
                    code: "AUTHSHIELD_CAPTCHA_REQUIRED",
                    captchaRequired: true,
                    captcha: {
                      provider: "mock",
                      tokenField: this.captcha.tokenField,
                      verifyEndpoint: "/captcha/verify",
                    },
                  },
                });
                if (!handled) {
                  next();
                }
                return;
              }
            } else {
            const handled = await this.handleLimitEvent(req, res, {
              type: "captcha_required",
              ip,
              username,
              defaultAction: "challenge_login",
              defaultStatus: 403,
              defaultBody: {
                error: "Captcha required",
                code: "AUTHSHIELD_CAPTCHA_REQUIRED",
                captchaRequired: true,
                captcha: {
                  provider: "mock",
                  tokenField: this.captcha.tokenField,
                  verifyEndpoint: "/captcha/verify",
                },
              },
            });
            if (!handled) {
              next();
            }
            return;
            }
          }
        }

        if (pairRateCount > this.loginRateLimit.maxPerIpAndUser) {
          const handled = await this.handleLimitEvent(req, res, {
            type: "rate_limit_ip_user",
            ip,
            username,
            defaultAction: "challenge_login",
            defaultStatus: 429,
            defaultBody: {
              error: "Too many attempts for this account from one IP",
              code: "AUTHSHIELD_RATE_LIMIT_IP_USER",
            },
            retryAfterSec: Math.ceil(this.loginRateLimit.windowMs / 1000),
          });
          if (!handled) {
            next();
          }
          return;
        }
      }

      if (await this.store.isIpBlocked(ip)) {
        const handled = await this.handleLimitEvent(req, res, {
          type: "ip_blocked",
          ip,
          username,
          defaultAction: "block_ip",
          defaultStatus: 429,
          defaultBody: {
            error: "Access temporarily blocked by AuthShield",
            code: "AUTHSHIELD_IP_BLOCKED",
          },
        });
        if (!handled) {
          next();
        }
        return;
      }
      next();
    };
  }

  public postLoginReporter(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction): void => {
      const beforeSessionId = this.getSessionId(req) ?? req.get("x-session-id-before") ?? undefined;
      let responseBody: unknown = undefined;
      const originalJson = res.json.bind(res);
      res.json = ((body: unknown) => {
        responseBody = body;
        return originalJson(body);
      }) as Response["json"];

      res.on("finish", async () => {
        const username = this.getUsername(req);
        if (!username) {
          return;
        }

        const success = res.statusCode >= 200 && res.statusCode < 300;
        const afterSessionId = this.extractPostLoginSessionId(req, res, responseBody);
        const event: LoginAttemptEvent = {
          ip: this.getIp(req),
          username,
          success,
          userAgent: req.get("user-agent") ?? undefined,
          deviceId: this.resolveDeviceId(req, res, false),
          sessionId: afterSessionId ?? this.getSessionId(req) ?? undefined,
          beforeSessionId,
          afterSessionId,
          timestamp: Date.now(),
        };

        try {
          await this.reportLogin(event);
        } catch (error) {
          console.error("AuthShield postLoginReporter error", error);
        }
      });

      next();
    };
  }

  public tokenGuard(): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const sessionId = this.getSessionId(req);
      if (!sessionId) {
        next();
        return;
      }

      if (await this.store.isSessionRevoked(sessionId)) {
        res.status(401).json({ error: "Session revoked", code: "AUTHSHIELD_SESSION_REVOKED" });
        return;
      }

      const event: TokenUsageEvent = {
        ip: this.getIp(req),
        sessionId,
        deviceId: this.getDeviceId(req, res),
        userAgent: req.get("user-agent") ?? undefined,
        timestamp: Date.now(),
      };

      const decision = await this.reportTokenUsage(event);
      if (!decision.allowed && this.mode === "enforce") {
        const status = decision.action === "revoke_token" ? 401 : 403;
        res.status(status).json({
          error: "Token rejected by AuthShield",
          action: decision.action,
          incidents: decision.incidents,
        });
        return;
      }

      next();
    };
  }

  public revokeHandler(): RequestHandler {
    return async (req: Request, res: Response): Promise<void> => {
      const sessionId = this.getSessionId(req) ?? String(req.body?.sessionId ?? "").trim();
      if (!sessionId) {
        res.status(400).json({ error: "sessionId is required" });
        return;
      }

      await this.store.revokeSession(sessionId, this.tokenRevokeDurationMs);
      res.json({ ok: true, revoked: sessionId });
    };
  }

  public async reportLogin(event: LoginAttemptEvent): Promise<MitigationDecision> {
    const incidents = await this.engine.evaluateLogin(event);
    const decision = await this.handleIncidents(incidents);
    await this.emitDecision({ flow: "login", event, decision });
    return decision;
  }

  public async reportTokenUsage(event: TokenUsageEvent): Promise<MitigationDecision> {
    const incidents = await this.engine.evaluateToken(event);
    const decision = await this.handleIncidents(incidents);
    await this.emitDecision({ flow: "token", event, decision });
    return decision;
  }

  private async handleIncidents(incidents: ReturnType<DetectionEngine["evaluateLogin"]> extends Promise<infer T> ? T : never): Promise<MitigationDecision> {
    for (const incident of incidents) {
      await this.logger.log(incident);
      if (this.onIncident) {
        await this.onIncident(incident);
      }
      await this.actions.execute(incident);
    }

    const topAction = this.pickAction(incidents);
    return {
      allowed: topAction === "allow" || this.mode === "monitor",
      action: topAction,
      incidents,
    };
  }

  private pickAction(incidents: { action: ActionType }[]): ActionType {
    if (incidents.some((incident) => incident.action === "revoke_token")) {
      return "revoke_token";
    }
    if (incidents.some((incident) => incident.action === "block_ip")) {
      return "block_ip";
    }
    if (incidents.some((incident) => incident.action === "challenge_login")) {
      return "challenge_login";
    }
    return "allow";
  }

  private resolveDeviceId(req: Request, res: Response, allowSetCookie: boolean): string {
    const fromHeader = req.get("x-device-id");
    if (fromHeader && fromHeader.trim()) {
      return fromHeader.trim();
    }

    const cookieHeader = req.get("cookie") ?? "";
    const key = `${this.deviceCookieName}=`;
    const existing = cookieHeader
      .split(";")
      .map((chunk) => chunk.trim())
      .find((chunk) => chunk.startsWith(key));

    if (existing) {
      return decodeURIComponent(existing.slice(key.length));
    }

    const generated = randomDeviceId();
    if (allowSetCookie) {
      res.append("Set-Cookie", `${this.deviceCookieName}=${generated}; Path=/; HttpOnly; SameSite=Lax`);
    }
    return generated;
  }

  private async emitDecision(payload: DecisionPayload): Promise<void> {
    if (!this.onDecision) {
      return;
    }
    await this.onDecision(payload);
  }

  private extractPostLoginSessionId(req: Request, res: Response, responseBody: unknown): string | undefined {
    const fromExtractor = this.getSessionId(req);
    if (fromExtractor) {
      return fromExtractor;
    }

    const fromHeader = res.getHeader("x-session-id");
    if (typeof fromHeader === "string" && fromHeader.trim()) {
      return fromHeader.trim();
    }

    if (responseBody && typeof responseBody === "object") {
      const body = responseBody as Record<string, unknown>;
      const token = body.token;
      if (typeof token === "string" && token.trim()) {
        return token.trim();
      }
      const sessionId = body.sessionId;
      if (typeof sessionId === "string" && sessionId.trim()) {
        return sessionId.trim();
      }
    }

    return undefined;
  }

  private async handleLimitEvent(req: Request, res: Response, event: LimitEvent): Promise<boolean> {
    const handlerResult = this.onLimitEvent ? await this.onLimitEvent(event, req) : undefined;

    if (handlerResult?.allow) {
      await this.emitDecision({
        flow: "pre_login_guard",
        event: { ip: event.ip, username: event.username },
        decision: {
          allowed: true,
          action: "allow",
          incidents: [],
        },
      });
      return false;
    }

    const action = handlerResult?.action ?? event.defaultAction;
    const status = handlerResult?.status ?? event.defaultStatus;
    const body = handlerResult?.body ?? event.defaultBody;

    if (event.retryAfterSec) {
      res.setHeader("Retry-After", String(event.retryAfterSec));
    }
    if (handlerResult?.headers) {
      for (const [key, value] of Object.entries(handlerResult.headers)) {
        res.setHeader(key, value);
      }
    }

    await this.emitDecision({
      flow: "pre_login_guard",
      event: { ip: event.ip, username: event.username },
      decision: {
        allowed: false,
        action,
        incidents: [],
      },
    });

    res.status(status).json(body);
    return true;
  }
}

export function authShield(config: AuthShieldConfig = {}): AuthShield {
  const mode = config.mode ?? "enforce";
  const store =
    config.redisClient || config.redisUrl
      ? new RedisAuthShieldStore(config.redisClient ?? new Redis(config.redisUrl as string), {
          keyPrefix: config.keyPrefix,
        })
      : new InMemoryAuthShieldStore();

  const engine = new DetectionEngine(
    [
      new BruteForceDetector({ windowMs: 10 * 60 * 1000, attemptsThreshold: 12, action: "block_ip" }),
      new SprayDetector({ windowMs: 10 * 60 * 1000, distinctUsersThreshold: 8, minAttemptsThreshold: 12 }),
      new AccountEnumerationDetector({
        windowMs: (config.enumWindowSec ?? 600) * 1000,
        uniqueUsersThreshold: config.enumUniqueUsersThreshold ?? 8,
        failsThreshold: config.enumFailsThreshold ?? 12,
        failRatioThreshold: 0.8,
        action: config.enumAction ?? "block_ip",
      }),
      new DistributedBruteForceDetector({
        windowMs: config.distributedFailWindowMs ?? 10 * 60 * 1000,
        failsThreshold: config.distributedFailThreshold ?? 15,
        action: config.distributedFailAction ?? "challenge_login",
      }),
      new StuffingDetector({ windowMs: 10 * 60 * 1000, attemptsThreshold: 8, distinctIpsThreshold: 4 }),
      new PhishingHeuristicsDetector({
        recentFailWindowMs: 10 * 60 * 1000,
        failThreshold: 3,
        fingerprintWindowMs: 7 * 24 * 60 * 60 * 1000,
      }),
      new SuccessAfterFailBurstDetector({
        windowMs: config.successAfterFailWindowMs ?? 10 * 60 * 1000,
        failThreshold: config.successAfterFailThreshold ?? 8,
        action: config.successAfterFailAction ?? "challenge_login",
      }),
      new ImpossibleTravelDetector({
        minDeltaMs: config.impossibleTravelMinDeltaMs ?? 5 * 60 * 1000,
        action: config.impossibleTravelAction ?? "challenge_login",
        stateTtlMs: 30 * 24 * 60 * 60 * 1000,
      }),
      new SessionFixationDetector({
        action: config.fixationAction ?? "revoke_token",
      }),
    ],
    [
      new TokenReplayDetector({
        replayWindowMs: config.replayWindowMs ?? 8_000,
        replayAction: config.replayAction ?? "revoke_token",
        replayStateTtlMs: 24 * 60 * 60 * 1000,
      }),
      new SessionFanoutDetector({
        windowMs: config.sessionFanoutWindowMs ?? 60_000,
        distinctIpPrefixThreshold: config.sessionFanoutDistinctIpThreshold ?? 3,
        action: config.sessionFanoutAction ?? "revoke_token",
      }),
      new TokenHijackDetector({
        sessionTtlMs: config.sessionTtlMs ?? 24 * 60 * 60 * 1000,
        revokeTtlMs: config.tokenRevokeDurationMs ?? 24 * 60 * 60 * 1000,
      }),
    ],
    store,
  );

  const logger = config.logger ?? (config.consoleLog === false ? { log: async () => {} } : new ConsoleIncidentLogger());
  const actions = new ActionExecutor(store, {
    mode,
    ipBlockDurationMs: config.ipBlockDurationMs ?? 10 * 60 * 1000,
    sessionRevokeDurationMs: config.tokenRevokeDurationMs ?? 24 * 60 * 60 * 1000,
    challengeDurationMs: config.loginRateLimit?.windowMs ?? 60_000,
  });

  return new AuthShield(store, engine, actions, logger, config);
}
