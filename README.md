# AuthShield.js

Embeddable middleware for Node.js authentication protection.

## Install

```bash
npm install authshield-js
```

## Repository

- GitHub: `https://github.com/iambant/authshield`
- Issues: `https://github.com/iambant/authshield/issues`

## Threat-informed defaults

Registration protection defaults are tuned for modern identity abuse patterns highlighted in Microsoft security reporting:

- high automation volume against identity surfaces
- bot-driven fake account creation waves
- disposable-email based account farming

See threat-model notes: `docs/registration-threat-model.md`.

## Quick start (TypeScript)

```ts
import express from "express";
import {
  authShield,
  preLoginGuard,
  postLoginReporter,
  preRegistrationGuard,
  postRegistrationReporter,
  tokenGuard,
  revokeHandler,
} from "authshield-js";

const app = express();
app.use(express.json());

const shield = authShield({
  redisUrl: process.env.REDIS_URL,
  mode: "enforce", // "monitor" or "enforce"
  loginRateLimit: {
    windowMs: 60_000,
    maxPerIp: 30,
    maxPerIpAndUser: 10,
  },
  captcha: {
    enabled: true,
    thresholdPerIpAndUser: 5,
    singleAsk: false,
    tokenField: "captchaToken",
  },
  onIncident: (incident) => {
    console.log("[authshield]", incident.attackType, incident.reason);
  },
  onDecision: ({ flow, decision }) => {
    if (flow === "login" && decision.action === "block_ip") {
      console.log("Security action:", decision.action);
    }
  },
});

app.post("/login", preLoginGuard(shield), loginHandler, postLoginReporter(shield));
app.post("/register", preRegistrationGuard(shield), registerHandler, postRegistrationReporter(shield));
app.get("/profile", tokenGuard(shield), profileHandler);
app.post("/logout", revokeHandler(shield));
```

If `postLoginReporter` is placed after `loginHandler`, call `next()` in `loginHandler` after sending the response.

## Quick start (JavaScript)

```js
const express = require("express");
const {
  authShield,
  preLoginGuard,
  postLoginReporter,
  preRegistrationGuard,
  postRegistrationReporter,
  tokenGuard,
  revokeHandler,
} = require("authshield-js");

const app = express();
app.use(express.json());

const shield = authShield({ mode: "enforce" });

app.post("/login", preLoginGuard(shield), loginHandler, postLoginReporter(shield));
app.post("/register", preRegistrationGuard(shield), registerHandler, postRegistrationReporter(shield));
app.get("/profile", tokenGuard(shield), profileHandler);
app.post("/logout", revokeHandler(shield));
```

AuthShield is written in TypeScript and distributed as JavaScript, so it works in plain JS Node.js projects.

## What it detects

- Brute force
- Password spraying
- Credential stuffing
- Account enumeration
- Phishing-like login anomalies
- Impossible travel (heuristic)
- Token hijack / token replay
- Session fixation
- Session fanout
- Success-after-fail burst
- Registration burst / fake account signup spikes
- Disposable-email signup abuse

## Main config options

- `mode`: `"monitor" | "enforce"`
- `redisUrl` or `redisClient`
- `loginRateLimit`: `windowMs`, `maxPerIp`, `maxPerIpAndUser`
- `registrationRateLimit`: `windowMs`, `maxPerIp`
- `captcha`: `enabled`, `thresholdPerIpAndUser`, `singleAsk`, `tokenField`, `verifyToken`
- `onIncident(incident)`
- `onDecision(payload)`
- `onLimitEvent(event, req)`
- `replayWindowMs`, `replayAction`
- `impossibleTravelMinDeltaMs`, `impossibleTravelAction`
- `enumWindowSec`, `enumUniqueUsersThreshold`, `enumFailsThreshold`, `enumAction`
- `fixationAction`
- `sessionFanoutWindowMs`, `sessionFanoutDistinctIpThreshold`, `sessionFanoutAction`
- `distributedFailWindowMs`, `distributedFailThreshold`, `distributedFailAction`
- `successAfterFailWindowMs`, `successAfterFailThreshold`, `successAfterFailAction`
- `registrationBurstWindowMs`, `registrationBurstThreshold`, `registrationBurstAction`
- `disposableEmailWindowMs`, `disposableEmailThreshold`, `disposableEmailAction`
- `registrationDisposableDomains` (defaults to upstream blocklist from `disposable-email-domains/disposable-email-domains`)
- `blockDisposableEmailOnRegistration` (instant pre-check at registration stage)

To refresh disposable domains list:

```bash
npm run update:disposable-domains
```

## Runtime actions

- `allow`
- `challenge_login`
- `block_ip`
- `revoke_token`

## Decision hooks for integrators

AuthShield can notify the host application about incidents and final decisions:

- `onIncident(incident)` is called for each detected incident.
- `onDecision(payload)` is called with the final decision for the current flow.

The final decision payload contains:

- `flow`: `pre_login_guard`, `login`, `pre_registration_guard`, `registration`, or `token`
- `decision.allowed`: whether the request was allowed by AuthShield
- `decision.action`: `allow`, `challenge_login`, `block_ip`, or `revoke_token`
- `decision.incidents`: the incidents that contributed to the decision

This hook is intended for application-specific reactions. AuthShield itself does not send notifications, disable users in your database, or call third-party APIs automatically. The integrator can use `decision.action` to trigger their own logic, for example:

- show an internal admin notification
- write to SIEM / audit log
- increment a fraud score in the application
- flag the account for manual review
- invoke a custom security workflow

Example:

```ts
const shield = authShield({
  mode: "enforce",
  onDecision: async ({ flow, event, decision }) => {
    if (flow === "login" && decision.action === "block_ip") {
      console.log("Blocked IP after login attack", event.ip);
    }

    if (flow === "token" && decision.action === "revoke_token") {
      console.log("Revoked suspicious session", event.sessionId);
    }
  },
});
```

If `postLoginReporter` or `postRegistrationReporter` is used after the application handler, the handler should call `next()` so AuthShield can compute and emit the final decision.

## Notes

- Use only in controlled/lab environments.
- Intended for defensive security research and adversary simulation.
