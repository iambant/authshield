# AuthShield.js

Embeddable middleware for Node.js authentication protection.

## Install

```bash
npm i @yourname/auth-shield
```

## Quick start (TypeScript)

```ts
import express from "express";
import { authShield, preLoginGuard, postLoginReporter, tokenGuard, revokeHandler } from "@yourname/auth-shield";

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
});

app.post("/login", preLoginGuard(shield), loginHandler, postLoginReporter(shield));
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
  tokenGuard,
  revokeHandler,
} = require("@yourname/auth-shield");

const app = express();
app.use(express.json());

const shield = authShield({ mode: "enforce" });

app.post("/login", preLoginGuard(shield), loginHandler, postLoginReporter(shield));
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

## Main config options

- `mode`: `"monitor" | "enforce"`
- `redisUrl` or `redisClient`
- `loginRateLimit`: `windowMs`, `maxPerIp`, `maxPerIpAndUser`
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

## Runtime actions

- `allow`
- `challenge_login`
- `block_ip`
- `revoke_token`

## Notes

- Use only in controlled/lab environments.
- Intended for defensive security research and adversary simulation.
