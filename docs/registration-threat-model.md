# Registration Threat Model Basis

AuthShield registration detectors are tuned for high-volume identity abuse patterns described by Microsoft security reporting.

## Sources

- Microsoft Digital Defense Report 2024: password-based identity attacks and sustained high automation pressure across identity surfaces.
  - https://www.microsoft.com/en-us/security/security-insider/intelligence-reports/microsoft-digital-defense-report-2024
- Microsoft Security Insider, "Bold Action Against Fraud: Disrupting Storm-1152" (December 2023): large-scale fraudulent account creation, CAPTCHA bypass tooling, and sale of fake accounts as a service.
  - https://www.microsoft.com/en-us/security/security-insider/risk-management/Bold-action-against-fraud-Disrupting-Storm-1152
- Disposable domain blocklist feed used by default for registration abuse detection:
  - https://github.com/disposable-email-domains/disposable-email-domains

## Mapping to detectors

- `RegistrationBurstDetector`
  - Purpose: detect bot-driven signup waves from one source IP.
  - Signal: fast growth of registration attempts in a fixed window.

- `DisposableEmailAbuseDetector`
  - Purpose: detect fake-account farming using disposable email domains.
  - Signal: repeated registration attempts with known disposable domains in a short window.

These defaults are conservative and should be adjusted per product baseline and geography.
