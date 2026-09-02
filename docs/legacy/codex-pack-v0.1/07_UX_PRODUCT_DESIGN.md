# 07 - UX AND PRODUCT DESIGN

## Visual direction: Evidence Workbench

Do not copy EDY's previous “dark dashboard + neon cards” pattern and do not imitate GitGuardian's visual identity.

The product should feel like an investigation desk rather than a KPI dashboard.

### Primary composition

```text
┌──────────────────────────────────────────────────────────────────┐
│ EDY VERDICT   Target: setup.exe   Mode: HASH LOOKUP   Scan 0241 │
├───────────────┬─────────────────────────────────┬────────────────┤
│ SIGNAL SPINE  │        EVIDENCE CANVAS          │ CASE / ACTION  │
│               │                                 │ DRAWER          │
│ File identity │ Verdict + explanation           │                │
│ Signature     │ Evidence timeline               │ Remediation    │
│ Local engines │ Finding relationships           │ Verification   │
│ Intel         │ Unknown/coverage states         │ Report         │
│ Vulns         │                                 │                │
├───────────────┴─────────────────────────────────┴────────────────┤
│ Command/search dock • Rescan • Compare • Export • Provider state│
└──────────────────────────────────────────────────────────────────┘
```

## Signature elements

- **Signal Spine:** compact vertical list of scan stages/providers with truthful states.
- **Evidence Canvas:** central investigation surface, not a grid of unrelated cards.
- **Case Drawer:** finding lifecycle, remediation and audit context.
- **Verdict Strip:** persistent but restrained severity/confidence/coverage summary.
- **Compare mode:** before/after remediation.

## Required UI states

Every provider/component must support:

- queued;
- running;
- completed;
- completed with findings;
- not configured;
- unavailable;
- unsupported platform;
- rate limited;
- timed out;
- failed;
- cancelled.

Never use a green success indicator for “provider did not run.”

## Accessibility/usability

- keyboard navigation;
- sufficient contrast;
- no critical meaning carried by color alone;
- scalable type;
- selectable/copyable technical evidence;
- friendly executive explanation without hiding technical detail;
- explicit privacy mode shown during every connected scan.

## First-run experience

1. Explain local-first model.
2. Show available built-in/platform capabilities.
3. Offer Engine Manager setup.
4. Providers requiring keys are optional.
5. Do not block first use on account creation.
6. Offer a synthetic demo target separately from real scans, clearly labeled.
