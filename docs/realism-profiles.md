# Realism Profiles and Industry Review

LabForge labs must model the target company as a believable enterprise, not as
a generic CTF network with renamed services. A scenario targeting a securities
firm should look and behave like a brokerage or financial trading organization;
a banking scenario should look like a digital banking, loan, account, payments,
fraud, AML, and compliance environment; a healthcare scenario should look like
a provider with patient, clinical, billing, identity, and audit systems.

`realism check` is a fast static pre-check. It scores the draft lab across
industry capabilities, zones, services, workflows, data/noise, security
controls, and attack-path realism. It is useful for catching obviously missing
zones, services, CTF-like labels, and noise data, but it is not the final
realism decision. A lab can contain enough keywords to pass a static check and
still feel fake when the UI, business workflows, data model, service behavior,
or security operations do not match the target industry.

Final realism review belongs to the `industry-realism-reviewer` specialist
agent. That agent must inspect the declared industry, infrastructure, services,
UI/source, seed data, noise data, security controls, and generated diagrams
before giving a pass, conditional pass, or fail verdict.

## Scenario Fields

Declare the target industry in `scenario.yaml`:

```yaml
target_industry: securities
target_organization_type: regional brokerage
realism_notes:
  - Public investor web and support channels are separate from core trading systems.
  - Customer authentication, order routing, market data, settlement, and compliance are represented.
  - Business noise includes market notices, routine failed logins, stale runbooks, and non-target tickets.
```

## Commands

List available profiles:

```powershell
python -m labforge realism profiles
```

Check a lab against a profile:

```powershell
python -m labforge realism check examples/scenario-02-ad-domain-compromise --industry enterprise
python -m labforge realism check examples/scenario-02-ad-domain-compromise --industry enterprise --strict
```

Write a report:

```powershell
python -m labforge realism check examples/my-lab --industry securities --out output/my-lab-realism.md
python -m labforge realism check examples/my-lab --industry securities --format json --out output/my-lab-realism.json
```

The report includes:

- `overall_score`: 0-100 supervisor-facing realism score.
- `score_breakdown.infrastructure`: network zones, trust boundaries, and
  service depth.
- `score_breakdown.services`: required industry capabilities and meaningful
  service coverage.
- `score_breakdown.workflows_ui`: whether the stages and visible workflows read
  like business operations rather than puzzle steps.
- `score_breakdown.data_noise`: business data, logs, tickets, documents, and
  benign operational records.
- `score_breakdown.security_controls`: monitoring, logging, segmentation, and
  control coverage.
- `score_breakdown.attack_path`: chain length, ATT&CK mapping texture, and
  absence of solver-facing shortcuts.
- `anti_ctf_signals`: terms such as `flag`, `ctf`, `foothold shell`, `exploit
  here`, or over-explicit CVE hints that should be rewritten as normal business
  or operations language.
- `findings[].remediation`: concrete guidance used by `design tasks` to create
  more specific fix tasks.

Status thresholds:

- `passed`: score is at least 85 and no blocking finding exists.
- `warning`: score is below 85 or non-blocking findings exist.
- `failed`: score is below 60 or strict/error findings exist.

Run the independent industry realism reviewer package:

```powershell
python -m labforge agents scaffold examples/my-lab --out output/my-lab-agents
python -m labforge agents run output/my-lab-agents --dry-run --adapter manual --agent industry-realism-reviewer --context-root examples/my-lab
```

The reviewer should not approve a lab merely because these commands pass.
Approval requires plausible industry-specific infrastructure, service behavior,
UI, workflows, data, monitoring, and operational noise.

## Anti-CTF Requirement

LabForge should not generate enterprise systems that speak directly to the
solver. Avoid UI labels, documents, routes, and seed data such as:

- `flag`, `submit flag`, `CTF`, `pwn`
- `foothold shell`
- `exploit here`
- direct answer text such as `password is ...`
- internal pages that name the exact CVE instead of exposing realistic version,
  configuration, and maintenance evidence

Use normal enterprise language instead: diagnostic console, evidence package,
controlled drop, access review, incident note, change ticket, stale runbook,
or vendor advisory.

## Enterprise Profile Expectations

A general enterprise lab should normally include:

- A public business entry point such as a portal, VPN, support site, or HR
  application.
- A directory or identity service such as Active Directory, LDAP, SSO, MFA, or
  an identity gateway.
- Internal applications such as reporting, intranet, business workflow, or
  operations consoles.
- File, archive, backup, document, or business-data services.
- Security monitoring such as central logging, SIEM, IDS, EDR, audit trails, or
  analyst-facing telemetry.

Use this profile for broad corporate IT scenarios such as Active Directory
domain compromise, helpdesk compromise, internal reporting compromise, or
corporate file collection.

## Securities Profile Expectations

A securities-firm lab should normally include:

- Public investor website, disclosure pages, support portal, or customer edge.
- Customer authentication, MFA, SSO, session management, or identity gateway.
- Trading, order, quote, brokerage, exchange, or order-management workflow.
- Market-data feed, quote feed, ticker data, or data-vendor integration.
- Back-office, settlement, clearing, reconciliation, or account processing.
- Risk, compliance, audit, surveillance, AML, or regulatory reporting.
- SIEM, IDS, EDR, SOC, logging, fraud, or centralized security monitoring.
- Databases, warehouse, object store, archive, ledger, or records store.

Network texture should include public edge, DMZ, application, core trading,
data, management, and security-monitoring zones. Docker-only prototypes may
represent these as Compose networks, but the logical architecture should still
match the industry.

## Banking Profile Expectations

A banking lab should normally include:

- Public online banking, mobile banking, loan application, support, or customer
  onboarding surface.
- Customer authentication, MFA, device trust, customer session management, or
  digital banking access gateway.
- Core account, deposit, balance, ledger, customer record, or core-banking
  adapter service.
- Loan origination, document intake, underwriting, servicing, or exception
  review workflow.
- Payment, ACH, wire, card, settlement, reconciliation, or batch processing
  service.
- Fraud monitoring, FDS, AML case review, suspicious activity, SAR, or
  transaction risk workflow.
- Compliance export, regulatory reporting, audit evidence, retention archive,
  or controlled suspicious-activity export.
- SOC, SIEM, EDR, IDS, access logging, and digital banking security telemetry.

Network texture should include public edge, DMZ, digital banking, core banking,
loan operations, payments, data, compliance, management, and
security-monitoring zones. A banking lab should not be treated as a brokerage
lab with labels changed. If the scenario involves loans or accounts, the
service behavior, UI, seed data, and noise should reflect loan cases, account
records, payments batches, fraud/AML queues, access logs, and compliance
exports rather than trading orders, market data, and settlement flows.

## Noise Requirement

Every meaningful service should include noise or normal business data. Examples:

- Benign tickets, stale documentation, and ordinary customer requests.
- Market notices, maintenance windows, and operational runbooks.
- Loan applications, document review queues, payment batch logs, AML case
  notes, suspicious-activity alerts, and digital banking login noise.
- Failed login noise, compliance alerts, and routine security telemetry.
- Non-target services such as HR, accounting, vendor portals, or internal wiki
  pages.

The goal is not to make the lab harder with random clutter. The goal is to make
the environment feel like a real company where the learner must distinguish
signal from normal business context.
