# Realism Profiles

LabForge labs must model the target company as a believable enterprise, not as
a generic CTF network with renamed services. A scenario targeting a securities
firm should look and behave like a brokerage or financial trading organization;
a healthcare scenario should look like a provider with patient, clinical,
billing, identity, and audit systems.

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

## Noise Requirement

Every meaningful service should include noise or normal business data. Examples:

- Benign tickets, stale documentation, and ordinary customer requests.
- Market notices, maintenance windows, and operational runbooks.
- Failed login noise, compliance alerts, and routine security telemetry.
- Non-target services such as HR, accounting, vendor portals, or internal wiki
  pages.

The goal is not to make the lab harder with random clutter. The goal is to make
the environment feel like a real company where the learner must distinguish
signal from normal business context.
