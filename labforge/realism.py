from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .model import LabSpec


class RealismModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class IndustryCapability(RealismModel):
    id: str
    description: str
    keywords: list[str] = Field(default_factory=list)
    required: bool = True
    min_keyword_matches: int = 1


class IndustryRealismProfile(RealismModel):
    industry: str
    display_name: str
    description: str
    required_zones: list[str] = Field(default_factory=list)
    capabilities: list[IndustryCapability] = Field(default_factory=list)
    common_technologies: list[str] = Field(default_factory=list)
    noise_expectations: list[str] = Field(default_factory=list)


class RealismFinding(RealismModel):
    severity: Literal["info", "warning", "error"]
    category: str
    message: str
    expected: str = ""


class RealismReport(RealismModel):
    lab_id: str
    industry: str
    status: Literal["passed", "warning", "failed"]
    profile: IndustryRealismProfile
    matched_capabilities: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    findings: list[RealismFinding] = Field(default_factory=list)


INDUSTRY_PROFILES: dict[str, IndustryRealismProfile] = {
    "enterprise": IndustryRealismProfile(
        industry="enterprise",
        display_name="General Enterprise IT",
        description="Generic corporate IT environment with public business apps, identity, internal servers, file/data services, and security monitoring.",
        required_zones=["public or internet edge", "dmz", "corporate", "data", "management", "security monitoring"],
        capabilities=[
            IndustryCapability(id="public-business-app", description="Public business web app, portal, VPN, or support entry point.", keywords=["portal", "vpn", "support", "web", "public", "hr"]),
            IndustryCapability(id="identity-directory", description="Directory, SSO, LDAP, AD, MFA, or identity service.", keywords=["ldap", "active-directory", "ad", "sso", "mfa", "identity", "directory"]),
            IndustryCapability(id="internal-application", description="Internal application, reporting server, intranet, or business system.", keywords=["internal", "reporting", "intranet", "application", "server"]),
            IndustryCapability(id="file-data-service", description="File server, document repository, archive, backup, or business data store.", keywords=["fileserver", "file", "archive", "backup", "document", "data"]),
            IndustryCapability(id="security-monitoring", description="Security monitoring, central logging, IDS, EDR, or audit trail.", keywords=["siem", "ids", "edr", "logging", "audit", "security"]),
        ],
        common_technologies=[
            "reverse proxy or WAF at public edge",
            "central identity directory",
            "segmented internal application network",
            "file server or document repository",
            "centralized logs and security monitoring",
        ],
        noise_expectations=[
            "business tickets, stale internal notes, routine login failures",
            "non-target maintenance runbooks and decoy files",
            "normal application and access logs",
        ],
    ),
    "securities": IndustryRealismProfile(
        industry="securities",
        display_name="Securities Firm / Brokerage",
        description="Brokerage, trading, market-data, settlement, compliance, and regulated customer-facing financial services.",
        required_zones=[
            "public or internet edge",
            "dmz",
            "application",
            "core trading",
            "data",
            "management",
            "security monitoring",
        ],
        capabilities=[
            IndustryCapability(
                id="public-investor-web",
                description="Public investor website, disclosure pages, notices, and support entry points.",
                keywords=["investor", "notice", "disclosure", "brokerage", "securities"],
                min_keyword_matches=1,
            ),
            IndustryCapability(
                id="customer-auth",
                description="Customer authentication, MFA, session, SSO, or identity gateway.",
                keywords=["customer auth", "customer login", "mfa", "sso", "identity gateway", "iam"],
                min_keyword_matches=1,
            ),
            IndustryCapability(
                id="trading-channel",
                description="Trading, order, quote, or brokerage channel used by customers or internal desks.",
                keywords=["trading", "order", "quote", "broker", "brokerage", "exchange", "oms"],
                min_keyword_matches=1,
            ),
            IndustryCapability(
                id="market-data",
                description="Market-data, price feed, quote feed, or data vendor integration.",
                keywords=["market data", "price feed", "quote feed", "ticker", "data-vendor"],
                min_keyword_matches=1,
            ),
            IndustryCapability(
                id="backoffice-settlement",
                description="Back-office, settlement, clearing, reconciliation, or account processing.",
                keywords=["settlement", "clearing", "reconciliation", "backoffice", "account processing"],
                min_keyword_matches=1,
            ),
            IndustryCapability(
                id="risk-compliance",
                description="Risk, compliance, audit, surveillance, AML, or regulatory reporting.",
                keywords=["risk", "compliance", "surveillance", "aml", "regulatory reporting"],
                min_keyword_matches=1,
            ),
            IndustryCapability(
                id="security-operations",
                description="SIEM, IDS, EDR, SOC, centralized logging, or fraud/security monitoring.",
                keywords=["siem", "ids", "edr", "soc", "fraud", "security monitoring"],
                min_keyword_matches=1,
            ),
            IndustryCapability(
                id="data-store",
                description="Database, warehouse, object storage, records archive, or ledger-like data store.",
                keywords=["database", "warehouse", "object-store", "ledger", "records store"],
                min_keyword_matches=1,
            ),
        ],
        common_technologies=[
            "WAF and reverse proxy at public edge",
            "API gateway for customer and partner channels",
            "message broker or event bus between trading/back-office systems",
            "relational database plus immutable audit/archive storage",
            "centralized logging and SIEM",
            "segmented core trading and data networks",
        ],
        noise_expectations=[
            "normal customer tickets, market notices, maintenance windows, stale runbooks",
            "benign trade operations logs, compliance alerts, failed login noise",
            "non-target internal systems such as HR, accounting, and vendor portals",
        ],
    ),
    "healthcare": IndustryRealismProfile(
        industry="healthcare",
        display_name="Healthcare Provider",
        description="Patient portal, EHR, imaging, billing, identity, and regulated clinical operations.",
        required_zones=["public edge", "dmz", "clinical", "administrative", "data", "security monitoring"],
        capabilities=[
            IndustryCapability(id="patient-portal", description="Patient-facing portal or appointment system.", keywords=["patient", "portal", "appointment"]),
            IndustryCapability(id="ehr", description="Electronic health record or clinical workflow system.", keywords=["ehr", "emr", "clinical", "record"]),
            IndustryCapability(id="billing", description="Billing, claims, or insurance integration.", keywords=["billing", "claims", "insurance"]),
            IndustryCapability(id="identity", description="Staff or patient identity and access control.", keywords=["identity", "auth", "sso", "mfa"]),
            IndustryCapability(id="audit", description="Audit, privacy, compliance, or access review.", keywords=["audit", "privacy", "hipaa", "compliance"]),
        ],
        common_technologies=["EHR integration engine", "HL7/FHIR API", "segmented clinical network", "centralized audit logging"],
        noise_expectations=["routine appointments, non-target departments, normal billing and clinical logs"],
    ),
    "manufacturing": IndustryRealismProfile(
        industry="manufacturing",
        display_name="Manufacturing / OT Enterprise",
        description="Corporate IT, production operations, MES, historian, engineering workstation, and segmented OT.",
        required_zones=["public edge", "corporate", "engineering", "ot", "data", "security monitoring"],
        capabilities=[
            IndustryCapability(id="corporate-entry", description="Corporate web, VPN, vendor, or helpdesk entry.", keywords=["portal", "vpn", "vendor", "helpdesk"]),
            IndustryCapability(id="mes", description="Manufacturing execution or production scheduling.", keywords=["mes", "production", "schedule"]),
            IndustryCapability(id="historian", description="Historian, telemetry, or plant data store.", keywords=["historian", "telemetry", "scada", "sensor"]),
            IndustryCapability(id="engineering", description="Engineering workstation, file share, or build/deploy workflow.", keywords=["engineering", "workstation", "plc", "recipe"]),
            IndustryCapability(id="monitoring", description="Security monitoring or operational monitoring.", keywords=["siem", "ids", "monitoring", "soc"]),
        ],
        common_technologies=["jump host into OT", "plant historian", "engineering file share", "segmented firewall between IT and OT"],
        noise_expectations=["maintenance tickets, production logs, vendor manuals, non-target plant assets"],
    ),
}


def list_realism_profiles() -> list[IndustryRealismProfile]:
    return list(INDUSTRY_PROFILES.values())


def get_realism_profile(industry: str) -> IndustryRealismProfile:
    key = normalize_industry(industry)
    if key not in INDUSTRY_PROFILES:
        known = ", ".join(sorted(INDUSTRY_PROFILES))
        raise ValueError(f"unknown realism industry `{industry}`. Available profiles: {known}")
    return INDUSTRY_PROFILES[key]


def check_realism(spec: LabSpec, *, industry: str | None = None, strict: bool = False) -> RealismReport:
    selected_industry = industry or spec.scenario.get("target_industry") or spec.scenario.get("industry") or ""
    findings: list[RealismFinding] = []
    if not selected_industry:
        profile = INDUSTRY_PROFILES["securities"]
        findings.append(
            RealismFinding(
                severity="warning",
                category="industry",
                message="No target industry is declared. Pass --industry or set scenario.target_industry.",
                expected="scenario.target_industry: securities",
            )
        )
    else:
        profile = get_realism_profile(str(selected_industry))

    haystack = lab_text_haystack(spec)
    matched: list[str] = []
    missing: list[str] = []
    for capability in profile.capabilities:
        keyword_matches = sum(1 for keyword in capability.keywords if keyword.lower() in haystack)
        if keyword_matches >= capability.min_keyword_matches:
            matched.append(capability.id)
        elif capability.required:
            missing.append(capability.id)
            findings.append(
                RealismFinding(
                    severity="error" if strict else "warning",
                    category="capability",
                    message=f"Missing industry capability: {capability.description}",
                    expected=", ".join(capability.keywords),
                )
            )

    zone_text = " ".join(str(zone.get("name", zone.get("id", ""))).lower() for zone in spec.environment.get("zones", []))
    network_text = " ".join(str(network.get("name", "")).lower() for network in spec.networks)
    zone_haystack = f"{zone_text} {network_text}"
    for zone in profile.required_zones:
        if not any(part in zone_haystack for part in zone.lower().split(" or ")):
            findings.append(
                RealismFinding(
                    severity="error" if strict else "warning",
                    category="zone",
                    message=f"Expected industry network/zone is not clearly represented: {zone}",
                    expected=zone,
                )
            )

    if len(spec.services) < max(4, len(profile.capabilities) // 2):
        findings.append(
            RealismFinding(
                severity="error" if strict else "warning",
                category="service-depth",
                message="Service count is low for the selected industry; the lab may feel like a CTF instead of an enterprise.",
                expected=f"At least {max(4, len(profile.capabilities) // 2)} meaningful services.",
            )
        )

    if spec.artifacts_model:
        for artifact in spec.artifacts_model.service_artifacts:
            if artifact.service in {"attacker-workstation", "controlled-drop"}:
                continue
            if not artifact.noise_inputs:
                findings.append(
                    RealismFinding(
                        severity="error" if strict else "warning",
                        category="noise",
                        message=f"Service `{artifact.service}` has no declared noise inputs.",
                        expected="Business records, logs, tickets, stale docs, or benign operational data.",
                    )
                )

    status: Literal["passed", "warning", "failed"]
    if any(finding.severity == "error" for finding in findings):
        status = "failed"
    elif findings:
        status = "warning"
    else:
        status = "passed"
    return RealismReport(
        lab_id=spec.lab_id,
        industry=profile.industry,
        status=status,
        profile=profile,
        matched_capabilities=matched,
        missing_capabilities=missing,
        findings=findings,
    )


def lab_text_haystack(spec: LabSpec) -> str:
    parts: list[str] = [
        json.dumps(spec.scenario, ensure_ascii=False),
        json.dumps(spec.topology, ensure_ascii=False),
        json.dumps(spec.stages, ensure_ascii=False),
        json.dumps(spec.environment, ensure_ascii=False),
        json.dumps(spec.artifacts, ensure_ascii=False),
    ]
    return " ".join(parts).lower()


def normalize_industry(value: str) -> str:
    lowered = value.strip().lower().replace("_", "-")
    aliases = {
        "brokerage": "securities",
        "financial": "securities",
        "finance": "securities",
        "stock-brokerage": "securities",
        "corporate": "enterprise",
        "general-enterprise": "enterprise",
        "enterprise-it": "enterprise",
        "health": "healthcare",
        "factory": "manufacturing",
        "ot": "manufacturing",
    }
    return aliases.get(lowered, lowered)


def realism_profiles_to_markdown() -> str:
    lines = [
        "# Realism Profiles",
        "",
        "| Industry | Display Name | Required Capabilities | Common Technologies |",
        "|---|---|---:|---:|",
    ]
    for profile in list_realism_profiles():
        lines.append(
            f"| `{profile.industry}` | {profile.display_name} | {len(profile.capabilities)} | {len(profile.common_technologies)} |"
        )
    lines.append("")
    return "\n".join(lines)


def realism_report_to_json(report: RealismReport) -> str:
    return json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n"


def realism_report_to_markdown(report: RealismReport) -> str:
    lines = [
        f"# Realism Report - {report.lab_id}",
        "",
        f"- Industry: `{report.industry}`",
        f"- Status: `{report.status}`",
        f"- Profile: {report.profile.display_name}",
        "",
        "## Capability Coverage",
        "",
        f"- Matched: {', '.join(f'`{item}`' for item in report.matched_capabilities) or '-'}",
        f"- Missing: {', '.join(f'`{item}`' for item in report.missing_capabilities) or '-'}",
        "",
        "## Expected Enterprise Texture",
        "",
        "### Common Technologies",
        "",
    ]
    lines.extend(f"- {item}" for item in report.profile.common_technologies)
    lines += [
        "",
        "### Noise Expectations",
        "",
    ]
    lines.extend(f"- {item}" for item in report.profile.noise_expectations)
    lines += [
        "",
        "## Findings",
        "",
        "| Severity | Category | Message | Expected |",
        "|---|---|---|---|",
    ]
    if not report.findings:
        lines.append("| info | - | No realism findings. | - |")
    for finding in report.findings:
        lines.append(f"| {finding.severity} | `{finding.category}` | {finding.message} | {finding.expected or '-'} |")
    lines.append("")
    return "\n".join(lines)


REALISM_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "realism-profile.schema.json": IndustryRealismProfile,
    "realism-report.schema.json": RealismReport,
}
