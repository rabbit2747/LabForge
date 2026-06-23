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
    recommended_services: list[str] = Field(default_factory=list)
    recommended_zones: list[str] = Field(default_factory=list)
    recommended_data: list[str] = Field(default_factory=list)
    recommended_workflows: list[str] = Field(default_factory=list)


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
    code: str = ""
    remediation: str = ""


class RealismScoreBreakdown(RealismModel):
    infrastructure: int = 0
    services: int = 0
    workflows_ui: int = 0
    data_noise: int = 0
    security_controls: int = 0
    attack_path: int = 0


class AntiCtfSignal(RealismModel):
    term: str
    category: str
    reason: str


class RealismReport(RealismModel):
    lab_id: str
    industry: str
    status: Literal["passed", "warning", "failed"]
    profile: IndustryRealismProfile
    overall_score: int = 0
    score_breakdown: RealismScoreBreakdown = Field(default_factory=RealismScoreBreakdown)
    matched_capabilities: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    anti_ctf_signals: list[AntiCtfSignal] = Field(default_factory=list)
    findings: list[RealismFinding] = Field(default_factory=list)


INDUSTRY_PROFILES: dict[str, IndustryRealismProfile] = {
    "enterprise": IndustryRealismProfile(
        industry="enterprise",
        display_name="General Enterprise IT",
        description="Generic corporate IT environment with public business apps, identity, internal servers, file/data services, and security monitoring.",
        required_zones=["public or internet edge", "dmz", "corporate", "data", "management", "security monitoring"],
        capabilities=[
            IndustryCapability(id="public-business-app", description="Public business web app, portal, VPN, or support entry point.", keywords=["portal", "vpn", "support", "web", "public", "hr"], recommended_services=["edge-proxy", "public-portal"], recommended_zones=["public or internet edge", "dmz"], recommended_workflows=["external user authentication and ticket/request submission"]),
            IndustryCapability(id="identity-directory", description="Directory, SSO, LDAP, AD, MFA, or identity service.", keywords=["ldap", "active-directory", "ad", "sso", "mfa", "identity", "directory"], recommended_services=["identity-provider", "directory-service"], recommended_zones=["management", "corporate"], recommended_data=["users", "groups", "service accounts"]),
            IndustryCapability(id="internal-application", description="Internal application, reporting server, intranet, or business system.", keywords=["internal", "reporting", "intranet", "application", "server"], recommended_services=["intranet", "reporting-app"], recommended_zones=["corporate", "application"], recommended_workflows=["employee-only business workflow"]),
            IndustryCapability(id="file-data-service", description="File server, document repository, archive, backup, or business data store.", keywords=["fileserver", "file", "archive", "backup", "document", "data"], recommended_services=["document-store", "records-archive"], recommended_zones=["data"], recommended_data=["business documents", "archive records", "backup metadata"]),
            IndustryCapability(id="security-monitoring", description="Security monitoring, central logging, IDS, EDR, or audit trail.", keywords=["siem", "ids", "edr", "logging", "audit", "security"], recommended_services=["siem", "log-forwarder", "ids-sensor"], recommended_zones=["security monitoring"], recommended_data=["audit logs", "security alerts"]),
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
                recommended_services=["investor-portal", "public-disclosure-site", "support-portal"],
                recommended_zones=["public or internet edge", "dmz"],
                recommended_workflows=["customer notices", "support request intake", "public disclosure browsing"],
            ),
            IndustryCapability(
                id="customer-auth",
                description="Customer authentication, MFA, session, SSO, or identity gateway.",
                keywords=["customer auth", "customer login", "customer-identity", "mfa", "sso", "identity gateway", "identity-gateway", "iam"],
                min_keyword_matches=1,
                recommended_services=["customer-identity-gateway", "session-service", "mfa-service"],
                recommended_zones=["dmz", "application"],
                recommended_data=["customer sessions", "MFA events", "identity audit trail"],
                recommended_workflows=["customer login", "session refresh", "MFA challenge"],
            ),
            IndustryCapability(
                id="trading-channel",
                description="Trading, order, quote, or brokerage channel used by customers or internal desks.",
                keywords=["trading", "order", "quote", "broker", "brokerage", "exchange", "oms"],
                min_keyword_matches=1,
                recommended_services=["order-management-system", "quote-api", "dealer-workstation"],
                recommended_zones=["application", "core trading"],
                recommended_data=["orders", "quotes", "execution reports"],
                recommended_workflows=["order entry", "quote lookup", "trade status review"],
            ),
            IndustryCapability(
                id="market-data",
                description="Market-data, price feed, quote feed, or data vendor integration.",
                keywords=["market data", "price feed", "quote feed", "ticker", "data-vendor"],
                min_keyword_matches=1,
                recommended_services=["market-data-gateway", "quote-cache", "vendor-feed-adapter"],
                recommended_zones=["core trading", "data"],
                recommended_data=["ticker snapshots", "price feed logs", "vendor feed credentials"],
                recommended_workflows=["market data subscription", "quote refresh", "feed health check"],
            ),
            IndustryCapability(
                id="backoffice-settlement",
                description="Back-office, settlement, clearing, reconciliation, or account processing.",
                keywords=["settlement", "clearing", "reconciliation", "backoffice", "account processing"],
                min_keyword_matches=1,
                recommended_services=["settlement-service", "reconciliation-batch", "clearing-adapter"],
                recommended_zones=["application", "data"],
                recommended_data=["settlement batches", "clearing files", "account records"],
                recommended_workflows=["end-of-day settlement", "reconciliation exception review"],
            ),
            IndustryCapability(
                id="risk-compliance",
                description="Risk, compliance, audit, surveillance, AML, or regulatory reporting.",
                keywords=["risk", "compliance", "surveillance", "aml", "regulatory reporting"],
                min_keyword_matches=1,
                recommended_services=["trade-surveillance", "risk-dashboard", "compliance-export-service"],
                recommended_zones=["application", "data"],
                recommended_data=["surveillance alerts", "regulatory export objects", "audit evidence"],
                recommended_workflows=["compliance export approval", "trade surveillance review"],
            ),
            IndustryCapability(
                id="security-operations",
                description="SIEM, IDS, EDR, SOC, centralized logging, or fraud/security monitoring.",
                keywords=["siem", "ids", "edr", "soc", "fraud", "security monitoring"],
                min_keyword_matches=1,
                recommended_services=["siem", "fraud-monitor", "edr-management"],
                recommended_zones=["security monitoring"],
                recommended_data=["security events", "fraud alerts", "EDR telemetry"],
            ),
            IndustryCapability(
                id="data-store",
                description="Database, warehouse, object storage, records archive, or ledger-like data store.",
                keywords=["database", "warehouse", "object-store", "ledger", "records store"],
                min_keyword_matches=1,
                recommended_services=["trade-data-warehouse", "records-archive", "object-store"],
                recommended_zones=["data"],
                recommended_data=["customer records", "trade history", "compliance exports"],
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
    "banking": IndustryRealismProfile(
        industry="banking",
        display_name="Retail / Commercial Banking",
        description="Digital banking, loan operations, deposit/account systems, payments, fraud monitoring, AML, compliance, and security operations.",
        required_zones=[
            "public or internet edge",
            "dmz",
            "digital banking",
            "core banking",
            "loan operations",
            "payments",
            "data",
            "compliance",
            "management",
            "security monitoring",
        ],
        capabilities=[
            IndustryCapability(
                id="public-banking-channel",
                description="Public banking website, online-banking entry, loan application portal, or customer support surface.",
                keywords=["bank", "banking", "loan", "deposit", "customer portal", "online banking", "mobile banking"],
                min_keyword_matches=1,
                recommended_services=["public-bank-site", "loan-application-portal", "customer-support-portal"],
                recommended_zones=["public or internet edge", "dmz"],
                recommended_workflows=["loan application intake", "customer support request", "public banking notice browsing"],
            ),
            IndustryCapability(
                id="customer-identity",
                description="Customer identity, MFA, device trust, session, or digital banking access gateway.",
                keywords=["mfa", "identity", "device", "session", "customer auth", "login", "access gateway"],
                min_keyword_matches=1,
                recommended_services=["customer-identity-gateway", "mfa-service", "device-trust-service"],
                recommended_zones=["dmz", "digital banking"],
                recommended_data=["customer sessions", "MFA events", "device fingerprints", "login audit trail"],
                recommended_workflows=["customer login", "device enrollment", "step-up authentication"],
            ),
            IndustryCapability(
                id="core-account-ledger",
                description="Core account, deposit, balance, ledger, account profile, or customer record system.",
                keywords=["core banking", "account", "deposit", "ledger", "balance", "customer record"],
                min_keyword_matches=1,
                recommended_services=["core-account-service", "deposit-ledger", "customer-record-service"],
                recommended_zones=["core banking", "data"],
                recommended_data=["account metadata", "ledger entries", "customer records"],
                recommended_workflows=["balance lookup", "account profile review", "ledger reconciliation"],
            ),
            IndustryCapability(
                id="loan-operations",
                description="Loan origination, document intake, underwriting, case review, or servicing workflow.",
                keywords=["loan", "underwriting", "document intake", "case review", "servicing", "collateral"],
                min_keyword_matches=1,
                recommended_services=["document-intake-service", "loan-ops-console", "underwriting-workflow"],
                recommended_zones=["digital banking", "loan operations", "data"],
                recommended_data=["loan applications", "uploaded evidence documents", "underwriting notes"],
                recommended_workflows=["application review", "document verification", "exception approval"],
            ),
            IndustryCapability(
                id="payments-batch",
                description="Payment, ACH, wire, card, settlement, reconciliation, or overnight batch processing.",
                keywords=["payment", "payments", "ach", "wire", "card", "settlement", "reconciliation", "batch"],
                min_keyword_matches=1,
                recommended_services=["payments-batch-service", "wire-transfer-adapter", "reconciliation-batch"],
                recommended_zones=["payments", "core banking", "data"],
                recommended_data=["payment batches", "reconciliation exceptions", "wire transfer metadata"],
                recommended_workflows=["payment batch release", "wire review", "reconciliation exception handling"],
            ),
            IndustryCapability(
                id="fraud-aml-monitoring",
                description="Fraud detection, FDS, AML, suspicious activity review, case queue, or transaction monitoring.",
                keywords=["fraud", "fds", "aml", "suspicious activity", "sar", "transaction monitoring"],
                min_keyword_matches=1,
                recommended_services=["fraud-monitoring-service", "aml-case-system", "transaction-risk-engine"],
                recommended_zones=["security monitoring", "compliance", "data"],
                recommended_data=["fraud alerts", "AML case notes", "suspicious activity indicators"],
                recommended_workflows=["fraud alert triage", "AML case review", "SAR evidence export"],
            ),
            IndustryCapability(
                id="compliance-reporting",
                description="Compliance export, audit evidence, regulatory reporting, SAR package, or retention archive.",
                keywords=["compliance", "audit", "regulatory", "sar", "export", "retention", "evidence"],
                min_keyword_matches=1,
                recommended_services=["compliance-export-service", "audit-evidence-store", "regulatory-reporting"],
                recommended_zones=["compliance", "data"],
                recommended_data=["regulatory exports", "audit packages", "retention metadata"],
                recommended_workflows=["compliance export approval", "regulatory evidence review"],
            ),
            IndustryCapability(
                id="bank-security-operations",
                description="SOC, SIEM, EDR, IDS, access monitoring, or digital banking security telemetry.",
                keywords=["siem", "soc", "edr", "ids", "security monitoring", "access log"],
                min_keyword_matches=1,
                recommended_services=["siem", "edr-management", "digital-banking-access-log"],
                recommended_zones=["security monitoring"],
                recommended_data=["access logs", "security alerts", "endpoint telemetry", "network detections"],
            ),
        ],
        common_technologies=[
            "WAF and reverse proxy at the public banking edge",
            "API gateway for online/mobile banking and loan channels",
            "customer identity gateway with MFA and device/session telemetry",
            "core banking adapter or synthetic ledger service",
            "batch scheduler for payments and reconciliation",
            "fraud detection/FDS and AML case review services",
            "central SIEM, access logging, and segmented banking networks",
        ],
        noise_expectations=[
            "routine loan applications, document review queues, and stale branch operations runbooks",
            "benign login failures, device trust events, customer support cases, and online banking notices",
            "payment batch logs, reconciliation exceptions, fraud alerts, AML review notes, and SOC telemetry",
            "non-target systems such as HR, vendor risk, branch inventory, and marketing content",
        ],
    ),
    "healthcare": IndustryRealismProfile(
        industry="healthcare",
        display_name="Healthcare Provider",
        description="Patient portal, EHR, imaging, billing, identity, and regulated clinical operations.",
        required_zones=["public edge", "dmz", "clinical", "administrative", "data", "security monitoring"],
        capabilities=[
            IndustryCapability(id="patient-portal", description="Patient-facing portal or appointment system.", keywords=["patient", "portal", "appointment"], recommended_services=["patient-portal", "appointment-api"], recommended_zones=["public edge", "dmz"], recommended_data=["appointments", "patient messages"]),
            IndustryCapability(id="ehr", description="Electronic health record or clinical workflow system.", keywords=["ehr", "emr", "clinical", "record"], recommended_services=["ehr-gateway", "clinical-workflow"], recommended_zones=["clinical", "data"], recommended_data=["encounters", "orders", "clinical notes"]),
            IndustryCapability(id="billing", description="Billing, claims, or insurance integration.", keywords=["billing", "claims", "insurance"], recommended_services=["claims-adapter", "billing-portal"], recommended_zones=["administrative"], recommended_data=["claims", "insurance eligibility"]),
            IndustryCapability(id="identity", description="Staff or patient identity and access control.", keywords=["identity", "auth", "sso", "mfa"], recommended_services=["staff-sso", "patient-identity"], recommended_zones=["administrative", "clinical"], recommended_data=["roles", "access reviews"]),
            IndustryCapability(id="audit", description="Audit, privacy, compliance, or access review.", keywords=["audit", "privacy", "hipaa", "compliance"], recommended_services=["privacy-audit", "access-review"], recommended_zones=["security monitoring"], recommended_data=["access audit trail", "privacy alerts"]),
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
            IndustryCapability(id="corporate-entry", description="Corporate web, VPN, vendor, or helpdesk entry.", keywords=["portal", "vpn", "vendor", "helpdesk"], recommended_services=["vendor-portal", "helpdesk", "edge-proxy"], recommended_zones=["public edge", "corporate"], recommended_workflows=["vendor ticket intake", "maintenance request"]),
            IndustryCapability(id="mes", description="Manufacturing execution or production scheduling.", keywords=["mes", "production", "schedule"], recommended_services=["mes", "production-scheduler"], recommended_zones=["ot", "data"], recommended_data=["work orders", "production schedules"], recommended_workflows=["work order release", "line status review"]),
            IndustryCapability(id="historian", description="Historian, telemetry, or plant data store.", keywords=["historian", "telemetry", "scada", "sensor"], recommended_services=["plant-historian", "telemetry-collector"], recommended_zones=["ot", "data"], recommended_data=["sensor readings", "tag history"]),
            IndustryCapability(id="engineering", description="Engineering workstation, file share, or build/deploy workflow.", keywords=["engineering", "workstation", "plc", "recipe"], recommended_services=["engineering-workstation", "recipe-share", "plc-jumpbox"], recommended_zones=["engineering", "ot"], recommended_data=["PLC projects", "recipes", "engineering change notes"]),
            IndustryCapability(id="monitoring", description="Security monitoring or operational monitoring.", keywords=["siem", "ids", "monitoring", "soc"], recommended_services=["ot-ids", "siem", "plant-monitoring"], recommended_zones=["security monitoring"], recommended_data=["network alerts", "process alarms"]),
        ],
        common_technologies=["jump host into OT", "plant historian", "engineering file share", "segmented firewall between IT and OT"],
        noise_expectations=["maintenance tickets, production logs, vendor manuals, non-target plant assets"],
    ),
    "active-directory": IndustryRealismProfile(
        industry="active-directory",
        display_name="Active Directory Enterprise",
        description="Windows domain, identity, endpoint, file, application, and monitoring environment for enterprise intrusion labs.",
        required_zones=["public edge", "workstation", "server", "domain services", "data", "security monitoring"],
        capabilities=[
            IndustryCapability(id="domain-controller", description="Windows domain controller, Kerberos, LDAP, DNS, or Group Policy.", keywords=["domain controller", "kerberos", "ldap", "dns", "gpo", "group policy"], recommended_services=["domain-controller", "dns", "ldap"], recommended_zones=["domain services"], recommended_data=["users", "groups", "SPNs", "GPOs"]),
            IndustryCapability(id="windows-workstations", description="Domain-joined user workstations or VDI clients.", keywords=["workstation", "windows", "domain joined", "vdi"], recommended_services=["windows-workstation", "helpdesk-workstation"], recommended_zones=["workstation"], recommended_data=["user profiles", "browser history", "endpoint logs"]),
            IndustryCapability(id="member-servers", description="Domain member servers such as IIS, MSSQL, file server, or app server.", keywords=["member server", "iis", "mssql", "file server", "app server"], recommended_services=["iis-app", "mssql", "file-server"], recommended_zones=["server", "data"], recommended_data=["shares", "service configs", "application logs"]),
            IndustryCapability(id="identity-operations", description="Helpdesk, IAM, password reset, privileged access, or admin workstation workflow.", keywords=["helpdesk", "iam", "password reset", "admin workstation", "privileged"], recommended_services=["helpdesk-portal", "pam-console"], recommended_zones=["management"], recommended_workflows=["password reset", "access request approval"]),
            IndustryCapability(id="windows-monitoring", description="Windows Event Forwarding, SIEM, EDR, or domain audit telemetry.", keywords=["wef", "event log", "siem", "edr", "audit"], recommended_services=["wef-collector", "siem", "edr-management"], recommended_zones=["security monitoring"], recommended_data=["event logs", "EDR alerts", "audit policy"]),
        ],
        common_technologies=["Domain Controller", "Kerberos/LDAP/DNS", "Windows workstations", "file shares", "SIEM/EDR telemetry"],
        noise_expectations=["ordinary logon events, helpdesk tickets, GPO notes, stale shares, routine admin activity"],
    ),
    "supply-chain": IndustryRealismProfile(
        industry="supply-chain",
        display_name="Software Supply Chain / Vendor Enterprise",
        description="Vendor software development, build, signing, release, update, and customer integration environment.",
        required_zones=["public edge", "corporate", "development", "build", "release", "customer", "security monitoring"],
        capabilities=[
            IndustryCapability(id="support-entry", description="Support portal, customer ticketing, docs, or public vendor channel.", keywords=["support", "ticket", "docs", "customer portal"], recommended_services=["support-portal", "public-docs"], recommended_zones=["public edge", "corporate"], recommended_workflows=["customer support ticket review"]),
            IndustryCapability(id="source-control", description="Source repository, code review, or developer collaboration.", keywords=["git", "repo", "source", "pull request", "code review"], recommended_services=["source-repo", "code-review"], recommended_zones=["development"], recommended_data=["branches", "commits", "review comments"]),
            IndustryCapability(id="build-pipeline", description="Build server, CI, artifact store, or package registry.", keywords=["build", "ci", "artifact", "package", "registry"], recommended_services=["build-server", "artifact-store"], recommended_zones=["build"], recommended_data=["build jobs", "artifact metadata"]),
            IndustryCapability(id="signing-release", description="Signing service, manifest, release channel, or update server.", keywords=["signing", "manifest", "release", "update", "channel"], recommended_services=["signing-service", "update-server", "release-console"], recommended_zones=["release"], recommended_data=["signed manifests", "release approvals"]),
            IndustryCapability(id="customer-integration", description="Customer agent, tenant, integration endpoint, or downstream update consumer.", keywords=["customer", "agent", "tenant", "integration", "poll"], recommended_services=["customer-agent", "customer-api"], recommended_zones=["customer"], recommended_data=["tenant config", "customer exports"]),
            IndustryCapability(id="release-monitoring", description="Build/release audit, security monitoring, or detection telemetry.", keywords=["audit", "siem", "logging", "monitoring", "edr"], recommended_services=["release-audit", "siem"], recommended_zones=["security monitoring"], recommended_data=["build logs", "release audit events"]),
        ],
        common_technologies=["source control", "CI/build server", "artifact store", "signing service", "update channel", "customer agent"],
        noise_expectations=["routine builds, failed test runs, release notes, customer tickets, stale runbooks, non-target channels"],
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
                    code="industry.missing",
                    remediation="Set scenario.target_industry to a supported industry and rerun the realism check.",
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
                    code=f"capability.{capability.id}.missing",
                    remediation=capability_remediation(capability),
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
                    code=f"zone.{slug_part(zone)}.missing",
                    remediation=f"Add an explicit `{zone}` zone/network and place at least one relevant service there.",
                )
            )

    if len(spec.services) < max(4, len(profile.capabilities) // 2):
        findings.append(
            RealismFinding(
                severity="error" if strict else "warning",
                category="service-depth",
                message="Service count is low for the selected industry; the lab may feel like a CTF instead of an enterprise.",
                expected=f"At least {max(4, len(profile.capabilities) // 2)} meaningful services.",
                code="services.too-shallow",
                remediation="Add role-specific services, background systems, and at least one non-target business service so the environment has enterprise texture.",
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
                        code=f"noise.{artifact.service}.missing",
                        remediation=f"Add seed data, benign logs, stale documents, or routine tickets for `{artifact.service}`.",
                    )
                )

    anti_ctf_signals = detect_anti_ctf_signals(haystack)
    for signal in anti_ctf_signals:
        findings.append(
            RealismFinding(
                severity="warning",
                category="anti-ctf",
                message=f"CTF-like wording detected: {signal.term}",
                expected="Use normal business, operations, or security-team language instead of solver-facing labels.",
                code=f"anti-ctf.{slug_part(signal.term)}",
                remediation=f"Rewrite `{signal.term}` as a normal internal term. Reason: {signal.reason}",
            )
        )

    score_breakdown = calculate_realism_scores(
        spec,
        profile=profile,
        matched_capabilities=matched,
        missing_capabilities=missing,
        anti_ctf_signals=anti_ctf_signals,
        findings=findings,
    )
    overall_score = round(
        (
            score_breakdown.infrastructure
            + score_breakdown.services
            + score_breakdown.workflows_ui
            + score_breakdown.data_noise
            + score_breakdown.security_controls
            + score_breakdown.attack_path
        )
        / 6
    )

    status: Literal["passed", "warning", "failed"]
    if any(finding.severity == "error" for finding in findings) or overall_score < 60:
        status = "failed"
    elif findings or overall_score < 85:
        status = "warning"
    else:
        status = "passed"
    return RealismReport(
        lab_id=spec.lab_id,
        industry=profile.industry,
        status=status,
        profile=profile,
        overall_score=overall_score,
        score_breakdown=score_breakdown,
        matched_capabilities=matched,
        missing_capabilities=missing,
        anti_ctf_signals=anti_ctf_signals,
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


def capability_remediation(capability: IndustryCapability) -> str:
    parts = [f"Add the `{capability.id}` capability as a normal business function."]
    if capability.recommended_services:
        parts.append(f"Recommended services: {', '.join(capability.recommended_services)}.")
    if capability.recommended_zones:
        parts.append(f"Place it in zones: {', '.join(capability.recommended_zones)}.")
    if capability.recommended_data:
        parts.append(f"Seed realistic data: {', '.join(capability.recommended_data)}.")
    if capability.recommended_workflows:
        parts.append(f"Represent workflows: {', '.join(capability.recommended_workflows)}.")
    return " ".join(parts)


def detect_anti_ctf_signals(haystack: str) -> list[AntiCtfSignal]:
    signals = [
        ("flag", "solver-language", "The word usually exposes the challenge objective instead of a business object."),
        ("ctf", "solver-language", "The scenario should read like an enterprise lab, not a game."),
        ("foothold shell", "solver-language", "Real systems do not label an operator console as a foothold."),
        ("exploit here", "solver-language", "The UI or documents should not tell the learner where to exploit."),
        ("pwn", "solver-language", "Use normal incident, admin, or application wording."),
        ("admin password", "credential-leak", "Credentials should be discovered through realistic logs, vault references, tickets, or misconfiguration."),
        ("password is", "credential-leak", "Avoid direct answer text in business documents."),
        ("submit flag", "solver-language", "Use controlled drop or evidence submission language."),
        ("cve-", "over-explicit-hint", "Internal documents should usually expose versions and behavior, not the exact exploit label."),
    ]
    found: list[AntiCtfSignal] = []
    for term, category, reason in signals:
        if term in haystack:
            found.append(AntiCtfSignal(term=term, category=category, reason=reason))
    return found


def calculate_realism_scores(
    spec: LabSpec,
    *,
    profile: IndustryRealismProfile,
    matched_capabilities: list[str],
    missing_capabilities: list[str],
    anti_ctf_signals: list[AntiCtfSignal],
    findings: list[RealismFinding],
) -> RealismScoreBreakdown:
    zone_score = ratio_score(count_represented_zones(spec, profile), len(profile.required_zones))
    service_depth_score = min(100, round((len(spec.services) / max(4, len(profile.capabilities))) * 100))
    capability_score = ratio_score(len(matched_capabilities), len(profile.capabilities))
    workflow_score = workflow_realism_score(spec)
    data_score = data_noise_score(spec)
    security_score = security_realism_score(spec, matched_capabilities)
    attack_score = attack_path_realism_score(spec, anti_ctf_signals)
    if any(finding.category == "anti-ctf" for finding in findings):
        workflow_score = max(0, workflow_score - 10)
        attack_score = max(0, attack_score - 15)
    if missing_capabilities:
        service_depth_score = max(0, service_depth_score - min(30, len(missing_capabilities) * 5))
    return RealismScoreBreakdown(
        infrastructure=round((zone_score * 0.65) + (service_depth_score * 0.35)),
        services=round((capability_score * 0.75) + (service_depth_score * 0.25)),
        workflows_ui=workflow_score,
        data_noise=data_score,
        security_controls=security_score,
        attack_path=attack_score,
    )


def count_represented_zones(spec: LabSpec, profile: IndustryRealismProfile) -> int:
    zone_text = " ".join(str(zone.get("name", zone.get("id", ""))).lower() for zone in spec.environment.get("zones", []))
    network_text = " ".join(str(network.get("name", "")).lower() for network in spec.networks)
    zone_haystack = f"{zone_text} {network_text}"
    count = 0
    for zone in profile.required_zones:
        if any(part in zone_haystack for part in zone.lower().split(" or ")):
            count += 1
    return count


def workflow_realism_score(spec: LabSpec) -> int:
    stages = spec.stage_list
    if not stages:
        return 20
    text = json.dumps(stages, ensure_ascii=False).lower()
    business_terms = ["approval", "ticket", "review", "workflow", "request", "operator", "analyst", "manager", "audit", "report"]
    technical_terms = ["mitre", "credential", "session", "internal", "service", "api", "log", "query", "build", "publish"]
    business_hits = sum(1 for term in business_terms if term in text)
    technical_hits = sum(1 for term in technical_terms if term in text)
    base = min(80, 30 + len(stages) * 8)
    return min(100, base + min(10, business_hits * 2) + min(10, technical_hits * 2))


def data_noise_score(spec: LabSpec) -> int:
    artifact_count = 0
    noisy_services = 0
    if spec.artifacts_model:
        for artifact in spec.artifacts_model.service_artifacts:
            artifact_count += 1
            if artifact.noise_inputs:
                noisy_services += 1
    raw = json.dumps(spec.artifacts, ensure_ascii=False).lower()
    data_terms = ["log", "ticket", "record", "archive", "audit", "export", "report", "customer", "order", "patient", "sensor"]
    term_hits = sum(1 for term in data_terms if term in raw)
    if artifact_count:
        return min(100, round((noisy_services / artifact_count) * 70) + min(30, term_hits * 3))
    return min(100, 25 + min(45, term_hits * 5))


def security_realism_score(spec: LabSpec, matched_capabilities: list[str]) -> int:
    raw = json.dumps(spec.security_controls, ensure_ascii=False).lower() + " " + lab_text_haystack(spec)
    terms = ["firewall", "waf", "ids", "siem", "edr", "logging", "audit", "mfa", "segmentation", "monitoring"]
    hits = sum(1 for term in terms if term in raw)
    base = min(75, hits * 10)
    if any(item in matched_capabilities for item in ["security-monitoring", "security-operations", "monitoring", "audit"]):
        base += 20
    return min(100, base)


def attack_path_realism_score(spec: LabSpec, anti_ctf_signals: list[AntiCtfSignal]) -> int:
    stages = spec.stage_list
    if not stages:
        return 20
    raw = json.dumps(stages, ensure_ascii=False).lower()
    tactic_terms = ["initial access", "execution", "persistence", "privilege escalation", "defense evasion", "credential access", "discovery", "lateral movement", "collection", "exfiltration", "impact"]
    technique_terms = ["t1", "mitre", "attack", "technique_id", "technique"]
    tactic_hits = sum(1 for term in tactic_terms if term in raw)
    technique_hits = sum(1 for term in technique_terms if term in raw)
    chain_score = min(55, len(stages) * 7)
    mapping_score = min(35, tactic_hits * 5 + technique_hits * 4)
    penalty = min(30, len(anti_ctf_signals) * 6)
    return max(0, min(100, chain_score + mapping_score + 10 - penalty))


def ratio_score(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 100
    return min(100, round((numerator / denominator) * 100))


def slug_part(value: str) -> str:
    return "-".join(part for part in value.lower().replace("/", " ").replace("`", "").split() if part)[:48] or "item"


def normalize_industry(value: str) -> str:
    lowered = "-".join(value.strip().lower().replace("_", " ").split())
    aliases = {
        "brokerage": "securities",
        "stock-brokerage": "securities",
        "bank": "banking",
        "banking": "banking",
        "regional-bank": "banking",
        "retail-bank": "banking",
        "commercial-bank": "banking",
        "core-banking": "banking",
        "financial": "banking",
        "financial-services": "banking",
        "finance": "banking",
        "corporate": "enterprise",
        "general-enterprise": "enterprise",
        "enterprise-it": "enterprise",
        "health": "healthcare",
        "factory": "manufacturing",
        "ot": "manufacturing",
        "ad": "active-directory",
        "windows-domain": "active-directory",
        "supplychain": "supply-chain",
        "software-supply-chain": "supply-chain",
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
        f"- Overall score: `{report.overall_score}/100`",
        f"- Profile: {report.profile.display_name}",
        "",
        "## Score Breakdown",
        "",
        "| Dimension | Score |",
        "|---|---:|",
        f"| Infrastructure realism | `{report.score_breakdown.infrastructure}` |",
        f"| Service realism | `{report.score_breakdown.services}` |",
        f"| Workflow/UI realism | `{report.score_breakdown.workflows_ui}` |",
        f"| Data/noise realism | `{report.score_breakdown.data_noise}` |",
        f"| Security-control realism | `{report.score_breakdown.security_controls}` |",
        f"| Attack-path realism | `{report.score_breakdown.attack_path}` |",
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
        "## Anti-CTF Signals",
        "",
        "| Term | Category | Reason |",
        "|---|---|---|",
    ]
    if not report.anti_ctf_signals:
        lines.append("| - | - | No CTF-like signals detected. |")
    for signal in report.anti_ctf_signals:
        lines.append(f"| `{signal.term}` | `{signal.category}` | {signal.reason} |")
    lines += [
        "",
        "## Findings",
        "",
        "| Severity | Category | Code | Message | Expected | Remediation |",
        "|---|---|---|---|---|---|",
    ]
    if not report.findings:
        lines.append("| info | - | - | No realism findings. | - | - |")
    for finding in report.findings:
        lines.append(
            f"| {finding.severity} | `{finding.category}` | `{finding.code or '-'}` | {finding.message} | "
            f"{finding.expected or '-'} | {finding.remediation or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


REALISM_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "realism-profile.schema.json": IndustryRealismProfile,
    "realism-report.schema.json": RealismReport,
}
