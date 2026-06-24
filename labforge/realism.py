from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

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
    required_ui_surfaces: list[str] = Field(default_factory=list)
    required_data_domains: list[str] = Field(default_factory=list)
    required_security_controls: list[str] = Field(default_factory=list)
    provider_realism_expectations: list[str] = Field(default_factory=list)


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


class IndustryCapabilityEvidence(RealismModel):
    capability_id: str
    service_evidence: list[str] = Field(default_factory=list)
    stage_evidence: list[str] = Field(default_factory=list)
    data_evidence: list[str] = Field(default_factory=list)
    workflow_evidence: list[str] = Field(default_factory=list)
    zone_evidence: list[str] = Field(default_factory=list)
    security_evidence: list[str] = Field(default_factory=list)

    @property
    def evidence_dimensions(self) -> int:
        return sum(
            1
            for values in (
                self.service_evidence,
                self.stage_evidence,
                self.data_evidence,
                self.workflow_evidence,
                self.zone_evidence,
                self.security_evidence,
            )
            if values
        )


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
    capability_evidence: dict[str, IndustryCapabilityEvidence] = Field(default_factory=dict)
    anti_ctf_signals: list[AntiCtfSignal] = Field(default_factory=list)
    findings: list[RealismFinding] = Field(default_factory=list)


class IndustryContextCoverage(RealismModel):
    industry: str
    status: Literal["passed", "warning", "failed"]
    covered_capabilities: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    stage_evidence: dict[str, list[str]] = Field(default_factory=dict)
    service_evidence: dict[str, list[str]] = Field(default_factory=dict)
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
        required_ui_surfaces=["portal", "login", "request", "admin", "records"],
        required_data_domains=["users", "groups", "tickets", "documents", "audit logs"],
        required_security_controls=["firewall", "logging", "siem", "mfa", "segmentation"],
        provider_realism_expectations=["Docker Compose is acceptable for generic web/data services; AD, endpoint, EDR, or Windows workstation realism should use hybrid provider support."],
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
        required_ui_surfaces=["investor", "trading", "order", "quote", "account", "compliance", "surveillance"],
        required_data_domains=["orders", "quotes", "accounts", "positions", "settlement", "surveillance alerts", "regulatory exports"],
        required_security_controls=["waf", "mfa", "siem", "ids", "audit", "segmentation"],
        provider_realism_expectations=[
            "Docker Compose can model securities web, API, and data-plane behavior.",
            "HTS/MTS, VDI, broker terminal, EDR, or Windows endpoint realism should use VM or hybrid provider support.",
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
        required_ui_surfaces=["online banking", "mobile banking", "loan", "account", "payments", "fraud", "aml", "compliance"],
        required_data_domains=["accounts", "ledger", "loan applications", "payments", "fraud alerts", "aml cases", "compliance exports"],
        required_security_controls=["waf", "mfa", "device trust", "siem", "edr", "ids", "segmentation", "audit"],
        provider_realism_expectations=[
            "Docker Compose can model banking portal, API, and batch behavior.",
            "Core banking terminal, endpoint EDR, Windows workstation, or AD realism should use VM-backed or hybrid provider support.",
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
        required_ui_surfaces=["patient", "appointment", "ehr", "billing", "claims", "privacy"],
        required_data_domains=["appointments", "encounters", "clinical notes", "claims", "billing events", "privacy audit logs"],
        required_security_controls=["mfa", "audit", "siem", "edr", "segmentation"],
        provider_realism_expectations=["Clinical workstation, imaging, identity, or EDR realism should use VM/hybrid assets rather than Docker-only services."],
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
        required_ui_surfaces=["mes", "work order", "historian", "scada", "engineering", "maintenance"],
        required_data_domains=["work orders", "historian tags", "alarms", "engineering changes", "maintenance logs"],
        required_security_controls=["segmentation", "firewall", "monitoring", "ids", "jump host"],
        provider_realism_expectations=["OT/ICS protocols and Windows engineering workstations usually require VM or hybrid provider support."],
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
        required_ui_surfaces=["domain controller", "workstation", "file share", "admin", "event log"],
        required_data_domains=["users", "groups", "gpo", "kerberos tickets", "smb shares", "windows event logs"],
        required_security_controls=["edr", "event logging", "siem", "firewall", "segmentation"],
        provider_realism_expectations=["AD realism requires Windows Server and workstation VMs; Docker-only is not sufficient for Kerberos/GPO behavior."],
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
        required_ui_surfaces=["support", "wiki", "source", "build", "release", "signing", "customer"],
        required_data_domains=["tickets", "commits", "build jobs", "artifacts", "manifests", "release audit logs", "customer exports"],
        required_security_controls=["waf", "audit", "siem", "signing", "segmentation", "egress control"],
        provider_realism_expectations=["Docker Compose is acceptable for supply-chain web/API flows; signed artifact behavior must remain synthetic and lab-scoped."],
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
    context_coverage = check_industry_context(spec, industry=profile.industry, strict=strict)
    findings.extend(context_coverage.findings)
    capability_evidence = build_capability_evidence(profile, spec)
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
        evidence = capability_evidence.get(capability.id)
        if capability.required and evidence and keyword_matches >= capability.min_keyword_matches and evidence.evidence_dimensions < 2:
            findings.append(
                RealismFinding(
                    severity="error" if strict else "warning",
                    category="capability-depth",
                    message=(
                        f"Industry capability `{capability.id}` is mentioned but not backed by enough service, "
                        "workflow, data, or network-zone evidence."
                    ),
                    expected="At least two evidence dimensions: service, stage procedure, business data/noise, workflow, or zone placement.",
                    code=f"capability-depth.{capability.id}.too-shallow",
                    remediation=capability_remediation(capability),
                )
            )
        if capability.required and evidence and keyword_matches >= capability.min_keyword_matches:
            findings.extend(capability_support_findings(capability, evidence, strict=strict))

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

    for term in profile.required_ui_surfaces:
        if term.lower() not in haystack:
            findings.append(
                RealismFinding(
                    severity="error" if strict else "warning",
                    category="ui-surface",
                    message=f"Expected industry UI/workflow surface is not represented: {term}",
                    expected=term,
                    code=f"ui.{slug_part(term)}.missing",
                    remediation=f"Add a normal learner-visible or internal UI/workflow surface for `{term}` with realistic labels, forms, routes, and records.",
                )
            )

    for term in profile.required_data_domains:
        if term.lower() not in haystack:
            findings.append(
                RealismFinding(
                    severity="error" if strict else "warning",
                    category="data-domain",
                    message=f"Expected industry data domain is not represented: {term}",
                    expected=term,
                    code=f"data.{slug_part(term)}.missing",
                    remediation=f"Seed synthetic but business-shaped `{term}` data, related logs, and benign noise records.",
                )
            )

    security_haystack = json.dumps(spec.security_controls, ensure_ascii=False).lower() + " " + haystack
    for control in profile.required_security_controls:
        if control.lower() not in security_haystack:
            findings.append(
                RealismFinding(
                    severity="error" if strict else "warning",
                    category="security-control",
                    message=f"Expected industry security control is not represented: {control}",
                    expected=control,
                    code=f"security-control.{slug_part(control)}.missing",
                    remediation=f"Add `{control}` as an explicit security control, telemetry source, or protected architecture variant.",
                )
            )

    deployment_text = json.dumps(spec.topology.get("deployment", {}), ensure_ascii=False).lower()
    docker_only = "docker" in deployment_text and not any(term in deployment_text for term in ("hybrid", "vm", "proxmox", "windows", "ludus"))
    provider_sensitive_terms = ("windows", "active directory", "kerberos", "gpo", "workstation", "edr", "ot", "scada", "plc", "ics")
    if docker_only and any(term in haystack for term in provider_sensitive_terms):
        findings.append(
            RealismFinding(
                severity="error" if strict else "warning",
                category="provider-realism",
                message="Docker-only deployment is declared while the scenario references assets that usually require VM or hybrid realism.",
                expected=", ".join(profile.provider_realism_expectations or ["Use VM/hybrid provider when endpoint, AD, OT, or EDR realism is required."]),
                code="provider.docker-only.realism-gap",
                remediation="Switch the recommended provider to hybrid/VM-backed execution or explicitly mark those assets as simulated with reviewer approval.",
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
        capability_evidence=capability_evidence,
        anti_ctf_signals=anti_ctf_signals,
        findings=findings,
    )


def check_industry_context(spec: LabSpec, *, industry: str | None = None, strict: bool = False) -> IndustryContextCoverage:
    selected_industry = industry or spec.scenario.get("target_industry") or spec.scenario.get("industry") or "enterprise"
    profile = get_realism_profile(str(selected_industry))
    service_text = service_context_haystack(spec)
    stage_text = stage_context_haystack(spec)
    stage_evidence = capability_context_evidence(profile, spec.stage_list)
    service_evidence = capability_context_evidence(profile, spec.services)

    covered: list[str] = []
    missing: list[str] = []
    findings: list[RealismFinding] = []
    for capability in profile.capabilities:
        stage_hits = stage_evidence.get(capability.id, [])
        service_hits = service_evidence.get(capability.id, [])
        if stage_hits or service_hits:
            covered.append(capability.id)
        elif capability.required:
            missing.append(capability.id)

    min_required = min(3, max(2, len(profile.capabilities) // 3))
    if len(covered) < min_required:
        findings.append(
            RealismFinding(
                severity="error" if strict else "warning",
                category="industry-context",
                message=(
                    f"Only {len(covered)} industry capability group(s) are visible in learner-facing stage or service context; "
                    f"expected at least {min_required}."
                ),
                expected=", ".join(capability.id for capability in profile.capabilities[: min_required + 2]),
                code="industry-context.coverage.too-thin",
                remediation=(
                    "Add normal industry services, stage procedures, learner clues, records, and noise that reflect the declared "
                    "business environment instead of relying on generic vulnerable services."
                ),
            )
        )

    if not any_capability_keyword_present(profile, stage_text):
        findings.append(
            RealismFinding(
                severity="error" if strict else "warning",
                category="industry-context",
                message="Stage procedures and learner-facing clues do not contain recognizable target-industry workflow language.",
                expected=", ".join(profile.required_ui_surfaces[:6] or [capability.description for capability in profile.capabilities[:4]]),
                code="industry-context.stage-language.missing",
                remediation="Rewrite stages so the learner sees realistic business workflows, records, operator notes, and service names for the declared industry.",
            )
        )

    if not any_capability_keyword_present(profile, service_text):
        findings.append(
            RealismFinding(
                severity="error" if strict else "warning",
                category="industry-context",
                message="Service names, roles, and purposes do not expose recognizable target-industry systems.",
                expected=", ".join(service for capability in profile.capabilities for service in capability.recommended_services[:1]) or profile.display_name,
                code="industry-context.service-language.missing",
                remediation="Add industry-shaped services such as portals, consoles, data stores, batch processors, monitoring, and non-target business systems.",
            )
        )

    status: Literal["passed", "warning", "failed"]
    if any(finding.severity == "error" for finding in findings):
        status = "failed"
    elif findings:
        status = "warning"
    else:
        status = "passed"
    return IndustryContextCoverage(
        industry=profile.industry,
        status=status,
        covered_capabilities=covered,
        missing_capabilities=missing,
        stage_evidence={key: value for key, value in stage_evidence.items() if value},
        service_evidence={key: value for key, value in service_evidence.items() if value},
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


def service_context_haystack(spec: LabSpec) -> str:
    service_parts: list[Any] = []
    for service in spec.services:
        service_parts.append(
            {
                "name": service.get("name"),
                "role": service.get("role"),
                "purpose": service.get("purpose"),
                "description": service.get("description"),
                "networks": service.get("networks"),
                "labels": service.get("labels"),
            }
        )
    if spec.artifacts_model:
        for artifact in spec.artifacts_model.service_artifacts:
            service_parts.append(
                {
                    "service": artifact.service,
                    "runtime": artifact.runtime,
                    "source_path": artifact.source_path,
                    "seed_inputs": artifact.seed_inputs,
                    "noise_inputs": artifact.noise_inputs,
                }
            )
    return " ".join(context_values(service_parts)).lower()


def stage_context_haystack(spec: LabSpec) -> str:
    stage_parts: list[Any] = []
    for stage in spec.stage_list:
        stage_parts.append(
            {
                "id": stage.get("id"),
                "title": stage.get("title"),
                "procedure": stage.get("procedure"),
                "learner_clue": stage.get("learner_clue") or stage.get("clue"),
                "required_findings": stage.get("required_findings"),
                "evidence": stage.get("evidence"),
                "infrastructure_touched": stage.get("infrastructure_touched"),
            }
        )
    return " ".join(context_values(stage_parts)).lower()


def capability_context_evidence(profile: IndustryRealismProfile, items: list[dict[str, Any]]) -> dict[str, list[str]]:
    evidence: dict[str, list[str]] = {}
    for capability in profile.capabilities:
        matches: list[str] = []
        for item in items:
            blob = " ".join(context_values(item)).lower()
            hit_terms = [keyword for keyword in capability.keywords if keyword.lower() in blob]
            if hit_terms:
                name = str(item.get("id") or item.get("name") or item.get("title") or "context-item")
                matches.append(f"{name}: {', '.join(hit_terms[:3])}")
        evidence[capability.id] = matches
    return evidence


def build_capability_evidence(profile: IndustryRealismProfile, spec: LabSpec) -> dict[str, IndustryCapabilityEvidence]:
    evidence: dict[str, IndustryCapabilityEvidence] = {}
    artifact_text = json.dumps(spec.artifacts, ensure_ascii=False).lower()
    stage_text = stage_context_haystack(spec)
    zone_text = " ".join(str(zone.get("name", zone.get("id", ""))).lower() for zone in spec.environment.get("zones", []))
    network_text = " ".join(str(network.get("name", "")).lower() for network in spec.networks)
    zone_haystack = f"{zone_text} {network_text}"

    for capability in profile.capabilities:
        item = IndustryCapabilityEvidence(capability_id=capability.id)
        item.service_evidence = capability_service_evidence(capability, spec.services)
        item.stage_evidence = capability_item_evidence(capability, spec.stage_list)
        item.data_evidence = capability_data_evidence(capability, artifact_text)
        item.workflow_evidence = capability_workflow_evidence(capability, stage_text)
        item.zone_evidence = capability_zone_evidence(capability, zone_haystack, spec.services)
        item.security_evidence = capability_security_evidence(capability, spec.security_controls)
        evidence[capability.id] = item
    return evidence


def capability_service_evidence(capability: IndustryCapability, services: list[dict[str, Any]]) -> list[str]:
    matches: list[str] = []
    recommended = [value.lower() for value in capability.recommended_services]
    for service in services:
        blob = " ".join(context_values(service)).lower()
        name = str(service.get("name") or "service")
        hit_terms = [keyword for keyword in capability.keywords if keyword.lower() in blob]
        hit_terms.extend(service_name for service_name in recommended if service_name in blob)
        if hit_terms:
            matches.append(f"{name}: {', '.join(sorted(set(hit_terms))[:4])}")
    return matches


def capability_item_evidence(capability: IndustryCapability, items: list[dict[str, Any]]) -> list[str]:
    matches: list[str] = []
    for item in items:
        blob = " ".join(context_values(item)).lower()
        hit_terms = [keyword for keyword in capability.keywords if keyword.lower() in blob]
        if hit_terms:
            name = str(item.get("id") or item.get("name") or item.get("title") or "context-item")
            matches.append(f"{name}: {', '.join(hit_terms[:4])}")
    return matches


def capability_data_evidence(capability: IndustryCapability, artifact_text: str) -> list[str]:
    terms = capability.recommended_data or capability.keywords
    matches = [term for term in terms if term.lower() in artifact_text]
    return [", ".join(matches[:4])] if matches else []


def capability_workflow_evidence(capability: IndustryCapability, stage_text: str) -> list[str]:
    terms = capability.recommended_workflows or []
    matches = [term for term in terms if term.lower() in stage_text]
    return [", ".join(matches[:4])] if matches else []


def capability_zone_evidence(capability: IndustryCapability, zone_haystack: str, services: list[dict[str, Any]]) -> list[str]:
    matches: list[str] = []
    for zone in capability.recommended_zones:
        if zone.lower() in zone_haystack:
            matches.append(zone)
    for service in services:
        service_networks = " ".join(context_values(service.get("networks"))).lower()
        for zone in capability.recommended_zones:
            if zone.lower() in service_networks and zone not in matches:
                matches.append(zone)
    return matches[:4]


def capability_security_evidence(capability: IndustryCapability, security_controls: dict[str, Any]) -> list[str]:
    controls_text = json.dumps(security_controls, ensure_ascii=False).lower()
    security_terms = {"waf", "mfa", "siem", "ids", "edr", "soc", "audit", "logging", "segmentation", "monitoring", "firewall", "device trust"}
    terms = [keyword for keyword in capability.keywords if keyword.lower() in security_terms]
    terms.extend(term for term in security_terms if term in capability.description.lower())
    matches = [term for term in sorted(set(terms)) if term in controls_text]
    return matches[:4]


def capability_support_findings(
    capability: IndustryCapability,
    evidence: IndustryCapabilityEvidence,
    *,
    strict: bool,
) -> list[RealismFinding]:
    findings: list[RealismFinding] = []
    severity: Literal["warning", "error"] = "error" if strict else "warning"
    if not evidence.service_evidence:
        findings.append(
            RealismFinding(
                severity=severity,
                category="capability-service",
                message=f"Industry capability `{capability.id}` is mentioned but no concrete service supports it.",
                expected=", ".join(capability.recommended_services or capability.keywords),
                code=f"capability-service.{capability.id}.missing",
                remediation=capability_remediation(capability),
            )
        )
    operational_evidence = [
        *evidence.stage_evidence,
        *evidence.data_evidence,
        *evidence.workflow_evidence,
    ]
    if (capability.recommended_data or capability.recommended_workflows) and not operational_evidence:
        findings.append(
            RealismFinding(
                severity=severity,
                category="capability-operational-depth",
                message=f"Industry capability `{capability.id}` has no business data, workflow, or stage evidence.",
                expected=", ".join([*capability.recommended_data, *capability.recommended_workflows] or capability.keywords),
                code=f"capability-operational-depth.{capability.id}.missing",
                remediation=capability_remediation(capability),
            )
        )
    if capability.recommended_zones and evidence.service_evidence and not evidence.zone_evidence:
        findings.append(
            RealismFinding(
                severity=severity,
                category="capability-zone-depth",
                message=f"Industry capability `{capability.id}` is not placed in an expected network or infrastructure zone.",
                expected=", ".join(capability.recommended_zones),
                code=f"capability-zone-depth.{capability.id}.missing",
                remediation=capability_remediation(capability),
            )
        )
    if is_security_capability(capability) and not evidence.security_evidence:
        findings.append(
            RealismFinding(
                severity=severity,
                category="capability-security-depth",
                message=f"Security capability `{capability.id}` lacks explicit security-control or telemetry evidence.",
                expected="SIEM, IDS, EDR, SOC, audit, monitoring, segmentation, or logging control evidence.",
                code=f"capability-security-depth.{capability.id}.missing",
                remediation="Add explicit security controls and telemetry sources that support this security capability.",
            )
        )
    return findings


def is_security_capability(capability: IndustryCapability) -> bool:
    text = f"{capability.id} {capability.description} {' '.join(capability.keywords)}".lower()
    return any(term in text for term in ("security", "siem", "ids", "edr", "soc", "monitoring", "fraud", "audit"))


def context_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            parts.extend(context_values(item))
        return parts
    if isinstance(value, dict):
        parts: list[str] = []
        for item in value.values():
            parts.extend(context_values(item))
        return parts
    return [str(value)]


def any_capability_keyword_present(profile: IndustryRealismProfile, haystack: str) -> bool:
    return any(keyword.lower() in haystack for capability in profile.capabilities for keyword in capability.keywords)


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
    ui_gaps = sum(1 for finding in findings if finding.category == "ui-surface")
    data_gaps = sum(1 for finding in findings if finding.category == "data-domain")
    security_gaps = sum(1 for finding in findings if finding.category == "security-control")
    provider_gaps = sum(1 for finding in findings if finding.category == "provider-realism")
    service_support_gaps = sum(1 for finding in findings if finding.category == "capability-service")
    operational_depth_gaps = sum(1 for finding in findings if finding.category == "capability-operational-depth")
    zone_depth_gaps = sum(1 for finding in findings if finding.category == "capability-zone-depth")
    security_depth_gaps = sum(1 for finding in findings if finding.category == "capability-security-depth")
    if ui_gaps:
        workflow_score = max(0, workflow_score - min(35, ui_gaps * 5))
    if data_gaps:
        data_score = max(0, data_score - min(35, data_gaps * 5))
    if security_gaps:
        security_score = max(0, security_score - min(40, security_gaps * 6))
    if provider_gaps:
        infrastructure_penalty = min(30, provider_gaps * 15)
        zone_score = max(0, zone_score - infrastructure_penalty)
    if service_support_gaps:
        service_depth_score = max(0, service_depth_score - min(40, service_support_gaps * 6))
    if operational_depth_gaps:
        workflow_score = max(0, workflow_score - min(35, operational_depth_gaps * 5))
        data_score = max(0, data_score - min(35, operational_depth_gaps * 5))
    if zone_depth_gaps:
        zone_score = max(0, zone_score - min(30, zone_depth_gaps * 5))
    if security_depth_gaps:
        security_score = max(0, security_score - min(35, security_depth_gaps * 8))
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
        "### Capability Evidence Depth",
        "",
        "| Capability | Service | Stage | Data | Workflow | Zone | Security |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    if not report.capability_evidence:
        lines.append("| - | 0 | 0 | 0 | 0 | 0 | 0 |")
    for capability_id, evidence in report.capability_evidence.items():
        lines.append(
            f"| `{capability_id}` | {len(evidence.service_evidence)} | {len(evidence.stage_evidence)} | "
            f"{len(evidence.data_evidence)} | {len(evidence.workflow_evidence)} | {len(evidence.zone_evidence)} | "
            f"{len(evidence.security_evidence)} |"
        )
    lines += [
        "",
        "## Expected Enterprise Texture",
        "",
        "### Common Technologies",
        "",
    ]
    lines.extend(f"- {item}" for item in report.profile.common_technologies)
    lines += [
        "",
        "### Required UI / Workflow Surfaces",
        "",
    ]
    lines.extend(f"- {item}" for item in report.profile.required_ui_surfaces or ["No profile-specific UI surface requirements declared."])
    lines += [
        "",
        "### Required Data Domains",
        "",
    ]
    lines.extend(f"- {item}" for item in report.profile.required_data_domains or ["No profile-specific data-domain requirements declared."])
    lines += [
        "",
        "### Required Security Controls",
        "",
    ]
    lines.extend(f"- {item}" for item in report.profile.required_security_controls or ["No profile-specific security-control requirements declared."])
    lines += [
        "",
        "### Provider Realism Expectations",
        "",
    ]
    lines.extend(f"- {item}" for item in report.profile.provider_realism_expectations or ["No profile-specific provider expectations declared."])
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
    "industry-context-coverage.schema.json": IndustryContextCoverage,
}
