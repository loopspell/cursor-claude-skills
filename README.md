# Security Review Skills

A collection of AI agent skills focused on security testing, penetration testing, and vulnerability assessment. Each skill provides a structured, repeatable workflow that can be used with Cursor (or compatible AI coding agents) to perform thorough security reviews.

## Repository Structure

```
Skills/
├── README.md
├── aws-cloud-security-review/
│   ├── SKILL.md
│   └── reference.md
├── java-desktop-security-pentest/
│   └── SKILL.md
└── <future-skill>/
    └── SKILL.md
```

Each skill lives in its own directory and contains a `SKILL.md` file with front matter metadata, scope definition, mandatory rules, phased workflows, reporting templates, and quality gates. Some skills include additional reference files (finding templates, checklists, CWE mappings).

## Skills

### [AWS Cloud Security Review](aws-cloud-security-review/SKILL.md)

End-to-end AWS cloud configuration security review with multi-account Organization support. User provides only AWS credentials; the agent handles scanning, live API validation, findings report drafting, gap analysis, and sanity checks autonomously.

| Detail | Value |
|--------|-------|
| **Phases** | 7 (Scanning → Validation → Gap Analysis → Reporting → Pentest Updates → Sanity Checks → Maintenance) |
| **Scanners** | ScoutSuite, Prowler |
| **Scope** | 25+ AWS services, all accessible regions, multi-account Organizations |

**Coverage areas:**

- Account classification (management vs member vs standalone) and SCP-blocked region detection
- IAM deep analysis: credential report, privilege escalation chains (PassRole tracing), cross-account trust validation (ExternalId, confused deputy), IAM Access Analyzer
- S3 bucket policies, public access blocks, encryption, HTTPS enforcement, versioning/Object Lock
- EC2/VPC: security groups, NACLs, IMDSv2, default VPC resource census, VPC Flow Logs
- Containers: EKS (public API endpoints, RBAC, node group IMDSv2, secrets encryption), ECR (image scanning, public repos)
- Networking: Route 53 (dangling DNS, subdomain takeover), WAF coverage, API Gateway authorization
- Monitoring stack: GuardDuty, SecurityHub, Inspector, CloudTrail (management + data events), CloudWatch (secrets-in-logs)
- Encryption/KMS: CMK rotation, EBS default encryption, Glue catalog encryption
- Compute services: ECS task definitions, Lambda, ELBv2 SSL/TLS policy validation, CloudFront, RDS (snapshots, extended support)
- Data services: OpenSearch, ElastiCache, Redshift (encryption, public access, audit logging)
- Storage: EFS (encryption, mount targets), S3, Backup vault policies and plans
- Identity: Cognito user pools/identity pools, SSO/Identity Center
- Secrets Manager rotation, SSM patch compliance and custom documents, ACM certificate expiry
- Delegated administrator awareness and multi-account Organization workflow (hub-and-spoke, finding deduplication, cross-account consistency)
- Resource existence checks with severity adjustment for empty regions/services
- Scanner disagreement process and time-of-check awareness for multi-day engagements

**Deliverables:** Client-ready findings report (CVSS 3.1 + OWASP + CWE with XML-tagged schema), executive summary, pentest updates summary, scanner gap analysis with exclusion log, and CVSS-validated sanity checks.

**Additional files:** [`reference.md`](aws-cloud-security-review/reference.md) — finding template, severity bands, typical severity reference table, common CWE mappings, Trend Micro KB URL patterns, AWS services validation checklist, executive summary template, and pentest updates template.

---

### [Java Desktop Security Pentest](java-desktop-security-pentest/SKILL.md)

End-to-end security testing workflow for Java desktop applications (JAR-based).

| Detail | Value |
|--------|-------|
| **Categories** | 11 |
| **Test Cases** | 83 (49 static, 19 dynamic, 15 hybrid) |
| **Platforms** | macOS, Linux, Windows |

**Coverage areas:**

- JAR integrity, manifest inspection, bytecode decompilation, obfuscation assessment, JPMS module audit, GraalVM native-image detection
- Native code (JNI/JNA) library audit and dependency CVE audit with SBOM generation (CycloneDX + SPDX)
- Java deserialization exploitation (ysoserial, gadget chain mapping, blacklist probing, JEP 290 filter handling)
- Local filesystem artifact review (credentials, PHI, temp files, permissions, embedded databases)
- Network and transport security (TLS/SSL trust-all detection, certificate pinning, JNDI/RMI, WebSocket connections)
- Authentication and authorization (brute-force, RBAC, horizontal/vertical privilege escalation)
- Input validation and injection (XXE, SQL injection, script sandbox escape, Rhino/Nashorn, unsafe reflection, custom URI protocol handlers)
- Cryptography audit (weak hashing, hardcoded keys, deprecated algorithms, PRNG)
- Platform-specific checks (Gatekeeper, JMX/debug ports, DYLD injection, Java agent injection, TCC pasteboard, `/proc` exposure, DLL hijacking, AMSI)
- Logging, error handling, and audit trail completeness
- Data leakage and privacy (heap memory secrets, clipboard, export paths)

**Deliverables:** Executive summary, security test results matrix, findings report (CVSS 3.1 + OWASP + CWE with extended schema), dynamic testing playbook, SBOM artifacts, screenshot evidence, and post-remediation re-test tracking.

## Usage

These skills are designed for use with [Cursor](https://cursor.com) AI agent mode. To use a skill:

1. Clone this repo or point your Cursor skill path to the relevant `SKILL.md`.
2. When starting a security review, reference the skill — the agent will follow the phased workflow, execute static tests autonomously, and prepare commands/payloads for dynamic tests that require user interaction.
3. The agent will produce structured deliverables (reports, SBOMs, evidence) as defined in each skill's reporting phase.
