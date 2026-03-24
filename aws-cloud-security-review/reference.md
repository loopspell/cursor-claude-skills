# Reference: AWS Cloud Security Review

## Finding Template

```
<Vulnerability Title></Vulnerability Title>
<Vulnerability Description></Vulnerability Description>
<CVSS 3.1 Score with string>X.X (AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_)</CVSS 3.1 Score with string>
<Reference>Trend Micro AWS KB (topic): https://www.trendmicro.com/trendaivisiononecloudriskmanagement/knowledge-base/aws/<Service>/<page>.html ; CIS AWS Foundations Benchmark: https://www.cisecurity.org/benchmark/amazon_web_services</Reference>
<Affected Resources>
- resource-id (region, context)
</Affected Resources>
<OWASP Severity>Likelihood: X/5, Business Impact: X/5</OWASP Severity>
<CWE>CWE-XXX: Name</CWE>
<Steps to Reproduce>
1. `aws <service> <command> --<args>`
   - Purpose: What this command does and what to look for.
2. Confirm <expected observation>.
   - Purpose: Verify the finding.
</Steps to Reproduce>
<Evidence>API response excerpts, CLI output, or screenshot references confirming the finding.</Evidence>
<Impact>Detailed, specific consequences proportional to severity. Include realistic attack scenarios and business impact.</Impact>
<Business Risk Context>Business-level consequences beyond technical severity (e.g., regulatory exposure, data breach scope, operational disruption).</Business Risk Context>
<Suggested Fix>Actionable remediation steps with specific AWS CLI commands or console instructions where applicable.</Suggested Fix>
<Remediation Effort>Low / Medium / High — estimated effort to implement the fix.</Remediation Effort>
<Status>Open / Remediated / Accepted Risk</Status>
<Date Identified>YYYY-MM-DD</Date Identified>
<Prerequisites (optional)>Required IAM permissions.</Prerequisites (optional)>
```

---

## Severity Bands

| CVSS Range | Severity | OWASP Likelihood | OWASP Impact |
|------------|----------|------------------|--------------|
| 9.0–10.0 | Critical | 4-5/5 | 5/5 |
| 7.0–8.9 | High | 3-4/5 | 4-5/5 |
| 4.0–6.9 | Medium | 2-3/5 | 2-4/5 |
| 0.1–3.9 | Low | 1-2/5 | 1-2/5 |

---

## Common CWE Mappings

| Issue Type | CWE |
|------------|-----|
| Full admin / excessive privileges | CWE-250: Execution with Unnecessary Privileges |
| Missing access control / cross-account | CWE-284: Improper Access Control |
| Confused deputy / unintended proxy | CWE-441: Unintended Proxy or Intermediary |
| Cleartext storage (unencrypted data) | CWE-312: Cleartext Storage of Sensitive Information |
| Cleartext transmission (no HTTPS) | CWE-319: Cleartext Transmission of Sensitive Information |
| Missing encryption at rest | CWE-311: Missing Encryption of Sensitive Data |
| Key not rotated | CWE-324: Use of a Key Past its Expiration Date |
| Insufficient logging/monitoring | CWE-778: Insufficient Logging |
| Privilege escalation (PassRole) | CWE-269: Improper Privilege Management |
| Public snapshot / exposed backup | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| Outdated TLS / weak cipher suite | CWE-326: Inadequate Encryption Strength |
| Secrets in logs | CWE-532: Insertion of Sensitive Information into Log File |
| Missing patching / outdated software | CWE-1104: Use of Unmaintained Third Party Components |
| Overly permissive trust policy | CWE-863: Incorrect Authorization |
| Dangling DNS / subdomain takeover | CWE-672: Operation on a Resource after Expiration or Release |
| Missing MFA | CWE-308: Use of Single-factor Authentication |
| Insecure default configuration | CWE-1188: Initialization with an Insecure Default |
| Public resource exposure (general) | CWE-668: Exposure of Resource to Wrong Sphere |
| Missing rate limiting / throttling | CWE-770: Allocation of Resources Without Limits or Throttling |
| Missing backup / recovery controls | CWE-693: Protection Mechanism Failure |

---

## Typical Severity Reference

Guidance for common finding types to reduce inconsistency across engagements:

| Finding Type | Typical CVSS | Notes |
|--------------|-------------|-------|
| Public S3 bucket with sensitive data | 7.5+ | Depends on data classification |
| Missing MFA on root account | 8.1 | Always High minimum |
| IMDSv2 not enforced | 5.3–6.5 | Depends on instance role permissions |
| Missing CloudTrail data events | 3.8–5.3 | Depends on what data is being processed |
| Default VPC not deleted (no resources) | 2.0–3.0 | Preventive guardrail only |
| Trust-all cross-account role (no ExternalId) | 6.5–8.1 | Depends on role permissions |
| Unrestricted security group (0.0.0.0/0) | 5.3–7.5 | Depends on ports and attached resources |
| Missing encryption at rest (EBS/RDS) | 4.0–5.3 | Higher if data is classified |
| Dangling DNS / subdomain takeover | 5.3–7.5 | Depends on domain reputation and usage |
| EKS public API endpoint (unrestricted) | 5.3–6.5 | Lower if RBAC is properly configured |
| Secrets in CloudWatch logs | 5.3–7.5 | Depends on secret type and log retention |
| Missing VPC Flow Logs | 3.8–5.3 | Logging/monitoring gap |
| No AWS Backup plan for critical resources | 3.8–5.3 | Data recovery gap |

These are starting points — always adjust based on environment context, data sensitivity, and blast radius.

---

## Trend Micro KB Base URL

```
https://www.trendmicro.com/trendaivisiononecloudriskmanagement/knowledge-base/aws/
```

Common service paths: `IAM/`, `S3/`, `EC2/`, `EBS/`, `RDS/`, `KMS/`, `GuardDuty/`, `Glue/`, `ECS/`, `Lambda/`, `CloudFront/`, `ELBv2/`, `SNS/`, `CloudTrail/`

Always validate URLs return 200 before including. Each reference must be topically relevant to the specific finding — not just a generic service landing page. The old `cloudoneconformity` domain is deprecated.

---

## AWS Services Validation Checklist

### Pre-Validation
- [ ] Account classification: management vs member vs standalone (`organizations.describe_organization()`)
- [ ] SCP-blocked region detection: test lightweight API call per region, exclude blocked regions
- [ ] Architecture doc review: if provided, review for expected resource layout and multi-account relationships

### Global Services
- [ ] IAM: roles, policies (inline + managed), trust relationships, credential report, PassRole, admin access
- [ ] IAM deep: privilege escalation chains (PassRole → target role → service → permissions)
- [ ] IAM deep: cross-account trust validation (ExternalId, wildcard principals, SourceArn/SourceAccount)
- [ ] IAM deep: credential report (root MFA, root access keys, password age, unused keys, users without MFA)
- [ ] IAM Access Analyzer: analyzer exists, cross-reference external access findings
- [ ] S3: bucket policies, public access blocks (account + bucket level), encryption, cross-account, HTTPS, versioning
- [ ] Organizations: delegated administrators, SCPs, delegated admin service ownership
- [ ] Route 53: dangling DNS records, public hosted zones, DNSSEC status
- [ ] Cognito: user pool password policy, self-signup, identity pool unauthenticated roles (if applicable)

### Per-Region Services (check ALL active, non-SCP-blocked regions)
- [ ] EC2: instances, security groups, subnets (public IP), NACLs, IMDSv2
- [ ] EC2/VPC: default VPC resource census (instances, RDS, ELB, Lambda, ECS in default VPC)
- [ ] EBS: volumes, encryption, default encryption, snapshots
- [ ] RDS: instances, encryption, deletion protection, backups
- [ ] RDS deep: public snapshots (`describe_db_snapshot_attributes`), extended support on EOL engines
- [ ] ECS: task definitions (read-only root, privileged, env secrets)
- [ ] Lambda: functions (public access, runtimes, env secrets)
- [ ] ELBv2: listeners (HTTP vs HTTPS), SSL policies
- [ ] ELBv2 deep: validate SSL policy version (flag outdated policies like `ELBSecurityPolicy-2016-08`)
- [ ] CloudFront: distributions (default root object, TLS)
- [ ] KMS: CMK rotation, pending deletion, public access
- [ ] Glue: Data Catalog encryption (connection passwords + metadata)
- [ ] GuardDuty: detector presence, active findings severity, delegated admin ownership
- [ ] SecurityHub: enabled status, delegated admin ownership
- [ ] Secrets Manager: rotation status
- [ ] SNS: KMS encryption
- [ ] CloudFormation: stack outputs (secrets)
- [ ] CloudWatch: log groups (public policies), alarms
- [ ] CloudWatch deep: sample recent log events for secrets/credentials patterns
- [ ] CloudTrail: multi-region trails, management events
- [ ] CloudTrail deep: data event selectors (S3 object-level, Lambda invocation)
- [ ] Config: recorder status
- [ ] DynamoDB: tables, encryption, backups
- [ ] EventBridge: event bus policies
- [ ] SSM: managed instances, patching compliance
- [ ] SSM deep: `describe_instance_patch_states()` — non-compliant counts by classification
- [ ] ACM: certificate expiry
- [ ] VPC: endpoints (trust boundaries), VPN tunnels
- [ ] VPC: Flow Logs enabled per VPC
- [ ] EKS: public API endpoints, RBAC (aws-auth ConfigMap), node group IMDSv2, secrets encryption, logging
- [ ] ECR: image scanning, lifecycle policies, public repositories
- [ ] OpenSearch: public domains, encryption at rest/transit, fine-grained access control
- [ ] ElastiCache: encryption in transit, auth tokens, VPC placement
- [ ] Redshift: public accessibility, encryption, audit logging, SSL enforcement
- [ ] EFS: encryption at rest, mount target security groups, file system policies
- [ ] WAF: WebACL attached to ALB/CloudFront/API Gateway
- [ ] API Gateway: authorization type per route, throttling, resource policies
- [ ] AWS Backup: vault policies, backup plans covering critical resources
- [ ] RDS: automated backup retention period (0 = disabled)
- [ ] DynamoDB: PITR enabled
- [ ] S3: Object Lock (if data integrity required)
- [ ] SSM: custom documents with embedded scripts/credentials
- [ ] Macie: cross-reference S3 sensitive data findings (if enabled)

---

## Executive Summary Template

```markdown
# Executive Summary – AWS Account <ACCOUNT_ID>

**Assessment Date:** <start> – <end>
**Account Purpose:** <from intake>
**Scope:** <services, regions, limitations>

## Overall Risk Posture

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

## Key Findings

1. <Top finding with one-line business impact>
2. <Second finding>
3. <Third finding>

## Strategic Recommendations

1. <Org-level or architectural recommendation>
2. <Second recommendation>
3. <Third recommendation>

## Comparison to Prior Assessments

<If available, note improvements or regressions from previous reviews>

## Limitations & Caveats

- <Any services not tested, access restrictions, time constraints>
```

---

## Pentest Updates Template

```markdown
# Pentest Updates – AWS Account <ACCOUNT_ID>

**Scan coverage:** ScoutSuite (X services, X findings, X danger) + Prowler (X services, X findings, X high/critical across X unique checks). All findings validated with live AWS API calls.

---

## <Service Section>

- <One-line finding summary>. **Severity: <Level> (<CVSS>). Confirmed.**
- <Passed check with resource count and regions>. **Severity: Passed.**
- <Zero-resource service>. **Severity: Informational. N/A.**

---

## Prowler high/critical validation (net-new vs ScoutSuite)

- Prowler reported X high/critical findings across X unique checks.
- Key context: Many services have zero resources — Prowler counts reflect check execution, not resource-level findings.

---

## Passed (no high/critical findings in current scoped checks)

- **<Service>:** X resources across X regions. **Severity: No High/Critical finding (Passed).**
```
