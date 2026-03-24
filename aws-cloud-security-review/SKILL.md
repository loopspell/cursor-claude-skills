---
name: aws-cloud-security-review
description: >-
  End-to-end AWS cloud configuration security review covering IAM, S3, EC2/VPC,
  EKS/ECR, RDS, Lambda, ELBv2, CloudFront, KMS, CloudTrail, GuardDuty, Route 53,
  WAF, API Gateway, OpenSearch, ElastiCache, Redshift, EFS, Backup, Cognito, and
  more. Supports multi-account Organization workflows. User provides only AWS
  credentials; agent handles scanning (ScoutSuite, Prowler), live API validation,
  findings report drafting, pentest updates, gap analysis, and sanity checks
  autonomously. Use when performing AWS security assessments, cloud pentests,
  cloud config reviews, or when the user provides AWS access keys/tokens for
  security review.
---

# AWS Cloud Configuration Security Review

End-to-end workflow for AWS security assessments. The user only provides AWS credentials (access key, secret key, session token) — the agent handles everything else autonomously: scanning, validation, report drafting, and sanity checks.

## Mandatory Rules

1. **Credential hygiene**: never commit `creds.txt` to git (ensure `.gitignore` covers it). After the engagement, remind the user to invalidate/rotate the temporary credentials. Never persist credentials in reports, scripts, or artifacts.
2. **Data handling**: if sensitive customer data (PII, secrets, database contents) is encountered during log sampling, CloudFormation output inspection, or any validation step, do not copy it into reports verbatim — redact or reference by pattern. Document data handling obligations in engagement closeout.
3. **Non-destructive only**: all validation uses read-only API calls. Never create, modify, or delete customer resources.

## Core Principle: Ask, Don't Assume

**Never assume scope, intent, or context.** When anything is ambiguous or could affect the quality/accuracy of the review, stop and ask the user before proceeding. This applies to:
- Scope decisions (which services, regions, or accounts are in-scope)
- Severity judgments where context from the user would change the rating
- Unusual configurations that could be intentional vs misconfigured
- Missing information that the agent cannot determine from API calls alone
- Any situation where guessing wrong would waste time or produce inaccurate results

## How It Starts

1. User provides AWS temporary credentials (access key ID, secret access key, session token) — typically pasted into `creds.txt` or provided directly
2. Agent identifies the AWS account ID from the credentials (via `sts:GetCallerIdentity`)
3. **Before scanning, ask the user the intake questions below** — do not skip this step
4. Agent runs all phases end-to-end, asking the user whenever credentials expire, scope is unclear, or a judgment call is needed

### Intake Questions (ask before Phase 1)

After identifying the account, ask the user the following (skip any already answered):

1. **Account purpose**: "What is this account used for? (e.g., production workloads, dev/test, shared services, org management)"
2. **Multi-account context**: "Is this part of an AWS Organization? Are there other accounts being reviewed in this engagement?"
3. **Scope**: "Are all AWS services in scope, or should I focus on specific services/regions?"
4. **Architecture docs**: "Do you have any architecture diagrams, network topology docs, or infrastructure documentation to share?"
5. **Known exceptions**: "Are there any known accepted risks, intentional configurations, or services I should exclude? (e.g., intentionally public S3 buckets, expected cross-account roles)"
6. **Prior findings**: "Are there findings reports from previous accounts in this engagement that I should reference for consistency?"
7. **Client context**: "Is this a client-facing deliverable? Any specific client requirements or report format preferences beyond the standard template?"

### Multi-Account Organization Workflow

When reviewing multiple accounts in an AWS Organization:

1. **Hub-and-spoke access**: if the user provides a hub role, use `sts:AssumeRole` to chain into each member account. Request role ARNs and external IDs for each target account.
2. **Account iteration order**: management account first (broadest blast radius), then production workloads, then shared services, then dev/test.
3. **Finding deduplication**: findings caused by Organization-level controls (SCPs, org-wide CloudTrail, delegated admin gaps) should be reported once at the org level, not duplicated per account. Per-account findings (e.g., specific IAM role misconfigurations) remain per-account.
4. **Cross-account consistency**: same finding types must use consistent severities across accounts. Document justification when severity differs (e.g., same misconfiguration is High in production but Low in dev/test).
5. **Org-level executive summary**: when reviewing 3+ accounts, produce a rollup summary across all accounts with aggregate finding counts, common themes, and org-wide recommendations.

## Workspace Layout

```
<workspace>/
├── creds.txt                              # AWS temp credentials (per account)
├── scoutsuite-results/
│   └── scoutsuite_results_aws-<id>.js     # ScoutSuite JSON data
├── account-<id>-artifacts/
│   ├── Findings-<id>.md                   # Client-ready findings report
│   ├── Pentest-Updates-AWS-<id>.md        # Pentest update summary
│   ├── Exclusion-Log-<id>.md             # Scanner finding exclusion audit trail
│   ├── prowler_<profile>.ocsf.json        # Prowler OCSF results
│   └── ...validation scripts/JSONs...
```

## Credentials

Read AWS temporary credentials from `creds.txt` (format: INI-style with `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`). Use `boto3.Session(...)` for all API calls. Never hardcode credentials in reports or scripts that persist.

When credentials expire mid-workflow:
- Notify the user and ask for refreshed credentials
- Resume from where the workflow left off — do not restart completed phases
- Re-verify any in-progress findings with the new credentials

---

## Phase 1: Scanning

### Step 1: Identify the Account

```python
sts = session.client('sts')
identity = sts.get_caller_identity()
account_id = identity['Account']
```

Create the artifacts directory: `account-<account_id>-artifacts/`

### Step 1b: Classify the Account

Determine whether this is an **Organization management account**, a **member/workload account**, or a **standalone account**:

```python
orgs = session.client('organizations')
try:
    org = orgs.describe_organization()['Organization']
    master = org['MasterAccountId']
    is_management = (account_id == master)
except orgs.exceptions.AWSOrganizationsNotInUseException:
    is_management = None  # standalone
```

This affects: SCP applicability, delegated admin services, GuardDuty/SecurityHub ownership, and severity context (management accounts have broader blast radius).

**Ask the user** if the account classification doesn't match what they described (e.g., they said "production workload" but it's the org management account).

### Step 1c: Review Architecture Documentation

If the user provides architecture diagrams, infrastructure PDFs, or network topology docs — review them before validation. They inform: expected resource layout, multi-account relationships, data flow paths, and which services are in-scope vs intentionally absent.

### Step 2: Run ScoutSuite

```bash
scout --provider aws --profile <profile> --report-dir . --no-browser
```

- Output: HTML report + `scoutsuite-results/scoutsuite_results_aws-<account_id>.js`
- The `.js` file contains `scoutsuite_results = {...}` — strip the prefix to parse as JSON

### Step 3: Run Prowler (or accept provided results)

Prowler results are provided as `.ocsf.json` files (JSON array or JSONL format). If not already available, run:

```bash
prowler aws -F ocsf-json --output-directory account-<id>-artifacts/
```

### Parsing Scanner Results

**ScoutSuite:** Strip `scoutsuite_results =` prefix, parse JSON, extract findings where `flagged_items > 0` at level `danger` or `warning`.

**Prowler:** Parse as JSON array first; if that fails, parse line-by-line as JSONL. Filter for `status == "FAIL"` with severity high/critical/medium. **Critical trap:** Prowler's `status_detail` wording can be misleading — e.g., "does not allow '*:*' administrative privileges" is actually a PASS. Always read the actual `status_detail` text.

---

## Phase 2: Service-by-Service Live Validation

Validate every scanner finding with live AWS API calls using `creds.txt`. Do NOT rely solely on scanner output. **Parallelize validation** across independent service groups (e.g., IAM + S3 global checks in parallel with per-region EC2/network checks) using concurrent subagents where possible.

### Validation Order

1. **IAM** (global): roles, policies, trust relationships, PassRole, admin access, confused deputy, credential report, privilege escalation chains, cross-account trust
2. **S3** (global): bucket policies, HTTPS enforcement, public access blocks, cross-account access, encryption
3. **EC2/Network** (per-region): instances, EBS, subnets, NACLs, security groups, VPCs, IMDSv2, default VPC resource census
4. **Monitoring** (per-region): GuardDuty, SecurityHub, Inspector, CloudTrail (including data events), CloudWatch (secrets-in-logs)
5. **Encryption/KMS** (per-region): CMK rotation, Glue catalog encryption, EBS default encryption
6. **Compute** (per-region): ECS, Lambda, ELBv2 (SSL/TLS policies), CloudFront, RDS (snapshots, extended support), Secrets Manager, SSM (patch compliance)
7. **Containers** (per-region): EKS (public API endpoints, RBAC, node group IMDSv2, secrets encryption), ECR (public repos, image scanning, lifecycle policies)
8. **Data Services** (per-region): OpenSearch (public domains, encryption, fine-grained access), ElastiCache (encryption in transit, auth tokens, VPC), Redshift (public accessibility, encryption, audit logging, SSL)
9. **Storage** (per-region): EFS (encryption, mount target security groups, file system policies), FSx (encryption, backup)
10. **Networking** (per-region): Route 53 (dangling DNS, public hosted zones, DNSSEC), VPC Flow Logs, WAF WebACLs on ALB/CloudFront/API Gateway, API Gateway (authorization, throttling, resource policies)
11. **Backup & Recovery** (per-region): AWS Backup vault policies and plans, RDS automated backup retention, S3 versioning/Object Lock, DynamoDB PITR
12. **Identity** (global): IAM Access Analyzer findings, SSO/Identity Center (if applicable), Cognito user pools (self-signup, password policy, unauthenticated identity pool roles)
13. **Other**: Organizations, SNS, DynamoDB, CloudFormation, CloudWatch, EventBridge, SSM, Macie (if enabled — cross-reference S3 sensitive data findings)

### SCP-Blocked Region Detection

Before multi-region enumeration, detect SCP-restricted regions:

```python
ec2 = session.client('ec2')
all_regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
# Test each region with a lightweight call; AccessDeniedException = SCP-blocked
```

Exclude SCP-blocked regions from "missing coverage" findings (e.g., GuardDuty not enabled in a region the org intentionally blocks is not a finding).

**Ask the user** if you detect SCP-blocked regions: "I found X regions blocked by SCPs — should I exclude these from coverage findings, or do you want them noted?"

### IAM Deep Checks

- **Credential Report**: Parse the CSV from `iam.generate_credential_report()` / `iam.get_credential_report()`. Check: root MFA enabled, root access keys absent, password age, unused keys (>90 days), users without MFA.
- **Privilege Escalation Chains**: For each role with `iam:PassRole`, trace the chain: what target roles can be passed, what services can assume them, and what permissions those roles grant. Document the full escalation path (e.g., `PassRole` → `ecs:RunTask` → task role with `AdministratorAccess`).
- **Cross-Account Trust Validation**: For every role trust policy allowing cross-account access, verify: `sts:ExternalId` condition present, no wildcard (`*`) principals, `aws:SourceArn`/`aws:SourceAccount` conditions where applicable. Flag overly permissive trust without confused-deputy protections.

**Ask the user** about any cross-account roles that look unusual: "I found role X trusting account Y without ExternalId — is this an expected/intentional configuration?"

### Delegated Administrator Awareness

Some services (GuardDuty, SecurityHub, Config, CloudFormation StackSets) may be managed by a delegated administrator account. When API calls fail with `AccessDeniedException` or `detectorId is not owned by the current account`:
- Check `organizations.list_delegated_administrators()` to identify the admin account
- Note in the finding that the service is org-managed
- Adjust Steps to Reproduce to work from the member account perspective (e.g., use the member's own detector ID, not the admin's)
- **Ask the user** if you encounter delegated admin services: "Service X appears to be managed by a delegated admin account (Y). Should I report the finding from this member account's perspective, or do you have access to the admin account?"

### Default VPC Resource Census

For each region, enumerate actual resources in the default VPC: EC2 instances, RDS instances, ELB, Lambda (VPC-attached), ECS tasks. If the default VPC contains only auto-created subnets/NACLs/security groups with zero workloads, findings about default VPC misconfigurations should be downgraded to Low (preventive guardrail gap only).

### Service-Specific Deep Checks

- **CloudTrail Data Events**: Beyond management events, check if S3 data events and Lambda invocation events are logged. Missing data events is a separate finding from missing management event trails.
- **RDS Snapshots**: Check `rds.describe_db_snapshots()` and `describe_db_cluster_snapshots()` for public snapshots (`restore` attribute includes `all`). Also check for RDS Extended Support charges on end-of-life engine versions.
- **ELBv2 SSL/TLS Policies**: For each HTTPS listener, validate the SSL policy is not outdated (e.g., `ELBSecurityPolicy-2016-08` lacks TLS 1.2 enforcement). Compare against current AWS recommended policies.
- **Secrets in CloudWatch Logs**: Sample recent log events from log groups for patterns resembling API keys, passwords, tokens, or connection strings. Flag log groups containing potential secrets.
- **SSM Patch Compliance**: Query `ssm.describe_instance_patch_states()` for managed instances. Report non-compliant instances with counts and missing patch classifications (Critical, Security).
- **EKS Cluster Security**: For each cluster, check `eks.describe_cluster()` for: `endpointPublicAccess` (should be false or restricted by CIDR), `encryptionConfig` (secrets encryption with KMS), logging enabled (api, audit, authenticator). Check node groups for IMDSv2 enforcement via launch template metadata options.
- **ECR Repository Security**: Check `ecr.describe_repositories()` for image scanning configuration and lifecycle policies. Check `ecr-public.describe_repositories()` for unintentional public repositories.
- **Route 53 Dangling DNS**: For each hosted zone, enumerate records pointing to resources (S3, CloudFront, Elastic IP, ELB) and verify the target resource still exists. Dangling CNAMEs to decommissioned resources enable subdomain takeover.
- **VPC Flow Logs**: For each VPC, check `ec2.describe_flow_logs()`. Missing flow logs is a CWE-778 finding (Insufficient Logging).
- **WAF Coverage**: For each ALB, CloudFront distribution, and API Gateway, check `wafv2.get_web_acl_for_resource()`. Missing WAF on internet-facing resources is reportable.
- **API Gateway Authorization**: For each REST/HTTP API, check authorization type on each route/method. `NONE` on public endpoints without WAF is a finding.
- **IAM Access Analyzer**: Check if an analyzer exists (`accessanalyzer.list_analyzers()`). If yes, cross-reference its findings with the agent's own external access checks. If no analyzer exists, that is itself a finding.
- **Backup Coverage**: Check `backup.list_backup_plans()` and verify critical resources (RDS, EBS, DynamoDB, EFS) are covered. Check RDS automated backup retention period (0 = disabled).
- **SSM Documents**: Check `ssm.list_documents(Filters=[{'Key':'Owner','Values':['Self']}])` for custom documents containing embedded scripts, credentials, or automation with elevated privileges.

### Multi-Region Verification

Check ALL accessible regions (excluding SCP-blocked ones). For each region-scoped service:
- Enumerate resources per region
- Track which regions have active workloads vs only default VPC infrastructure
- If a finding spans empty regions, note this context and adjust severity

### Resource Existence Check

Before reporting a finding, verify resources actually exist. If zero resources exist for a service:
- Assess if the finding is a preventive guardrail gap (still reportable at Low) or not applicable
- Do NOT assign Medium+ severity to findings where the entire scope is empty regions/services

---

### Post-Validation Checkpoint

Before proceeding to gap analysis, present a summary to the user:
- Total findings validated so far (by severity)
- Any findings you're unsure about (borderline severity, unusual config, ambiguous scope)
- Services with zero resources (confirm user expects this)
- Any API access issues encountered

**Ask the user**: "Here's what I've found so far — [summary]. Any of these look like known/accepted risks I should exclude? Anything missing you expected me to find?"

---

## Phase 3: Gap Analysis

Cross-reference Prowler and ScoutSuite results against validated findings:

1. Parse all unique Prowler FAIL checks (high/critical/medium)
2. Parse all ScoutSuite danger/warning findings
3. For each scanner finding, determine: covered by report, correctly excluded, or genuine gap
4. Document exclusion reasoning (false positive, out of scope, duplicate, zero resources, etc.)
5. Produce an exclusion log artifact (`account-<id>-artifacts/Exclusion-Log-<id>.md`) with: scanner finding ID, scanner name, exclusion category (false positive / accepted risk / not applicable / duplicate), and reasoning

### Scanner Disagreement Process

When the agent's live validation contradicts a scanner finding:
- **Scanner says FAIL, live says PASS**: document the discrepancy with the specific API call and response that disproves the scanner. Classify as "false positive" in the exclusion log.
- **Scanner says PASS, live says FAIL**: this is a genuine gap — the scanner missed it. Add to the findings report with a note that it was not flagged by scanners.
- **Scanner and agent disagree on severity**: use the agent's live-validated severity with documented justification.

### Time-of-Check Awareness

For multi-day engagements, resources may be created or deleted during the review:
- Before finalizing the report, perform a final resource count reconciliation against the live environment
- If resources referenced in findings no longer exist, update or remove the finding
- If new resources appear that would be in-scope, assess them before report delivery

**Ask the user** if the gap analysis reveals potential findings that are borderline: "Scanner flagged X but live validation shows [context]. Should I include this as a finding or exclude it? Here's my reasoning: [reasoning]."

---

## Phase 4: Findings Report Drafting

Create `account-<id>-artifacts/Findings-<id>.md` using the format defined in [reference.md](reference.md) (finding template, severity bands, CWE mappings).

### Finding Format

Key rules:

- Use XML-like tags: `<Vulnerability Title>`, `<Vulnerability Description>`, `<CVSS 3.1 Score with string>`, `<Reference>`, `<Affected Resources>`, `<OWASP Severity>`, `<CWE>`, `<Steps to Reproduce>`, `<Evidence>`, `<Impact>`, `<Business Risk Context>`, `<Suggested Fix>`, `<Remediation Effort>`, `<Status>`, `<Date Identified>`, `<Prerequisites (optional)>`
- Separate findings with `---`
- Order: High → Medium → Low (strict descending CVSS)
- CVSS vectors must mathematically produce the stated score
- Every Trend Micro URL must be validated (not 404) and must be topically relevant to the specific finding — not just a generic service page
- Include the complete list of ALL affected resources — not a sample. Include resource identifiers, regions, and relevant context (e.g., VPC ID, subnet count, encryption status)
- Steps to Reproduce: numbered, with AWS CLI commands and `- Purpose:` annotations
- Use specific resource identifiers, not generic placeholders
- Reuse proven Steps to Reproduce patterns from previously completed accounts where the same finding type applies
- When a CLI command returns an expected error (e.g., `NoSuchBucketPolicy`), document the error as confirmation
- Formal pentest language — no "Live validation confirmed" or tool-centric phrasing

### Severity Rules

- CVSS 3.1 must be mathematically verified
- Do not blindly accept scanner severities
- OWASP Likelihood/Impact must align with CVSS band
- Impact language must be proportional to severity
- CWE must be semantically correct for the specific issue
- If too many Mediums, evaluate which can be justifiably downgraded to Low
- Remove findings that are purely informational or no longer applicable

**Ask the user** when a severity decision is close to a boundary: "Finding X could be rated Medium (5.3) or Low (3.8) depending on whether [context factor] applies. Which context is correct for this environment?"

---

## Phase 5: Pentest Updates

Create `account-<id>-artifacts/Pentest-Updates-AWS-<id>.md`:

- Bullet-point summaries per service section
- Each finding: one-line summary + `**Severity: <level> (<CVSS>). Confirmed.**`
- Passed high/critical checks: resource counts, regions validated
- Services with zero resources: mark as `**Severity: Informational. N/A.**`
- Prowler/ScoutSuite coverage summary section
- Passed checks section with per-service breakdown

---

## Phase 6: Sanity Checks

Run after every draft and every update:

1. **CVSS math**: Calculate each vector and verify it matches the stated score
2. **Ordering**: Confirm strict descending CVSS order
3. **Structural completeness**: All XML tags present and closed for every finding
4. **CWE validation**: Correct CWE ID and name for each issue
5. **OWASP alignment**: Likelihood/Impact ratings consistent with CVSS band
6. **URL validation**: Every Trend Micro reference returns 200 (not 404)
7. **Resource counts**: Match live environment
8. **Account ID check**: No cross-contamination of resource IDs between accounts
9. **Cross-account consistency**: Same finding types use consistent severities across accounts with documented justification for differences
10. **Edge cases**: Empty regions, zero-resource services, default VPC-only infrastructure
11. **Client reproducibility**: Execute each finding's Steps to Reproduce commands against the live account to verify they work. Watch for: hardcoded IDs from a different account/session, delegated admin detector IDs, expired resource references, and commands that require specific CLI profiles
12. **Account type context**: Verify severity accounts for whether this is a management vs member account (management account compromise has broader blast radius)
13. **Terminology & spelling**: spell-check all deliverables; verify consistent terminology throughout
14. **Pagination completeness**: verify all API calls used paginators — never assume a single `describe_*` call returns all results

### CVSS Calculation (Python)

```python
import math

def cvss31(vector_str):
    parts = {}
    for item in vector_str.split('/'):
        k, v = item.split(':')
        parts[k] = v
    AV = {'N':0.85,'A':0.62,'L':0.55,'P':0.20}
    AC = {'L':0.77,'H':0.44}
    PR_U = {'N':0.85,'L':0.62,'H':0.27}
    PR_C = {'N':0.85,'L':0.68,'H':0.50}
    UI = {'N':0.85,'R':0.62}
    CIA = {'N':0.0,'L':0.22,'H':0.56}
    S = parts['S']
    pr = PR_C if S == 'C' else PR_U
    exploit = 8.22 * AV[parts['AV']] * AC[parts['AC']] * pr[parts['PR']] * UI[parts['UI']]
    isc = 1-((1-CIA[parts['C']])*(1-CIA[parts['I']])*(1-CIA[parts['A']]))
    impact = 6.42*isc if S=='U' else 7.52*(isc-0.029)-3.25*(isc-0.02)**15
    if impact <= 0: return 0.0
    score = min(exploit+impact, 10) if S=='U' else min(1.08*(exploit+impact), 10)
    return math.ceil(score * 10) / 10
```

---

## Phase 7: Maintenance

When credentials are refreshed or the environment changes:
- Re-verify affected findings with live API calls
- Update resource counts, identifiers, descriptions, and severity if warranted
- Remove findings no longer applicable
- Re-run sanity checks

---

## Common Pitfalls

| Pitfall | Solution |
|---------|----------|
| Prowler "FAIL" that's actually a pass | Read `status_detail` text carefully |
| ScoutSuite findings in `.js` not `.html` | Parse `scoutsuite_results_aws-<id>.js`, strip JS prefix |
| CVSS score doesn't match vector | Always calculate mathematically, never estimate |
| Finding spans 17 regions but only 2 have resources | Downgrade severity, note empty-region context |
| Trend Micro URL returns 404 | Navigate the KB base page to find the correct URL |
| Hardcoded detector/resource IDs in Steps to Reproduce | Reference prior step output instead |
| "Live validation confirmed" in report text | Use formal pentest language only |
| Same finding at different severity across accounts | Must have documented justification |
| GuardDuty/SecurityHub managed by delegated admin | API calls fail from member account — use member's own detector ID |
| SCP blocks regions but scanner flags missing coverage | Detect SCP-blocked regions and exclude from findings |
| PassRole exists but no escalation path traced | Map the full chain: PassRole → target role → service → permissions |
| Steps to Reproduce fail when client runs them | Test all commands against live account before finalizing |
| Default VPC findings rated Medium but zero workloads | Census default VPC resources; downgrade to Low if empty |
| CloudTrail "enabled" but no data events | Check data event selectors separately from management events |
| RDS snapshot marked private but `restore` allows `all` | Always check snapshot attributes, not just instance settings |
| Secrets visible in CloudWatch log events | Sample recent log events for credential patterns |
| Management account treated same as member | Management accounts have broader blast radius — adjust severity context |
| Assumed a config was intentional or accidental | Always ask the user — never assume intent for unusual configurations |
| Skipped intake questions to save time | Intake questions prevent rework; always ask them before Phase 1 |
| `ec2.describe_regions()` returns only opted-in regions | Use `AllRegions=True` parameter to detect opt-in regions that are disabled |
| Paginated API responses truncated | Always use paginators (`get_paginator()`) — never assume a single `describe_*` call returns all results |
| Service quotas hit during enumeration | Implement exponential backoff and handle `ThrottlingException` / `TooManyRequestsException` |
| S3 `GetBucketPolicy` returns `NoSuchBucketPolicy` | This means no resource policy exists — not an error; different from a permissive policy |
| Lambda@Edge functions only visible in us-east-1 | Always check us-east-1 for Lambda@Edge even if other regions are primary |
| Dangling CNAME to deleted resource | Enumerate Route 53 records and verify target resources still exist |
| EKS public endpoint flagged but restricted by CIDR | Check `publicAccessCidrs` — if restricted to corporate IPs, downgrade severity |
| Cognito identity pool allows unauthenticated | Check the IAM role attached to unauthenticated identities — if role is minimal, adjust severity |
