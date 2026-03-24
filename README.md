# Security Review Skills

A collection of AI agent skills focused on security testing, penetration testing, and vulnerability assessment. Each skill provides a structured, repeatable workflow that can be used with Cursor (or compatible AI coding agents) to perform thorough security reviews.

## Repository Structure

```
Skills/
├── README.md
├── java-desktop-security-pentest/
│   └── SKILL.md
└── <future-skill>/
    └── SKILL.md
```

Each skill lives in its own directory and contains a `SKILL.md` file with front matter metadata, scope definition, mandatory rules, phased workflows, test matrices, reporting templates, and quality gates.

## Skills

### [Java Desktop Security Pentest](java-desktop-security-pentest/SKILL.md)

End-to-end security testing workflow for Java desktop applications (JAR-based).

| Detail | Value |
|--------|-------|
| **Categories** | 11 |
| **Test Cases** | 73 (43 static, 19 dynamic, 11 hybrid) |
| **Platforms** | macOS, Linux, Windows |

**Coverage areas:**

- JAR integrity, manifest inspection, bytecode decompilation, and obfuscation assessment
- Dependency CVE audit with SBOM generation (CycloneDX + SPDX)
- Java deserialization exploitation (ysoserial, gadget chain mapping, blacklist probing)
- Local filesystem artifact review (credentials, PHI, temp files, permissions)
- Network and transport security (TLS/SSL trust-all detection, certificate pinning, JNDI/RMI)
- Authentication and authorization (brute-force, RBAC, horizontal/vertical privilege escalation)
- Input validation and injection (XXE, SQL injection, script sandbox escape, Rhino/Nashorn)
- Cryptography audit (weak hashing, hardcoded keys, deprecated algorithms, PRNG)
- Platform-specific checks (Gatekeeper, JMX/debug ports, DYLD injection, DLL hijacking)
- Logging, error handling, and audit trail completeness
- Data leakage and privacy (heap memory secrets, clipboard, export paths)

**Deliverables:** Security test results matrix, findings report (CVSS 3.1 + OWASP + CWE), dynamic testing playbook, SBOM artifacts, screenshot evidence, and post-remediation re-test tracking.

---

## Adding a New Skill

1. Create a new directory at the repo root with a descriptive kebab-case name (e.g., `web-api-security-review/`).
2. Add a `SKILL.md` file inside with YAML front matter (`name`, `description`) followed by the full workflow.
3. Update this README by adding an entry under the **Skills** section following the format above.

### Skill Template

```yaml
---
name: your-skill-name
description: >
  One-paragraph description covering scope, test count, and primary use cases.
---

# Skill Title

## Scope
## Mandatory Rules
## Phases / Workflow
## Reporting
## Quality Gates
```

## Usage

These skills are designed for use with [Cursor](https://cursor.com) AI agent mode. To use a skill:

1. Clone this repo or point your Cursor skill path to the relevant `SKILL.md`.
2. When starting a security review, reference the skill — the agent will follow the phased workflow, execute static tests autonomously, and prepare commands/payloads for dynamic tests that require user interaction.
3. The agent will produce structured deliverables (reports, SBOMs, evidence) as defined in each skill's reporting phase.

## License

Private repository. All rights reserved.
