# Security Policy

## Scope

This policy covers vulnerabilities in the **Terasploit Framework** itself —
bugs in the framework code, its entry points, its module loading system, or
its dependencies that could cause unintended harm to a user running TSF on
their own machine.

This policy does **not** cover:

- Techniques, payloads, or modules that work as intended against authorized
  targets. That is the purpose of the framework.
- Vulnerabilities in third-party tools, targets, or systems that TSF interacts
  with during authorized testing.

---

## Reporting a Vulnerability

If you discover a vulnerability in the framework itself, please **do not open
a public issue**. Disclosing exploitable bugs publicly before a fix is
available puts users at unnecessary risk.

Report it privately by emailing:

**asteroth.git@gmail.com**

Include:

- A clear description of the vulnerability.
- Steps to reproduce.
- The version or commit hash where you observed the issue.
- Your assessment of the impact and exploitability.

You will receive an acknowledgement within 7 days. If a fix is warranted, it
will be coordinated with you before any public disclosure.

---

## Supported Versions

Only the current `master` branch receives security fixes. No patches are
backported to older versions.

---

## Legal Boundary

Terasploit is intended exclusively for **authorized security testing and
educational research**. Using it against systems you do not own or lack
explicit written permission to test is illegal and unethical.

Reporting a vulnerability in the framework is not authorization to use the
framework against systems you do not control. The authors accept no liability
for misuse.
