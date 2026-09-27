# References and mapping boundaries

These projects informed requirements and design choices. Their code and detection catalogs were not copied into this implementation.

| Reference | Relevant idea |
|---|---|
| [Sigma specification](https://sigmahq.io/sigma-specification/) | Declarative rule metadata; this project's DSL has its own explicit semantics |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Local log investigation and reproducible CLI workflows |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Timelines and investigation-oriented results |
| [Zircolite](https://github.com/wagga40/Zircolite) | Portable local analysis with SQLite |
| [DFIR-IRIS](https://github.com/dfir-iris/iris-web) | Structured cases and analyst handoff |
| [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Explicit outcomes, correlation identifiers, sensitive data exclusion and log integrity |
| [OWASP Top 10](https://owasp.org/Top10/) | Application-security context; category membership is not proof of a vulnerability |

ATT&CK candidate references:

- [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/), [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/).
- [T1621 Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/).
- [T1098.005 Device Registration](https://attack.mitre.org/techniques/T1098/005/): applied only with declared identity-provider scope and qualifying sequence evidence.

Packaged rules record rationale, candidate status and references. No ATT&CK mapping is manufactured from a 404/403 response alone. DET-008 establishes repeated authorization denial, not broken access control. Successful MFA enrollment alone does not establish persistence. ATT&CK metadata is a small reviewed allowlist, not a complete STIX snapshot or an automatic upstream synchronization service.

OWASP is reflected in the event contract and readiness recommendations. The report is not a compliance assessment. Offline operation means reference updates require an explicit reviewed release.
