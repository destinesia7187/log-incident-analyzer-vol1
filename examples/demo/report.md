# Log Incident Analyzer — investigation report

Cases: 1 · Alerts: 3 · Events: 12

Rule matches require analyst review. Missing observations do not establish safety.

## Telemetry

| Rule | Status | Eligible / candidates |
|---|---|---|
| DET\-001 | ready | 10 / 10 |
| DET\-002 | ready | 10 / 10 |
| DET\-003 | ready | 1 / 1 |
| DET\-004 | ready | 10 / 10 |
| DET\-005 | no\_data | 0 / 0 |
| DET\-006 | ready | 1 / 1 |
| DET\-007 | no\_data | 0 / 0 |
| DET\-008 | no\_data | 0 / 0 |

## MFA device registration after suspicious sign\-in

**HIGH · escalate** · CASE-5c25878f2d3916bb74f3f976

UTC: 2026-01-15T12:00:00Z — 2026-01-15T12:02:00Z

User: demo\-user; source: 192\.0\.2\.10

Score: 75 · Evidence confidence: supported
Status: new

- maximum rule severity: 60
- mfa registration sequence: 15

### ATT&CK candidates

- T1110\.001: candidate\. Observed events satisfy the documented rule conditions; intent requires analyst review\.
- T1098\.005: candidate\. Observed events satisfy the documented rule conditions; intent requires analyst review\.

### Context


### Facts

- Successful sign\-in after failures: documented rule conditions matched\.
- Repeated failed sign\-ins: documented rule conditions matched\.
- MFA device registration after suspicious sign\-in: documented rule conditions matched\.

### Hypotheses

- Potential unauthorized activity; verify with the account or service owner\.

### Alternative explanations

- An authorized account recovery may include registration of a new device\.
- The account owner may have mistyped or used an outdated password\.
- The owner may have recovered access\. A successful login alone does not prove compromise\.

### Limitations

- Observed behavior requires analyst review; compromise is not established\.

### Next checks

- Review related audit records and approved maintenance context\.
- Verify the account owner or service owner recognizes the activity\.

### Evidence

12 events. Full records: analysis.json / analysis.sqlite.

- 106c16d0f1c454b536a394637d930175cc6a2689cc7dcac4648984600c108d87
- 1f4eb268c9cee97277bb6bbc3cd2146efc3ab589c0659a444afaf0ea78ef573d
- 223a9874a4ef9929b53afa683b840c78cbd9e5500cfa1de0f9bd2162c779d924
- 4d4e1b9359e1f9579f9d8c0587e792eee90a39800293cccda29ab8805760a299
- 504fc8dc69286e0dabda18b96f9e026f704ba286b05eb9d05632778f99d7b1f1
- 85e4a9283875a8c5793e9003d318fa32da4bd56371e7a11d09068c6e62c1b745
- 8e1cd4b72237e4bae782008f87bd679ff48fac2e7b1e620a7b87d41601adb14d
- a056a8437f9461e477fdce998d55bfe047fd931c6eb02ab614bb592f4bc8dcce
- b22c7b325a12234a752a5691ac1e739ea6c916dabe0f97f91afd8a48483ef5e8
- b51f623ff87d08af8e9d2779fb97d030f454eac3f77fd58675723b7c1e6278aa
- f34a80d06acfa1f9d10945c83122da5587111710c231b393dbbb32bcdbb928bb
- ffcddb9d966fbd50bf21aa140a360eadbe7894c8cb7a6b99f9f4bb7b55f415c4

### Analyst notes
