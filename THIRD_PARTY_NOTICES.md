# Third-party references

The application and its eight rules were authored for this project. No code or rule bodies were copied from Hayabusa, Zircolite, Sigma, Timesketch, IRIS or OTRF datasets. Their design influence is described in the specification.

MITRE ATT&CK identifiers, technique names and official links identify the behavior considered by a rule. ATT&CK is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE or OWASP.

Runtime libraries: Python, Typer, Pydantic, PyYAML, Jinja2, tzdata and their dependencies. The exact resolved versions and distribution hashes are in `uv.lock` / `requirements.lock.txt`. Their license notices remain in the installed distributions. The dependency inventory is generated from the installed environment for each release.

All identities and requests belong to controlled synthetic scenarios. The lab collection contains audit logs captured from actual requests to a disposable local HTTP application. External security datasets are referenced in the specification but are not redistributed.
