# Security policy

DWI is safety-sensitive storage software.

## Reporting a vulnerability

When the public repository is available, use its GitHub **Security** tab and
the **Report a vulnerability** / **Security Advisories** workflow for private
coordination. Do not open a regular public Issue for a sensitive vulnerability
and do not publicly disclose exploit details before coordination.

Release operator action: **Enable GitHub Private Vulnerability Reporting
immediately when the repository becomes public.** Until that setting is
enabled, use the repository's configured private maintainer channel; no email
address is implied by this document.

Normal non-security bugs belong in regular GitHub Issues once that repository
channel is enabled.

Prioritize reports involving:

- a path that bypasses protected-root, network or reparse checks;
- a way to manufacture safety decisions, human confirmation or authority;
- duplicate mutation, replay, journal corruption or recovery loss;
- hidden network access, telemetry, upload or protocol leakage;
- a release artifact that executes outside the documented boundary.

DWI does not promise that Python or Windows filesystem APIs are atomic under
all concurrent replacement races. The documented response is conservative
blocking, explicit partial state and recovery reconciliation. Do not include
secrets, private paths or journal contents in a report unless essential and
sanitized.
