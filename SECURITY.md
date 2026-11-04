# Security policy

Please report vulnerabilities privately through GitHub security advisories: open the repository's Security tab and choose "Report a vulnerability".

Do not open public issues, pull requests or discussions for security problems.

In scope: anything a website, a network attacker, or a tampered release or catalogue could use against a signer, and anything a signer or a website could use against an integrator's backend or signing service. Out of scope: attacks that need code already running as the signer's own user, or an administrator account, on their machine; [docs/design.md](docs/design.md#trust-model) explains why.

Include the affected component (helper, `@keyseal/server`, `@keyseal/browser`, service or spec), the version, and steps to reproduce. We will acknowledge the report, keep you informed while we work on a fix, and credit you in the advisory unless you prefer otherwise.
