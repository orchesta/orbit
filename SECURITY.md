# Security policy

## Supported versions

Security fixes go into the latest release. Please upgrade to it before reporting a problem, if you can.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub instead: open the [Security tab](https://github.com/orchesta/orbit/security) of this repository and choose **Report a vulnerability**. Include what you can of the following:

- the Orbit version (`orbit version`) and how you run it (server, CLI, Docker image, CI template),
- the steps or input that trigger the problem,
- what an attacker could do with it.

We will acknowledge the report, keep you informed while we look into it, and credit you in the release notes if you wish. This is a small project, so please allow some time for a fix.

## Scope

Reports about Orbit itself are welcome, for example the server, the API, the `orbit scan` CLI, the Docker images and the CI templates in this repository.

Vulnerabilities that Orbit reports in your dependencies come from [osv.dev](https://osv.dev). Please report those to the affected project or to osv.dev, not here.
