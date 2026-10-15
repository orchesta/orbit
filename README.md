# Orbit

[![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Orbit is a self-hosted dependency and vulnerability scanner. It reads the manifests and lockfiles of Go, npm, Python and NuGet projects, looks every package up in [osv.dev](https://osv.dev) and reports known vulnerabilities and outdated versions. It runs either as a **server** (web UI and REST API backed by PostgreSQL) that scans your GitHub, GitLab and Azure DevOps repositories on a schedule, or as the **`orbit scan` CLI**, which needs no database and can fail a CI build when it finds vulnerable dependencies.

The backend is Go, the UI is React, and the database is PostgreSQL. Orbit is an early-stage project and has no tagged release yet; see [Limitations](#limitations) before relying on it.

## Contents

- [Features](#features)
- [Two ways to run Orbit](#two-ways-to-run-orbit)
- [Quick start: server](#quick-start-server)
- [Command line: `orbit scan`](#command-line-orbit-scan)
- [Quick start: CI](#quick-start-ci)
- [Supported ecosystems and files](#supported-ecosystems-and-files)
- [Git providers](#git-providers)
- [Configuration](#configuration)
- [REST API](#rest-api)
- [Deployment](#deployment)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Development](#development)
- [License](#license)

## Features

- Go modules, npm (npm, yarn v1 and berry, pnpm), Python (requirements files, Pipfile, Poetry, uv, `pyproject.toml`) and NuGet.
- Uses lockfiles for exact versions, including transitive dependencies. Manifest-only projects get an estimated version and a warning.
- Vulnerability data from osv.dev. Outdated-version checks against npm, PyPI, NuGet and the Go module proxy.
- Server: imports repositories from GitHub, GitLab and Azure DevOps (Services and Server), scans them on a cron schedule per repository with a bounded worker pool, and shows a dashboard, a vulnerability list and scan history.
- CLI: `orbit scan` with `table`, `json`, `sarif` and `junit` output, a severity threshold, documented exit codes, and an `.orbitignore` file for accepted findings with optional expiry dates.
- Flags known malicious packages (OpenSSF Malicious Packages, `MAL-` advisories on osv.dev) separately. They fail `orbit scan` at every `--fail-on` level except `none`.
- Ready-made CI templates for GitHub Actions, GitLab CI and Azure Pipelines (Azure DevOps Services and Server 2020+).
- Access tokens are encrypted at rest (AES-256-GCM). First-run setup is protected by a setup token. Failed logins are rate-limited.

## Two ways to run Orbit

| | Server (`orbit serve`) | CLI (`orbit scan`) |
| --- | --- | --- |
| Use it for | Continuous monitoring of many repositories | Checking a build in CI, or a local checkout |
| What it scans | Clones each repository's configured branch | A directory that is already on disk |
| Needs | PostgreSQL, a JWT secret, an encryption key | Nothing except outbound HTTPS to `api.osv.dev` |
| Interface | Web UI on port 8080, REST API under `/api/v1` | Report on stdout or in a file, exit code 0/1/2 |
| Triggers | Cron schedule per repository, or **Scan Now** in the UI | Every pipeline run |
| Outdated versions | Always checked | Only with `--outdated` |
| Distribution | `orchestalabs/orbit` image on Docker Hub, Docker Compose, Kubernetes manifest | `orchestalabs/orbit-cli` image on Docker Hub, release binaries, CI templates |

Both are the same binary. `orbit` with no arguments, or `orbit serve`, starts the server. `orbit scan` runs the CLI. `orbit version` prints the version and `orbit help` lists the subcommands.

## Quick start: server

Prerequisites: Docker with Docker Compose, `git`, `bash` and `openssl`.

```bash
git clone https://github.com/orchesta/orbit.git
cd orbit
bash run.sh
```

Run `run.sh` from the repository root. It:

1. generates `ORBIT_JWT_SECRET`, `ORBIT_CRYPTO_ENCRYPTION_KEY` and `ORBIT_SETUP_TOKEN` into `deploy/docker/.env` (mode 600) on the first run and reuses them afterwards,
2. refuses to start if an old PostgreSQL 16 volume still holds data that has not been migrated (see [Upgrading from PostgreSQL 16](#upgrading-from-postgresql-16)),
3. builds the image and runs `docker compose up --build` in the foreground.

It also deletes macOS metadata files (`._*` and `.DS_Store`) under the current directory, because they break Docker builds on some external drives.

**Back up `deploy/docker/.env`.** Without the `ORBIT_CRYPTO_ENCRYPTION_KEY` it holds, stored access tokens cannot be decrypted and must be added again.

If you prefer to start Compose yourself on a fresh install, create the `.env` file first. Compose refuses to start without the three secrets:

```bash
# Fresh installs only. Never overwrite an existing .env: it holds the encryption key.
test -e deploy/docker/.env || (umask 077 && {
  echo "ORBIT_JWT_SECRET=$(openssl rand -hex 32)"
  echo "ORBIT_CRYPTO_ENCRYPTION_KEY=$(openssl rand -hex 32)"
  echo "ORBIT_SETUP_TOKEN=$(openssl rand -hex 32)"
} > deploy/docker/.env)
make docker-up    # docker compose -f deploy/docker/docker-compose.yml up --build -d
```

To replace the default database password (`orbit_secret`), add `ORBIT_DATABASE_PASSWORD=...` to `deploy/docker/.env` **before the first start**. PostgreSQL only reads it when it initializes the volume.

### First run

1. Open <http://localhost:8080>. On a fresh install the setup page opens.
2. Enter your email, password and display name, plus the **setup token**. It is the `ORBIT_SETUP_TOKEN` value in `deploy/docker/.env`:

   ```bash
   grep '^ORBIT_SETUP_TOKEN=' deploy/docker/.env
   ```

   The token makes sure nobody else can claim a freshly exposed instance by creating the first admin account.
3. **Settings → Access Tokens → Add Token**: add a GitHub or GitLab personal access token. For Azure DevOps, add a connection under **Azure DevOps connections** first, then a token for it (see [Git providers](#git-providers)).
4. **Repositories → Import**: pick repositories from a token, or add one manually by URL.
5. Each repository is scanned on its schedule (default `0 */6 * * *`, every 6 hours; schedules run at most every 15 minutes). Open a repository and click **Scan Now** for an immediate scan.
6. Check the **Dashboard** for the overview and **Vulnerabilities** for the findings of each repository's latest scan.

### Existing deployments and the setup token

`deploy/docker/docker-compose.yml` requires `ORBIT_JWT_SECRET`, `ORBIT_CRYPTO_ENCRYPTION_KEY` and `ORBIT_SETUP_TOKEN`, and a missing value makes every `docker compose` command fail, including `down`. Older deployments have none of them in `deploy/docker/.env`. Run `bash run.sh` once: it generates the missing values and, if needed, then stops at the PostgreSQL upgrade guard with the migration instructions. If you manage `.env` yourself, add the three variables (for example the output of `openssl rand -hex 32`, written out as a value). A new `ORBIT_CRYPTO_ENCRYPTION_KEY` cannot decrypt tokens stored with an earlier one, so keep any existing key.

## Command line: `orbit scan`

`orbit scan` checks a directory that is already on disk, such as your working copy or a CI checkout, without a server or a database. It prints or writes a report and exits with a code a build can act on. `orbit scan -h` lists every flag.

### Install

| Option | How |
| --- | --- |
| Docker | `docker run --rm -v "$PWD":/src:ro orchestalabs/orbit-cli:<tag>` ([Docker Hub](https://hub.docker.com/r/orchestalabs/orbit-cli); runs `scan --path /src` by default) |
| Release binary | `orbit_<tag>_<os>_<arch>` from the [GitHub releases](https://github.com/orchesta/orbit/releases) for Linux amd64/arm64, macOS amd64/arm64 and Windows amd64, verified against `checksums.txt` (see below) |
| From source | `go install github.com/orchesta/orbit/cmd/orbit@latest` with Go 1.27+ (reports version `dev`), `go build -o orbit ./cmd/orbit` in a clone, or `docker build -f deploy/docker/Dockerfile.cli -t orbit-cli .` |

Images and binaries are published when a `v*` tag is pushed (see [Releases and images](#releases-and-images)). To install a release binary on Linux or macOS:

```bash
TAG=v1.0.0                      # the release you want
ASSET=orbit_${TAG}_linux_amd64  # or linux_arm64, darwin_amd64, darwin_arm64, windows_amd64.exe
BASE=https://github.com/orchesta/orbit/releases/download/$TAG
curl -fsSLO "$BASE/$ASSET" && curl -fsSLO "$BASE/checksums.txt"
grep " $ASSET\$" checksums.txt | sha256sum -c -     # macOS: shasum -a 256 -c -
chmod +x "$ASSET" && sudo mv "$ASSET" /usr/local/bin/orbit
```

### Usage

```bash
orbit scan                                   # current directory, table on stdout, fail on high or critical
orbit scan --path services/api               # one part of a monorepo
orbit scan --fail-on critical                # fail only on critical findings
orbit scan --format sarif --out orbit.sarif  # also: json, junit
orbit scan --outdated                        # also check for newer versions
```

```
SEVERITY  ID              PACKAGE         FIXED    MANIFEST
HIGH      CVE-2020-8203   lodash@4.17.15  4.17.19  package-lock.json
HIGH      CVE-2021-23337  lodash@4.17.15  4.18.0   package-lock.json
MEDIUM    CVE-2020-28500  lodash@4.17.15  4.17.21  package-lock.json
MEDIUM    CVE-2025-13465  lodash@4.17.15  4.18.0   package-lock.json

1 dependencies, 1 vulnerable (2 high, 2 medium)
threshold high: FAILED
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--path` | `.` | Directory to scan |
| `--fail-on` | `high` | `critical`, `high`, `medium`, `low`, `unknown` or `none`; a known malicious package fails at every value except `none` |
| `--format` | `table` | `table`, `json`, `sarif` or `junit` |
| `--out` | `-` (stdout) | Report file |
| `--ignore-file` | `<path>/.orbitignore` if it exists | Accepted findings; `""` disables it |
| `--outdated` | off | Also ask the registries for the latest versions |
| `--timeout` | `10m` | Give up after this long |
| `--quiet` / `--verbose` | off | Less or more progress on stderr |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Clean, or every finding is below `--fail-on` or ignored, and none is a malicious package (or `--fail-on none`) |
| 1 | At least one finding that is not ignored is at or above `--fail-on`, or is a malicious package (at every level except `none`) |
| 2 | The scan could not complete: osv.dev unreachable, timeout, bad flag, missing or invalid ignore file |

On exit 2 nothing is written to stdout and an existing `--out` file is deleted, so a stale report is never uploaded. An osv.dev failure never counts as "no vulnerabilities".

### `.orbitignore`

Accept a finding on purpose, with a reason, instead of lowering the threshold:

```
# <advisory-id> [expires=YYYY-MM-DD] [package=<name>] reason...
GHSA-xxxx-yyyy-zzzz  expires=2026-12-31  Not reachable: only used in tests
CVE-2024-1234        package=lodash      Accepted until the upgrade, see JIRA-12
```

- Put the file at the root of the scanned directory, or pass it with `--ignore-file`. Blank lines and lines starting with `#` are ignored.
- Matching is case-insensitive and covers the ID a finding is reported under and its aliases, so either the CVE or the GHSA ID works.
- `expires=YYYY-MM-DD` keeps an entry active until the end of that day (UTC); after that the finding counts again and a warning is printed.
- `package=<name>` limits an entry to one package.
- Entries do not apply to malicious packages (see below). A matching entry produces a `not applied` warning instead.
- A malformed line is an error (exit 2) that names the line. Entries that never matched produce an `unused ignore entry` warning.
- Ignored findings still appear in the reports, marked as ignored.

### Malicious packages

osv.dev also serves the [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) database. Its advisories have IDs that start with `MAL-` and usually carry no severity score. Orbit treats a finding as malicious when its ID or one of its aliases starts with `MAL-`:

- It is rated `critical` when the advisory has no score of its own.
- It fails the scan at every `--fail-on` level except `none`, whatever its severity.
- `.orbitignore` entries do not apply to it.
- Reports list it first and mark it: `(malicious)` in the table and `N malicious` in the summary line, `"malicious": true` on the JSON finding and a `malicious` count in the JSON summary, the `malicious` tag and `security-severity` 10.0 in SARIF, and the failure type `malicious` in JUnit.

```
SEVERITY              ID              PACKAGE      FIXED  MANIFEST
CRITICAL (malicious)  MAL-2025-46969  chalk@5.6.1  -      package-lock.json

1 dependencies, 1 vulnerable (1 critical), 1 malicious
threshold high: FAILED
```

A malicious package version was published with harmful code on purpose. Upgrading may not be enough: remove it, and treat machines and CI runners that installed it as compromised.

## Quick start: CI

The same `orbit scan` runs in ready-made templates. Each template describes its inputs in the comment at its top.

### GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@<full commit SHA> # vX.Y.Z
  - uses: orchesta/orbit@v1.0.0
    with:
      fail-on: high
      version: v1.0.0
  - if: always() && hashFiles('orbit.sarif') != ''
    uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
    with:
      sarif_file: orbit.sarif
```

`v1.0.0` is a placeholder for a real release tag. Pin it in both places: `version` is the tag of the `orchestalabs/orbit-cli` image the action runs, and a major ref such as `@v1` has no image tag. The action writes `orbit.sarif` by default. A complete workflow is in [`.github/examples/orbit-scan.yml`](.github/examples/orbit-scan.yml), and the action's inputs are in [`action.yml`](action.yml).

The templates pull `orchestalabs/orbit-cli` from Docker Hub, which limits pulls by anonymous users. If many pipelines share one IP address, log in to Docker Hub in the job (`docker login`) or mirror the image to your own registry (`imageName` in the Azure template, the `image` of the GitLab job).

### GitLab CI and Azure Pipelines

- GitLab CI: include [`ci/gitlab/orbit.gitlab-ci.yml`](ci/gitlab/orbit.gitlab-ci.yml). It writes a JUnit report for the merge request and a SARIF artifact.
- Azure Pipelines: use the step template [`ci/azure-pipelines/orbit-scan.yml`](ci/azure-pipelines/orbit-scan.yml) (example: [`example.yml`](ci/azure-pipelines/example.yml)). It works on Azure DevOps Services and on Azure DevOps Server 2020 and later, in a container or with a downloaded, checksum-verified binary (Windows agents too).

Parameters and caveats for both are in the comment at the top of each template.

## Supported ecosystems and files

| Ecosystem | Manifests | Lockfiles |
| --- | --- | --- |
| Go | `go.mod` | not needed: `go.mod` versions are exact |
| npm | `package.json` | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 and berry), `pnpm-lock.yaml` |
| Python (PyPI) | `pyproject.toml`, `Pipfile`, `*.txt` files whose name starts or ends with `requirements` (`requirements.txt`, `requirements-dev.txt`, `dev-requirements.txt`) | `Pipfile.lock`, `poetry.lock`, `uv.lock` |
| NuGet | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `Directory.Packages.props` (central versions) | `packages.lock.json` |

**Commit your lockfiles.** A lockfile pins the real version of every direct and transitive dependency. Without one, Orbit only sees the range from the manifest (for example `^1.2.0`) and has to estimate a version, which can miss a vulnerability or report one that does not apply. The CLI warns about it (`N dependencies have no lockfile; their versions are approximate`).

The scan skips `.git`, `node_modules`, `bower_components`, `vendor`, `.venv`, `venv`, `__pycache__`, `.tox`, `.terraform`, `.yarn`, `.pnpm-store` and `testdata` directories.

## Git providers

The server imports and clones repositories from:

| Provider | Hosts | Setup |
| --- | --- | --- |
| GitHub | `github.com` | Add a personal access token in Settings |
| GitLab | `gitlab.com` | Add a personal access token in Settings |
| Azure DevOps Services | `dev.azure.com/{org}`, `{org}.visualstudio.com` | Add a connection, then a PAT with **Code (Read)** |
| Azure DevOps Server (on-premises, 2019 and later) | `https://host[:port]/tfs/{Collection}` | Add a connection, then a PAT |

GitHub Enterprise Server and self-managed GitLab are not supported; the GitHub and GitLab clients only talk to the public hosts above. Azure DevOps needs a **connection** (a saved, HTTPS-only base URL) before tokens and repositories can be added. Only `https` base URLs are accepted, and a token is only ever sent to the host and port of its connection.

For an Azure DevOps Server behind an internal certificate authority, mount the CA bundle into the Orbit container and point both Go and git at it with `SSL_CERT_FILE` and `GIT_SSL_CAINFO`. Orbit does not offer an option to skip certificate verification.

The CLI does not talk to any Git provider. It scans whatever is checked out.

## Configuration

The server reads `orbit.yaml` (or `orbit.yml` and other formats viper supports) from the working directory, `/etc/orbit` or `$HOME/.orbit`, and environment variables. Environment variables win. They are named `ORBIT_<SECTION>_<KEY>`, for example `scanner.max_concurrent_scans` is `ORBIT_SCANNER_MAX_CONCURRENT_SCANS`. The secrets have shorter names. See [`orbit.yaml`](orbit.yaml) for the file layout.

| Environment variable | Default | Notes |
| --- | --- | --- |
| `ORBIT_JWT_SECRET` | none, **required** | At least 32 characters. Orbit does not start without it. Changing it logs everyone out. Legacy name: `ORBIT_AUTH_JWT_SECRET` |
| `ORBIT_CRYPTO_ENCRYPTION_KEY` | none, **required** | 64 hex characters (`openssl rand -hex 32`). Encrypts stored access tokens; plaintext tokens from older versions are encrypted on the first start. Keep it: a different key cannot decrypt existing tokens |
| `ORBIT_SETUP_TOKEN` | empty | Must be entered in the first-run setup form. Required by the Compose file; outside Compose an empty value disables the check. Legacy name: `ORBIT_AUTH_SETUP_TOKEN` |
| `ORBIT_SERVER_HOST` / `ORBIT_SERVER_PORT` | `0.0.0.0` / `8080` | Listen address |
| `ORBIT_SERVER_SHUTDOWN_TIMEOUT` | `25` | Seconds to finish requests and hand running scans back to the queue on shutdown |
| `ORBIT_SERVER_TRUST_PROXY_HEADERS` | `false` | Behind a reverse proxy, set `true` so the client IP comes from `X-Forwarded-For`/`X-Real-IP`. Otherwise all clients share the proxy's login rate limit. Do not enable it without a proxy that sets these headers |
| `ORBIT_SERVER_CORS_ALLOWED_ORIGINS` | empty | Comma-separated browser origins allowed to call the API. Empty means same-origin only, which is all the bundled UI needs |
| `ORBIT_DATABASE_HOST` / `_PORT` | `localhost` / `5432` | |
| `ORBIT_DATABASE_USER` / `_PASSWORD` / `_NAME` | `orbit` / `orbit` / `orbit` | `orbit.yaml` and Compose use password `orbit_secret` and database `orbit_db` |
| `ORBIT_DATABASE_SSL_MODE` | `disable` | Any libpq `sslmode`; the Kubernetes manifest uses `require` |
| `ORBIT_SCANNER_WORK_DIR` | `/tmp/orbit-repos` | Where repositories are cloned (Compose uses `/tmp/orbit-scans`) |
| `ORBIT_SCANNER_CLONE_TIMEOUT` | `120` | Seconds per clone; `0` means no limit |
| `ORBIT_SCANNER_MAX_CONCURRENT_SCANS` | `3` | Size of the background scan worker pool |
| `ORBIT_SCANNER_SCAN_TIMEOUT` | `900` | Seconds a whole scan may take |
| `ORBIT_SCANNER_RETAIN_SCANS` | `10` | Finished scans kept per repository; `0` keeps all |

Compose-only variables, set in `deploy/docker/.env`: `ORBIT_DATABASE_PASSWORD` (also used for the PostgreSQL container), `ORBIT_SERVER_TRUST_PROXY_HEADERS`, `ORBIT_SERVER_CORS_ALLOWED_ORIGINS`, `ORBIT_TMP_SIZE` (size of the `/tmp` tmpfs that holds clones, default `1g`) and `COMPOSE_PROJECT_NAME`.

`orbit.yaml` also contains `log.level`, `log.format` and `scanner.default_schedule`. The current server does not apply them: it always logs JSON at `info` level, and new repositories get the schedule `0 */6 * * *` unless one is given when they are added.

The CLI reads no configuration file and is configured with flags. It honours `NO_COLOR`, and its HTTP client uses Go's default transport, so the standard `HTTPS_PROXY`/`NO_PROXY` variables apply.

## REST API

All endpoints are under `/api/v1`. Except for the public ones, they need an `Authorization: Bearer <token>` header with the JWT from `/auth/login` (valid for 24 hours). Any signed-in user can read; requests other than `GET`, `HEAD` and `OPTIONS` need the admin role. Responses use one envelope:

```json
{ "success": true, "data": { } }
```

Errors return `{ "success": false, "error": "message" }`.

<details>
<summary>Endpoint list</summary>

**Public**

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | Health check |
| `GET` | `/auth/status` | `setup_completed` and `setup_token_required` |
| `POST` | `/auth/setup` | Create the first admin (`email`, `password`, `display_name`, `setup_token`) |
| `POST` | `/auth/login` | Log in; returns `token` and `user` |

**Account**

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/auth/me` | The signed-in user |

**Repositories**

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/repositories` | List repositories (paginated, see below) |
| `POST` | `/repositories` | Add a repository manually |
| `GET` | `/repositories/{id}` | Repository details |
| `PUT` | `/repositories/{id}` | Update a repository |
| `DELETE` | `/repositories/{id}` | Delete a repository |
| `POST` | `/repositories/github/fetch` | List GitHub repositories for a saved token (`token_id`) |
| `POST` | `/repositories/gitlab/fetch` | List GitLab projects for a saved token (`token_id`) |
| `POST` | `/repositories/azuredevops/fetch` | List Azure DevOps repositories for a saved token (`token_id`) |
| `POST` | `/repositories/import` | Bulk import; returns `{created, skipped}`, where `skipped` names repositories whose URL was already imported |

Query parameters of `GET /repositories`:

| Param | Default | Description |
| --- | --- | --- |
| `page` | `1` | Page number |
| `per_page` | `25` | Items per page (max 100) |
| `provider` | | `github`, `gitlab` or `azuredevops` |
| `q` | | Search by name or URL |
| `status` | | `vulnerable`, `outdated` or `issues` (either) |
| `sort` | `name` | `name` (A–Z) or `recent` (newest first) |

Paginated responses carry `data`, `total`, `page`, `per_page` and `total_pages` inside the envelope's `data`.

**Scans**

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/repositories/{id}/scan` | Queue a scan (202 Accepted) |
| `GET` | `/repositories/{id}/scans` | Scan history |
| `GET` | `/scans/{id}` | Scan result |
| `GET` | `/scans/{id}/dependencies` | Dependencies found by a scan |

**Vulnerabilities**

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/vulnerabilities` | Findings from each repository's latest completed scan (paginated) |
| `GET` | `/vulnerabilities/{id}` | Vulnerability details |
| `GET` | `/scans/{id}/vulnerabilities` | Vulnerabilities of a scan |
| `GET` | `/repositories/{id}/vulnerabilities` | Vulnerabilities of a repository |

`GET /vulnerabilities` takes `page` (max 1,000,000), `per_page` (default 25, max 100) and `severity` (`critical`, `high`, `medium`, `low`, `unknown`). Besides the pagination fields it returns `counts` (findings per severity, ignoring the `severity` filter) and `unverified_repositories` (repositories without a successful vulnerability check).

**Access tokens**

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/tokens` | List saved tokens |
| `POST` | `/tokens` | Add a token (Azure DevOps tokens need `git_host_id`) |
| `DELETE` | `/tokens/{id}` | Delete a token |

**Git host connections** (Azure DevOps)

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/git-hosts` | List connections |
| `POST` | `/git-hosts` | Add a connection (`kind`, `name`, `base_url`) |
| `DELETE` | `/git-hosts/{id}` | Delete a connection and its tokens (409 while it has repositories) |

**Dashboard**

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/dashboard/stats` | Aggregate counts (repositories, scans, vulnerabilities) |

</details>

## Deployment

### Docker Compose

[`deploy/docker/docker-compose.yml`](deploy/docker/docker-compose.yml) runs Orbit and `postgres:18-alpine`. Orbit listens on port 8080. PostgreSQL is published on `127.0.0.1:5432` only. The Orbit container runs as uid 10001 with a read-only root filesystem, all capabilities dropped and `no-new-privileges`. Clones go to a tmpfs on `/tmp` (`ORBIT_TMP_SIZE`, default `1g`). The 40-second stop grace period lets running scans return to the queue before the container stops. Database migrations run automatically on startup.

Useful commands: `make docker-up`, `make docker-down`, `make docker-logs`.

### Upgrading from PostgreSQL 16

Earlier releases ran PostgreSQL 16 on the `orbit-data` volume. PostgreSQL 18 uses a new volume, `orbit-pgdata`. `run.sh` refuses to start while the old volume still holds data that has not been migrated, so you never get an empty database by accident.

Stop Orbit first with `docker compose -f deploy/docker/docker-compose.yml down` (if that fails on a missing `ORBIT_*` variable, see [Existing deployments and the setup token](#existing-deployments-and-the-setup-token), or `docker stop` the old containers). Then:

```bash
deploy/docker/upgrade-postgres.sh   # dumps the old volume, restores into the new one, compares row counts
bash run.sh
```

- The script refuses to run while a container is using either volume.
- The dump is kept in `deploy/docker/backups/`.
- The old volume is not deleted or changed; only a temporary PostgreSQL server is started on it. Once you have checked the data, remove it with the `docker volume rm` command the script prints.
- If the old volume has a non-default name, pass it as an argument.
- If the old volume holds both a PostgreSQL 16 cluster and a PostgreSQL 18 one (`18/docker`, created by an earlier compose file), choose with `--from=16` or `--from=18`.
- `--force` restores into a new volume that already has a cluster.

### Kubernetes

[`deploy/k8s/orbit.yaml`](deploy/k8s/orbit.yaml) is a starting point: a Deployment (non-root, read-only root filesystem, health probes on `/api/v1/health`), a ClusterIP Service on port 80, a ConfigMap and a Secret. Before applying it:

- fill in `jwt-secret` and `encryption-key` in the `orbit-secrets` Secret (or create the Secret separately) and change `database-password`,
- add a `setup-token` key to the Secret; it is optional in the manifest but recommended before the first setup,
- replace `image: orbit:latest` with a published image such as `orchestalabs/orbit:<tag>`,
- provide PostgreSQL yourself: the manifest expects a service named `postgres-service` and connects with `sslmode=require`.

```bash
kubectl apply -f deploy/k8s/orbit.yaml
```

The manifest runs one replica. Login rate limits are kept in memory, so with more replicas they apply per instance.

### Releases and images

Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which publishes:

- a GitHub release with `orbit_<tag>_<os>_<arch>` binaries for Linux amd64 and arm64, macOS amd64 (Intel) and arm64 (Apple silicon) and Windows amd64 (`.exe`), plus `checksums.txt` (SHA-256),
- [`orchestalabs/orbit:<tag>`](https://hub.docker.com/r/orchestalabs/orbit) on Docker Hub, the server image with the UI,
- [`orchestalabs/orbit-cli:<tag>`](https://hub.docker.com/r/orchestalabs/orbit-cli) on Docker Hub, the CLI-only image (no `git`, entrypoint `orbit`, default command `scan --path /src`).

Both images are built for `linux/amd64` and `linux/arm64`. Release tags also update `latest`; prerelease tags (containing `-`, such as `v1.2.0-rc1`) only get their own tag. Publishing needs the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.

The release binaries are mainly for the CLI. The server serves the UI from `./ui/dist` on disk, so use the server image to run the server.

## Security notes

- **What leaves your network.** To find vulnerabilities, Orbit sends package coordinates (ecosystem, name, version) to `api.osv.dev`. Source code, file paths and repository details are not sent. The server also asks the public registries (npm, PyPI, NuGet, the Go module proxy) for the latest versions of every package; the CLI does that only with `--outdated`. Private feeds such as Azure Artifacts are not queried.
- **Access tokens** for GitHub, GitLab and Azure DevOps, including tokens stored on repositories, are encrypted at rest with AES-256-GCM using `ORBIT_CRYPTO_ENCRYPTION_KEY`. Losing the key means re-adding the tokens.
- **First-run setup** requires `ORBIT_SETUP_TOKEN` when it is set, so only someone who has the token can create the first admin account.
- **Logins** are limited to 5 failures per email and 20 per client IP in 15 minutes. Behind a reverse proxy, set `ORBIT_SERVER_TRUST_PROXY_HEADERS=true` so the limit applies per real client.
- **Browser access** is same-origin only unless `ORBIT_SERVER_CORS_ALLOWED_ORIGINS` is set.
- **TLS verification** is never turned off. For an Azure DevOps Server with an internal CA, mount a CA bundle as described under [Git providers](#git-providers).
- **CI logs.** `orbit scan` neutralises CI log commands (`##vso[`, `##[`, a leading `::`) in text that comes from the scanned repository or osv.dev, to reduce the risk of repository content issuing commands to the CI agent. The default `.orbitignore` must be a regular file; a symlink is refused.

## Limitations

Orbit reports known vulnerabilities for the versions it can see. Please keep these limits in mind when you read its results:

- It finds only advisories that are published in osv.dev. A clean result means no known advisory matched, not that the dependencies are free of problems.
- Malicious packages are found only when they are in the OpenSSF Malicious Packages data on osv.dev, matched by package name and version. A private package with the same name as a public malicious one is reported too, and `.orbitignore` cannot suppress that finding.
- It does not analyse whether vulnerable code is actually reached by your application.
- Without a lockfile, versions are estimated from manifest ranges and can be wrong in either direction.
- Supported ecosystems are Go, npm, Python and NuGet. Other ecosystems (for example Maven, Gradle, Cargo or Composer) are not scanned.
- GitHub and GitLab are supported on github.com and gitlab.com only; GitHub Enterprise Server and self-managed GitLab are not.
- The server stores one row per advisory, so two advisories for the same CVE are counted twice in the UI. The CLI merges them into one finding.
- The CI templates and Azure DevOps Server support have been tested with stubs and local servers. Please report problems you see on real installations.

## Development

Prerequisites: Go 1.27+, Node 26+, PostgreSQL 18+ (or Docker to run it), `git`. `make lint` needs [golangci-lint](https://golangci-lint.run), `make fmt` needs `goimports`, and the `migrate-*` targets need the [golang-migrate](https://github.com/golang-migrate/migrate) CLI.

### Running locally

```bash
# PostgreSQL with the credentials from orbit.yaml
docker run -d --name orbit-postgres -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=orbit -e POSTGRES_PASSWORD=orbit_secret -e POSTGRES_DB=orbit_db \
  postgres:18-alpine

# Backend on :8080, from the repository root so orbit.yaml is picked up
export ORBIT_JWT_SECRET=$(openssl rand -hex 32)
export ORBIT_CRYPTO_ENCRYPTION_KEY=$(openssl rand -hex 32)
go run ./cmd/orbit
```

Keep the same `ORBIT_CRYPTO_ENCRYPTION_KEY` across restarts, or tokens you saved earlier cannot be decrypted. Migrations run on startup.

```bash
# UI dev server on http://localhost:3000, proxies /api to http://localhost:8080
cd ui
npm install
npm run dev
```

To serve the UI from the Go server instead, run `npm run build` in `ui/` and start the server from the repository root; it serves `./ui/dist`.

### Make targets

| Target | What it does |
| --- | --- |
| `make build` | Build `bin/orbit` |
| `make run` | `go run ./cmd/orbit` (needs the secrets above) |
| `make test` | `go test -v -race -coverprofile=coverage.out ./...` |
| `make test-short` | `go test -v -short ./...` |
| `make test-integration` | PostgreSQL integration tests in `internal/adapter/persistence/...` (needs `ORBIT_TEST_DATABASE_URL`) |
| `make lint` | `golangci-lint run ./...` |
| `make fmt` | `gofmt -s -w .` and `goimports -w .` |
| `make clean` | Remove `bin/` and `coverage.out` |
| `make docker-up` / `docker-down` / `docker-logs` | Compose stack in `deploy/docker` |
| `make migrate-up` / `migrate-down` / `migrate-create` | golang-migrate against `DATABASE_URL` (default `postgres://orbit:orbit@localhost:5432/orbit?sslmode=disable`; override it to match your database) |
| `make deps` | `go mod download` and `go mod tidy` |
| `make all` | `deps`, `lint`, `test`, `build` |

### Tests

```bash
# Go unit tests (./internal/... ./cmd/... skips ui/node_modules once the UI is installed)
go test -race ./internal/... ./cmd/...

# Integration tests (build tag "integration"). Each test creates and drops its own database.
docker run -d --name orbit-test-postgres -p 5433:5432 -e POSTGRES_PASSWORD=test postgres:18-alpine
export ORBIT_TEST_DATABASE_URL='postgres://postgres:test@localhost:5433/postgres?sslmode=disable'
make test-integration                 # persistence package only, as in CI
go test -tags integration ./internal/...   # every integration test

# UI
cd ui && npm ci && npm run lint && npm test && npm run build
```

Tests that need the database skip themselves when `ORBIT_TEST_DATABASE_URL` is not set. The Git clone integration tests in `internal/infrastructure/git` need network access to github.com. CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) also runs `go vet`, `govulncheck`, `npm audit --audit-level=high`, a Docker build, and a self-scan with the CLI image.

### Project structure

```
cmd/orbit/                 entry point: serve, scan, version, help
internal/
  domain/                  entities and repository interfaces
  usecase/                 repository management, scan queue, scheduler and workers
  engine/                  DB-free analysis engine shared by the server and the CLI
  report/                  CLI reports (table, JSON, SARIF, JUnit) and .orbitignore
  adapter/
    handler/               HTTP handlers
    persistence/postgres/  PostgreSQL repositories and embedded migrations
  infrastructure/
    analyzer/              Go, npm, pip and NuGet analyzers
    vulnerability/osv/     osv.dev client
    git/                   GitHub, GitLab and Azure DevOps clients, git clone
    auth/ crypto/ config/ server/ httpclient/
ui/                        React UI (Vite, Tailwind, React Router, TanStack Query)
deploy/docker/             Dockerfiles, Compose file, PostgreSQL upgrade script
deploy/k8s/                Kubernetes manifest
ci/                        GitLab CI and Azure Pipelines templates
action.yml                 GitHub Action
```

See [ui/README.md](ui/README.md) for the UI.

## License

[MIT](LICENSE)
