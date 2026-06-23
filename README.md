# sm — Google Cloud Secret Manager Environment Injector

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/frozen425/sm.svg)](https://pkg.go.dev/github.com/frozen425/sm)

`sm` is a lightweight, secure, and production-grade Go CLI tool designed to mirror 1Password's `op run` command for **Google Cloud Secret Manager**. It resolves secret references from a template file (`.env.tpl`) or shell environment variables on-the-fly, fetches their payloads, and securely injects them into the runtime environment of a spawned child process—preventing sensitive credentials from ever being written in plaintext to disk.

By using **convention-over-configuration** and automatic project/environment detection, `sm` enables a clean workflow where developer configuration files contain **zero hardcoded secret names or Google Cloud project IDs**.

---

## Features

- **Zero Plaintext on Disk**: Secrets are fetched dynamically into memory, injected into the child process, and wiped when the process exits.
- **Convention-over-Configuration**: Simply define `DATABASE_URL=sm://` in your `.env.tpl`. `sm` dynamically constructs candidate names based on the active GCP project and environment (e.g. `dev-database-url`, `database-url-prod`).
- **Dynamic Project & Env Detection**: No hardcoded project IDs. `sm` resolves project configuration directly from active `gcloud` settings, and detects the active environment tier (e.g. `dev`, `prod`, `staging`) from the project ID naming structure or local shell.
- **Service/Component Isolation**: Supports a `--service` scope parameter to look up service-prefixed secrets (e.g., `auth-database-url-dev`).
- **Enterprise-Grade Compliance Logging**: Sets a sanitized `X-Goog-Request-Reason` HTTP/gRPC header for GCP Audit Logs, allowing security teams to audit precisely why a secret was fetched.
- **No Production Container Overhead**: Compiled in Go with direct API calls. You do not need the heavy Google Cloud SDK or `gcloud` CLI installed inside production containers.
- **Short-Lived Credentials & Impersonation**: Seamlessly integrates with Google Cloud Application Default Credentials (ADC) and Service Account Impersonation, avoiding static JSON credential keys on developer laptops.

---

## Installation

Ensure you have [Go](https://go.dev/doc/install) installed, then compile and install `sm`:

```bash
# Clone the repository
git clone https://github.com/frozen425/sm.git
cd sm

# Build and install to your $GOPATH/bin
go install
```

---

## Getting Started

For a comprehensive, step-by-step guide on creating secrets with initial placeholders using `gcloud` and Terraform, updating them with real values, and consuming them with `sm`, check out the [Getting Started Guide](GETTING_STARTED.md).

## Quick Start

### 1. Set Up Google Cloud Authentication
Authenticate with GCP using the built-in login helper:
```bash
sm login
```
*(This triggers the standard Google Cloud Application Default Credentials (ADC) browser login flow behind the scenes).*

### 2. Create a Secret in Secret Manager
Create a secret that aligns with environment naming conventions (e.g., prefixing with `localdev` for local runs):
```bash
gcloud secrets create localdev-database-url --data-file=- <<< "postgres://user:pass@localhost:5432/my-db"
```

### 3. Define your Template File (`.env.tpl`)
Create a `.env.tpl` file in the root of your application repository:
```env
# Injected from GCP Secret Manager (using convention mapping)
DATABASE_URL=sm://

# Standard non-secret environment variables (passed through)
DEBUG=true
PORT=8080
```

### 4. Run your Application
Execute your application command wrapped in `sm run`:
```bash
sm run -- go run main.go
```
`sm` will list available secrets in the active project, find `localdev-database-url` matching `DATABASE_URL`, access the secret payload, merge it with `DEBUG` and `PORT`, and launch `go run main.go` with the environment injected.

---

## Naming Conventions & Candidate Matching

When resolving a variable `DATABASE_URL` for a service `auth` in environment `dev`, `sm` generates a prioritized list of candidate secret names to look up in GCP Secret Manager:

1. **Service-Scoped**:
   - `auth-database-url-dev`
   - `auth-DATABASE-URL-dev`
   - `dev-auth-database-url`
   - `dev-auth-DATABASE-URL`
   - `auth-database-url`
   - `auth-DATABASE-URL`
2. **Environment-Scoped**:
   - `dev-database-url`
   - `dev-DATABASE-URL`
   - `database-url-dev`
   - `DATABASE-URL-DEV`
3. **Simple (Multi-Project Isolation)**:
   - `database-url`
   - `DATABASE-URL`

### Custom Explicit URIs
If you need to bypass convention matching, you can specify explicit names or paths in your `.env.tpl`:
- `API_KEY=sm://production-stripe-key` (Explicit secret name in the active project)
- `EXTERNAL_SECRET=sm://projects/custom-project/secrets/my-secret/versions/1` (Fully qualified GCP Secret Manager path)

---

## CLI Options & Reference

```bash
sm run [flags] -- [command] [args...]
```

| Flag / Option | Environment Variable | Description |
| :--- | :--- | :--- |
| `-env-file` | - | Path to the environment template file (default: `.env.tpl`). |
| `-project` | `GOOGLE_CLOUD_PROJECT`, `GCP_PROJECT` | GCP Project ID. If not set, resolves automatically from `gcloud` active config. |
| `-service` / `-component` | `SERVICE_NAME`, `COMPONENT_NAME` | Scopes lookups by prefixing candidates with this service name. |
| `-request-reason` | - | Custom string sent in the `X-Goog-Request-Reason` audit header. |

---

## Production Deployments (Cloud Run)

### 1. Direct Go API Calls
`sm` does not execute `gcloud` to query GCP Secret Manager. It uses Google's direct REST/gRPC client libraries. Therefore, you do not need the `gcloud` CLI in your Docker container. Simply build `sm` into your container image.

### 2. Platform-Native Alternative (Recommended)
While you can wrap your Docker container command in `sm run -- [cmd]`, the Google Cloud best practice for **Cloud Run Services and Cloud Run Jobs** is to use Cloud Run's native Secret Manager integration. This mounts secrets as environment variables or volume mounts directly via the Cloud Run control plane, completely removing secret-fetching code from your container lifecycle.

---

## Compliance & Auditing

### Audit Trails (`X-Goog-Request-Reason`)
For auditing, `sm` attaches a custom reason string to the `X-Goog-Request-Reason` HTTP/gRPC header. If a service is specified, it defaults to:
`sm env injection for [service]`
`sm` automatically sanitizes the reason to contain **only alphanumeric and space characters** (no punctuation or hyphens). This prevents Google Cloud from base64 encoding the reason string inside Cloud Audit Logs, ensuring the reasons are fully readable in plain text for compliance reports.

### Custom User-Agent
All API requests generated by the tool are tagged with a custom User-Agent prefix:
`sm/1.0.0`
This allows cloud administrators to easily filter and attribute Secret Manager API traffic in GCP Usage metrics and billing reports.

---

## Security Considerations

### 1. Restrictive File Permissions
When injecting secrets as files (`?destination=`), `sm` creates parent directories with `0700` permissions and files with `0600` permissions (readable/writeable only by the owner). This prevents other local users on the system from accessing the secret content.

### 2. Process Memory Exposure
Secrets resolved by `sm` are injected as environment variables or file descriptors into the spawned child process. Since environment variables are visible in memory, ensure your operating system blocks non-root users from reading the process environments (e.g. `/proc/<pid>/environ` on Linux).

### 3. File Cleanup & `SIGKILL` Limitations
`sm` intercepts termination signals (`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`) and uses Go's `defer` statement to delete all injected secret files from disk before exiting. However, if the `sm` parent process receives `SIGKILL` (`kill -9`) or experiences a sudden hardware power loss, the operating system kernel terminates the process immediately. In this scenario, user-space cleanup code cannot run, and the plaintext files will remain on disk.

### 4. Direct Token Usage Warning
Avoid passing raw sensitive credentials (like access tokens) using the CLI flag `--token`, as this will write them to your terminal history (`~/.zsh_history`) and expose them in process listings (`ps aux`). Always prefer setting the `GCP_ACCESS_TOKEN` environment variable.

---

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
