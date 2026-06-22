# Getting Started with `sm`

This guide walks you through setting up and using `sm` to manage your application secrets. You will learn how to:
1. Create GCP secrets with initial placeholder values using the **`gcloud` CLI** and **Terraform**.
2. Update them with real secret values securely (preventing leakages in git or CLI history).
3. Use `sm` to automatically resolve and inject those secrets into your application environment.

---

## Prerequisites
- A Google Cloud Platform (GCP) account and project.
- The `gcloud` CLI installed and authenticated (`gcloud auth login`).
- Terraform installed (if using IaC).
- The `sm` CLI tool compiled and installed in your system path.

---

## Step 1: Create Secrets with Placeholder Values
It is a security best practice to **create secrets with initial placeholder values** when using command lines or infrastructure-as-code (IaC). This prevents sensitive production credentials from being recorded in your terminal shell history or stored in plaintext inside Terraform state files.

### Option A: Using the `gcloud` CLI
Run the following commands to create a secret and add an initial placeholder version:

```bash
# 1. Create a secret resource named 'dev-database-url'
gcloud secrets create dev-database-url --replication-policy="automatic"

# 2. Add an initial version with a placeholder value
echo -n "placeholder-db-string" | gcloud secrets versions add dev-database-url --data-file=-
```

### Option B: Using Terraform
Define the Secret Manager resource and its placeholder version in your Terraform configuration:

```hcl
# 1. Create the secret container
resource "google_secret_manager_secret" "database_url" {
  secret_id = "dev-database-url"
  
  replication {
    auto {}
  }
}

# 2. Create the placeholder secret version (prevents hardcoded credentials in TF files/state)
resource "google_secret_manager_secret_version" "database_url_placeholder" {
  secret      = google_secret_manager_secret.database_url.id
  secret_data = "placeholder-db-string"
}
```
Apply the Terraform configuration:
```bash
terraform init
terraform apply
```

---

## Step 2: Set the Real Secret Values Securely
Once the secret container is established, the authorized owner or administrator should populate the actual secret values.

### Method 1: Using Stdin (Highly Secure)
To avoid writing the secret value in terminal command logs, use `gcloud` with the `--data-file=-` flag. This will prompt you to enter the value in the terminal securely:

```bash
gcloud secrets versions add dev-database-url --data-file=-
# Type or paste your real database connection string (e.g., postgres://user:pass@host:5432/db)
# Press Ctrl+D to send EOF and complete the upload
```

### Method 2: Using a Temporary File
Write the secret to a temporary file, upload it, and immediately delete the file securely:

```bash
# Write the secret
echo -n "postgres://user:pass@host:5432/db" > temp_secret.txt

# Upload version
gcloud secrets versions add dev-database-url --data-file=temp_secret.txt

# Delete the temporary file securely
rm temp_secret.txt
```

---

## Step 3: Configure your Project for `sm`

### 1. Authenticate your Local Shell
Ensure your local application runner is authenticated with Google Application Default Credentials (ADC):
```bash
gcloud auth application-default login
```

### 2. Create your `.env.tpl` Template File
In the root directory of your application repository, create a `.env.tpl` template file. You specify variables that need to be resolved from Secret Manager using the `sm://` prefix:

```env
# Tells sm to resolve this variable dynamically from GCP Secret Manager
DATABASE_URL=sm://

# Standard non-secret variables are passed through as-is
DEBUG=true
PORT=9000
```

---

## Step 4: Run your Application with `sm`
Execute your application command wrapped in `sm run --`:

```bash
# Explicitly specifying the environment and project (if not auto-detected)
sm run --project="my-gcp-project" --service="" -- go run main.go
```

### How `sm` resolves `DATABASE_URL=sm://`:
1. `sm` detects the active project as `my-gcp-project` and active environment as `dev`.
2. It generates candidate secret names based on convention: `dev-database-url`, `database-url-dev`, `database-url`.
3. It searches Secret Manager in `my-gcp-project` and matches `dev-database-url`.
4. It fetches the latest payload value (`postgres://user:pass@host:5432/db`), injects it into `DATABASE_URL` environment variable, and starts your Go app.
