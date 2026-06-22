# Example template file for sm

# 1. Convention-based secret lookup
# Looks up candidate secret names in Google Secret Manager, e.g.:
# dev-database-url, database-url-dev, database-url, etc.
DATABASE_URL=sm://

# 2. Explicit secret name lookup (in the active project)
STRIPE_SECRET_KEY=sm://production-stripe-key

# 3. Fully qualified Secret Manager resource path
CLOUD_SQL_PASSWORD=sm://projects/my-production-project/secrets/sql-password/versions/1

# 4. Standard (non-secret) environment variable
DEBUG=true
PORT=8080
LOG_LEVEL=info
