# Secrets detection test fixtures
import os
import boto3

# AISHIELD-SEC-SECRETS-001: AWS Access Key
aws_access_key = "AKIAIOSFODNN7EXAMPLE"

# AISHIELD-SEC-SECRETS-002: AWS Secret Key
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# AISHIELD-SEC-SECRETS-003: GCP Service Account
gcp_config = {"type": "service_account", "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}

# AISHIELD-SEC-SECRETS-004: Azure Connection String
azure_conn = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123"

# AISHIELD-SEC-SECRETS-005: Private Key
private_key = "-----BEGIN RSA PRIVATE KEY-----"

# AISHIELD-SEC-SECRETS-006: GitHub PAT
github_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"

# AISHIELD-SEC-SECRETS-007: Slack Token
slack_bot_token = "xoxb-FAKE-EXAMPLE-TOKEN-FOR-TESTING-ONLY"

# AISHIELD-SEC-SECRETS-008: Generic API Key
api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"

# AISHIELD-SEC-SECRETS-009: JWT Token
auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw"

# AISHIELD-SEC-SECRETS-010: Stripe Key
stripe_key = "sk_live_FAKE_EXAMPLE_KEY_FOR_TESTING"

# AISHIELD-SEC-SECRETS-013: Database URL with password
database_url = "postgres://admin:supersecretpass@db.example.com:5432/mydb"

# AISHIELD-SEC-SECRETS-014: Hardcoded password
db_password = "my_super_secret_password_123"

# AISHIELD-SEC-SECRETS-015: Google API Key
google_maps_key = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
