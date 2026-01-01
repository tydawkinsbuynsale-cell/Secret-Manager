# 🔐 Enterprise-Grade Secret Manager

A production-ready command-line tool for securely storing and managing API keys, tokens, and other secrets with military-grade encryption, automatic backups, audit logging, and integrity verification.

## Features

### Core Security
- **AES-256 Encryption**: Military-grade encryption using Fernet (AES-256)
- **PBKDF2 Key Derivation**: 100,000 iterations for brute-force resistance
- **Integrity Checking**: SHA-256 checksums detect tampering
- **Password Strength Validation**: Enforces strong master passwords
- **Secure Clipboard**: Auto-clear after 30 seconds

### Enterprise Features
- **Automatic Backups**: Encrypted backups with rotation (keeps last 10)
- **Audit Logging**: Complete audit trail of all operations
- **Secret Expiration**: Set expiration dates with warning alerts
- **Import/Export**: Support for .env and JSON formats
- **Search & Filter**: Find secrets by name, category, or notes
- **Metadata Tracking**: Created/updated timestamps, notes, categories

### Reliability
3. Initialize the secret manager:
```bash
python secret_manager.py init
```

## Usage

### Initialize (First Time)
```bash
python secret_manager.py init
```
Sets up the secret manager and creates your master password. Choose a strong password!up Restore**: Restore from any backup
- **Data Integrity**: Automatic corruption detection
- **Error Recovery**: Comprehensive error handling
- **Cross-platform**: Works on Windows, macOS, and Linux

## Installation

1. Install Python 3.7+
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Add a Secret
```bash
python secret_manager.py add MY_API_KEY
```
You'll be prompted for your master password and the secret value.
Copy to clipboard (auto-clears in 30s):
```bash
python secret_manager.py get MY_API_KEY --copy
```

### Add Secret with Expiration
```bash
python secret_manager.py add TEMP_TOKEN -c temp --expires 30 --notes "Expires in 30 days"
```


Add with category:
```bash
python secret_manager.py add AWS_ACCESS_KEY -c aws
```

### Retrieve a Secret
```bash
python secret_manager.py get MY_API_KEY
```
Import from .env File
```bash
python secret_manager.py import production.env --format env -c production
```

### Import from JSON
```bash
python secret_manager.py import secrets.json --format json
```

### View Audit Logs
```bash
python secret_manager.py audit
```

### LIntegrity Checking**: SHA-256 checksums detect file tampering
5. **No Plaintext**: Secrets are never stored in plaintext
6. **Password Protection**: All operations require master password
7. **Audit Trail**: Complete log of all operations with timestamps
8. **Automatic Backups**: Encrypted backups created before every modification
9. **Secure Clipboard**: Auto-clears clipboard after 30 seconds
10. **Password Validation**: Enforces minimum password strength requirements
python secret_manager.py backups
```

### Restore from Backup
```bash
- `checksum.txt` - Integrity verification checksum
- `audit.log` - Operation audit trail
- `backups/` - Encrypted backup files (last 10 kept)
python secret_manager.py restore secrets_backup_20260101_120000.enc
``Initialize (first time)
python secret_manager.py init

# Add some API keys with metadata
python secret_manager.py add OPENAI_API_KEY -c ai --notes "Production OpenAI key"
python secret_manager.py add AWS_ACCESS_KEY_ID -c aws --expires 90
python secret_manager.py add AWS_SECRET_ACCESS_KEY -c aws --expires 90
python secret_manager.py add GITHUB_TOKEN -c github --notes "Personal access token"

# Add temporary secret
python secret_manager.py add TEMP_API_KEY -c temp --expires 7 --notes "Expires in 1 week"

# List all secrets (shows expiration warnings)
python secret_manager.py list

# Search for AWS-related secrets
python secret_manager.py search aws

# Get secret and copy to clipboard (auto-clears in 30s)
python secret_manager.py get OPENAI_API_KEY --copy

# Import from existing .env file (enforced 12+ chars)
- **Automatic backups**: Backups are created automatically before modifications
- **Backup your storage folder**: Keep encrypted backups of `~/.secret_manager/`
- **Use --copy flag**: Secrets auto-clear from clipboard after 30 seconds
- **Set expiration dates**: Get warnings before secrets expire
- **Review audit logs**: Track all operations with `audit` command
- **Don't commit .env files**: Add `.env` to your `.gitignore`
- **Use categories**: Organize secrets for easier management
- **Add notes**: Document what each secret is for
- **Test restores**: Periodically verify bac with automatic backups
- The security depends on your master password strength (minimum enforced)
- Integrity checking detects tampering - you'll be alerted if files are modified
- Audit logs track all operations for security monitoring
- For team environments, consider enterprise secret management (HashiCorp Vault, AWS Secrets Manager)
- Never commit your `.secret_manager` folder to version control
- Be cautious when exporting to .env files on shared systems
- Clipboard auto-clears after 30 seconds for security
- Backups are also encrypted with your master password
# Generate strong password
python secret_manager.py generate --length 32

# List backups
python secret_manager.py backups

# Restore from backup if needed
python secret_ with metadata
manager.add_secret("API_KEY", "secret-value", password, 
                  category="api", expires_days=90, 
                  notes="Production API key")

# Get a secret (checks expiration)
api_key = manager.get_secret("API_KEY", password, copy_to_clipboard=True)

# List all secrets with metadata
manager.list_secrets(password, show_metadata=True)

# Import from file
manager.import_from_env("production.env", password, category="prod")

# Export to .env
manager.export_to_env(password, ".env")

# View audit logs
manager.show_audit_logs(limit=100)

# List and restore backups
manager.list_backups()
manager.restore_from_backup("secrets_backup_20260101_120000.enc", password)

# Generate strong password
strong_pwd = manager.generate_strong_password(length=32

Export to custom file:
```bash
python secret_manager.py export -o production.env
```

### Delete a Secret
```bash
python secret_manager.py delete MY_API_KEY
```

### Custom Storage Location
```bash
python secret_manager.py list --storage /path/to/storage
```

## Security Features

1. **Encryption**: All secrets are encrypted with AES-256 via Fernet
2. **Key Derivation**: Master password is processed through PBKDF2 with 100,000 iterations
3. **Salt**: Unique salt stored separately prevents rainbow table attacks
4. **No Plaintext**: Secrets are never stored in plaintext
5. **Password Protection**: All operations require master password

## Storage

By default, encrypted secrets are stored in:
- **Windows**: `C:\Users\<username>\.secret_manager\`
- **macOS/Linux**: `~/.secret_manager/`

Files stored:
- `secrets.enc` - Encrypted secrets database
- `salt.bin` - Cryptographic salt

## Example Workflow

```bash
# Add some API keys
python secret_manager.py add OPENAI_API_KEY -c ai
python secret_manager.py add AWS_ACCESS_KEY_ID -c aws
python secret_manager.py add AWS_SECRET_ACCESS_KEY -c aws
python secret_manager.py add GITHUB_TOKEN -c github

# List all secrets
python secret_manager.py list

# Search for AWS-related secrets
python secret_manager.py search aws

# Export to .env for local development
python secret_manager.py export

# Get a specific secret
python secret_manager.py get OPENAI_API_KEY
```

## Tips

- **Choose a strong master password**: This is the key to all your secrets
- **Backup your storage folder**: Keep encrypted backups of `~/.secret_manager/`
- **Don't commit .env files**: Add `.env` to your `.gitignore`
- **Use categories**: Organize secrets for easier management
- **Rotate secrets regularly**: Update API keys periodically

## Security Considerations

⚠️ **Important Notes:**
- This tool stores secrets encrypted on disk
- The security depends on your master password strength
- For team environments, consider enterprise secret management (HashiCorp Vault, AWS Secrets Manager)
- Never commit your `.secret_manager` folder to version control
- Be cautious when exporting to .env files on shared systems

## Advanced: Python API

You can also use the SecretManager class in your Python scripts:

```python
from secret_manager import SecretManager

manager = SecretManager()
password = "your-master-password"

# Add a secret
manager.add_secret("API_KEY", "secret-value", password, category="api")

# Get a secret
api_key = manager.get_secret("API_KEY", password)

# List all secrets
manager.list_secrets(password)

# Export to .env
manager.export_to_env(password, ".env")
```

## License

MIT License - Feel free to use and modify for your needs.
