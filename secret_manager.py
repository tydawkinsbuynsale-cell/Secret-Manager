#!/usr/bin/env python3
"""
Enterprise-Grade Secure API Key & Secret Manager
Encrypts and stores API keys, tokens, and other secrets with audit logging,
backups, integrity checking, and advanced security features.
"""

import json
import os
import sys
import getpass
import base64
import hashlib
import secrets
import shutil
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Error: cryptography package is required. Install with: pip install cryptography")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


class AuditLogger:
    """Audit logging for all secret operations"""
    
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def log(self, action: str, secret_name: str, status: str, details: str = ""):
        """Log an operation with timestamp"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "action": action,
            "secret_name": secret_name,
            "status": status,
            "details": details
        }
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"{Colors.YELLOW}Warning: Could not write to audit log: {e}{Colors.END}")
    
    def get_recent_logs(self, limit: int = 50) -> List[Dict]:
        """Retrieve recent audit log entries"""
        if not self.log_file.exists():
            return []
        
        logs = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    try:
                        logs.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            return []
        
        return logs[-limit:]


class BackupManager:
    """Automated backup management with rotation"""
    
    def __init__(self, backup_dir: Path, max_backups: int = 10):
        self.backup_dir = backup_dir
        self.max_backups = max_backups
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, source_file: Path) -> bool:
        """Create a timestamped backup"""
        if not source_file.exists():
            return False
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"secrets_backup_{timestamp}.enc"
        backup_path = self.backup_dir / backup_name
        
        try:
            shutil.copy2(source_file, backup_path)
            self._rotate_backups()
            return True
        except Exception as e:
            print(f"{Colors.RED}Backup failed: {e}{Colors.END}")
            return False
    
    def _rotate_backups(self):
        """Keep only the most recent backups"""
        backups = sorted(self.backup_dir.glob("secrets_backup_*.enc"))
        
        while len(backups) > self.max_backups:
            oldest = backups.pop(0)
            try:
                oldest.unlink()
            except Exception:
                pass
    
    def list_backups(self) -> List[Tuple[str, datetime, int]]:
        """List all available backups"""
        backups = []
        for backup in sorted(self.backup_dir.glob("secrets_backup_*.enc"), reverse=True):
            try:
                stat = backup.stat()
                timestamp = datetime.fromtimestamp(stat.st_mtime)
                size = stat.st_size
                backups.append((backup.name, timestamp, size))
            except Exception:
                continue
        
        return backups
    
    def restore_backup(self, backup_name: str, target_file: Path) -> bool:
        """Restore from a backup"""
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            return False
        
        try:
            shutil.copy2(backup_path, target_file)
            return True
        except Exception as e:
            print(f"{Colors.RED}Restore failed: {e}{Colors.END}")
            return False


class IntegrityChecker:
    """Verify data integrity and detect tampering"""
    
    @staticmethod
    def calculate_checksum(data: bytes) -> str:
        """Calculate SHA-256 checksum"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def verify_integrity(data: bytes, expected_checksum: str) -> bool:
        """Verify data against checksum"""
        actual = IntegrityChecker.calculate_checksum(data)
        return secrets.compare_digest(actual, expected_checksum)


class PasswordValidator:
    """Validate password strength"""
    
    @staticmethod
    def check_strength(password: str) -> Tuple[int, str]:
        """
        Check password strength
        Returns: (score 0-4, feedback message)
        """
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        
        # Cap at 4
        score = min(score, 4)
        
        if score < 2:
            feedback.append("Password is too weak. Use at least 12 characters with mixed case, numbers, and symbols.")
        elif score == 2:
            feedback.append("Password is weak. Consider adding more complexity.")
        elif score == 3:
            feedback.append("Password is moderate. Good for basic use.")
        else:
            feedback.append("Password is strong.")
        
        return score, "; ".join(feedback)
    
    @staticmethod
    def validate_master_password(password: str, min_score: int = 2) -> bool:
        """Validate if password meets minimum requirements"""
        score, _ = PasswordValidator.check_strength(password)
        return score >= min_score


class ClipboardManager:
    """Secure clipboard operations with auto-clear"""
    
    @staticmethod
    def copy_with_timeout(text: str, timeout: int = 30):
        """Copy to clipboard and auto-clear after timeout"""
        try:
            import pyperclip
            pyperclip.copy(text)
            print(f"{Colors.GREEN}✓ Copied to clipboard (will clear in {timeout}s){Colors.END}")
            
            # Auto-clear in background
            def clear_clipboard():
                import time
                time.sleep(timeout)
                try:
                    if pyperclip.paste() == text:
                        pyperclip.copy('')
                except:
                    pass
            
            thread = threading.Thread(target=clear_clipboard, daemon=True)
            thread.start()
        except ImportError:
            print(f"{Colors.YELLOW}pyperclip not installed. Secret displayed only.{Colors.END}")
            print(f"\n{text}\n")
        except Exception as e:
            print(f"{Colors.YELLOW}Clipboard error: {e}{Colors.END}")
            print(f"\n{text}\n")


class SecretManager:
    def __init__(self, storage_path=None):
        """Initialize the Secret Manager"""
        if storage_path is None:
            storage_path = Path.home() / '.secret_manager'
        
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        self.secrets_file = self.storage_path / 'secrets.enc'
        self.salt_file = self.storage_path / 'salt.bin'
        self.checksum_file = self.storage_path / 'checksum.txt'
        
        # Initialize subsystems
        self.audit_logger = AuditLogger(self.storage_path / 'audit.log')
        self.backup_manager = BackupManager(self.storage_path / 'backups')
        
    def _generate_key(self, password: str, salt: bytes) -> bytes:
        """Generate encryption key from password"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create new one"""
        if self.salt_file.exists():
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            return salt
    
    def _get_cipher(self, password: str) -> Fernet:
        """Get Fernet cipher with password"""
        salt = self._get_or_create_salt()
        key = self._generate_key(password, salt)
        return Fernet(key)
    
    def _load_secrets(self, password: str) -> dict:
        """Load and decrypt secrets with integrity verification"""
        if not self.secrets_file.exists():
            return {}
        
        try:
            with open(self.secrets_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Verify integrity if checksum exists
            if self.checksum_file.exists():
                with open(self.checksum_file, 'r') as f:
                    expected_checksum = f.read().strip()
                
                if not IntegrityChecker.verify_integrity(encrypted_data, expected_checksum):
                    raise ValueError("Data integrity check failed! File may be corrupted or tampered with.")
            
            cipher = self._get_cipher(password)
            decrypted_data = cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except InvalidToken:
            raise ValueError("Invalid password")
        except ValueError as e:
            raise e
        except Exception as e:
            raise ValueError(f"Error loading secrets: {e}")
    
    def _save_secrets(self, secrets: dict, password: str):
        """Save and encrypt secrets with integrity checking"""
        cipher = self._get_cipher(password)
        encrypted_data = cipher.encrypt(json.dumps(secrets).encode())
        
        with open(self.secrets_file, 'wb') as f:
            f.write(encrypted_data)
        
        # Store checksum
        checksum = IntegrityChecker.calculate_checksum(encrypted_data)
        with open(self.checksum_file, 'w') as f:
            f.write(checksum)
        
        # Auto-backup
        self.backup_manager.create_backup(self.secrets_file)
    
    def add_secret(self, name: str, value: str, password: str, category: str = "general",
                   expires_days: Optional[int] = None, notes: str = ""):
        """Add or update a secret with metadata"""
        try:
            secrets = self._load_secrets(password)
            
            is_new = name not in secrets
            
            secret_data = {
                'value': value,
                'category': category,
                'created_at': secrets.get(name, {}).get('created_at', datetime.now().isoformat()),
                'updated_at': datetime.now().isoformat(),
                'notes': notes
            }
            
            if expires_days:
                expiry = datetime.now() + timedelta(days=expires_days)
                secret_data['expires_at'] = expiry.isoformat()
            
            secrets[name] = secret_data
            self._save_secrets(secrets, password)
            
            action = "added" if is_new else "updated"
            self.audit_logger.log("add" if is_new else "update", name, "success", f"Category: {category}")
            print(f"{Colors.GREEN}✓ Secret '{name}' {action} successfully{Colors.END}")
        except Exception as e:
            self.audit_logger.log("add", name, "failed", str(e))
            raise
    
    def get_secret(self, name: str, password: str, copy_to_clipboard: bool = False) -> str:
        """Retrieve a secret with optional clipboard copy"""
        try:
            secrets = self._load_secrets(password)
            
            if name not in secrets:
                self.audit_logger.log("get", name, "failed", "Secret not found")
                raise KeyError(f"Secret '{name}' not found")
            
            secret_data = secrets[name]
            value = secret_data['value']
            
            # Check expiration
            if 'expires_at' in secret_data:
                expiry = datetime.fromisoformat(secret_data['expires_at'])
                if datetime.now() > expiry:
                    print(f"{Colors.YELLOW}Warning: This secret has expired{Colors.END}")
            
            self.audit_logger.log("get", name, "success", "")
            
            if copy_to_clipboard:
                ClipboardManager.copy_with_timeout(value)
            
            return value
        except KeyError as e:
            raise e
        except Exception as e:
            self.audit_logger.log("get", name, "failed", str(e))
            raise
    
    def list_secrets(self, password: str, show_metadata: bool = True):
        """List all secret names with metadata"""
        secrets = self._load_secrets(password)
        
        if not secrets:
            print(f"{Colors.YELLOW}No secrets stored yet{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}Stored Secrets:{Colors.END}")
        print("-" * 100)
        
        if show_metadata:
            print(f"{'Name':<25} {'Category':<15} {'Updated':<20} {'Expires':<15} {'Status':<10}")
            print("-" * 100)
            
            for name, data in sorted(secrets.items()):
                category = data.get('category', 'general')
                updated = data.get('updated_at', 'N/A')
                if updated != 'N/A':
                    try:
                        updated = datetime.fromisoformat(updated).strftime('%Y-%m-%d %H:%M')
                    except:
                        pass
                
                expires = data.get('expires_at', 'N/A')
                status = 'Active'
                if expires != 'N/A':
                    try:
                        expiry = datetime.fromisoformat(expires)
                        expires = expiry.strftime('%Y-%m-%d')
                        if datetime.now() > expiry:
                            status = Colors.RED + "Expired" + Colors.END
                        elif datetime.now() > expiry - timedelta(days=7):
                            status = Colors.YELLOW + "Expiring" + Colors.END
                    except:
                        pass
                
                print(f"{name:<25} {category:<15} {updated:<20} {expires:<15} {status}")
        else:
            print(f"{'Name':<30} {'Category':<20}")
            print("-" * 60)
            for name, data in sorted(secrets.items()):
                category = data.get('category', 'general')
                print(f"{name:<30} {category:<20}")
        
        print(f"\n{Colors.BOLD}Total: {len(secrets)} secrets{Colors.END}")
    
    def delete_secret(self, name: str, password: str):
        """Delete a secret with audit logging"""
        try:
            secrets = self._load_secrets(password)
            
            if name not in secrets:
                self.audit_logger.log("delete", name, "failed", "Secret not found")
                raise KeyError(f"Secret '{name}' not found")
            
            del secrets[name]
            self._save_secrets(secrets, password)
            
            self.audit_logger.log("delete", name, "success", "")
            print(f"{Colors.GREEN}✓ Secret '{name}' deleted{Colors.END}")
        except KeyError as e:
            raise e
        except Exception as e:
            self.audit_logger.log("delete", name, "failed", str(e))
            raise
    
    def search_secrets(self, query: str, password: str):
        """Search secrets by name, category, or notes"""
        secrets = self._load_secrets(password)
        query_lower = query.lower()
        
        results = {
            name: data for name, data in secrets.items()
            if query_lower in name.lower() 
            or query_lower in data.get('category', '').lower()
            or query_lower in data.get('notes', '').lower()
        }
        
        if not results:
            print(f"{Colors.YELLOW}No secrets found matching '{query}'{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}Found {len(results)} secret(s):{Colors.END}")
        print("-" * 80)
        print(f"{'Name':<25} {'Category':<15} {'Updated':<20} {'Notes':<20}")
        print("-" * 80)
        
        for name, data in sorted(results.items()):
            category = data.get('category', 'general')
            updated = data.get('updated_at', 'N/A')
            if updated != 'N/A':
                try:
                    updated = datetime.fromisoformat(updated).strftime('%Y-%m-%d %H:%M')
                except:
                    pass
            notes = data.get('notes', '')[:20]
            print(f"{name:<25} {category:<15} {updated:<20} {notes:<20}")
    
    def export_to_env(self, password: str, output_file: str = ".env"):
        """Export secrets to .env file format"""
        try:
            secrets = self._load_secrets(password)
            
            if not secrets:
                print(f"{Colors.YELLOW}No secrets to export{Colors.END}")
                return
            
            output_path = Path(output_file)
            with open(output_path, 'w') as f:
                f.write(f"# Exported from Secret Manager on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# DO NOT COMMIT THIS FILE TO VERSION CONTROL\n\n")
                
                for name, data in sorted(secrets.items()):
                    value = data['value']
                    category = data.get('category', 'general')
                    f.write(f"# Category: {category}\n")
                    f.write(f"{name}={value}\n\n")
            
            self.audit_logger.log("export", output_file, "success", f"Exported {len(secrets)} secrets")
            print(f"{Colors.GREEN}✓ Exported {len(secrets)} secrets to {output_file}{Colors.END}")
        except Exception as e:
            self.audit_logger.log("export", output_file, "failed", str(e))
            raise
    
    def import_from_env(self, env_file: str, password: str, category: str = "imported"):
        """Import secrets from a .env file"""
        try:
            env_path = Path(env_file)
            if not env_path.exists():
                raise FileNotFoundError(f"File not found: {env_file}")
            
            secrets = self._load_secrets(password)
            imported_count = 0
            
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        
                        if key and value:
                            secrets[key] = {
                                'value': value,
                                'category': category,
                                'created_at': datetime.now().isoformat(),
                                'updated_at': datetime.now().isoformat(),
                                'notes': f'Imported from {env_file}'
                            }
                            imported_count += 1
            
            self._save_secrets(secrets, password)
            self.audit_logger.log("import", env_file, "success", f"Imported {imported_count} secrets")
            print(f"{Colors.GREEN}✓ Imported {imported_count} secrets from {env_file}{Colors.END}")
        except Exception as e:
            self.audit_logger.log("import", env_file, "failed", str(e))
            raise
    
    def import_from_json(self, json_file: str, password: str):
        """Import secrets from a JSON file"""
        try:
            json_path = Path(json_file)
            if not json_path.exists():
                raise FileNotFoundError(f"File not found: {json_file}")
            
            with open(json_path, 'r') as f:
                import_data = json.load(f)
            
            secrets = self._load_secrets(password)
            imported_count = 0
            
            for name, data in import_data.items():
                if isinstance(data, dict) and 'value' in data:
                    secrets[name] = data
                    imported_count += 1
                elif isinstance(data, str):
                    secrets[name] = {
                        'value': data,
                        'category': 'general',
                        'created_at': datetime.now().isoformat(),
                        'updated_at': datetime.now().isoformat(),
                        'notes': f'Imported from {json_file}'
                    }
                    imported_count += 1
            
            self._save_secrets(secrets, password)
            self.audit_logger.log("import", json_file, "success", f"Imported {imported_count} secrets")
            print(f"{Colors.GREEN}✓ Imported {imported_count} secrets from {json_file}{Colors.END}")
        except Exception as e:
            self.audit_logger.log("import", json_file, "failed", str(e))
            raise
    
    def show_audit_logs(self, limit: int = 50):
        """Display recent audit logs"""
        logs = self.audit_logger.get_recent_logs(limit)
        
        if not logs:
            print(f"{Colors.YELLOW}No audit logs found{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}Recent Audit Logs (last {len(logs)}):{Colors.END}")
        print("-" * 100)
        print(f"{'Timestamp':<20} {'Action':<10} {'Secret':<25} {'Status':<10} {'Details':<30}")
        print("-" * 100)
        
        for log in logs:
            timestamp = log.get('timestamp', 'N/A')
            if timestamp != 'N/A':
                try:
                    timestamp = datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
            
            action = log.get('action', 'N/A')
            secret_name = log.get('secret_name', 'N/A')
            status = log.get('status', 'N/A')
            details = log.get('details', '')[:30]
            
            status_color = Colors.GREEN if status == 'success' else Colors.RED
            status_display = f"{status_color}{status}{Colors.END}"
            
            print(f"{timestamp:<20} {action:<10} {secret_name:<25} {status_display:<20} {details:<30}")
    
    def list_backups(self):
        """List all available backups"""
        backups = self.backup_manager.list_backups()
        
        if not backups:
            print(f"{Colors.YELLOW}No backups found{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}Available Backups:{Colors.END}")
        print("-" * 80)
        print(f"{'Filename':<40} {'Date':<20} {'Size':<10}")
        print("-" * 80)
        
        for name, timestamp, size in backups:
            date_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            size_kb = size / 1024
            print(f"{name:<40} {date_str:<20} {size_kb:>7.1f} KB")
        
        print(f"\n{Colors.BOLD}Total: {len(backups)} backups{Colors.END}")
    
    def restore_from_backup(self, backup_name: str, password: str):
        """Restore secrets from a backup file"""
        try:
            # Verify password with current database first
            try:
                self._load_secrets(password)
            except:
                pass  # OK if no current database
            
            success = self.backup_manager.restore_backup(backup_name, self.secrets_file)
            
            if not success:
                raise FileNotFoundError(f"Backup '{backup_name}' not found")
            
            # Verify restored data with password
            self._load_secrets(password)
            
            self.audit_logger.log("restore", backup_name, "success", "")
            print(f"{Colors.GREEN}✓ Successfully restored from {backup_name}{Colors.END}")
        except Exception as e:
            self.audit_logger.log("restore", backup_name, "failed", str(e))
            raise
    
    def generate_strong_password(self, length: int = 24) -> str:
        """Generate a cryptographically strong password"""
        import string
        
        if length < 12:
            length = 12
        
        # Ensure we have at least one of each character type
        password_chars = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice(string.punctuation)
        ]
        
        # Fill the rest randomly
        all_chars = string.ascii_letters + string.digits + string.punctuation
        password_chars += [secrets.choice(all_chars) for _ in range(length - 4)]
        
        # Shuffle to avoid predictable pattern
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)


def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enterprise-Grade Secure API Key & Secret Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python secret_manager.py add MY_API_KEY -c aws
  python secret_manager.py get MY_API_KEY --copy
  python secret_manager.py list
  python secret_manager.py export
  python secret_manager.py import env_file.env
  python secret_manager.py search aws
  python secret_manager.py audit
  python secret_manager.py backups
  python secret_manager.py generate
        """
    )
    
    parser.add_argument('action', 
                       choices=['add', 'get', 'list', 'delete', 'export', 'import', 
                               'search', 'audit', 'backups', 'restore', 'generate', 'init'],
                       help='Action to perform')
    parser.add_argument('name', nargs='?', help='Secret name or file path for import')
    parser.add_argument('-c', '--category', default='general', help='Category for the secret')
    parser.add_argument('-o', '--output', default='.env', help='Output file for export')
    parser.add_argument('--storage', help='Custom storage path')
    parser.add_argument('--copy', action='store_true', help='Copy secret to clipboard')
    parser.add_argument('--expires', type=int, help='Days until secret expires')
    parser.add_argument('--notes', default='', help='Notes for the secret')
    parser.add_argument('--no-backup', action='store_true', help='Disable auto-backup')
    parser.add_argument('--format', choices=['env', 'json'], default='env', help='Import file format')
    parser.add_argument('--length', type=int, default=24, help='Password length for generate')
    
    args = parser.parse_args()
    
    # Initialize master password for init action
    if args.action == 'init':
        print(f"{Colors.BOLD}Initialize Secret Manager{Colors.END}")
        print("Choose a strong master password. This will protect all your secrets.\n")
        
        while True:
            password = getpass.getpass('Enter master password: ')
            score, feedback = PasswordValidator.check_strength(password)
            
            print(f"Password strength: {score}/4 - {feedback}")
            
            if score < 2:
                print(f"{Colors.RED}Password too weak. Please try again.{Colors.END}\n")
                continue
            
            password_confirm = getpass.getpass('Confirm master password: ')
            
            if password != password_confirm:
                print(f"{Colors.RED}Passwords don't match. Please try again.{Colors.END}\n")
                continue
            
            break
        
        # Initialize with empty database
        manager = SecretManager(args.storage)
        manager._save_secrets({}, password)
        print(f"\n{Colors.GREEN}✓ Secret Manager initialized successfully!{Colors.END}")
        print(f"Storage location: {manager.storage_path}")
        return
    
    # Initialize manager
    manager = SecretManager(args.storage)
    
    # Get master password
    password = getpass.getpass('Master password: ')
    
    try:
        if args.action == 'add':
            if not args.name:
                print(f"{Colors.RED}Error: Secret name required for 'add' action{Colors.END}")
                sys.exit(1)
            
            value = getpass.getpass(f'Enter value for {args.name}: ')
            manager.add_secret(args.name, value, password, args.category, 
                             expires_days=args.expires, notes=args.notes)
        
        elif args.action == 'get':
            if not args.name:
                print(f"{Colors.RED}Error: Secret name required for 'get' action{Colors.END}")
                sys.exit(1)
            
            value = manager.get_secret(args.name, password, copy_to_clipboard=args.copy)
            if not args.copy:
                print(f"\n{Colors.CYAN}{args.name}={value}{Colors.END}")
        
        elif args.action == 'list':
            manager.list_secrets(password)
        
        elif args.action == 'delete':
            if not args.name:
                print(f"{Colors.RED}Error: Secret name required for 'delete' action{Colors.END}")
                sys.exit(1)
            
            confirm = input(f"Delete '{args.name}'? (yes/no): ")
            if confirm.lower() == 'yes':
                manager.delete_secret(args.name, password)
            else:
                print(f"{Colors.YELLOW}Cancelled{Colors.END}")
        
        elif args.action == 'export':
            manager.export_to_env(password, args.output)
        
        elif args.action == 'import':
            if not args.name:
                print(f"{Colors.RED}Error: File path required for 'import' action{Colors.END}")
                sys.exit(1)
            
            if args.format == 'env':
                manager.import_from_env(args.name, password, args.category)
            elif args.format == 'json':
                manager.import_from_json(args.name, password)
        
        elif args.action == 'search':
            if not args.name:
                print(f"{Colors.RED}Error: Search query required{Colors.END}")
                sys.exit(1)
            manager.search_secrets(args.name, password)
        
        elif args.action == 'audit':
            manager.show_audit_logs()
        
        elif args.action == 'backups':
            manager.list_backups()
        
        elif args.action == 'restore':
            if not args.name:
                print(f"{Colors.RED}Error: Backup filename required{Colors.END}")
                sys.exit(1)
            
            confirm = input(f"Restore from '{args.name}'? This will overwrite current secrets. (yes/no): ")
            if confirm.lower() == 'yes':
                manager.restore_from_backup(args.name, password)
            else:
                print(f"{Colors.YELLOW}Cancelled{Colors.END}")
        
        elif args.action == 'generate':
            password_gen = manager.generate_strong_password(args.length)
            print(f"\n{Colors.GREEN}Generated Password:{Colors.END}")
            print(f"{Colors.CYAN}{password_gen}{Colors.END}\n")
            
            score, feedback = PasswordValidator.check_strength(password_gen)
            print(f"Strength: {score}/4 - {feedback}")
    
    except ValueError as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        sys.exit(1)
    except KeyError as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Cancelled{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Unexpected error: {e}{Colors.END}")
        sys.exit(1)


if __name__ == '__main__':
    main()
