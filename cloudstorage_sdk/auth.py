"""
Authentication management for CloudStorage SDK.

This module handles API key authentication, token management,
and session handling for secure API access.
"""

import hashlib
import hmac
import time
import base64
from typing import Optional, Dict, Any
from urllib.parse import urlencode

from .exceptions import AuthenticationError, ConfigurationError


class AuthManager:
    """
    Manages authentication for CloudStorage API requests.
    
    Handles API key validation, request signing, and authentication
    headers for secure communication with the CloudStorage service.
    """
    
    def __init__(self, api_key: str, api_secret: Optional[str] = None):
        """
        Initialize authentication manager.
        
        Args:
            api_key: API key for authentication
            api_secret: API secret for request signing (optional)
        """
        if not api_key:
            raise ConfigurationError("API key is required for authentication")
        
        self.api_key = api_key
        self.api_secret = api_secret
        self._validate_credentials()
    
    def _validate_credentials(self):
        """Validate API credentials format."""
        if not self.api_key.startswith(('ak_', 'test_')):
            raise ConfigurationError("Invalid API key format. API keys should start with 'ak_' or 'test_'")
        
        if self.api_secret and not self.api_secret.startswith(('sk_', 'test_')):
            raise ConfigurationError("Invalid API secret format. API secrets should start with 'sk_' or 'test_'")
    
    def get_auth_headers(self, method: str = "GET", path: str = "/", body: Optional[bytes] = None) -> Dict[str, str]:
        """
        Generate authentication headers for API requests.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            body: Request body bytes for signature calculation
            
        Returns:
            Dictionary of authentication headers
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-CloudStorage-Version": "1.0",
        }
        
        # Add signature if API secret is available
        if self.api_secret:
            signature = self._generate_signature(method, path, body)
            headers["X-CloudStorage-Signature"] = signature
            headers["X-CloudStorage-Timestamp"] = str(int(time.time()))
        
        return headers
    
    def _generate_signature(self, method: str, path: str, body: Optional[bytes] = None) -> str:
        """
        Generate request signature using HMAC-SHA256.
        
        Args:
            method: HTTP method
            path: Request path
            body: Request body bytes
            
        Returns:
            Base64-encoded signature
        """
        timestamp = str(int(time.time()))
        
        # Create string to sign
        string_to_sign_parts = [
            method.upper(),
            path,
            timestamp,
        ]
        
        # Include body hash if present
        if body:
            body_hash = hashlib.sha256(body).hexdigest()
            string_to_sign_parts.append(body_hash)
        
        string_to_sign = "\n".join(string_to_sign_parts)
        
        # Generate HMAC signature
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, signature: str, method: str, path: str, timestamp: str, body: Optional[bytes] = None) -> bool:
        """
        Verify request signature (for webhook validation).
        
        Args:
            signature: Received signature
            method: HTTP method
            path: Request path
            timestamp: Request timestamp
            body: Request body bytes
            
        Returns:
            True if signature is valid
        """
        if not self.api_secret:
            return False
        
        # Recreate string to sign
        string_to_sign_parts = [
            method.upper(),
            path,
            timestamp,
        ]
        
        if body:
            body_hash = hashlib.sha256(body).hexdigest()
            string_to_sign_parts.append(body_hash)
        
        string_to_sign = "\n".join(string_to_sign_parts)
        
        # Generate expected signature
        expected_signature = hmac.new(
            self.api_secret.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        expected_signature_b64 = base64.b64encode(expected_signature).decode('utf-8')
        
        # Compare signatures securely
        return hmac.compare_digest(signature, expected_signature_b64)
    
    def is_authenticated(self) -> bool:
        """Check if client has valid authentication credentials."""
        return bool(self.api_key)
    
    def get_api_key_info(self) -> Dict[str, Any]:
        """Get information about the current API key."""
        key_type = "test" if self.api_key.startswith("test_") else "production"
        
        return {
            "key_id": self.api_key,
            "key_type": key_type,
            "has_secret": bool(self.api_secret),
            "can_sign_requests": bool(self.api_secret),
        }


class TokenManager:
    """
    Manages access tokens and refresh tokens for enhanced security.
    
    This is for future expansion when implementing OAuth2 or JWT tokens.
    """
    
    def __init__(self):
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[float] = None
    
    def set_tokens(self, access_token: str, refresh_token: Optional[str] = None, expires_in: Optional[int] = None):
        """Set access and refresh tokens."""
        self.access_token = access_token
        self.refresh_token = refresh_token
        
        if expires_in:
            self.token_expires_at = time.time() + expires_in
    
    def is_token_valid(self) -> bool:
        """Check if access token is valid and not expired."""
        if not self.access_token:
            return False
        
        if self.token_expires_at and time.time() >= self.token_expires_at:
            return False
        
        return True
    
    def needs_refresh(self) -> bool:
        """Check if token needs to be refreshed."""
        if not self.access_token:
            return True
        
        if self.token_expires_at:
            # Refresh if token expires in the next 5 minutes
            return time.time() >= (self.token_expires_at - 300)
        
        return False
    
    def clear_tokens(self):
        """Clear all stored tokens."""
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None


class CredentialManager:
    """
    Manages credential storage and retrieval from various sources.
    
    Supports environment variables, credential files, and secure storage.
    """
    
    def __init__(self):
        self.credentials_cache: Dict[str, str] = {}
    
    def get_credential(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get credential from various sources.
        
        Args:
            key: Credential key name
            default: Default value if not found
            
        Returns:
            Credential value or default
        """
        import os
        
        # Check cache first
        if key in self.credentials_cache:
            return self.credentials_cache[key]
        
        # Check environment variables
        env_value = os.getenv(key)
        if env_value:
            self.credentials_cache[key] = env_value
            return env_value
        
        # Check common environment variable variations
        env_variations = [
            f"CLOUDSTORAGE_{key.upper()}",
            f"CS_{key.upper()}",
            key.upper(),
        ]
        
        for env_var in env_variations:
            env_value = os.getenv(env_var)
            if env_value:
                self.credentials_cache[key] = env_value
                return env_value
        
        # Try to load from credentials file
        cred_file_value = self._load_from_credentials_file(key)
        if cred_file_value:
            self.credentials_cache[key] = cred_file_value
            return cred_file_value
        
        return default
    
    def _load_from_credentials_file(self, key: str) -> Optional[str]:
        """Load credential from credentials file."""
        import os
        import json
        from pathlib import Path
        
        # Common credential file locations
        credential_files = [
            Path.home() / ".cloudstorage" / "credentials.json",
            Path.home() / ".config" / "cloudstorage" / "credentials.json",
            Path.cwd() / ".cloudstorage.json",
            Path.cwd() / "credentials.json",
        ]
        
        for cred_file in credential_files:
            if cred_file.exists():
                try:
                    with open(cred_file, 'r') as f:
                        credentials = json.load(f)
                    
                    if key in credentials:
                        return credentials[key]
                
                except (json.JSONDecodeError, IOError, KeyError):
                    continue
        
        return None
    
    def store_credential(self, key: str, value: str, persistent: bool = False):
        """
        Store credential in cache and optionally persist to file.
        
        Args:
            key: Credential key name
            value: Credential value
            persistent: Whether to persist to credentials file
        """
        self.credentials_cache[key] = value
        
        if persistent:
            self._save_to_credentials_file(key, value)
    
    def _save_to_credentials_file(self, key: str, value: str):
        """Save credential to credentials file."""
        import json
        from pathlib import Path
        
        cred_dir = Path.home() / ".cloudstorage"
        cred_file = cred_dir / "credentials.json"
        
        # Create directory if it doesn't exist
        cred_dir.mkdir(exist_ok=True, parents=True)
        
        # Load existing credentials
        credentials = {}
        if cred_file.exists():
            try:
                with open(cred_file, 'r') as f:
                    credentials = json.load(f)
            except (json.JSONDecodeError, IOError):
                credentials = {}
        
        # Update and save
        credentials[key] = value
        
        try:
            with open(cred_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            
            # Set restrictive permissions
            cred_file.chmod(0o600)
            
        except IOError as e:
            raise ConfigurationError(f"Failed to save credentials: {e}")
    
    def clear_cache(self):
        """Clear credentials cache."""
        self.credentials_cache.clear()
