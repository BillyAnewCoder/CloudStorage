"""
Cryptographic operations for CloudStorage SDK.

This module provides encryption, decryption, and key management
for secure file storage and transmission.
"""

import os
import hashlib
import hmac
import base64
from typing import Optional, Union, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

from .exceptions import EncryptionError, ConfigurationError


class CryptoManager:
    """
    Manages cryptographic operations for file encryption and security.
    
    Provides AES-256-CBC encryption, key derivation, and integrity verification
    for secure file storage and transmission.
    """
    
    def __init__(self, enabled: bool = False, encryption_key: Optional[str] = None):
        """
        Initialize crypto manager.
        
        Args:
            enabled: Whether encryption is enabled
            encryption_key: Master encryption key (base64 encoded)
        """
        self.enabled = enabled
        self._master_key: Optional[bytes] = None
        
        if enabled:
            if encryption_key:
                try:
                    self._master_key = base64.b64decode(encryption_key)
                except Exception as e:
                    raise ConfigurationError(f"Invalid encryption key format: {e}")
            else:
                # Generate a new master key
                self._master_key = self._generate_master_key()
    
    def _generate_master_key(self) -> bytes:
        """Generate a new 256-bit master encryption key."""
        return os.urandom(32)  # 256 bits
    
    def get_master_key_b64(self) -> Optional[str]:
        """Get the master key as a base64 string for storage."""
        if self._master_key:
            return base64.b64encode(self._master_key).decode('utf-8')
        return None
    
    def encrypt(self, data: bytes, metadata: Optional[dict] = None) -> bytes:
        """
        Encrypt data using AES-256-CBC with HMAC authentication.
        
        Args:
            data: Data to encrypt
            metadata: Additional metadata to include in authentication
            
        Returns:
            Encrypted data with authentication tag
            
        Format:
            [salt:16][iv:16][hmac:32][encrypted_data:variable]
        """
        if not self.enabled or not self._master_key:
            raise EncryptionError("Encryption is not enabled or key is not available")
        
        try:
            # Generate salt and IV
            salt = os.urandom(16)
            iv = os.urandom(16)
            
            # Derive encryption and MAC keys
            encryption_key, mac_key = self._derive_keys(self._master_key, salt)
            
            # Pad data to block size
            padder = PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Encrypt data
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Create authentication data
            auth_data = salt + iv + encrypted_data
            if metadata:
                import json
                metadata_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
                auth_data += metadata_bytes
            
            # Generate HMAC
            mac = hmac.new(mac_key, auth_data, hashlib.sha256).digest()
            
            # Combine all components
            result = salt + iv + mac + encrypted_data
            
            return result
            
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}")
    
    def decrypt(self, encrypted_data: bytes, metadata: Optional[dict] = None) -> bytes:
        """
        Decrypt data and verify authentication.
        
        Args:
            encrypted_data: Encrypted data with authentication tag
            metadata: Additional metadata for authentication verification
            
        Returns:
            Decrypted data
        """
        if not self.enabled or not self._master_key:
            raise EncryptionError("Encryption is not enabled or key is not available")
        
        try:
            # Extract components
            if len(encrypted_data) < 64:  # 16+16+32 minimum
                raise EncryptionError("Invalid encrypted data format")
            
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            mac = encrypted_data[32:64]
            ciphertext = encrypted_data[64:]
            
            # Derive keys
            encryption_key, mac_key = self._derive_keys(self._master_key, salt)
            
            # Verify HMAC
            auth_data = salt + iv + ciphertext
            if metadata:
                import json
                metadata_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
                auth_data += metadata_bytes
            
            expected_mac = hmac.new(mac_key, auth_data, hashlib.sha256).digest()
            
            if not hmac.compare_digest(mac, expected_mac):
                raise EncryptionError("Authentication verification failed")
            
            # Decrypt data
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadder = PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data
            
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}")
    
    def _derive_keys(self, master_key: bytes, salt: bytes) -> Tuple[bytes, bytes]:
        """
        Derive encryption and MAC keys from master key using PBKDF2.
        
        Args:
            master_key: Master encryption key
            salt: Salt for key derivation
            
        Returns:
            Tuple of (encryption_key, mac_key)
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for encryption + 32 bytes for MAC
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        derived_key = kdf.derive(master_key)
        
        encryption_key = derived_key[:32]
        mac_key = derived_key[32:]
        
        return encryption_key, mac_key
    
    def encrypt_file(self, file_path: Union[str, os.PathLike], output_path: Optional[Union[str, os.PathLike]] = None) -> str:
        """
        Encrypt a file and save to disk.
        
        Args:
            file_path: Path to file to encrypt
            output_path: Output path (defaults to input + .enc)
            
        Returns:
            Path to encrypted file
        """
        import pathlib
        
        file_path = pathlib.Path(file_path)
        if not file_path.exists():
            raise EncryptionError(f"File not found: {file_path}")
        
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + '.enc')
        else:
            output_path = pathlib.Path(output_path)
        
        try:
            with open(file_path, 'rb') as infile:
                data = infile.read()
            
            encrypted_data = self.encrypt(data)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(encrypted_data)
            
            return str(output_path)
            
        except Exception as e:
            raise EncryptionError(f"File encryption failed: {e}")
    
    def decrypt_file(self, encrypted_file_path: Union[str, os.PathLike], output_path: Optional[Union[str, os.PathLike]] = None) -> str:
        """
        Decrypt a file and save to disk.
        
        Args:
            encrypted_file_path: Path to encrypted file
            output_path: Output path (defaults to input without .enc)
            
        Returns:
            Path to decrypted file
        """
        import pathlib
        
        encrypted_file_path = pathlib.Path(encrypted_file_path)
        if not encrypted_file_path.exists():
            raise EncryptionError(f"Encrypted file not found: {encrypted_file_path}")
        
        if output_path is None:
            if encrypted_file_path.suffix == '.enc':
                output_path = encrypted_file_path.with_suffix('')
            else:
                output_path = encrypted_file_path.with_suffix('.dec')
        else:
            output_path = pathlib.Path(output_path)
        
        try:
            with open(encrypted_file_path, 'rb') as infile:
                encrypted_data = infile.read()
            
            decrypted_data = self.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
            
            return str(output_path)
            
        except Exception as e:
            raise EncryptionError(f"File decryption failed: {e}")
    
    def generate_file_key(self) -> str:
        """Generate a file-specific encryption key."""
        key = os.urandom(32)
        return base64.b64encode(key).decode('utf-8')
    
    def hash_data(self, data: bytes, algorithm: str = 'sha256') -> str:
        """
        Generate cryptographic hash of data.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha512, md5)
            
        Returns:
            Hexadecimal hash string
        """
        if algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'sha512':
            hasher = hashlib.sha512()
        elif algorithm == 'md5':
            hasher = hashlib.md5()
        else:
            raise EncryptionError(f"Unsupported hash algorithm: {algorithm}")
        
        hasher.update(data)
        return hasher.hexdigest()
    
    def verify_integrity(self, data: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Verify data integrity using cryptographic hash.
        
        Args:
            data: Data to verify
            expected_hash: Expected hash value
            algorithm: Hash algorithm
            
        Returns:
            True if integrity check passes
        """
        actual_hash = self.hash_data(data, algorithm)
        return hmac.compare_digest(actual_hash, expected_hash)


class KeyManager:
    """
    Manages encryption keys for different scopes and purposes.
    """
    
    def __init__(self):
        self._keys: dict = {}
    
    def generate_key(self, key_id: str, key_type: str = 'aes256') -> str:
        """Generate and store a new encryption key."""
        if key_type == 'aes256':
            key = os.urandom(32)
        elif key_type == 'aes128':
            key = os.urandom(16)
        else:
            raise EncryptionError(f"Unsupported key type: {key_type}")
        
        key_b64 = base64.b64encode(key).decode('utf-8')
        self._keys[key_id] = {
            'key': key_b64,
            'type': key_type,
            'created_at': time.time(),
        }
        
        return key_b64
    
    def get_key(self, key_id: str) -> Optional[str]:
        """Get a stored encryption key."""
        key_info = self._keys.get(key_id)
        return key_info['key'] if key_info else None
    
    def rotate_key(self, key_id: str, key_type: str = 'aes256') -> str:
        """Rotate an existing key."""
        old_key_info = self._keys.get(key_id)
        if old_key_info:
            # Store old key for backward compatibility
            old_key_id = f"{key_id}_old_{int(time.time())}"
            self._keys[old_key_id] = old_key_info
        
        return self.generate_key(key_id, key_type)
    
    def delete_key(self, key_id: str) -> bool:
        """Delete a stored key."""
        return self._keys.pop(key_id, None) is not None
