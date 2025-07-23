"""
Custom exceptions for CloudStorage SDK.

This module defines all the exception classes used throughout the SDK
for proper error handling and user feedback.
"""


class CloudStorageError(Exception):
    """Base exception for all CloudStorage SDK errors."""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
    
    def __str__(self):
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message


class AuthenticationError(CloudStorageError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, error_code="AUTH_ERROR", **kwargs)


class AuthorizationError(CloudStorageError):
    """Raised when user lacks permission for an operation."""
    
    def __init__(self, message: str = "Operation not authorized", **kwargs):
        super().__init__(message, error_code="AUTHZ_ERROR", **kwargs)


class FileNotFoundError(CloudStorageError):
    """Raised when a requested file is not found."""
    
    def __init__(self, message: str = "File not found", file_id: int = None, **kwargs):
        super().__init__(message, error_code="FILE_NOT_FOUND", **kwargs)
        self.file_id = file_id


class UploadError(CloudStorageError):
    """Raised when file upload fails."""
    
    def __init__(self, message: str = "File upload failed", filename: str = None, **kwargs):
        super().__init__(message, error_code="UPLOAD_ERROR", **kwargs)
        self.filename = filename


class DownloadError(CloudStorageError):
    """Raised when file download fails."""
    
    def __init__(self, message: str = "File download failed", file_id: int = None, **kwargs):
        super().__init__(message, error_code="DOWNLOAD_ERROR", **kwargs)
        self.file_id = file_id


class QuotaExceededError(CloudStorageError):
    """Raised when storage quota is exceeded."""
    
    def __init__(self, message: str = "Storage quota exceeded", **kwargs):
        super().__init__(message, error_code="QUOTA_EXCEEDED", **kwargs)


class RateLimitError(CloudStorageError):
    """Raised when API rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = None, **kwargs):
        super().__init__(message, error_code="RATE_LIMIT", **kwargs)
        self.retry_after = retry_after


class ValidationError(CloudStorageError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str = "Validation failed", field: str = None, **kwargs):
        super().__init__(message, error_code="VALIDATION_ERROR", **kwargs)
        self.field = field


class EncryptionError(CloudStorageError):
    """Raised when encryption/decryption operations fail."""
    
    def __init__(self, message: str = "Encryption operation failed", **kwargs):
        super().__init__(message, error_code="ENCRYPTION_ERROR", **kwargs)


class CompressionError(CloudStorageError):
    """Raised when compression/decompression operations fail."""
    
    def __init__(self, message: str = "Compression operation failed", **kwargs):
        super().__init__(message, error_code="COMPRESSION_ERROR", **kwargs)


class NetworkError(CloudStorageError):
    """Raised when network operations fail."""
    
    def __init__(self, message: str = "Network operation failed", **kwargs):
        super().__init__(message, error_code="NETWORK_ERROR", **kwargs)


class TimeoutError(CloudStorageError):
    """Raised when operations timeout."""
    
    def __init__(self, message: str = "Operation timed out", timeout_seconds: int = None, **kwargs):
        super().__init__(message, error_code="TIMEOUT_ERROR", **kwargs)
        self.timeout_seconds = timeout_seconds


class IntegrityError(CloudStorageError):
    """Raised when file integrity checks fail."""
    
    def __init__(self, message: str = "File integrity check failed", expected_etag: str = None, actual_etag: str = None, **kwargs):
        super().__init__(message, error_code="INTEGRITY_ERROR", **kwargs)
        self.expected_etag = expected_etag
        self.actual_etag = actual_etag


class ShareLinkError(CloudStorageError):
    """Raised when share link operations fail."""
    
    def __init__(self, message: str = "Share link operation failed", token: str = None, **kwargs):
        super().__init__(message, error_code="SHARE_LINK_ERROR", **kwargs)
        self.token = token


class VersionError(CloudStorageError):
    """Raised when file versioning operations fail."""
    
    def __init__(self, message: str = "File versioning operation failed", file_id: int = None, version: int = None, **kwargs):
        super().__init__(message, error_code="VERSION_ERROR", **kwargs)
        self.file_id = file_id
        self.version = version


class ConfigurationError(CloudStorageError):
    """Raised when SDK configuration is invalid."""
    
    def __init__(self, message: str = "Invalid configuration", config_key: str = None, **kwargs):
        super().__init__(message, error_code="CONFIG_ERROR", **kwargs)
        self.config_key = config_key


class BatchOperationError(CloudStorageError):
    """Raised when batch operations fail."""
    
    def __init__(self, message: str = "Batch operation failed", operation_id: str = None, failed_items: list = None, **kwargs):
        super().__init__(message, error_code="BATCH_ERROR", **kwargs)
        self.operation_id = operation_id
        self.failed_items = failed_items or []


class ServerError(CloudStorageError):
    """Raised when server returns an error."""
    
    def __init__(self, message: str = "Server error", status_code: int = None, **kwargs):
        super().__init__(message, error_code="SERVER_ERROR", **kwargs)
        self.status_code = status_code


class ClientError(CloudStorageError):
    """Raised when client makes an invalid request."""
    
    def __init__(self, message: str = "Invalid client request", status_code: int = None, **kwargs):
        super().__init__(message, error_code="CLIENT_ERROR", **kwargs)
        self.status_code = status_code
