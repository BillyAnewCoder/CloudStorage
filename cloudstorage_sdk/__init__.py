"""
CloudStorage SDK - Enterprise-grade Python client for cloud storage operations.

This package provides comprehensive cloud storage capabilities including:
- File upload/download with chunked transfer support
- Authentication with API keys
- File versioning and metadata management
- Advanced sharing with permissions and expiration
- Async/await support for high-performance operations
- Encryption and compression features
- CLI tools for power users
"""

__version__ = "1.0.0"
__author__ = "CloudStorage Team"
__email__ = "support@cloudstorage.com"

from .client import CloudStorageClient
from .async_client import AsyncCloudStorageClient
from .models import (
    FileInfo,
    FileVersion,
    ShareLink,
    ApiKey,
    UploadProgress,
    DownloadProgress,
    SearchFilter,
)
from .exceptions import (
    CloudStorageError,
    AuthenticationError,
    FileNotFoundError,
    UploadError,
    DownloadError,
    QuotaExceededError,
    RateLimitError,
)

__all__ = [
    # Main clients
    "CloudStorageClient",
    "AsyncCloudStorageClient",
    
    # Data models
    "FileInfo",
    "FileVersion", 
    "ShareLink",
    "ApiKey",
    "UploadProgress",
    "DownloadProgress",
    "SearchFilter",
    
    # Exceptions
    "CloudStorageError",
    "AuthenticationError", 
    "FileNotFoundError",
    "UploadError",
    "DownloadError", 
    "QuotaExceededError",
    "RateLimitError",
]
