"""
Data models for CloudStorage SDK.

This module defines all the data structures used throughout the SDK
for type safety and consistency.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
from enum import Enum


class PermissionType(Enum):
    """File permission types."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SHARE = "share"


@dataclass
class FileInfo:
    """Information about a file in cloud storage."""
    
    id: int
    filename: str
    original_name: str
    mime_type: str
    size: int
    path: str
    etag: str
    version: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    is_encrypted: bool = False
    encryption_key: Optional[str] = None
    is_public: bool = False
    download_count: int = 0
    user_id: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileInfo":
        """Create FileInfo from API response dictionary."""
        # Convert datetime strings to datetime objects
        created_at = None
        updated_at = None
        
        if data.get("createdAt"):
            created_at = datetime.fromisoformat(data["createdAt"].replace("Z", "+00:00"))
        if data.get("updatedAt"):
            updated_at = datetime.fromisoformat(data["updatedAt"].replace("Z", "+00:00"))
        
        return cls(
            id=data["id"],
            filename=data["filename"],
            original_name=data["originalName"],
            mime_type=data["mimeType"],
            size=data["size"],
            path=data["path"],
            etag=data["etag"],
            version=data["version"],
            metadata=data.get("metadata", {}),
            tags=data.get("tags", []),
            is_encrypted=data.get("isEncrypted", False),
            encryption_key=data.get("encryptionKey"),
            is_public=data.get("isPublic", False),
            download_count=data.get("downloadCount", 0),
            user_id=data.get("userId", 0),
            created_at=created_at,
            updated_at=updated_at,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert FileInfo to dictionary."""
        result = {
            "id": self.id,
            "filename": self.filename,
            "originalName": self.original_name,
            "mimeType": self.mime_type,
            "size": self.size,
            "path": self.path,
            "etag": self.etag,
            "version": self.version,
            "metadata": self.metadata,
            "tags": self.tags,
            "isEncrypted": self.is_encrypted,
            "isPublic": self.is_public,
            "downloadCount": self.download_count,
            "userId": self.user_id,
        }
        
        if self.encryption_key:
            result["encryptionKey"] = self.encryption_key
        if self.created_at:
            result["createdAt"] = self.created_at.isoformat()
        if self.updated_at:
            result["updatedAt"] = self.updated_at.isoformat()
        
        return result


@dataclass
class FileVersion:
    """Information about a specific version of a file."""
    
    id: int
    file_id: int
    version: int
    filename: str
    size: int
    path: str
    etag: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileVersion":
        """Create FileVersion from API response dictionary."""
        created_at = None
        if data.get("createdAt"):
            created_at = datetime.fromisoformat(data["createdAt"].replace("Z", "+00:00"))
        
        return cls(
            id=data["id"],
            file_id=data["fileId"],
            version=data["version"],
            filename=data["filename"],
            size=data["size"],
            path=data["path"],
            etag=data["etag"],
            metadata=data.get("metadata", {}),
            created_at=created_at,
        )


@dataclass
class ShareLink:
    """Information about a file share link."""
    
    id: int
    file_id: int
    token: str
    permissions: List[str] = field(default_factory=lambda: ["read"])
    password: Optional[str] = None
    download_limit: Optional[int] = None
    download_count: int = 0
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ShareLink":
        """Create ShareLink from API response dictionary."""
        expires_at = None
        created_at = None
        
        if data.get("expiresAt"):
            expires_at = datetime.fromisoformat(data["expiresAt"].replace("Z", "+00:00"))
        if data.get("createdAt"):
            created_at = datetime.fromisoformat(data["createdAt"].replace("Z", "+00:00"))
        
        return cls(
            id=data["id"],
            file_id=data["fileId"],
            token=data["token"],
            permissions=data.get("permissions", ["read"]),
            password=data.get("password"),
            download_limit=data.get("downloadLimit"),
            download_count=data.get("downloadCount", 0),
            expires_at=expires_at,
            created_at=created_at,
        )
    
    @property
    def share_url(self) -> str:
        """Get the full share URL."""
        return f"/api/share/{self.token}"
    
    @property
    def is_expired(self) -> bool:
        """Check if the share link has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at
    
    @property
    def is_download_limit_reached(self) -> bool:
        """Check if download limit has been reached."""
        if self.download_limit is None:
            return False
        return self.download_count >= self.download_limit


@dataclass
class ApiKey:
    """Information about an API key."""
    
    id: int
    user_id: int
    key_id: str
    key_secret: str
    name: str
    permissions: List[str] = field(default_factory=list)
    is_active: bool = True
    last_used: Optional[datetime] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApiKey":
        """Create ApiKey from API response dictionary."""
        last_used = None
        created_at = None
        expires_at = None
        
        if data.get("lastUsed"):
            last_used = datetime.fromisoformat(data["lastUsed"].replace("Z", "+00:00"))
        if data.get("createdAt"):
            created_at = datetime.fromisoformat(data["createdAt"].replace("Z", "+00:00"))
        if data.get("expiresAt"):
            expires_at = datetime.fromisoformat(data["expiresAt"].replace("Z", "+00:00"))
        
        return cls(
            id=data["id"],
            user_id=data["userId"],
            key_id=data["keyId"],
            key_secret=data["keySecret"],
            name=data["name"],
            permissions=data.get("permissions", []),
            is_active=data.get("isActive", True),
            last_used=last_used,
            created_at=created_at,
            expires_at=expires_at,
        )
    
    @property
    def is_expired(self) -> bool:
        """Check if the API key has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at


@dataclass
class UploadProgress:
    """Progress information for file uploads."""
    
    filename: str
    total_bytes: int
    uploaded_bytes: int
    percentage: float
    speed_bps: float  # Bytes per second
    eta_seconds: Optional[float] = None
    
    @property
    def speed_mbps(self) -> float:
        """Upload speed in MB/s."""
        return self.speed_bps / (1024 * 1024)
    
    @property
    def uploaded_mb(self) -> float:
        """Uploaded bytes in MB."""
        return self.uploaded_bytes / (1024 * 1024)
    
    @property
    def total_mb(self) -> float:
        """Total bytes in MB."""
        return self.total_bytes / (1024 * 1024)


@dataclass
class DownloadProgress:
    """Progress information for file downloads."""
    
    filename: str
    total_bytes: int
    downloaded_bytes: int
    percentage: float
    speed_bps: float  # Bytes per second
    eta_seconds: Optional[float] = None
    
    @property
    def speed_mbps(self) -> float:
        """Download speed in MB/s."""
        return self.speed_bps / (1024 * 1024)
    
    @property
    def downloaded_mb(self) -> float:
        """Downloaded bytes in MB."""
        return self.downloaded_bytes / (1024 * 1024)
    
    @property
    def total_mb(self) -> float:
        """Total bytes in MB."""
        return self.total_bytes / (1024 * 1024)


@dataclass
class SearchFilter:
    """Filter criteria for file searches."""
    
    query: Optional[str] = None
    tags: Optional[List[str]] = None
    mime_types: Optional[List[str]] = None
    size_min: Optional[int] = None
    size_max: Optional[int] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    is_public: Optional[bool] = None
    is_encrypted: Optional[bool] = None
    
    def to_params(self) -> Dict[str, Any]:
        """Convert filter to API query parameters."""
        params = {}
        
        if self.query:
            params["q"] = self.query
        if self.tags:
            params["tags"] = ",".join(self.tags)
        if self.mime_types:
            params["mimeTypes"] = ",".join(self.mime_types)
        if self.size_min is not None:
            params["sizeMin"] = self.size_min
        if self.size_max is not None:
            params["sizeMax"] = self.size_max
        if self.created_after:
            params["createdAfter"] = self.created_after.isoformat()
        if self.created_before:
            params["createdBefore"] = self.created_before.isoformat()
        if self.is_public is not None:
            params["isPublic"] = str(self.is_public).lower()
        if self.is_encrypted is not None:
            params["isEncrypted"] = str(self.is_encrypted).lower()
        
        return params


@dataclass
class BatchOperation:
    """Information about a batch operation."""
    
    operation_id: str
    operation_type: str  # upload, download, delete, etc.
    total_items: int
    completed_items: int = 0
    failed_items: int = 0
    status: str = "pending"  # pending, running, completed, failed
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)
    
    @property
    def progress_percentage(self) -> float:
        """Calculate progress percentage."""
        if self.total_items == 0:
            return 0.0
        return (self.completed_items / self.total_items) * 100
    
    @property
    def is_completed(self) -> bool:
        """Check if operation is completed."""
        return self.status == "completed"
    
    @property
    def is_failed(self) -> bool:
        """Check if operation failed."""
        return self.status == "failed"


@dataclass
class StorageStats:
    """Storage usage statistics."""
    
    total_files: int
    total_size: int
    used_quota: int
    quota_limit: Optional[int] = None
    file_type_breakdown: Dict[str, int] = field(default_factory=dict)
    monthly_uploads: int = 0
    monthly_downloads: int = 0
    
    @property
    def total_size_gb(self) -> float:
        """Total size in GB."""
        return self.total_size / (1024 ** 3)
    
    @property
    def used_quota_gb(self) -> float:
        """Used quota in GB."""
        return self.used_quota / (1024 ** 3)
    
    @property
    def quota_limit_gb(self) -> Optional[float]:
        """Quota limit in GB."""
        if self.quota_limit is None:
            return None
        return self.quota_limit / (1024 ** 3)
    
    @property
    def quota_usage_percentage(self) -> Optional[float]:
        """Quota usage as percentage."""
        if self.quota_limit is None:
            return None
        return (self.used_quota / self.quota_limit) * 100
