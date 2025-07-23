"""
Synchronous CloudStorage client implementation.

This module provides the main synchronous client for interacting with the CloudStorage API.
It includes comprehensive file operations, authentication, and enterprise features.
"""

import os
import json
import time
import hashlib
import mimetypes
from typing import Optional, List, Dict, Any, Callable, BinaryIO, Union
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import FileInfo, FileVersion, ShareLink, ApiKey, UploadProgress, DownloadProgress, SearchFilter
from .exceptions import (
    CloudStorageError, AuthenticationError, FileNotFoundError, 
    UploadError, DownloadError, QuotaExceededError, RateLimitError
)
from .auth import AuthManager
from .crypto import CryptoManager
from .utils import chunk_file, calculate_etag, format_file_size


class CloudStorageClient:
    """
    Enterprise-grade synchronous client for CloudStorage operations.
    
    Provides comprehensive file management, authentication, versioning,
    sharing, and encryption capabilities with enterprise-grade reliability.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        endpoint: str = "https://api.cloudstorage.com",
        timeout: int = 30,
        max_retries: int = 3,
        chunk_size: int = 8 * 1024 * 1024,  # 8MB chunks
        enable_compression: bool = True,
        enable_encryption: bool = False,
        encryption_key: Optional[str] = None,
    ):
        """
        Initialize the CloudStorage client.
        
        Args:
            api_key: API key for authentication (can also use CLOUDSTORAGE_API_KEY env var)
            api_secret: API secret for authentication (can also use CLOUDSTORAGE_API_SECRET env var)
            endpoint: CloudStorage API endpoint URL
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            chunk_size: Chunk size for multipart uploads
            enable_compression: Enable automatic compression for uploads
            enable_encryption: Enable client-side encryption
            encryption_key: Encryption key (if not provided, one will be generated)
        """
        self.api_key = api_key or os.getenv("CLOUDSTORAGE_API_KEY")
        self.api_secret = api_secret or os.getenv("CLOUDSTORAGE_API_SECRET")
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self.chunk_size = chunk_size
        self.enable_compression = enable_compression
        
        if not self.api_key:
            raise AuthenticationError("API key is required. Provide it as parameter or CLOUDSTORAGE_API_KEY env var.")
        
        # Initialize managers
        self.auth = AuthManager(self.api_key, self.api_secret)
        self.crypto = CryptoManager(enable_encryption, encryption_key)
        
        # Setup HTTP session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"CloudStorage-Python-SDK/1.0.0",
        })
    
    def _request(
        self, 
        method: str, 
        path: str, 
        **kwargs
    ) -> requests.Response:
        """Make authenticated request to the API."""
        url = f"{self.endpoint}{path}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                raise RateLimitError(f"Rate limit exceeded. Retry after {retry_after} seconds.")
            
            # Handle authentication errors
            if response.status_code == 401:
                raise AuthenticationError("Invalid or expired API credentials.")
            
            # Handle quota exceeded
            if response.status_code == 402:
                raise QuotaExceededError("Storage quota exceeded.")
            
            # Raise for other HTTP errors
            response.raise_for_status()
            
            return response
            
        except requests.exceptions.ConnectionError as e:
            raise CloudStorageError(f"Connection error: {e}")
        except requests.exceptions.Timeout as e:
            raise CloudStorageError(f"Request timeout: {e}")
        except requests.exceptions.RequestException as e:
            raise CloudStorageError(f"Request failed: {e}")
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        response = self._request("GET", "/api/health")
        return response.json()
    
    def upload_file(
        self,
        file_path: Union[str, Path, BinaryIO],
        remote_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        is_public: bool = False,
        encrypt: Optional[bool] = None,
        progress_callback: Optional[Callable[[UploadProgress], None]] = None,
    ) -> FileInfo:
        """
        Upload a file to CloudStorage.
        
        Args:
            file_path: Path to file or file-like object
            remote_name: Remote filename (defaults to original filename)
            metadata: Custom metadata dictionary
            tags: List of tags for the file
            is_public: Whether file should be publicly accessible
            encrypt: Whether to encrypt the file (overrides client default)
            progress_callback: Callback function for upload progress
            
        Returns:
            FileInfo object with upload details
        """
        # Handle different input types
        if isinstance(file_path, (str, Path)):
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            filename = remote_name or file_path.name
            file_size = file_path.stat().st_size
            mime_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
            
            with open(file_path, "rb") as f:
                return self._upload_file_object(
                    f, filename, file_size, mime_type, metadata, tags, 
                    is_public, encrypt, progress_callback
                )
        else:
            # File-like object
            if not remote_name:
                raise ValueError("remote_name is required when uploading file-like objects")
            
            # Try to get file size
            current_pos = file_path.tell()
            file_path.seek(0, 2)  # Seek to end
            file_size = file_path.tell()
            file_path.seek(current_pos)  # Restore position
            
            mime_type = mimetypes.guess_type(remote_name)[0] or "application/octet-stream"
            
            return self._upload_file_object(
                file_path, remote_name, file_size, mime_type, metadata, tags,
                is_public, encrypt, progress_callback
            )
    
    def _upload_file_object(
        self,
        file_obj: BinaryIO,
        filename: str,
        file_size: int,
        mime_type: str,
        metadata: Optional[Dict[str, Any]],
        tags: Optional[List[str]],
        is_public: bool,
        encrypt: Optional[bool],
        progress_callback: Optional[Callable[[UploadProgress], None]],
    ) -> FileInfo:
        """Internal method to upload file object."""
        
        # Determine if encryption should be used
        should_encrypt = encrypt if encrypt is not None else self.crypto.enabled
        
        # Prepare file data
        file_data = file_obj.read()
        
        # Encrypt if needed
        if should_encrypt:
            file_data = self.crypto.encrypt(file_data)
            mime_type = "application/octet-stream"  # Encrypted files are binary
        
        # Compress if enabled and file is large enough
        if self.enable_compression and len(file_data) > 1024:  # Only compress files > 1KB
            import gzip
            compressed_data = gzip.compress(file_data)
            if len(compressed_data) < len(file_data):  # Only use if actually smaller
                file_data = compressed_data
                # Update metadata to indicate compression
                if metadata is None:
                    metadata = {}
                metadata["compressed"] = True
        
        # Calculate ETag
        etag = calculate_etag(file_data)
        
        # Prepare upload data
        upload_data = {
            "metadata": json.dumps(metadata or {}),
            "tags": json.dumps(tags or []),
            "isPublic": str(is_public).lower(),
            "isEncrypted": str(should_encrypt).lower(),
        }
        
        # For large files, use chunked upload
        if len(file_data) > self.chunk_size:
            return self._chunked_upload(
                file_data, filename, mime_type, upload_data, progress_callback
            )
        else:
            return self._simple_upload(
                file_data, filename, mime_type, upload_data, progress_callback
            )
    
    def _simple_upload(
        self,
        file_data: bytes,
        filename: str,
        mime_type: str,
        upload_data: Dict[str, str],
        progress_callback: Optional[Callable[[UploadProgress], None]],
    ) -> FileInfo:
        """Upload file in a single request."""
        
        if progress_callback:
            progress_callback(UploadProgress(
                filename=filename,
                total_bytes=len(file_data),
                uploaded_bytes=0,
                percentage=0.0,
                speed_bps=0.0
            ))
        
        files = {
            "file": (filename, file_data, mime_type)
        }
        
        start_time = time.time()
        response = self._request("POST", "/api/files", data=upload_data, files=files)
        upload_time = time.time() - start_time
        
        if progress_callback:
            speed = len(file_data) / upload_time if upload_time > 0 else 0
            progress_callback(UploadProgress(
                filename=filename,
                total_bytes=len(file_data),
                uploaded_bytes=len(file_data),
                percentage=100.0,
                speed_bps=speed
            ))
        
        file_data_response = response.json()
        return FileInfo.from_dict(file_data_response)
    
    def _chunked_upload(
        self,
        file_data: bytes,
        filename: str,
        mime_type: str,
        upload_data: Dict[str, str],
        progress_callback: Optional[Callable[[UploadProgress], None]],
    ) -> FileInfo:
        """Upload large file in chunks."""
        
        # For this demo, we'll still do a simple upload
        # In a real implementation, you'd implement multipart upload protocol
        return self._simple_upload(file_data, filename, mime_type, upload_data, progress_callback)
    
    def download_file(
        self,
        file_id: int,
        local_path: Optional[Union[str, Path]] = None,
        progress_callback: Optional[Callable[[DownloadProgress], None]] = None,
    ) -> Optional[Path]:
        """
        Download a file from CloudStorage.
        
        Args:
            file_id: ID of the file to download
            local_path: Local path to save the file (optional)
            progress_callback: Callback function for download progress
            
        Returns:
            Path to downloaded file, or None if local_path was not provided
        """
        
        # Get file info first
        file_info = self.get_file_info(file_id)
        
        if progress_callback:
            progress_callback(DownloadProgress(
                filename=file_info.original_name,
                total_bytes=file_info.size,
                downloaded_bytes=0,
                percentage=0.0,
                speed_bps=0.0
            ))
        
        # Download file
        start_time = time.time()
        response = self._request("GET", f"/api/files/{file_id}/download", stream=True)
        
        # Determine local path
        if local_path is None:
            local_path = Path(file_info.original_name)
        else:
            local_path = Path(local_path)
            if local_path.is_dir():
                local_path = local_path / file_info.original_name
        
        # Download with progress tracking
        downloaded_bytes = 0
        with open(local_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=self.chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded_bytes += len(chunk)
                    
                    if progress_callback:
                        elapsed_time = time.time() - start_time
                        speed = downloaded_bytes / elapsed_time if elapsed_time > 0 else 0
                        percentage = (downloaded_bytes / file_info.size) * 100
                        
                        progress_callback(DownloadProgress(
                            filename=file_info.original_name,
                            total_bytes=file_info.size,
                            downloaded_bytes=downloaded_bytes,
                            percentage=percentage,
                            speed_bps=speed
                        ))
        
        # Decrypt if needed
        if file_info.is_encrypted and self.crypto.enabled:
            with open(local_path, "rb") as f:
                encrypted_data = f.read()
            
            decrypted_data = self.crypto.decrypt(encrypted_data)
            
            with open(local_path, "wb") as f:
                f.write(decrypted_data)
        
        return local_path
    
    def get_file_info(self, file_id: int) -> FileInfo:
        """Get information about a file."""
        response = self._request("GET", f"/api/files/{file_id}")
        return FileInfo.from_dict(response.json())
    
    def list_files(
        self,
        limit: int = 50,
        offset: int = 0,
        search_filter: Optional[SearchFilter] = None,
    ) -> List[FileInfo]:
        """
        List files with optional filtering.
        
        Args:
            limit: Maximum number of files to return
            offset: Number of files to skip
            search_filter: Optional search and filter criteria
            
        Returns:
            List of FileInfo objects
        """
        params = {
            "limit": limit,
            "offset": offset,
        }
        
        if search_filter:
            if search_filter.query:
                params["q"] = search_filter.query
            if search_filter.tags:
                params["tags"] = ",".join(search_filter.tags)
        
        response = self._request("GET", "/api/files", params=params)
        files_data = response.json()
        
        return [FileInfo.from_dict(file_data) for file_data in files_data]
    
    def search_files(
        self,
        query: str,
        tags: Optional[List[str]] = None,
        limit: int = 50,
    ) -> List[FileInfo]:
        """Search files by query and tags."""
        search_filter = SearchFilter(query=query, tags=tags)
        return self.list_files(limit=limit, search_filter=search_filter)
    
    def update_file(
        self,
        file_id: int,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        is_public: Optional[bool] = None,
    ) -> FileInfo:
        """Update file metadata and settings."""
        update_data = {}
        
        if metadata is not None:
            update_data["metadata"] = metadata
        if tags is not None:
            update_data["tags"] = tags
        if is_public is not None:
            update_data["isPublic"] = is_public
        
        response = self._request("PATCH", f"/api/files/{file_id}", json=update_data)
        return FileInfo.from_dict(response.json())
    
    def delete_file(self, file_id: int) -> bool:
        """Delete a file."""
        response = self._request("DELETE", f"/api/files/{file_id}")
        result = response.json()
        return result.get("success", False)
    
    def get_file_versions(self, file_id: int) -> List[FileVersion]:
        """Get all versions of a file."""
        response = self._request("GET", f"/api/files/{file_id}/versions")
        versions_data = response.json()
        
        return [FileVersion.from_dict(version_data) for version_data in versions_data]
    
    def create_share_link(
        self,
        file_id: int,
        permissions: List[str] = None,
        password: Optional[str] = None,
        expires_at: Optional[str] = None,
        download_limit: Optional[int] = None,
    ) -> ShareLink:
        """
        Create a share link for a file.
        
        Args:
            file_id: ID of the file to share
            permissions: List of permissions (e.g., ["read", "download"])
            password: Optional password protection
            expires_at: ISO format expiration date
            download_limit: Maximum number of downloads
            
        Returns:
            ShareLink object
        """
        share_data = {
            "permissions": permissions or ["read"],
        }
        
        if password:
            share_data["password"] = password
        if expires_at:
            share_data["expiresAt"] = expires_at
        if download_limit:
            share_data["downloadLimit"] = download_limit
        
        response = self._request("POST", f"/api/files/{file_id}/share", json=share_data)
        return ShareLink.from_dict(response.json())
    
    def get_share_links(self, file_id: int) -> List[ShareLink]:
        """Get all share links for a file."""
        response = self._request("GET", f"/api/files/{file_id}/share")
        links_data = response.json()
        
        return [ShareLink.from_dict(link_data) for link_data in links_data]
    
    def copy_file(self, file_id: int, new_name: Optional[str] = None) -> FileInfo:
        """Copy a file (creates a new version)."""
        # This would be implemented as a server-side copy operation
        # For now, we'll download and re-upload
        
        # Get original file info
        original_info = self.get_file_info(file_id)
        
        # Download to temporary location
        import tempfile
        with tempfile.NamedTemporaryFile() as temp_file:
            self.download_file(file_id, temp_file.name)
            
            # Re-upload with new name
            copy_name = new_name or f"Copy of {original_info.original_name}"
            return self.upload_file(
                temp_file.name,
                remote_name=copy_name,
                metadata=original_info.metadata,
                tags=original_info.tags,
                is_public=original_info.is_public,
            )
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage usage statistics."""
        # This would be a dedicated endpoint in a real API
        files = self.list_files(limit=1000)  # Get more files for stats
        
        total_files = len(files)
        total_size = sum(file.size for file in files)
        
        # Count by file type
        type_counts = {}
        for file in files:
            mime_type = file.mime_type.split("/")[0]
            type_counts[mime_type] = type_counts.get(mime_type, 0) + 1
        
        return {
            "total_files": total_files,
            "total_size": total_size,
            "total_size_formatted": format_file_size(total_size),
            "file_types": type_counts,
        }
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.session.close()
