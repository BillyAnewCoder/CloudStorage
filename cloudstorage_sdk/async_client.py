"""
Asynchronous CloudStorage client implementation.

This module provides an async/await compatible client for high-performance
operations and concurrent file transfers.
"""

import asyncio
import aiohttp
import os
import json
import time
import mimetypes
from typing import Optional, List, Dict, Any, Callable, BinaryIO, Union
from pathlib import Path

from .models import FileInfo, FileVersion, ShareLink, ApiKey, UploadProgress, DownloadProgress, SearchFilter
from .exceptions import (
    CloudStorageError, AuthenticationError, FileNotFoundError, 
    UploadError, DownloadError, QuotaExceededError, RateLimitError
)
from .auth import AuthManager
from .crypto import CryptoManager
from .utils import chunk_file, calculate_etag, format_file_size


class AsyncCloudStorageClient:
    """
    Enterprise-grade asynchronous client for CloudStorage operations.
    
    Provides the same functionality as CloudStorageClient but with async/await
    support for high-performance concurrent operations.
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
        max_concurrent_uploads: int = 5,
    ):
        """
        Initialize the async CloudStorage client.
        
        Args:
            api_key: API key for authentication
            api_secret: API secret for authentication
            endpoint: CloudStorage API endpoint URL
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            chunk_size: Chunk size for multipart uploads
            enable_compression: Enable automatic compression
            enable_encryption: Enable client-side encryption
            encryption_key: Encryption key
            max_concurrent_uploads: Maximum concurrent upload operations
        """
        self.api_key = api_key or os.getenv("CLOUDSTORAGE_API_KEY")
        self.api_secret = api_secret or os.getenv("CLOUDSTORAGE_API_SECRET")
        self.endpoint = endpoint.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.chunk_size = chunk_size
        self.enable_compression = enable_compression
        self.max_concurrent_uploads = max_concurrent_uploads
        
        if not self.api_key:
            raise AuthenticationError("API key is required.")
        
        # Initialize managers
        self.auth = AuthManager(self.api_key, self.api_secret)
        self.crypto = CryptoManager(enable_encryption, encryption_key)
        
        # Session will be created when needed
        self._session: Optional[aiohttp.ClientSession] = None
        self._upload_semaphore = asyncio.Semaphore(max_concurrent_uploads)
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "CloudStorage-Python-SDK/1.0.0",
            }
            
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
            self._session = aiohttp.ClientSession(
                headers=headers,
                timeout=self.timeout,
                connector=connector,
            )
        
        return self._session
    
    async def _request(
        self,
        method: str,
        path: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Make authenticated async request to the API."""
        session = await self._get_session()
        url = f"{self.endpoint}{path}"
        
        for attempt in range(3):  # Max retries
            try:
                async with session.request(method, url, **kwargs) as response:
                    # Handle rate limiting
                    if response.status == 429:
                        retry_after = int(response.headers.get("Retry-After", 60))
                        if attempt < 2:  # Don't sleep on last attempt
                            await asyncio.sleep(min(retry_after, 60))
                            continue
                        raise RateLimitError(f"Rate limit exceeded. Retry after {retry_after} seconds.")
                    
                    # Handle authentication errors
                    if response.status == 401:
                        raise AuthenticationError("Invalid or expired API credentials.")
                    
                    # Handle quota exceeded
                    if response.status == 402:
                        raise QuotaExceededError("Storage quota exceeded.")
                    
                    # Raise for other HTTP errors
                    response.raise_for_status()
                    
                    return response
                    
            except aiohttp.ClientConnectionError as e:
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue
                raise CloudStorageError(f"Connection error: {e}")
            except asyncio.TimeoutError as e:
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise CloudStorageError(f"Request timeout: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        async with await self._request("GET", "/api/health") as response:
            return await response.json()
    
    async def upload_file(
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
        Upload a file to CloudStorage asynchronously.
        
        Args:
            file_path: Path to file or file-like object
            remote_name: Remote filename (defaults to original filename)
            metadata: Custom metadata dictionary
            tags: List of tags for the file
            is_public: Whether file should be publicly accessible
            encrypt: Whether to encrypt the file
            progress_callback: Callback function for upload progress
            
        Returns:
            FileInfo object with upload details
        """
        async with self._upload_semaphore:
            return await self._upload_file_internal(
                file_path, remote_name, metadata, tags, is_public, encrypt, progress_callback
            )
    
    async def _upload_file_internal(
        self,
        file_path: Union[str, Path, BinaryIO],
        remote_name: Optional[str],
        metadata: Optional[Dict[str, Any]],
        tags: Optional[List[str]],
        is_public: bool,
        encrypt: Optional[bool],
        progress_callback: Optional[Callable[[UploadProgress], None]],
    ) -> FileInfo:
        """Internal upload implementation."""
        
        # Handle different input types
        if isinstance(file_path, (str, Path)):
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            filename = remote_name or file_path.name
            file_size = file_path.stat().st_size
            mime_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
            
            async with aiohttp.aiofiles.open(file_path, "rb") as f:
                file_data = await f.read()
        else:
            # File-like object
            if not remote_name:
                raise ValueError("remote_name is required when uploading file-like objects")
            
            filename = remote_name
            file_data = file_path.read()
            file_size = len(file_data)
            mime_type = mimetypes.guess_type(remote_name)[0] or "application/octet-stream"
        
        # Determine if encryption should be used
        should_encrypt = encrypt if encrypt is not None else self.crypto.enabled
        
        # Encrypt if needed
        if should_encrypt:
            file_data = self.crypto.encrypt(file_data)
            mime_type = "application/octet-stream"
        
        # Compress if enabled
        if self.enable_compression and len(file_data) > 1024:
            import gzip
            compressed_data = gzip.compress(file_data)
            if len(compressed_data) < len(file_data):
                file_data = compressed_data
                if metadata is None:
                    metadata = {}
                metadata["compressed"] = True
        
        # Prepare upload
        upload_data = {
            "metadata": json.dumps(metadata or {}),
            "tags": json.dumps(tags or []),
            "isPublic": str(is_public).lower(),
            "isEncrypted": str(should_encrypt).lower(),
        }
        
        if progress_callback:
            progress_callback(UploadProgress(
                filename=filename,
                total_bytes=len(file_data),
                uploaded_bytes=0,
                percentage=0.0,
                speed_bps=0.0
            ))
        
        # Create multipart form data
        form_data = aiohttp.FormData()
        for key, value in upload_data.items():
            form_data.add_field(key, value)
        form_data.add_field('file', file_data, filename=filename, content_type=mime_type)
        
        start_time = time.time()
        async with await self._request("POST", "/api/files", data=form_data) as response:
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
            
            file_data_response = await response.json()
            return FileInfo.from_dict(file_data_response)
    
    async def download_file(
        self,
        file_id: int,
        local_path: Optional[Union[str, Path]] = None,
        progress_callback: Optional[Callable[[DownloadProgress], None]] = None,
    ) -> Optional[Path]:
        """
        Download a file from CloudStorage asynchronously.
        
        Args:
            file_id: ID of the file to download
            local_path: Local path to save the file
            progress_callback: Callback function for download progress
            
        Returns:
            Path to downloaded file
        """
        
        # Get file info first
        file_info = await self.get_file_info(file_id)
        
        # Determine local path
        if local_path is None:
            local_path = Path(file_info.original_name)
        else:
            local_path = Path(local_path)
            if local_path.is_dir():
                local_path = local_path / file_info.original_name
        
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
        downloaded_bytes = 0
        
        async with await self._request("GET", f"/api/files/{file_id}/download") as response:
            async with aiohttp.aiofiles.open(local_path, "wb") as f:
                async for chunk in response.content.iter_chunked(self.chunk_size):
                    await f.write(chunk)
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
            async with aiohttp.aiofiles.open(local_path, "rb") as f:
                encrypted_data = await f.read()
            
            decrypted_data = self.crypto.decrypt(encrypted_data)
            
            async with aiohttp.aiofiles.open(local_path, "wb") as f:
                await f.write(decrypted_data)
        
        return local_path
    
    async def get_file_info(self, file_id: int) -> FileInfo:
        """Get information about a file."""
        async with await self._request("GET", f"/api/files/{file_id}") as response:
            file_data = await response.json()
            return FileInfo.from_dict(file_data)
    
    async def list_files(
        self,
        limit: int = 50,
        offset: int = 0,
        search_filter: Optional[SearchFilter] = None,
    ) -> List[FileInfo]:
        """List files with optional filtering."""
        params = {
            "limit": limit,
            "offset": offset,
        }
        
        if search_filter:
            if search_filter.query:
                params["q"] = search_filter.query
            if search_filter.tags:
                params["tags"] = ",".join(search_filter.tags)
        
        async with await self._request("GET", "/api/files", params=params) as response:
            files_data = await response.json()
            return [FileInfo.from_dict(file_data) for file_data in files_data]
    
    async def upload_files_concurrent(
        self,
        file_paths: List[Union[str, Path]],
        progress_callback: Optional[Callable[[str, UploadProgress], None]] = None,
    ) -> List[FileInfo]:
        """
        Upload multiple files concurrently.
        
        Args:
            file_paths: List of file paths to upload
            progress_callback: Callback function that receives filename and progress
            
        Returns:
            List of FileInfo objects for uploaded files
        """
        
        async def upload_single(file_path: Union[str, Path]) -> FileInfo:
            def wrapped_callback(progress: UploadProgress):
                if progress_callback:
                    progress_callback(str(file_path), progress)
            
            return await self.upload_file(file_path, progress_callback=wrapped_callback)
        
        # Create upload tasks
        tasks = [upload_single(file_path) for file_path in file_paths]
        
        # Execute with concurrency limit
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and return successful uploads
        successful_uploads = []
        for result in results:
            if isinstance(result, FileInfo):
                successful_uploads.append(result)
            elif isinstance(result, Exception):
                # Log or handle the exception as needed
                print(f"Upload failed: {result}")
        
        return successful_uploads
    
    async def sync_directory(
        self,
        local_dir: Union[str, Path],
        remote_prefix: str = "",
        exclude_patterns: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, UploadProgress], None]] = None,
    ) -> List[FileInfo]:
        """
        Synchronize a local directory to cloud storage.
        
        Args:
            local_dir: Local directory to sync
            remote_prefix: Remote path prefix
            exclude_patterns: List of patterns to exclude (glob-style)
            progress_callback: Progress callback function
            
        Returns:
            List of uploaded FileInfo objects
        """
        import fnmatch
        
        local_dir = Path(local_dir)
        if not local_dir.is_dir():
            raise ValueError("local_dir must be a directory")
        
        exclude_patterns = exclude_patterns or []
        
        # Find all files to upload
        files_to_upload = []
        for file_path in local_dir.rglob("*"):
            if file_path.is_file():
                # Check exclusion patterns
                relative_path = file_path.relative_to(local_dir)
                excluded = any(
                    fnmatch.fnmatch(str(relative_path), pattern)
                    for pattern in exclude_patterns
                )
                
                if not excluded:
                    remote_name = str(relative_path) if not remote_prefix else f"{remote_prefix}/{relative_path}"
                    files_to_upload.append((file_path, remote_name))
        
        # Upload files concurrently
        async def upload_with_remote_name(file_path: Path, remote_name: str) -> FileInfo:
            def wrapped_callback(progress: UploadProgress):
                if progress_callback:
                    progress_callback(remote_name, progress)
            
            return await self.upload_file(
                file_path,
                remote_name=remote_name,
                progress_callback=wrapped_callback
            )
        
        tasks = [
            upload_with_remote_name(file_path, remote_name)
            for file_path, remote_name in files_to_upload
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        successful_uploads = []
        for result in results:
            if isinstance(result, FileInfo):
                successful_uploads.append(result)
        
        return successful_uploads
    
    async def close(self):
        """Close the client session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
