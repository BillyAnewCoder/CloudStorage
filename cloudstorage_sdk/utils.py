"""
Utility functions for CloudStorage SDK.

This module provides common utility functions for file operations,
data processing, and general helper functions.
"""

import os
import hashlib
import mimetypes
import time
import math
from typing import Iterator, Optional, Union, BinaryIO, List, Dict, Any
from pathlib import Path


def calculate_etag(data: bytes, chunk_size: int = 8 * 1024 * 1024) -> str:
    """
    Calculate ETag for file data (compatible with S3-style ETags).
    
    Args:
        data: File data as bytes
        chunk_size: Chunk size for multipart ETag calculation
        
    Returns:
        ETag string
    """
    if len(data) <= chunk_size:
        # Simple MD5 for small files
        return hashlib.md5(data).hexdigest()
    else:
        # Multipart MD5 for large files
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        chunk_hashes = [hashlib.md5(chunk).digest() for chunk in chunks]
        combined_hash = hashlib.md5(b''.join(chunk_hashes)).hexdigest()
        return f"{combined_hash}-{len(chunks)}"


def calculate_file_etag(file_path: Union[str, Path], chunk_size: int = 8 * 1024 * 1024) -> str:
    """
    Calculate ETag for a file on disk.
    
    Args:
        file_path: Path to the file
        chunk_size: Chunk size for reading and calculation
        
    Returns:
        ETag string
    """
    file_path = Path(file_path)
    file_size = file_path.stat().st_size
    
    if file_size <= chunk_size:
        # Simple MD5 for small files
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    else:
        # Multipart MD5 for large files
        chunk_hashes = []
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunk_hashes.append(hashlib.md5(chunk).digest())
        
        combined_hash = hashlib.md5(b''.join(chunk_hashes)).hexdigest()
        return f"{combined_hash}-{len(chunk_hashes)}"


def chunk_file(file_obj: BinaryIO, chunk_size: int = 8 * 1024 * 1024) -> Iterator[bytes]:
    """
    Read file in chunks.
    
    Args:
        file_obj: File object to read from
        chunk_size: Size of each chunk in bytes
        
    Yields:
        File chunks as bytes
    """
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        yield chunk


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string (e.g., "1.5 MB")
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    
    if i >= len(size_names):
        i = len(size_names) - 1
    
    p = math.pow(1024, i)
    size = round(size_bytes / p, 2)
    
    return f"{size} {size_names[i]}"


def parse_file_size(size_str: str) -> int:
    """
    Parse human-readable file size to bytes.
    
    Args:
        size_str: Size string (e.g., "1.5 MB", "500KB")
        
    Returns:
        Size in bytes
    """
    size_str = size_str.strip().upper()
    
    # Extract number and unit
    import re
    match = re.match(r'^(\d+(?:\.\d+)?)\s*([KMGTPE]?B?)$', size_str)
    if not match:
        raise ValueError(f"Invalid size format: {size_str}")
    
    number, unit = match.groups()
    number = float(number)
    
    # Convert to bytes
    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 ** 2,
        'GB': 1024 ** 3,
        'TB': 1024 ** 4,
        'PB': 1024 ** 5,
        'EB': 1024 ** 6,
    }
    
    # Handle unit variations
    if unit == '':
        unit = 'B'
    elif unit in ['K', 'M', 'G', 'T', 'P', 'E']:
        unit += 'B'
    
    if unit not in multipliers:
        raise ValueError(f"Unknown unit: {unit}")
    
    return int(number * multipliers[unit])


def guess_mime_type(filename: str) -> str:
    """
    Guess MIME type from filename.
    
    Args:
        filename: Name of the file
        
    Returns:
        MIME type string
    """
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or "application/octet-stream"


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize filename for safe storage.
    
    Args:
        filename: Original filename
        max_length: Maximum filename length
        
    Returns:
        Sanitized filename
    """
    import re
    
    # Remove or replace unsafe characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Ensure filename is not empty
    if not filename:
        filename = "unnamed_file"
    
    # Truncate if too long
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        available_length = max_length - len(ext)
        filename = name[:available_length] + ext
    
    return filename


def validate_file_path(file_path: Union[str, Path]) -> Path:
    """
    Validate and normalize file path.
    
    Args:
        file_path: Path to validate
        
    Returns:
        Normalized Path object
        
    Raises:
        ValueError: If path is invalid
    """
    try:
        path = Path(file_path).resolve()
        
        # Check if path exists
        if not path.exists():
            raise ValueError(f"File does not exist: {file_path}")
        
        # Check if it's a file
        if not path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")
        
        # Check if readable
        if not os.access(path, os.R_OK):
            raise ValueError(f"File is not readable: {file_path}")
        
        return path
        
    except Exception as e:
        raise ValueError(f"Invalid file path: {e}")


def create_progress_bar(current: int, total: int, width: int = 50, prefix: str = "Progress") -> str:
    """
    Create a text progress bar.
    
    Args:
        current: Current progress value
        total: Total/maximum value
        width: Width of the progress bar
        prefix: Prefix text
        
    Returns:
        Progress bar string
    """
    if total == 0:
        percentage = 0
    else:
        percentage = min(100, max(0, (current / total) * 100))
    
    filled_width = int(width * percentage / 100)
    bar = '█' * filled_width + '░' * (width - filled_width)
    
    return f"{prefix}: |{bar}| {percentage:.1f}% ({current}/{total})"


def calculate_transfer_speed(bytes_transferred: int, elapsed_time: float) -> float:
    """
    Calculate transfer speed in bytes per second.
    
    Args:
        bytes_transferred: Number of bytes transferred
        elapsed_time: Time elapsed in seconds
        
    Returns:
        Speed in bytes per second
    """
    if elapsed_time <= 0:
        return 0
    return bytes_transferred / elapsed_time


def estimate_remaining_time(bytes_transferred: int, total_bytes: int, elapsed_time: float) -> Optional[float]:
    """
    Estimate remaining transfer time.
    
    Args:
        bytes_transferred: Bytes transferred so far
        total_bytes: Total bytes to transfer
        elapsed_time: Time elapsed so far
        
    Returns:
        Estimated remaining time in seconds, or None if cannot estimate
    """
    if bytes_transferred <= 0 or elapsed_time <= 0:
        return None
    
    speed = calculate_transfer_speed(bytes_transferred, elapsed_time)
    if speed <= 0:
        return None
    
    remaining_bytes = total_bytes - bytes_transferred
    return remaining_bytes / speed


def retry_with_backoff(
    func,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """
    Retry function with exponential backoff.
    
    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        backoff_factor: Exponential backoff factor
        exceptions: Exceptions to catch and retry on
        
    Returns:
        Function result
        
    Raises:
        Last exception if all retries fail
    """
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            return func()
        except exceptions as e:
            last_exception = e
            
            if attempt < max_retries:
                delay = min(base_delay * (backoff_factor ** attempt), max_delay)
                time.sleep(delay)
            else:
                break
    
    raise last_exception


def compress_data(data: bytes, compression_type: str = 'gzip') -> bytes:
    """
    Compress data using specified algorithm.
    
    Args:
        data: Data to compress
        compression_type: Compression algorithm (gzip, zlib, bz2)
        
    Returns:
        Compressed data
    """
    if compression_type == 'gzip':
        import gzip
        return gzip.compress(data)
    elif compression_type == 'zlib':
        import zlib
        return zlib.compress(data)
    elif compression_type == 'bz2':
        import bz2
        return bz2.compress(data)
    else:
        raise ValueError(f"Unsupported compression type: {compression_type}")


def decompress_data(data: bytes, compression_type: str = 'gzip') -> bytes:
    """
    Decompress data using specified algorithm.
    
    Args:
        data: Compressed data
        compression_type: Compression algorithm (gzip, zlib, bz2)
        
    Returns:
        Decompressed data
    """
    if compression_type == 'gzip':
        import gzip
        return gzip.decompress(data)
    elif compression_type == 'zlib':
        import zlib
        return zlib.decompress(data)
    elif compression_type == 'bz2':
        import bz2
        return bz2.decompress(data)
    else:
        raise ValueError(f"Unsupported compression type: {compression_type}")


def generate_unique_filename(base_name: str, existing_names: List[str]) -> str:
    """
    Generate a unique filename by adding a suffix if needed.
    
    Args:
        base_name: Base filename
        existing_names: List of existing filenames
        
    Returns:
        Unique filename
    """
    if base_name not in existing_names:
        return base_name
    
    name, ext = os.path.splitext(base_name)
    counter = 1
    
    while True:
        new_name = f"{name}_{counter}{ext}"
        if new_name not in existing_names:
            return new_name
        counter += 1


def validate_metadata(metadata: Dict[str, Any], max_size: int = 2048) -> bool:
    """
    Validate metadata dictionary.
    
    Args:
        metadata: Metadata dictionary
        max_size: Maximum serialized size in bytes
        
    Returns:
        True if valid
        
    Raises:
        ValueError: If metadata is invalid
    """
    import json
    
    try:
        # Check if JSON serializable
        serialized = json.dumps(metadata, ensure_ascii=False)
        
        # Check size
        if len(serialized.encode('utf-8')) > max_size:
            raise ValueError(f"Metadata too large (max {max_size} bytes)")
        
        # Check for reserved keys
        reserved_keys = {'__system__', '__internal__', '__cloudstorage__'}
        if any(key.startswith('__') and key in reserved_keys for key in metadata.keys()):
            raise ValueError("Metadata contains reserved keys")
        
        return True
        
    except (TypeError, ValueError) as e:
        raise ValueError(f"Invalid metadata: {e}")


def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge multiple dictionaries, with later ones taking precedence.
    
    Args:
        *dicts: Dictionaries to merge
        
    Returns:
        Merged dictionary
    """
    result = {}
    for d in dicts:
        if d:
            result.update(d)
    return result


def filter_dict(data: Dict[str, Any], allowed_keys: List[str]) -> Dict[str, Any]:
    """
    Filter dictionary to only include allowed keys.
    
    Args:
        data: Dictionary to filter
        allowed_keys: List of allowed keys
        
    Returns:
        Filtered dictionary
    """
    return {k: v for k, v in data.items() if k in allowed_keys}


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary (takes precedence)
        
    Returns:
        Deep merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result
