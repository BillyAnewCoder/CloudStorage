"""
Command-line interface for CloudStorage SDK.

This module provides a comprehensive CLI tool for power users to interact
with CloudStorage services from the command line.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich import print as rprint

from .client import CloudStorageClient
from .async_client import AsyncCloudStorageClient
from .models import FileInfo, SearchFilter, UploadProgress, DownloadProgress
from .exceptions import CloudStorageError, AuthenticationError
from .utils import format_file_size, parse_file_size


# Initialize Rich console
console = Console()


class CLIContext:
    """CLI context object to share state between commands."""
    
    def __init__(self):
        self.client: Optional[CloudStorageClient] = None
        self.config: Dict[str, Any] = {}
        self.config_file = Path.home() / ".cloudstorage" / "config.json"
    
    def load_config(self):
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.config = {}
    
    def save_config(self):
        """Save configuration to file."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
        self.config_file.chmod(0o600)
    
    def get_client(self) -> CloudStorageClient:
        """Get authenticated client."""
        if self.client is None:
            api_key = self.config.get('api_key') or os.getenv('CLOUDSTORAGE_API_KEY')
            api_secret = self.config.get('api_secret') or os.getenv('CLOUDSTORAGE_API_SECRET')
            endpoint = self.config.get('endpoint', 'http://localhost:5000')
            
            if not api_key:
                raise AuthenticationError("API key not configured. Use 'cloudstorage config' or set CLOUDSTORAGE_API_KEY environment variable.")
            
            self.client = CloudStorageClient(
                api_key=api_key,
                api_secret=api_secret,
                endpoint=endpoint
            )
        
        return self.client


# Create CLI context
cli_context = CLIContext()


@click.group()
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def cli(ctx, debug):
    """CloudStorage CLI - Enterprise-grade cloud storage management."""
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    
    # Load configuration
    cli_context.load_config()
    
    if debug:
        console.print("[dim]Debug mode enabled[/dim]")


@cli.command()
@click.option('--api-key', prompt=True, help='API key for authentication')
@click.option('--api-secret', help='API secret for request signing')
@click.option('--endpoint', default='http://localhost:5000', help='CloudStorage API endpoint')
def config(api_key, api_secret, endpoint):
    """Configure CloudStorage credentials and settings."""
    
    cli_context.config.update({
        'api_key': api_key,
        'endpoint': endpoint
    })
    
    if api_secret:
        cli_context.config['api_secret'] = api_secret
    
    cli_context.save_config()
    
    console.print("✅ Configuration saved successfully!")
    
    # Test connection
    try:
        client = cli_context.get_client()
        health = client.health_check()
        console.print(f"✅ Connection test successful! Server status: {health.get('status', 'unknown')}")
    except Exception as e:
        console.print(f"⚠️ Configuration saved but connection test failed: {e}")


@cli.command()
def status():
    """Check API status and connection."""
    try:
        client = cli_context.get_client()
        health = client.health_check()
        
        table = Table(title="CloudStorage Status")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Status", health.get('status', 'unknown'))
        table.add_row("Timestamp", health.get('timestamp', 'unknown'))
        table.add_row("Endpoint", client.endpoint)
        
        console.print(table)
        
    except Exception as e:
        console.print(f"❌ Status check failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument('files', nargs=-1, required=True, type=click.Path(exists=True))
@click.option('--public', is_flag=True, help='Make files publicly accessible')
@click.option('--encrypt', is_flag=True, help='Encrypt files before upload')
@click.option('--tags', help='Comma-separated tags for the files')
@click.option('--metadata', help='JSON metadata for the files')
@click.option('--remote-name', help='Remote filename (only for single file upload)')
def upload(files, public, encrypt, tags, metadata, remote_name):
    """Upload files to CloudStorage."""
    
    if remote_name and len(files) > 1:
        console.print("❌ --remote-name can only be used with a single file")
        sys.exit(1)
    
    # Parse optional parameters
    tags_list = [tag.strip() for tag in tags.split(',')] if tags else None
    metadata_dict = json.loads(metadata) if metadata else None
    
    try:
        client = cli_context.get_client()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            for file_path in files:
                file_path = Path(file_path)
                task = progress.add_task(f"Uploading {file_path.name}", total=100)
                
                def progress_callback(prog: UploadProgress):
                    progress.update(task, completed=prog.percentage)
                
                file_info = client.upload_file(
                    file_path=file_path,
                    remote_name=remote_name if len(files) == 1 else None,
                    tags=tags_list,
                    metadata=metadata_dict,
                    is_public=public,
                    encrypt=encrypt,
                    progress_callback=progress_callback
                )
                
                progress.update(task, completed=100)
                console.print(f"✅ Uploaded: {file_info.original_name} (ID: {file_info.id})")
        
    except Exception as e:
        console.print(f"❌ Upload failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument('file_id', type=int)
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def download(file_id, output):
    """Download a file from CloudStorage."""
    
    try:
        client = cli_context.get_client()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            # Get file info first
            file_info = client.get_file_info(file_id)
            task = progress.add_task(f"Downloading {file_info.original_name}", total=100)
            
            def progress_callback(prog: DownloadProgress):
                progress.update(task, completed=prog.percentage)
            
            local_path = client.download_file(
                file_id=file_id,
                local_path=output,
                progress_callback=progress_callback
            )
            
            progress.update(task, completed=100)
            console.print(f"✅ Downloaded: {local_path}")
        
    except Exception as e:
        console.print(f"❌ Download failed: {e}")
        sys.exit(1)


@cli.command(name='list')
@click.option('--limit', '-l', default=50, help='Maximum number of files to list')
@click.option('--offset', '-o', default=0, help='Number of files to skip')
@click.option('--query', '-q', help='Search query')
@click.option('--tags', help='Filter by tags (comma-separated)')
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
def list_files(limit, offset, query, tags, output_json):
    """List files in CloudStorage."""
    
    try:
        client = cli_context.get_client()
        
        # Create search filter
        search_filter = None
        if query or tags:
            tags_list = [tag.strip() for tag in tags.split(',')] if tags else None
            search_filter = SearchFilter(query=query, tags=tags_list)
        
        files = client.list_files(
            limit=limit,
            offset=offset,
            search_filter=search_filter
        )
        
        if output_json:
            file_data = [file.to_dict() for file in files]
            console.print(json.dumps(file_data, indent=2, default=str))
        else:
            if not files:
                console.print("No files found.")
                return
            
            table = Table(title="Files")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Size", style="yellow")
            table.add_column("Type", style="blue")
            table.add_column("Created", style="magenta")
            table.add_column("Public", style="red")
            
            for file in files:
                table.add_row(
                    str(file.id),
                    file.original_name,
                    format_file_size(file.size),
                    file.mime_type.split('/')[0],
                    file.created_at.strftime('%Y-%m-%d %H:%M') if file.created_at else 'Unknown',
                    "Yes" if file.is_public else "No"
                )
            
            console.print(table)
        
    except Exception as e:
        console.print(f"❌ Failed to list files: {e}")
        sys.exit(1)


@cli.command()
@click.argument('file_id', type=int)
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
def info(file_id, output_json):
    """Get detailed information about a file."""
    
    try:
        client = cli_context.get_client()
        file_info = client.get_file_info(file_id)
        
        if output_json:
            console.print(json.dumps(file_info.to_dict(), indent=2, default=str))
        else:
            table = Table(title=f"File Information: {file_info.original_name}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("ID", str(file_info.id))
            table.add_row("Filename", file_info.original_name)
            table.add_row("Size", format_file_size(file_info.size))
            table.add_row("MIME Type", file_info.mime_type)
            table.add_row("ETag", file_info.etag)
            table.add_row("Version", str(file_info.version))
            table.add_row("Public", "Yes" if file_info.is_public else "No")
            table.add_row("Encrypted", "Yes" if file_info.is_encrypted else "No")
            table.add_row("Downloads", str(file_info.download_count))
            table.add_row("Created", file_info.created_at.strftime('%Y-%m-%d %H:%M:%S') if file_info.created_at else 'Unknown')
            table.add_row("Updated", file_info.updated_at.strftime('%Y-%m-%d %H:%M:%S') if file_info.updated_at else 'Unknown')
            
            if file_info.tags:
                table.add_row("Tags", ", ".join(file_info.tags))
            
            if file_info.metadata:
                table.add_row("Metadata", json.dumps(file_info.metadata, indent=2))
            
            console.print(table)
        
    except Exception as e:
        console.print(f"❌ Failed to get file info: {e}")
        sys.exit(1)


@cli.command()
@click.argument('file_id', type=int)
@click.confirmation_option(prompt='Are you sure you want to delete this file?')
def delete(file_id):
    """Delete a file from CloudStorage."""
    
    try:
        client = cli_context.get_client()
        
        # Get file info first for confirmation
        file_info = client.get_file_info(file_id)
        
        success = client.delete_file(file_id)
        
        if success:
            console.print(f"✅ Deleted: {file_info.original_name}")
        else:
            console.print("❌ Delete operation failed")
            sys.exit(1)
        
    except Exception as e:
        console.print(f"❌ Delete failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument('file_id', type=int)
@click.option('--permissions', default='read', help='Comma-separated permissions (read, download)')
@click.option('--password', help='Password protection for the share link')
@click.option('--expires', help='Expiration date (YYYY-MM-DD HH:MM:SS)')
@click.option('--download-limit', type=int, help='Maximum number of downloads')
def share(file_id, permissions, password, expires, download_limit):
    """Create a share link for a file."""
    
    try:
        client = cli_context.get_client()
        
        permissions_list = [p.strip() for p in permissions.split(',')]
        
        share_link = client.create_share_link(
            file_id=file_id,
            permissions=permissions_list,
            password=password,
            expires_at=expires,
            download_limit=download_limit
        )
        
        console.print(Panel(
            f"Share link created!\n\n"
            f"Token: {share_link.token}\n"
            f"URL: {client.endpoint}{share_link.share_url}\n"
            f"Permissions: {', '.join(share_link.permissions)}\n"
            f"Download count: {share_link.download_count}/{share_link.download_limit or '∞'}",
            title="Share Link",
            border_style="green"
        ))
        
    except Exception as e:
        console.print(f"❌ Failed to create share link: {e}")
        sys.exit(1)


@cli.command()
@click.argument('query')
@click.option('--tags', help='Filter by tags (comma-separated)')
@click.option('--limit', '-l', default=50, help='Maximum number of results')
def search(query, tags, limit):
    """Search for files."""
    
    try:
        client = cli_context.get_client()
        
        tags_list = [tag.strip() for tag in tags.split(',')] if tags else None
        files = client.search_files(query=query, tags=tags_list, limit=limit)
        
        if not files:
            console.print("No files found matching the search criteria.")
            return
        
        table = Table(title=f"Search Results for '{query}'")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Relevance", style="magenta")
        
        for file in files:
            # Simple relevance score based on query match in filename
            relevance = "High" if query.lower() in file.original_name.lower() else "Medium"
            
            table.add_row(
                str(file.id),
                file.original_name,
                format_file_size(file.size),
                relevance
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"❌ Search failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument('local_dir', type=click.Path(exists=True, file_okay=False))
@click.option('--remote-prefix', help='Remote path prefix')
@click.option('--exclude', multiple=True, help='Patterns to exclude (can be used multiple times)')
@click.option('--dry-run', is_flag=True, help='Show what would be uploaded without actually uploading')
def sync(local_dir, remote_prefix, exclude, dry_run):
    """Synchronize a local directory to CloudStorage."""
    
    import fnmatch
    
    local_dir = Path(local_dir)
    exclude_patterns = list(exclude) if exclude else []
    
    # Add common exclusions
    exclude_patterns.extend([
        '.git/*',
        '.DS_Store',
        'Thumbs.db',
        '*.tmp',
        '*.log'
    ])
    
    # Find files to upload
    files_to_upload = []
    
    for file_path in local_dir.rglob("*"):
        if file_path.is_file():
            relative_path = file_path.relative_to(local_dir)
            
            # Check exclusion patterns
            excluded = any(
                fnmatch.fnmatch(str(relative_path), pattern)
                for pattern in exclude_patterns
            )
            
            if not excluded:
                remote_name = str(relative_path)
                if remote_prefix:
                    remote_name = f"{remote_prefix}/{remote_name}"
                
                files_to_upload.append((file_path, remote_name))
    
    if not files_to_upload:
        console.print("No files to upload.")
        return
    
    console.print(f"Found {len(files_to_upload)} files to upload:")
    
    table = Table()
    table.add_column("Local Path", style="cyan")
    table.add_column("Remote Name", style="green")
    table.add_column("Size", style="yellow")
    
    total_size = 0
    for local_path, remote_name in files_to_upload:
        size = local_path.stat().st_size
        total_size += size
        table.add_row(str(local_path), remote_name, format_file_size(size))
    
    console.print(table)
    console.print(f"Total size: {format_file_size(total_size)}")
    
    if dry_run:
        console.print("🔍 Dry run complete. Use --no-dry-run to actually upload.")
        return
    
    # Confirm upload
    if not Confirm.ask("Proceed with upload?"):
        console.print("Upload cancelled.")
        return
    
    try:
        client = cli_context.get_client()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            main_task = progress.add_task("Uploading files", total=len(files_to_upload))
            
            for i, (local_path, remote_name) in enumerate(files_to_upload):
                file_task = progress.add_task(f"Uploading {local_path.name}", total=100)
                
                def progress_callback(prog: UploadProgress):
                    progress.update(file_task, completed=prog.percentage)
                
                try:
                    file_info = client.upload_file(
                        file_path=local_path,
                        remote_name=remote_name,
                        progress_callback=progress_callback
                    )
                    
                    progress.update(file_task, completed=100)
                    progress.advance(main_task)
                    
                except Exception as e:
                    console.print(f"❌ Failed to upload {local_path}: {e}")
        
        console.print("✅ Sync completed!")
        
    except Exception as e:
        console.print(f"❌ Sync failed: {e}")
        sys.exit(1)


@cli.command()
def stats():
    """Display storage usage statistics."""
    
    try:
        client = cli_context.get_client()
        stats = client.get_storage_stats()
        
        table = Table(title="Storage Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Files", str(stats['total_files']))
        table.add_row("Total Size", stats['total_size_formatted'])
        table.add_row("Average File Size", format_file_size(stats['total_size'] // max(stats['total_files'], 1)))
        
        if stats['file_types']:
            table.add_row("File Types", ", ".join(f"{k}: {v}" for k, v in stats['file_types'].items()))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"❌ Failed to get statistics: {e}")
        sys.exit(1)


if __name__ == '__main__':
    cli()
