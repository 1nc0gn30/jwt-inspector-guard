"""Cross-platform compatibility layer for jwt-inspector-guard.

Provides atomic file I/O, path normalization, safe reading/writing with
robust encoding fallbacks, safe deletion, and runtime platform detection
across Linux, macOS, Windows, and Termux environments.
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass
from typing import Any, Optional, Tuple, Union


@dataclass(frozen=True)
class PlatformInfo:
    """Runtime platform inspection details."""

    system: str
    release: str
    machine: str
    python_version: str
    is_windows: bool
    is_macos: bool
    is_linux: bool
    is_termux: bool
    is_posix: bool
    fs_encoding: str

    def to_dict(self) -> dict[str, Any]:
        """Convert platform info to dictionary."""
        return asdict(self)


def get_platform_info() -> PlatformInfo:
    """Detect and return detailed information about the current runtime platform.

    Returns:
        PlatformInfo: Populated platform attributes.
    """
    sys_name = platform.system()
    is_win = sys_name == "Windows"
    is_mac = sys_name == "Darwin"
    is_lin = sys_name == "Linux"
    is_termux = is_lin and ("com.termux" in os.environ.get("PREFIX", "") or "TERMUX_VERSION" in os.environ)
    is_posix = os.name == "posix"
    fs_enc = sys.getfilesystemencoding() or "utf-8"

    return PlatformInfo(
        system=sys_name,
        release=platform.release(),
        machine=platform.machine(),
        python_version=platform.python_version(),
        is_windows=is_win,
        is_macos=is_mac,
        is_linux=is_lin,
        is_termux=is_termux,
        is_posix=is_posix,
        fs_encoding=fs_enc,
    )


def normalize_path(path: Union[str, pathlib.Path]) -> pathlib.Path:
    """Normalize a filesystem path across POSIX, Windows, and Termux environments.

    Expands user directories (~), resolves symlinks/relative tokens, and sanitizes
    embedded null bytes.

    Args:
        path: Path string or pathlib.Path instance.

    Returns:
        pathlib.Path: Fully resolved and normalized path.

    Raises:
        ValueError: If path contains invalid null characters.
    """
    if isinstance(path, str):
        if "\0" in path:
            raise ValueError("Path contains invalid null characters.")
        p = pathlib.Path(path)
    else:
        p = path

    return p.expanduser().resolve()


def atomic_write_bytes(
    path: Union[str, pathlib.Path],
    data: bytes,
    make_dirs: bool = True,
    sync: bool = True,
) -> int:
    """Write binary data atomically to disk with fsync.

    Writes to a temporary file in the target directory before atomically
    replacing the target destination, ensuring zero corruption during power failure
    or concurrent process access.

    Args:
        path: Target file path.
        data: Binary payload to write.
        make_dirs: Whether to automatically create parent directories.
        sync: Whether to force disk synchronization via os.fsync.

    Returns:
        int: Number of bytes written.
    """
    dest_path = normalize_path(path)
    if make_dirs:
        dest_path.parent.mkdir(parents=True, exist_ok=True)

    temp_dir = dest_path.parent
    prefix = f".tmp_{dest_path.name}_"

    fd, temp_file_path = tempfile.mkstemp(dir=temp_dir, prefix=prefix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            if sync:
                os.fsync(f.fileno())

        os.replace(temp_file_path, dest_path)
        return len(data)
    except Exception:
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError:
                pass
        raise


def atomic_write_text(
    path: Union[str, pathlib.Path],
    text: str,
    encoding: str = "utf-8",
    make_dirs: bool = True,
    sync: bool = True,
) -> int:
    """Write text data atomically to disk with explicit encoding and fsync.

    Args:
        path: Target file path.
        text: String content to write.
        encoding: Text encoding (default: utf-8).
        make_dirs: Whether to automatically create parent directories.
        sync: Whether to force disk synchronization.

    Returns:
        int: Number of bytes written.
    """
    encoded_bytes = text.encode(encoding)
    return atomic_write_bytes(path, encoded_bytes, make_dirs=make_dirs, sync=sync)


def read_text_safe(
    path: Union[str, pathlib.Path],
    default: Optional[str] = None,
    encodings: Tuple[str, ...] = ("utf-8", "utf-8-sig", "latin-1"),
) -> str:
    """Read a text file safely with multiple encoding fallbacks.

    Args:
        path: File path to read.
        default: Fallback string if file does not exist. If None, FileNotFoundError is raised.
        encodings: Sequence of encodings to attempt in priority order.

    Returns:
        str: Read string content.

    Raises:
        FileNotFoundError: If file not found and default is None.
        UnicodeDecodeError: If all candidate encodings fail.
    """
    p = normalize_path(path)
    if not p.is_file():
        if default is not None:
            return default
        raise FileNotFoundError(f"File not found: {p}")

    raw_bytes = p.read_bytes()
    for enc in encodings:
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue

    # Final fallback with error replacement
    return raw_bytes.decode("utf-8", errors="replace")


def read_bytes_safe(
    path: Union[str, pathlib.Path],
    default: Optional[bytes] = None,
) -> bytes:
    """Read raw bytes from a file safely.

    Args:
        path: Target file path.
        default: Fallback bytes if file does not exist. If None, FileNotFoundError is raised.

    Returns:
        bytes: Raw byte contents.

    Raises:
        FileNotFoundError: If file does not exist and default is None.
    """
    p = normalize_path(path)
    if not p.is_file():
        if default is not None:
            return default
        raise FileNotFoundError(f"File not found: {p}")
    return p.read_bytes()


def read_json_safe(
    path: Union[str, pathlib.Path],
    default: Any = None,
) -> Any:
    """Read and parse a JSON file safely.

    Args:
        path: JSON file path.
        default: Fallback object if file does not exist or JSON parsing fails.

    Returns:
        Any: Parsed JSON data structure or default value.
    """
    try:
        content = read_text_safe(path)
        return json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        if default is not None:
            return default
        raise


def write_json_safe(
    path: Union[str, pathlib.Path],
    data: Any,
    indent: int = 2,
    sort_keys: bool = True,
) -> int:
    """Serialize and atomically write data to a JSON file.

    Args:
        path: Destination file path.
        data: Python data structure to serialize.
        indent: JSON indentation spaces.
        sort_keys: Whether to sort dictionary keys for deterministic outputs.

    Returns:
        int: Number of bytes written.
    """
    serialized = json.dumps(data, indent=indent, sort_keys=sort_keys, default=str)
    return atomic_write_text(path, serialized + "\n")


def safe_delete(path: Union[str, pathlib.Path], missing_ok: bool = True) -> bool:
    """Safely remove a file from disk without throwing unexpected exceptions.

    Args:
        path: File to delete.
        missing_ok: If True, do not raise error if target does not exist.

    Returns:
        bool: True if file was deleted, False if it was not found or failed.
    """
    try:
        p = normalize_path(path)
        if p.is_file() or p.is_symlink():
            p.unlink()
            return True
        elif not missing_ok and not p.exists():
            raise FileNotFoundError(f"Target file does not exist: {p}")
        return False
    except FileNotFoundError:
        if missing_ok:
            return False
        raise
    except OSError:
        return False


def safe_remove_dir(path: Union[str, pathlib.Path], missing_ok: bool = True) -> bool:
    """Safely remove a directory tree from disk.

    Args:
        path: Directory path to remove.
        missing_ok: If True, ignore missing directory.

    Returns:
        bool: True if removed, False otherwise.
    """
    try:
        p = normalize_path(path)
        if p.is_dir():
            shutil.rmtree(p)
            return True
        elif not missing_ok and not p.exists():
            raise FileNotFoundError(f"Target directory does not exist: {p}")
        return False
    except FileNotFoundError:
        if missing_ok:
            return False
        raise
    except OSError:
        return False
