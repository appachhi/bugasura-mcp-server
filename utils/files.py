"""Server-filesystem helpers: save destinations, created folders, and the STDIO-only path guard."""
import os
from typing import Optional

from utils.client import in_http_request


def resolve_save_destination(save_to_path: str, filename: str) -> tuple[str, Optional[str]]:
    """Turn a caller's save_to_path into the file path to write.

    A folder is an existing directory, a path ending in a separator, or a path that does
    not exist yet and has no file extension — the file goes inside it under `filename`.
    Anything else is the full file path, written as given. Nothing is created here: the
    second value is the missing folder the caller creates once its own checks pass.
    Raises: ValueError when save_to_path is not absolute.
    """
    raw = os.path.expanduser(save_to_path.strip())
    if not os.path.isabs(raw):
        raise ValueError(f"'{save_to_path}' is not an absolute path")
    if os.path.isdir(raw):
        return os.path.join(raw, filename), None
    if raw.endswith(('/', os.sep)) or (not os.path.exists(raw) and not os.path.splitext(raw)[1]):
        return os.path.join(raw, filename), raw
    return raw, None


def create_folder(folder: str) -> Optional[str]:
    """Create `folder` (parents included); return the topmost folder created, for remove_created_folder."""
    top, parent = None, os.path.abspath(folder)
    while parent and not os.path.exists(parent):
        top, parent = parent, os.path.dirname(parent)
    os.makedirs(folder, exist_ok=True)
    return top


def remove_created_folder(folder: str, top: Optional[str]) -> None:
    """Remove the empty folders create_folder made, from `folder` up to `top`."""
    if not top:
        return
    current = os.path.abspath(folder)
    while True:
        try:
            os.rmdir(current)
        except OSError:
            return
        if current == top:
            return
        current = os.path.dirname(current)


def local_path_rejected(param: str) -> Optional[dict]:
    """A `failed` payload when `param` (a server-side file path) is used over HTTP, else None.

    Over streamable HTTP the "local" filesystem is the shared server's, not the user's, so
    file paths would let any signed-in caller read or write files on that box.
    """
    if not in_http_request():
        return None
    return {
        'status': 'failed',
        'error': f'{param} is not available on this hosted Bugasura MCP server.',
        'error_type': 'ValidationError',
        'message': (f"{param} refers to the server's own filesystem, which a hosted server does not "
                    "expose. Create an upload link with bugasura_create_upload_link for the user's "
                    "file and pass its upload_id, or, where the tool takes one, a shareable https "
                    "link (Google Drive, Dropbox, or any public download URL) as source_url."),
    }
