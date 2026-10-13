"""
Upload links: stage a user's file on this server so a knowledge base tool can send it on.

The hosted server cannot read the user's disk and the model must never carry file bytes, so
`bugasura_create_upload_link` hands out a short-lived, single-use URL (`/upload/<upload_id>`)
bound to the signed-in user. The user drops the file on that page (or a terminal client runs
`curl -F file=@<path> <url>`), the file is staged under UPLOAD_STAGING_PATH, and the KB tool
called with `upload_id` posts it to the Bugasura API exactly like a local `file_paths` upload.

The routes are public (outside /mcp's bearer check): the unguessable upload_id is the
capability, and consuming a staged file still requires the same signed-in user.
"""
import asyncio, json, os, re, secrets, shutil, time

from html import escape
from typing import Optional

from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException
from starlette.formparsers import MultiPartException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from config.config import (
    API_BASE, MCP_PUBLIC_BASE_URL, MCP_SERVER_NAME, UPLOAD_CLAIM_TTL_SECONDS, UPLOAD_CONSUMER_TOOLS,
    UPLOAD_IN_PROGRESS_GRACE_SECONDS, UPLOAD_MAX_EXTENSION_CHARS, UPLOAD_MAX_FILENAME_BYTES,
    UPLOAD_MAX_FILENAME_CHARS, UPLOAD_MAX_FILES, UPLOAD_MAX_OPEN_PER_USER, UPLOAD_MAX_STAGED_MB_PER_USER,
    UPLOAD_MAX_STAGED_MB_TOTAL, UPLOAD_MULTIPART_OVERHEAD_BYTES, UPLOAD_ORPHAN_GRACE_SECONDS,
    UPLOAD_PURPOSES, UPLOAD_STAGED_TTL_SECONDS, UPLOAD_STAGING_PATH, UPLOAD_SWEEP_INTERVAL_SECONDS,
    UPLOAD_TICKET_TTL_SECONDS, logger,
)

_META_FILE = "meta.json"
# Created with O_EXCL by the first POST, which makes each link single-use across workers
_LOCK_FILE = ".lock"
# Created with O_EXCL by the tool call sending the files on, so two calls never send them twice
_CLAIM_FILE = ".claim"
# Uploaded files live in their own folder, apart from the ticket's bookkeeping files
_FILES_DIR = "files"
# secrets.token_urlsafe(24) yields 32 chars; anything else is not one of ours
_UPLOAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
_CHUNK_BYTES = 1024 * 1024

_PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    # Not no-referrer: that makes browsers send "Origin: null" on the form POST, which the Origin guard refuses
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def _fail(error: str, message: str, error_type: str = "ValidationError") -> dict:
    return {"status": "failed", "error": error, "error_type": error_type, "message": message}


def _ticket_dir(upload_id: str) -> Optional[str]:
    if not isinstance(upload_id, str) or not _UPLOAD_ID_RE.match(upload_id):
        return None
    return os.path.join(UPLOAD_STAGING_PATH, upload_id)


def _read_meta(ticket_dir: str) -> Optional[dict]:
    try:
        with open(os.path.join(ticket_dir, _META_FILE), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_meta(ticket_dir: str, meta: dict) -> None:
    tmp_path = os.path.join(ticket_dir, f".{_META_FILE}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh)
    os.replace(tmp_path, os.path.join(ticket_dir, _META_FILE))


def _load_ticket(upload_id: str) -> tuple[Optional[str], Optional[dict]]:
    """The ticket's directory and meta, or (None, None) when unknown or from another backend."""
    ticket_dir = _ticket_dir(upload_id)
    meta = _read_meta(ticket_dir) if ticket_dir else None
    # The staging dir may be shared by tenants; user ids are only unique per backend
    if not meta or meta.get("api_base") != API_BASE:
        return None, None
    return ticket_dir, meta


def _sweep_expired() -> None:
    """Remove expired tickets and orphaned directories (on each create and from sweep_periodically)."""
    now = time.time()
    try:
        entries = list(os.scandir(UPLOAD_STAGING_PATH))
    except OSError:
        return
    for entry in entries:
        if not entry.is_dir(follow_symlinks=False):
            continue
        meta = _read_meta(entry.path)
        try:
            stale = (meta.get("expires", 0) < now if meta
                     else entry.stat(follow_symlinks=False).st_mtime < now - UPLOAD_ORPHAN_GRACE_SECONDS)
        except OSError:
            continue
        if stale and not (meta and meta.get("status") == "pending" and _upload_in_progress(entry.path, now)):
            shutil.rmtree(entry.path, ignore_errors=True)


def _upload_in_progress(ticket_dir: str, now: float) -> bool:
    """True when an upload took the ticket's lock less than UPLOAD_IN_PROGRESS_GRACE_SECONDS ago."""
    try:
        started = os.stat(os.path.join(ticket_dir, _LOCK_FILE)).st_mtime
    except OSError:
        return False
    return started > now - UPLOAD_IN_PROGRESS_GRACE_SECONDS


async def sweep_periodically() -> None:
    """Sweep expired uploads at startup, then every UPLOAD_SWEEP_INTERVAL_SECONDS (HTTP server only)."""
    while True:
        try:
            await asyncio.to_thread(_sweep_expired)
        except Exception:
            logger.exception("sweep_periodically: upload sweep failed")
        await asyncio.sleep(UPLOAD_SWEEP_INTERVAL_SECONDS)


def create_ticket(user_id: str, purpose: str) -> dict:
    """Open an upload link for `user_id`. Returns the link details or a failure envelope."""
    if not user_id:
        return _fail("No signed-in user",
                     "Upload links need the Bugasura sign-in of the hosted server.", "AuthError")
    os.makedirs(UPLOAD_STAGING_PATH, mode=0o700, exist_ok=True)
    _sweep_expired()

    now = time.time()
    open_links = sum(1 for _, meta in _tickets() if meta.get("user_id") == user_id)
    if open_links >= UPLOAD_MAX_OPEN_PER_USER:
        return _fail("Too many open upload links",
                     f"You have {open_links} upload links that have not been used by a tool yet. Use one of "
                     f"them, or wait for them to expire ({UPLOAD_TICKET_TTL_SECONDS // 60} minutes for an unused "
                     f"link, {UPLOAD_STAGED_TTL_SECONDS // 60} for an uploaded file) before creating another.")

    upload_id = secrets.token_urlsafe(24)
    ticket_dir = os.path.join(UPLOAD_STAGING_PATH, upload_id)
    os.mkdir(ticket_dir, 0o700)
    expires = int(now + UPLOAD_TICKET_TTL_SECONDS)
    _write_meta(ticket_dir, {
        "user_id": user_id, "api_base": API_BASE, "purpose": purpose,
        "created": int(now), "expires": expires, "status": "pending", "files": [],
    })
    extensions, max_mb = UPLOAD_PURPOSES[purpose]
    logger.info(f"create_ticket: upload link {upload_id[:6]}… for user {user_id} ({purpose})")
    return {
        "status": "OK",
        "upload_id": upload_id,
        "upload_url": f"{MCP_PUBLIC_BASE_URL}/upload/{upload_id}",
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires)),
        "expires_in_minutes": UPLOAD_TICKET_TTL_SECONDS // 60,
        "allowed_extensions": sorted(extensions) if extensions else ["any"],
        "max_file_size_mb": max_mb,
        "max_files": _max_files(purpose),
    }


def staged_paths(upload_id: str, user_id: str, purpose: str) -> dict:
    """Paths of the files staged under `upload_id` for this user, or a failure envelope."""
    ticket_dir, meta = _load_ticket(upload_id)
    # Someone else's id answers exactly like an unknown one
    if not meta or not user_id or meta.get("user_id") != user_id:
        return _fail("Upload not found",
                     "No upload with that upload_id exists for this account. Create a new link with "
                     "bugasura_create_upload_link.")
    if meta.get("expires", 0) < time.time():
        return _fail("Upload link expired",
                     "That upload expired before it was used. Create a new link with "
                     "bugasura_create_upload_link and ask the user to upload the file again.")
    if meta.get("status") != "uploaded":
        return _fail("File not uploaded yet",
                     "Nothing has been uploaded to that link yet. Ask the user to open the upload link, "
                     "add the file and press Upload, then call this tool again with the same upload_id.")
    if meta.get("purpose") != purpose:
        return _fail("Upload is for a different tool",
                     f"That upload was made for {UPLOAD_CONSUMER_TOOLS.get(meta.get('purpose'), 'another tool')}; "
                     f"call that tool with the upload_id instead.")
    files_dir = os.path.realpath(os.path.join(ticket_dir, _FILES_DIR))
    paths = []
    for entry in meta.get("files") or []:
        name = entry.get("name") if isinstance(entry, dict) else None
        path = os.path.realpath(os.path.join(files_dir, name)) if isinstance(name, str) else ""
        # Only names the upload route could have written, inside this ticket's own folder
        if (not name or name.startswith(".") or re.search(r"[\\/\x00-\x1f\x7f]", name)
                or os.path.dirname(path) != files_dir or not os.path.isfile(path)):
            logger.error(f"staged_paths: upload {upload_id[:6]}… lists an unusable file {name!r}")
            return _fail("Uploaded file unavailable",
                         "The uploaded file is no longer available. Create a new link with "
                         "bugasura_create_upload_link and ask the user to upload the file again.")
        paths.append(path)
    return {"status": "OK", "paths": paths}


def claim(upload_id: str) -> Optional[dict]:
    """Reserve a staged upload for one tool call. None when claimed, else a failure envelope.

    The caller sends the files, then calls `discard` on success or `release` on failure. A claim
    older than UPLOAD_CLAIM_TTL_SECONDS belongs to a call that died and is taken over.
    """
    ticket_dir = _ticket_dir(upload_id)
    if not ticket_dir:
        return _fail("Upload not found", "No upload with that upload_id exists for this account.")
    path = os.path.join(ticket_dir, _CLAIM_FILE)
    for _ in range(2):
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            return None
        except FileExistsError:
            try:
                if os.stat(path).st_mtime > time.time() - UPLOAD_CLAIM_TTL_SECONDS:
                    break
                os.unlink(path)
            except FileNotFoundError:
                continue
        except OSError:
            break
    return _fail("Upload already being sent",
                 "Another call is already sending this upload to Bugasura. Wait for it to finish, then check "
                 "whether the file arrived before trying again.")


def release(upload_id: str) -> None:
    """Free a claimed upload after a failed call, so it can be retried with the same upload_id."""
    ticket_dir = _ticket_dir(upload_id)
    if ticket_dir:
        try:
            os.unlink(os.path.join(ticket_dir, _CLAIM_FILE))
        except OSError:
            pass


def discard(upload_id: str) -> None:
    """Delete a consumed upload's staged files."""
    ticket_dir = _ticket_dir(upload_id)
    if ticket_dir:
        shutil.rmtree(ticket_dir, ignore_errors=True)


def _tickets():
    """(ticket_dir, meta) for every live ticket on this backend that no tool has consumed yet."""
    try:
        entries = list(os.scandir(UPLOAD_STAGING_PATH))
    except OSError:
        return
    for entry in entries:
        meta = _read_meta(entry.path) if entry.is_dir(follow_symlinks=False) else None
        if meta and meta.get("api_base") == API_BASE:
            yield entry.path, meta


def _staged_bytes(user_id: Optional[str] = None) -> int:
    """Bytes held by uploaded files, for one user or (None) for every tenant sharing the staging dir."""
    total = 0
    try:
        entries = list(os.scandir(UPLOAD_STAGING_PATH))
    except OSError:
        return 0
    for entry in entries:
        meta = _read_meta(entry.path) if entry.is_dir(follow_symlinks=False) else None
        if not meta or meta.get("status") != "uploaded":
            continue
        if user_id is not None and (meta.get("user_id") != user_id or meta.get("api_base") != API_BASE):
            continue
        total += sum(f.get("size", 0) for f in meta.get("files") or [] if isinstance(f, dict))
    return total


def _max_files(purpose: str) -> int:
    # A document import reads a single importFile
    return 1 if purpose == "document_import" else UPLOAD_MAX_FILES


def _safe_filename(filename: Optional[str]) -> str:
    """Basename without control or path characters, trimmed to a sane length (extension kept).

    Empty when nothing usable is left, or the extension is implausibly long.
    """
    name = re.split(r"[\\/]", filename or "")[-1]
    name = re.sub(r"[\x00-\x1f\x7f<>:\"|?*]", "", name).strip().lstrip(".")
    stem, ext = os.path.splitext(name)
    if not stem or len(ext) > UPLOAD_MAX_EXTENSION_CHARS:
        return ""
    stem = stem[:UPLOAD_MAX_FILENAME_CHARS - len(ext)]
    # Multibyte names: trim by bytes too, so open() never fails on the name's length
    while len((stem + ext).encode("utf-8")) > UPLOAD_MAX_FILENAME_BYTES:
        stem = stem[:-1]
    return stem.rstrip() + ext if stem.strip() else ""


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "")


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(status_code=status_code, headers=_PAGE_HEADERS, content=f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} · {escape(MCP_SERVER_NAME)}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222;line-height:1.5}}
form{{border:2px dashed #bbb;border-radius:8px;padding:1.5rem}}button{{margin-top:1rem;padding:.5rem 1.25rem;font-size:1rem}}
.muted{{color:#666;font-size:.9rem}}</style></head>
<body><h1>{escape(title)}</h1>{body}</body></html>""")


def _gone_page() -> HTMLResponse:
    return _page("Upload link not available",
                 "<p>This upload link has expired or has already been used.</p>"
                 "<p>Ask your assistant for a new upload link.</p>", status_code=404)


def _open_ticket(upload_id: str) -> tuple[Optional[str], Optional[dict]]:
    """A ticket that can still take an upload, or (None, None)."""
    ticket_dir, meta = _load_ticket(upload_id)
    if not meta or meta.get("status") != "pending" or meta.get("expires", 0) < time.time():
        return None, None
    return ticket_dir, meta


async def upload_page(request: Request):
    """GET /upload/{upload_id}: a plain file form (no JavaScript) for the ticket's purpose."""
    _, meta = _open_ticket(request.path_params.get("upload_id", ""))
    if not meta:
        return _gone_page()
    extensions, max_mb = UPLOAD_PURPOSES[meta["purpose"]]
    accept = f' accept="{escape(",".join(f".{ext}" for ext in sorted(extensions)))}"' if extensions else ""
    allowed = ", ".join(sorted(extensions)) if extensions else "any file type"
    max_files = _max_files(meta["purpose"])
    multiple = " multiple" if max_files > 1 else ""
    minutes = max(1, int((meta["expires"] - time.time()) // 60))
    return _page("Upload to Bugasura", f"""
<form method="post" enctype="multipart/form-data">
<p><input type="file" name="file"{accept} required{multiple}></p>
<p class="muted">Allowed: {escape(allowed)} · up to {max_mb} MB in total
{f'· up to {max_files} files' if max_files > 1 else '· one file'}</p>
<button type="submit">Upload</button>
</form>
<p class="muted">This link works once and expires in about {minutes} minutes. The file goes to Bugasura only
after you return to your assistant and it finishes the upload.</p>""")


def _result(request: Request, status_code: int, error: str, message: str) -> HTMLResponse | JSONResponse:
    """A failed upload, as a page for a browser or JSON for curl."""
    if _wants_html(request):
        return _page("Upload failed", f"<p>{escape(message)}</p>", status_code=status_code)
    return JSONResponse(_fail(error, message), status_code=status_code, headers={"Cache-Control": "no-store"})


def _clear_files(ticket_dir: str) -> None:
    shutil.rmtree(os.path.join(ticket_dir, _FILES_DIR), ignore_errors=True)


async def upload_files(request: Request):
    """POST /upload/{upload_id}: stage the multipart `file` part(s) for the ticket's purpose."""
    upload_id = request.path_params.get("upload_id", "")
    ticket_dir, meta = _open_ticket(upload_id)
    if not meta:
        if _wants_html(request):
            return _gone_page()
        return JSONResponse(_fail("Upload link not available",
                                  "This upload link has expired or has already been used. Ask the "
                                  "assistant for a new one."), status_code=404)

    extensions, max_mb = UPLOAD_PURPOSES[meta["purpose"]]
    max_bytes = max_mb * 1024 * 1024
    max_files = _max_files(meta["purpose"])

    # Refuse an oversized body before reading it
    length = request.headers.get("content-length")
    if not length or not length.isdigit():
        return _result(request, 411, "Content-Length required", "Send the file as a multipart form upload.")
    if int(length) > max_bytes + UPLOAD_MULTIPART_OVERHEAD_BYTES:
        return _result(request, 413, "File too large", f"Uploads are limited to {max_mb} MB in total.")
    # Uploaded files wait up to an hour for a tool, so cap what one user, and everyone, can park here
    incoming = max(0, int(length) - UPLOAD_MULTIPART_OVERHEAD_BYTES)
    if _staged_bytes(meta.get("user_id")) + incoming > UPLOAD_MAX_STAGED_MB_PER_USER * 1024 * 1024:
        return _result(request, 507, "Too much uploaded",
                       f"Your uploads waiting to be sent to Bugasura already come close to "
                       f"{UPLOAD_MAX_STAGED_MB_PER_USER} MB. Finish those first, or wait for them to expire.")
    if _staged_bytes() + incoming > UPLOAD_MAX_STAGED_MB_TOTAL * 1024 * 1024:
        logger.warning(f"upload_files: staging space full, refusing {upload_id[:6]}…")
        return _result(request, 507, "Server busy", "The server has no room for this upload right now. "
                                                    "Try again in a few minutes.")

    try:
        lock_fd = os.open(os.path.join(ticket_dir, _LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return _result(request, 409, "Upload already in progress",
                       "This link is already being used for an upload. Ask the assistant for a new link.")
    os.close(lock_fd)

    staged, failure = [], None
    form = None
    try:
        try:
            form = await request.form(max_files=max_files, max_fields=max_files + 5)
        except (HTTPException, MultiPartException) as exc:
            logger.info(f"upload_files: rejected multipart body for {upload_id[:6]}…: {exc}")
            failure = (400, "Invalid upload", f"Send a multipart form with up to {max_files} file(s) "
                                              f"in the field 'file'.")
            return _result(request, *failure)

        uploads = [value for _, value in form.multi_items() if isinstance(value, UploadFile)]
        if not uploads:
            failure = (400, "No file received", "Choose a file to upload.")
            return _result(request, *failure)

        total = 0
        files_dir = os.path.join(ticket_dir, _FILES_DIR)
        os.makedirs(files_dir, mode=0o700, exist_ok=True)
        for upload in uploads:
            name = _safe_filename(upload.filename)
            ext = os.path.splitext(name)[1].lstrip(".").lower()
            # Any extension passes when the purpose has no list, but one is always required
            if not ext or (extensions and ext not in extensions):
                allowed = ", ".join(sorted(extensions)) if extensions else "any file with an extension"
                failure = (415, "Unsupported file type",
                           f"'{name or upload.filename}' is not a supported file. Allowed: {allowed}.")
                return _result(request, *failure)
            # Two files with one name would overwrite each other
            taken = {f["name"] for f in staged}
            index = 2
            unique = name
            while unique in taken:
                unique = f"{os.path.splitext(name)[0]} ({index}).{ext}"
                index += 1

            size = 0
            with open(os.path.join(files_dir, unique), "wb") as out:
                while chunk := await upload.read(_CHUNK_BYTES):
                    size += len(chunk)
                    total += len(chunk)
                    if total > max_bytes:
                        failure = (413, "File too large", f"Uploads are limited to {max_mb} MB in total.")
                        break
                    out.write(chunk)
            if failure:
                return _result(request, *failure)
            if not size:
                failure = (400, "Empty file", f"'{unique}' is empty.")
                return _result(request, *failure)
            staged.append({"name": unique, "size": size})

        meta.update(status="uploaded", files=staged, expires=int(time.time() + UPLOAD_STAGED_TTL_SECONDS))
        _write_meta(ticket_dir, meta)
    except BaseException:
        # e.g. a client disconnect, a cancelled request or a full disk: free the link rather than leave it locked
        failure = (500, "Upload failed", "The upload could not be saved.")
        raise
    finally:
        if form is not None:
            await form.close()
        # A rejected upload frees the link for another try
        if failure:
            _clear_files(ticket_dir)
            try:
                os.unlink(os.path.join(ticket_dir, _LOCK_FILE))
            except OSError:
                pass

    names = [f["name"] for f in staged]
    tool = UPLOAD_CONSUMER_TOOLS[meta["purpose"]]
    logger.info(f"upload_files: staged {len(staged)} file(s) under {upload_id[:6]}…")
    if _wants_html(request):
        return _page("Upload complete", f"<p>Received {escape(', '.join(names))}.</p>"
                     "<p>Go back to your assistant and tell it the upload is done. You can close this tab.</p>")
    return JSONResponse({
        "status": "OK",
        "upload_id": upload_id,
        "files": staged,
        "next_step": f"Call {tool} with upload_id='{upload_id}' to add the file(s) to Bugasura.",
    }, headers={"Cache-Control": "no-store"})
