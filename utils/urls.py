"""Fetching caller-supplied URLs: http(s) only, internal addresses blocked, redirects re-checked."""
import ipaddress, os, re, shutil, socket, tempfile, urllib.parse, urllib.request
from typing import Optional

from config.config import CDN_BASE_URL
from utils.client import in_http_request


# Schemes the file-fetch helpers below may open. urllib's default opener also handles
# file://, ftp:// and data:, so an unguarded urlopen() would turn a caller-supplied
# `source_url` into an arbitrary local-file read — the bytes are uploaded to Bugasura,
# and the extension check upstream only ever sees the *display* filename, not the URL.
_FETCHABLE_URL_SCHEMES = ('http', 'https')


def require_fetchable_url(url: str) -> None:
    """Raise ValueError unless `url` is an http(s) URL with a host.

    Every helper that opens a caller-supplied URL calls this first. Callers already
    wrap these helpers in `except Exception` and surface the message, so a ValueError
    here reaches the user as a normal actionable failure.
    """
    try:
        parsed = urllib.parse.urlparse(url or '')
    except Exception:
        raise ValueError(f"'{url}' is not a valid URL.")
    scheme = (parsed.scheme or '').lower()
    if scheme not in _FETCHABLE_URL_SCHEMES:
        raise ValueError(
            f"Only http:// and https:// links can be fetched, but this one uses "
            f"'{scheme or 'no'}' scheme. Ask the user for a shareable https link "
            f"(Google Drive, Dropbox, or any public download URL). Local paths belong "
            f"in file_paths, not source_url."
        )
    if not parsed.netloc or not parsed.hostname:
        raise ValueError(f"'{url}' has no host — it is not a fetchable link.")
    # Over HTTP the server sits inside our network; never let a caller reach it (SSRF).
    if in_http_request():
        _reject_internal_host(parsed.hostname, parsed.port or (443 if scheme == 'https' else 80))


def _reject_internal_host(host: str, port: int) -> None:
    """Raise ValueError when `host` resolves to a loopback, private, link-local or reserved address."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"Could not resolve the host '{host}'. Check the link and try again.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%', 1)[0])
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            raise ValueError(
                f"'{host}' points to a private or internal address, which this server will not "
                f"fetch. Ask the user for a public https link (Google Drive, Dropbox, or any "
                f"public download URL)."
            )


class _CheckedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Apply the same URL checks to every redirect hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require_fetchable_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# Only http(s) handlers plus the checked redirect handler; no file://, ftp:// or data:.
URL_OPENER = urllib.request.OpenerDirector()
for _handler in (urllib.request.ProxyHandler(), urllib.request.HTTPHandler(),
                 urllib.request.HTTPSHandler(), _CheckedRedirectHandler(),
                 urllib.request.HTTPErrorProcessor(), urllib.request.HTTPDefaultErrorHandler()):
    URL_OPENER.add_handler(_handler)


def normalise_share_url(url: str) -> str:
    """Convert well-known sharing URLs to direct download URLs.

    Handles Google Drive share links and Dropbox share links.
    All other URLs are returned unchanged.
    """
    # Google Drive: https://drive.google.com/file/d/FILE_ID/view?...
    #           or: https://drive.google.com/open?id=FILE_ID
    # confirm=t skips Drive's virus-scan page for files over ~100 MB
    drive_download = 'https://drive.usercontent.google.com/download?id={}&export=download&confirm=t'
    parsed = urllib.parse.urlparse(url)
    if 'drive.google.com' in parsed.netloc:
        # /file/d/FILE_ID/... form
        parts = parsed.path.split('/')
        try:
            file_id = parts[parts.index('d') + 1]
            return drive_download.format(file_id)
        except (ValueError, IndexError):
            pass
        # ?id=FILE_ID form
        qs = urllib.parse.parse_qs(parsed.query)
        if 'id' in qs:
            return drive_download.format(qs['id'][0])
    # Dropbox: replace dl=0 with dl=1 (or add dl=1)
    if 'dropbox.com' in parsed.netloc:
        qs = urllib.parse.parse_qs(parsed.query)
        qs['dl'] = ['1']
        new_query = urllib.parse.urlencode({k: v[0] for k, v in qs.items()})
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    return url


def infer_filename_from_url_path(url: str) -> Optional[str]:
    """Extract a filename from the URL path if it looks like a real file.

    Works for Dropbox-style URLs where the filename is in the path.
    Returns None for Google Drive and other URLs where there is no filename.
    """
    try:
        path = urllib.parse.urlparse(url).path.rstrip('/')
        if not path:
            return None
        basename = urllib.parse.unquote(path.split('/')[-1])
        # Only accept if it has a recognisable extension.
        if '.' in basename and not basename.startswith('.'):
            return basename
    except Exception:
        pass
    return None


def download_url_tmp(url: str, suffix: str, timeout: int = 30,
                      max_bytes: Optional[int] = None) -> tuple:
    """Download a URL to a delete=False temp file; return (path, inferred_filename_or_None).

    Streams the response in 64 KB chunks to avoid loading the whole file into
    memory. Extracts the filename from the Content-Disposition response header
    when available (works for Google Drive and similar services). Cleans up the
    temp file if the download fails before the path is returned.

    `max_bytes` aborts the transfer as soon as the response passes the cap, so an
    oversized link is rejected without filling the temp directory first — the
    callers' own size checks can only run once the whole file is already on disk.
    Only http(s) URLs are accepted; see require_fetchable_url.
    Raises: ValueError on a rejected URL or an oversized response;
            urllib.error.URLError / urllib.error.HTTPError / OSError on failure.
    """
    require_fetchable_url(url)
    req = urllib.request.Request(url, headers={'User-Agent': 'BugasuraMCP/1.0'})
    tmp = tempfile.NamedTemporaryFile(mode='wb', suffix=suffix, delete=False)
    inferred_name: Optional[str] = None
    try:
        with URL_OPENER.open(req, timeout=timeout) as resp:
            cd = resp.headers.get('Content-Disposition', '')
            if cd:
                m = re.search(r'filename[^;=\n]*=[\s"\']*([^;"\']+)[\s"\']*', cd, re.IGNORECASE)
                if m:
                    candidate = urllib.parse.unquote(m.group(1).strip('" \''))
                    if '.' in candidate:
                        inferred_name = candidate
            # A web page (sign-in, preview, quota error) where a file was expected must not be saved as the file.
            # Bugasura's own CDN is exempt: it labels stored files by sniffing them, so a .txt can be text/html
            if (resp.headers.get_content_type() == 'text/html' and not _on_bugasura_cdn(url)
                    and not suffix.lower().endswith(('.html', '.htm'))
                    and not (inferred_name or '').lower().endswith(('.html', '.htm'))):
                raise ValueError("the link returned a web page instead of the file — it may be private, "
                                 "need a sign-in, or not be a direct download link")
            written = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if max_bytes is not None and written > max_bytes:
                    limit = (f"{max_bytes / (1024 * 1024):.0f}MB" if max_bytes >= 1024 * 1024
                             else f"{max_bytes / 1024:.0f}KB")
                    raise ValueError(
                        f"The file at this link is larger than {limit}, so the download was "
                        f"stopped. Ask the user for a smaller file."
                    )
                tmp.write(chunk)
    except Exception:
        tmp.close()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    tmp.close()
    return tmp.name, inferred_name


def fetch_url_bytes(url: str, max_bytes: int, timeout: int = 30) -> tuple:
    """Read a URL into memory; return (content, exceeded_limit).

    Stops reading once max_bytes has been passed and reports it through the
    second element, so an oversized file is detected without ever buffering
    the whole thing. `content` is truncated in that case and must not be
    treated as the complete file.
    Only http(s) URLs are accepted; see require_fetchable_url.
    Raises: ValueError on a rejected URL;
            urllib.error.URLError / urllib.error.HTTPError / OSError on failure.
    """
    require_fetchable_url(url)
    req = urllib.request.Request(url, headers={'User-Agent': 'BugasuraMCP/1.0'})
    with URL_OPENER.open(req, timeout=timeout) as resp:
        # One byte past the cap is enough to tell "at the limit" from "over it".
        content = resp.read(max_bytes + 1)
    if len(content) > max_bytes:
        return content[:max_bytes], True
    return content, False


def _on_bugasura_cdn(url: str) -> bool:
    """True when `url` points at the CDN that serves files stored in Bugasura."""
    cdn_host = urllib.parse.urlparse(CDN_BASE_URL).netloc.lower() if CDN_BASE_URL else ''
    return bool(cdn_host) and urllib.parse.urlparse(url).netloc.lower() == cdn_host


def download_url_to_path(url: str, dest_path: str, timeout: int = 60,
                          max_bytes: Optional[int] = None) -> int:
    """Download a URL onto the local filesystem at dest_path; return the byte size.

    Streams through download_url_tmp() so the transfer never buffers the whole
    file in memory, then moves the temp file into place — shutil.move rather than
    os.replace, since the temp directory is often on a different filesystem. The
    destination is only written once the download has fully succeeded, and the temp
    file is removed if the move itself fails.

    The http(s)-only guard and the optional `max_bytes` cap are inherited from
    download_url_tmp, so nothing lands on disk from a rejected or oversized URL.
    Raises: ValueError on a rejected URL or an oversized response;
            urllib.error.URLError / urllib.error.HTTPError / OSError on failure.
    """
    suffix = os.path.splitext(dest_path)[1] or '.tmp'
    tmp_path, _ = download_url_tmp(url, suffix, timeout, max_bytes)
    try:
        shutil.move(tmp_path, dest_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return os.path.getsize(dest_path)
