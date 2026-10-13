"""Attachments: open files from an upload link or local paths and stream them to the API."""
import mimetypes, os
from typing import Optional

from config.config import ATTACHMENT_MAX_FILE_SIZE_MB, logger
from core.uploads import claim, discard, release, staged_paths
from utils.auth import current_user_id
from utils.client import UPLOAD_TIMEOUT, make_api_request
from utils.files import local_path_rejected

# Shared Field descriptions for the attachment parameters of the issue/comment/requirement tools
ATTACH_UPLOAD_ID_DESCRIPTION = (
    "upload_id from bugasura_create_upload_link(purpose='attachment'), once the user has uploaded the "
    "file(s) to its link — the way to attach a file from the user's own computer on the hosted server. "
    "Never read or encode the file yourself.")
ATTACH_FILE_PATHS_DESCRIPTION = (
    "Absolute paths of files to attach on the machine running this server (local STDIO servers only; "
    "rejected on the hosted server). Ask the user for the exact path — never guess it.")


def close_upload_files(files: list) -> None:
    """Close the file handles in multipart fields built for an upload."""
    for _field, (_name, file_handle, _content_type) in files:
        file_handle.close()


# Comment kind -> (comments endpoint prefix, item id param) for /v1/{testcase,requirement}comments/*
_PROJECT_COMMENT_KINDS = {
    'testcase': ('/v1/testcasecomments', 'testCaseId'),
    'requirement': ('/v1/requirementcomments', 'requirementId'),
}


def attachment_names_csv(names: Optional[str]) -> Optional[str]:
    """A comma-separated filename list without the spaces the API would treat as part of a name."""
    if names is None:
        return None
    return ','.join(name.strip() for name in names.split(',') if name.strip())


async def project_comment_attachment_names(api_key: str, kind: str, team_id: int, project_id: int,
                                           item_id: int, comment_id: int,
                                           report_id: Optional[int] = None) -> Optional[str]:
    """
    A test case / requirement comment's attachment filenames as the update endpoint's CSV.

    Their update endpoint treats a missing attachment list as "keep none" and deletes the files,
    so an update that was not given one must resend this. None when the comment is unreadable.
    A test case comment posted in a sprint needs its report_id: without one the API only looks
    at comments made outside any sprint.
    """
    endpoint, id_param = _PROJECT_COMMENT_KINDS[kind]
    params = {'teamId': team_id, 'team_id': team_id, 'appId': project_id, 'app_id': project_id,
              id_param: item_id, 'commentId': comment_id}
    if report_id is not None:
        params.update(reportId=report_id, report_id=report_id)
    response = await make_api_request('GET', f'{endpoint}/get', api_key, params=params)
    if response.get('status') != 'OK':
        return None
    details = response.get('commentDetails')
    rows = details if isinstance(details, list) else [details] if isinstance(details, dict) else []
    row = next((r for r in rows if str(r.get('comment_id')) == str(comment_id)), None)
    if row is None:
        return None
    return attachment_names_csv(row.get('comment_attachments') or '')


async def send_with_attachments(method: str, endpoint: str, api_key: str, opened: dict,
                                upload_id: Optional[str], **kwargs) -> dict:
    """
    Make the API call with the files from `open_attachments` (streamed), then close them.

    On success the response gains `attached_files` and the upload link's staged files are
    deleted; on failure they are kept so the call can be retried with the same upload_id.
    """
    files = opened.get('files') or []
    if files:
        kwargs.update(files=files, timeout=UPLOAD_TIMEOUT)
    if files and upload_id and (busy := claim(upload_id)):
        close_upload_files(files)
        return busy
    succeeded = False
    try:
        response = await make_api_request(method, endpoint, api_key, **kwargs)
        succeeded = files and isinstance(response, dict) and response.get('status') == 'OK'
    finally:
        close_upload_files(files)
        if files and upload_id:
            discard(upload_id) if succeeded else release(upload_id)
    if succeeded:
        _report_skipped_attachments(response, opened['filenames'])
    return response


def _report_skipped_attachments(response: dict, filenames: list) -> None:
    """Set `attached_files`, leaving out files the API reported skipping (size or count limits).

    The API still answers OK when it skips files: issues list the reasons in `errorMessage`,
    requirements append them to `message`.
    """
    errors = response.get('errorMessage') or []
    errors = [str(e) for e in (errors if isinstance(errors, list) else [errors]) if e]
    message = str(response.get('message') or '')
    if 'error while uploading' in message.lower():
        errors.append(message)
    skipped = [name for name in filenames if any(name in error for error in errors)]
    response['attached_files'] = [name for name in filenames if name not in skipped]
    if errors:
        response['not_attached'] = skipped
        response['attachment_errors'] = errors
        response['warning'] = ("Bugasura did not store every file: " + "; ".join(errors) + ". Tell the user which "
                               "files were not attached; the plan's attachment size limit may be lower than the "
                               "MCP's. The upload link is used up, so a new one is needed to try those files again.")


def open_attachments(file_paths: Optional[list], upload_id: Optional[str]) -> dict:
    """
    Open the files to attach: an upload link's staged files, or local paths (STDIO only).

    Each file becomes its own multipart field (file0, file1, …), the shape every attachment
    endpoint accepts; the handles are streamed by httpx. Neither source given -> no files.
    The caller closes them with `close_upload_files` and discards `upload_id` on success.

    Returns:
        dict: {'status': 'OK', 'files': [(field, (filename, file_handle, content_type))],
               'filenames': [str]} or a failure envelope.
    """
    if file_paths and upload_id:
        return {'status': 'failed', 'error': 'Multiple file sources provided', 'error_type': 'ValidationError',
                'message': 'Provide either upload_id or file_paths, not both.'}
    if file_paths and (rejected := local_path_rejected('file_paths')):
        return rejected
    paths = list(file_paths or [])
    if upload_id:
        staged = staged_paths(upload_id, current_user_id(), 'attachment')
        if staged.get('status') != 'OK':
            return staged
        paths = staged['paths']

    files, filenames = [], []
    succeeded = False
    try:
        for index, path in enumerate(paths):
            name = os.path.basename(path)
            if not os.path.isfile(path):
                if upload_id:
                    return {'status': 'failed', 'error': 'Uploaded file unavailable', 'error_type': 'ValidationError',
                            'message': ("The uploaded file is no longer available. Create a new link with "
                                        "bugasura_create_upload_link(purpose='attachment') and ask the user to "
                                        "upload it again.")}
                return {'status': 'failed', 'error': f'File not found: {path}', 'error_type': 'ValidationError',
                        'message': f"Could not find a readable file at '{path}'. Ask the user for the exact absolute path."}
            if not os.path.splitext(name)[1]:
                return {'status': 'failed', 'error': 'Missing file extension', 'error_type': 'ValidationError',
                        'message': f"'{name}' has no file extension; Bugasura needs one to store an attachment."}
            size = os.path.getsize(path)
            if size > ATTACHMENT_MAX_FILE_SIZE_MB * 1024 * 1024:
                return {'status': 'failed', 'error': 'File too large', 'error_type': 'ValidationError',
                        'message': (f"'{name}' is {size / (1024 * 1024):.1f}MB. Attachments are limited to "
                                    f"{ATTACHMENT_MAX_FILE_SIZE_MB}MB each.")}
            content_type = mimetypes.guess_type(name)[0] or 'application/octet-stream'
            files.append((f"file{index}", (name, open(path, 'rb'), content_type)))
            filenames.append(name)
        succeeded = True
        return {'status': 'OK', 'files': files, 'filenames': filenames}
    except OSError as e:
        logger.error(f"open_attachments: could not open '{path}': {e}")
        return {'status': 'failed', 'error': 'Could not read file', 'error_type': 'IOError',
                'message': f"Could not read '{os.path.basename(path)}'."}
    finally:
        if not succeeded:
            close_upload_files(files)
