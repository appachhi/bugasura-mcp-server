"""Response formatting: markdown rendering, pagination envelopes, and response sanitising."""
import json
from typing import Any, Optional

from config.config import SECRET_RESPONSE_KEYS, logger


# Keys stripped from the upstream response before merging "extras" into the
# pagination envelope — they either describe the envelope itself or are
# rewritten by paginated().
_PAGINATION_META_KEYS = {'total_rows', 'total', 'count', 'nrows',
                         'start_at', 'max_results', 'items', 'has_more',
                         'next_offset', 'offset'}


def _render_markdown(data: Any, title: Optional[str] = None) -> str:
    """
    Render a tool response dict as a human-readable markdown string.

    Keeps the rendering simple and generic — structured for agent readability
    rather than reproducing every upstream field. Error responses (status != 'OK')
    render as an Error block. Pagination envelopes render a summary plus the first
    page of items.
    """
    if isinstance(data, str):
        return data
    if not isinstance(data, dict):
        return f"```\n{data}\n```"

    lines: list = []
    if title:
        lines.append(f"# {title}")
        lines.append("")

    status = data.get('status')
    if status and status != 'OK':
        lines.append(f"**Status:** `{status}`")
        for k in ('error', 'error_type', 'message', 'action', 'help',
                 'step', 'instruction'):
            if k in data and data[k]:
                lines.append(f"- **{k}:** {data[k]}")
        if 'options' in data and isinstance(data['options'], list):
            lines.append("")
            lines.append(f"**Options ({len(data['options'])}):**")
            for opt in data['options'][:20]:
                if isinstance(opt, dict):
                    ident = opt.get('team_id') or opt.get('project_id') or opt.get('issue_id') or opt.get('id') or '?'
                    name = opt.get('team_name') or opt.get('project_name') or opt.get('summary') or opt.get('name') or ''
                    lines.append(f"- `{ident}` — {name}")
        return "\n".join(lines) if lines else json.dumps(data, indent=2)

    # Pagination envelope
    if 'items' in data and isinstance(data['items'], list):
        total = data.get('total', len(data['items']))
        offset = data.get('offset', 0)
        has_more = data.get('has_more', False)
        lines.append(f"**{len(data['items'])} of {total}** (offset {offset}{', more available' if has_more else ''})")
        lines.append("")
        shown = data['items'][:50]
        if len(data['items']) > len(shown):
            lines.append(f"_Showing the first {len(shown)} rows of this page; request JSON or a smaller max_results to see the rest._")
            lines.append("")
        for item in shown:
            if isinstance(item, dict):
                ident = (item.get('issue_id') or item.get('issue_key') or
                         item.get('project_id') or item.get('team_id') or
                         item.get('sprint_id') or item.get('testcase_id') or
                         item.get('requirement_id') or item.get('kb_id') or
                         item.get('page_id') or item.get('doc_id') or
                         item.get('space_key') or item.get('project_key') or
                         item.get('run_id') or item.get('id') or item.get('folder_id') or '?')
                name = (item.get('summary') or item.get('project_name') or
                        item.get('team_name') or item.get('sprint_name') or
                        item.get('doc_name') or item.get('page_name') or
                        item.get('page_title') or item.get('space_name') or
                        item.get('name') or item.get('title') or
                        item.get('run_name') or item.get('folder_name') or '')
                extras = []
                for fk in ('bug_status', 'status', 'severity', 'priority',
                           'platform', 'assignees'):
                    if item.get(fk):
                        extras.append(f"{fk}={item[fk]}")
                line = f"- `{ident}`"
                if name:
                    line += f" {name}"
                if extras:
                    line += f" — {' | '.join(extras)}"
                lines.append(line)
            else:
                lines.append(f"- {item}")
        return "\n".join(lines)

    # Generic detail view: key-value dump, skipping verbose/null fields
    for k, v in data.items():
        if v is None or v == '' or k in ('status',):
            continue
        if isinstance(v, (dict, list)) and len(str(v)) > 400:
            lines.append(f"- **{k}**: _(collapsed — {len(v) if hasattr(v, '__len__') else '?'} entries)_")
        else:
            lines.append(f"- **{k}**: {v}")
    return "\n".join(lines) if lines else json.dumps(data, indent=2)


def respond(data: Any, response_format: str = "json") -> Any:
    """
    Finalize a tool response.

    - response_format='json'     → pass the dict through unchanged.
    - response_format='markdown' → wrap the rendered markdown in a dict so it
      still satisfies FastMCP's structured-content output schema.

    Tools annotate their return type as `dict`, which causes FastMCP to build
    an output_schema expecting structured content; returning a bare string
    would fail that validation ("structured_content must be a dict or None").
    Wrapping the markdown under a `markdown` key keeps the envelope structured
    while surfacing the human-readable rendering to agents.
    """
    if response_format == 'markdown':
        rendered = _render_markdown(data)
        status = data.get('status') if isinstance(data, dict) else 'OK'
        return {'status': status or 'OK', 'markdown': rendered}
    return data


def display_team_name(team: dict) -> Optional[str]:
    """
    Bugasura's team display-name rule: a team still on its default name is shown
    as "... Projects". Mirrors the backend's own normalisation so every tool
    renders the same name the web app does.

    Accepts rows from either /v1/teams/get ('name'/'alias') or /v1/teams/getApps
    ('team_name'/'team_alias_name').
    """
    name = team.get('name') if team.get('name') is not None else team.get('team_name')
    if name is None:
        return None
    alias = team.get('alias') or team.get('team_alias_name') or ''
    if name == alias or name == 'My Apps':
        return name.replace(' Apps', ' Projects')
    return name


def paginated(items: list, total: Optional[int] = None, offset: int = 0,
               max_results: Optional[int] = None, **extras) -> dict:
    """
    Wrap a page of items in the standard pagination envelope (mcp-builder §Pagination).

    Returns:
        {
            'status': 'OK',
            'total':       int,        # total items matching the query
            'count':       int,        # items in this response
            'offset':      int,        # echo of start_at
            'items':       list,       # the page contents
            'has_more':    bool,
            'next_offset': int | None
        }
    Extra keyword arguments are merged at the top level (e.g. 'message',
    legacy keys such as 'project_list' for backwards compatibility).
    """
    count = len(items)
    if total is None:
        # Unknown upstream total: a full page may have more behind it; total is then a lower bound
        total = count + offset
        has_more = bool(max_results) and count >= max_results
    else:
        has_more = (offset + count) < total
    next_offset = offset + count if has_more else None
    envelope = {
        'status': 'OK',
        'total': total,
        'count': count,
        'offset': offset,
        'items': items,
        'has_more': has_more,
        'next_offset': next_offset,
    }
    envelope.update(extras)
    return envelope


def paginate_upstream(upstream: dict, items_key: Optional[str] = None,
                       offset: int = 0, max_results: Optional[int] = None,
                       local: bool = False) -> dict:
    """
    Wrap a Bugasura upstream list response in the standard pagination envelope.

    items_key: name of the field carrying the list (e.g. 'project_list', 'comment_list').
               If None, the first list-valued field is used.
    local:     the endpoint returns everything; slice [offset:offset+max_results] here.
    Non-OK upstream responses pass through unchanged.
    """
    if not isinstance(upstream, dict) or upstream.get('status') != 'OK':
        return upstream
    if items_key is None:
        for k, v in upstream.items():
            if isinstance(v, list):
                items_key = k
                break
    if items_key is None:
        return upstream
    items = upstream.get(items_key)
    if not isinstance(items, list):
        return upstream
    total = (upstream.get('total_rows')
             or upstream.get('nrows')
             or upstream.get('total')
             or upstream.get('count'))
    if local:
        total = len(items)
        items = items[offset:offset + max_results] if max_results else items[offset:]
    extras = {k: v for k, v in upstream.items()
              if k not in _PAGINATION_META_KEYS
              and k != items_key
              and k != 'status'}
    return paginated(items, total=total, offset=offset, max_results=max_results, **extras)


def filter_large_fields(data: dict) -> dict:
    """
    Remove large unnecessary fields from API responses to reduce payload size.

    Fields removed:
    - tools_integration_settings: Large JSON containing integration configs
      (can be 100KB+, not needed by MCP clients)
    - tools_mapped_fields: Integration field mappings (also large)

    This function recursively processes nested structures (lists and dicts).
    """
    if not isinstance(data, dict):
        return data

    # Fields to remove from responses
    fields_to_remove = ['tools_integration_settings', 'tools_mapped_fields']

    # Create a new dict without the large fields
    filtered = {}
    for key, value in data.items():
        if key in fields_to_remove:
            logger.debug(f"Filtered out large field: {key}")
            continue

        # Recursively filter nested dicts
        if isinstance(value, dict):
            filtered[key] = filter_large_fields(value)
        # Recursively filter lists of dicts
        elif isinstance(value, list):
            filtered[key] = [filter_large_fields(item) if isinstance(item, dict) else item for item in value]
        else:
            filtered[key] = value

    return filtered


def redact_secrets(data):
    """Return a copy of data with every credential-named key masked, at any depth (JSON-object strings included)."""
    if isinstance(data, str) and data.lstrip().startswith('{'):
        try:
            return json.dumps(redact_secrets(json.loads(data)))
        except ValueError:
            return data
    if isinstance(data, dict):
        return {k: ('[REDACTED]' if str(k).lower() in SECRET_RESPONSE_KEYS and v not in (None, '')
                    else redact_secrets(v))
                for k, v in data.items()}
    if isinstance(data, list):
        return [redact_secrets(item) for item in data]
    return data
