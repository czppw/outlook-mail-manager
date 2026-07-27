"""Sanitize untrusted email HTML before rendering it in a sandboxed iframe."""

import bleach

_ALLOWED_TAGS = [
    "a",
    "abbr",
    "address",
    "article",
    "b",
    "blockquote",
    "br",
    "caption",
    "code",
    "col",
    "colgroup",
    "dd",
    "del",
    "details",
    "div",
    "dl",
    "dt",
    "em",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "i",
    "ins",
    "kbd",
    "li",
    "main",
    "ol",
    "p",
    "pre",
    "q",
    "s",
    "section",
    "small",
    "span",
    "strong",
    "sub",
    "summary",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
]
_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "abbr": ["title"],
    "td": ["colspan", "rowspan"],
    "th": ["colspan", "rowspan"],
    "col": ["span"],
    "colgroup": ["span"],
}
_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; img-src data: cid:; media-src 'none'; "
    "style-src 'unsafe-inline'; font-src 'none'; form-action 'none'; base-uri 'none'"
)


def sanitize_email_html(value: str) -> str:
    cleaned = bleach.clean(
        value or "",
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        protocols=["http", "https", "mailto"],
        strip=True,
        strip_comments=True,
    )
    meta = (
        '<meta http-equiv="Content-Security-Policy" '
        f'content="{_CONTENT_SECURITY_POLICY}">'
        '<meta name="referrer" content="no-referrer">'
    )
    return meta + cleaned
