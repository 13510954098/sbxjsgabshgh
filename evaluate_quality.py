#!/usr/bin/env python3

"""Conservative Animeko online-source quality evaluator.

It borrows Animeko's layered datasource-test methodology while deliberately
stopping short of browser/JavaScript execution or third-party program execution.
The highest automated result is therefore "static transport verified", not proof
that a real player decoded frames successfully.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit
import unittest
from unittest import mock

import update_sources as updater

SCHEMA_VERSION = 1
MAX_INPUT_SIZE = 25 * 1024 * 1024
MAX_STATE_SIZE = 5 * 1024 * 1024
MAX_REPORT_SIZE = 10 * 1024 * 1024
MAX_STATE_SOURCES = 1000
MAX_HISTORY = 6
MAX_BODY_BYTES = 1024 * 1024
MAX_PLAYLIST_BYTES = 512 * 1024
MAX_SEGMENT_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 6 * 1024 * 1024
MAX_REDIRECTS = 5
MAX_SUBJECTS = 40
MAX_EPISODES = 100
MAX_PLAY_PAGES = 3
REQUEST_DEADLINE = 25
MIN_REQUEST_GAP_SECONDS = 0.75
MAX_CONFIG_REQUEST_GAP_SECONDS = 5.0
QUALITY_TEST_QUERIES = ("名侦探柯南", "葬送的芙莉莲", "进击的巨人", "海贼王")
H_QUALITY_TEST_QUERIES = ("OVA", "無修正", "里番")
MEDIA_SUFFIXES = (".m3u8", ".mp4", ".mkv", ".flv", ".webm", ".ts")
MEDIA_URL_MARKERS = (
    "akamaized", "bilivideo.com", "mime_type=video", "/video/tos/", "sign.bytetos",
    "sign.byteimg", "cloudflarestorage", "mcloud.139",
)
NESTED_URL_MARKERS = ("player", "play", "vip", "parse", "xigua.php", "index.php")
URL_RE = re.compile(r"https?:(?:\\?/){2}[^\s\"'<>]+", re.IGNORECASE)
CSS_IDENT_RE = re.compile(r"[-_a-zA-Z][-_a-zA-Z0-9]*")
CHALLENGE_MARKERS = (
    "cf-chl-", "challenge-platform", "turnstile", "just a moment", "captcha", "验证码",
    "人机验证", "访问验证", "security check",
)
VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
})
ALLOWED_REQUEST_HEADERS = frozenset({"user-agent", "referer", "cookie", "range", "accept"})


class QualityError(RuntimeError):
    pass


def bounded_text(value, limit: int = 500) -> str:
    text = str(value).replace("\x00", "").strip()
    return text[:limit]


def sha256_json(value) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def source_identity(item: dict) -> str:
    args = item.get("arguments") or {}
    search = args.get("searchConfig") or {}
    raw = [item.get("factoryId"), args.get("name"), search.get("searchUrl")]
    return sha256_json(raw)[:24]


def config_fingerprint(item: dict) -> str:
    return sha256_json(item)


def redact_url(value: str | None) -> str | None:
    if not value:
        return value
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        netloc = host if port in (None, 80, 443) else f"{host}:{port}"
        query = "<redacted>" if parsed.query else ""
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, query, ""))
    except (TypeError, ValueError):
        return "<invalid-url>"


def root_site(host: str) -> str:
    parts = host.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower().rstrip(".")


def validate_target_url(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError):
        return "invalid-url"
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not host:
        return "bad-scheme-or-host"
    if parsed.username is not None or parsed.password is not None:
        return "userinfo"
    if port not in (None, 80, 443):
        return "non-default-port"
    if updater.is_literal_private_host(host):
        return "private-host"
    return None


@dataclass
class FetchResult:
    ok: bool
    url: str
    status: int | None = None
    data: bytes = b""
    content_type: str | None = None
    latency_ms: int | None = None
    error: str | None = None
    redirects: list[str] = field(default_factory=list)


class SafeFetcher:
    """HTTP GET with updater's DNS/IP pinning and strict per-source budgets."""

    def __init__(self, request_gap_ms: int = 0):
        self.bytes_read = 0
        self.last_request_by_host: dict[str, float] = {}
        configured = max(0.0, min(request_gap_ms / 1000.0, MAX_CONFIG_REQUEST_GAP_SECONDS))
        self.request_gap = max(MIN_REQUEST_GAP_SECONDS, configured)

    def fetch(self, url: str, *, headers: dict[str, str] | None = None,
              max_bytes: int = MAX_BODY_BYTES, range_probe: bool = False) -> FetchResult:
        started = time.monotonic()
        current = url
        redirects: list[str] = []
        request_headers = self._clean_headers(headers or {})
        if range_probe:
            request_headers["Range"] = "bytes=0-65535"
        for _ in range(MAX_REDIRECTS + 1):
            static_error = validate_target_url(current)
            if static_error:
                return self._failure(current, started, static_error, redirects)
            parsed = urlsplit(current)
            host = (parsed.hostname or "").lower().rstrip(".")
            self._wait_for_host(host)
            deadline = time.monotonic() + REQUEST_DEADLINE
            safety_error, pinned_ip = updater.check_url_safety(current, deadline)
            if safety_error:
                return self._failure(current, started, safety_error, redirects)
            session = updater.get_pinned_session(host, pinned_ip)
            try:
                remaining = max(0.001, deadline - time.monotonic())
                with session.get(
                    current,
                    headers=request_headers,
                    timeout=(min(5, remaining), min(20, remaining)),
                    allow_redirects=False,
                    stream=True,
                ) as response:
                    self.last_request_by_host[host] = time.monotonic()
                    status = response.status_code
                    if status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location")
                        if not location:
                            return self._failure(current, started, "redirect-without-location", redirects,
                                                 status)
                        redirects.append(redact_url(current) or "")
                        next_url = urljoin(current, location)
                        if urlsplit(current).scheme == "https" and urlsplit(next_url).scheme != "https":
                            return self._failure(next_url, started, "redirect-downgrade", redirects, status)
                        if root_site(urlsplit(next_url).hostname or "") != root_site(host):
                            request_headers.pop("Cookie", None)
                        current = next_url
                        continue
                    if status < 200 or status >= 300:
                        return self._failure(current, started, f"http-{status}", redirects, status)
                    content_length = response.headers.get("Content-Length")
                    if content_length and content_length.isdigit() and int(content_length) > max_bytes * 16:
                        return self._failure(current, started, "too-large-header", redirects, status)
                    remaining_budget = MAX_SOURCE_BYTES - self.bytes_read
                    allowed = min(max_bytes, remaining_budget)
                    if allowed <= 0:
                        return self._failure(current, started, "source-byte-budget", redirects, status)
                    chunks = []
                    size = 0
                    for chunk in response.iter_content(32 * 1024):
                        if not chunk:
                            continue
                        room = allowed - size
                        if room <= 0:
                            break
                        chunks.append(chunk[:room])
                        size += min(len(chunk), room)
                        if size >= allowed:
                            break
                    self.bytes_read += size
                    data = b"".join(chunks)
                    if not data:
                        return self._failure(current, started, "empty", redirects, status)
                    return FetchResult(
                        ok=True,
                        url=redact_url(response.url) or "",
                        status=status,
                        data=data,
                        content_type=response.headers.get("Content-Type"),
                        latency_ms=round((time.monotonic() - started) * 1000),
                        redirects=redirects,
                    )
            except Exception as exc:
                self.last_request_by_host[host] = time.monotonic()
                return self._failure(current, started, f"{type(exc).__name__}", redirects)
        return self._failure(current, started, "too-many-redirects", redirects)

    def _wait_for_host(self, host: str):
        previous = self.last_request_by_host.get(host)
        if previous is None:
            return
        wait = self.request_gap - (time.monotonic() - previous)
        if wait > 0:
            time.sleep(wait)

    @staticmethod
    def _clean_headers(headers: dict[str, str]) -> dict[str, str]:
        cleaned = {"User-Agent": updater.UA_DEFAULT, "Accept": "*/*"}
        for key, value in headers.items():
            if (not isinstance(key, str) or not isinstance(value, str)
                    or key.lower() not in ALLOWED_REQUEST_HEADERS or len(value) > 4096
                    or "\r" in value or "\n" in value):
                continue
            cleaned["-".join(part.capitalize() for part in key.split("-"))] = value
        return cleaned

    @staticmethod
    def _failure(url: str, started: float, error: str, redirects: list[str],
                 status: int | None = None) -> FetchResult:
        return FetchResult(
            ok=False,
            url=redact_url(url) or "",
            status=status,
            latency_ms=round((time.monotonic() - started) * 1000),
            error=bounded_text(error, 120),
            redirects=redirects,
        )


class HtmlNode:
    __slots__ = ("tag", "attrs", "parent", "children", "parts")

    def __init__(self, tag: str, attrs=None, parent: "HtmlNode | None" = None):
        self.tag = tag.lower()
        self.attrs = {str(k).lower(): ("" if v is None else str(v)) for k, v in (attrs or [])}
        self.parent = parent
        self.children: list[HtmlNode] = []
        self.parts: list[str] = []

    def text(self) -> str:
        values = list(self.parts)
        for child in self.children:
            values.append(child.text())
        return " ".join(" ".join(values).split())

    def descendants(self):
        for child in self.children:
            yield child
            yield from child.descendants()

    def link(self) -> str | None:
        node: HtmlNode | None = self
        while node is not None:
            for key in ("href", "data-href", "data-url", "src"):
                value = node.attrs.get(key)
                if value:
                    return html.unescape(value.strip())
            node = node.parent
        return None


class _DomParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = HtmlNode("document")
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = HtmlNode(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(node)
        if tag.lower() not in VOID_TAGS:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1].children.append(HtmlNode(tag, attrs, self.stack[-1]))

    def handle_endtag(self, tag):
        lower = tag.lower()
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == lower:
                del self.stack[index:]
                return

    def handle_data(self, data):
        if data.strip():
            self.stack[-1].parts.append(data)


@dataclass(frozen=True)
class AttrTest:
    name: str
    operator: str | None
    value: str | None


@dataclass(frozen=True)
class PseudoTest:
    name: str
    argument: str | None = None


@dataclass(frozen=True)
class CompoundSelector:
    tag: str | None
    element_id: str | None
    classes: tuple[str, ...]
    attrs: tuple[AttrTest, ...]
    pseudos: tuple[PseudoTest, ...]


def split_css_groups(selector: str) -> list[str]:
    groups, current = [], []
    depth = 0
    quote_char = None
    for char in selector:
        if quote_char:
            current.append(char)
            if char == quote_char:
                quote_char = None
            continue
        if char in "\"'":
            quote_char = char
            current.append(char)
        elif char in "[(":
            depth += 1
            current.append(char)
        elif char in "])":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced-selector")
            current.append(char)
        elif char == "," and depth == 0:
            group = "".join(current).strip()
            if not group:
                raise ValueError("empty-selector-group")
            groups.append(group)
            current = []
        else:
            current.append(char)
    if quote_char or depth != 0:
        raise ValueError("unbalanced-selector")
    group = "".join(current).strip()
    if group:
        groups.append(group)
    return groups


def parse_compound(raw: str) -> CompoundSelector:
    if not raw:
        raise ValueError("empty-compound")
    index = 0
    tag = None
    element_id = None
    classes: list[str] = []
    attrs: list[AttrTest] = []
    pseudos: list[PseudoTest] = []
    if raw.startswith("*"):
        index = 1
    else:
        match = CSS_IDENT_RE.match(raw)
        if match:
            tag = match.group(0).lower()
            index = match.end()
    while index < len(raw):
        marker = raw[index]
        if marker in {".", "#"}:
            match = CSS_IDENT_RE.match(raw, index + 1)
            if not match:
                raise ValueError("bad-css-identifier")
            if marker == ".":
                classes.append(match.group(0))
            else:
                if element_id is not None:
                    raise ValueError("multiple-ids")
                element_id = match.group(0)
            index = match.end()
            continue
        if marker == "[":
            end = raw.find("]", index + 1)
            if end < 0:
                raise ValueError("unclosed-attribute")
            content = raw[index + 1:end].strip()
            match = re.fullmatch(r"([-_:a-zA-Z0-9]+)\s*(?:(\^=|\$=|\*=|~=|=)\s*(.*))?", content)
            if not match:
                raise ValueError("bad-attribute-selector")
            name, operator, value = match.groups()
            if value is not None:
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
            attrs.append(AttrTest(name.lower(), operator, value))
            index = end + 1
            continue
        if marker == ":":
            match = CSS_IDENT_RE.match(raw, index + 1)
            if not match:
                raise ValueError("bad-pseudo")
            name = match.group(0).lower()
            index = match.end()
            argument = None
            if index < len(raw) and raw[index] == "(":
                depth = 1
                end = index + 1
                quote_char = None
                while end < len(raw) and depth:
                    char = raw[end]
                    if quote_char:
                        if char == quote_char:
                            quote_char = None
                    elif char in "\"'":
                        quote_char = char
                    elif char == "(":
                        depth += 1
                    elif char == ")":
                        depth -= 1
                    end += 1
                if depth:
                    raise ValueError("unclosed-pseudo")
                argument = raw[index + 1:end - 1].strip()
                index = end
            if name not in {"first-child", "last-child", "nth-child", "not", "has"}:
                raise ValueError(f"unsupported-pseudo:{name}")
            if name in {"nth-child", "not", "has"} and not argument:
                raise ValueError(f"missing-pseudo-argument:{name}")
            pseudos.append(PseudoTest(name, argument))
            continue
        raise ValueError("unsupported-selector-token")
    return CompoundSelector(tag, element_id, tuple(classes), tuple(attrs), tuple(pseudos))


def parse_css_selector(selector: str):
    parsed_groups = []
    for group in split_css_groups(selector):
        parts = []
        token = []
        combinator = None
        depth = 0
        quote_char = None
        index = 0
        while index < len(group):
            char = group[index]
            if quote_char:
                token.append(char)
                if char == quote_char:
                    quote_char = None
                index += 1
                continue
            if char in "\"'":
                quote_char = char
                token.append(char)
            elif char in "[(":
                depth += 1
                token.append(char)
            elif char in "])":
                depth -= 1
                token.append(char)
            elif depth == 0 and char == ">":
                raw = "".join(token).strip()
                if raw:
                    parts.append((combinator, parse_compound(raw)))
                    token = []
                elif not parts:
                    raise ValueError("leading-child-combinator")
                combinator = ">"
            elif depth == 0 and char.isspace():
                raw = "".join(token).strip()
                if raw:
                    parts.append((combinator, parse_compound(raw)))
                    token = []
                    if combinator != ">":
                        combinator = " "
                while index + 1 < len(group) and group[index + 1].isspace():
                    index += 1
            else:
                token.append(char)
            index += 1
        raw = "".join(token).strip()
        if raw:
            parts.append((combinator, parse_compound(raw)))
        if not parts:
            raise ValueError("empty-selector")
        parsed_groups.append(parts)
    return parsed_groups


def node_matches(node: HtmlNode, selector: CompoundSelector) -> bool:
    if selector.tag and node.tag != selector.tag:
        return False
    if selector.element_id is not None and node.attrs.get("id") != selector.element_id:
        return False
    node_classes = set(node.attrs.get("class", "").split())
    if any(value not in node_classes for value in selector.classes):
        return False
    for test in selector.attrs:
        actual = node.attrs.get(test.name)
        if actual is None:
            return False
        if test.operator is None:
            continue
        expected = test.value or ""
        if test.operator == "=" and actual != expected:
            return False
        if test.operator == "^=" and not actual.startswith(expected):
            return False
        if test.operator == "$=" and not actual.endswith(expected):
            return False
        if test.operator == "*=" and expected not in actual:
            return False
        if test.operator == "~=" and expected not in actual.split():
            return False
    siblings = node.parent.children if node.parent is not None else []
    position = siblings.index(node) + 1 if node in siblings else 0
    for pseudo in selector.pseudos:
        if pseudo.name == "first-child" and position != 1:
            return False
        if pseudo.name == "last-child" and position != len(siblings):
            return False
        if pseudo.name == "nth-child":
            try:
                expected_position = int(pseudo.argument or "")
            except ValueError:
                raise ValueError("unsupported-nth-child-expression") from None
            if position != expected_position:
                return False
        if pseudo.name == "not":
            if node_matches(node, parse_compound(pseudo.argument or "")):
                return False
        if pseudo.name == "has":
            argument = (pseudo.argument or "").strip()
            direct = argument.startswith(">")
            inner = parse_compound(argument[1:].strip() if direct else argument)
            candidates = node.children if direct else list(node.descendants())
            if not any(node_matches(candidate, inner) for candidate in candidates):
                return False
    return True


def complex_matches(node: HtmlNode, parts, index: int | None = None) -> bool:
    if index is None:
        index = len(parts) - 1
    if not node_matches(node, parts[index][1]):
        return False
    if index == 0:
        return True
    combinator = parts[index][0]
    if combinator == ">":
        return node.parent is not None and complex_matches(node.parent, parts, index - 1)
    parent = node.parent
    while parent is not None:
        if complex_matches(parent, parts, index - 1):
            return True
        parent = parent.parent
    return False


def select_nodes(root: HtmlNode, selector: str, limit: int = MAX_EPISODES) -> list[HtmlNode]:
    parsed_groups = parse_css_selector(selector)
    output = []
    seen = set()
    for node in root.descendants():
        if any(complex_matches(node, group) for group in parsed_groups):
            identity = id(node)
            if identity not in seen:
                seen.add(identity)
                output.append(node)
                if len(output) >= limit:
                    break
    return output


def parse_html_document(data: bytes) -> HtmlNode:
    parser = _DomParser()
    parser.feed(decode_body(data))
    parser.close()
    return parser.root


def decode_body(data: bytes) -> str:
    for encoding in ("utf-8", "gb18030", "big5"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")


def challenge_kind(data: bytes) -> str | None:
    lower = decode_body(data[:300_000]).lower()
    return next((marker for marker in CHALLENGE_MARKERS if marker in lower), None)


def normalize_title(value: str) -> str:
    return "".join(char.casefold() for char in value if char.isalnum())


def title_matches(title: str, query: str) -> bool:
    a, b = normalize_title(title), normalize_title(query)
    return bool(a and b and (a in b or b in a))


def extract_json_keys(expression: str) -> list[str]:
    return re.findall(r"['\"]([^'\"]+)['\"]", expression)


def recursive_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from recursive_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from recursive_dicts(child)


def json_indexed_subjects(data: bytes, names_expr: str, links_expr: str) -> list[dict]:
    try:
        obj = json.loads(decode_body(data))
    except (ValueError, TypeError):
        return []
    name_keys = extract_json_keys(names_expr)
    link_keys = extract_json_keys(links_expr)
    output = []
    for record in recursive_dicts(obj):
        name = next((record.get(key) for key in name_keys if isinstance(record.get(key), str)), None)
        link = next((record.get(key) for key in link_keys if isinstance(record.get(key), str)), None)
        if name and link:
            output.append({"name": bounded_text(name, 300), "link": link})
            if len(output) >= MAX_SUBJECTS:
                break
    return output


def extract_subjects(data: bytes, config: dict, base_url: str) -> list[dict]:
    format_id = str(config.get("subjectFormatId") or "a").lower()
    if "json" in format_id:
        fmt = config.get("selectorSubjectFormatJsonPathIndexed") or {}
        return [
            {"name": row["name"], "url": urljoin(base_url, row["link"])}
            for row in json_indexed_subjects(
                data, str(fmt.get("selectNames") or ""), str(fmt.get("selectLinks") or ""))
        ]
    root = parse_html_document(data)
    if format_id == "indexed":
        fmt = config.get("selectorSubjectFormatIndexed") or {}
        names = select_nodes(root, str(fmt.get("selectNames") or ""), MAX_SUBJECTS)
        links = select_nodes(root, str(fmt.get("selectLinks") or ""), MAX_SUBJECTS)
        output = []
        for name_node, link_node in zip(names, links):
            link = link_node.link()
            if link:
                output.append({"name": name_node.text(), "url": urljoin(base_url, link)})
        return output
    fmt = config.get("selectorSubjectFormatA") or {}
    nodes = select_nodes(root, str(fmt.get("selectLists") or ""), MAX_SUBJECTS)
    return [
        {"name": node.text(), "url": urljoin(base_url, link)}
        for node in nodes if (link := node.link())
    ]


def extract_episodes(data: bytes, config: dict, base_url: str) -> list[dict]:
    root = parse_html_document(data)
    flattened = config.get("selectorChannelFormatFlattened") or {}
    no_channel = config.get("selectorChannelFormatNoChannel") or {}
    output = []
    list_selector = str(flattened.get("selectEpisodeLists") or "")
    episode_selector = str(flattened.get("selectEpisodesFromList") or "")
    channel_selector = str(flattened.get("selectChannelNames") or "")
    if list_selector and episode_selector:
        lists = select_nodes(root, list_selector, 30)
        channels = select_nodes(root, channel_selector, 30) if channel_selector else []
        for list_index, episode_list in enumerate(lists):
            channel = channels[list_index].text() if list_index < len(channels) else f"线路{list_index + 1}"
            for node in select_nodes(episode_list, episode_selector, MAX_EPISODES):
                link = node.link()
                if link:
                    output.append({"channel": bounded_text(channel, 120), "name": node.text(),
                                   "url": urljoin(base_url, link)})
                    if len(output) >= MAX_EPISODES:
                        return output
    if output:
        return output
    selector = str(no_channel.get("selectEpisodes") or "")
    if selector:
        for node in select_nodes(root, selector, MAX_EPISODES):
            link = node.link()
            if link:
                output.append({"channel": "默认线路", "name": node.text(),
                               "url": urljoin(base_url, link)})
    return output


def validate_css_fields(config: dict) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    search_url = config.get("searchUrl")
    if not isinstance(search_url, str) or not search_url:
        errors.append("searchConfig.searchUrl缺失")
    else:
        candidate = search_url.replace("{keyword}", quote("测试"))
        error = validate_target_url(candidate)
        if error:
            errors.append(f"searchConfig.searchUrl非法:{error}")
        if "{keyword}" not in search_url:
            warnings.append("searchUrl不含{keyword}")
        if urlsplit(candidate).scheme != "https":
            warnings.append("搜索使用明文HTTP")
    format_id = str(config.get("subjectFormatId") or "a").lower()
    selector_values = []
    if "json" not in format_id:
        if format_id == "indexed":
            fmt = config.get("selectorSubjectFormatIndexed") or {}
            selector_values += [("selectNames", fmt.get("selectNames")),
                                ("selectLinks", fmt.get("selectLinks"))]
        else:
            fmt = config.get("selectorSubjectFormatA") or {}
            selector_values += [("selectLists", fmt.get("selectLists"))]
    channel = config.get("selectorChannelFormatFlattened") or {}
    no_channel = config.get("selectorChannelFormatNoChannel") or {}
    if channel.get("selectEpisodeLists") and channel.get("selectEpisodesFromList"):
        selector_values += [
            ("selectEpisodeLists", channel.get("selectEpisodeLists")),
            ("selectEpisodesFromList", channel.get("selectEpisodesFromList")),
        ]
        if channel.get("selectChannelNames"):
            selector_values.append(("selectChannelNames", channel.get("selectChannelNames")))
    elif no_channel.get("selectEpisodes"):
        selector_values.append(("selectEpisodes", no_channel.get("selectEpisodes")))
    else:
        errors.append("缺少可测试的剧集selector")
    for field_name, value in selector_values:
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field_name}缺失")
            continue
        try:
            parse_css_selector(value)
        except ValueError as exc:
            warnings.append(f"evaluator-unsupported-selector:{field_name}:{exc}")
    matcher = config.get("matchVideo") or {}
    if not matcher.get("matchVideoUrl"):
        warnings.append("matchVideoUrl缺失")
    regex_fields = (
        ("matchChannelName", channel.get("matchChannelName")),
        ("matchEpisodeSortFromName", channel.get("matchEpisodeSortFromName")),
        ("matchEpisodeSortFromName", no_channel.get("matchEpisodeSortFromName")),
        ("matchNestedUrl", matcher.get("matchNestedUrl")),
        ("matchVideoUrl", matcher.get("matchVideoUrl")),
    )
    for field_name, pattern in regex_fields:
        if pattern is None:
            continue
        if not isinstance(pattern, str) or len(pattern) > updater.MAX_LEN_REGEX:
            errors.append(f"{field_name}类型或长度非法")
            continue
        normalized = re.sub(r"\(\?<([A-Za-z][A-Za-z0-9_]*)>", "(", pattern)
        try:
            re.compile(normalized)
        except re.error:
            warnings.append(f"java-regex-not-python-checkable:{field_name}")
    episode_pattern = channel.get("matchEpisodeSortFromName") or no_channel.get("matchEpisodeSortFromName")
    if isinstance(episode_pattern, str) and "(?<ep>" not in episode_pattern:
        warnings.append("集数正则缺少ep命名组")
    return errors, warnings


def config_capabilities(config: dict) -> dict:
    matcher = config.get("matchVideo") or {}
    headers = matcher.get("addHeadersToVideo") or {}
    return {
        "httpsSearch": urlsplit(str(config.get("searchUrl") or "")).scheme == "https",
        "subjectFormat": str(config.get("subjectFormatId") or "a"),
        "channelFormat": str(config.get("channelFormatId") or ""),
        "filtersEpisodeSort": bool(config.get("filterByEpisodeSort")),
        "filtersSubjectName": bool(config.get("filterBySubjectName")),
        "nestedVideoResolution": bool(matcher.get("enableNestedUrl")),
        "hasVideoPattern": bool(matcher.get("matchVideoUrl")),
        "hasPlaybackHeaders": isinstance(headers, dict) and bool(headers),
        "defaultResolution": bounded_text(config.get("defaultResolution") or "", 40),
        "requestIntervalMs": min(max(int(config.get("requestInterval") or 0), 0), 3_600_000),
    }


def build_search_url(config: dict, query: str) -> str:
    keyword = query
    if config.get("searchUseOnlyFirstWord"):
        keyword = keyword.split()[0]
    if config.get("searchRemoveSpecial"):
        keyword = "".join(char for char in keyword if char.isalnum() or char.isspace())
    return str(config.get("searchUrl") or "").replace("{keyword}", quote(keyword, safe=""))


def source_query(name: str, source_id: str, day: str) -> str:
    pool = H_QUALITY_TEST_QUERIES if any(token in name.casefold() for token in ("hanime", "里番", "h动漫")) else QUALITY_TEST_QUERIES
    index = int(hashlib.sha256(f"{source_id}:{day}".encode()).hexdigest()[:8], 16) % len(pool)
    return pool[index]


def clean_extracted_url(value: str) -> str | None:
    value = html.unescape(value).replace("\\/", "/").strip(" \t\r\n\"'`()[]{};,\\")
    value = unquote(value) if value.startswith("http%") else value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if validate_target_url(value):
        return None
    return value


def static_media_urls(data: bytes, page_url: str, config: dict) -> tuple[list[str], list[str]]:
    text = decode_body(data)
    candidates = []
    embedded = []

    def add_candidate(value: str | None, *, is_embedded: bool = False):
        if not value or len(candidates) >= 200:
            return
        cleaned = clean_extracted_url(value)
        if cleaned and cleaned not in candidates:
            candidates.append(cleaned)
        if cleaned and is_embedded and cleaned not in embedded:
            embedded.append(cleaned)

    for match in URL_RE.finditer(text):
        add_candidate(match.group(0))
        if len(candidates) >= 200:
            break
    try:
        root = parse_html_document(data)
        for node in root.descendants():
            for key in ("src", "href", "data-src", "data-url", "data-play"):
                raw = node.attrs.get(key)
                if raw:
                    add_candidate(
                        urljoin(page_url, html.unescape(raw)),
                        is_embedded=(node.tag in {"iframe", "frame", "embed", "source", "script"}
                                     or key in {"data-url", "data-play"}),
                    )
            if len(candidates) >= 200:
                break
    except Exception:
        pass

    def looks_like_media(url: str) -> bool:
        lowered = url.casefold()
        return (any(suffix in urlsplit(url).path.casefold() for suffix in MEDIA_SUFFIXES)
                or any(marker in lowered for marker in MEDIA_URL_MARKERS))

    media = [url for url in candidates if looks_like_media(url)]
    matcher = config.get("matchVideo") or {}
    nested = []
    if matcher.get("enableNestedUrl"):
        for url in [*embedded, *candidates]:
            if (url not in media and url not in nested
                    and (url in embedded or any(marker in url.casefold() for marker in NESTED_URL_MARKERS))):
                nested.append(url)
                if len(nested) >= 20:
                    break
    return media[:20], nested


def media_headers(config: dict, referer: str) -> dict[str, str]:
    matcher = config.get("matchVideo") or {}
    configured = matcher.get("addHeadersToVideo") or {}
    headers = {}
    if isinstance(configured, dict):
        for key, value in configured.items():
            if isinstance(key, str) and isinstance(value, str):
                if key.casefold() == "referer":
                    headers["Referer"] = value or referer
                elif key.casefold() == "useragent":
                    headers["User-Agent"] = value
    cookies = matcher.get("cookies")
    if isinstance(cookies, str) and cookies and len(cookies) <= 4096:
        headers["Cookie"] = cookies
    headers.setdefault("Referer", referer)
    return headers


def parse_hls(text: str, playlist_url: str) -> dict:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    entries = [line for line in lines if not line.startswith("#")]
    durations = []
    hosts = []
    variant_heights = []
    variant_bandwidths = []
    discontinuities = 0
    pending = None
    for line in lines:
        if line.startswith("#EXT-X-STREAM-INF:"):
            resolution = re.search(r"(?:^|,)RESOLUTION=\d+x(\d+)(?:,|$)", line.split(":", 1)[1])
            bandwidth = re.search(r"(?:^|,)BANDWIDTH=(\d+)(?:,|$)", line.split(":", 1)[1])
            if resolution:
                variant_heights.append(int(resolution.group(1)))
            if bandwidth:
                variant_bandwidths.append(int(bandwidth.group(1)))
        elif line.startswith("#EXT-X-DISCONTINUITY") and not line.startswith("#EXT-X-DISCONTINUITY-SEQUENCE"):
            discontinuities += 1
        elif line.startswith("#EXTINF:"):
            try:
                pending = float(line.split(":", 1)[1].split(",", 1)[0])
            except ValueError:
                pending = None
        elif not line.startswith("#"):
            full = urljoin(playlist_url, line)
            host = (urlsplit(full).hostname or "").lower()
            if host:
                hosts.append(host)
            if pending is not None:
                durations.append(pending)
                pending = None
    median = statistics.median(durations) if durations else None
    score = 0
    reasons = []
    if discontinuities:
        score += 2
        reasons.append(f"discontinuity:{discontinuities}")
    distinct_hosts = sorted(set(hosts))
    if len(distinct_hosts) > 1:
        score += 1
        reasons.append(f"segment-hosts:{len(distinct_hosts)}")
    if median and durations and durations[0] > 0 and durations[0] < median * 0.5:
        score += 1
        reasons.append("short-leading-segment")
    suspicion = "high" if score >= 3 else "medium" if score == 2 else "low" if score == 1 else "none"
    is_master = any(line.startswith("#EXT-X-STREAM-INF") for line in lines) and not durations
    return {
        "entries": entries,
        "variantCount": sum(line.startswith("#EXT-X-STREAM-INF:") for line in lines),
        "subtitleTrackCount": sum(
            line.startswith("#EXT-X-MEDIA:") and "TYPE=SUBTITLES" in line.upper()
            for line in lines),
        "audioTrackCount": sum(
            line.startswith("#EXT-X-MEDIA:") and "TYPE=AUDIO" in line.upper()
            for line in lines),
        "maxVariantHeight": max(variant_heights) if variant_heights else None,
        "maxVariantBandwidth": max(variant_bandwidths) if variant_bandwidths else None,
        "segmentCount": len(durations),
        "discontinuityCount": discontinuities,
        "distinctSegmentHostCount": len(distinct_hosts),
        "leadingDurations": durations[:5],
        "medianDuration": median,
        "adSuspicion": suspicion,
        "adReasons": reasons,
        "isMaster": is_master,
    }


def probe_media(fetcher, media_url: str, headers: dict[str, str]) -> dict:
    current = media_url
    master_playlist = None
    for depth in range(3):
        result = fetcher.fetch(
            current, headers=headers, max_bytes=MAX_PLAYLIST_BYTES, range_probe=True)
        if not result.ok:
            return {"ok": False, "kind": "unknown", "error": result.error,
                    "latencyMs": result.latency_ms, "url": redact_url(current)}
        content_type = (result.content_type or "").casefold()
        is_hls = ".m3u8" in urlsplit(current).path.casefold() or "mpegurl" in content_type
        if not is_hls:
            return {"ok": True, "kind": "file", "status": result.status,
                    "latencyMs": result.latency_ms, "url": redact_url(current),
                    "adSuspicion": "unknown"}
        parsed = parse_hls(decode_body(result.data), current)
        public_parsed = {key: value for key, value in parsed.items() if key != "entries"}
        if not parsed["entries"]:
            return {"ok": False, "kind": "hls", "status": result.status,
                    "latencyMs": result.latency_ms, "url": redact_url(current),
                    "error": "empty-playlist", **public_parsed}
        next_url = urljoin(current, parsed["entries"][0])
        if parsed["isMaster"]:
            master_playlist = {
                "variantCount": parsed["variantCount"],
                "subtitleTrackCount": parsed["subtitleTrackCount"],
                "audioTrackCount": parsed["audioTrackCount"],
                "maxVariantHeight": parsed["maxVariantHeight"],
                "maxVariantBandwidth": parsed["maxVariantBandwidth"],
            }
            current = next_url
            continue
        segment = fetcher.fetch(next_url, headers=headers, max_bytes=MAX_SEGMENT_BYTES,
                                range_probe=True)
        return {
            "ok": segment.ok,
            "kind": "hls",
            "masterPlaylist": master_playlist,
            "status": result.status,
            "latencyMs": (result.latency_ms or 0) + (segment.latency_ms or 0),
            "url": redact_url(current),
            "segmentStatus": segment.status,
            "segmentError": segment.error,
            **public_parsed,
        }
    return {"ok": False, "kind": "hls", "url": redact_url(current),
            "error": "nested-playlist-depth"}


def choose_subject(subjects: list[dict], query: str) -> tuple[dict | None, bool]:
    exact = next((row for row in subjects if title_matches(row.get("name", ""), query)), None)
    return (exact, True) if exact else ((subjects[0], False) if subjects else (None, False))


def representative_episodes(episodes: list[dict]) -> list[dict]:
    output, seen = [], set()
    for episode in episodes:
        channel = episode.get("channel") or ""
        if channel in seen:
            continue
        seen.add(channel)
        output.append(episode)
        if len(output) >= MAX_PLAY_PAGES:
            break
    return output


def calculate_score(stages: dict, warnings: list[str], probe: dict | None) -> int:
    score = 0
    score += 20 if stages.get("L0") == "passed" else 0
    score += 15 if stages.get("searchFetch") == "passed" else 0
    score += 15 if stages.get("subjectParse") == "passed" else 0
    score += 5 if stages.get("titleMatch") == "passed" else 0
    score += 20 if stages.get("episodeParse") == "passed" else 0
    score += 10 if stages.get("videoResolve") == "passed" else 0
    score += 15 if stages.get("transportProbe") == "passed" else 0
    if "搜索使用明文HTTP" in warnings:
        score -= 5
    suspicion = (probe or {}).get("adSuspicion")
    if suspicion == "high":
        score -= 10
    elif suspicion == "medium":
        score -= 5
    elif suspicion == "low":
        score -= 2
    return max(0, min(100, score))


def quality_label(score: int, stages: dict) -> str:
    if score >= 90 and stages.get("transportProbe") == "passed":
        return "excellent"
    if score >= 75 and stages.get("videoResolve") == "passed":
        return "good"
    if score >= 55 and stages.get("episodeParse") == "passed":
        return "fair"
    return "poor"


def evaluate_source(item: dict, fetcher=None, *, today: str | None = None) -> dict:
    started = time.monotonic()
    args = item.get("arguments") or {}
    config = args.get("searchConfig") or {}
    name = bounded_text(args.get("name") or "", 200)
    source_id = source_identity(item)
    today = today or datetime.now(timezone.utc).date().isoformat()
    query = source_query(name, source_id, today)
    result = {
        "sourceId": source_id,
        "factoryId": item.get("factoryId"),
        "name": name,
        "configFingerprint": config_fingerprint(item),
        "testedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "query": query,
        "officialTier": updater.safe_tier(args.get("tier")),
        "stages": {},
        "warnings": [],
        "errors": [],
        "metrics": {},
        "probe": None,
        "channelResults": [],
    }
    errors, warnings = validate_css_fields(config)
    item_valid, item_problems = updater.validate_item(item)
    if not item_valid:
        errors.extend(f"animeko-config:{problem}" for problem in item_problems)
    result["warnings"].extend(warnings)
    result["metrics"]["capabilities"] = config_capabilities(config)
    if errors:
        result["errors"].extend(errors)
        result["stages"]["L0"] = "failed"
        return finalize_result(result, started)
    result["stages"]["L0"] = "passed"
    if fetcher is None:
        fetcher = SafeFetcher(int(config.get("requestInterval") or 0))
    search_url = build_search_url(config, query)
    result["metrics"]["searchUrl"] = redact_url(search_url)
    search = fetcher.fetch(search_url, max_bytes=MAX_BODY_BYTES)
    result["metrics"]["searchLatencyMs"] = search.latency_ms
    if not search.ok:
        result["stages"]["searchFetch"] = "failed"
        result["errors"].append(f"search:{search.error}")
        return finalize_result(result, started)
    result["stages"]["searchFetch"] = "passed"
    try:
        subjects = extract_subjects(search.data, config, search_url)
    except ValueError as exc:
        result["stages"]["subjectParse"] = "unsupported"
        result["warnings"].append(f"subject-parse-unsupported:{exc}")
        return finalize_result(result, started)
    except Exception as exc:
        result["stages"]["subjectParse"] = "failed"
        result["errors"].append(f"subject-parse:{type(exc).__name__}")
        return finalize_result(result, started)
    result["metrics"]["subjectCount"] = len(subjects)
    subject, matched = choose_subject(subjects, query)
    if subject is None:
        challenge = challenge_kind(search.data)
        result["stages"]["subjectParse"] = "blocked" if challenge else "failed"
        if challenge:
            result["warnings"].append(f"challenge:{challenge}")
        else:
            result["errors"].append("subject-parse:empty")
        return finalize_result(result, started)
    result["stages"]["subjectParse"] = "passed"
    result["stages"]["titleMatch"] = "passed" if matched else "failed"
    result["metrics"]["selectedSubjectName"] = bounded_text(subject.get("name", ""), 200)
    episode_page = fetcher.fetch(subject["url"], max_bytes=MAX_BODY_BYTES)
    result["metrics"]["episodeLatencyMs"] = episode_page.latency_ms
    if not episode_page.ok:
        result["stages"]["episodeParse"] = "failed"
        result["errors"].append(f"episode-fetch:{episode_page.error}")
        return finalize_result(result, started)
    try:
        episodes = extract_episodes(episode_page.data, config, subject["url"])
    except ValueError as exc:
        result["stages"]["episodeParse"] = "unsupported"
        result["warnings"].append(f"episode-parse-unsupported:{exc}")
        return finalize_result(result, started)
    except Exception as exc:
        result["stages"]["episodeParse"] = "failed"
        result["errors"].append(f"episode-parse:{type(exc).__name__}")
        return finalize_result(result, started)
    result["metrics"]["episodeCount"] = len(episodes)
    result["metrics"]["channelCount"] = len(set(row.get("channel") for row in episodes))
    if not episodes:
        challenge = challenge_kind(episode_page.data)
        result["stages"]["episodeParse"] = "blocked" if challenge else "failed"
        if challenge:
            result["warnings"].append(f"challenge:{challenge}")
        else:
            result["errors"].append("episode-parse:empty")
        return finalize_result(result, started)
    result["stages"]["episodeParse"] = "passed"
    matcher = config.get("matchVideo") or {}
    channel_results = []
    for episode in representative_episodes(episodes):
        resolved = None
        resolved_referer = None
        play_url = episode["url"]
        if any(suffix in urlsplit(play_url).path.casefold() for suffix in MEDIA_SUFFIXES):
            resolved, resolved_referer = play_url, subject["url"]
        else:
            queue = [(play_url, 0)]
            visited = set()
            while queue:
                page_url, depth = queue.pop(0)
                if page_url in visited or depth > 2:
                    continue
                visited.add(page_url)
                page = fetcher.fetch(page_url, max_bytes=MAX_BODY_BYTES)
                if not page.ok:
                    continue
                media_urls, nested_urls = static_media_urls(page.data, page_url, config)
                if media_urls:
                    resolved, resolved_referer = media_urls[0], page_url
                    break
                if matcher.get("enableNestedUrl"):
                    queue.extend((url, depth + 1) for url in nested_urls[:2] if url not in visited)
        channel_result = {
            "channel": bounded_text(episode.get("channel") or "默认线路", 120),
            "episodeName": bounded_text(episode.get("name") or "", 120),
            "resolveStatus": "passed" if resolved else "failed",
            "transportStatus": "not-run",
        }
        if resolved:
            channel_result["resolvedVideoUrl"] = redact_url(resolved)
            probe = probe_media(
                fetcher, resolved, media_headers(config, resolved_referer or subject["url"]))
            channel_result["probe"] = probe
            channel_result["transportStatus"] = "passed" if probe.get("ok") else "failed"
        channel_results.append(channel_result)
    result["channelResults"] = channel_results
    resolved_channels = [row for row in channel_results if row["resolveStatus"] == "passed"]
    passed_channels = [row for row in channel_results if row["transportStatus"] == "passed"]
    result["metrics"]["testedChannelCount"] = len(channel_results)
    result["metrics"]["resolvedChannelCount"] = len(resolved_channels)
    result["metrics"]["transportPassedChannelCount"] = len(passed_channels)
    if not resolved_channels:
        result["stages"]["videoResolve"] = "failed"
        result["errors"].append("video-resolve:no-static-media-url")
        return finalize_result(result, started)
    result["stages"]["videoResolve"] = "passed"
    representative = (passed_channels or resolved_channels)[0]
    result["metrics"]["resolvedVideoUrl"] = representative.get("resolvedVideoUrl")
    result["probe"] = representative.get("probe")
    result["stages"]["transportProbe"] = "passed" if passed_channels else "failed"
    if not passed_channels:
        probe = result.get("probe") or {}
        result["errors"].append(
            f"transport:{probe.get('error') or probe.get('segmentError') or 'failed'}")
    return finalize_result(result, started)


def finalize_result(result: dict, started: float) -> dict:
    result["warnings"] = sorted(set(bounded_text(value) for value in result["warnings"]))[:30]
    result["errors"] = sorted(set(bounded_text(value) for value in result["errors"]))[:30]
    result["score"] = calculate_score(result["stages"], result["warnings"], result.get("probe"))
    result["quality"] = quality_label(result["score"], result["stages"])
    result["eligibleForTierRecommendation"] = "unsupported" not in result["stages"].values()
    result["totalDurationMs"] = round((time.monotonic() - started) * 1000)
    return result


def validate_observation(value: dict) -> bool:
    if not isinstance(value, dict):
        return False
    required = {"sourceId", "name", "configFingerprint", "testedAt", "stages", "score", "quality"}
    if not required.issubset(value):
        return False
    return (
        isinstance(value["sourceId"], str) and re.fullmatch(r"[0-9a-f]{24}", value["sourceId"])
        and isinstance(value["name"], str) and len(value["name"]) <= 200
        and isinstance(value["configFingerprint"], str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value["configFingerprint"]))
        and isinstance(value["stages"], dict)
        and isinstance(value["score"], int) and not isinstance(value["score"], bool)
        and 0 <= value["score"] <= 100
        and value["quality"] in {"excellent", "good", "fair", "poor"}
    )


def empty_state() -> dict:
    return {"schemaVersion": SCHEMA_VERSION, "sources": {}}


def load_json_limited(path: str, maximum: int):
    target = Path(path)
    if not target.is_file() or target.is_symlink():
        raise QualityError("文件缺失或为symlink")
    if target.stat().st_size > maximum:
        raise QualityError("文件过大")
    with target.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_state(path: str) -> dict:
    if not os.path.exists(path):
        return empty_state()
    try:
        state = load_json_limited(path, MAX_STATE_SIZE)
    except (OSError, ValueError, QualityError):
        return empty_state()
    if (not isinstance(state, dict) or state.get("schemaVersion") != SCHEMA_VERSION
            or not isinstance(state.get("sources"), dict)
            or len(state["sources"]) > MAX_STATE_SOURCES):
        return empty_state()
    cleaned = empty_state()
    for source_id, record in state["sources"].items():
        if not isinstance(record, dict) or source_id != record.get("sourceId"):
            continue
        history = record.get("history")
        if not isinstance(history, list):
            continue
        valid = [entry for entry in history if validate_observation(entry)][-MAX_HISTORY:]
        if valid:
            cleaned["sources"][source_id] = {"sourceId": source_id, "name": bounded_text(record.get("name", ""), 200),
                                                     "history": valid}
    return cleaned


def update_state(state: dict, observations: list[dict]) -> dict:
    updated = copy.deepcopy(state)
    updated.setdefault("schemaVersion", SCHEMA_VERSION)
    sources = updated.setdefault("sources", {})
    for observation in observations:
        if not validate_observation(observation):
            raise QualityError("拒绝写入非法质量观察")
        source_id = observation["sourceId"]
        record = sources.setdefault(source_id, {"sourceId": source_id, "name": observation["name"], "history": []})
        record["name"] = observation["name"]
        fingerprint = observation["configFingerprint"]
        tested_day = observation["testedAt"][:10]
        history = [entry for entry in record.get("history", [])
                   if not (entry.get("configFingerprint") == fingerprint
                           and str(entry.get("testedAt", ""))[:10] == tested_day)]
        history.append(observation)
        record["history"] = history[-MAX_HISTORY:]
    if len(sources) > MAX_STATE_SOURCES:
        ordered = sorted(sources.items(), key=lambda pair: pair[1].get("history", [{}])[-1].get("testedAt", ""),
                         reverse=True)[:MAX_STATE_SOURCES]
        updated["sources"] = dict(ordered)
    return updated


def recommendation(history: list[dict], fingerprint: str) -> dict:
    observations = [
        entry for entry in history
        if entry.get("configFingerprint") == fingerprint
        and entry.get("eligibleForTierRecommendation", True)
    ][-MAX_HISTORY:]
    dates = {str(entry.get("testedAt", ""))[:10] for entry in observations}
    ready = len(observations) >= 3 and len(dates) >= 3
    if not observations:
        return {"ready": False, "observations": 0, "distinctDays": 0, "recommendedTier": None}
    scores = [entry["score"] for entry in observations]
    probes = [entry.get("stages", {}).get("transportProbe") == "passed" for entry in observations]
    durations = [entry.get("totalDurationMs") for entry in observations
                 if isinstance(entry.get("totalDurationMs"), int)]
    high_ads = [entry for entry in observations if (entry.get("probe") or {}).get("adSuspicion") == "high"]
    success_rate = sum(probes) / len(probes)
    median_score = statistics.median(scores)
    median_duration = statistics.median(durations) if durations else None
    tier = None
    if ready:
        if success_rate >= 0.95 and median_score >= 90 and (median_duration or math.inf) <= 8000 and not high_ads:
            tier = 0
        elif success_rate >= 0.80 and median_score >= 80:
            tier = 1
        elif success_rate >= 0.60 and median_score >= 65:
            tier = 3
        else:
            tier = 4
    return {
        "ready": ready,
        "observations": len(observations),
        "distinctDays": len(dates),
        "transportSuccessRate": round(success_rate, 3),
        "medianScore": median_score,
        "medianDurationMs": median_duration,
        "highAdObservations": len(high_ads),
        "recommendedTier": tier,
    }


def choose_sample(items: list[dict], state: dict, sample_size: int) -> list[dict]:
    if sample_size <= 0 or sample_size >= len(items):
        return list(items)
    records = state.get("sources", {})
    def key(item):
        source_id = source_identity(item)
        history = (records.get(source_id) or {}).get("history") or []
        last = history[-1].get("testedAt", "") if history else ""
        return (last, source_id)
    return sorted(items, key=key)[:sample_size]


def build_report(items: list[dict], state: dict, observations: list[dict]) -> dict:
    current = {entry["sourceId"]: entry for entry in observations}
    summaries = []
    for item in sorted(items, key=lambda value: ((value.get("arguments") or {}).get("name") or "").casefold()):
        args = item.get("arguments") or {}
        source_id = source_identity(item)
        record = (state.get("sources", {}).get(source_id) or {})
        rec = recommendation(record.get("history") or [], config_fingerprint(item))
        official_tier = updater.safe_tier(args.get("tier"))
        summaries.append({
            "sourceId": source_id,
            "name": bounded_text(args.get("name") or "", 200),
            "factoryId": item.get("factoryId"),
            "officialTier": official_tier,
            "recommendation": rec,
            "tierDisagreement": bool(rec["ready"] and rec["recommendedTier"] != official_tier),
            "testedThisRun": source_id in current,
            "latest": current.get(source_id) or ((record.get("history") or [None])[-1]),
        })
    tested = len(observations)
    passed_transport = sum(entry.get("stages", {}).get("transportProbe") == "passed" for entry in observations)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "method": {
            "levels": ["L0-config", "L1-subject-and-episode", "L2-static-video-url", "L3-static-transport"],
            "executesSiteJavaScript": False,
            "executesThirdPartyPrograms": False,
            "executesSourceRegexAgainstNetworkData": False,
            "realPlaybackClaimed": False,
            "staticHtmlOnly": True,
            "maxChannelsPerSource": MAX_PLAY_PAGES,
            "hlsPlaylistAndFirstSegmentProbe": True,
            "hlsAdHeuristics": True,
            "creamycakeTierRemainsAuthoritative": True,
            "recommendationsRequireDistinctDays": 3,
        },
        "run": {
            "totalSources": len(items),
            "testedSources": tested,
            "transportPassed": passed_transport,
            "transportPassRate": round(passed_transport / tested, 3) if tested else None,
        },
        "observations": observations,
        "sources": summaries,
    }


def atomic_write_json(path: str, value, maximum: int, *, pretty: bool = True):
    payload = (json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        indent=2 if pretty else None, separators=None if pretty else (",", ":"),
        allow_nan=False,
    ) + "\n").encode("utf-8")
    if len(payload) > maximum:
        raise QualityError("输出超过大小上限")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink() or (target.exists() and target.is_symlink()):
        raise QualityError("拒绝通过symlink写入")
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_online_items(path: str) -> list[dict]:
    obj = load_json_limited(path, MAX_INPUT_SIZE)
    try:
        items = obj["exportedMediaSourceDataList"]["mediaSources"]
    except (KeyError, TypeError) as exc:
        raise QualityError("输入不是Animeko导出格式") from exc
    if not isinstance(items, list) or not items or len(items) > updater.MAX_TOTAL_CANDIDATES:
        raise QualityError("输入数据源数量非法")
    output = []
    seen = set()
    for item in items:
        if not isinstance(item, dict) or item.get("factoryId") != "web-selector":
            continue
        normalized = updater.normalize_item(item)
        if normalized is None:
            continue
        source_id = source_identity(normalized)
        if source_id not in seen:
            seen.add(source_id)
            output.append(normalized)
    if not output:
        raise QualityError("没有可评估的web-selector源")
    return output


def validate_report(report: dict) -> list[str]:
    problems = []
    if not isinstance(report, dict) or report.get("schemaVersion") != SCHEMA_VERSION:
        return ["schemaVersion非法"]
    if not isinstance(report.get("observations"), list) or not isinstance(report.get("sources"), list):
        return ["报告列表缺失"]
    for index, observation in enumerate(report["observations"]):
        if not validate_observation(observation):
            problems.append(f"observation[{index}]非法")
    for index, source in enumerate(report["sources"]):
        if not isinstance(source, dict) or not isinstance(source.get("recommendation"), dict):
            problems.append(f"source[{index}]非法")
    return problems


class FakeFetcher:
    def __init__(self, responses: dict[str, FetchResult]):
        self.responses = responses

    def fetch(self, url: str, **_kwargs):
        return self.responses.get(url, FetchResult(False, redact_url(url) or "", error="missing-fixture"))


def run_selftests():
    class Tests(unittest.TestCase):
        def test_css_selector_subset(self):
            root = parse_html_document(b'<body><div class="box"><a href="/x">Hello</a></div></body>')
            nodes = select_nodes(root, "body > .box a[href^='/']")
            self.assertEqual(len(nodes), 1)
            self.assertEqual(nodes[0].text(), "Hello")

        def test_css_common_pseudos(self):
            root = parse_html_document(
                b'<div class="panel"><a id="first"></a><a class="more"></a></div>')
            self.assertEqual(len(select_nodes(root, ".panel:has(> .more) > a:nth-child(2)")), 1)
            self.assertEqual(len(select_nodes(root, "a:first-child:not(.more)")), 1)
            self.assertEqual(len(select_nodes(root, "a:last-child")), 1)
            with self.assertRaises(ValueError):
                parse_css_selector("a:hover")

        def test_indexed_subjects(self):
            config = {"subjectFormatId": "indexed", "selectorSubjectFormatIndexed": {
                "selectNames": ".name", "selectLinks": ".link"}}
            data = b'<div><span class="name">Show</span><a class="link" href="/s"></a></div>'
            self.assertEqual(extract_subjects(data, config, "https://a.example/q")[0]["url"],
                             "https://a.example/s")

        def test_a_subjects(self):
            config = {"subjectFormatId": "a", "selectorSubjectFormatA": {"selectLists": "h3 > a"}}
            rows = extract_subjects(b'<h3><a href="/s">Show</a></h3>', config, "https://a.example/q")
            self.assertEqual(rows, [{"name": "Show", "url": "https://a.example/s"}])

        def test_episode_extraction(self):
            config = {"selectorChannelFormatFlattened": {
                "selectChannelNames": ".tabs span", "selectEpisodeLists": ".lists ul",
                "selectEpisodesFromList": "a"}}
            data = b'<div class="tabs"><span>A</span></div><div class="lists"><ul><li><a href="/p1">1</a></li></ul></div>'
            rows = extract_episodes(data, config, "https://a.example/show")
            self.assertEqual(rows[0]["channel"], "A")
            self.assertEqual(rows[0]["url"], "https://a.example/p1")

        def test_json_indexed(self):
            data = json.dumps([{"title": "Show", "url": "/s"}]).encode()
            rows = json_indexed_subjects(data, "$[*]['title','name']", "$[*]['url','link']")
            self.assertEqual(rows, [{"name": "Show", "link": "/s"}])

        def test_representative_episodes_cover_channels(self):
            episodes = [
                {"channel": "A", "name": "1"}, {"channel": "A", "name": "2"},
                {"channel": "B", "name": "1"}, {"channel": "C", "name": "1"},
                {"channel": "D", "name": "1"},
            ]
            self.assertEqual([row["channel"] for row in representative_episodes(episodes)],
                             ["A", "B", "C"])

        def test_static_media_url(self):
            data = b'<script>var u="https:\\/\\/cdn.example\\/a.m3u8?token=x";</script>'
            media, _ = static_media_urls(data, "https://a.example/p", {"matchVideo": {}})
            self.assertTrue(media[0].startswith("https://cdn.example/a.m3u8"))

        def test_hls_ad_signals(self):
            parsed = parse_hls("#EXTM3U\n#EXTINF:1,\na.ts\n#EXT-X-DISCONTINUITY\n#EXTINF:10,\nhttps://b.example/b.ts\n",
                               "https://a.example/a.m3u8")
            self.assertEqual(parsed["adSuspicion"], "high")
            self.assertEqual(parsed["segmentCount"], 2)
            master = parse_hls(
                "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=4000000,RESOLUTION=1920x1080\n1080.m3u8\n",
                "https://a.example/master.m3u8")
            self.assertTrue(master["isMaster"])
            self.assertEqual(master["maxVariantHeight"], 1080)
            self.assertEqual(master["maxVariantBandwidth"], 4000000)

        def test_recommendation_needs_three_days(self):
            base = {"sourceId": "a" * 24, "name": "X", "configFingerprint": "b" * 64,
                    "stages": {"transportProbe": "passed"}, "score": 95, "quality": "excellent",
                    "totalDurationMs": 1000}
            history = [{**base, "testedAt": f"2026-08-2{day}T00:00:00+00:00"} for day in range(1, 4)]
            rec = recommendation(history, "b" * 64)
            self.assertTrue(rec["ready"])
            self.assertEqual(rec["recommendedTier"], 0)

        def test_recommendation_does_not_mix_configs(self):
            history = [{"sourceId": "a" * 24, "name": "X", "configFingerprint": "c" * 64,
                        "testedAt": "2026-08-20T00:00:00+00:00", "stages": {}, "score": 1,
                        "quality": "poor"}]
            self.assertEqual(recommendation(history, "b" * 64)["observations"], 0)

        def test_choose_sample_prefers_unseen(self):
            def item(name):
                return {"factoryId": "web-selector", "version": 2, "arguments": {"name": name,
                    "searchConfig": {"searchUrl": f"https://{name}.example/?q={{keyword}}"}}}
            old, unseen = item("old"), item("new")
            state = empty_state()
            sid = source_identity(old)
            state["sources"][sid] = {"sourceId": sid, "name": "old", "history": [{
                "sourceId": sid, "name": "old", "configFingerprint": config_fingerprint(old),
                "testedAt": "2026-01-01T00:00:00+00:00", "stages": {}, "score": 0,
                "quality": "poor"}]}
            self.assertEqual(source_identity(choose_sample([old, unseen], state, 1)[0]),
                             source_identity(unseen))

        def test_url_redaction(self):
            self.assertEqual(redact_url("https://a.example/x?token=secret"),
                             "https://a.example/x?<redacted>")

        def test_private_url_rejected(self):
            self.assertEqual(validate_target_url("http://127.0.0.1/x"), "private-host")
            self.assertEqual(validate_target_url("https://example.com/x"), None)

        def test_state_rejects_invalid_observation(self):
            with self.assertRaises(QualityError):
                update_state(empty_state(), [{"score": 1}])

        def test_state_keeps_one_observation_per_config_and_day(self):
            observation = {"sourceId": "a" * 24, "name": "X", "configFingerprint": "b" * 64,
                           "testedAt": "2026-08-25T00:00:00+00:00", "stages": {}, "score": 1,
                           "quality": "poor"}
            state = update_state(empty_state(), [observation])
            newer = {**observation, "testedAt": "2026-08-25T10:00:00+00:00", "score": 2}
            state = update_state(state, [newer])
            history = state["sources"]["a" * 24]["history"]
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["score"], 2)

        def test_end_to_end_static_transport(self):
            item = {"factoryId": "web-selector", "version": 2, "arguments": {
                "name": "X", "description": "", "iconUrl": "", "tier": 3, "searchConfig": {
                    "searchUrl": "https://site.example/search?q={keyword}",
                    "subjectFormatId": "a",
                    "selectorSubjectFormatA": {"selectLists": "h3 > a"},
                    "selectorChannelFormatFlattened": {
                        "selectChannelNames": ".tab", "selectEpisodeLists": ".list",
                        "selectEpisodesFromList": "a"},
                    "matchVideo": {"enableNestedUrl": False, "matchVideoUrl": ".+m3u8.+"},
                }}}
            sid = source_identity(item)
            query = source_query("X", sid, "2026-08-25")
            search_url = build_search_url(item["arguments"]["searchConfig"], query)
            responses = {
                search_url: FetchResult(True, redact_url(search_url) or "", 200,
                                        f'<h3><a href="/show">{query}</a></h3>'.encode(), "text/html", 10),
                "https://site.example/show": FetchResult(True, "https://site.example/show", 200,
                    b'<span class="tab">A</span><div class="list"><a href="/play">1</a></div>', "text/html", 10),
                "https://site.example/play": FetchResult(True, "https://site.example/play", 200,
                    b'<script>var u="https://cdn.example/a.m3u8"</script>', "text/html", 10),
                "https://cdn.example/a.m3u8": FetchResult(True, "https://cdn.example/a.m3u8", 200,
                    b'#EXTM3U\n#EXTINF:10,\nseg.ts\n', "application/vnd.apple.mpegurl", 10),
                "https://cdn.example/seg.ts": FetchResult(True, "https://cdn.example/seg.ts", 206,
                    b"segment", "video/mp2t", 10),
            }
            result = evaluate_source(item, FakeFetcher(responses), today="2026-08-25")
            self.assertEqual(result["stages"]["transportProbe"], "passed")
            self.assertEqual(result["quality"], "excellent")
            self.assertEqual(result["score"], 100)
            self.assertNotIn("entries", result["probe"])

        def test_safe_fetch_header_filter(self):
            cleaned = SafeFetcher._clean_headers({"Authorization": "secret", "Referer": "https://a.example",
                                                  "X-Test": "bad"})
            self.assertNotIn("Authorization", cleaned)
            self.assertNotIn("X-Test", cleaned)
            self.assertEqual(cleaned["Referer"], "https://a.example")

        def test_atomic_write_rejects_oversize(self):
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(QualityError):
                    atomic_write_json(os.path.join(directory, "x.json"), {"x": "a" * 100}, 20)

        def test_validate_report(self):
            observation = {"sourceId": "a" * 24, "name": "X", "configFingerprint": "b" * 64,
                           "testedAt": "2026-08-25T00:00:00+00:00", "stages": {}, "score": 1,
                           "quality": "poor"}
            report = {"schemaVersion": 1, "observations": [observation],
                      "sources": [{"recommendation": {}}]}
            self.assertFalse(validate_report(report))

        @mock.patch.object(time, "sleep")
        def test_request_gap_is_bounded(self, sleep):
            fetcher = SafeFetcher(999999)
            self.assertEqual(fetcher.request_gap, MAX_CONFIG_REQUEST_GAP_SECONDS)
            fetcher.last_request_by_host["a.example"] = time.monotonic()
            fetcher._wait_for_host("a.example")
            self.assertTrue(sleep.called)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    print(f"quality-selftests: {suite.countTestCases()}")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


def parse_args(argv: list[str]):
    parser = argparse.ArgumentParser(description="Evaluate Animeko source quality without JavaScript")
    parser.add_argument("--input", default="dist/online.json")
    parser.add_argument("--state", default="quality-cache/state.json")
    parser.add_argument("--report", default="reports/quality.json")
    parser.add_argument("--sample-size", type=int, default=16)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--validate", metavar="REPORT")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.test:
        run_selftests()
    if args.validate:
        try:
            report = load_json_limited(args.validate, MAX_REPORT_SIZE)
            problems = validate_report(report)
        except Exception as exc:
            print(f"质量报告读取失败: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if problems:
            print("质量报告无效: " + "; ".join(problems[:20]), file=sys.stderr)
            return 1
        print("质量报告校验通过")
        return 0
    try:
        items = load_online_items(args.input)
        state = load_state(args.state)
        selected = choose_sample(items, state, max(0, args.sample_size))
        observations = []
        for index, item in enumerate(selected, 1):
            name = (item.get("arguments") or {}).get("name") or "<unnamed>"
            print(f"[{index}/{len(selected)}] 评估 {name}", flush=True)
            observation = evaluate_source(item)
            observations.append(observation)
            print(f"  {observation['quality']} score={observation['score']} "
                  f"stage={observation['stages']}", flush=True)
        state = update_state(state, observations)
        report = build_report(items, state, observations)
        problems = validate_report(report)
        if problems:
            raise QualityError("; ".join(problems[:20]))
        atomic_write_json(args.state, state, MAX_STATE_SIZE, pretty=False)
        atomic_write_json(args.report, report, MAX_REPORT_SIZE)
        print(f"质量报告: {args.report}；本轮 {len(observations)}/{len(items)} 个源")
        return 0
    except (OSError, ValueError, QualityError) as exc:
        print(f"质量评估失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
