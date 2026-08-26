#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

MAX_URL_LENGTH = 8192
PRIVATE_HOST_SUFFIXES = (
    "localhost", "local", "internal", "lan", "home", "localdomain", "invalid", "test",
    "example", "svc", "cluster.local",
)
SENSITIVE_QUERY_NAMES = frozenset({
    "token", "access_token", "api_key", "apikey", "key", "auth", "authorization",
    "signature", "sig", "credential", "password", "passwd", "secret", "x-amz-signature",
    "x-goog-signature",
})
GITHUB_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
REPOSITORY_PART_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
NUMERIC_HOST_RE = re.compile(r"(?:0x[0-9a-f]+|[0-9.]+)\Z", re.IGNORECASE)
PROXY_HOSTS = frozenset({
    "gh-proxy.com", "v6.gh-proxy.org", "cdn.gh-proxy.org", "ghfast.top",
    "ghproxy.net", "gh.ddlc.top", "ghproxy.cc",
})


class UrlPolicyError(ValueError):
    pass


def has_control(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _decode_segment(raw: str) -> str:
    if BAD_PERCENT_RE.search(raw):
        raise UrlPolicyError("URL含非法percent encoding")
    value = raw
    for _ in range(5):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    else:
        raise UrlPolicyError("URL重复percent encoding过深")
    if (value in {".", ".."} or "/" in value or "\\" in value or has_control(value)):
        raise UrlPolicyError("URL path segment非法")
    return value


def _canonical_path(path: str) -> tuple[str, list[str]]:
    if path == "":
        return "", []
    if not path.startswith("/") or "\\" in path:
        raise UrlPolicyError("URL path非法")
    raw_parts = path[1:].split("/")
    decoded = [_decode_segment(part) for part in raw_parts]
    canonical = "/" + "/".join(
        quote(part, safe="!$&'()*+,;=:@-._~") for part in decoded)
    return canonical, decoded


def _canonical_host(hostname: str) -> str:
    host = hostname.rstrip(".").casefold()
    if not host or len(host) > 253:
        raise UrlPolicyError("URL hostname非法")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise UrlPolicyError("URL不得使用IP literal")
    if NUMERIC_HOST_RE.fullmatch(host):
        raise UrlPolicyError("URL不得使用numeric hostname")
    if any(host == suffix or host.endswith("." + suffix) for suffix in PRIVATE_HOST_SUFFIXES):
        raise UrlPolicyError("URL不得使用内部hostname")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UrlPolicyError("URL hostname IDNA无效") from exc
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels):
        raise UrlPolicyError("URL hostname label无效")
    return ascii_host


def _validate_query(query: str):
    if has_control(query) or BAD_PERCENT_RE.search(query):
        raise UrlPolicyError("URL query非法")
    for name, _ in parse_qsl(query, keep_blank_values=True, strict_parsing=False):
        if name.casefold() in SENSITIVE_QUERY_NAMES:
            raise UrlPolicyError("URL query包含敏感参数")


def _github_ref_safe(ref: str) -> bool:
    return (
        isinstance(ref, str)
        and 1 <= len(ref) <= 255
        and not ref.startswith(("/", "."))
        and not ref.endswith(("/", "."))
        and ".." not in ref
        and "@{" not in ref
        and "//" not in ref
        and not any(ord(ch) < 32 or ord(ch) == 127 or ch in " ~^:?*[\\" for ch in ref)
    )


def _split_ref(parts: list[str], index: int) -> tuple[str, list[str]]:
    if len(parts) <= index + 1:
        raise UrlPolicyError("GitHub URL缺少ref或文件path")
    if parts[index] == "refs":
        if len(parts) <= index + 3 or parts[index + 1] != "heads":
            raise UrlPolicyError("GitHub显式refs仅允许无歧义的heads/main或heads/master")
        if parts[index + 2] not in {"main", "master"}:
            raise UrlPolicyError("GitHub显式refs分支可能含slash，拒绝歧义解析")
        return "/".join(parts[index:index + 3]), parts[index + 3:]
    return parts[index], parts[index + 1:]


def _validate_github_parts(owner: str, repo: str, ref: str, file_parts: list[str]):
    if not GITHUB_NAME_RE.fullmatch(owner) or not GITHUB_NAME_RE.fullmatch(repo):
        raise UrlPolicyError("GitHub owner/repository非法")
    if not _github_ref_safe(ref) or not file_parts or any(not part for part in file_parts):
        raise UrlPolicyError("GitHub ref或文件path非法")


def _github_identity(host: str, parts: list[str]) -> str | None:
    if host == "raw.githubusercontent.com":
        if len(parts) < 4:
            raise UrlPolicyError("raw.githubusercontent.com path非法")
        ref, file_parts = _split_ref(parts, 2)
        _validate_github_parts(parts[0], parts[1], ref, file_parts)
        return f"github:{parts[0].casefold()}/{parts[1].casefold()}"
    if host == "github.com":
        if len(parts) < 5 or parts[2] not in {"raw", "blob"}:
            raise UrlPolicyError("github.com必须指向raw/blob文件")
        ref, file_parts = _split_ref(parts, 3)
        _validate_github_parts(parts[0], parts[1], ref, file_parts)
        return f"github:{parts[0].casefold()}/{parts[1].casefold()}"
    if host == "cdn.jsdelivr.net":
        if len(parts) < 4 or parts[0] != "gh" or "@" not in parts[2]:
            raise UrlPolicyError("jsDelivr GitHub path非法")
        repo, ref = parts[2].split("@", 1)
        _validate_github_parts(parts[1], repo, ref, parts[3:])
        return f"github:{parts[1].casefold()}/{repo.casefold()}"
    return None


def _proxy_identity(host: str, parts: list[str]) -> str | None:
    if host not in PROXY_HOSTS:
        return None
    if len(parts) > 2 and parts[:3] == ["https:", "", "raw.githubusercontent.com"]:
        parts = parts[3:]
    elif parts and parts[0] == "raw.githubusercontent.com":
        parts = parts[1:]
    elif len(parts) > 2 and parts[:3] == ["https:", "", "github.com"]:
        github_parts = parts[3:]
        if len(github_parts) < 5 or github_parts[2] not in {"raw", "blob"}:
            raise UrlPolicyError("GitHub proxy github.com path非法")
        ref, file_parts = _split_ref(github_parts, 3)
        _validate_github_parts(github_parts[0], github_parts[1], ref, file_parts)
        return f"github:{github_parts[0].casefold()}/{github_parts[1].casefold()}"
    else:
        raise UrlPolicyError("GitHub proxy path非法")
    if len(parts) < 4:
        raise UrlPolicyError("GitHub proxy缺少文件path")
    ref, file_parts = _split_ref(parts, 2)
    _validate_github_parts(parts[0], parts[1], ref, file_parts)
    return f"github:{parts[0].casefold()}/{parts[1].casefold()}"


def _other_repository_identity(host: str, parts: list[str]) -> str | None:
    if host == "gitlab.com" and "-" in parts:
        marker = parts.index("-")
        if marker >= 2 and len(parts) > marker + 3 and parts[marker + 1] in {"raw", "blob"}:
            repo = parts[:marker]
            if all(REPOSITORY_PART_RE.fullmatch(part) for part in repo):
                return "gitlab:" + "/".join(part.casefold() for part in repo)
    if host in {"gitee.com", "raw.atomgit.com"} and len(parts) >= 5 and parts[2] in {"raw", "blob"}:
        if all(REPOSITORY_PART_RE.fullmatch(part) for part in parts[:2]):
            platform = "gitee" if host == "gitee.com" else "gitee"
            return f"{platform}:{parts[0].casefold()}/{parts[1].casefold()}"
    if host == "codeberg.org" and len(parts) >= 6 and parts[2] in {"raw", "src"}:
        if all(REPOSITORY_PART_RE.fullmatch(part) for part in parts[:2]):
            return f"codeberg:{parts[0].casefold()}/{parts[1].casefold()}"
    return None


def canonicalize_url(value: str) -> str:
    if not isinstance(value, str):
        raise UrlPolicyError("URL必须是字符串")
    if value != value.strip() or not value or len(value) > MAX_URL_LENGTH or has_control(value):
        raise UrlPolicyError("URL为空、过长、含空白边界或控制字符")
    if any(marker in value for marker in ("{", "}", "${", "{{")):
        raise UrlPolicyError("URL不得包含模板占位符")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise UrlPolicyError("URL无法解析") from exc
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
        raise UrlPolicyError("URL必须为无userinfo的HTTPS")
    if parsed.fragment:
        raise UrlPolicyError("URL不得包含fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UrlPolicyError("URL端口非法") from exc
    if port not in (None, 443):
        raise UrlPolicyError("URL仅允许默认HTTPS端口")
    host = _canonical_host(parsed.hostname or "")
    path, parts = _canonical_path(parsed.path)
    _validate_query(parsed.query)
    if host in {"raw.githubusercontent.com", "github.com", "cdn.jsdelivr.net"}:
        if parsed.query:
            raise UrlPolicyError("GitHub/jsDelivr文件URL不得包含query")
        _github_identity(host, parts)
    elif host in PROXY_HOSTS:
        if parsed.query:
            raise UrlPolicyError("GitHub proxy URL不得包含query")
        _proxy_identity(host, parts)
    canonical = urlunsplit(("https", host, path, parsed.query, ""))
    if len(canonical) > MAX_URL_LENGTH:
        raise UrlPolicyError("canonical URL过长")
    return canonical


def repository_key_for_url(value: str) -> str | None:
    canonical = canonicalize_url(value)
    parsed = urlsplit(canonical)
    host = parsed.hostname or ""
    _, parts = _canonical_path(parsed.path)
    identity = _github_identity(host, parts)
    if identity is not None:
        return identity
    identity = _proxy_identity(host, parts)
    if identity is not None:
        return identity
    return _other_repository_identity(host, parts)


def _github_resource_parts(host: str, parts: list[str]):
    if host == "raw.githubusercontent.com":
        ref, file_parts = _split_ref(parts, 2)
        return parts[0], parts[1], ref, file_parts
    if host == "github.com":
        ref, file_parts = _split_ref(parts, 3)
        return parts[0], parts[1], ref, file_parts
    if host == "cdn.jsdelivr.net":
        repo, ref = parts[2].split("@", 1)
        return parts[1], repo, ref, parts[3:]
    if host in PROXY_HOSTS:
        if len(parts) > 2 and parts[:3] == ["https:", "", "raw.githubusercontent.com"]:
            nested = parts[3:]
            ref, file_parts = _split_ref(nested, 2)
            return nested[0], nested[1], ref, file_parts
        if parts and parts[0] == "raw.githubusercontent.com":
            nested = parts[1:]
            ref, file_parts = _split_ref(nested, 2)
            return nested[0], nested[1], ref, file_parts
        if len(parts) > 2 and parts[:3] == ["https:", "", "github.com"]:
            nested = parts[3:]
            ref, file_parts = _split_ref(nested, 3)
            return nested[0], nested[1], ref, file_parts
    return None


def resource_key_for_url(value: str) -> str:
    canonical = canonicalize_url(value)
    parsed = urlsplit(canonical)
    host = parsed.hostname or ""
    _, parts = _canonical_path(parsed.path)
    github_resource = _github_resource_parts(host, parts)
    if github_resource is None:
        return canonical
    owner, repo, ref, file_parts = github_resource
    return "github-resource:" + owner.casefold() + "/" + repo.casefold() + "@" + ref.casefold() + "/" + "/".join(file_parts)


def is_repository_seed(value: str) -> bool:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise UrlPolicyError("repository seed格式无效")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise UrlPolicyError("repository seed无法解析") from exc
    if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        return False
    try:
        if parsed.port not in (None, 443):
            return False
    except ValueError:
        return False
    host = _canonical_host(parsed.hostname or "")
    _, parts = _canonical_path(parsed.path)
    if any(not part for part in parts):
        return False
    if host == "github.com":
        return len(parts) == 2 and all(GITHUB_NAME_RE.fullmatch(part) for part in parts)
    if host == "gitlab.com":
        return len(parts) >= 2 and "-" not in parts and all(REPOSITORY_PART_RE.fullmatch(part) for part in parts)
    if host in {"gitee.com", "codeberg.org"}:
        return len(parts) == 2 and all(REPOSITORY_PART_RE.fullmatch(part) for part in parts)
    return False
