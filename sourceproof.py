#!/usr/bin/env python3
"""SourceProof: citation-backed verification of claims against official webpages."""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, wait
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

VERSION = "0.1.1"
USER_AGENT = "SourceProof/0.1.1 (+https://github.com/frenzoblings57-dot/sourceproof)"
MAX_URLS = 10
MAX_BODY = 2_000_000
FETCH_TIMEOUT = 8  # per network operation; the request-wide cap is TOTAL_DEADLINE
TOTAL_DEADLINE = float(os.environ.get("SOURCEPROOF_DEADLINE", "8"))  # whole /v1/verify call; gateways give up near 10s
MAX_REDIRECTS = 5
MAX_REQUEST_BODY = 50_000
MAX_INFLIGHT = 64  # concurrent /v1/verify calls before answering 429

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9'-]{1,}")


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.title: list[str] = []
        self._in_script = False
        self._in_style = False
        self._in_title = False

    def handle_starttag(self, tag: str, attrs):
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"}:
            self._in_script = True
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"}:
            self._in_script = False
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str):
        if self._in_script or self._in_style:
            return
        clean = " ".join(data.split())
        if not clean:
            return
        if self._in_title:
            self.title.append(clean)
        self.parts.append(clean)


def tokens(text: str) -> set[str]:
    return set(TOKEN_RE.findall(text.lower()))


class RequestError(ValueError):
    """Client error that maps to a documented error code."""

    code = "invalid_request"


class SourceURLError(RequestError):
    """A source URL is malformed or points at a non-public address."""

    code = "private_or_invalid_url"


class SourceResolveError(Exception):
    """A source host does not resolve. Reported per source, never fatal."""


class SourceFetchError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def is_public_address(address) -> bool:
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


def resolve_public_ips(host: str, port: int | None = None) -> list[str]:
    """Resolve a host and return its addresses only if every one is public."""
    if host.lower().rstrip(".") in {"localhost", "localhost.localdomain"}:
        raise SourceURLError("private, local, or reserved hosts are not accepted")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise SourceResolveError("source host could not be resolved") from None
    ips = []
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not is_public_address(address):
            raise SourceURLError("private, local, or reserved hosts are not accepted")
        ips.append(str(address))
    if not ips:
        raise SourceResolveError("source host could not be resolved")
    return ips


def validate_url_syntax(value) -> str:
    """Cheap checks with no network access."""
    if not isinstance(value, str) or len(value) > 2048:
        raise SourceURLError("each source must be a URL of at most 2048 characters")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SourceURLError("only http and https source URLs are accepted")
    if parsed.username or parsed.password:
        raise SourceURLError("credential-bearing URLs are not accepted")
    return value


def validate_url(value) -> str:
    validate_url_syntax(value)
    resolve_public_ips(urlparse(value).hostname)
    return value


# The request deadline travels with the worker thread so connects and
# redirects can stop early instead of lingering after the response is sent.
_local = threading.local()


def _remaining() -> float | None:
    deadline = getattr(_local, "deadline", None)
    if deadline is None:
        return None
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("source fetch exceeded the request deadline")
    return left


def _bounded(timeout):
    left = _remaining()
    if left is None:
        return timeout
    return left if not timeout else min(timeout, left)


# Connections re-check the address at connect time and dial the checked IP
# directly, so a DNS answer cannot change between validation and use
# (DNS rebinding). Redirects open new connections, so every hop is covered.
class PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        ip = resolve_public_ips(self.host, self.port)[0]
        self.sock = socket.create_connection((ip, self.port), _bounded(self.timeout), self.source_address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        ip = resolve_public_ips(self.host, self.port)[0]
        raw = socket.create_connection((ip, self.port), _bounded(self.timeout), self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class PinnedHTTPHandler(HTTPHandler):
    def http_open(self, req):
        return self.do_open(PinnedHTTPConnection, req)


class PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self):
        super().__init__(context=ssl.create_default_context())

    def https_open(self, req):
        return self.do_open(PinnedHTTPSConnection, req, context=self._context)


class CheckedRedirectHandler(HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _remaining()
        parsed = urlparse(newurl)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise SourceURLError("redirect to a non-http(s) or credential-bearing URL was blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = build_opener(
    ProxyHandler({}),  # never route through an environment proxy
    PinnedHTTPHandler(),
    PinnedHTTPSHandler(),
    CheckedRedirectHandler(),
)

TEXT_TYPES = {
    "application/xhtml+xml", "application/xml", "application/json", "application/ld+json",
    "application/rss+xml", "application/atom+xml",
}


def is_text_type(content_type: str) -> bool:
    kind = content_type.split(";", 1)[0].strip().lower()
    return kind == "" or kind.startswith("text/") or kind in TEXT_TYPES or kind.endswith(("+xml", "+json"))


def fetch_source(url: str, deadline: float | None = None) -> dict:
    _local.deadline = deadline
    try:
        started = time.time()
        request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1"})
        with OPENER.open(request, timeout=FETCH_TIMEOUT) as response:
            content_type = response.headers.get("Content-Type", "")
            if not is_text_type(content_type):
                raise SourceFetchError("unsupported_content_type", f"source is {content_type.split(';', 1)[0].strip()}, not text or HTML")
            parts, total = [], 0
            while total <= MAX_BODY:
                _remaining()
                chunk = response.read(min(65536, MAX_BODY + 1 - total))
                if not chunk:
                    break
                parts.append(chunk)
                total += len(chunk)
            raw = b"".join(parts)[:MAX_BODY]
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                body = raw.decode(charset, errors="replace")
            except LookupError:
                body = raw.decode("utf-8", errors="replace")
            parser = TextExtractor()
            parser.feed(body)
            text = " ".join(parser.parts)
            return {
                "url": url,
                "status": getattr(response, "status", 200),
                "content_type": content_type,
                "title": " ".join(parser.title)[:300],
                "text": text[:200_000],
                "retrieved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "latency_ms": round((time.time() - started) * 1000),
            }
    finally:
        _local.deadline = None


def error_info(exc: BaseException) -> tuple[str, str]:
    """Stable machine-readable code plus a short message for source_errors."""
    message = str(exc)[:240] or type(exc).__name__
    if isinstance(exc, SourceFetchError):
        return exc.code, message
    if isinstance(exc, SourceResolveError):
        return "unresolvable_host", message
    if isinstance(exc, SourceURLError):
        return "blocked_url", message
    if isinstance(exc, HTTPError):
        return f"http_{exc.code}", message
    if isinstance(exc, URLError) and isinstance(exc.reason, BaseException):
        if isinstance(exc.reason, SourceResolveError):
            return "unresolvable_host", str(exc.reason)
        if isinstance(exc.reason, TimeoutError):
            return "timeout", "source did not respond in time"
        return "connection_failed", message
    if isinstance(exc, TimeoutError):
        return "timeout", "source did not respond in time"
    return "fetch_failed", message


def evidence_for_claim(claim: str, source: dict) -> dict:
    claim_terms = tokens(claim)
    source_terms = tokens(source.get("text", ""))
    overlap = claim_terms & source_terms
    coverage = len(overlap) / max(1, len(claim_terms))
    lowered = source.get("text", "").lower()
    negated = any(marker in lowered for marker in ("not true", "false claim", "denied", "no evidence that"))
    if coverage >= 0.60 and not negated:
        verdict = "supports"
    elif negated and coverage >= 0.35:
        verdict = "contradicts"
    else:
        verdict = "unclear"
    words = claim.split()
    anchor = " ".join(words[: min(8, len(words))]).lower()
    position = lowered.find(anchor) if anchor else -1
    if position < 0 and overlap:
        position = min((lowered.find(term) for term in overlap if lowered.find(term) >= 0), default=0)
    snippet = source.get("text", "")[max(0, position - 140): position + 360].strip() if source.get("text") else ""
    return {
        "url": source["url"],
        "title": source.get("title", ""),
        "verdict": verdict,
        "matched_terms": sorted(overlap),
        "coverage": round(coverage, 3),
        "quote": snippet[:500],
        "retrieved_at": source.get("retrieved_at"),
    }


def verify(payload: dict, deadline_seconds: float | None = None) -> dict:
    if not isinstance(payload, dict):
        raise RequestError("JSON object required")
    claim = payload.get("claim")
    sources = payload.get("sources")
    if not isinstance(claim, str) or not claim.strip() or len(claim) > 1000:
        raise RequestError("claim must be a non-empty string of at most 1000 characters")
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_URLS:
        raise RequestError(f"sources must contain 1 to {MAX_URLS} URLs")
    urls = list(dict.fromkeys(validate_url_syntax(item) for item in sources))
    deadline = time.monotonic() + (TOTAL_DEADLINE if deadline_seconds is None else deadline_seconds)
    failures: dict[str, BaseException] = {}
    fetched: dict[str, dict] = {}
    timed_out = TimeoutError("source did not respond within the request deadline")

    # Sources are checked and fetched in parallel under one shared deadline,
    # so ten slow sources cost about 8 seconds in total, not 80.
    pool = ThreadPoolExecutor(max_workers=len(urls), thread_name_prefix="source")
    try:
        checks = {pool.submit(resolve_public_ips, urlparse(url).hostname): url for url in urls}
        done, pending = wait(checks, timeout=max(0.0, deadline - time.monotonic()))
        for future, url in checks.items():
            if future in pending:
                failures[url] = timed_out
                continue
            try:
                future.result()
            except SourceURLError:
                raise  # a private or reserved address is a client error for the whole request
            except Exception as exc:
                failures[url] = exc
        todo = [url for url in urls if url not in failures]
        jobs = {pool.submit(fetch_source, url, deadline): url for url in todo}
        done, pending = wait(jobs, timeout=max(0.0, deadline - time.monotonic()))
        for future, url in jobs.items():
            if future in pending:
                failures[url] = timed_out
                continue
            try:
                fetched[url] = future.result()
            except Exception as exc:  # one bad source must not lose the whole verification
                failures[url] = exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    results, errors = [], []
    for url in urls:  # keep the caller's order
        if url in fetched:
            results.append(evidence_for_claim(claim, fetched[url]))
        else:
            code, message = error_info(failures[url])
            errors.append({"url": url, "code": code, "error": message})
    supports = sum(item["verdict"] == "supports" for item in results)
    contradicts = sum(item["verdict"] == "contradicts" for item in results)
    if supports and contradicts:
        verdict = "partially_supported"
    elif supports:
        verdict = "supported"
    elif contradicts:
        verdict = "contradicted"
    else:
        verdict = "insufficient_evidence"
    confidence = round(min(0.99, max(0.05, (supports + contradicts) / max(1, len(results)) * 0.8)), 2)
    return {
        "service": "SourceProof",
        "version": VERSION,
        "claim": claim,
        "verdict": verdict,
        "confidence": confidence,
        "evidence": results,
        "source_errors": errors,
        "retrieved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": "keyword coverage with citation snippets; not a substitute for human review",
    }


def _load_openapi():
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "openapi.json"), "rb") as handle:
            return json.loads(handle.read())
    except (OSError, ValueError):
        return None


OPENAPI = _load_openapi()
INFLIGHT = threading.BoundedSemaphore(MAX_INFLIGHT)
ALLOW = "GET, HEAD, POST"
CHUNK_SIZE_RE = re.compile(rb"^[0-9a-fA-F]{1,8}$")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive for the RelayMiner; every reply sets Content-Length
    server_version = "SourceProof/" + VERSION
    timeout = 15  # idle client sockets are dropped (slow-body protection)

    # -- responses ---------------------------------------------------------
    def send_json(self, status: int, payload, head: bool = False, headers: dict | None = None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        """Replace http.server's HTML error pages so every response is JSON."""
        phrase = self.responses.get(code, ("error",))[0]
        self.close_connection = True
        self.send_json(code, {"error": phrase.lower().replace(" ", "_"), "message": message or phrase},
                       head=getattr(self, "command", None) == "HEAD", headers={"Connection": "close"})

    # -- GET / HEAD --------------------------------------------------------
    def route_get(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            return 200, {"status": "ok", "service": "sourceproof", "version": VERSION}, None
        if path == "/v1/version":
            return 200, {"service": "sourceproof", "version": VERSION}, None
        if path == "/":
            return 200, {"service": "sourceproof", "name": "SourceProof", "operation": "POST /v1/verify", "docs": "/openapi.json"}, None
        if path == "/openapi.json" and OPENAPI is not None:
            return 200, OPENAPI, None
        if path == "/v1/verify":
            return 405, {"error": "method_not_allowed", "message": "use POST /v1/verify"}, {"Allow": "POST"}
        return 404, {"error": "not_found"}, None

    def do_GET(self):
        status, payload, headers = self.route_get()
        self.send_json(status, payload, headers=headers)

    def do_HEAD(self):
        status, payload, headers = self.route_get()
        self.send_json(status, payload, head=True, headers=headers)

    def method_not_allowed(self):
        self.close_connection = True
        self.send_json(405, {"error": "method_not_allowed", "message": "supported methods: " + ALLOW}, headers={"Allow": ALLOW})

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = method_not_allowed

    # -- POST --------------------------------------------------------------
    def read_body(self) -> bytes:
        """Read a request body sent with Content-Length or chunked encoding."""
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            return self.read_chunked()
        raw = self.headers.get("Content-Length")
        if raw is None:
            return b""
        if not raw.strip().isdigit():
            raise RequestError("Content-Length must be a non-negative integer")
        length = int(raw)
        if length > MAX_REQUEST_BODY:
            raise RequestError("request body is too large")
        return self.rfile.read(length)

    def read_chunked(self) -> bytes:
        parts, total = [], 0
        while True:
            line = self.rfile.readline(1024)
            if not line.endswith(b"\n"):
                raise RequestError("malformed chunked body")
            size_text = line.split(b";", 1)[0].strip()  # ignore chunk extensions
            if not CHUNK_SIZE_RE.match(size_text):
                raise RequestError("malformed chunk size")
            size = int(size_text, 16)
            if size == 0:
                for _ in range(32):  # discard optional trailers
                    if self.rfile.readline(1024) in (b"\r\n", b"\n", b""):
                        break
                return b"".join(parts)
            total += size
            if total > MAX_REQUEST_BODY:
                raise RequestError("request body is too large")
            data = self.rfile.read(size)
            if len(data) != size or self.rfile.read(2) != b"\r\n":
                raise RequestError("malformed chunked body")
            parts.append(data)

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/v1/verify":
            self.close_connection = True  # the unread body would desync keep-alive
            return self.send_json(404, {"error": "not_found"})
        if not INFLIGHT.acquire(blocking=False):
            self.close_connection = True
            return self.send_json(429, {"error": "busy", "message": "too many verifications in flight; retry shortly"},
                                  headers={"Retry-After": "1"})
        try:
            result = verify(json.loads(self.read_body()))
            return self.send_json(200, result)
        except (json.JSONDecodeError, UnicodeDecodeError):
            status, body = 400, {"error": "invalid_json", "message": "request body is not valid JSON"}
        except RequestError as exc:
            status, body = 400, {"error": exc.code, "message": str(exc)}
        except TimeoutError:
            status, body = 408, {"error": "request_timeout", "message": "request body was not received in time"}
        except Exception:
            traceback.print_exc(file=sys.stderr)
            status, body = 500, {"error": "internal_error", "message": "unexpected server error"}
        finally:
            INFLIGHT.release()
        self.close_connection = True
        self.send_json(status, body)

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))


def run(host: str = "0.0.0.0", port: int = 8080):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"SourceProof listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    run(args.host, args.port)
