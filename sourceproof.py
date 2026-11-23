#!/usr/bin/env python3
"""SourceProof: citation-backed verification of claims against official webpages."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen

VERSION = "0.1.0"
USER_AGENT = "SourceProof/0.1 (+https://github.com/frenzoblings57-dot/sourceproof)"
MAX_URLS = 10
MAX_BODY = 2_000_000
FETCH_TIMEOUT = 8

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


def is_private_host(host: str) -> bool:
    if host.lower() in {"localhost", "localhost.localdomain"}:
        return True
    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for item in addresses:
        address = ipaddress.ip_address(item[4][0])
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast:
            return True
    return False


def validate_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("each source must be a URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only http and https source URLs are accepted")
    if parsed.username or parsed.password:
        raise ValueError("credential-bearing URLs are not accepted")
    if is_private_host(parsed.hostname):
        raise ValueError("private, local, or reserved hosts are not accepted")
    return value


def fetch_source(url: str) -> dict:
    started = time.time()
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1"})
    with urlopen(request, timeout=FETCH_TIMEOUT) as response:
        content_type = response.headers.get("Content-Type", "")
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raw = raw[:MAX_BODY]
        charset = response.headers.get_content_charset() or "utf-8"
        body = raw.decode(charset, errors="replace")
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


def verify(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("JSON object required")
    claim = payload.get("claim")
    sources = payload.get("sources")
    if not isinstance(claim, str) or not claim.strip() or len(claim) > 1000:
        raise ValueError("claim must be a non-empty string of at most 1000 characters")
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_URLS:
        raise ValueError(f"sources must contain 1 to {MAX_URLS} URLs")
    urls = [validate_url(item) for item in sources]
    results = []
    errors = []
    for url in urls:
        try:
            results.append(evidence_for_claim(claim, fetch_source(url)))
        except Exception as exc:  # keep one bad source from losing the whole verification
            errors.append({"url": url, "error": str(exc)[:240]})
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


class Handler(BaseHTTPRequestHandler):
    server_version = "SourceProof/" + VERSION

    def send_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {"ok": True, "service": "SourceProof", "version": VERSION})
        if self.path == "/":
            return self.send_json(200, {"service": "SourceProof", "operation": "POST /v1/verify", "docs": "/openapi.json"})
        if self.path == "/openapi.json":
            try:
                with open("openapi.json", "rb") as handle:
                    body = handle.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            except OSError:
                pass
        self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/v1/verify":
            return self.send_json(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 50_000:
                raise ValueError("request body is too large")
            payload = json.loads(self.rfile.read(length))
            self.send_json(200, verify(payload))
        except ValueError as exc:
            self.send_json(400, {"error": "invalid_request", "message": str(exc)})
        except json.JSONDecodeError:
            self.send_json(400, {"error": "invalid_json"})
        except Exception as exc:
            self.send_json(502, {"error": "upstream_failure", "message": str(exc)[:240]})

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
