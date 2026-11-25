import http.client
import json
import os
import socket
import sys
import ssl
import threading
import time
import unittest
from urllib.error import HTTPError, URLError
from http.server import ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import sourceproof

PUBLIC_IP = "93.184.216.34"


def addrinfo(*ips):
    """Fake socket.getaddrinfo so tests never touch real DNS."""
    def fake(host, port, *args, **kwargs):
        try:  # IP literals resolve to themselves, as in real life
            literal = str(__import__("ipaddress").ip_address(host))
        except ValueError:
            literal = None
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in ([literal] if literal else ips)]
    return fake


class SourceProofTests(unittest.TestCase):
    def test_private_hosts_are_rejected(self):
        with self.assertRaises(sourceproof.SourceURLError):
            sourceproof.validate_url("http://127.0.0.1:8080/health")

    def test_non_public_addresses_are_rejected(self):
        for ip in ("169.254.169.254", "10.0.0.5", "100.64.0.1", "::1", "::ffff:127.0.0.1", "224.0.0.1"):
            with self.subTest(ip=ip), patch("sourceproof.socket.getaddrinfo", addrinfo(ip)):
                with self.assertRaises(sourceproof.SourceURLError):
                    sourceproof.validate_url("https://example.com/")

    def test_mixed_public_and_private_answers_are_rejected(self):
        with patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP, "127.0.0.1")):
            with self.assertRaises(sourceproof.SourceURLError):
                sourceproof.validate_url("https://example.com/")

    def test_unresolvable_host_has_its_own_message(self):
        with patch("sourceproof.socket.getaddrinfo", side_effect=socket.gaierror):
            with self.assertRaises(sourceproof.SourceResolveError) as ctx:
                sourceproof.validate_url("https://no-such-host.invalid/")
        self.assertIn("could not be resolved", str(ctx.exception))
        self.assertNotIn("private", str(ctx.exception))

    def test_public_host_is_accepted(self):
        with patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            self.assertEqual(sourceproof.validate_url("https://example.com/"), "https://example.com/")

    def test_credentials_and_bad_schemes_are_rejected(self):
        for url in ("https://user:pw@example.com/", "ftp://example.com/", "file:///etc/passwd", "https:///x"):
            with self.subTest(url=url), self.assertRaises(sourceproof.SourceURLError):
                sourceproof.validate_url(url)

    def test_connect_time_check_blocks_rebinding(self):
        # Validation passed earlier; DNS now answers with the metadata address.
        conn = sourceproof.PinnedHTTPConnection("example.com", 80, timeout=1)
        with patch("sourceproof.socket.getaddrinfo", addrinfo("169.254.169.254")):
            with self.assertRaises(sourceproof.SourceURLError):
                conn.connect()

    def test_connect_dials_the_checked_ip(self):
        conn = sourceproof.PinnedHTTPConnection("example.com", 80, timeout=1)
        with patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)), \
                patch("sourceproof.socket.create_connection") as dial:
            conn.connect()
        self.assertEqual(dial.call_args[0][0], (PUBLIC_IP, 80))

    def test_redirects_to_other_schemes_are_blocked(self):
        handler = sourceproof.CheckedRedirectHandler()
        req = sourceproof.Request("https://example.com/")
        for target in ("ftp://example.com/x", "file:///etc/passwd", "https://u:p@example.com/"):
            with self.subTest(target=target), self.assertRaises(sourceproof.SourceURLError):
                handler.redirect_request(req, None, 302, "Found", {}, target)

    def test_invalid_request_is_rejected(self):
        with self.assertRaises(sourceproof.RequestError):
            sourceproof.verify({"claim": "hello", "sources": []})

    @patch("sourceproof.fetch_source")
    def test_supported_claim_returns_evidence(self, fetch):
        fetch.return_value = {
            "url": "https://example.com",
            "title": "Official page",
            "text": "Pocket Network publishes data services for AI agents.",
            "retrieved_at": "2026-11-23T00:00:00Z",
        }
        with patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            result = sourceproof.verify({
                "claim": "Pocket Network publishes data services for AI agents",
                "sources": ["https://example.com"],
            })
        self.assertEqual(result["verdict"], "supported")
        self.assertEqual(len(result["evidence"]), 1)
        self.assertGreater(result["evidence"][0]["coverage"], 0.5)

    def test_source_errors_do_not_hide_valid_results(self):
        def fake(url, deadline=None):
            if "bad" in url:
                raise RuntimeError("boom")
            return {"url": url, "title": "", "text": "The claim is true", "retrieved_at": "now"}
        with patch("sourceproof.fetch_source", side_effect=fake), patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            result = sourceproof.verify({"claim": "The claim is true", "sources": ["https://bad.example.com", "https://ok.example.org"]})
        self.assertEqual(result["verdict"], "supported")
        self.assertEqual([e["url"] for e in result["source_errors"]], ["https://bad.example.com"])
        self.assertEqual(result["source_errors"][0]["code"], "fetch_failed")

    def test_unresolvable_source_is_reported_not_fatal(self):
        with patch("sourceproof.socket.getaddrinfo", side_effect=socket.gaierror):
            result = sourceproof.verify({"claim": "anything here", "sources": ["https://no-such-host.invalid/"]})
        self.assertEqual(result["verdict"], "insufficient_evidence")
        self.assertEqual(result["source_errors"][0]["code"], "unresolvable_host")

    def test_private_source_still_fails_the_whole_request(self):
        with patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            with self.assertRaises(sourceproof.SourceURLError):
                sourceproof.verify({"claim": "a b", "sources": ["https://example.com/", "http://127.0.0.1/"]})

    def test_sources_run_in_parallel(self):
        def slow(url, deadline=None):
            time.sleep(0.5)
            return {"url": url, "title": "", "text": "claim text", "retrieved_at": "now"}
        urls = [f"https://s{i}.example.com/" for i in range(10)]
        with patch("sourceproof.fetch_source", side_effect=slow), patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            started = time.monotonic()
            result = sourceproof.verify({"claim": "claim text", "sources": urls})
        self.assertLess(time.monotonic() - started, 2.0)  # serial would be 5s
        self.assertEqual(len(result["evidence"]), 10)

    def test_total_deadline_caps_slow_sources(self):
        def hang(url, deadline=None):
            time.sleep(3)
        with patch("sourceproof.fetch_source", side_effect=hang), patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            started = time.monotonic()
            result = sourceproof.verify({"claim": "a b", "sources": ["https://slow.example.com/"]}, deadline_seconds=0.4)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(result["source_errors"][0]["code"], "timeout")

    def test_duplicate_sources_are_fetched_once(self):
        calls = []
        def fake(url, deadline=None):
            calls.append(url)
            return {"url": url, "title": "", "text": "x y", "retrieved_at": "now"}
        with patch("sourceproof.fetch_source", side_effect=fake), patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            sourceproof.verify({"claim": "x y", "sources": ["https://a.example.com/"] * 3})
        self.assertEqual(len(calls), 1)

    def test_error_codes(self):
        self.assertEqual(sourceproof.error_info(HTTPError("u", 404, "Not Found", {}, None))[0], "http_404")
        self.assertEqual(sourceproof.error_info(URLError(TimeoutError()))[0], "timeout")
        self.assertEqual(sourceproof.error_info(URLError(ConnectionRefusedError()))[0], "connection_failed")
        self.assertEqual(sourceproof.error_info(sourceproof.SourceURLError("x"))[0], "blocked_url")

    def test_binary_content_types_are_skipped(self):
        for ok in ("text/html; charset=utf-8", "application/json", "application/xhtml+xml", ""):
            self.assertTrue(sourceproof.is_text_type(ok), ok)
        for bad in ("application/pdf", "image/png", "application/octet-stream"):
            self.assertFalse(sourceproof.is_text_type(bad), bad)


class PortAndAddressTests(unittest.TestCase):
    def test_only_ports_80_and_443_are_accepted(self):
        for url in ("http://github.com:22/", "https://example.com:8443/", "http://example.com:25/", "http://example.com:8080/x"):
            with self.subTest(url=url), self.assertRaises(sourceproof.SourceURLError):
                sourceproof.validate_url_syntax(url)
        for url in ("http://example.com/", "https://example.com/", "http://example.com:80/", "https://example.com:443/x", "https://example.com:80/"):
            with self.subTest(url=url):
                self.assertEqual(sourceproof.validate_url_syntax(url), url)

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(sourceproof.SourceURLError):
            sourceproof.validate_url_syntax("http://example.com:99999/")

    def test_connect_time_port_check_runs_before_any_dns(self):
        for cls in (sourceproof.PinnedHTTPConnection, sourceproof.PinnedHTTPSConnection):
            conn = cls("github.com", 22, timeout=1)
            with patch("sourceproof.socket.getaddrinfo", side_effect=AssertionError("DNS must not run")):
                with self.assertRaises(sourceproof.SourceURLError):
                    conn.connect()

    def test_redirect_to_a_disallowed_port_is_blocked(self):
        handler = sourceproof.CheckedRedirectHandler()
        req = sourceproof.Request("https://example.com/")
        for target in ("http://github.com:22/", "https://example.com:8443/", "http://example.com:3306/"):
            with self.subTest(target=target), self.assertRaises(sourceproof.SourceURLError):
                handler.redirect_request(req, None, 302, "Found", {}, target)

    def test_redirect_to_standard_ports_is_followed(self):
        handler = sourceproof.CheckedRedirectHandler()
        req = sourceproof.Request("https://example.com/")
        new = handler.redirect_request(req, None, 302, "Found", {}, "https://other.example.org/next")
        self.assertEqual(new.full_url, "https://other.example.org/next")

    def test_blocked_networks_setting(self):
        nets = sourceproof.parse_blocked_networks("135.181.248.55, 10.9.0.0/16;2001:db8::1")
        self.assertEqual(len(nets), 3)
        with patch.object(sourceproof, "BLOCKED_NETWORKS", nets):
            for ip in ("135.181.248.55", "10.9.4.4", "::ffff:135.181.248.55"):
                with self.subTest(ip=ip), patch("sourceproof.socket.getaddrinfo", addrinfo(ip)):
                    with self.assertRaises(sourceproof.SourceURLError):
                        sourceproof.resolve_public_ips("example.com")
            with patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
                self.assertEqual(sourceproof.resolve_public_ips("example.com"), [PUBLIC_IP])

    def test_blocked_networks_bad_entry_fails_fast(self):
        with self.assertRaises(ValueError):
            sourceproof.parse_blocked_networks("not-an-ip")
        self.assertEqual(sourceproof.parse_blocked_networks(""), [])

    def test_nat64_and_6to4_are_rejected(self):
        for ip in ("64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:7f00:1::1"):
            with self.subTest(ip=ip), patch("sourceproof.socket.getaddrinfo", addrinfo(ip)):
                with self.assertRaises(sourceproof.SourceURLError):
                    sourceproof.resolve_public_ips("example.com")


class ErrorMessageTests(unittest.TestCase):
    def test_raw_exception_text_never_leaks(self):
        secret = "SECRET-/etc/internal 10.0.0.9"
        for exc in (RuntimeError(secret), OSError(secret), URLError(OSError(secret)), ValueError(secret),
                    sourceproof.SourceFetchError("unsupported_content_type", secret)):
            with self.subTest(exc=type(exc).__name__):
                code, message = sourceproof.error_info(exc)
                self.assertNotIn("SECRET", message)
                self.assertNotIn("10.0.0.9", message)
                self.assertTrue(message)

    def test_http_errors_report_only_the_status(self):
        code, message = sourceproof.error_info(HTTPError("http://x/secret-path", 503, "Unavailable SECRET", {}, None))
        self.assertEqual((code, message), ("http_503", "source returned HTTP 503"))

    def test_blocked_redirect_inside_urlerror_is_blocked_url(self):
        self.assertEqual(sourceproof.error_info(URLError(sourceproof.SourceURLError("x")))[0], "blocked_url")

    @patch("sourceproof.fetch_source", side_effect=RuntimeError("SECRET-internal-detail"))
    def test_verify_response_has_fixed_messages(self, _fetch):
        with patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            result = sourceproof.verify({"claim": "a b", "sources": ["https://example.com/"]})
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(result["source_errors"][0]["error"], sourceproof.ERROR_MESSAGES["fetch_failed"])


class SlowServer:
    """Loopback server that misbehaves on purpose. The SSRF guard is patched open for it."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.conns = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        self.sock.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.conns.append(conn)
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        try:
            if self.behaviour == "silent":  # accepts and never speaks: a stalled TLS server
                self.stop.wait(15)
                return
            conn.settimeout(3)
            conn.recv(4096)
            if self.behaviour == "slow_headers":
                for byte in b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello":
                    conn.sendall(bytes([byte]))
                    time.sleep(0.5)
            elif self.behaviour == "slow_body":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
                for _ in range(40):
                    conn.sendall(b"x")
                    time.sleep(0.5)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.sock.close()
        for conn in self.conns:
            conn.close()


class DeadlineEnforcementTests(unittest.TestCase):
    def fetch(self, behaviour, scheme="http", deadline=1.0):
        server = SlowServer(behaviour)
        self.addCleanup(server.close)
        patches = (
            patch.object(sourceproof, "ALLOWED_PORTS", {server.port}),
            patch("sourceproof.resolve_public_ips", return_value=["127.0.0.1"]),
        )
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        started = time.monotonic()
        with self.assertRaises(Exception) as ctx:
            sourceproof.fetch_source(f"{scheme}://127.0.0.1:{server.port}/", time.monotonic() + deadline)
        return time.monotonic() - started, ctx.exception

    def test_slow_drip_body_is_cut_off_at_the_deadline(self):
        elapsed, exc = self.fetch("slow_body")  # a full body would take 20s
        self.assertLess(elapsed, 2.0)
        self.assertIsInstance(exc, TimeoutError)  # not a truncated "success"

    def test_slow_headers_are_cut_off_at_the_deadline(self):
        elapsed, exc = self.fetch("slow_headers")  # headers alone would take ~15s
        self.assertLess(elapsed, 2.0)
        self.assertIsInstance(exc, TimeoutError)

    def test_stalled_tls_handshake_is_cut_off_at_the_deadline(self):
        elapsed, exc = self.fetch("silent", scheme="https")
        self.assertLess(elapsed, 2.0)
        self.assertIsInstance(exc, TimeoutError)

    def test_a_cut_off_worker_is_freed_for_the_next_request(self):
        # One worker only: if the slow fetch kept its thread, the next request could not run.
        server = SlowServer("slow_headers")  # only the reaper can end this one early
        self.addCleanup(server.close)
        with patch.object(sourceproof, "POOL", ThreadPoolExecutor(max_workers=1)), \
                patch.object(sourceproof, "ALLOWED_PORTS", {server.port, 80, 443}), \
                patch("sourceproof.resolve_public_ips", return_value=["127.0.0.1"]):
            first = sourceproof.verify({"claim": "a b", "sources": [f"http://127.0.0.1:{server.port}/"]}, deadline_seconds=0.8)
            self.assertEqual(first["source_errors"][0]["code"], "timeout")
            fast = {"url": "https://ok.example.com/", "title": "", "text": "claim text", "retrieved_at": "now"}
            with patch("sourceproof.fetch_source", return_value=fast), patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)), \
                    patch("sourceproof.resolve_public_ips", return_value=[PUBLIC_IP]):
                started = time.monotonic()
                second = sourceproof.verify({"claim": "claim text", "sources": ["https://ok.example.com/"]}, deadline_seconds=1.5)
            self.assertLess(time.monotonic() - started, 1.2)
            self.assertEqual(second["verdict"], "supported")

    def test_verify_reports_the_slow_page_as_a_timeout(self):
        server = SlowServer("slow_body")
        self.addCleanup(server.close)
        with patch.object(sourceproof, "ALLOWED_PORTS", {server.port}), \
                patch("sourceproof.resolve_public_ips", return_value=["127.0.0.1"]):
            started = time.monotonic()
            result = sourceproof.verify({"claim": "a b", "sources": [f"http://127.0.0.1:{server.port}/"]}, deadline_seconds=1.0)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(result["source_errors"][0]["code"], "timeout")


class ThreadCapTests(unittest.TestCase):
    def test_concurrent_fetches_never_exceed_the_pool_cap(self):
        running, peak, lock = 0, 0, threading.Lock()

        def fake(url, deadline=None):
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
            time.sleep(0.15)
            with lock:
                running -= 1
            return {"url": url, "title": "", "text": "claim text", "retrieved_at": "now"}

        urls = [f"https://s{i}.example.com/" for i in range(10)]
        with patch.object(sourceproof, "POOL", ThreadPoolExecutor(max_workers=3)), \
                patch("sourceproof.fetch_source", side_effect=fake), patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            result = sourceproof.verify({"claim": "claim text", "sources": urls}, deadline_seconds=5)
        self.assertLessEqual(peak, 3)
        self.assertEqual(len(result["evidence"]), 10)

    def test_saturated_pool_still_returns_by_the_deadline(self):
        def hang(url, deadline=None):
            time.sleep(1.5)
            return {"url": url, "title": "", "text": "claim text", "retrieved_at": "now"}

        urls = [f"https://s{i}.example.com/" for i in range(6)]
        with patch.object(sourceproof, "POOL", ThreadPoolExecutor(max_workers=1)), \
                patch("sourceproof.fetch_source", side_effect=hang), patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            started = time.monotonic()
            result = sourceproof.verify({"claim": "claim text", "sources": urls}, deadline_seconds=0.5)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(len(result["source_errors"]), 6)
        self.assertTrue(all(e["code"] == "timeout" for e in result["source_errors"]))


class HttpContractTests(unittest.TestCase):
    """Documented error codes, checked over a real socket."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), sourceproof.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, body):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/v1/verify", body=body, headers={"Content-Type": "application/json"})
        res = conn.getresponse()
        data = json.loads(res.read())
        conn.close()
        return res.status, data

    def test_invalid_json(self):
        status, data = self.post(b"not json")
        self.assertEqual((status, data["error"]), (400, "invalid_json"))

    def test_bad_utf8_is_invalid_json(self):
        status, data = self.post(b"\xff\xfe")
        self.assertEqual((status, data["error"]), (400, "invalid_json"))

    def test_invalid_request(self):
        status, data = self.post(json.dumps({"claim": "", "sources": []}).encode())
        self.assertEqual((status, data["error"]), (400, "invalid_request"))

    def test_private_url(self):
        status, data = self.post(json.dumps({"claim": "a b", "sources": ["http://127.0.0.1/"]}).encode())
        self.assertEqual((status, data["error"]), (400, "private_or_invalid_url"))

    def test_not_found_is_json(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/nope")
        res = conn.getresponse()
        self.assertEqual(res.status, 404)
        self.assertEqual(json.loads(res.read())["error"], "not_found")


    # -- chunked request bodies (what real relays send) ---------------------
    def raw(self, data: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            out = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    return out
                out += chunk

    def chunked(self, body: bytes, pieces=2, ext=b"", trailer=b"") -> bytes:
        step = max(1, len(body) // pieces)
        out = b""
        for i in range(0, len(body), step):
            piece = body[i:i + step]
            out += b"%x%s\r\n%s\r\n" % (len(piece), ext, piece)
        return (b"POST /v1/verify HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
                b"Content-Type: application/json\r\n\r\n" + out + b"0\r\n" + trailer + b"\r\n")

    def test_chunked_body_is_accepted(self):
        body = json.dumps({"claim": "", "sources": []}).encode()  # reaches validation, so parsing succeeded
        reply = self.raw(self.chunked(body, pieces=3))
        self.assertIn(b"400", reply.split(b"\r\n", 1)[0])
        self.assertIn(b'"invalid_request"', reply)  # not invalid_json

    def test_chunked_extensions_and_trailers(self):
        body = json.dumps({"claim": "", "sources": []}).encode()
        reply = self.raw(self.chunked(body, ext=b";note=1", trailer=b"X-Sum: 1\r\n"))
        self.assertIn(b'"invalid_request"', reply)

    def test_chunked_full_verify(self):
        with patch("sourceproof.fetch_source", return_value={"url": "https://example.com/", "title": "", "text": "hello world", "retrieved_at": "now"}), \
                patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            body = json.dumps({"claim": "hello world", "sources": ["https://example.com/"]}).encode()
            reply = self.raw(self.chunked(body, pieces=4))
        self.assertIn(b"200 OK", reply.split(b"\r\n", 1)[0])
        self.assertIn(b'"verdict": "supported"', reply)

    def test_malformed_chunked_bodies(self):
        head = b"POST /v1/verify HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        for bad in (b"zz\r\nabc\r\n0\r\n\r\n", b"5\r\nabc\r\n", b"-1\r\n\r\n", b"ffffffff\r\n"):
            with self.subTest(bad=bad):
                reply = self.raw(head + bad)
                self.assertIn(b"400", reply.split(b"\r\n", 1)[0])
                self.assertIn(b'"invalid_request"', reply)

    def test_oversized_chunked_body(self):
        head = b"POST /v1/verify HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        reply = self.raw(head + b"%x\r\n" % (sourceproof.MAX_REQUEST_BODY + 1))
        self.assertIn(b"too large", reply)

    # -- HEAD and other methods ---------------------------------------------
    def test_head_returns_200_with_headers_and_no_body(self):
        for path in ("/", "/health", "/v1/version", "/openapi.json"):
            with self.subTest(path=path):
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
                conn.request("HEAD", path)
                res = conn.getresponse()
                self.assertEqual(res.status, 200)
                self.assertIn("application/json", res.getheader("Content-Type"))
                self.assertGreater(int(res.getheader("Content-Length")), 0)
                self.assertEqual(res.read(), b"")
                conn.close()

    def test_get_root_and_openapi_are_json_objects(self):
        for path in ("/", "/openapi.json", "/health", "/v1/version"):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", path)
            res = conn.getresponse()
            self.assertEqual(res.status, 200, path)
            self.assertIsInstance(json.loads(res.read()), dict)
            conn.close()

    def test_wrong_methods_get_json_405(self):
        for method, path in (("GET", "/v1/verify"), ("PUT", "/"), ("DELETE", "/health")):
            with self.subTest(method=method, path=path):
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
                conn.request(method, path)
                res = conn.getresponse()
                self.assertEqual(res.status, 405)
                self.assertTrue(res.getheader("Allow"))
                self.assertEqual(json.loads(res.read())["error"], "method_not_allowed")
                conn.close()

    def test_protocol_errors_are_json_not_html(self):
        reply = self.raw(b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")  # 414
        self.assertIn(b"application/json", reply)
        self.assertNotIn(b"<html", reply.lower())
        for junk in (b"NONSENSE\r\n\r\n", b"GET / BADPROTO\r\n\r\n"):  # HTTP/0.9 fallback: body only
            self.assertIsInstance(json.loads(self.raw(junk)), dict)

    def test_keep_alive_reuses_the_connection(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        for _ in range(3):
            conn.request("GET", "/health")
            res = conn.getresponse()
            self.assertEqual(res.status, 200)
            res.read()
        conn.close()

    # -- failure behaviour --------------------------------------------------
    def test_unexpected_error_is_500_without_details(self):
        with patch("sourceproof.verify", side_effect=RuntimeError("secret internals")):
            status, data = self.post(json.dumps({"claim": "a b", "sources": ["https://example.com"]}).encode())
        self.assertEqual((status, data["error"]), (500, "internal_error"))
        self.assertNotIn("secret", json.dumps(data))

    def test_busy_server_answers_429(self):
        with patch("sourceproof.INFLIGHT", threading.BoundedSemaphore(0)):
            status, data = self.post(json.dumps({"claim": "a b", "sources": ["https://example.com"]}).encode())
        self.assertEqual((status, data["error"]), (429, "busy"))

    def test_failing_source_is_200_with_source_errors(self):
        def boom(url, deadline=None):
            raise URLError(ConnectionRefusedError())
        with patch("sourceproof.fetch_source", side_effect=boom), patch("sourceproof.socket.getaddrinfo", addrinfo(PUBLIC_IP)):
            status, data = self.post(json.dumps({"claim": "a b", "sources": ["https://down.example.com"]}).encode())
        self.assertEqual(status, 200)
        self.assertEqual(data["source_errors"][0]["code"], "connection_failed")


if __name__ == "__main__":
    unittest.main()
