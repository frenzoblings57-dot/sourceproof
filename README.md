# SourceProof

SourceProof checks how well supplied webpages support a claim. It returns a support verdict, citation snippets, source timestamps, and any failed sources, so AI agents can see what the sources say before using a claim.

**What the verdict means.** The check is keyword-based. `supported` means at least 60% of the claim's words appear on a page and no negation phrase was found. It does not establish that a claim is true, and a false claim that reuses the right words can still score `supported`. Treat the citations as the evidence and the verdict as a hint.

Built for Pocket Network agent services. Proposed Beta/TestNet service ID: `sourceproof`.

## API

|Method |Path |Purpose |
|---|---|---|
|GET |`/health` |`{"status":"ok"}` readiness check |
|GET |`/v1/version` |service identity and version |
|GET |`/openapi.json` |machine-readable API contract |
|POST |`/v1/verify` |check how well 1–10 supplied webpages support a claim |

Full contract with schemas: [`openapi.json`](https://github.com/frenzoblings57-dot/sourceproof/blob/main/openapi.json). Every response, including errors, is a JSON object.

### Verify

Request:

```json
{
  "claim": "Pocket Network is an open network for data services for AI agents",
  "sources": ["https://docs.pokt.network/"]
}
```

Response:

```json
{
  "service": "SourceProof",
  "version": "0.1.2",
  "claim": "Pocket Network is an open network for data services for AI agents",
  "verdict": "supported",
  "confidence": 0.8,
  "evidence": [
    {
      "url": "https://docs.pokt.network/",
      "title": "Pocket Network Docs",
      "verdict": "supports",
      "matched_terms": ["ai", "agents", "data", "network", "services"],
      "coverage": 1.0,
      "quote": "...data services for AI agents...",
      "retrieved_at": "2026-11-23T10:58:47Z"
    }
  ],
  "source_errors": [],
  "retrieved_at": "2026-11-23T10:58:47Z",
  "method": "keyword coverage with citation snippets; not a substitute for human review"
}
```

### Verdicts

|Verdict |Meaning |
|---|---|
|`supported` |at least one source supports the claim |
|`contradicted` |a source contains a relevant negation or denial |
|`partially_supported` |supporting and contradicting evidence are both present |
|`insufficient_evidence` |the supplied sources do not contain enough relevant evidence |

The result also reports a confidence estimate, matched terms, a short citation snippet, retrieval time, and source-level errors. SourceProof does not silently hide a failed source.

### Sources

Sources must be HTTP(S) URLs. Local, private, link-local, multicast, reserved, and credential-bearing URLs are rejected to reduce SSRF risk. A request may include up to 10 sources. Sources are fetched in parallel under one shared 8-second deadline for the whole request, so ten slow sources cost about 8 seconds, not 80. Each page is limited to 2 MB and must be text, HTML, XML, or JSON. Only ports 80 and 443 are accepted, and that rule is re-checked on every redirect hop. Redirects are followed up to 5 hops. Addresses that embed IPv4 inside IPv6 (NAT64 and 6to4) are rejected. The connection goes to the address that was checked, so DNS rebinding cannot swap in an internal one.

## Errors

|Status |Code |When |
|---|---|---|
|400 |`invalid_json` |request body is not valid JSON |
|400 |`invalid_request` |claim or sources are missing, malformed, or outside limits |
|400 |`private_or_invalid_url` |source URL is not a permitted public HTTP(S) URL |
|404 |`not_found` |path is not one of the documented operations |
|405 |`method_not_allowed` |wrong method for the path; the `Allow` header lists the right ones |
|408 |`request_timeout` |the request body was not received in time |
|429 |`busy` |too many verifications in flight; retry after the `Retry-After` seconds |
|500 |`internal_error` |unexpected server error; this should not occur |

A failed individual source never causes a 5xx. It is returned in `source_errors` with a `code` (`unresolvable_host`, `timeout`, `connection_failed`, `blocked_url`, `unsupported_content_type`, `http_<status>`, or `fetch_failed`) while the other sources are still analyzed. A source that points at a private or reserved address is the one exception: the whole request is rejected with 400 `private_or_invalid_url`.

Request bodies may be sent with `Content-Length` or chunked transfer encoding. `HEAD` works on `/`, `/health`, `/v1/version`, and `/openapi.json`. Every response, including protocol errors, is a JSON object.

## Run and test

```shell
python3 -m unittest discover -s tests -v
python3 sourceproof.py --port 8080
```

Health check:

```shell
curl http://127.0.0.1:8080/health
```

Verification request:

```shell
curl -s http://127.0.0.1:8080/v1/verify \
  -H 'content-type: application/json' \
  -d '{"claim":"Pocket Network publishes data services for AI agents","sources":["https://docs.pokt.network/"]}'
```

The repository also includes [`pocket-ready-proof.json`](./pocket-ready-proof.json), which records successful public identity, health, and verification probes.

## Production

```shell
docker build -t sourceproof:0.1.2 .
docker run --rm -p 8080:8080 \
  -e SOURCEPROOF_BLOCKED_IPS="<this server's public IP>" \
  sourceproof:0.1.2
```

Settings (environment variables):

|Variable |Default |Meaning |
|--- |--- |--- |
|`SOURCEPROOF_BLOCKED_IPS` |empty |Comma-separated IPs or CIDRs the service must never connect to. **Set this to the server's own public IP**, so callers cannot make the service connect back to its host. A bad entry stops startup. |
|`SOURCEPROOF_DEADLINE` |`8` |Total seconds for one `/v1/verify` call |
|`SOURCEPROOF_MAX_FETCH_THREADS` |`64` |Hard cap on threads fetching sources across all requests |
|`SOURCEPROOF_MAX_INFLIGHT` |`32` |Concurrent `/v1/verify` calls before the service answers 429 |

Private, loopback, link-local, and other non-public addresses are always blocked. Also keep the host firewall closed to the container's access to internal networks, so the application check is not the only layer.

The container runs as a non-root user, includes a Docker health check against `/health`, and uses Python’s standard library and has no runtime dependency on API keys or third-party services. Before production traffic, operators should add external rate limiting, structured request logging with URL privacy controls, and a cache for repeated source pages.

## Pocket service

The Pocket metadata card is [`service-card.json`](https://github.com/frenzoblings57-dot/sourceproof/blob/main/service-card.json). The deployment sequence and required owner/operator wallet inputs are documented in [`POCKET.md`](https://github.com/frenzoblings57-dot/sourceproof/blob/main/POCKET.md).

SourceProof is designed to run as a stateless REST backend behind Pocket’s HA RelayMiner. The service card defines identity, readiness, and functional probes so a supplier cannot accidentally expose the wrong backend under the `sourceproof` service ID.

## Limitations

The MVP uses transparent keyword coverage and negation markers rather than an opaque LLM judgment. It is an evidence-triage and citation tool, not a legal, medical, compliance, or final editorial determination. Agents should inspect the returned evidence before taking high-impact action.

## License

MIT
