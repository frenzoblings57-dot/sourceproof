# SourceProof

SourceProof verifies claims against current official webpages. It returns a clear verdict, citation snippets, source timestamps, and any conflicting or failed sources so AI agents can check information before using it.

Built for Pocket Network agent services. Proposed Beta/TestNet service ID: `sourceproof`.

## API

|Method |Path |Purpose |
|---|---|---|
|GET |`/health` |`{"status":"ok"}` readiness check |
|GET |`/v1/version` |service identity and version |
|GET |`/openapi.json` |machine-readable API contract |
|POST |`/v1/verify` |verify a claim against 1–10 supplied webpages |

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
  "version": "0.1.0",
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

Sources must be HTTP(S) URLs. Local, private, link-local, multicast, reserved, and credential-bearing URLs are rejected to reduce SSRF risk. A request may include up to 10 sources. Each source is bounded by an 8-second timeout and a 2 MB response limit.

## Errors

|Status |Code |When |
|---|---|---|
|400 |`invalid_json` |request body is not valid JSON |
|400 |`invalid_request` |claim or sources are missing, malformed, or outside limits |
|400 |`private_or_invalid_url` |source URL is not a permitted public HTTP(S) URL |
|404 |`not_found` |path is not one of the documented operations |
|502 |`upstream_failure` |a request cannot be completed because of an unexpected upstream failure |

A failed individual source is returned in `source_errors` while other valid sources continue to be analyzed.

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
docker build -t sourceproof:0.1.0 .
docker run --rm -p 8080:8080 sourceproof:0.1.0
```

The container uses Python’s standard library and has no runtime dependency on API keys or third-party services. Before production traffic, operators should add external rate limiting, structured request logging with URL privacy controls, and a cache for repeated source pages.

## Pocket service

The Pocket metadata card is [`service-card.json`](https://github.com/frenzoblings57-dot/sourceproof/blob/main/service-card.json). The deployment sequence and required owner/operator wallet inputs are documented in [`POCKET.md`](https://github.com/frenzoblings57-dot/sourceproof/blob/main/POCKET.md).

SourceProof is designed to run as a stateless REST backend behind Pocket’s HA RelayMiner. The service card defines identity, readiness, and functional probes so a supplier cannot accidentally expose the wrong backend under the `sourceproof` service ID.

## Limitations

The MVP uses transparent keyword coverage and negation markers rather than an opaque LLM judgment. It is an evidence-triage and citation tool, not a legal, medical, compliance, or final editorial determination. Agents should inspect the returned evidence before taking high-impact action.

## License

MIT
