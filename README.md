# SourceProof

**SourceProof — Official Claim Verification** is an agent-callable HTTP service that checks a claim against current web sources and returns a machine-readable verdict with citation snippets, source timestamps, and errors per source.

The first MVP is intentionally narrow: an agent supplies the claim and the official webpages it wants checked. SourceProof does not pretend that keyword overlap is full fact-checking; its response states the heuristic method so downstream agents can apply appropriate caution.

## API

```bash
curl -s http://localhost:8080/v1/verify \
  -H 'content-type: application/json' \
  -d '{
    "claim": "Pocket Network publishes data services for AI agents",
    "sources": ["https://docs.pokt.network/"]
  }'
```

The response contains `supported`, `contradicted`, `partially_supported`, or `insufficient_evidence`, plus evidence snippets and retrieval timestamps. `GET /health` is the supplier health check and `GET /openapi.json` is the discovery contract.

## Run locally

Requires Python 3.10+ and no third-party packages:

```bash
python3 sourceproof.py --port 8080
```

Then run the tests:

```bash
python3 -m unittest discover -s tests -v
```

## Safety and limitations

- Only HTTP(S) URLs are accepted.
- Local, private, link-local, multicast, reserved, and credential-bearing URLs are rejected to reduce SSRF risk.
- A source is capped at 2 MB and 8 seconds per request.
- HTML scripts and styles are ignored before evidence extraction.
- The MVP uses transparent keyword coverage and negation markers, not an opaque LLM judgment. It is a triage and citation tool, not a legal, medical, or compliance determination.
- Deployments should add rate limiting, request logging controls, and a cache before public production traffic.

## Pocket service

Pocket service ID selected for registration: `sourceproof`. The validated metadata card is [`service-card.json`](./service-card.json), and the deployment checklist is [`POCKET.md`](./POCKET.md).

The service is designed to run behind a Pocket HA RelayMiner as a stateless REST backend. The repository includes the OpenAPI contract, identity/version endpoint, health endpoint, and functional probe required for supplier verification. Pocket registration and supplier staking remain separate operational steps and require a funded Beta TestNet owner/operator wallet.

## License

MIT
