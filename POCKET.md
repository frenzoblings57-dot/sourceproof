# Pocket deployment checklist

This repository is ready for Pocket registration and supplier deployment after the operator supplies a funded Beta TestNet owner/operator wallet.

## Service metadata

- Proposed immutable service ID: `sourceproof`
- Card: [`service-card.json`](./service-card.json)
- OpenAPI: [`openapi.json`](./openapi.json)
- Backend port: `8080`
- REST operations: `GET /v1/version`, `GET /health`, `POST /v1/verify`

## Registration sequence

Use Pocket’s official Service Builder tooling to check the catalog, read live Beta pricing parameters, validate `service-card.json`, then run `pocketd tx service add-service sourceproof ... --card-file service-card.json` from the service-owner wallet. The service fee, compute units, gas, and network state must be read live immediately before submission.

## Supplier sequence

The supplier hosts the SourceProof container on its own server and exposes the listening service port to the HA RelayMiner. Configure the RelayMiner's `backend_url` to the supplier-hosted backend address (for example, `http://sourceproof-backend.example:8080`), with the backend reachable at the root paths described by `service-card.json`. Run the container as provided, including its non-root user and health check. Stake a Beta supplier with `sourceproof` in its service list, wait for the next session boundary, then exercise the path with a funded Pocket application using `pocket-ap`. The owner/operator key, server credentials, and Beta testnet stake are not stored in this repository.

## Local verification proof

The implementation passes the unit suite. See `live-proof.json` for a successful `POST /v1/verify` response against `https://docs.pokt.network/`; the proof records the endpoint used for that test and is evidence of the backend response, not a production hosting address. It is not a claim that the request has already traversed Pocket, because Pocket registration requires the operator wallet and testnet stake.
