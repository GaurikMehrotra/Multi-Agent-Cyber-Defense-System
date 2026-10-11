# Read-only enrichment

`MockIntel` is the default and always returns unknown reputation. No real threat intelligence is claimed in generated evaluations. The optional `HTTPSIntel` client implements **this project's custom service contract**, not an assumed third-party/vendor API:

* Operator supplies an explicitly approved HTTPS base URL and matching hostname.
* Read-only `GET /lookup?ip=<canonical-address>` returns JSON with `ip`, `source`, `reputation` (unknown/benign/suspicious), and numeric `confidence` (0..1).
* Optional `X-API-Key` comes only from private environment configuration.
* External export requires `ALLOW_EXTERNAL_INTEL=yes`; private/lab addresses are never exported even with this opt-in.
* No redirects; three-second HTTP timeout; streamed response cap 16 KiB; typed output and exact returned-entity match.
* An actual vendor integration needs a reviewed adapter for that vendor's current docs, terms and schema. None is invented or claimed tested.

For your own compatible reviewed service, use a host worker with `INTEL_BACKEND=https`, `INTEL_BASE_URL`, `INTEL_ALLOWED_HOST`, optional `INTEL_API_KEY`, and the explicit export flag in private `.env`. The internal-only Compose worker has no external egress and defaults to mock. A service-returned reputation is a hypothesis, not proof of maliciousness. Model output cannot set the endpoint or authorization.
