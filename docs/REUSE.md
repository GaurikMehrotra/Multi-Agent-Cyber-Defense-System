# Reuse from related projects

No SOC-analyst or malware repositories were supplied or accessed. To reuse them safely:

* Extract the case database into migrations/models with no malware sample blobs; keep evidence IDs and provenance stable.
* Refactor LLM providers behind `Backend.complete`; preserve provider/model metadata, cache scope, schema validation, opt-in export and secrets from environment.
* Wrap every old tool in `Tool(schema, function, roles, timeout, max_bytes)` and remove arbitrary shell/SQL/URL parameters. Do not reuse unconstrained malware execution tools.
* Convert graph/intel clients to bounded read-only methods with typed entity arguments, destination allowlists and mocked responses; no credentials in traces.
* RAG retrieval should return evidence IDs, source hashes and untrusted quoted content. Retrieved instructions cannot grant approval, alter scopes or select raw flags. Do not index confidential samples into hosted stores without review.
* Write adapter tests first. No code from other projects is assumed compatible or safe.
