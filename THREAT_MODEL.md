# Threat model

Assets: tool authorization, evidence integrity, approval records, sensitive telemetry, isolated lab boundaries, model validity, and operator credentials. Adversaries may control HTTP/DNS/TLS/banner content, a dataset's records, or model output. They do not have root on the host; root can rewrite code, secrets, audit files and network topology.

| Threat | Control | Residual risk |
|---|---|---|
| Traffic prompt injection | Delimited escaped data; typed reports; hard-coded tools, target allowlist and roles | A model may produce persuasive but misleading prose; manual support review required |
| Scope escape / flags | Strict canonical IPv4, exact asset allowlist, immutable argv, no NSE, lab-only scanner | Docker operator/root can change network topology; inspect before lab use |
| Approval bypass | Authenticated admin only; exact plan digest; proposals separated from simulation | API key theft grants its role; store locally with mode 0600 and rotate |
| Tool misuse / exhaustion | Bounded schemas, row/result caps, timeouts, per-run call and wall-clock limits, finite graph | Python read-only threads cannot be forcibly killed; a timed-out thread may finish later |
| Poisoned / mislabeled datasets | Explicit license/provenance manifest, conflicting-label duplicate rejection, temporal/family/external splits | Deduplication cannot repair unknown labels or sensor flow-construction bugs |
| Leakage | Identifiers excluded from model features; scaler fits benign training only; validation-only tuning | Related sessions can still span partitions; add session/host holdouts for public studies |
| External LLM data disclosure | FakeLLM default, local Ollama option, hosted export opt-in, redaction and bounded evidence | Hosted provider retention and free-tier terms need review; prefer aggregate/local evidence |
| Audit tampering | fsync, process locks, hash chain; DB append-only trigger | Hash chains alone cannot detect full rewrite/truncation without trusted external anchor; DB owner can drop triggers |
| API abuse | Hashed keys, RBAC, pagination, size limits, per-key limits | Development in-memory rate limiter is single-process; use shared rate storage before scaling |
| Supply-chain changes | Exact Python dependency pins, image digests, installed/source-release pip-audit, trusted TLS/package signatures | OS packages installed from signed Debian repositories can change; refresh and scan built images |
| Lab capture privacy | Generator container interface only; internal-only network | Captures still contain lab metadata; keep local and review before sharing |

The database owner in development is not a hardened production role. Never expose this stack to the public Internet. HTTP API and dashboard bind only localhost; the verification gateway is isolated, authenticated, and unpublished. Production deployment is outside this project's validated scope.
