# Phase ledger and terminal guide

The user's later instruction supersedes the original “Phase 1 only” and “wait for next” wording. Code was implemented across the required engineering phases without those pauses. **Not all research/owner-dependent milestones are complete.** Do not describe this ledger as 24 fully completed phases.

Run commands from the repository root with the Python 3.12 virtual environment activated. Full code is in the listed source files; no notebook contains the reusable implementation. The README contains prerequisites, private-key initialization and Compose details. Each row's commit message can be used as `git add <reviewed-files>; git commit -m "<message>"` when recreating the work incrementally; these are suggested milestone commits, not a claim that all were separately made.

| Phase | Implementation / exact command | Expected outcome / status | Suggested commit message |
|---|---|---|---|
| 1 LOCAL | `python -m pip install -r requirements.txt`; `python scripts/init_env.py` | CPU stack, private keys, safety/config scaffold. Implemented and installed; preserve existing .env | Add CPU development environment and safety policy |
| 2 core | `make core`; `python scripts/migrate.py` or `docker compose --profile agents run --rm --no-deps api alembic upgrade head` | PostgreSQL schema; content IDs; file hash chain and DB audit mirror | Add evidence persistence and append-only audit |
| 3 detect | `make sensors` | Tiny offline DNS PCAP yields Zeek conn/dns and Suricata demonstration alert; no live capture | Add offline sensors and malformed-log parsers |
| 4 LOCAL | Review DATA_SOURCES.md; `python -m src.eval.datasets data/source.csv data/source.manifest.json` | Importer requires actual owner confirmation. **Source terms and WTMC2021 paper reviewed; archive-specific approval/sample preparation remain; no data imported** | Add explicit dataset provenance and approval gate |
| 5 LOCAL | `python -m pytest tests/test_detection.py -q` | No time, exact-flow or held-family leakage in tested partitions | Add leakage-safe feature and split pipelines |
| 6 LOCAL | `make detection-eval` | Metric harness and transparent baselines; generated plumbing only | Add fixed-threshold metrics and detector baselines |
| 7 LOCAL | `make detection-eval` | CPU XGBoost and SHAP arrays; independent research accuracy unverified | Add XGBoost and feature attribution |
| 8 LOCAL | `make detection-eval` | Benign-only AE, validation threshold, safe checkpoints and fusion; optional Kaggle deferred | Add benign-trained autoencoder and fusion |
| 9 LOCAL | `python -m pytest tests/test_scope.py -q` | Canonical lab literals only, immutable profiles and fixed connect flags | Add immutable lab scope and scan profiles |
| 10 LOCAL | `make safety` | Delimiter/schema/reference guards exercised; real-model robustness unverified | Add untrusted-evidence and report guards |
| 11 LOCAL | `python -m pytest tests/test_safety_agents.py -q` | Role, result, timeout, kill and budget checks | Add bounded typed tool registry |
| 12 lab | `make lab`; `docker compose --profile lab run --rm traffic`; `python -m src.sensors.lab_checksums data/pcaps/lab.pcap data/pcaps/lab-repaired.pcap`; `PYTHONPATH=. python scripts/sensors.py data/pcaps/lab-repaired.pcap` | Finite benign lab traffic and own-container capture; scanner internal-only | Add isolated benign lab and verification gateway |
| 13 LOCAL | `python -m src.eval.response_eval` | Oracle simulator checks explicitly separate from agent quality | Add approved simulated containment and collateral scoring |
| 14 LOCAL | `make demo` | Six specialists, finite LangGraph, checkpoints, review and human interrupt | Add checkpointed evidence-grounded investigation graph |
| 15 LOCAL | `make agent-eval` | Fixed pipeline and single-call baselines on matched scenarios/backend | Add matched workflow baselines |
| 16 optional | Read docs/OPTIONAL_FRAMEWORKS.md before selecting maintained packages | CrewAI/AutoGen **not implemented**, optional milestone | Document optional adapter maintenance checks |
| 17 LOCAL | `python -m src.eval.response_eval`; `make agent-eval` | Six authored scenarios; oracle and actual-plan scores distinguished | Add scenario truth and response evaluation |
| 18 LOCAL | `make safety`; `python -m pytest tests/test_scope.py tests/test_safety_agents.py -q` | Guard escape attempts counted; zero escaped in executed suite | Add safety red-team regressions |
| 19 LOCAL / hosted | `make detection-eval agent-eval`; `python -m src.eval.replay_eval`; follow docs/EVALUATION.md | Generated metrics, 108 runs, consistency/ablations, latency, templates. **Hosted/public benchmarks and 30 human reviews outstanding** | Add honest evaluation artifacts and review assignments |
| 20 agents | `make agents`; log into local dashboard with private key | RBAC API, cases/evidence/trace, approved simulation, overrides, STOP | Add authenticated API and simulated SOC dashboard |
| 21 LOCAL | `docker compose --profile agents --profile lab ps`; `docker stats --no-stream` | Profile limits and cloud service checks; **actual laptop measurements outstanding** | Integrate bounded Compose services |
| 22 LOCAL | `make lint test audit safety` | pytest, ruff format/lint, Bandit, pip-audit; CI uses mocks only | Add security checks, CI and project policies |
| 23 LOCAL | Read README, SAFETY, THREAT_MODEL, MODEL_CARD, DATA_SOURCES | Architecture, instructions, sample report, limitations and measured results | Document architecture and verified capabilities |
| 24 LOCAL | `python scripts/check_git.py`; `git status --short`; `git push -u origin main` | Artifact/history checks and push; verify remote SHA | Audit repository artifacts and publish implementation |

## External work still required

1. Review the recorded current terms and correction findings in DATA_SOURCES.md; confirm exact archive/variant rights and approved purpose, then supply canonical source/external flows with verified feature semantics and benign exposure. Dataset pages became reachable on retry; the original proxy denial is no longer the source-review blocker.
2. Groq openai/gpt-oss-20b is the selected hosted candidate. Review account availability, data retention/export policy and free-tier terms, enter credentials privately, and run the matched evaluation using docs/HOSTED_EVALUATION.md. No secret should be pasted into chat.
3. Complete the 30-report human review CSV against actual linked evidence. Generating it does not perform review.
4. Run per-stage CPU/RAM/latency and aggregate container measurements on the actual 8 GiB WSL2 laptop. Cloud measurements cannot substitute.

Optional comparison frameworks and heavier GPU experiments are deliberately marked deferred, not half-built adapters. Current-source terms, provider access and human work cannot be fabricated to make the ledger say complete.
