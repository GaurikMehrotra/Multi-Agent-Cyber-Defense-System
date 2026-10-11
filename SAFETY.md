# Safety policy

This project is for defensive analysis of public, approved datasets and traffic from an isolated lab. Scanning systems you do not own or lack written authorization to test can be illegal.

* Sensor processing is offline. Never mount a real host interface for capture. The optional lab capture records only the traffic-generator container's own eth0.
* The lab is Docker's **internal** network `172.30.0.0/24`. Nmap has only this network, no published ports, no host networking, no Docker socket and no raw-socket capabilities. The worker has core and lab networks, both internal; it is not an IP router.
* `src/tools/scope_guard.py` allows only canonical IPv4 literals `172.30.0.10` and `172.30.0.11`. It rejects DNS, IPv6, CIDRs, encodings, unknown lab addresses and public addresses. `scope.yaml` is documentation, not editable authorization.
* Nmap uses only a fixed TCP connect profile for ports 8000 and 8001: at most five probes per second, zero retries, twenty-second host timeout. No NSE scripts of any category, raw flags, service exploitation, credential guessing, denial of service or evasion are available.
* Agents have role-bound tools. Tools validate typed arguments, limits and deadlines before execution. No model can grant permissions, change profiles, approve a plan, reset the kill switch or issue arbitrary commands.
* Response is **mock simulation only**. Human approval is bound to the exact plan hash. Graph checkpoint resume alone cannot execute a response. Low confidence must escalate.
* `runtime/STOP` stops tool calls, LLM calls, scans and simulation. Admin API `/stop` creates it; authenticated `/resume` logs an override before clearing it. Finite already-started subprocesses may finish before observing the flag; deadlines cap their duration. A read-only tool thread can finish after timeout but cannot commit an action.
* Traffic fields are attacker-controlled. JSON delimiters, escaping, schemas, reference validation and permission checks are mandatory. These controls do not prove that arbitrary LLM prose is factually correct. The Reviewer challenges conclusions; humans must check support.
* All conclusions are hypotheses with confidence and evidence IDs. ATT&CK IDs are checked against the loaded curated reference. Add current official ATT&CK data only after reviewing its terms; do not mistake this one-technique reference for full coverage.
* Do not commit `.env`, data, PCAPs, checkpoints, model weights, database files, cached evidence, live malware or API credentials. The code never implements real response enforcement.

Run `make safety` and `make test`. CI uses FakeLLM and mocked sensors/scans; it never runs the lab or an external model. Hosted LLM export is off by default and needs explicit consent. Do not send confidential raw traffic to external services.
