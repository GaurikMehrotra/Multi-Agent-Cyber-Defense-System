"""Only the immutable isolated gateway endpoint can be called."""

import os

import httpx

from src.tools.nmap_profiles import ScanArgs


class VerificationClient:
    def __init__(self, budget, audit, run_id):
        self.budget, self.audit, self.run_id = budget, audit, run_id
        self.key = os.environ["VERIFY_API_KEY"]

    def __call__(self, args: ScanArgs):
        self.budget.consume("scans")
        self.audit.write(self.run_id, "scan_gateway_attempt", args.model_dump())
        response = httpx.post(
            "http://172.30.0.20:8090/verify",
            headers={"X-API-Key": self.key},
            json=args.model_dump(),
            trust_env=False,
            timeout=min(25, self.budget.remaining),
        )
        response.raise_for_status()
        if len(response.content) > 65536:
            raise ValueError("verification response too large")
        self.budget.check()
        return response.json()
